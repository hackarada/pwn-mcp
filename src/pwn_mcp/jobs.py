"""Background job worker for long-running scan/cli tasks."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from . import store
from .cli_run import (
    DEFAULT_TIMEOUT,
    enforce_scope_for_targets,
    extract_targets,
    run_allowlisted,
    validate_argv,
)
from .util import run_cmd, which

logger = logging.getLogger("pwn_mcp.jobs")

JOB_KINDS = frozenset({
    "cli_run",
    "nuclei_scan",
    "nmap_scan",
    "subfinder_enum",
    "monitor_subs",
    "hash_crack",
})

_worker_started = False
_worker_lock = threading.Lock()
_stop_event = threading.Event()
_DEFAULT_WORKERS = 2


def ensure_workers(n: int = _DEFAULT_WORKERS) -> None:
    """Start background worker threads once per process."""
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        store.init_db()
        _stop_event.clear()
        for i in range(max(1, n)):
            t = threading.Thread(
                target=_worker_loop,
                name=f"pwn-mcp-job-{i}",
                daemon=True,
            )
            t.start()
        _worker_started = True
        logger.info("Started %d job worker(s)", n)


def _worker_loop() -> None:
    while not _stop_event.is_set():
        job = store.job_claim_next()
        if job is None:
            _stop_event.wait(0.5)
            continue
        try:
            if store.job_is_cancel_requested(job["id"]):
                store.job_finish(
                    job["id"], status="cancelled", error="cancelled"
                )
                continue
            result = _run_job(job)
            if store.job_is_cancel_requested(job["id"]):
                store.job_finish(
                    job["id"],
                    status="cancelled",
                    result=result,
                    error="cancelled during run",
                )
            else:
                store.job_finish(job["id"], status="succeeded", result=result)
        except Exception as e:
            logger.exception("Job %s failed", job.get("id"))
            store.job_finish(job["id"], status="failed", error=str(e))


def _run_job(job: dict[str, Any]) -> Any:
    kind = job["kind"]
    params = job["params"] or {}
    if kind == "cli_run":
        return _run_cli_run(params)
    if kind == "nuclei_scan":
        return _run_nuclei(params)
    if kind == "nmap_scan":
        return _run_nmap(params)
    if kind == "subfinder_enum":
        return _run_subfinder(params)
    if kind == "monitor_subs":
        return _run_monitor_subs(params)
    if kind == "hash_crack":
        return _run_hash_crack(params)
    raise ValueError(f"Unknown job kind: {kind}")


def _run_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Inside a running loop (unlikely in worker thread) — use new loop
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _run_cli_run(params: dict[str, Any]) -> dict:
    tool = params.get("tool", "")
    argv = params.get("argv", [])
    timeout = float(params.get("timeout", DEFAULT_TIMEOUT))
    _, args = validate_argv(tool, argv)
    name = tool.strip().lower()
    hosts = _run_sync(enforce_scope_for_targets(extract_targets(name, args)))
    out = run_allowlisted(name, args, timeout)
    out["scoped_hosts"] = hosts
    return out


def _run_nuclei(params: dict[str, Any]) -> dict:
    url = params.get("url", "")
    args = params.get("args", "-silent -severity medium,high,critical")
    if not which("nuclei"):
        raise FileNotFoundError("nuclei not found on PATH")
    import shlex

    _run_sync(enforce_scope_for_targets([url]))
    output = run_cmd(
        ["nuclei", "-u", url, *shlex.split(args)],
        timeout=float(params.get("timeout", 280)),
    )
    return {"url": url, "output": output}


def _run_nmap(params: dict[str, Any]) -> dict:
    target = params.get("target", "")
    args = params.get("args", "-sV --top-ports 100")
    if not which("nmap"):
        raise FileNotFoundError("nmap not found on PATH")
    import shlex

    _run_sync(enforce_scope_for_targets([target]))
    output = run_cmd(
        ["nmap", *shlex.split(args), target],
        timeout=float(params.get("timeout", 280)),
    )
    return {"target": target, "output": output}


def _run_subfinder(params: dict[str, Any]) -> dict:
    domain = params.get("domain", "")
    args = params.get("args", "-silent")
    if not which("subfinder"):
        raise FileNotFoundError("subfinder not found on PATH")
    import shlex

    _run_sync(enforce_scope_for_targets([domain]))
    output = run_cmd(
        ["subfinder", "-d", domain, *shlex.split(args)],
        timeout=float(params.get("timeout", 160)),
    )
    subs = [ln.strip() for ln in output.splitlines() if ln.strip() and not ln.startswith("[")]
    return {"domain": domain, "output": output, "subdomains": subs}


def _run_monitor_subs(params: dict[str, Any]) -> dict:
    """Diff fresh subfinder results against a caller-provided prior list."""
    domain = params.get("domain", "")
    prior = set(params.get("prior") or [])
    fresh = _run_subfinder({"domain": domain, "args": params.get("args", "-silent")})
    current = set(fresh.get("subdomains") or [])
    new = sorted(current - prior)
    gone = sorted(prior - current)
    return {
        "domain": domain,
        "prior_count": len(prior),
        "current_count": len(current),
        "new": new,
        "gone": gone,
        "subdomains": sorted(current),
    }


def _run_hash_crack(params: dict[str, Any]) -> dict:
    """Run hashcat or john when present (allowlisted job kind)."""
    tool = (params.get("tool") or "hashcat").strip().lower()
    argv = params.get("argv") or []
    if tool not in ("hashcat", "john"):
        raise ValueError("hash_crack tool must be 'hashcat' or 'john'")
    if not which(tool):
        raise FileNotFoundError(f"{tool} not found on PATH")
    # Reuse cli_run validation path by temporarily using run_cmd only —
    # hashcat/john are not in TOOL_POLICIES; execute carefully without shell.
    if isinstance(argv, str):
        import shlex
        argv = shlex.split(argv)
    for a in argv:
        if any(c in a for c in ";|&`$()<>\n\r"):
            raise ValueError("shell metacharacters not allowed")
        if ".." in a or a.startswith("/"):
            # allow absolute hash files? deny for safety like cli_run
            if a.startswith("/") or a.startswith("~"):
                raise ValueError("absolute paths not allowed")
    timeout = float(params.get("timeout", 300))
    output = run_cmd([tool, *argv], timeout=timeout)
    return {"tool": tool, "argv": argv, "output": output}


def enqueue(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    if kind not in JOB_KINDS:
        raise ValueError(
            f"Unknown job kind '{kind}'. Allowed: {', '.join(sorted(JOB_KINDS))}"
        )
    ensure_workers()
    return store.job_create(kind, params)
