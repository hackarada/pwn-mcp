"""Constrained allowlisted CLI runner for optional external binaries.

Agents can invoke real CLIs (nuclei, subfinder, nmap, whois, dig) without a
shell. Arguments are validated, dangerous flags blocked, and targets extracted
for the same scope checks used by higher-level tools.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass

from .scope import load_scope
from .util import target_host, truncate, which

#: Max wall-clock seconds a cli_run invocation may request.
MAX_TIMEOUT = 300.0
DEFAULT_TIMEOUT = 120.0
MAX_OUTPUT_CHARS = 12000
MAX_ARGV = 64
MAX_ARG_LEN = 2048

_SHELL_META = re.compile(r"[;|&`$()<>\n\r\x00]")
_ABS_PATH = re.compile(r"^(?:/|[A-Za-z]:[\\/])")

_DIG_NON_TARGET = frozenset({
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "ANY", "PTR",
    "SRV", "CAA", "IN", "CH", "HS",
})

#: nmap flags that consume the next argv token (not a host target).
_NMAP_VALUE_FLAGS = frozenset({
    "-p", "-port", "--port",
    "-g", "--source-port",
    "-S",
    "-e",
    "-b",
    "-D",
    "-f",
    "-T",
    "-m",
    "-iR",
    "--exclude",
    "--max-retries",
    "--host-timeout",
    "--scan-delay",
    "--max-scan-delay",
    "--min-rate",
    "--max-rate",
    "--min-parallelism",
    "--max-parallelism",
    "--ttl",
    "--datadir",
    "--dns-servers",
    "--proxies",
    "--script",
    "--script-args",
    "--version-intensity",
    "-oN", "-oX", "-oG", "-oA", "-oS",  # denied anyway, but skip values
    "-iL",
})


@dataclass(frozen=True)
class ToolPolicy:
    """Per-binary policy for the constrained runner."""

    description: str
    #: Flags whose following argument is a scan target (host/url/domain).
    target_flags: frozenset[str]
    #: Flags that must never be passed (file I/O, escapes, etc.).
    denied_flags: frozenset[str]
    #: If True, non-flag positional args are treated as targets.
    positional_targets: bool = False


TOOL_POLICIES: dict[str, ToolPolicy] = {
    "nuclei": ToolPolicy(
        description="ProjectDiscovery vulnerability scanner",
        target_flags=frozenset({"-u", "-target", "--target"}),
        denied_flags=frozenset({
            "-l", "-list",
            "-lfa", "-allow-local-file-access",
            "-reset",
            "-hae", "-http-api-endpoint",
            "-sresp", "-store-resp", "-srd", "-store-resp-dir",
            "-me", "-markdown-export",
            "-se", "-sarif-export",
            "-je", "-json-export",
            "-jle", "-jsonl-export",
            "-pe", "-pdf-export",
            "-o", "-output",
            "-rdb", "-report-db",
            "-config", "-rc", "-report-config",
            "-ud", "-update-template-dir",
        }),
        positional_targets=False,
    ),
    "subfinder": ToolPolicy(
        description="ProjectDiscovery passive subdomain discovery",
        target_flags=frozenset({"-d", "-domain"}),
        denied_flags=frozenset({
            "-dL", "-list",
            "-o", "-output",
            "-oJ", "-oD", "-oI",
            "-config", "-provider-config",
        }),
        positional_targets=False,
    ),
    "nmap": ToolPolicy(
        description="Network port / service scanner",
        target_flags=frozenset(),
        denied_flags=frozenset({
            "-iL",
            "-oN", "-oX", "-oG", "-oA", "-oS",
            "--datadir",
            "--script-args-file",
            "--excludefile",
        }),
        positional_targets=True,
    ),
    "whois": ToolPolicy(
        description="WHOIS lookup",
        target_flags=frozenset(),
        denied_flags=frozenset({"-f", "--filename"}),
        positional_targets=True,
    ),
    "dig": ToolPolicy(
        description="DNS lookup (dig)",
        target_flags=frozenset(),
        denied_flags=frozenset({"-f"}),
        positional_targets=True,
    ),
}


def list_allowed_tools() -> list[dict]:
    """Return allowlisted tools and whether each binary is on PATH."""
    out: list[dict] = []
    for name, policy in sorted(TOOL_POLICIES.items()):
        out.append({
            "tool": name,
            "description": policy.description,
            "available": which(name) is not None,
            "target_flags": sorted(policy.target_flags),
            "positional_targets": policy.positional_targets,
        })
    return out


def _split_argv(argv: list[str] | str) -> list[str]:
    if isinstance(argv, str):
        argv = shlex.split(argv)
    if not isinstance(argv, list):
        raise ValueError("argv must be a list of strings or a shell-style string")
    return [str(a) for a in argv]


def validate_argv(tool: str, argv: list[str] | str) -> tuple[ToolPolicy, list[str]]:
    """Validate tool name + argv. Returns (policy, normalized argv without binary)."""
    name = tool.strip().lower()
    if name not in TOOL_POLICIES:
        allowed = ", ".join(sorted(TOOL_POLICIES))
        raise ValueError(f"Tool '{tool}' is not allowlisted. Allowed: {allowed}")

    policy = TOOL_POLICIES[name]
    args = _split_argv(argv)

    # If agent included the binary as argv[0], drop it.
    if args and args[0].lower().rsplit("/", 1)[-1] == name:
        args = args[1:]

    if len(args) > MAX_ARGV:
        raise ValueError(f"Too many arguments (max {MAX_ARGV})")

    for arg in args:
        if len(arg) > MAX_ARG_LEN:
            raise ValueError(f"Argument too long (max {MAX_ARG_LEN} chars)")
        if _SHELL_META.search(arg):
            raise ValueError(
                f"Shell metacharacters are not allowed in arguments: {arg!r}"
            )
        if ".." in arg:
            raise ValueError(f"Path traversal (..) is not allowed: {arg!r}")
        if _ABS_PATH.match(arg):
            raise ValueError(f"Absolute paths are not allowed: {arg!r}")

    for arg in args:
        flag = arg.split("=", 1)[0]
        if flag in policy.denied_flags:
            raise ValueError(
                f"Flag '{flag}' is blocked for {name} "
                "(file I/O / dangerous options). Use stdout-only invocation."
            )

    return policy, args


def extract_targets(tool: str, args: list[str]) -> list[str]:
    """Pull host/url/domain targets from validated argv for scope checks."""
    policy = TOOL_POLICIES[tool]
    targets: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        flag = arg.split("=", 1)[0]

        if tool == "nmap" and flag in _NMAP_VALUE_FLAGS and "=" not in arg:
            i += 2  # skip flag + its value
            continue

        if flag in policy.target_flags:
            if "=" in arg:
                targets.append(arg.split("=", 1)[1])
            elif i + 1 < len(args):
                targets.append(args[i + 1])
                i += 1
            i += 1
            continue
        if policy.positional_targets and not arg.startswith("-"):
            if tool == "dig":
                if arg.startswith("+") or arg.startswith("@"):
                    i += 1
                    continue
                if arg.upper() in _DIG_NON_TARGET:
                    i += 1
                    continue
            targets.append(arg)
        i += 1
    return targets


async def enforce_scope_for_targets(targets: list[str]) -> list[str]:
    """Reject out-of-scope targets when a scope file is configured."""
    scope = load_scope()
    hosts: list[str] = []
    for value in targets:
        host = target_host(value)
        if not host:
            continue
        hosts.append(host)
        if scope is not None and not await scope.is_allowed(host):
            raise PermissionError(
                f"Target '{host}' is outside the authorized scope "
                f"({scope.source})."
            )
    return hosts


def _scrubbed_env() -> dict[str, str]:
    """Minimal env for child processes (keep PATH/HOME/certs, drop secrets)."""
    keep = (
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE", "NUCLEI_TEMPLATES",
    )
    return {k: os.environ[k] for k in keep if k in os.environ}


def run_allowlisted(
    tool: str,
    args: list[str],
    timeout: float,
) -> dict:
    """Execute an allowlisted binary; return structured result."""
    binary = which(tool)
    if not binary:
        raise FileNotFoundError(
            f"{tool} not found on PATH — install it or use a higher-level tool"
        )
    timeout = max(1.0, min(float(timeout), MAX_TIMEOUT))
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=_scrubbed_env(),
        )
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") + (e.stderr or "")
        return {
            "tool": tool,
            "argv": [tool, *args],
            "timed_out": True,
            "timeout_sec": timeout,
            "exit_code": None,
            "output": truncate(partial.strip(), MAX_OUTPUT_CHARS),
        }

    out = proc.stdout or ""
    if proc.stderr:
        out = f"{out}\n--- stderr ---\n{proc.stderr}" if out else proc.stderr
    return {
        "tool": tool,
        "argv": [tool, *args],
        "timed_out": False,
        "timeout_sec": timeout,
        "exit_code": proc.returncode,
        "output": truncate(out.strip(), MAX_OUTPUT_CHARS),
    }
