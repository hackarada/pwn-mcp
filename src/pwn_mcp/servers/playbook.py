"""Composable recon/scan playbooks that return summaries + job ids."""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ..http_observe import baseline_from, classify
from ..jobs import enqueue
from ..util import which

mcp = FastMCP("playbook")

UA = "pwn-mcp/0.1 (security testing)"

_PLAYBOOKS = {
    "recon_surface": {
        "description": "DNS, tech fingerprint, robots, crawl, JS analyze, API discover",
    },
    "api_pass": {
        "description": "API docs, GraphQL introspection, CORS, security headers",
    },
    "xss_pass": {
        "description": "One GET that checks whether a query param is reflected. Does not run the page.",
    },
    "web2_recon": {
        "description": (
            "crt.sh → subfinder job → live probe → triage hints → nuclei job. "
            "Returns step data + job ids for the agent to poll."
        ),
    },
}


@mcp.tool(
    name="list",
    tags={"playbook"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def list_playbooks() -> dict:
    """List built-in playbooks and what they do."""
    return {
        "playbooks": [
            {"name": name, **meta} for name, meta in sorted(_PLAYBOOKS.items())
        ],
        "hint": "Run with playbook_run(name='web2_recon', target='example.com')",
    }


@mcp.tool(
    tags={"playbook", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def run(
    name: str,
    target: str,
    param: str | None = None,
    nuclei_args: str = "-silent -severity medium,high,critical",
) -> dict:
    """Run a built-in playbook against a target.

    Long steps (subfinder, nuclei) are enqueued as jobs — poll ``jobs_status``.

    Args:
        name: Playbook name from playbook_list.
        target: Domain or URL (e.g. example.com or https://example.com).
        param: Required for xss_pass (query param name).
        nuclei_args: Args for the nuclei job in web2_recon.
    """
    key = name.strip().lower()
    if key not in _PLAYBOOKS:
        raise ToolError(
            f"Unknown playbook '{name}'. Use playbook_list for names."
        )
    if key == "recon_surface":
        return await _recon_surface(target)
    if key == "api_pass":
        return await _api_pass(target)
    if key == "xss_pass":
        if not param:
            raise ToolError("xss_pass requires param=")
        return await _xss_pass(target, param)
    if key == "web2_recon":
        return await _web2_recon(target, nuclei_args)
    raise ToolError(f"Playbook '{name}' not implemented")


def _base_url(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = f"https://{t}"
    return t.rstrip("/")


def _domain(target: str) -> str:
    t = target.strip()
    if "://" in t:
        host = urlparse(t).hostname or t
    else:
        host = t.split("/")[0].split(":")[0]
    return host.lower().strip(".")


async def _recon_surface(target: str) -> dict:
    base = _base_url(target)
    domain = _domain(target)
    steps: list[dict[str, Any]] = []

    # DNS A
    dns_info: dict[str, Any] = {"domain": domain}
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        ans = await resolver.resolve(domain, "A")
        dns_info["A"] = [r.to_text() for r in ans]
    except Exception as e:
        dns_info["error"] = str(e)
    steps.append({"step": "dns_lookup", "result": dns_info})

    async with httpx.AsyncClient(
        timeout=15.0, verify=False, follow_redirects=True, headers={"User-Agent": UA}
    ) as client:
        tech: dict[str, Any] = {"url": base}
        try:
            r = await client.get(base)
            tech["status"] = r.status_code
            tech["server"] = r.headers.get("server")
            tech["powered_by"] = r.headers.get("x-powered-by")
            tech["title"] = _title(r.text)
            tech["stack_hints"] = _stack_hints(r)
        except httpx.HTTPError as e:
            tech["error"] = str(e)
        steps.append({"step": "tech_fingerprint", "result": tech})

        robots: dict[str, Any] = {}
        try:
            rr = await client.get(f"{base}/robots.txt")
            robots["status"] = rr.status_code
            robots["body_preview"] = rr.text[:1500] if rr.status_code == 200 else ""
        except httpx.HTTPError as e:
            robots["error"] = str(e)
        steps.append({"step": "fetch_robots", "result": robots})

        crawl = await _crawl(client, base)
        steps.append({"step": "crawl_links", "result": crawl})

        js_urls = [u for u in crawl.get("scripts", [])][:5]
        js_findings = []
        for ju in js_urls:
            try:
                jr = await client.get(ju)
                endpoints = sorted(set(_API_PATH.findall(jr.text)))[:40]
                js_findings.append({"url": ju, "endpoints": endpoints, "size": len(jr.content)})
            except httpx.HTTPError as e:
                js_findings.append({"url": ju, "error": str(e)})
        steps.append({"step": "js_analyze", "result": {"bundles": js_findings}})

        api = await _api_paths(client, base)
        steps.append({"step": "api_discover", "result": api})

    return {
        "playbook": "recon_surface",
        "target": target,
        "domain": domain,
        "base_url": base,
        "steps": steps,
        "jobs": [],
        "kill_signals": _kill_signals(steps),
    }


async def _api_pass(target: str) -> dict:
    base = _base_url(target)
    steps: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, follow_redirects=True, headers={"User-Agent": UA}
    ) as client:
        api = await _api_paths(client, base)
        steps.append({"step": "api_discover", "result": api})

        gql_url = ""
        for cand in api.get("found", []):
            if "graphql" in cand.get("path", "") and cand.get("kind") == "json":
                gql_url = f"{base}{cand['path']}"
                break
        if gql_url:
            gql = await _graphql_probe(client, gql_url)
        else:
            shells = [
                item["path"] for item in api.get("spa_shells", [])
                if "graphql" in item.get("path", "")
            ]
            gql = {
                "skipped": "no JSON GraphQL document in the doc probe",
                "spa_shells": shells,
            }
        steps.append({"step": "graphql_probe", "result": gql})

        cors = await _cors(client, base)
        steps.append({"step": "cors_check", "result": cors})

        headers = await _sec_headers(client, base)
        steps.append({"step": "security_headers", "result": headers})

    return {
        "playbook": "api_pass",
        "target": target,
        "base_url": base,
        "steps": steps,
        "jobs": [],
    }


async def _xss_pass(target: str, param: str) -> dict:
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    url = _base_url(target)
    canary = "pwnmcpXSS99"
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[param] = f"<script>{canary}</script>"
    fuzzed = urlunparse(parsed._replace(query=urlencode(q)))

    async with httpx.AsyncClient(
        timeout=15.0, verify=False, follow_redirects=True, headers={"User-Agent": UA}
    ) as client:
        try:
            r = await client.get(fuzzed)
            body = r.text
            reflected = canary in body
            raw_angle = f"<script>{canary}</script>" in body
            encoded_tag = "&lt;script" in body.lower()
        except httpx.HTTPError as e:
            return {
                "playbook": "xss_pass",
                "error": str(e),
                "jobs": [],
            }

    return {
        "playbook": "xss_pass",
        "target": url,
        "param": param,
        "steps": [{
            "step": "reflected_xss_probe",
            "result": {
                "reflected": reflected,
                "raw_script_tag": raw_angle,
                "appears_encoded": encoded_tag and not raw_angle,
                "reflection_in_error": r.status_code >= 500,
                "status": r.status_code,
                "probe_url": fuzzed,
            },
        }],
        "jobs": [],
    }


async def _web2_recon(target: str, nuclei_args: str) -> dict:
    domain = _domain(target)
    base = _base_url(target)
    steps: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []

    # crt.sh
    subs: set[str] = set()
    crt: dict[str, Any] = {"domain": domain}
    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            r = await client.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
            )
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            subs.add(name)
                crt["count"] = len(subs)
            else:
                crt["status"] = r.status_code
    except Exception as e:
        crt["error"] = str(e)
    steps.append({"step": "crt_sh", "result": crt})

    # subfinder job
    if which("subfinder"):
        job = enqueue("subfinder_enum", {"domain": domain, "args": "-silent"})
        jobs.append({"role": "subfinder", **{k: job[k] for k in ("id", "status", "kind")}})
        steps.append({"step": "subfinder_enum", "result": {"job_id": job["id"], "status": "queued"}})
    else:
        steps.append({"step": "subfinder_enum", "result": {"skipped": "subfinder not on PATH"}})

    # live probe sample (apex + up to 20 crt subs)
    probe_hosts = [domain] + sorted(subs)[:20]
    live: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=8.0, verify=False, follow_redirects=True, headers={"User-Agent": UA}
    ) as client:
        sem = asyncio.Semaphore(10)

        async def probe(host: str) -> None:
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    try:
                        r = await client.get(url)
                        live.append({
                            "host": host,
                            "url": str(r.url),
                            "status": r.status_code,
                            "title": _title(r.text)[:120],
                            "server": r.headers.get("server"),
                        })
                        return
                    except httpx.HTTPError:
                        continue

        await asyncio.gather(*(probe(h) for h in probe_hosts))
    steps.append({"step": "live_probe", "result": {"live": live, "probed": len(probe_hosts)}})

    # triage hints from live URLs
    urls = [x["url"] for x in live]
    triage = _triage_urls(urls)
    steps.append({"step": "url_triage", "result": triage})

    # nuclei job (required enqueue)
    nuclei_target = base
    if live:
        nuclei_target = live[0]["url"]
    if which("nuclei"):
        job = enqueue(
            "nuclei_scan",
            {"url": nuclei_target, "args": nuclei_args},
        )
        jobs.append({"role": "nuclei", **{k: job[k] for k in ("id", "status", "kind")}})
        steps.append({
            "step": "nuclei_scan",
            "result": {"job_id": job["id"], "url": nuclei_target, "status": "queued"},
        })
    else:
        steps.append({"step": "nuclei_scan", "result": {"skipped": "nuclei not on PATH"}})

    return {
        "playbook": "web2_recon",
        "target": target,
        "domain": domain,
        "base_url": base,
        "subdomains_sample": sorted(subs)[:100],
        "steps": steps,
        "jobs": jobs,
        "kill_signals": _kill_signals(steps),
        "next": "Poll jobs_status / jobs_result for subfinder and nuclei job ids",
    }


# --- helpers ---

_API_PATH = re.compile(
    r'''["'`]((?:/api|/v\d+|/graphql|/auth|/rest|/oauth)[^"'`\s]*)["'`]'''
)

_API_DOC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger-ui.html", "/api-docs",
    "/v3/api-docs", "/graphql", "/graphiql", "/redoc",
    "/.well-known/openid-configuration",
]


async def _crawl(client: httpx.AsyncClient, base: str) -> dict:
    try:
        r = await client.get(base)
    except httpx.HTTPError as e:
        return {"error": str(e)}
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I)
    scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I)
    own = urlparse(base).netloc
    internal = []
    for h in hrefs:
        full = urljoin(base, h)
        if urlparse(full).netloc == own:
            internal.append(full)
    return {
        "status": r.status_code,
        "internal_links": sorted(set(internal))[:80],
        "scripts": [urljoin(base, s) for s in scripts][:20],
    }


async def _api_paths(client: httpx.AsyncClient, base: str) -> dict:
    found = []
    spa_shells = []
    baseline = None
    try:
        index = await client.get(base if base.endswith("/") else f"{base}/")
        if index.status_code == 200:
            baseline = baseline_from(index.text)
    except httpx.HTTPError:
        baseline = None
    for path in _API_DOC_PATHS:
        try:
            r = await client.get(f"{base}{path}")
        except httpx.HTTPError:
            continue
        if r.status_code == 404:
            continue
        content_type = r.headers.get("content-type", "")
        entry = {
            "path": path,
            "status": r.status_code,
            "content_type": content_type,
            "kind": classify(
                status=r.status_code,
                content_type=content_type,
                body=r.text,
                baseline=baseline,
            ),
        }
        if entry["kind"] == "spa_shell":
            spa_shells.append(entry)
        else:
            found.append(entry)
    return {"found": found, "spa_shells": spa_shells, "probed": len(_API_DOC_PATHS)}


async def _graphql_probe(client: httpx.AsyncClient, url: str) -> dict:
    query = {"query": "{ __schema { queryType { name } mutationType { name } } }"}
    try:
        r = await client.post(url, json=query)
        data = r.json() if "json" in r.headers.get("content-type", "") else {}
        schema = (data.get("data") or {}).get("__schema")
        content_type = r.headers.get("content-type", "")
        return {
            "url": url,
            "status": r.status_code,
            "content_type": content_type,
            "response_kind": classify(
                status=r.status_code, content_type=content_type, body=r.text,
            ),
            "introspection_enabled": bool(schema),
            "schema": schema,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


async def _cors(client: httpx.AsyncClient, url: str) -> dict:
    origin = "https://evil.example"
    try:
        r = await client.get(url, headers={"Origin": origin})
        acao = r.headers.get("access-control-allow-origin", "")
        return {
            "acao": acao,
            "reflects_origin": acao == origin,
            "credentials": r.headers.get("access-control-allow-credentials"),
        }
    except httpx.HTTPError as e:
        return {"error": str(e)}


async def _sec_headers(client: httpx.AsyncClient, url: str) -> dict:
    interesting = [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
    ]
    try:
        r = await client.get(url)
        present = {h: r.headers.get(h) for h in interesting if r.headers.get(h)}
        missing = [h for h in interesting if h not in present]
        return {"present": present, "missing": missing}
    except httpx.HTTPError as e:
        return {"error": str(e)}


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]*)</title>", html, re.I)
    return (m.group(1).strip() if m else "")[:200]


def _stack_hints(r: httpx.Response) -> list[str]:
    hints = []
    server = (r.headers.get("server") or "").lower()
    powered = (r.headers.get("x-powered-by") or "").lower()
    body = r.text[:8000].lower()
    if "laravel" in powered or "laravel" in body:
        hints.append("Laravel — check mass assignment / IDOR")
    if "express" in powered:
        hints.append("Express — prototype pollution / path traversal")
    if "x-runtime" in r.headers:
        hints.append("Rails-like — mass assignment / IDOR on :id")
    if "/_next/" in body:
        hints.append("Next.js — SSRF via server actions / open redirect")
    if "wp-content" in body:
        hints.append("WordPress — plugins / REST auth")
    if "<app-root" in body or "ng-version" in body or "data-beasties-container" in body:
        hints.append("Angular markers in the HTML")
    if "graphql" in body or "graphql" in str(r.url):
        hints.append("GraphQL — introspection / mutation authz")
    if "asp.net" in powered or "aspnet" in server:
        hints.append("ASP.NET — ViewState / ReturnUrl redirect")
    if not hints and (server or powered):
        hints.append(f"headers: server={server or '-'} powered_by={powered or '-'}")
    return hints


def _triage_urls(urls: list[str]) -> dict:
    buckets = {
        "interesting_params": [],
        "api": [],
        "admin": [],
        "auth": [],
        "upload": [],
    }
    param_re = re.compile(
        r"[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=", re.I
    )
    for u in urls:
        if param_re.search(u):
            buckets["interesting_params"].append(u)
        if re.search(r"/api/|/v\d+/|/graphql|/rest/", u, re.I):
            buckets["api"].append(u)
        if re.search(r"/admin|/internal|/debug|/console|/manage", u, re.I):
            buckets["admin"].append(u)
        if re.search(r"/oauth|/login|/auth|/sso|/saml|/callback|/token", u, re.I):
            buckets["auth"].append(u)
        if re.search(r"upload|attachment|avatar|document", u, re.I):
            buckets["upload"].append(u)
    return {k: v[:50] for k, v in buckets.items()}


def _kill_signals(steps: list[dict]) -> list[str]:
    """Factual notes about this batch. The caller decides what to do next."""
    signals: list[str] = []
    saw_live_probe = False
    live: list = []
    for s in steps:
        result = s.get("result") or {}
        if s.get("step") == "live_probe":
            saw_live_probe = True
            live = result.get("live") or []
        if s.get("step") == "api_discover":
            found = result.get("found") or []
            shells = result.get("spa_shells") or []
            signals.append(
                f"api_discover: {len(found)} distinct documents, "
                f"{len(shells)} matched the site index"
            )
        if s.get("step") == "js_analyze":
            bundles = result.get("bundles") or []
            count = 0
            if isinstance(bundles, list):
                count = sum(len(b.get("endpoints") or []) for b in bundles if isinstance(b, dict))
            elif isinstance(bundles, dict):
                count = sum(
                    len((b or {}).get("endpoints") or [])
                    for b in bundles.values()
                    if isinstance(b, dict)
                )
            signals.append(f"js_analyze: {count} endpoint paths extracted, not requested")
        if s.get("step") == "tech_fingerprint":
            title = result.get("title") or ""
            if title:
                signals.append(f"title: {title}")
            hints = result.get("stack_hints") or []
            signals.extend(hints)
    if saw_live_probe and not live:
        signals.append("live_probe: 0 hosts returned HTTP")
    elif live and all(x.get("status") in (403, 401) for x in live):
        signals.append("live_probe: sampled hosts returned 401 or 403")
    return signals
