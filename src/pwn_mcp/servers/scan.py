"""Scanning and fuzzing tools: ports, subdomains, paths, and vuln probes."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shlex
import string
import subprocess
from importlib.resources import files
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import dns.asyncresolver
import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ..cli_run import (
    DEFAULT_TIMEOUT,
    enforce_scope_for_targets,
    extract_targets,
    list_allowed_tools,
    run_allowlisted,
    validate_argv,
)
from ..util import run_cmd, truncate, which

mcp = FastMCP("scan")

UA = "pwn-mcp/0.1 (security testing)"

_PORT_PRESETS = {
    "web": [80, 443, 8080, 8443, 8000, 8008, 3000, 5000, 9000],
    "common": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
               1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
               8443, 9200, 27017],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "db": [1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017, 28017],
}


def _wordlist(name: str) -> list[str]:
    text = files("pwn_mcp.data").joinpath(name).read_text()
    return [line.strip() for line in text.splitlines() if line.strip()]


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=120.0,
)
async def port_scan(
    host: str,
    ports: list[int] | None = None,
    preset: str = "common",
    timeout: float = 1.5,
    concurrency: int = 64,
    banner: bool = True,
) -> dict:
    """TCP-connect port scan with optional banner grabbing (pure Python).

    Args:
        host: Target hostname or IP.
        ports: Explicit port list (overrides preset).
        preset: One of common, web, mail, db (used when ports is omitted).
        timeout: Per-connection timeout in seconds.
        concurrency: Max simultaneous connections.
        banner: Try to read a service banner from open ports.
    """
    scan_ports = ports or _PORT_PRESETS.get(preset)
    if not scan_ports:
        raise ToolError(f"Unknown preset '{preset}'. Use one of {list(_PORT_PRESETS)} or pass ports.")
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[dict] = []

    async def probe(port: int) -> None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
            except (TimeoutError, OSError):
                return
            entry: dict = {"port": port}
            if banner:
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    if data:
                        entry["banner"] = data.decode("utf-8", "replace").strip()
                except (TimeoutError, OSError):
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            open_ports.append(entry)

    await asyncio.gather(*(probe(p) for p in scan_ports))
    open_ports.sort(key=lambda e: e["port"])
    return {"host": host, "scanned": len(scan_ports), "open": open_ports}


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=300.0,
)
async def nmap_scan(target: str, args: str = "-sV --top-ports 100") -> str:
    """Run nmap against a target (requires nmap on PATH).

    Args:
        target: Host/IP/CIDR to scan.
        args: nmap arguments, e.g. '-sV -p- --script vuln'.
    """
    if not which("nmap"):
        raise ToolError("nmap not found on PATH — install it or use scan_port_scan")
    return await asyncio.get_event_loop().run_in_executor(
        None, lambda: run_cmd(["nmap", *shlex.split(args), target], timeout=280)
    )


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def subdomain_enum(
    domain: str,
    wordlist: list[str] | None = None,
    use_crtsh: bool = True,
) -> dict:
    """Enumerate subdomains via certificate transparency (crt.sh) and DNS brute-force.

    Args:
        domain: Apex domain, e.g. example.com.
        wordlist: Custom subdomain names (defaults to bundled list).
        use_crtsh: Query crt.sh certificate transparency logs.
    """
    result: dict = {"domain": domain}
    subs: set[str] = set()

    if use_crtsh:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(
                    "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
                )
                if r.status_code == 200:
                    for entry in r.json():
                        for name in entry.get("name_value", "").splitlines():
                            name = name.strip().lstrip("*.").lower()
                            if name.endswith(domain):
                                subs.add(name)
            result["crtsh_count"] = len(subs)
        except (httpx.HTTPError, ValueError) as e:
            result["crtsh_error"] = str(e)

    names = wordlist or _wordlist("subdomains.txt")
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    sem = asyncio.Semaphore(50)
    resolved: dict[str, list[str]] = {}

    async def check(name: str) -> None:
        fqdn = f"{name}.{domain}"
        async with sem:
            try:
                answers = await resolver.resolve(fqdn, "A")
                resolved[fqdn] = [r.to_text() for r in answers]
            except dns.exception.DNSException:
                pass

    await asyncio.gather(*(check(n) for n in names))
    subs.update(resolved)
    result["subdomains"] = sorted(subs)
    result["resolved"] = resolved
    result["total"] = len(subs)
    return result


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=300.0,
)
async def dir_bruteforce(
    url: str,
    wordlist: list[str] | None = None,
    extensions: list[str] | None = None,
    status_filter: list[int] | None = None,
    concurrency: int = 30,
) -> dict:
    """Brute-force URL paths with a wordlist (ffuf-style, pure httpx).

    Args:
        url: Base URL, e.g. https://example.com.
        wordlist: Path names (defaults to bundled list).
        extensions: Extra extensions to try per word, e.g. ['.php', '.bak'].
        status_filter: Only report these statuses (default: all non-404).
        concurrency: Max simultaneous requests.
    """
    base = url.rstrip("/")
    words = wordlist or _wordlist("dirpaths.txt")
    paths = list(words)
    for ext in extensions or []:
        ext = ext if ext.startswith(".") else "." + ext
        paths += [w + ext for w in words]
    sem = asyncio.Semaphore(concurrency)
    hits: list[dict] = []

    async with httpx.AsyncClient(
        timeout=10.0, verify=False, headers={"User-Agent": UA},
        follow_redirects=False,
    ) as client:
        # Fingerprint soft-404 behavior by requesting a non-existent path
        soft_404: dict | None = None
        if not status_filter:
            try:
                canary_slug = f"_pwn_soft404_{secrets.token_hex(6)}"
                baseline_404 = await client.get(f"{base}/{canary_slug}")
                if baseline_404.status_code != 404:
                    soft_404 = {
                        "status": baseline_404.status_code,
                        "size": len(baseline_404.content),
                    }
            except httpx.HTTPError:
                pass

        async def probe(path: str) -> None:
            async with sem:
                try:
                    r = await client.get(f"{base}/{path.lstrip('/')}")
                except httpx.HTTPError:
                    return
            if status_filter and r.status_code not in status_filter:
                return
            if not status_filter:
                if r.status_code == 404:
                    return
                if soft_404 and r.status_code == soft_404["status"]:
                    if abs(len(r.content) - soft_404["size"]) <= 32:
                        return
            hits.append({
                "path": "/" + path.lstrip("/"),
                "status": r.status_code,
                "size": len(r.content),
                "location": r.headers.get("location"),
            })

        await asyncio.gather(*(probe(p) for p in paths))
    hits.sort(key=lambda h: (h["status"], h["path"]))
    result: dict = {"base": base, "tested": len(paths), "hits": hits}
    if soft_404:
        result["soft_404_calibrated"] = True
        result["soft_404_status"] = soft_404["status"]
    return result


def _canary() -> str:
    return "pwn" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))


def _with_params(url: str, extra: dict[str, str]) -> str:
    parts = urlparse(url)
    existing = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k not in extra
    ]
    for k, v in extra.items():
        existing.append((k, v))
    return urlunparse(parts._replace(query=urlencode(existing)))


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=120.0,
)
async def param_fuzz(
    url: str,
    params: list[str],
    payloads: list[str],
    method: str = "GET",
) -> dict:
    """Fuzz query parameters with payloads; report reflections and response diffs.

    Args:
        url: Target URL.
        params: Parameter names to fuzz.
        payloads: Payload strings to inject.
        method: GET (query string) or POST (form body).
    """
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        try:
            baseline = await client.get(url)
        except httpx.HTTPError as e:
            raise ToolError(f"Baseline request failed: {e}")
        base_len = len(baseline.content)

        results = []
        for param in params:
            for payload in payloads:
                try:
                    if method.upper() == "POST":
                        r = await client.post(url, data={param: payload})
                    else:
                        r = await client.get(_with_params(url, {param: payload}))
                except httpx.HTTPError as e:
                    results.append({"param": param, "payload": payload, "error": str(e)})
                    continue
                reflected = payload in r.text
                results.append({
                    "param": param,
                    "payload": payload,
                    "status": r.status_code,
                    "size": len(r.content),
                    "size_delta": len(r.content) - base_len,
                    "reflected": reflected,
                })
    interesting = [r for r in results if r.get("reflected") or abs(r.get("size_delta", 0)) > 100]
    return {"url": url, "baseline_size": base_len, "results": results,
            "interesting": interesting}


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def reflected_xss_probe(url: str, param: str, method: str = "GET") -> dict:
    """Inject a unique canary with special chars and analyze reflection context.

    Args:
        url: Target URL.
        param: Parameter name to inject into.
        method: GET or POST.
    """
    canary = _canary()
    payload = f"{canary}'\"><{canary}/"
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA},
    ) as client:
        try:
            if method.upper() == "POST":
                r = await client.post(url, data={param: payload})
            else:
                r = await client.get(_with_params(url, {param: payload}))
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")
    body = r.text
    idx = body.find(canary)
    if idx == -1:
        return {"reflected": False, "param": param, "status": r.status_code}

    # Examine surrounding context to classify the reflection
    end = body.find("/", idx + len(canary))
    segment = body[max(0, idx - 200): end + 1 if end != -1 else idx + 200]
    chars = {"quote": "'" in segment or '"' in segment,
             "angle": "<" in segment or ">" in segment}
    context = "html_text"
    open_tag = segment.rfind("<", 0, segment.find(canary))
    close_tag = segment.rfind(">", 0, segment.find(canary))
    if open_tag > close_tag:
        context = "inside_tag_or_attr"
    elif "<script" in segment.lower().split(canary)[0][-100:]:
        context = "inside_script"
    encoded = canary not in body or ("<" not in segment and "&lt;" in segment)
    return {
        "reflected": True,
        "param": param,
        "status": r.status_code,
        "context": context,
        "special_chars_unescaped": chars,
        "appears_encoded": encoded,
        "reflection_excerpt": segment,
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=120.0,
)
async def open_redirect_check(
    url: str,
    params: list[str] | None = None,
    canary_host: str = "example.org",
) -> dict:
    """Test common redirect parameters for open-redirect vulnerabilities.

    Args:
        url: Target URL.
        params: Parameter names to try (defaults to common redirect params).
        canary_host: External host used as the redirect destination.
    """
    try_params = params or ["next", "url", "redirect", "redirect_uri", "return",
                            "returnTo", "dest", "destination", "redir", "target",
                            "continue", "callback", "to", "goto"]
    payloads = [f"https://{canary_host}/", f"//{canary_host}/",
                f"/\\{canary_host}", f"https://{canary_host}%2f@evil"]
    findings = []
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA},
        follow_redirects=False,
    ) as client:
        for param in try_params:
            for payload in payloads:
                try:
                    r = await client.get(_with_params(url, {param: payload}))
                except httpx.HTTPError:
                    continue
                loc = r.headers.get("location", "")
                vulnerable = (
                    r.status_code in (301, 302, 303, 307, 308)
                    and canary_host in loc
                )
                meta_refresh = (
                    r.status_code == 200
                    and "url=" in r.text.lower()
                    and canary_host in r.text
                )
                if vulnerable or meta_refresh:
                    findings.append({
                        "param": param, "payload": payload,
                        "status": r.status_code, "location": loc or None,
                        "via": "location" if vulnerable else "meta/body",
                    })
    return {"url": url, "findings": findings, "vulnerable": bool(findings)}


_INTROSPECTION_QUERY = (
    "{__schema{queryType{name} mutationType{name} subscriptionType{name} "
    "types{name kind}}}"
)


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def graphql_probe(url: str) -> dict:
    """Probe a GraphQL endpoint for introspection and field suggestions.

    Args:
        url: GraphQL endpoint URL, e.g. https://api.example.com/graphql.
    """
    result: dict = {"url": url}
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA},
        follow_redirects=False,
    ) as client:
        # Introspection via POST
        try:
            r = await client.post(
                url, json={"query": _INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            result["post_status"] = r.status_code
            try:
                data = r.json()
            except ValueError:
                data = None
            if data and "data" in data and data["data"].get("__schema"):
                schema = data["data"]["__schema"]
                types = schema.get("types", [])
                interesting = [t["name"] for t in types
                               if not t["name"].startswith("__")
                               and t.get("kind") in ("OBJECT", "INPUT_OBJECT")]
                result["introspection_enabled"] = True
                result["query_type"] = (schema.get("queryType") or {}).get("name")
                result["mutation_type"] = (schema.get("mutationType") or {}).get("name")
                result["subscription_type"] = (
                    schema.get("subscriptionType") or {}).get("name")
                result["type_count"] = len(types)
                result["types_sample"] = interesting[:50]
            elif data and "errors" in data:
                result["introspection_enabled"] = False
                result["errors"] = [e.get("message", "") for e in data["errors"]][:5]
                # field-suggestion leakage is itself a finding
                if any("Did you mean" in m for m in result["errors"]):
                    result["field_suggestions"] = True
            else:
                result["introspection_enabled"] = False
                result["raw_preview"] = truncate(r.text, 500)
        except httpx.HTTPError as e:
            result["post_error"] = str(e)

        # Introspection via GET (some setups allow it)
        try:
            r = await client.get(url, params={"query": _INTROSPECTION_QUERY})
            result["get_status"] = r.status_code
            if '"__schema"' in r.text:
                result["get_introspection"] = True
        except httpx.HTTPError as e:
            result["get_error"] = str(e)

    result["vulnerable"] = bool(
        result.get("introspection_enabled") or result.get("get_introspection"))
    return result


_SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig/Django-like"),
    ("${7*7}", "49", "MVEL/OGNL/Spring-EL"),
    ("#{7*7}", "49", "Ruby/ERB/EL"),
    ("<%= 7*7 %>", "49", "ERB/ASP/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiplication)"),
    ("${{7*7}}", "49", "Vue/Angular template"),
]


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def ssti_probe(url: str, param: str, method: str = "GET") -> dict:
    """Probe a parameter for Server-Side Template Injection (SSTI) using math expressions.

    Injects template expressions (e.g. {{7*7}}, ${7*7}) and checks if the expression
    evaluates to 49 or 7777777 in the response body.

    Args:
        url: Target URL.
        param: Parameter name to test.
        method: GET or POST.
    """
    findings = []
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA}, follow_redirects=True
    ) as client:
        try:
            if method.upper() == "POST":
                baseline = await client.post(url, data={param: "pwnsafe"})
            else:
                baseline = await client.get(_with_params(url, {param: "pwnsafe"}))
        except httpx.HTTPError as e:
            raise ToolError(f"Baseline request failed: {e}")

        for payload, expected, engine in _SSTI_PAYLOADS:
            try:
                if method.upper() == "POST":
                    resp = await client.post(url, data={param: payload})
                else:
                    resp = await client.get(_with_params(url, {param: payload}))
            except httpx.HTTPError:
                continue

            if expected in resp.text and expected not in baseline.text:
                findings.append({
                    "payload": payload,
                    "expected_eval": expected,
                    "likely_engine": engine,
                    "status": resp.status_code,
                    "evaluated": True,
                })

    return {
        "url": url,
        "param": param,
        "vulnerable": bool(findings),
        "findings": findings,
    }


_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"sqlite3::sqlexception",
    r"microsoft ole db provider for sql server",
    r"ora-\d{5}",
]


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def sqli_probe(url: str, param: str, method: str = "GET") -> dict:
    """Heuristic SQL injection probe testing quote syntax errors and boolean differential responses.

    Args:
        url: Target URL.
        param: Parameter name to test.
        method: GET or POST.
    """
    indicators = []
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA}, follow_redirects=True
    ) as client:
        try:
            if method.upper() == "POST":
                base_resp = await client.post(url, data={param: "1"})
            else:
                base_resp = await client.get(_with_params(url, {param: "1"}))
        except httpx.HTTPError as e:
            raise ToolError(f"Baseline request failed: {e}")

        for quote in ("'", '"', "''"):
            try:
                if method.upper() == "POST":
                    r = await client.post(url, data={param: f"1{quote}"})
                else:
                    r = await client.get(_with_params(url, {param: f"1{quote}"}))
            except httpx.HTTPError:
                continue

            for pattern in _SQLI_ERROR_PATTERNS:
                if re.search(pattern, r.text, re.IGNORECASE):
                    indicators.append({
                        "type": "error_based",
                        "payload": f"1{quote}",
                        "matched_error": pattern,
                        "status": r.status_code,
                    })

        try:
            if method.upper() == "POST":
                r_true = await client.post(url, data={param: "1' OR '1'='1"})
                r_false = await client.post(url, data={param: "1' OR '1'='2"})
            else:
                r_true = await client.get(_with_params(url, {param: "1' OR '1'='1"}))
                r_false = await client.get(_with_params(url, {param: "1' OR '1'='2"}))

            delta = abs(len(r_true.content) - len(r_false.content))
            if delta > 80 and (r_true.status_code == 200 or r_false.status_code == 200):
                indicators.append({
                    "type": "boolean_differential",
                    "true_payload": "1' OR '1'='1",
                    "false_payload": "1' OR '1'='2",
                    "size_delta": delta,
                    "true_status": r_true.status_code,
                    "false_status": r_false.status_code,
                })
        except httpx.HTTPError:
            pass

    return {
        "url": url,
        "param": param,
        "vulnerable": bool(indicators),
        "indicators": indicators,
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def subfinder_enum(domain: str, args: str = "-silent") -> str:
    """Enumerate subdomains with ProjectDiscovery subfinder (requires subfinder on PATH).

    Install via pdtm: ``pdtm -i subfinder``. Prefer this over brute-only
    ``scan_subdomain_enum`` when passive sources are available.

    Args:
        domain: Apex domain, e.g. example.com.
        args: Extra subfinder flags (default: -silent). ``-d`` is always set.
    """
    if not which("subfinder"):
        raise ToolError(
            "subfinder not found on PATH — install with "
            "`pdtm -i subfinder` or use scan_subdomain_enum"
        )
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(
            ["subfinder", "-d", domain, *shlex.split(args)],
            timeout=160,
        ),
    )


def _require_nuclei() -> None:
    if not which("nuclei"):
        raise ToolError(
            "nuclei not found on PATH — install with `pdtm -i nuclei`"
        )


def _nuclei_raw(args: list[str], timeout: float = 90.0) -> str:
    """Run nuclei and return combined stdout/stderr (not truncated)."""
    proc = subprocess.run(
        ["nuclei", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    out = proc.stdout or ""
    if proc.stderr:
        out = f"{out}\n{proc.stderr}" if out else proc.stderr
    return out


_TAG_LINE = re.compile(r"^([a-zA-Z0-9_./:-]+)\s+\((\d+)\)\s*$")


@mcp.tool(
    tags={"scan"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
    timeout=90.0,
)
async def nuclei_list_tags(query: str | None = None, limit: int = 80) -> dict:
    """List available nuclei template tags (sorted by template count).

    Use this to discover what to pass as ``-tags`` to ``scan_nuclei_scan``.
    Follow up with ``scan_nuclei_list_templates`` for concrete template paths.

    Args:
        query: Optional case-insensitive substring filter on tag name.
        limit: Max tags to return (default 80).
    """
    _require_nuclei()
    if limit < 1:
        raise ToolError("limit must be >= 1")
    raw = await asyncio.get_event_loop().run_in_executor(
        None, lambda: _nuclei_raw(["-tgl", "-silent"], timeout=80)
    )
    tags: list[dict] = []
    q = (query or "").strip().lower()
    for line in raw.splitlines():
        m = _TAG_LINE.match(line.strip())
        if not m:
            continue
        name, count = m.group(1), int(m.group(2))
        if q and q not in name.lower():
            continue
        tags.append({"tag": name, "count": count})
    return {
        "total_matching": len(tags),
        "returned": min(limit, len(tags)),
        "tags": tags[:limit],
        "hint": "Pass tags to scan_nuclei_scan via args, e.g. '-silent -tags xss,sqli -severity high,critical'",
    }


@mcp.tool(
    tags={"scan"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
    timeout=120.0,
)
async def nuclei_list_templates(
    tags: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    template_id: str | None = None,
    query: str | None = None,
    limit: int = 150,
) -> dict:
    """List nuclei templates matching filters (paths agents can target with -t / -tags).

    At least one of tags, severity, protocol, or template_id is required — the
    full catalog is 10k+ templates. Use ``scan_nuclei_list_tags`` first to pick tags.

    Args:
        tags: Comma-separated nuclei tags, e.g. 'xss,cve'.
        severity: Comma-separated severities: info,low,medium,high,critical.
        protocol: Comma-separated types: http,dns,ssl,tcp,websocket,code,...
        template_id: Template id filter (supports wildcards), e.g. 'CVE-2024-*'.
        query: Optional substring filter on returned template paths.
        limit: Max template paths to return (default 150).
    """
    _require_nuclei()
    if not any((tags, severity, protocol, template_id)):
        raise ToolError(
            "Provide at least one filter: tags, severity, protocol, or template_id "
            "(full catalog is too large). Try scan_nuclei_list_tags first."
        )
    if limit < 1:
        raise ToolError("limit must be >= 1")

    args = ["-tl", "-silent"]
    if tags:
        args.extend(["-tags", tags])
    if severity:
        args.extend(["-severity", severity])
    if protocol:
        args.extend(["-type", protocol])
    if template_id:
        args.extend(["-id", template_id])

    raw = await asyncio.get_event_loop().run_in_executor(
        None, lambda: _nuclei_raw(args, timeout=100)
    )
    q = (query or "").strip().lower()
    paths: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing ") or line.startswith("["):
            continue
        if not line.endswith((".yaml", ".yml")):
            continue
        if q and q not in line.lower():
            continue
        paths.append(line)

    return {
        "filters": {
            "tags": tags,
            "severity": severity,
            "protocol": protocol,
            "template_id": template_id,
            "query": query,
        },
        "total_matching": len(paths),
        "returned": min(limit, len(paths)),
        "templates": paths[:limit],
        "hint": (
            "Run with scan_nuclei_scan args like "
            "'-silent -tags xss -severity high,critical' or "
            "'-silent -t http/cves/2024/CVE-2024-xxxx.yaml'"
        ),
    }


@mcp.tool(
    tags={"scan"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
    timeout=30.0,
)
async def nuclei_templates_version() -> dict:
    """Show installed nuclei engine and templates version / directory."""
    _require_nuclei()
    version = await asyncio.get_event_loop().run_in_executor(
        None, lambda: _nuclei_raw(["-version"], timeout=20)
    )
    tpl_ver = await asyncio.get_event_loop().run_in_executor(
        None, lambda: _nuclei_raw(["-tv"], timeout=20)
    )
    return {
        "engine": truncate(version.strip(), 2000),
        "templates": truncate(tpl_ver.strip(), 2000),
        "templates_dir": os.path.expanduser("~/nuclei-templates"),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=300.0,
)
async def nuclei_scan(url: str, args: str = "-silent -severity medium,high,critical") -> str:
    """Run ProjectDiscovery nuclei against a URL (requires nuclei on PATH).

    Prefer discovering coverage first: ``scan_nuclei_list_tags`` then
    ``scan_nuclei_list_templates``, then scan with scoped ``-tags`` / ``-t`` /
    ``-severity``. Default args favor higher-severity findings.

    Args:
        url: Target URL, e.g. https://example.com.
        args: Extra nuclei flags. ``-u`` is always set from url.
    """
    _require_nuclei()
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(
            ["nuclei", "-u", url, *shlex.split(args)],
            timeout=280,
        ),
    )


@mcp.tool(
    tags={"scan"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def cli_tools() -> dict:
    """List allowlisted CLIs for ``scan_cli_run`` and whether each is on PATH.

    Prefer higher-level tools when available; use ``scan_cli_run`` when you need
    full CLI flags the wrappers do not expose.
    """
    return {
        "tools": list_allowed_tools(),
        "hint": (
            "Invoke with scan_cli_run(tool='nuclei', argv=['-u', 'https://example.com', "
            "'-silent', '-tags', 'xss']). Shell metacharacters, absolute paths, and "
            "file I/O flags are blocked. Targets are scope-checked."
        ),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=320.0,
)
async def cli_run(
    tool: str,
    argv: list[str] | str,
    timeout: float = 120.0,
) -> dict:
    """Run an allowlisted CLI with validated argv (no shell).

    Allowlisted: nuclei, subfinder, nmap, whois, dig. See ``scan_cli_tools``.
    Arguments cannot contain shell metacharacters, absolute paths, or ``..``.
    File I/O / dangerous flags are denied. Targets parsed from argv
    (``-u``/``-d``/positionals) are enforced against the active scope.

    Args:
        tool: Allowlisted binary name, e.g. 'nuclei'.
        argv: Argument list (preferred) or a single shell-style string.
            Do not include the binary name (it is added automatically).
        timeout: Seconds to wait (max 300).
    """
    try:
        _policy, args = validate_argv(tool, argv)
    except ValueError as e:
        raise ToolError(str(e)) from e

    name = tool.strip().lower()
    try:
        hosts = await enforce_scope_for_targets(extract_targets(name, args))
    except PermissionError as e:
        raise ToolError(str(e)) from e

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: run_allowlisted(
                name, args, timeout if timeout else DEFAULT_TIMEOUT
            ),
        )
    except FileNotFoundError as e:
        raise ToolError(str(e)) from e

    result["scoped_hosts"] = hosts
    return result

