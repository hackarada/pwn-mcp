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
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

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
from ..http_observe import baseline_from, classify, classify_reflection, matches_baseline
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
    spa_shells = 0

    async with httpx.AsyncClient(
        timeout=10.0, verify=False, headers={"User-Agent": UA},
        follow_redirects=False,
    ) as client:
        # A catch-all that returns the site index (or one stable error page)
        # is not a distinct document. Record it so the caller can ignore it.
        documents, soft_404 = await _shell_documents(client, base)

        async def probe(path: str) -> None:
            nonlocal spa_shells
            async with sem:
                try:
                    r = await client.get(f"{base}/{path.lstrip('/')}")
                except httpx.HTTPError:
                    return
            if status_filter and r.status_code not in status_filter:
                return
            if not status_filter and r.status_code == 404:
                return
            if not status_filter and _is_shell(r, documents, soft_404):
                spa_shells += 1
                return
            content_type = r.headers.get("content-type", "")
            hits.append({
                "path": "/" + path.lstrip("/"),
                "status": r.status_code,
                "size": len(r.content),
                "content_type": content_type,
                "kind": classify(
                    status=r.status_code,
                    content_type=content_type,
                    body=r.text,
                    baseline=documents[0] if documents else None,
                ),
                "location": r.headers.get("location"),
            })

        await asyncio.gather(*(probe(p) for p in paths))
    hits.sort(key=lambda h: (h["status"], h["path"]))
    result: dict = {
        "base": base,
        "tested": len(paths),
        "hits": hits,
        "spa_shells": spa_shells,
    }
    if soft_404:
        result["soft_404_calibrated"] = True
        result["soft_404_status"] = soft_404["status"]
    return result


async def _shell_documents(
    client: httpx.AsyncClient, base: str
) -> tuple[list[dict], dict | None]:
    """Index document, plus a canary response when unknown paths are not 404."""
    documents: list[dict] = []
    soft_404: dict | None = None
    try:
        index = await client.get(base if base.endswith("/") else f"{base}/")
        if index.status_code == 200:
            documents.append(baseline_from(index.text))
    except httpx.HTTPError:
        pass
    try:
        canary = await client.get(f"{base}/_pwn_soft404_{secrets.token_hex(6)}")
        if canary.status_code != 404:
            documents.append(baseline_from(canary.text))
            soft_404 = {
                "status": canary.status_code,
                "size": len(canary.content),
            }
    except httpx.HTTPError:
        pass
    return documents, soft_404


def _is_shell(response: httpx.Response, documents: list[dict], soft_404: dict | None) -> bool:
    if any(matches_baseline(response.text, doc) for doc in documents):
        return True
    if soft_404 and response.status_code == soft_404["status"]:
        return abs(len(response.content) - soft_404["size"]) <= 32
    return False


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

    ``special_chars_unescaped`` is true only when the payload's own quotes or
    angles come back raw, between the two canary copies. Tags in the rest of
    the page do not count. ``appears_encoded`` means those characters came
    back as HTML entities. ``reflection_in_error`` means the status is 500 or
    higher. Encoded input on an error page is a reflection, not a confirmed XSS.

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
    judged = classify_reflection(r.text, canary, r.status_code)
    judged["param"] = param
    return judged


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
            result["post_content_type"] = r.headers.get("content-type", "")
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
                result["response_kind"] = classify(
                    status=r.status_code,
                    content_type=result["post_content_type"],
                    body=r.text,
                )
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
    r"sqlite_error",
    r"microsoft ole db provider for sql server",
    r"ora-\d{5}",
]
_AUTH_FIELD = re.compile(
    r'"(?:token|access_token|id_token|authentication)"\s*:', re.IGNORECASE
)


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def sqli_probe(
    url: str,
    param: str,
    method: str = "GET",
    content_type: str = "form",
) -> dict:
    """Send SQL metacharacters in one parameter and report response differences.

    ``content_type=form`` sends a query string (GET) or a form body (POST).
    ``content_type=json`` always POSTs a JSON object ``{param: payload}``,
    which is what JSON login and REST bodies expect.

    Indicators are observations. ``error_based`` means the body matched a
    database error string. ``boolean_differential`` is a response-size gap
    between two payloads. ``auth_differential`` means a payload response
    contains an auth field (``token``, ``authentication``, …) the baseline
    did not. ``status_differential`` is only a status change. Read the
    indicator type and decide. The tool does not identify the query or
    extract data.

    Args:
        url: Target URL.
        param: Parameter or JSON field name to test.
        method: GET or POST. Ignored when content_type is json (sent as POST).
        content_type: ``form`` (default) or ``json``.
    """
    mode = content_type.strip().lower()
    if mode not in ("form", "json"):
        raise ToolError("content_type must be 'form' or 'json'")
    sent_method = "POST" if mode == "json" else method.upper()
    indicators = []

    async def send(client: httpx.AsyncClient, value: str) -> httpx.Response:
        if mode == "json":
            return await client.post(url, json={param: value})
        if sent_method == "POST":
            return await client.post(url, data={param: value})
        return await client.get(_with_params(url, {param: value}))

    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers={"User-Agent": UA}, follow_redirects=True
    ) as client:
        try:
            base_resp = await send(client, "1")
        except httpx.HTTPError as e:
            raise ToolError(f"Baseline request failed: {e}")

        for quote in ("'", '"', "''"):
            payload = f"1{quote}"
            try:
                r = await send(client, payload)
            except httpx.HTTPError:
                continue
            matched = False
            for pattern in _SQLI_ERROR_PATTERNS:
                if re.search(pattern, r.text, re.IGNORECASE):
                    indicators.append({
                        "type": "error_based",
                        "payload": payload,
                        "matched_error": pattern,
                        "status": r.status_code,
                    })
                    matched = True
                    break
            if (
                not matched
                and r.status_code != base_resp.status_code
                and max(r.status_code, base_resp.status_code) >= 500
                and not any(item["type"] == "status_differential" for item in indicators)
            ):
                indicators.append({
                    "type": "status_differential",
                    "payload": payload,
                    "baseline_status": base_resp.status_code,
                    "status": r.status_code,
                })

        try:
            r_true = await send(client, "1' OR '1'='1")
            r_false = await send(client, "1' OR '1'='2")
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

        # JSON logins often accept a comment-terminated tautology and return a
        # token instead of a SQL error string. Compare that to the baseline.
        if not any(item["type"] == "auth_differential" for item in indicators):
            try:
                r_auth = await send(client, "' OR 1=1--")
            except httpx.HTTPError:
                r_auth = None
            if (
                r_auth is not None
                and _AUTH_FIELD.search(r_auth.text)
                and not _AUTH_FIELD.search(base_resp.text)
            ):
                indicators.append({
                    "type": "auth_differential",
                    "payload": "' OR 1=1--",
                    "baseline_status": base_resp.status_code,
                    "status": r_auth.status_code,
                    "body_preview": truncate(r_auth.text, 400),
                })

    return {
        "url": url,
        "param": param,
        "method": sent_method,
        "content_type": mode,
        "baseline_status": base_resp.status_code,
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

    Allowlisted: nuclei, subfinder, nmap, whois, dig, httpx, katana, naabu,
    dnsx, ffuf, assetfinder. See ``scan_cli_tools``.
    Arguments cannot contain shell metacharacters, absolute paths, or ``..``.
    File I/O / dangerous flags are denied. Targets parsed from argv
    (``-u``/``-d``/``-host``/positionals) are enforced against the active scope.

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


# --- Phase 2: PD wrappers, discovery, probes, takeover ---


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def httpx_probe(url: str, args: str = "-silent -status-code -title -tech-detect") -> str:
    """Probe a URL with ProjectDiscovery httpx (requires httpx binary on PATH).

    Args:
        url: Target URL.
        args: Extra httpx flags (``-u`` is set from url).
    """
    if not which("httpx"):
        raise ToolError("httpx binary not found on PATH (ProjectDiscovery httpx)")
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(["httpx", "-u", url, *shlex.split(args)], timeout=160),
    )


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def katana_crawl(url: str, args: str = "-silent -d 2 -jc") -> str:
    """Crawl with ProjectDiscovery katana (requires katana on PATH).

    Args:
        url: Seed URL.
        args: Extra katana flags (``-u`` is set from url).
    """
    if not which("katana"):
        raise ToolError("katana not found on PATH")
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(["katana", "-u", url, *shlex.split(args)], timeout=160),
    )


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=180.0,
)
async def naabu_scan(host: str, args: str = "-silent -top-ports 100") -> str:
    """Port scan with ProjectDiscovery naabu (requires naabu on PATH).

    Args:
        host: Target hostname or IP.
        args: Extra naabu flags (``-host`` is set from host).
    """
    if not which("naabu"):
        raise ToolError("naabu not found on PATH")
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(["naabu", "-host", host, *shlex.split(args)], timeout=160),
    )


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=90.0,
)
async def dnsx_resolve(domain: str, args: str = "-silent -a -resp") -> str:
    """Resolve with ProjectDiscovery dnsx (requires dnsx on PATH).

    Args:
        domain: Domain to resolve.
        args: Extra dnsx flags (``-d`` is set from domain).
    """
    if not which("dnsx"):
        raise ToolError("dnsx not found on PATH")
    return await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: run_cmd(["dnsx", "-d", domain, *shlex.split(args)], timeout=80),
    )


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=300.0,
)
async def content_discover(
    url: str,
    extra_paths: list[str] | None = None,
    from_sitemap: bool = True,
    from_js: bool = True,
    recurse_depth: int = 1,
    concurrency: int = 20,
) -> dict:
    """Content discovery: bundled wordlist + sitemap/JS-fed paths + optional recurse.

    Responses that match the site index or a stable catch-all page are counted
    in ``spa_shells`` and left out of ``hits``. ``kind`` labels what remains.

    Args:
        url: Base URL.
        extra_paths: Caller-supplied paths to probe.
        from_sitemap: Pull paths from /sitemap.xml.
        from_js: Extract path-like strings from linked JS (first page).
        recurse_depth: When a directory-like hit is found, probe children one level (0/1).
        concurrency: Max parallel requests.
    """
    base = url.rstrip("/")
    paths: set[str] = set(_wordlist("dirpaths.txt"))
    for p in extra_paths or []:
        paths.add(p.lstrip("/"))

    async with httpx.AsyncClient(
        timeout=10.0, verify=False, headers={"User-Agent": UA}, follow_redirects=False,
    ) as client:
        if from_sitemap:
            try:
                sm = await client.get(f"{base}/sitemap.xml")
                if sm.status_code == 200:
                    for loc in re.findall(r"<loc>([^<]+)</loc>", sm.text)[:200]:
                        path = urlparse(loc).path.lstrip("/")
                        if path:
                            paths.add(path)
            except httpx.HTTPError:
                pass
        if from_js:
            try:
                page = await client.get(base)
                for src in re.findall(r'''src=["']([^"']+\.js[^"']*)["']''', page.text, re.I)[:5]:
                    try:
                        jr = await client.get(urljoin(str(page.url), src))
                        for m in re.findall(r'''["'`](/[a-zA-Z0-9_\-./]{2,80})["'`]''', jr.text):
                            if not m.startswith("//") and "." not in m.rsplit("/", 1)[-1]:
                                paths.add(m.lstrip("/"))
                    except httpx.HTTPError:
                        continue
            except httpx.HTTPError:
                pass

        sem = asyncio.Semaphore(concurrency)
        hits: list[dict] = []
        documents, soft_404 = await _shell_documents(client, base)
        spa_shells = 0

        async def probe(path: str) -> None:
            nonlocal spa_shells
            async with sem:
                try:
                    r = await client.get(f"{base}/{path.lstrip('/')}")
                except httpx.HTTPError:
                    return
            if r.status_code == 404:
                return
            if _is_shell(r, documents, soft_404):
                spa_shells += 1
                return
            content_type = r.headers.get("content-type", "")
            hits.append({
                "path": "/" + path.lstrip("/"),
                "status": r.status_code,
                "size": len(r.content),
                "content_type": content_type,
                "kind": classify(
                    status=r.status_code,
                    content_type=content_type,
                    body=r.text,
                    baseline=documents[0] if documents else None,
                ),
                "location": r.headers.get("location"),
            })

        await asyncio.gather(*(probe(p) for p in sorted(paths)[:800]))

        if recurse_depth >= 1:
            dirs = [
                h["path"] for h in hits
                if h["status"] in (200, 301, 302, 403) and h["path"].endswith("/")
            ][:30]
            child_words = ["index", "admin", "config", "backup", "test", "api", "v1", "v2"]
            children = [f"{d.rstrip('/')}/{w}" for d in dirs for w in child_words]
            await asyncio.gather(*(probe(p) for p in children))

    hits.sort(key=lambda h: (h["status"], h["path"]))
    return {
        "base": base,
        "tested": len(paths),
        "hits": hits[:400],
        "spa_shells": spa_shells,
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def ssrf_probe(
    url: str,
    param: str,
    canary_host: str = "169.254.169.254",
    method: str = "GET",
) -> dict:
    """Probe a parameter for SSRF by injecting internal/metadata URLs.

    Uses detection-friendly targets (metadata IP, localhost). Does not use OAST.

    Args:
        url: Target URL containing the parameter.
        param: Parameter name to inject into.
        canary_host: Host/IP embedded in the SSRF payload (default AWS metadata).
        method: GET or POST.
    """
    payloads = [
        f"http://{canary_host}/",
        f"http://{canary_host}/latest/meta-data/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        f"http://0:{canary_host}",
    ]
    findings = []
    async with httpx.AsyncClient(
        timeout=12.0, verify=False, headers={"User-Agent": UA}, follow_redirects=False,
    ) as client:
        baseline_url = _with_params(url, {param: "https://example.com"})
        try:
            if method.upper() == "POST":
                base_r = await client.post(url, data={param: "https://example.com"})
            else:
                base_r = await client.get(baseline_url)
            base_len = len(base_r.content)
            base_status = base_r.status_code
        except httpx.HTTPError as e:
            return {"url": url, "param": param, "error": str(e), "findings": []}

        for payload in payloads:
            try:
                if method.upper() == "POST":
                    r = await client.post(url, data={param: payload})
                else:
                    r = await client.get(_with_params(url, {param: payload}))
            except httpx.HTTPError as e:
                findings.append({"payload": payload, "error": str(e)})
                continue
            body = r.text.lower()
            signals = []
            if "ami-id" in body or "instance-id" in body or "meta-data" in body:
                signals.append("cloud_metadata_body")
            if "root:x:" in body or "localhost" in body and r.status_code == 200:
                signals.append("local_content_hint")
            if abs(len(r.content) - base_len) > 200 or r.status_code != base_status:
                signals.append("response_diff")
            findings.append({
                "payload": payload,
                "status": r.status_code,
                "size": len(r.content),
                "signals": signals,
                "interesting": bool(signals),
            })
    return {
        "url": url,
        "param": param,
        "findings": findings,
        "vulnerable": any(f.get("interesting") for f in findings),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def idor_probe(
    url: str,
    param: str,
    ids: list[str] | None = None,
    headers_a: dict[str, str] | None = None,
    headers_b: dict[str, str] | None = None,
) -> dict:
    """Compare responses across object IDs / two auth contexts for IDOR signals.

    Args:
        url: URL with the object parameter.
        param: ID parameter name.
        ids: Object IDs to try (default: 1, 2, 100, 9999).
        headers_a: Auth context A (e.g. user cookie).
        headers_b: Auth context B (optional second user); when set, compares A vs B
            on the same id.
    """
    test_ids = ids or ["1", "2", "100", "9999"]
    results = []
    async with httpx.AsyncClient(
        timeout=12.0, verify=False, headers={"User-Agent": UA}, follow_redirects=True,
    ) as client:
        for oid in test_ids:
            entry: dict = {"id": oid}
            try:
                ra = await client.get(
                    _with_params(url, {param: oid}), headers=headers_a or {}
                )
                entry["a"] = {"status": ra.status_code, "size": len(ra.content),
                              "preview": truncate(ra.text, 200)}
            except httpx.HTTPError as e:
                entry["a"] = {"error": str(e)}
                results.append(entry)
                continue
            if headers_b:
                try:
                    rb = await client.get(
                        _with_params(url, {param: oid}), headers=headers_b
                    )
                    entry["b"] = {"status": rb.status_code, "size": len(rb.content),
                                  "preview": truncate(rb.text, 200)}
                    entry["diff"] = (
                        entry["a"]["status"] == entry["b"]["status"]
                        and abs(entry["a"]["size"] - entry["b"]["size"]) < 32
                        and entry["a"]["status"] == 200
                    )
                    entry["note"] = (
                        "same body for two auth contexts — possible IDOR"
                        if entry["diff"] else "responses differ"
                    )
                except httpx.HTTPError as e:
                    entry["b"] = {"error": str(e)}
            results.append(entry)

    statuses = [r.get("a", {}).get("status") for r in results if "a" in r]
    cross_id_leak = (
        len(set(s for s in statuses if s == 200)) >= 2
        and not headers_b
    )
    return {
        "url": url,
        "param": param,
        "results": results,
        "cross_id_200": cross_id_leak,
        "auth_context_same": any(r.get("diff") for r in results),
        "vulnerable": bool(cross_id_leak or any(r.get("diff") for r in results)),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def cache_probe(url: str, poison_header: str = "X-Forwarded-Host") -> dict:
    """Probe for web-cache poisoning via unkeyed headers.

    Args:
        url: Target URL.
        poison_header: Header to inject (X-Forwarded-Host, X-Original-URL, ...).
    """
    canary = f"pwncache-{_canary()}.evil"
    async with httpx.AsyncClient(
        timeout=12.0, verify=False, headers={"User-Agent": UA}, follow_redirects=False,
    ) as client:
        try:
            baseline = await client.get(url)
            poisoned = await client.get(url, headers={poison_header: canary})
            check = await client.get(url)
        except httpx.HTTPError as e:
            return {"url": url, "error": str(e)}

    reflected = canary.lower() in poisoned.text.lower() or canary.lower() in str(
        poisoned.headers
    ).lower()
    persisted = canary.lower() in check.text.lower()
    cache_headers = {
        k: poisoned.headers.get(k)
        for k in ("x-cache", "cf-cache-status", "age", "cache-control", "via")
        if poisoned.headers.get(k)
    }
    return {
        "url": url,
        "poison_header": poison_header,
        "canary": canary,
        "reflected_in_poison_response": reflected,
        "persisted_on_clean_request": persisted,
        "cache_headers": cache_headers,
        "baseline_status": baseline.status_code,
        "poison_status": poisoned.status_code,
        "vulnerable": bool(persisted),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def host_header_probe(url: str, evil_host: str = "evil.example") -> dict:
    """Probe Host / X-Forwarded-Host handling for poisoning and password-reset issues.

    Args:
        url: Target URL.
        evil_host: Attacker host to inject.
    """
    findings = []
    async with httpx.AsyncClient(
        timeout=12.0, verify=False, headers={"User-Agent": UA}, follow_redirects=False,
    ) as client:
        variants = [
            {"Host": evil_host},
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"Forwarded": f"host={evil_host}"},
        ]
        for hdrs in variants:
            try:
                # httpx sets Host from URL; use header override carefully
                r = await client.get(url, headers=hdrs)
            except httpx.HTTPError as e:
                findings.append({"headers": hdrs, "error": str(e)})
                continue
            body_hit = evil_host.lower() in r.text.lower()
            loc = r.headers.get("location", "")
            loc_hit = evil_host.lower() in loc.lower()
            findings.append({
                "headers": hdrs,
                "status": r.status_code,
                "reflected_body": body_hit,
                "reflected_location": loc_hit,
                "location": loc[:200] if loc else None,
                "interesting": body_hit or loc_hit,
            })
    return {
        "url": url,
        "evil_host": evil_host,
        "findings": findings,
        "vulnerable": any(f.get("interesting") for f in findings),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def subdomain_takeover_check(domain: str) -> dict:
    """Check a hostname for dangling CNAME / common takeover fingerprints.

    Args:
        domain: Hostname to check (e.g. docs.example.com).
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    result: dict = {"domain": domain, "cname": [], "a": [], "signals": []}
    try:
        ans = await resolver.resolve(domain, "CNAME")
        result["cname"] = [r.to_text().rstrip(".") for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
        result["cname_error"] = str(e)
    try:
        ans = await resolver.resolve(domain, "A")
        result["a"] = [r.to_text() for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    fingerprints = {
        "github": ["There isn't a GitHub Pages site here", "For root URLs"],
        "heroku": ["No such app", "no-such-app"],
        "aws_s3": ["NoSuchBucket", "The specified bucket does not exist"],
        "azure": ["404 Web Site not found"],
        "shopify": ["Sorry, this shop is currently unavailable"],
        "pantheon": ["404 error unknown site"],
        "fastly": ["Fastly error: unknown domain"],
    }
    async with httpx.AsyncClient(
        timeout=10.0, verify=False, headers={"User-Agent": UA}, follow_redirects=True,
    ) as client:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{domain}/")
            except httpx.HTTPError:
                continue
            body = r.text[:8000]
            result["http_status"] = r.status_code
            for vendor, needles in fingerprints.items():
                if any(n.lower() in body.lower() for n in needles):
                    result["signals"].append(vendor)
            break

    dangling = bool(result["cname"]) and not result["a"]
    result["dangling_cname"] = dangling
    result["vulnerable"] = dangling or bool(result["signals"])
    return result


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def cloud_bucket_probe(name: str) -> dict:
    """Probe common public cloud bucket URL patterns for a name.

    Args:
        name: Bucket / project name guess (e.g. company-assets).
    """
    candidates = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://{name}.s3-us-west-2.amazonaws.com/",
        f"https://{name}.storage.googleapis.com/",
        f"https://{name}.blob.core.windows.net/",
        f"https://storage.googleapis.com/{name}/",
    ]
    hits = []
    async with httpx.AsyncClient(
        timeout=10.0, verify=False, headers={"User-Agent": UA}, follow_redirects=False,
    ) as client:
        for u in candidates:
            try:
                r = await client.get(u)
            except httpx.HTTPError as e:
                hits.append({"url": u, "error": str(e)})
                continue
            listing = "<ListBucketResult" in r.text or "BlobPrefix" in r.text
            hits.append({
                "url": u,
                "status": r.status_code,
                "size": len(r.content),
                "listing_hint": listing,
                "interesting": r.status_code in (200, 403) or listing,
            })
    return {
        "name": name,
        "hits": hits,
        "open_listing": any(h.get("listing_hint") for h in hits),
    }


@mcp.tool(
    tags={"scan", "active"},
    annotations={"openWorldHint": True},
    timeout=90.0,
)
async def graphql_deep(
    url: str,
    auth_headers: dict[str, str] | None = None,
) -> dict:
    """Deeper GraphQL checks: batching, field suggestions, alias abuse, authz differential.

    Args:
        url: GraphQL endpoint.
        auth_headers: Optional auth headers for differential comparison.
    """
    result: dict = {"url": url}
    headers = {"Content-Type": "application/json", "User-Agent": UA}
    async with httpx.AsyncClient(
        timeout=15.0, verify=False, headers=headers, follow_redirects=False,
    ) as client:
        # Field suggestion leakage
        try:
            r = await client.post(url, json={"query": "{ __typenameX }"})
            errs = []
            try:
                errs = [e.get("message", "") for e in (r.json().get("errors") or [])]
            except ValueError:
                pass
            result["field_suggestion"] = any("Did you mean" in m for m in errs)
            result["suggestion_errors"] = errs[:5]
        except httpx.HTTPError as e:
            result["suggestion_error"] = str(e)

        # Batch array
        try:
            batch = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            r = await client.post(url, json=batch)
            result["batch_status"] = r.status_code
            try:
                data = r.json()
                result["batch_accepted"] = isinstance(data, list) and len(data) >= 2
            except ValueError:
                result["batch_accepted"] = False
                result["batch_preview"] = truncate(r.text, 300)
        except httpx.HTTPError as e:
            result["batch_error"] = str(e)

        # Alias amplification
        alias_q = "{" + " ".join(f"a{i}: __typename" for i in range(20)) + "}"
        try:
            r = await client.post(url, json={"query": alias_q})
            result["alias_status"] = r.status_code
            result["alias_ok"] = r.status_code == 200 and "__typename" in r.text
        except httpx.HTTPError as e:
            result["alias_error"] = str(e)

        # Authz differential on a common sensitive field guess
        sensitive = "{ __schema { queryType { name } } }"
        try:
            r_anon = await client.post(url, json={"query": sensitive})
            result["anon_introspection_status"] = r_anon.status_code
            result["anon_has_schema"] = "__schema" in r_anon.text
            if auth_headers:
                r_auth = await client.post(
                    url, json={"query": sensitive}, headers={**headers, **auth_headers}
                )
                result["auth_introspection_status"] = r_auth.status_code
                result["auth_has_schema"] = "__schema" in r_auth.text
                result["authz_diff"] = (
                    result["anon_has_schema"] != result["auth_has_schema"]
                )
        except httpx.HTTPError as e:
            result["authz_error"] = str(e)

    result["interesting"] = bool(
        result.get("field_suggestion")
        or result.get("batch_accepted")
        or result.get("anon_has_schema")
    )
    return result

