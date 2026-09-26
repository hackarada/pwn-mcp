"""Web reconnaissance and HTTP analysis tools."""

from __future__ import annotations

import asyncio
import json
import math
import re
import socket
import ssl
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import httpx
from cryptography import x509
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import WebSocketException

from ..http_observe import baseline_from, classify, html_title, preview, project_json
from ..scope import load_scope
from ..util import MAX_BODY_CHARS, run_cmd, target_host, truncate, which

mcp = FastMCP("recon")

UA = "pwn-mcp/0.1 (security testing)"
_TIMEOUT = httpx.Timeout(15.0, connect=8.0)
_BATCH_MAX = 10
_MULTIPART_MAX = 2_000_000
_BODY_LIMIT_MAX = 100_000
_WS_STEP_MAX = 20


def _client(verify_tls: bool = False, follow_redirects: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=_TIMEOUT,
        verify=verify_tls,
        follow_redirects=follow_redirects,
        headers={"User-Agent": UA},
    )


def _body_limit(body_limit: int | None) -> int:
    if body_limit is None:
        return MAX_BODY_CHARS
    limit = int(body_limit)
    if limit < 1 or limit > _BODY_LIMIT_MAX:
        raise ToolError(f"body_limit must be between 1 and {_BODY_LIMIT_MAX}")
    return limit


def _multipart_files(parts: list[dict]) -> list[tuple]:
    """Build httpx file tuples. ``size`` pads ``content`` with A up to that many bytes."""
    if not parts:
        raise ToolError("multipart must contain at least one part")
    files: list[tuple] = []
    for index, part in enumerate(parts):
        if not isinstance(part, dict):
            raise ToolError(f"multipart[{index}] must be an object")
        name = part.get("name")
        if not isinstance(name, str) or not name:
            raise ToolError(f"multipart[{index}] needs a name")
        content = part.get("content") or ""
        if not isinstance(content, str):
            raise ToolError(f"multipart[{index}].content must be a string")
        raw = content.encode()
        if part.get("size") is not None:
            size = int(part["size"])
            if size < 0 or size > _MULTIPART_MAX:
                raise ToolError(
                    f"multipart size must be between 0 and {_MULTIPART_MAX}"
                )
            if len(raw) < size:
                raw = raw + (b"A" * (size - len(raw)))
            else:
                raw = raw[:size]
        elif len(raw) > _MULTIPART_MAX:
            raise ToolError(f"multipart content exceeds {_MULTIPART_MAX} bytes")
        filename = part.get("filename")
        if filename is not None and not isinstance(filename, str):
            raise ToolError(f"multipart[{index}].filename must be a string")
        content_type = part.get("content_type") or "application/octet-stream"
        if filename:
            files.append((name, (filename, raw, str(content_type))))
        else:
            files.append((name, (None, raw.decode("utf-8", "replace"))))
    return files


def _drop_content_type(headers: dict[str, str] | None) -> dict[str, str] | None:
    if not headers:
        return headers
    return {key: value for key, value in headers.items() if key.lower() != "content-type"}


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    params: dict[str, str] | None = None,
    fields: list[str] | None = None,
    multipart: list[dict] | None = None,
    body_limit: int | None = None,
    verify_tls: bool = False,
    follow_redirects: bool = True,
) -> dict:
    """Send an arbitrary HTTP request and inspect the response.

    This tool does not store cookies or tokens. When a JSON body contains a
    token, send it on the next call yourself: ``Authorization: Bearer <token>``
    and ``Cookie: token=<token>``. Some APIs ignore the header and read only
    the cookie.

    ``fields`` projects a JSON body before truncation. ``data[].name`` keeps
    ``name`` on each object in ``data``. Use it when ``body`` ends with a
    truncation note and you need a few keys from a large document.

    ``multipart`` builds a multipart body. Each part has ``name``, and
    optionally ``filename``, ``content``, ``content_type``, and ``size``.
    ``size`` is the exact byte length: ``content`` is padded with ``A`` or
    trimmed to fit, so a large file upload does not have to be pasted in.
    Do not send ``body`` and ``multipart`` together.

    Args:
        url: Full target URL, e.g. https://example.com/api/login.
        method: HTTP method (GET, POST, PUT, DELETE, OPTIONS, ...).
        headers: Request headers to send.
        body: Raw request body.
        params: Query parameters.
        fields: JSON paths to keep. ``[]`` walks a list (``data[].solved``).
        multipart: File or form parts. ``size`` pads with A up to 2000000 bytes.
        body_limit: Response characters to keep (default 8000, max 100000).
        verify_tls: Verify TLS certificates (default False for testing).
        follow_redirects: Follow 3xx redirects.
    """
    if body is not None and multipart:
        raise ToolError("pass body or multipart, not both")
    limit = _body_limit(body_limit)
    files = _multipart_files(multipart) if multipart else None
    request_headers = _drop_content_type(headers) if files else headers
    async with _client(verify_tls, follow_redirects) as client:
        try:
            resp = await client.request(
                method.upper(),
                url,
                headers=request_headers,
                content=None if files else body,
                files=files,
                params=params,
            )
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")
    text = resp.text
    result = {
        "status": resp.status_code,
        "reason": resp.reason_phrase,
        "url": str(resp.url),
        "headers": dict(resp.headers),
        "redirects": [str(r.url) for r in resp.history],
        "elapsed_ms": round(resp.elapsed.total_seconds() * 1000),
        "body_length": len(resp.content),
    }
    if fields:
        try:
            projected = project_json(json.loads(resp.text), fields)
        except json.JSONDecodeError:
            result["fields_applied"] = False
            result["fields_error"] = "response body is not JSON"
        else:
            text = json.dumps(projected, separators=(",", ":"))
            result["fields_applied"] = True
    result["body"] = truncate(text, limit)
    return result


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def http_batch(
    requests: list[dict],
    verify_tls: bool = False,
    follow_redirects: bool = True,
) -> dict:
    """Send up to 10 HTTP requests at the same time.

    Use this when the requests must overlap, such as a double-submit or a
    like race. One ``recon_http_request`` after another does not overlap.
    Each item needs ``url`` and may set ``method``, ``headers``, ``body``,
    and ``params``. Results stay in input order. Each request URL is
    scope-checked.

    Args:
        requests: 1 to 10 request objects.
        verify_tls: Verify TLS certificates (default False for testing).
        follow_redirects: Follow 3xx redirects.
    """
    if not isinstance(requests, list) or not requests:
        raise ToolError("requests must be a non-empty list")
    if len(requests) > _BATCH_MAX:
        raise ToolError(f"at most {_BATCH_MAX} requests")
    calls: list[dict] = []
    for index, req in enumerate(requests):
        url = req.get("url") if isinstance(req, dict) else None
        if not isinstance(url, str) or not url.strip():
            raise ToolError(f"requests[{index}] needs a url")
        method = req.get("method") or "GET"
        if not isinstance(method, str):
            raise ToolError(f"requests[{index}].method must be a string")
        req_headers = req.get("headers")
        if req_headers is not None and not isinstance(req_headers, dict):
            raise ToolError(f"requests[{index}].headers must be an object")
        req_body = req.get("body")
        if req_body is not None and not isinstance(req_body, str):
            raise ToolError(f"requests[{index}].body must be a string")
        req_params = req.get("params")
        if req_params is not None and not isinstance(req_params, dict):
            raise ToolError(f"requests[{index}].params must be an object")
        calls.append({
            "url": url,
            "method": method,
            "headers": req_headers,
            "body": req_body,
            "params": req_params,
        })

    results: list[dict | None] = [None] * len(calls)

    async def one(index: int, req: dict) -> None:
        try:
            response = await client.request(
                req["method"].upper(),
                req["url"],
                headers=req["headers"],
                content=req["body"],
                params=req["params"],
            )
        except httpx.HTTPError as exc:
            results[index] = {"index": index, "url": req["url"], "error": str(exc)}
            return
        results[index] = {
            "index": index,
            "status": response.status_code,
            "reason": response.reason_phrase,
            "url": str(response.url),
            "elapsed_ms": round(response.elapsed.total_seconds() * 1000),
            "body_length": len(response.content),
            "body": truncate(response.text, 2000),
        }

    async with _client(verify_tls, follow_redirects) as client:
        await asyncio.gather(*(one(index, req) for index, req in enumerate(calls)))
    return {"count": len(calls), "results": results}


_SECURITY_HEADERS = {
    "content-security-policy": ("CSP", "high"),
    "strict-transport-security": ("HSTS", "high"),
    "x-frame-options": ("clickjacking protection", "medium"),
    "x-content-type-options": ("MIME sniffing protection", "medium"),
    "referrer-policy": ("referrer leakage protection", "low"),
    "permissions-policy": ("browser feature restrictions", "low"),
    "cross-origin-opener-policy": ("COOP", "low"),
    "cross-origin-resource-policy": ("CORP", "low"),
}


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def security_headers(url: str) -> dict:
    """Audit a URL's HTTP response for missing/misconfigured security headers.

    Args:
        url: Full target URL.
    """
    async with _client() as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")
    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings = []
    for header, (desc, severity) in _SECURITY_HEADERS.items():
        if header in headers:
            findings.append(
                {"header": header, "status": "present", "value": headers[header]}
            )
        else:
            findings.append(
                {"header": header, "status": "MISSING", "severity": severity,
                 "impact": f"No {desc}"}
            )
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if header in headers:
            findings.append(
                {"header": header, "status": "info-disclosure",
                 "severity": "low", "value": headers[header]}
            )
    missing = sum(1 for f in findings if f["status"] == "MISSING")
    return {
        "url": str(resp.url),
        "status": resp.status_code,
        "missing_count": missing,
        "findings": findings,
    }


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=20.0,
)
async def tls_cert_info(host: str, port: int = 443) -> dict:
    """Fetch and analyze a host's TLS certificate.

    Args:
        host: Hostname to connect to.
        port: TLS port (default 443).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock, \
             ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            version = tls.version()
            cipher = tls.cipher()
    except OSError as e:
        raise ToolError(f"TLS connection failed: {e}")
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    now = datetime.now(UTC)
    expiry = cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": expiry.isoformat(),
        "days_until_expiry": (expiry - now).days,
        "expired": expiry < now,
        "signature_algorithm": getattr(
            cert.signature_algorithm_oid,
            "_name",
            getattr(cert.signature_algorithm_oid, "dotted_string", "unknown"),
        ),
        "subject_alt_names": sans,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "self_signed": cert.subject == cert.issuer,
    }


_BODY_MARKERS = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Next.js": [r"/_next/", r"__NEXT_DATA__"],
    "React": [r"data-reactroot", r"react-dom"],
    "Angular": [r"ng-app", r"ng-version", r"<app-root\b", r"data-beasties-container"],
    "Vue.js": [r"data-v-", r"__VUE__"],
    "jQuery": [r"jquery[.-]?\d", r"jQuery"],
    "Laravel": [r"laravel_session", r"csrf-token"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Drupal": [r"Drupal\.settings", r"/sites/default/files"],
    "Rails": [r"csrf-param.*authenticity_token", r"data-turbo"],
}
_COOKIE_MARKERS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Tomcat/JBoss)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "connect.sid": "Express.js",
    "csrftoken": "Django",
}


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def tech_fingerprint(url: str) -> dict:
    """Fingerprint web technologies from response headers, cookies, and body.

    Args:
        url: Full target URL.
    """
    async with _client() as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")
    detected: dict[str, str] = {}
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                   "x-drupal-cache", "x-backend-server"):
        if header in resp.headers:
            detected[header] = resp.headers[header]
    for cookie in resp.headers.get_list("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        if name in _COOKIE_MARKERS:
            detected[f"cookie:{name}"] = _COOKIE_MARKERS[name]
    body = resp.text[:200_000]
    for tech, patterns in _BODY_MARKERS.items():
        if any(re.search(p, body) for p in patterns):
            detected[tech] = "body marker"
    stack_bugs = _stack_bug_hints(detected, resp.headers, body)
    return {
        "url": str(resp.url),
        "status": resp.status_code,
        "title": html_title(body),
        "content_type": resp.headers.get("content-type", ""),
        "detected": detected,
        "stack_bug_hints": stack_bugs,
    }


_STACK_BUG_HINTS = {
    "WordPress": "plugins / REST auth / xmlrpc",
    "Next.js": "server-action SSRF / open redirect / middleware bypass",
    "Laravel": "mass assignment / IDOR / debug mode",
    "Django": "DEBUG / IDOR / SSRF via redirects",
    "Rails": "mass assignment / IDOR on :id / SSRF",
    "React": "client-side secrets in bundles / XSS sinks",
    "Angular": "template injection / XSS",
    "Vue.js": "client XSS / prototype pollution",
    "Express.js": "prototype pollution / path traversal",
    "PHP": "LFI / type juggling / unserialize",
    "Java (Tomcat/JBoss)": "actuators / deserialization / path traversal",
    "ASP.NET": "ViewState / ReturnUrl open redirect",
}


def _stack_bug_hints(detected: dict, headers, body: str) -> list[str]:
    hints: list[str] = []
    for key, val in detected.items():
        tech = key.split(":", 1)[-1] if key.startswith("cookie:") else key
        if tech in _STACK_BUG_HINTS:
            hints.append(f"{tech} → {_STACK_BUG_HINTS[tech]}")
        elif val in _STACK_BUG_HINTS:
            hints.append(f"{val} → {_STACK_BUG_HINTS[val]}")
    powered = (headers.get("x-powered-by") or "").lower()
    server = (headers.get("server") or "").lower()
    if "express" in powered:
        hints.append(f"Express.js → {_STACK_BUG_HINTS['Express.js']}")
    if "flask" in powered or "werkzeug" in server:
        hints.append("Flask → SSTI / SSRF")
    if "spring" in powered or "spring" in body[:4000].lower():
        hints.append("Spring → actuators / SpEL / IDOR")
    if "graphql" in body[:8000].lower():
        hints.append("GraphQL → introspection / mutation authz / batching")
    # dedupe preserve order
    seen: set[str] = set()
    out = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def fetch_robots(url: str) -> dict:
    """Fetch and parse robots.txt and sitemap.xml for a site.

    Args:
        url: Base site URL, e.g. https://example.com.
    """
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}" if "://" in url else url.rstrip("/")
    result: dict = {"base": base}
    async with _client() as client:
        try:
            r = await client.get(f"{base}/robots.txt")
            if r.status_code == 200:
                disallows, allows, sitemaps = [], [], []
                for line in r.text.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if low.startswith("disallow:"):
                        disallows.append(line.split(":", 1)[1].strip())
                    elif low.startswith("allow:"):
                        allows.append(line.split(":", 1)[1].strip())
                    elif low.startswith("sitemap:"):
                        sitemaps.append(line.split(":", 1)[1].strip())
                result["robots_txt"] = {
                    "found": True,
                    "disallow": [d for d in disallows if d],
                    "allow": [a for a in allows if a],
                    "sitemaps": sitemaps,
                }
            else:
                result["robots_txt"] = {"found": False, "status": r.status_code}
        except httpx.HTTPError as e:
            result["robots_txt"] = {"found": False, "error": str(e)}

        try:
            r = await client.get(f"{base}/sitemap.xml")
            if r.status_code == 200:
                locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
                result["sitemap_xml"] = {
                    "found": True, "url_count": len(locs), "urls": locs[:100],
                }
            else:
                result["sitemap_xml"] = {"found": False, "status": r.status_code}
        except httpx.HTTPError as e:
            result["sitemap_xml"] = {"found": False, "error": str(e)}
    return result


@mcp.tool(
    tags={"recon"},
    annotations={"openWorldHint": True, "readOnlyHint": True},
    timeout=30.0,
)
async def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """Resolve DNS records for a domain.

    Args:
        domain: Domain to query.
        record_type: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, or ALL.
    """
    types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"] \
        if record_type.upper() == "ALL" else [record_type.upper()]
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    records: dict[str, list[str]] = {}
    for rtype in types:
        try:
            answers = await resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException as e:
            records[rtype] = [f"error: {e}"]
    if not records:
        raise ToolError(f"No DNS records found for {domain}")
    return {"domain": domain, "records": records}


@mcp.tool(
    tags={"recon"},
    annotations={"openWorldHint": True, "readOnlyHint": True},
    timeout=30.0,
)
async def whois_lookup(target: str) -> str:
    """Run a WHOIS lookup via the local whois binary.

    Args:
        target: Domain or IP address.
    """
    if not which("whois"):
        raise ToolError("whois binary not found on PATH")
    return await asyncio.get_event_loop().run_in_executor(
        None, lambda: run_cmd(["whois", target], timeout=20)
    )


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def cors_check(url: str) -> dict:
    """Probe a URL's CORS policy with hostile Origin headers.

    Args:
        url: Full target URL.
    """
    host = urlparse(url).netloc
    origins = [
        f"https://evil-{host}",
        "null",
        f"https://{host}.evil.example",
        "https://attacker.example",
        f"http://{host}",  # scheme downgrade
    ]
    findings = []
    async with _client() as client:
        for origin in origins:
            try:
                resp = await client.get(url, headers={"Origin": origin})
            except httpx.HTTPError:
                continue
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if not acao:
                continue
            if acao == "*" and acac.lower() == "true":
                findings.append({"origin": origin, "acao": acao, "acac": acac,
                                 "severity": "info", "note": "wildcard + credentials is invalid per spec"})
            elif acao == "*" :
                findings.append({"origin": origin, "acao": acao,
                                 "severity": "info", "note": "wildcard ACAO (public content only)"})
            elif acao == origin:
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append({"origin": origin, "acao": acao, "acac": acac,
                                 "severity": sev,
                                 "note": f"arbitrary origin reflected ({origin})"})
    return {"url": url, "findings": findings,
            "vulnerable": any(f["severity"] in ("high", "medium") for f in findings)}


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def crawl_links(url: str) -> dict:
    """Fetch a page and extract links, forms, scripts, and HTML comments.

    Args:
        url: Full target URL.
    """
    async with _client() as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")
    body = resp.text
    base = str(resp.url)

    hrefs = {urljoin(base, m) for m in re.findall(r'''(?:href|src|action)=["']([^"']+)["']''', body, re.IGNORECASE)}
    scripts = sorted(u for u in hrefs if re.search(r"\.js($|\?)", u))
    forms = []
    for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
        attrs = form_match.group(1)
        inner = form_match.group(2)
        action_m = re.search(r'''action=["']?([^"'\s>]*)''', attrs, re.IGNORECASE)
        method_m = re.search(r'''method=["']?(\w+)''', attrs, re.IGNORECASE)
        inputs = re.findall(r'''name=["']([^"']+)["']''', inner, re.IGNORECASE)
        action = action_m.group(1) if action_m and action_m.group(1) else ""
        forms.append({
            "action": urljoin(base, action) if action else base,
            "method": (method_m.group(1).upper() if method_m else "GET"),
            "inputs": sorted(set(inputs)),
        })
    comments = [c.strip() for c in re.findall(r"<!--(.*?)-->", body, re.DOTALL)][:50]
    own = urlparse(base).netloc
    internal = sorted(u for u in hrefs if urlparse(u).netloc == own and u not in scripts)
    external = sorted(u for u in hrefs if urlparse(u).netloc not in ("", own) and u not in scripts)
    return {
        "url": base,
        "status": resp.status_code,
        "internal_links": internal[:200],
        "external_links": external[:100],
        "scripts": scripts[:100],
        "forms": forms,
        "comments": comments,
    }


_SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r'''(?i)aws[_-]?secret[_-]?access[_-]?key["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{40})''',
    "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z-]+",
    "github_token": r"gh[pousr]_[0-9A-Za-z]{36,}",
    "stripe_key": r"[sr]k_(live|test)_[0-9A-Za-z]{16,}",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
    "bearer_token": r'''(?i)bearer\s+([A-Za-z0-9\-_.=]{20,})''',
    "basic_auth_url": r'''[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+''',
    "generic_secret": r'''(?i)(api[_-]?key|apikey|secret|client_secret|auth[_-]?token|access[_-]?token)["'\s]*[:=]["'\s]*[0-9A-Za-z_\-]{16,}''',
}


def _find_secrets(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name, pattern in _SECRET_PATTERNS.items():
        matches = {m if isinstance(m, str) else m[0] for m in re.findall(pattern, text)}
        if matches:
            found[name] = sorted(
                {m[:14] + "…" if len(m) > 16 else m for m in matches}
            )[:20]
    # high-entropy strings (heuristic)
    entropy_hits = []
    for m in re.findall(r'''["']([A-Za-z0-9+/=_-]{32,})["']''', text):
        if _shannon(m) >= 4.5 and not m.startswith("http"):
            entropy_hits.append(m[:14] + "…")
    if entropy_hits:
        found["high_entropy"] = sorted(set(entropy_hits))[:15]
    return found


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_API_PATH = re.compile(r'''["'`]((?:/api|/v\d+|/graphql|/auth|/rest|/oauth)[^"'`\s]*)["'`]''')


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def js_analyze(url: str, max_bundles: int = 5) -> dict:
    """Analyze JavaScript (bundle or page) for API endpoints, secrets, and sourcemaps.

    If ``url`` is an HTML page, script srcs are extracted and analyzed.
    If it is a .js bundle, it is analyzed directly.

    Args:
        url: URL of a JS bundle or a page containing scripts.
        max_bundles: Max number of script files to fetch when given a page.
    """
    async with _client() as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}")

        bundles: dict[str, str] = {}
        text = resp.text
        if url.endswith(".js") or "javascript" in resp.headers.get(
                "content-type", ""):
            bundles[str(resp.url)] = text
        else:
            srcs = re.findall(r'''<script[^>]+src=["']([^"']+)["']''', text, re.IGNORECASE)
            for src in srcs[:max_bundles]:
                js_url = urljoin(str(resp.url), src)
                try:
                    r = await client.get(js_url)
                    if r.status_code == 200:
                        bundles[js_url] = r.text
                except httpx.HTTPError:
                    continue
        if not bundles:
            raise ToolError("No JavaScript content found to analyze")

        report: dict = {"analyzed": list(bundles), "bundles": {}}
        all_endpoints: set[str] = set()
        for js_url, js in bundles.items():
            endpoints = {m.strip() for m in _API_PATH.findall(js)}
            endpoints |= {m for m in re.findall(
                r'''["'`]((?:https?://[^"'`\s]+)/(?:api|v\d+|graphql|rest)[^"'`\s]*)["'`]''', js)}
            all_endpoints |= endpoints

            secrets_found = _find_secrets(js)
            sourcemap = None
            sm = re.search(r"//#\s*sourceMappingURL=(\S+)", js)
            if sm:
                map_url = urljoin(js_url, sm.group(1))
                sourcemap = {"url": map_url, "exposed": False}
                try:
                    r = await client.get(map_url)
                    if r.status_code == 200:
                        sourcemap["exposed"] = True
                        try:
                            sources = r.json().get("sources", [])
                            sourcemap["source_count"] = len(sources)
                            sourcemap["sources_sample"] = sources[:30]
                        except ValueError:
                            sourcemap["note"] = "map file not valid JSON"
                except httpx.HTTPError:
                    pass

            report["bundles"][js_url] = {
                "size": len(js),
                "endpoints": sorted(endpoints)[:100],
                "secrets": secrets_found,
                "sourcemap": sourcemap,
            }
        report["all_endpoints"] = sorted(all_endpoints)[:200]
        return report


_API_DOC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/api/openapi.json", "/api/swagger.json",
    "/redoc", "/rapidoc", "/graphql", "/graphiql", "/playground",
    "/api/graphql", "/api/schema", "/actuator", "/actuator/mappings",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/oauth2/.well-known/openid-configuration",
]


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def api_discover(url: str, extra_paths: list[str] | None = None) -> dict:
    """Probe a host for exposed API documentation, schemas, and spec endpoints.

    Responses that are the same document as the site index are returned in
    ``spa_shells``, not ``found``. A catch-all HTML 200 is not an API document.

    Args:
        url: Base URL, e.g. https://api.example.com.
        extra_paths: Additional paths to probe.
    """
    base = url.rstrip("/")
    paths = _API_DOC_PATHS + [p for p in (extra_paths or [])]
    found = []
    spa_shells = []
    async with _client(follow_redirects=False) as client:
        baseline = await _index_baseline(client, base)
        for path in paths:
            try:
                r = await client.get(f"{base}{path}")
            except httpx.HTTPError:
                continue
            if r.status_code == 404:
                continue
            entry = _observed(path, r, baseline)
            if entry["kind"] == "spa_shell":
                spa_shells.append(entry)
            else:
                found.append(entry)
    return {
        "base": base,
        "found": found,
        "spa_shells": spa_shells,
        "probed": len(paths),
    }


def _observed(path: str, response: httpx.Response, baseline: dict | None) -> dict:
    content_type = response.headers.get("content-type", "")
    kind = classify(
        status=response.status_code,
        content_type=content_type,
        body=response.text,
        baseline=baseline,
    )
    entry = {
        "path": path if path.startswith("/") else "/" + path,
        "status": response.status_code,
        "content_type": content_type,
        "size": len(response.content),
        "kind": kind,
    }
    title = html_title(response.text)
    if title and kind != "spa_shell":
        entry["title"] = title
    if kind == "json":
        entry["preview"] = preview(response.text, 500)
    elif kind == "directory_listing":
        hrefs = re.findall(r"""href=["']([^"'#?]+)["']""", response.text, re.IGNORECASE)
        entry["entries"] = [href for href in hrefs if href not in ("/", ".", "..")][:40]
    return entry


async def _index_baseline(client: httpx.AsyncClient, base: str) -> dict | None:
    try:
        index = await client.get(base if base.endswith("/") else base + "/")
    except httpx.HTTPError:
        return None
    if index.status_code != 200:
        return None
    return baseline_from(index.text)


def _same_origin_path(base: str, raw: str) -> str | None:
    """Return a path on *base*, or None when *raw* points at another host."""
    text = raw.strip()
    if not text or text.startswith("//"):
        return None
    if "://" in text:
        parsed = urlparse(text)
        base_host = urlparse(base).netloc
        if parsed.netloc.lower() != base_host.lower():
            return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    if not text.startswith("/"):
        text = "/" + text
    return text


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=60.0,
)
async def probe_paths(url: str, paths: list[str], limit: int = 40) -> dict:
    """GET specific paths and label each response.

    Use this after robots.txt, a crawl, or ``js_analyze`` to see which of
    those paths are real documents. ``kind`` is ``spa_shell`` when the body
    matches the site index, ``json`` for a JSON body, ``directory_listing``
    for an index page, and ``html`` / ``text`` / ``error`` otherwise.

    The tool does not rank or drop paths. The caller decides what to request
    next. Paths on a different host are skipped.

    Args:
        url: Base URL, e.g. https://app.example/.
        paths: Relative paths or same-host absolute URLs.
        limit: Max paths to request (default 40, capped at 60).
    """
    base = url.rstrip("/")
    cap = max(1, min(int(limit), 60))
    selected: list[str] = []
    skipped_other_host: list[str] = []
    for raw in paths:
        if not isinstance(raw, str):
            continue
        path = _same_origin_path(base, raw)
        if path is None:
            skipped_other_host.append(raw)
            continue
        if path not in selected:
            selected.append(path)
        if len(selected) >= cap:
            break

    results: list[dict] = []
    async with _client(follow_redirects=False) as client:
        baseline = await _index_baseline(client, base)
        sem = asyncio.Semaphore(10)

        async def one(path: str) -> None:
            async with sem:
                try:
                    response = await client.get(f"{base}{path}")
                except httpx.HTTPError as exc:
                    results.append({"path": path, "error": str(exc)})
                    return
            entry = _observed(path, response, baseline)
            if entry["kind"] not in ("spa_shell", "json", "directory_listing"):
                entry["preview"] = preview(response.text, 240)
            results.append(entry)

        await asyncio.gather(*(one(path) for path in selected))

    results.sort(key=lambda item: item.get("path", ""))
    return {
        "base": base,
        "tested": len(selected),
        "skipped_other_host": skipped_other_host[:20],
        "results": results,
    }


def _ws_record(frame: str | bytes, text: str) -> dict:
    if isinstance(frame, bytes):
        return {"type": "binary", "size": len(frame), "data": truncate(text)}
    return {"type": "text", "size": len(frame), "data": truncate(text)}


def _validate_ws_steps(steps: list) -> None:
    if len(steps) > _WS_STEP_MAX:
        raise ToolError(f"at most {_WS_STEP_MAX} websocket steps")
    for step in steps:
        if not isinstance(step, dict):
            raise ToolError("each websocket step must be an object")
        has_send = "send" in step
        has_wait = "wait_prefix" in step
        if has_send == has_wait:
            raise ToolError("each websocket step needs exactly one of send or wait_prefix")
        if has_send and not isinstance(step["send"], str):
            raise ToolError("send must be a string")
        if has_wait and not isinstance(step["wait_prefix"], str):
            raise ToolError("wait_prefix must be a string")


async def _run_ws_steps(
    ws,
    steps: list[dict],
    sent: list[str],
    received: list[dict],
    max_messages: int,
    recv_timeout: float,
) -> list[dict]:
    script: list[dict] = []
    for step in steps:
        if "send" in step:
            message = step["send"]
            await ws.send(message)
            sent.append(message)
            script.append({"send": message})
            continue
        prefix = step["wait_prefix"]
        timeout = float(step.get("timeout", recv_timeout))
        matched = False
        while len(received) < max_messages:
            try:
                frame = await asyncio.wait_for(ws.recv(), timeout=timeout)
            except TimeoutError:
                break
            text = frame.decode("utf-8", "replace") if isinstance(frame, bytes) else frame
            received.append(_ws_record(frame, text))
            if text.startswith(prefix):
                matched = True
                break
        script.append({"wait_prefix": prefix, "matched": matched})
    return script


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def websocket_probe(
    url: str,
    messages: list[str] | None = None,
    steps: list[dict] | None = None,
    headers: dict[str, str] | None = None,
    subprotocols: list[str] | None = None,
    max_messages: int = 10,
    recv_timeout: float = 3.0,
    open_timeout: float = 8.0,
    verify_tls: bool = False,
) -> dict:
    """Connect to a WebSocket endpoint, optionally send messages, and capture replies.

    ``messages`` sends every frame immediately, then reads. ``steps`` is a
    script for protocols that must ack before the next frame. Each step is
    ``{"send": "40"}`` or ``{"wait_prefix": "40", "timeout": 2}``. A wait
    reads until a frame starts with that prefix. Socket.io: wait for ``0``,
    send ``40``, wait for ``40``, then send the event. After the script the
    probe still reads until ``max_messages`` or ``recv_timeout``.

    Args:
        url: WebSocket URL, e.g. ws://host/path or wss://host/path.
        messages: Text frames to send immediately after connect (default: none).
        steps: Ordered send / wait_prefix script. Do not combine with messages.
        headers: Extra handshake headers (Origin, Authorization, cookies, ...).
        subprotocols: Optional Sec-WebSocket-Protocol values.
        max_messages: Max frames to collect (sent echoes + unsolicited).
        recv_timeout: Seconds to wait for each inbound frame before stopping.
        open_timeout: Handshake timeout in seconds.
        verify_tls: Verify TLS certificates for wss:// (default False for testing).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        raise ToolError("url must use ws:// or wss:// scheme")
    if max_messages < 1:
        raise ToolError("max_messages must be >= 1")

    ssl_ctx: ssl.SSLContext | bool | None = None
    if parsed.scheme == "wss":
        if verify_tls:
            ssl_ctx = True
        else:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    if steps and messages:
        raise ToolError("pass steps or messages, not both")
    if steps:
        _validate_ws_steps(steps)

    sent: list[str] = []
    received: list[dict] = []
    negotiated: str | None = None
    script: list[dict] | None = None

    try:
        async with ws_connect(
            url,
            additional_headers=headers,
            subprotocols=subprotocols,
            open_timeout=open_timeout,
            close_timeout=3.0,
            ping_interval=None,
            ssl=ssl_ctx,
        ) as ws:
            negotiated = ws.subprotocol
            if steps:
                script = await _run_ws_steps(
                    ws, steps, sent, received, max_messages, recv_timeout,
                )
            else:
                for msg in messages or []:
                    await ws.send(msg)
                    sent.append(msg)
            while len(received) < max_messages:
                try:
                    frame = await asyncio.wait_for(ws.recv(), timeout=recv_timeout)
                except TimeoutError:
                    break
                text = frame.decode("utf-8", "replace") if isinstance(frame, bytes) else frame
                received.append(_ws_record(frame, text))
    except (WebSocketException, OSError, TimeoutError) as e:
        raise ToolError(f"WebSocket probe failed: {e}") from e

    result = {
        "url": url,
        "connected": True,
        "subprotocol": negotiated,
        "sent": sent,
        "received": received,
        "received_count": len(received),
    }
    if script is not None:
        result["script"] = script
    return result


@mcp.tool(
    tags={"recon"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def scope_check(target: str) -> dict:
    """Check whether a target URL, hostname, or IP is authorized under the active scope.

    Args:
        target: Target URL, host, or IP, e.g. 'https://api.example.com/v1'.
    """
    scope = load_scope()
    host = target_host(target)
    if not host:
        return {"target": target, "host": "", "allowed": False, "reason": "invalid_target"}
    if scope is None:
        return {
            "target": target,
            "host": host,
            "allowed": True,
            "scope_configured": False,
            "reason": "unrestricted (no scope configured)",
        }
    allowed = await scope.is_allowed(host)
    return {
        "target": target,
        "host": host,
        "allowed": allowed,
        "scope_configured": True,
        "scope_source": scope.source,
        "reason": "in_scope" if allowed else "outside_scope",
    }


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=45.0,
)
async def secrets_scan(url: str, body: str | None = None) -> dict:
    """Scan a URL response (or supplied body) for secrets and high-entropy tokens.

    Args:
        url: URL to fetch when body is omitted.
        body: Optional raw text to scan instead of fetching.
    """
    source = "body"
    text = body or ""
    meta: dict = {"url": url}
    if body is None:
        source = "fetched"
        async with _client() as client:
            try:
                r = await client.get(url)
            except httpx.HTTPError as e:
                raise ToolError(f"Request failed: {e}") from e
            text = r.text
            meta["status"] = r.status_code
            meta["content_type"] = r.headers.get("content-type", "")
    secrets = _find_secrets(text[:500_000])
    return {**meta, "source": source, "secrets": secrets, "hit_types": list(secrets)}


@mcp.tool(
    tags={"recon", "active"},
    annotations={"openWorldHint": True},
    timeout=30.0,
)
async def session_extract(url: str, headers: dict[str, str] | None = None) -> dict:
    """Fetch a page and extract cookies, CSRF tokens, and auth-related form fields.

    Args:
        url: Page URL (login or any authenticated page).
        headers: Optional request headers (e.g. Cookie for an existing session).
    """
    async with _client() as client:
        try:
            r = await client.get(url, headers=headers or {})
        except httpx.HTTPError as e:
            raise ToolError(f"Request failed: {e}") from e

    cookies = []
    for raw in r.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        cookies.append({
            "name": name,
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": (
                "none" if "samesite=none" in attrs
                else "lax" if "samesite=lax" in attrs
                else "strict" if "samesite=strict" in attrs
                else None
            ),
        })

    csrf_patterns = [
        r'''(?i)name=["']csrf[^"']*["'][^>]*value=["']([^"']+)["']''',
        r'''(?i)name=["']_token["'][^>]*value=["']([^"']+)["']''',
        r'''(?i)name=["']authenticity_token["'][^>]*value=["']([^"']+)["']''',
        r'''(?i)name=["']__RequestVerificationToken["'][^>]*value=["']([^"']+)["']''',
        r'''(?i)<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']''',
        r'''(?i)csrfmiddlewaretoken["'\s]*value=["']([^"']+)["']''',
    ]
    csrf_tokens = []
    for pat in csrf_patterns:
        for m in re.findall(pat, r.text):
            csrf_tokens.append(m[:80])

    return {
        "url": str(r.url),
        "status": r.status_code,
        "cookies": cookies,
        "csrf_tokens": sorted(set(csrf_tokens))[:20],
        "set_cookie_count": len(cookies),
    }


@mcp.tool(
    tags={"recon"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def url_triage(urls: list[str], patterns: list[str] | None = None) -> dict:
    """Triage a caller-supplied URL list into gf-style buckets (no network).

    Args:
        urls: Absolute or relative URLs / paths to classify.
        patterns: Optional subset of buckets: interesting_params, api, admin,
            auth, upload, redirect, ssrf, idor, debug.
    """
    return _triage_urls(urls, patterns)


_GF_PATTERNS: dict[str, re.Pattern[str]] = {
    "interesting_params": re.compile(
        r"[?&](id|user|user_id|uid|account|file|path|filepath|doc|document|"
        r"url|uri|redirect|next|return|dest|destination|continue|src|source|"
        r"token|key|api_key|apikey|secret|callback|ref)=",
        re.I,
    ),
    "api": re.compile(r"/api/|/v\d+/|/graphql|/rest/|/swagger|/openapi", re.I),
    "admin": re.compile(r"/admin|/internal|/debug|/console|/manage|/dashboard|/backoffice", re.I),
    "auth": re.compile(r"/oauth|/login|/logout|/auth|/sso|/saml|/callback|/token|/session|/register|/signup", re.I),
    "upload": re.compile(r"upload|attachment|avatar|document|import|file", re.I),
    "redirect": re.compile(r"[?&](redirect|next|url|return|returnTo|continue|dest|destination|goto|r)=", re.I),
    "ssrf": re.compile(r"[?&](url|uri|path|dest|redirect|proxy|fetch|webhook|callback|target|host)=", re.I),
    "idor": re.compile(r"/(\d{2,})(?:/|$|\?)|[?&](id|user_id|uid|account_id|order_id)=\d+", re.I),
    "debug": re.compile(r"/debug|/trace|/actuator|/metrics|/env|/phpinfo|/server-status|/\.git", re.I),
}


def _triage_urls(urls: list[str], patterns: list[str] | None = None) -> dict:
    wanted = patterns or list(_GF_PATTERNS)
    buckets: dict[str, list[str]] = {k: [] for k in wanted if k in _GF_PATTERNS}
    unknown = [k for k in wanted if k not in _GF_PATTERNS]
    for u in urls:
        for name, cre in _GF_PATTERNS.items():
            if name in buckets and cre.search(u):
                buckets[name].append(u)
    return {
        "buckets": {k: v[:80] for k, v in buckets.items()},
        "counts": {k: len(v) for k, v in buckets.items()},
        "input_count": len(urls),
        "unknown_patterns": unknown,
    }

