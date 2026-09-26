"""pwn-mcp: security testing tools for web, API, and SPA applications.

Parent FastMCP server that mounts the category sub-servers and enforces
the optional authorized-target scope via middleware.
"""

from __future__ import annotations

import logging
import os

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from .browser import create_browser_proxy
from .middleware import ScopeEnforcementMiddleware, ToolSchemaMiddleware
from .proxy_server import proxy_manager
from .scope import load_scope
from .servers.crypto import mcp as crypto_mcp
from .servers.jobs import mcp as jobs_mcp
from .servers.playbook import mcp as playbook_mcp
from .servers.proxy import mcp as proxy_mcp
from .servers.recon import mcp as recon_mcp
from .servers.scan import mcp as scan_mcp

logger = logging.getLogger("pwn_mcp")

active_scope = load_scope()
browser_mounted = False


def _auth_from_env() -> StaticTokenVerifier | None:
    """Optional shared bearer token for remote HTTP deployments.

    Set ``PWN_MCP_AUTH_TOKEN`` to require ``Authorization: Bearer <token>``.
    Leave unset for local/stdio or private-network use.
    """
    token = os.environ.get("PWN_MCP_AUTH_TOKEN", "").strip()
    if not token:
        return None
    return StaticTokenVerifier(
        tokens={token: {"client_id": "pwn-mcp", "scopes": ["mcp"]}},
        required_scopes=["mcp"],
    )


_STACK_BUG_MAP = (
    "Stack→bug hints: Rails/Laravel/Django→IDOR/mass-assignment; Flask→SSTI/SSRF; "
    "Express→prototype pollution; Spring→actuators; Next.js→server-action SSRF; "
    "GraphQL→introspection/mutation authz; WordPress→plugins/REST. "
    "See recon_tech_fingerprint.stack_bug_hints."
)

mcp = FastMCP(
    "pwn-mcp",
    instructions=(
        "Security testing toolkit for web/API/SPA (CTF, VDP, authorized testing). "
        "Namespaces: recon_* (HTTP/DNS/TLS/WS/JS/API/session/secrets/url_triage), "
        "crypto_* (encode/JWT/jwt_attack/hash + hash_crack_enqueue), "
        "scan_* (ports/dirs/vuln probes + PD wrappers + ssrf/idor/cache/host/"
        "takeover/buckets/graphql_deep + nmap/subfinder/nuclei/cli_run), "
        "proxy_* (history, intercept/resume, replay, match_replace, export_har/burp), "
        "browser_* (optional Playwright HTTP sidecar — navigate/snapshot/click/type "
        "for SPAs; route Chromium through proxy_* via PWN_MCP_BROWSER_PROXY), "
        "jobs_* (background long scans — use when nuclei/nmap/cli_run/hashcat would "
        "exceed tool timeouts; poll jobs_status/jobs_result; kinds include "
        "cli_run, nuclei_scan, nmap_scan, subfinder_enum, monitor_subs, hash_crack), "
        "playbook_* (recon_surface, api_pass, xss_pass, web2_recon — batches calls "
        "and returns step data + job ids; it does not conclude the test). "
        "recon_probe_paths labels each path: json, html, text, directory_listing, "
        "error, or spa_shell when the body matches the site index. A 200 HTML "
        "spa_shell is the catch-all page, not an API document. "
        "Prefer typed tools; use scan_cli_run for full CLI flags on the allowlist "
        "(nuclei,subfinder,nmap,whois,dig,httpx,katana,naabu,dnsx,ffuf,assetfinder). "
        "For nuclei: scan_nuclei_list_tags → list_templates → scan or jobs_start. "
        "For SPAs: browser_navigate → browser_snapshot → interact by ref; "
        "then proxy_endpoints / proxy_history for XHR inventory. "
        "scan_sqli_probe content_type=json POSTs a JSON field; form is the default. "
        "scan_reflected_xss_probe and playbook xss_pass only see server-side reflection. "
        "appears_encoded or reflection_in_error means the payload was escaped or "
        "the hit was an error page, not a confirmed XSS. "
        "recon_http_request fields projects a JSON body before truncation "
        "(data[].name walks a list). body_limit raises that cap up to 100000. "
        "multipart builds a file field from name, filename, content, and size. "
        "recon_http_batch sends up to 10 requests at once for a race or "
        "double-submit. recon_websocket_probe steps is a script of send or "
        "wait_prefix; use it when the server must ack before the next frame "
        "(socket.io: wait for 0, send 40, wait for 40, then send the event). "
        "crypto_jwt_sign accepts RS256, RS384, and RS512 with private_key_pem, "
        "and secret_encoding=base64 for a raw HMAC key. crypto_totp returns a "
        "fresh code for a base32 secret. "
        "Browser tools run in the Playwright sidecar. 127.0.0.1 and localhost "
        "there are the sidecar, not the host. For an app published on the Docker "
        "host, open http://host.docker.internal:<port>/. "
        "Agent owns session memory and decides what to follow. MCP does not store "
        "tokens or recon notepads and does not tell you to stop. A token in a "
        "JSON body must be sent on the next request as Authorization: Bearer "
        "and Cookie: token=... . "
        f"{_STACK_BUG_MAP} "
        "If a scope file is configured, active tools only run in-scope. "
        "Only use against targets you are authorized to test."
    ),
    version="0.1.0",
    auth=_auth_from_env(),
)

mcp.mount(recon_mcp, namespace="recon")
mcp.mount(crypto_mcp, namespace="crypto")
mcp.mount(scan_mcp, namespace="scan")
mcp.mount(proxy_mcp, namespace="proxy")
mcp.mount(jobs_mcp, namespace="jobs")
mcp.mount(playbook_mcp, namespace="playbook")

_browser = create_browser_proxy()
if _browser is not None:
    # No extra namespace: Playwright tools are already named browser_*.
    mcp.mount(_browser)
    browser_mounted = True

# Outermost: normalize schemas after every other list_tools hook has run.
mcp.add_middleware(ToolSchemaMiddleware())
mcp.add_middleware(ScopeEnforcementMiddleware(active_scope))


@mcp.custom_route("/health", methods=["GET"])
async def health_check(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.custom_route("/ready", methods=["GET"])
async def ready_check(_request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ready",
        "scope_configured": active_scope is not None,
        "proxy_running": proxy_manager.is_running(),
        "browser_enabled": browser_mounted,
        "auth_required": bool(os.environ.get("PWN_MCP_AUTH_TOKEN", "").strip()),
    })


def _autostart_proxy() -> None:
    """Start the embedded proxy when PWN_MCP_PROXY_PORT is set.

    Runs from main() so logging is configured. Importing this module must
    not bind a port (tests import it).
    """
    raw = os.environ.get("PWN_MCP_PROXY_PORT", "").strip()
    if not raw:
        return
    try:
        port = int(raw)
    except ValueError:
        logger.warning("PWN_MCP_PROXY_PORT=%r is not an integer; proxy not started", raw)
        return
    host = os.environ.get("PWN_MCP_PROXY_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        proxy_manager.start(host=host, port=port, scope=active_scope)
    except Exception as exc:
        logger.warning("Failed to auto-start proxy on %s:%s: %s", host, raw, exc)
        return
    logger.info("Auto-started embedded proxy on %s:%d", host, port)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    _autostart_proxy()
    transport = os.environ.get("PWN_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("http", "streamable-http", "sse"):
        host = os.environ.get("PWN_MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("PWN_MCP_PORT", "8000"))
        logger.info("Starting pwn-mcp transport=%s on %s:%d", transport, host, port)
        mcp.run(transport=transport, host=host, port=port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
