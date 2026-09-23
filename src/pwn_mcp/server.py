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

from .middleware import ScopeEnforcementMiddleware
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
        "jobs_* (background long scans — use when nuclei/nmap/cli_run/hashcat would "
        "exceed tool timeouts; poll jobs_status/jobs_result; kinds include "
        "cli_run, nuclei_scan, nmap_scan, subfinder_enum, monitor_subs, hash_crack), "
        "playbook_* (recon_surface, api_pass, xss_pass, web2_recon — returns summaries "
        "+ job ids for the agent to poll). "
        "Prefer typed tools; use scan_cli_run for full CLI flags on the allowlist "
        "(nuclei,subfinder,nmap,whois,dig,httpx,katana,naabu,dnsx,ffuf,assetfinder). "
        "For nuclei: scan_nuclei_list_tags → list_templates → scan or jobs_start. "
        "Agent owns session memory; MCP does not store recon notepads. "
        "5-minute kill signals: only 403/static pages, no APIs/JS endpoints, empty "
        "nuclei — move on. "
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
        "auth_required": bool(os.environ.get("PWN_MCP_AUTH_TOKEN", "").strip()),
    })


# Auto-start proxy if configured via environment
if os.environ.get("PWN_MCP_PROXY_PORT"):
    try:
        _auto_port = int(os.environ["PWN_MCP_PROXY_PORT"])
        _auto_host = os.environ.get("PWN_MCP_PROXY_HOST", "127.0.0.1")
        proxy_manager.start(host=_auto_host, port=_auto_port, scope=active_scope)
        logger.info(
            "Auto-started embedded proxy on %s:%d", _auto_host, _auto_port
        )
    except Exception as _e:
        logger.warning(
            "Failed to auto-start proxy on port %s: %s",
            os.environ.get("PWN_MCP_PROXY_PORT"),
            _e,
        )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
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
