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


mcp = FastMCP(
    "pwn-mcp",
    instructions=(
        "Security testing toolkit for web applications, APIs, and SPAs "
        "(CTF, VDP, authorized internal testing). Tool namespaces: "
        "recon_* for HTTP/DNS/TLS/WebSocket reconnaissance, JS bundle and "
        "API-doc discovery, crypto_* for encoding and JWT/hash utilities, "
        "scan_* for port/dir/subdomain scanning, optional nmap/subfinder/"
        "nuclei wrappers (list tags/templates then scan), allowlisted "
        "cli_run for full CLI flags, and vuln probes, "
        "proxy_* for managing the embedded intercepting proxy and agent traffic telemetry. "
        "If a scope file is configured, active tools and proxy egress only run against "
        "in-scope targets. Only use against targets you are authorized to test."
    ),
    version="0.1.0",
    auth=_auth_from_env(),
)

mcp.mount(recon_mcp, namespace="recon")
mcp.mount(crypto_mcp, namespace="crypto")
mcp.mount(scan_mcp, namespace="scan")
mcp.mount(proxy_mcp, namespace="proxy")

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
