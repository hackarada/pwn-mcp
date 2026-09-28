"""pwn-mcp: security testing tools for web, API, and SPA applications.

Parent FastMCP server that mounts the category sub-servers and enforces
the optional authorized-target scope via middleware.
"""

from __future__ import annotations

import logging
import os

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.server.transforms import ResourcesAsTools
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from .browser import create_browser_proxy
from .guide import register as register_guide
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


mcp = FastMCP(
    "pwn-mcp",
    instructions=(
        "Security testing tools for authorized web, API, and SPA testing. "
        "Call list_resources, then read_resource with uri pwn://guide, before "
        "choosing tools. tools/list is the catalog. Tools return evidence; "
        "you decide what to follow. Only use against targets you are authorized "
        "to test."
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

register_guide(mcp)
# Tool-only clients cannot call resources/read. These two tools are read-only.
mcp.add_transform(ResourcesAsTools(mcp))

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
