"""Optional Playwright MCP integration via FastMCP's Proxy Provider.

When ``PWN_MCP_BROWSER=1`` and ``PWN_MCP_BROWSER_URL`` are set, mounts
[Playwright MCP](https://playwright.dev/mcp/introduction) into pwn-mcp over
HTTP so agents get ``browser_*`` tools (navigate, snapshot, click, …)
alongside recon/scan/proxy — single MCP endpoint, shared scope middleware.

Intended deploy: Compose profile ``browser`` runs
``mcr.microsoft.com/playwright/mcp`` as a sidecar; pwn-mcp proxies to
``http://playwright:8931/mcp``. Chromium's outbound HTTP proxy is configured
on the sidecar (``--proxy-server``), typically ``http://pwn-mcp:8080``.

See: https://gofastmcp.com/servers/providers/proxy
"""

from __future__ import annotations

import logging
import os

from fastmcp.server.providers.proxy import FastMCPProxy, StatefulProxyClient

logger = logging.getLogger("pwn_mcp.browser")

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def browser_enabled() -> bool:
    return os.environ.get("PWN_MCP_BROWSER", "").strip().lower() in _TRUTHY


def browser_mcp_url() -> str | None:
    """Upstream Playwright MCP Streamable HTTP URL, or None if unset."""
    url = os.environ.get("PWN_MCP_BROWSER_URL", "").strip()
    return url or None


def chromium_proxy_hint() -> str | None:
    """Documented Chromium outbound proxy (configured on the sidecar, not here)."""
    explicit = os.environ.get("PWN_MCP_BROWSER_PROXY", "").strip()
    if explicit:
        return explicit
    port = os.environ.get("PWN_MCP_PROXY_PORT", "").strip()
    if not port:
        return None
    host = os.environ.get("PWN_MCP_PROXY_HOST", "127.0.0.1").strip() or "127.0.0.1"
    if host in ("0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    return f"http://{host}:{port}"


def create_browser_proxy() -> FastMCPProxy | None:
    """Build a per-client FastMCP HTTP proxy to Playwright MCP, or None.

    Playwright state (page, cookies, refs) has to survive navigate, then
    snapshot, then click. ``StatefulProxyClient.new_stateful`` keeps one
    upstream session for each incoming MCP connection and closes it when
    that connection ends. A fresh session per call, or a single shared
    client closed by ``async with``, drops the page and deletes the
    upstream session on every ``tools/list``.
    """
    if not browser_enabled():
        return None

    url = browser_mcp_url()
    if not url:
        logger.warning(
            "PWN_MCP_BROWSER is set but PWN_MCP_BROWSER_URL is empty — "
            "set it to the Playwright MCP HTTP endpoint "
            "(e.g. http://playwright:8931/mcp)"
        )
        return None

    # One Playwright session per incoming MCP connection. Pair with
    # --shared-browser-context on the sidecar.
    backend = StatefulProxyClient(url)
    proxy = FastMCPProxy(
        client_factory=backend.new_stateful,
        name="playwright",
        provider_error_strategy="warn",
    )
    logger.info(
        "Mounted Playwright MCP via HTTP (%s); chromium_proxy_hint=%s",
        url,
        chromium_proxy_hint() or "(configure on sidecar)",
    )
    return proxy
