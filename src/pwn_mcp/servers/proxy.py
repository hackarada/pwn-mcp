"""FastMCP tool server for managing the in-server proxy and agent traffic telemetry."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ..proxy_server import proxy_manager

mcp = FastMCP("proxy")


@mcp.tool(
    tags={"proxy"},
    annotations={"openWorldHint": False},
)
async def start(
    port: int = 8080,
    host: str = "127.0.0.1",
    custom_headers: dict[str, str] | None = None,
) -> dict:
    """Start the embedded intercepting proxy server for agent traffic.

    Agents, Playwright/Chromium browsers, curl, or Python SDKs can route traffic
    through this proxy (HTTP_PROXY=http://127.0.0.1:8080). The proxy strictly
    enforces the authorized target scope, injects custom headers, and records
    all traffic for inspection.

    Args:
        port: Listening port (default 8080).
        host: Listening bind address (default 127.0.0.1).
        custom_headers: Headers to automatically inject into all outbound requests
            (e.g. {'X-HackerOne-Research': 'myhandle'}).
    """
    import asyncio
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: proxy_manager.start(host=host, port=port, custom_headers=custom_headers),
        )
    except Exception as e:
        raise ToolError(f"Failed to start proxy: {e}")


@mcp.tool(
    tags={"proxy"},
    annotations={"openWorldHint": False},
)
async def stop() -> dict:
    """Stop the running embedded proxy server."""
    import asyncio
    return await asyncio.get_event_loop().run_in_executor(None, proxy_manager.stop)


@mcp.tool(
    tags={"proxy"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def status() -> dict:
    """Get the running status, configuration, port, CA cert path, and counters of the proxy."""
    return proxy_manager.get_status()


@mcp.tool(
    tags={"proxy"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def history(
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    limit: int = 50,
) -> list[dict]:
    """Inspect captured HTTP/HTTPS traffic flows intercepted by the proxy (like Burp HTTP history).

    Args:
        host: Filter by substring of target host.
        method: Filter by HTTP method (GET, POST, etc.).
        status: Filter by HTTP status code (e.g. 200, 403).
        limit: Max number of most-recent records to return (default 50).
    """
    return proxy_manager.get_history(host=host, method=method, status=status, limit=limit)


@mcp.tool(
    tags={"proxy"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def get_traffic(flow_id: str) -> dict:
    """Fetch full request and response headers and body details for a specific flow ID.

    Args:
        flow_id: The ID of the flow from proxy_history.
    """
    flow = proxy_manager.get_flow(flow_id)
    if not flow:
        raise ToolError(f"Flow ID '{flow_id}' not found in traffic history")
    return flow


@mcp.tool(
    tags={"proxy"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def endpoints() -> dict:
    """Aggregate attack surface inventory discovered across all intercepted traffic.

    Returns deduplicated endpoints, methods, query parameters, and observed status codes.
    """
    return proxy_manager.get_endpoints()


@mcp.tool(
    tags={"proxy"},
    annotations={"openWorldHint": False},
)
def set_headers(headers: dict[str, str]) -> dict:
    """Dynamically add or update custom headers that the proxy injects into all outbound requests.

    Args:
        headers: Key-value header pairs to inject.
    """
    return proxy_manager.set_custom_headers(headers)


@mcp.tool(
    tags={"proxy"},
    annotations={"openWorldHint": False},
)
def clear() -> dict:
    """Clear the in-memory traffic history buffer."""
    return proxy_manager.clear_history()
