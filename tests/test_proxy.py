"""Tests for the embedded mitmproxy server and proxy_* MCP tools.

Proxy lifecycle (start/stop/status) is tested directly against the
ProxyManager singleton since it's a threading manager.
Traffic capture tools are tested through the MCP client.
"""

import httpx
import pytest
from fastmcp import Client

from pwn_mcp.proxy_server import proxy_manager
from pwn_mcp.scope import Scope


@pytest.fixture(autouse=True)
def ensure_proxy_stopped():
    """Stop the proxy before and after each test for isolation."""
    proxy_manager.stop()
    yield
    proxy_manager.stop()


# ────────────────────────────────────────────
# 1. Lifecycle (direct manager calls)
# ────────────────────────────────────────────


def test_proxy_lifecycle_direct():
    assert not proxy_manager.is_running()

    status = proxy_manager.start(host="127.0.0.1", port=18090)
    assert status["running"] is True
    assert status["port"] == 18090
    assert "proxy_url" in status
    assert "agent_env_setup" in status

    assert proxy_manager.is_running()

    stopped = proxy_manager.stop()
    assert stopped["status"] == "stopped"
    assert not proxy_manager.is_running()


def test_proxy_already_running_returns_status():
    proxy_manager.start(host="127.0.0.1", port=18091)
    result = proxy_manager.start(host="127.0.0.1", port=18091)
    assert result["status"] == "already_running"
    assert result["port"] == 18091


def test_proxy_stop_when_not_running():
    result = proxy_manager.stop()
    assert result["status"] == "not_running"


# ────────────────────────────────────────────
# 2. Scope Enforcement (direct manager + httpx)
# ────────────────────────────────────────────


def test_proxy_blocks_out_of_scope(http_server: str):
    scope = Scope.parse("127.0.0.1\nlocalhost\n!blocked.example")
    proxy_manager.start(host="127.0.0.1", port=18092, scope=scope)
    proxy_url = "http://127.0.0.1:18092"

    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        r = client.get(f"{http_server}/json")
        assert r.status_code == 200

        r_blocked = client.get("http://blocked.example/private")
        assert r_blocked.status_code == 403
        assert "outside the authorized scope" in r_blocked.text


# ────────────────────────────────────────────
# 3. Traffic History and Endpoints (direct manager)
# ────────────────────────────────────────────


def test_proxy_history_and_endpoints(http_server: str):
    scope = Scope.parse("127.0.0.1\nlocalhost")
    proxy_manager.start(
        host="127.0.0.1",
        port=18093,
        scope=scope,
        custom_headers={"X-Agent-Scanner": "pwn-agent"},
    )
    proxy_url = "http://127.0.0.1:18093"

    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        client.get(f"{http_server}/json")
        client.get(f"{http_server}/admin")

    history = proxy_manager.get_history(limit=10)
    assert len(history) >= 2
    assert all(h["scope_status"] == "allowed" for h in history)

    latest = history[0]
    assert latest["method"] == "GET"
    assert latest["status_code"] is not None

    flow = proxy_manager.get_flow(latest["id"])
    assert flow is not None
    assert flow["id"] == latest["id"]

    endpoints = proxy_manager.get_endpoints()
    assert endpoints["total_unique"] >= 2
    paths = {ep["path"] for ep in endpoints["endpoints"]}
    assert "/json" in paths
    assert "/admin" in paths


def test_proxy_history_blocked_flows(http_server: str):
    scope = Scope.parse("127.0.0.1\n!blocked.example")
    proxy_manager.start(host="127.0.0.1", port=18094, scope=scope)
    proxy_url = "http://127.0.0.1:18094"

    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        client.get(f"{http_server}/json")
        client.get("http://blocked.example/secret")

    all_history = proxy_manager.get_history(limit=20)
    blocked = [h for h in all_history if h["scope_status"] == "blocked"]
    allowed = [h for h in all_history if h["scope_status"] == "allowed"]
    assert len(blocked) >= 1
    assert len(allowed) >= 1
    assert any("blocked.example" in h["host"] for h in blocked)


def test_proxy_history_filtering(http_server: str):
    scope = Scope.parse("127.0.0.1\nlocalhost")
    proxy_manager.start(host="127.0.0.1", port=18095, scope=scope)
    proxy_url = "http://127.0.0.1:18095"

    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        client.get(f"{http_server}/json")
        client.get(f"{http_server}/admin")

    # Filter by host
    history = proxy_manager.get_history(host="127.0.0.1", limit=10)
    assert all("127.0.0.1" in h["host"] for h in history)

    # Filter by method
    get_only = proxy_manager.get_history(method="GET", limit=10)
    assert all(h["method"] == "GET" for h in get_only)

    # Filter by status
    ok_only = proxy_manager.get_history(status=200, limit=10)
    assert all(h["status_code"] == 200 for h in ok_only)


def test_proxy_set_headers_and_clear(http_server: str):
    scope = Scope.parse("127.0.0.1\nlocalhost")
    proxy_manager.start(host="127.0.0.1", port=18096, scope=scope)

    result = proxy_manager.set_custom_headers({"X-Custom": "test-value"})
    assert result["status"] == "updated"
    assert result["custom_headers"]["X-Custom"] == "test-value"

    proxy_url = "http://127.0.0.1:18096"
    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        client.get(f"{http_server}/json")

    history = proxy_manager.get_history(limit=5)
    assert len(history) >= 1

    cleared = proxy_manager.clear_history()
    assert cleared["status"] == "cleared"
    assert cleared["cleared_entries"] >= 1
    assert len(proxy_manager.get_history(limit=10)) == 0


# ────────────────────────────────────────────
# 4. MCP Tool Surface (status/history/endpoints via client)
# ────────────────────────────────────────────


async def test_proxy_mcp_status_tool(mcp_client: Client):
    st = await mcp_client.call_tool("proxy_status", {})
    assert "running" in st.data
    assert "proxy_url" in st.data
    assert "ca_cert_path" in st.data


async def test_proxy_mcp_history_and_endpoints_tools(mcp_client: Client, http_server: str):
    scope = Scope.parse("127.0.0.1\nlocalhost")
    proxy_manager.start(host="127.0.0.1", port=18097, scope=scope)

    proxy_url = "http://127.0.0.1:18097"
    with httpx.Client(proxy=proxy_url, timeout=10.0) as client:
        client.get(f"{http_server}/json")

    hist = await mcp_client.call_tool("proxy_history", {"limit": 5})
    assert isinstance(hist.data, list)
    assert len(hist.data) >= 1

    eps = await mcp_client.call_tool("proxy_endpoints", {})
    assert "endpoints" in eps.data
    assert eps.data["total_unique"] >= 1

    clr = await mcp_client.call_tool("proxy_clear", {})
    assert clr.data["status"] == "cleared"
