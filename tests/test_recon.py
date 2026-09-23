"""Tests for recon_* tools against the local fixture HTTP server."""

import pytest
from fastmcp import Client


async def test_http_request(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/json", "method": "GET"})
    assert r.data["status"] == 200
    assert "ok" in r.data["body"]


async def test_http_request_post(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/", "method": "POST", "body": "a=1&b=2"})
    assert r.data["status"] == 200
    assert "a=1" in r.data["body"]


async def test_security_headers(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_security_headers", {"url": f"{http_server}/"})
    missing = [f["header"] for f in r.data["findings"] if f["status"] == "MISSING"]
    # fixture server sets no security headers
    assert "content-security-policy" in missing
    assert "strict-transport-security" in missing
    assert r.data["missing_count"] >= 4


async def test_fetch_robots(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_fetch_robots", {"url": http_server})
    robots = r.data["robots_txt"]
    assert robots["found"] is True
    assert "/admin" in robots["disallow"]
    assert r.data["sitemap_xml"]["found"] is True
    assert r.data["sitemap_xml"]["url_count"] == 2


async def test_cors_check_reflects_origin(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_cors_check", {"url": f"{http_server}/cors_reflect"})
    assert r.data["vulnerable"] is True
    assert any(f["severity"] == "high" for f in r.data["findings"])


async def test_cors_check_wildcard(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_cors_check", {"url": f"{http_server}/cors_wildcard"})
    assert r.data["vulnerable"] is False
    assert any("wildcard" in f.get("note", "") for f in r.data["findings"])


async def test_crawl_links(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_crawl_links", {"url": f"{http_server}/"})
    assert any("/about" in u for u in r.data["internal_links"])
    assert any("external.example" in u for u in r.data["external_links"])
    assert any("app.js" in s for s in r.data["scripts"])
    assert len(r.data["forms"]) == 2
    assert r.data["forms"][0]["method"] == "POST"
    assert "/login" in r.data["forms"][0]["action"]
    assert set(r.data["forms"][0]["inputs"]) == {"user", "pass"}
    assert r.data["forms"][1]["method"] == "GET"
    assert "/search" in r.data["forms"][1]["action"]
    assert set(r.data["forms"][1]["inputs"]) == {"q"}
    assert any("debug" in c for c in r.data["comments"])


async def test_js_analyze_bundle(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_js_analyze", {"url": f"{http_server}/static/app.js"})
    bundle = r.data["bundles"][f"{http_server}/static/app.js"]
    assert "/api/session" in bundle["endpoints"]
    assert any("api.example.internal" in e for e in bundle["endpoints"])
    assert "stripe_key" in bundle["secrets"]
    assert bundle["sourcemap"]["exposed"] is True
    assert bundle["sourcemap"]["source_count"] == 2


async def test_js_analyze_page_discovers_scripts(
        mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_js_analyze", {"url": f"{http_server}/"})
    assert any("app.js" in u for u in r.data["analyzed"])


async def test_api_discover(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "recon_api_discover", {"url": http_server})
    paths = {f["path"]: f["status"] for f in r.data["found"]}
    assert paths["/openapi.json"] == 200
    assert paths["/graphql"] == 400  # exists but errors without query
    # 404 endpoints excluded entirely
    assert "/swagger.yaml" not in paths


async def test_dns_lookup_invalid_domain(mcp_client: Client):
    from fastmcp.exceptions import ToolError
    with pytest.raises(ToolError):
        await mcp_client.call_tool(
            "recon_dns_lookup",
            {"domain": "nonexistent.invalid.domain.pwnmcp", "record_type": "A"})


async def test_recon_scope_check(mcp_client: Client):
    r = await mcp_client.call_tool("recon_scope_check", {"target": "https://example.com/api"})
    assert "allowed" in r.data
    assert r.data["host"] == "example.com"


@pytest.fixture
async def ws_echo_server():
    """Local WebSocket echo server for websocket_probe tests."""
    from websockets.asyncio.server import serve

    async def echo(websocket):
        async for message in websocket:
            await websocket.send(f"echo:{message}")

    async with serve(echo, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"


async def test_websocket_probe(mcp_client: Client, ws_echo_server: str):
    r = await mcp_client.call_tool("recon_websocket_probe", {
        "url": ws_echo_server,
        "messages": ["ping", "hello"],
        "recv_timeout": 1.0,
        "max_messages": 5,
    })
    assert r.data["connected"] is True
    assert r.data["sent"] == ["ping", "hello"]
    bodies = [m["data"] for m in r.data["received"]]
    assert "echo:ping" in bodies
    assert "echo:hello" in bodies


async def test_websocket_probe_rejects_http_scheme(mcp_client: Client, http_server: str):
    from fastmcp.exceptions import ToolError
    with pytest.raises(ToolError):
        await mcp_client.call_tool(
            "recon_websocket_probe", {"url": http_server})

