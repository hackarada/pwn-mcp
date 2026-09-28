"""Tests for recon_* tools against the local fixture HTTP server."""

import base64

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from websockets.asyncio.server import serve


async def test_http_request(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/json", "method": "GET"})
    assert r.data["status"] == 200
    assert "ok" in r.data["body"]


async def test_http_request_projects_json_fields(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/json", "fields": ["ok", "missing"]})
    assert r.data["fields_applied"] is True
    assert r.data["body"] == '{"ok":true}'


async def test_http_request_fields_on_non_json(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/echo", "params": {"q": "hi"}, "fields": ["ok"]})
    assert r.data["fields_applied"] is False
    assert r.data["fields_error"] == "response body is not JSON"


async def test_http_request_post(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/", "method": "POST", "body": "a=1&b=2"})
    assert r.data["status"] == 200
    assert "a=1" in r.data["body"]


async def test_http_request_body_limit(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/long", "body_limit": 100})
    assert r.data["body_length"] == 20000
    assert r.data["body"].startswith("L" * 100)
    assert "20000 chars total" in r.data["body"]


async def test_http_request_multipart_pads_to_size(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/upload",
        "method": "POST",
        "multipart": [{
            "name": "file",
            "filename": "big.png",
            "content": "hi",
            "size": 8,
            "content_type": "image/png",
        }],
    })
    assert r.data["status"] == 200
    assert "big.png" in r.data["body"]
    assert "hiAAAAAA" in r.data["body"]
    assert "multipart/form-data" in r.data["body"]


async def test_http_request_binary_is_base64(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {"url": f"{http_server}/binary"})
    assert r.data["kind"] == "binary"
    assert r.data["body_encoding"] == "base64"
    assert r.data["body_length"] == 6
    assert base64.b64decode(r.data["body"]) == b"\xff\xfe\x00pyc"


async def test_http_request_listing_replaces_html(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {"url": f"{http_server}/files"})
    assert r.data["kind"] == "directory_listing"
    assert r.data["body"] == "2 entries"
    names = [item["name"] for item in r.data["listing"]]
    assert names == ["acquisitions.md", "quarantine"]


async def test_http_request_reports_set_cookie(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {"url": f"{http_server}/set-cookie"})
    assert r.data["set_cookies"] == ["token=abc123; Path=/"]


async def test_http_request_stamps_totp_at_send_time(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_request", {
        "url": f"{http_server}/totp",
        "method": "POST",
        "body": '{"code":"{{totp}}"}',
        "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "totp_at": 1111111109,
    })
    assert r.data["status"] == 200
    assert r.data["totp"]["code"] == "081804"
    assert "081804" in r.data["body"]


async def test_http_vary_reports_which_body_succeeded(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_http_vary", {
        "url": f"{http_server}/guess",
        "bodies": ["nope", "correct-horse"],
    })
    assert r.data["hits"] == [1]
    assert r.data["results"][0]["status"] == 401
    assert r.data["results"][1]["status"] == 200


async def test_http_batch_overlaps(mcp_client: Client, http_server: str):
    url = f"{http_server}/race"
    r = await mcp_client.call_tool("recon_http_batch", {"requests": [
        {"url": url, "method": "POST", "body": "1"},
        {"url": url, "method": "POST", "body": "2"},
    ]})
    assert r.data["count"] == 2
    peaks = []
    for item in r.data["results"]:
        assert item["status"] == 200
        peaks.append(item["body"])
    assert any('"peak": 2' in body or '"peak":2' in body for body in peaks)


async def test_http_batch_rejects_too_many(mcp_client: Client, http_server: str):
    url = f"{http_server}/json"
    with pytest.raises(ToolError, match="at most 10"):
        await mcp_client.call_tool("recon_http_batch", {
            "requests": [{"url": url} for _ in range(11)],
        })


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
    openapi = next(f for f in r.data["found"] if f["path"] == "/openapi.json")
    assert openapi["kind"] == "json"


async def test_probe_paths_labels_shell_and_json(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_probe_paths", {
        "url": http_server,
        "paths": [
            "/json",
            "/shell/missing",
            "/openapi.json",
            "https://evil.example/secret",
        ],
    })
    by_path = {item["path"]: item for item in r.data["results"]}
    assert by_path["/json"]["kind"] == "json"
    assert by_path["/shell/missing"]["kind"] == "spa_shell"
    assert by_path["/openapi.json"]["kind"] == "json"
    assert "https://evil.example/secret" in r.data["skipped_other_host"]


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
    with pytest.raises(ToolError):
        await mcp_client.call_tool(
            "recon_websocket_probe", {"url": http_server})


@pytest.fixture
async def ws_script_server():
    """Server that acks engine.io-style before accepting the next frame."""

    async def scripted(websocket):
        await websocket.send('0{"sid":"abc"}')
        async for message in websocket:
            if message == "40":
                await websocket.send('40{"sid":"abc"}')
            elif str(message).startswith("42"):
                await websocket.send("42ack")

    async with serve(scripted, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"


async def test_websocket_probe_steps_wait_for_ack(mcp_client: Client, ws_script_server: str):
    r = await mcp_client.call_tool("recon_websocket_probe", {
        "url": ws_script_server,
        "recv_timeout": 1.0,
        "max_messages": 8,
        "steps": [
            {"wait_prefix": "0", "timeout": 1},
            {"send": "40"},
            {"wait_prefix": "40", "timeout": 1},
            {"send": '42["event"]'},
        ],
    })
    assert r.data["sent"] == ["40", '42["event"]']
    assert r.data["script"] == [
        {"wait_prefix": "0", "matched": True},
        {"send": "40"},
        {"wait_prefix": "40", "matched": True},
        {"send": '42["event"]'},
    ]
    bodies = [m["data"] for m in r.data["received"]]
    assert "42ack" in bodies

