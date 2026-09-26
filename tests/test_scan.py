"""Tests for scan_* tools against the local fixture HTTP server."""

import socket
import threading

import pytest
from fastmcp import Client


@pytest.fixture
def banner_listener():
    """A TCP listener on 127.0.0.1 that sends a banner on connect."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        try:
            while True:
                conn, _ = srv.accept()
                conn.sendall(b"SSH-2.0-pwnmcp-test\r\n")
                conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    srv.close()


async def test_port_scan_finds_open_port(mcp_client: Client, banner_listener):
    r = await mcp_client.call_tool("scan_port_scan", {
        "host": "127.0.0.1",
        "ports": [banner_listener, 1],  # port 1 virtually always closed
        "timeout": 1.0,
    })
    open_ports = {p["port"]: p for p in r.data["open"]}
    assert banner_listener in open_ports
    assert 1 not in open_ports
    assert "SSH-2.0" in open_ports[banner_listener].get("banner", "")


async def test_dir_bruteforce(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_dir_bruteforce", {
        "url": http_server,
        "wordlist": ["admin", "secret", "definitely-not-here-xyz"],
    })
    found = {h["path"]: h["status"] for h in r.data["hits"]}
    assert found["/admin"] == 200
    assert found["/secret"] == 403
    assert "/definitely-not-here-xyz" not in found


async def test_param_fuzz_reflection(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_param_fuzz", {
        "url": f"{http_server}/search",
        "params": ["q", "unused"],
        "payloads": ["<xss123>"],
    })
    reflected = [x for x in r.data["results"]
                 if x["param"] == "q" and x.get("reflected")]
    assert reflected
    assert not any(x.get("reflected") for x in r.data["results"]
                   if x["param"] == "unused")


async def test_reflected_xss_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_reflected_xss_probe", {
        "url": f"{http_server}/echo", "param": "q"})
    assert r.data["reflected"] is True
    assert r.data["context"] == "html_text"
    assert r.data["special_chars_unescaped"]["angle"] is True
    assert r.data["appears_encoded"] is False
    assert r.data["reflection_in_error"] is False


async def test_reflected_xss_probe_encoded_error_page(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_reflected_xss_probe", {
        "url": f"{http_server}/error_echo", "param": "q"})
    assert r.data["reflected"] is True
    assert r.data["special_chars_unescaped"] == {"quote": False, "angle": False}
    assert r.data["appears_encoded"] is True
    assert r.data["reflection_in_error"] is True


async def test_open_redirect_check(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_open_redirect_check", {
        "url": f"{http_server}/redirect",
        "params": ["next"],
        "canary_host": "example.org"})
    assert r.data["vulnerable"] is True
    assert any(f["location"] == "https://example.org/" for f in r.data["findings"])


async def test_open_redirect_safe_param(mcp_client: Client, http_server: str):
    # /echo reflects but never redirects
    r = await mcp_client.call_tool("scan_open_redirect_check", {
        "url": f"{http_server}/echo", "params": ["q"]})
    assert r.data["vulnerable"] is False


async def test_graphql_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "scan_graphql_probe", {"url": f"{http_server}/graphql"})
    assert r.data["introspection_enabled"] is True
    assert r.data["vulnerable"] is True
    assert r.data["query_type"] == "Query"
    assert "AdminPanel" in r.data["types_sample"]


async def test_graphql_probe_non_graphql(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "scan_graphql_probe", {"url": f"{http_server}/json"})
    assert r.data["vulnerable"] is False
    assert r.data.get("introspection_enabled") is False


async def test_ssti_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "scan_ssti_probe", {"url": f"{http_server}/ssti", "param": "q"})
    assert r.data["vulnerable"] is True
    assert any(f["expected_eval"] == "49" for f in r.data["findings"])


async def test_sqli_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "scan_sqli_probe", {"url": f"{http_server}/sqli", "param": "q"})
    assert r.data["vulnerable"] is True
    assert any(ind["type"] == "error_based" for ind in r.data["indicators"])


async def test_sqli_probe_json_auth_differential(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_sqli_probe", {
        "url": f"{http_server}/login",
        "param": "email",
        "method": "POST",
        "content_type": "json",
    })
    assert r.data["content_type"] == "json"
    assert r.data["baseline_status"] == 401
    assert r.data["vulnerable"] is True
    auth = [ind for ind in r.data["indicators"] if ind["type"] == "auth_differential"]
    assert auth
    assert "token" in auth[0]["body_preview"]


async def test_subfinder_missing_binary(mcp_client: Client, monkeypatch):
    from fastmcp.exceptions import ToolError
    import pwn_mcp.servers.scan as scan_mod

    monkeypatch.setattr(scan_mod, "which", lambda _b: None)
    with pytest.raises(ToolError, match="subfinder not found"):
        await mcp_client.call_tool(
            "scan_subfinder_enum", {"domain": "example.com"})


async def test_nuclei_missing_binary(mcp_client: Client, monkeypatch):
    from fastmcp.exceptions import ToolError
    import pwn_mcp.servers.scan as scan_mod

    monkeypatch.setattr(scan_mod, "which", lambda _b: None)
    with pytest.raises(ToolError, match="nuclei not found"):
        await mcp_client.call_tool(
            "scan_nuclei_scan", {"url": "https://example.com"})


async def test_nuclei_list_templates_requires_filter(mcp_client: Client, monkeypatch):
    from fastmcp.exceptions import ToolError
    import pwn_mcp.servers.scan as scan_mod

    monkeypatch.setattr(scan_mod, "which", lambda _b: "/usr/bin/nuclei")
    with pytest.raises(ToolError, match="at least one filter"):
        await mcp_client.call_tool("scan_nuclei_list_templates", {})


async def test_nuclei_list_tags_parses_output(mcp_client: Client, monkeypatch):
    import pwn_mcp.servers.scan as scan_mod

    monkeypatch.setattr(scan_mod, "which", lambda _b: "/usr/bin/nuclei")
    monkeypatch.setattr(
        scan_mod,
        "_nuclei_raw",
        lambda _args, timeout=90.0: (
            "Listing available tags\n"
            "xss (1423)\n"
            "sqli (500)\n"
            "cve (4492)\n"
        ),
    )
    r = await mcp_client.call_tool(
        "scan_nuclei_list_tags", {"query": "xs", "limit": 10})
    assert r.data["total_matching"] == 1
    assert r.data["tags"][0]["tag"] == "xss"
    assert r.data["tags"][0]["count"] == 1423


async def test_nuclei_list_templates_parses_output(mcp_client: Client, monkeypatch):
    import pwn_mcp.servers.scan as scan_mod

    monkeypatch.setattr(scan_mod, "which", lambda _b: "/usr/bin/nuclei")
    monkeypatch.setattr(
        scan_mod,
        "_nuclei_raw",
        lambda _args, timeout=90.0: (
            "Listing available templates\n"
            "http/vulnerabilities/xss/reflected-xss.yaml\n"
            "http/cves/2024/CVE-2024-1234.yaml\n"
            "[INF] done\n"
        ),
    )
    r = await mcp_client.call_tool(
        "scan_nuclei_list_templates",
        {"tags": "xss", "query": "cve", "limit": 50},
    )
    assert r.data["total_matching"] == 1
    assert r.data["templates"] == ["http/cves/2024/CVE-2024-1234.yaml"]

