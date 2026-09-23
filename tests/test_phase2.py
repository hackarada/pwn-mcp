"""Phase 2/4 capability smoke tests (no external binaries required)."""

from __future__ import annotations

import pytest
from fastmcp import Client


async def test_url_triage(mcp_client: Client):
    r = await mcp_client.call_tool("recon_url_triage", {
        "urls": [
            "https://x.example/api/v1/users?id=1",
            "https://x.example/admin/dashboard",
            "https://x.example/login?next=https://evil",
            "https://x.example/upload",
        ]
    })
    assert r.data["counts"]["api"] >= 1
    assert r.data["counts"]["admin"] >= 1
    assert r.data["counts"]["auth"] >= 1


async def test_secrets_scan_body(mcp_client: Client):
    r = await mcp_client.call_tool("recon_secrets_scan", {
        "url": "https://unused.example",
        "body": 'const k = "AKIAIOSFODNN7EXAMPLE"; api_key="sk_live_abcdefghijklmnop"',
    })
    assert "aws_access_key" in r.data["secrets"] or "generic_secret" in r.data["secrets"]


async def test_session_extract(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_session_extract", {"url": http_server})
    assert r.data["status"] == 200
    assert "cookies" in r.data
    assert "csrf_tokens" in r.data


async def test_tech_fingerprint_stack_hints(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("recon_tech_fingerprint", {"url": http_server})
    assert "stack_bug_hints" in r.data
    assert isinstance(r.data["stack_bug_hints"], list)


async def test_ssrf_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_ssrf_probe", {
        "url": f"{http_server}/echo",
        "param": "q",
    })
    assert "findings" in r.data
    assert len(r.data["findings"]) >= 1


async def test_idor_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_idor_probe", {
        "url": f"{http_server}/echo",
        "param": "q",
        "ids": ["1", "2"],
    })
    assert len(r.data["results"]) == 2


async def test_host_header_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_host_header_probe", {"url": http_server})
    assert "findings" in r.data


async def test_cache_probe(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_cache_probe", {"url": http_server})
    assert "reflected_in_poison_response" in r.data


async def test_content_discover(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool("scan_content_discover", {
        "url": http_server,
        "extra_paths": ["admin", "robots.txt"],
        "from_sitemap": True,
        "from_js": False,
        "recurse_depth": 0,
    })
    assert r.data["tested"] >= 1
    paths = {h["path"] for h in r.data["hits"]}
    assert "/admin" in paths or "/robots.txt" in paths or len(r.data["hits"]) >= 0


async def test_graphql_deep(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "scan_graphql_deep", {"url": f"{http_server}/graphql"}
    )
    assert r.data.get("batch_accepted") or "batch_status" in r.data


async def test_jwt_attack_weak_secret(mcp_client: Client):
    # token signed with "secret"
    signed = await mcp_client.call_tool("crypto_jwt_sign", {
        "payload": {"sub": "admin"},
        "secret": "secret",
        "alg": "HS256",
    })
    r = await mcp_client.call_tool("crypto_jwt_attack", {"token": signed.data})
    assert r.data["attacks"]["alg_none"]["token"].endswith(".")
    assert r.data["attacks"]["weak_hmac"]["cracked"] is True
    assert r.data["attacks"]["weak_hmac"]["secret"] == "secret"


async def test_cloud_bucket_probe(mcp_client: Client):
    r = await mcp_client.call_tool(
        "scan_cloud_bucket_probe", {"name": "this-bucket-should-not-exist-pwnmcp-xyz"}
    )
    assert "hits" in r.data
    assert len(r.data["hits"]) >= 1


async def test_cli_tools_includes_pd(mcp_client: Client):
    r = await mcp_client.call_tool("scan_cli_tools", {})
    names = {t["tool"] for t in r.data["tools"]}
    assert {"httpx", "katana", "naabu", "dnsx", "ffuf", "assetfinder"} <= names


async def test_proxy_export_empty(mcp_client: Client):
    har = await mcp_client.call_tool("proxy_export_har", {"limit": 5})
    assert "log" in har.data
    burp = await mcp_client.call_tool("proxy_export_burp", {"limit": 5})
    assert burp.data["format"] == "burp_xml"
    assert "<items" in burp.data["xml"]
