"""Tests for playbook_* tools."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError


async def test_playbook_list(mcp_client: Client):
    r = await mcp_client.call_tool("playbook_list", {})
    names = {p["name"] for p in r.data["playbooks"]}
    assert names >= {"recon_surface", "api_pass", "xss_pass", "web2_recon"}


async def test_playbook_recon_surface(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "playbook_run", {"name": "recon_surface", "target": http_server}
    )
    assert r.data["playbook"] == "recon_surface"
    steps = {s["step"] for s in r.data["steps"]}
    assert "tech_fingerprint" in steps
    assert "crawl_links" in steps
    assert isinstance(r.data["jobs"], list)


async def test_playbook_api_pass(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "playbook_run", {"name": "api_pass", "target": http_server}
    )
    assert r.data["playbook"] == "api_pass"
    steps = {s["step"] for s in r.data["steps"]}
    assert "api_discover" in steps
    assert "cors_check" in steps


async def test_playbook_xss_pass(mcp_client: Client, http_server: str):
    r = await mcp_client.call_tool(
        "playbook_run",
        {"name": "xss_pass", "target": f"{http_server}/echo?q=1", "param": "q"},
    )
    assert r.data["playbook"] == "xss_pass"
    result = r.data["steps"][0]["result"]
    assert result["reflected"] is True


async def test_playbook_xss_requires_param(mcp_client: Client, http_server: str):
    with pytest.raises(ToolError, match="param"):
        await mcp_client.call_tool(
            "playbook_run", {"name": "xss_pass", "target": http_server}
        )


async def test_playbook_unknown(mcp_client: Client):
    with pytest.raises(ToolError, match="Unknown playbook"):
        await mcp_client.call_tool(
            "playbook_run", {"name": "not_a_book", "target": "example.com"}
        )
