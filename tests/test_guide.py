"""The guide is a resource, and tool-only clients can read it."""

from __future__ import annotations

from fastmcp import Client

from pwn_mcp.guide import GUIDE_URI


async def test_list_and_read_guide(mcp_client: Client):
    names = {tool.name for tool in await mcp_client.list_tools()}
    assert {"list_resources", "read_resource"} <= names

    listed = await mcp_client.call_tool("list_resources", {})
    assert GUIDE_URI in str(listed.data)

    page = await mcp_client.call_tool("read_resource", {"uri": GUIDE_URI})
    text = str(page.data)
    assert "spa_shell" in text
    assert "host.docker.internal" in text
    assert "auth_differential" in text
