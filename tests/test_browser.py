"""Unit tests for optional Playwright MCP HTTP proxy wiring (no live browser)."""

from __future__ import annotations

import pytest
from fastmcp.server.providers.proxy import FastMCPProxy, StatefulProxyClient
from fastmcp.tools.base import Tool

from pwn_mcp.browser import (
    browser_enabled,
    browser_mcp_url,
    chromium_proxy_hint,
    create_browser_proxy,
)
from pwn_mcp.middleware import ToolSchemaMiddleware, normalize_mcp_object_schema


def test_browser_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PWN_MCP_BROWSER", raising=False)
    monkeypatch.delenv("PWN_MCP_BROWSER_URL", raising=False)
    assert browser_enabled() is False
    assert create_browser_proxy() is None


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_browser_enabled_truthy(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("PWN_MCP_BROWSER", value)
    assert browser_enabled() is True


def test_create_browser_proxy_requires_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PWN_MCP_BROWSER", "1")
    monkeypatch.delenv("PWN_MCP_BROWSER_URL", raising=False)
    assert browser_mcp_url() is None
    assert create_browser_proxy() is None


def test_create_browser_proxy_with_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PWN_MCP_BROWSER", "1")
    monkeypatch.setenv("PWN_MCP_BROWSER_URL", "http://playwright:8931/mcp")
    proxy = create_browser_proxy()
    assert isinstance(proxy, FastMCPProxy)
    factory = proxy.client_factory
    assert isinstance(factory.__self__, StatefulProxyClient)
    assert factory.__func__ is StatefulProxyClient.new_stateful


def test_normalize_empty_output_schema():
    schema = normalize_mcp_object_schema({})
    assert schema == {"type": "object"}


def test_normalize_strips_draft_schema_keywords():
    schema = normalize_mcp_object_schema(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"url": {"type": "string", "$schema": "nope"}},
            "required": ["url"],
        }
    )
    assert schema is not None
    assert "$schema" not in schema
    assert schema["properties"]["url"] == {"type": "string"}
    assert schema["required"] == ["url"]


@pytest.mark.asyncio
async def test_tool_schema_middleware_rewrites_playwright_shape():
    original = Tool(
        name="browser_close",
        description="Close the page",
        parameters={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
        },
        output_schema={},
    )

    async def call_next(_context):
        return [original]

    result = await ToolSchemaMiddleware().on_list_tools(None, call_next)  # type: ignore[arg-type]
    assert result[0] is not original
    assert result[0].output_schema == {"type": "object"}
    assert "$schema" not in result[0].parameters
    assert original.output_schema == {}


def test_chromium_proxy_hint_compose_defaults(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PWN_MCP_BROWSER_PROXY", raising=False)
    monkeypatch.setenv("PWN_MCP_PROXY_PORT", "8080")
    monkeypatch.setenv("PWN_MCP_PROXY_HOST", "0.0.0.0")
    assert chromium_proxy_hint() == "http://127.0.0.1:8080"


def test_chromium_proxy_hint_explicit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PWN_MCP_BROWSER_PROXY", "http://pwn-mcp:8080")
    assert chromium_proxy_hint() == "http://pwn-mcp:8080"
