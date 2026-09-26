"""FastMCP middleware: authorized-target scope and client-safe tool schemas."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool

from .scope import Scope
from .util import TARGET_KEYS, is_probable_scan_target, target_host

logger = logging.getLogger("pwn_mcp.scope")

_SCHEMA_META_KEYS = frozenset({"$schema", "$id"})


def _target_strings(value: Any, key: str | None = None) -> list[str]:
    """Collect url/host/target/domain strings, including nested request lists."""
    found: list[str] = []
    if isinstance(value, str):
        if key in TARGET_KEYS and value.strip():
            found.append(value)
        return found
    if isinstance(value, dict):
        for child_key, child in value.items():
            if isinstance(child_key, str):
                found.extend(_target_strings(child, child_key))
        return found
    if isinstance(value, list):
        for item in value:
            found.extend(_target_strings(item, key))
    return found


class ScopeEnforcementMiddleware(Middleware):
    """Rejects tool calls whose target arguments fall outside the loaded scope.

    When ``scope`` is None every call passes through (unrestricted mode).
    String arguments named url/host/target/domain are inspected, including
    those nested in a list of requests, and only when they look like
    hosts/URLs (not Playwright a11y refs like ``e5``).
    """

    def __init__(self, scope: Scope | None) -> None:
        self.scope = scope

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if self.scope is None:
            return await call_next(context)

        arguments = getattr(context.message, "arguments", None) or {}
        for value in _target_strings(arguments):
            if not is_probable_scan_target(value):
                continue
            host = target_host(value)
            if not host:
                continue
            if not await self.scope.is_allowed(host):
                raise ToolError(
                    f"Target '{host}' is outside the authorized scope "
                    f"({self.scope.source}). Add it to the scope file or unset "
                    "PWN_MCP_SCOPE / remove scope.txt to run unrestricted."
                )
        return await call_next(context)


def normalize_mcp_object_schema(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Make a tool input/output schema match the MCP tool schema shape.

    The MCP tool schema requires ``type: "object"`` when ``inputSchema`` or
    ``outputSchema`` is present. Playwright MCP sends ``outputSchema: {}``
    and a draft-2020 ``$schema`` on ``inputSchema``. Clients that validate
    each tool with that shape then fail the entire ``tools/list`` result, so
    every tool on the server disappears from the client, not only the
    browser tools.
    """
    if not isinstance(schema, dict):
        return schema
    cleaned = {key: value for key, value in schema.items() if key not in _SCHEMA_META_KEYS}
    if cleaned.get("type") != "object":
        cleaned["type"] = "object"
    properties = cleaned.get("properties")
    if properties is None:
        return cleaned
    if not isinstance(properties, dict):
        cleaned["properties"] = {}
        return cleaned
    fixed: dict[str, Any] = {}
    for name, prop in properties.items():
        if isinstance(prop, dict):
            fixed[name] = {
                key: value for key, value in prop.items() if key not in _SCHEMA_META_KEYS
            }
        else:
            # JSON Schema allows boolean property schemas. The MCP tool
            # schema requires each property value to be an object.
            fixed[name] = {}
    cleaned["properties"] = fixed
    required = cleaned.get("required")
    if required is not None and not (
        isinstance(required, list) and all(isinstance(item, str) for item in required)
    ):
        cleaned.pop("required", None)
    return cleaned


class ToolSchemaMiddleware(Middleware):
    """Rewrite tool schemas so a strict MCP client can parse ``tools/list``."""

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        normalized: list[Tool] = []
        for tool in tools:
            parameters = normalize_mcp_object_schema(tool.parameters)
            output = tool.output_schema
            if isinstance(output, dict):
                output = normalize_mcp_object_schema(output)
            if parameters != tool.parameters or output != tool.output_schema:
                tool = tool.model_copy(
                    update={"parameters": parameters, "output_schema": output}
                )
            normalized.append(tool)
        return normalized
