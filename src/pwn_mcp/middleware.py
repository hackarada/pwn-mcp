"""FastMCP middleware enforcing an authorized-target scope."""

from __future__ import annotations

import logging

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from .scope import Scope
from .util import TARGET_KEYS, target_host

logger = logging.getLogger("pwn_mcp.scope")


class ScopeEnforcementMiddleware(Middleware):
    """Rejects tool calls whose target arguments fall outside the loaded scope.

    When ``scope`` is None every call passes through (unrestricted mode).
    Only string arguments named url/host/target/domain are inspected.
    """

    def __init__(self, scope: Scope | None) -> None:
        self.scope = scope

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if self.scope is None:
            return await call_next(context)

        arguments = getattr(context.message, "arguments", None) or {}
        for key in TARGET_KEYS:
            value = arguments.get(key)
            if not isinstance(value, str) or not value.strip():
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
