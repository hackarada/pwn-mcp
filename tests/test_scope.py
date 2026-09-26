"""Scope parsing/matching and middleware enforcement tests."""

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from pwn_mcp.middleware import ScopeEnforcementMiddleware
from pwn_mcp.scope import Scope
from pwn_mcp.util import is_probable_scan_target, target_host


def _scoped_server(scope_text: str) -> FastMCP:
    srv = FastMCP("scoped-test")

    @srv.tool
    def ping(url: str) -> str:
        return f"pong {url}"

    @srv.tool
    def click(target: str) -> str:
        return f"clicked {target}"

    srv.add_middleware(
        ScopeEnforcementMiddleware(Scope.parse(scope_text)))
    return srv


def test_target_host_normalization():
    assert target_host("https://Example.COM:8443/path?q=1") == "example.com"
    assert target_host("10.0.0.1:8080") == "10.0.0.1"
    assert target_host("example.com") == "example.com"
    assert target_host("[::1]") == "::1"
    assert target_host("http://sub.a.b.example.com/x") == "sub.a.b.example.com"


def test_is_probable_scan_target():
    assert is_probable_scan_target("https://example.com/x")
    assert is_probable_scan_target("example.com")
    assert is_probable_scan_target("10.0.0.1")
    assert is_probable_scan_target("localhost")
    assert is_probable_scan_target("intranet")
    # Playwright a11y refs + selectors must not be scoped as hosts
    assert not is_probable_scan_target("e5")
    assert not is_probable_scan_target("e12")
    assert not is_probable_scan_target(".btn-primary")
    assert not is_probable_scan_target("#login")
    assert not is_probable_scan_target("")


def test_scope_parse_and_match_sync():
    scope = Scope.parse("example.com\n*.allowed.io\n10.0.0.0/8\n192.168.1.5")
    assert "example.com" in scope.hosts
    assert "allowed.io" in scope.wildcards
    assert len(scope.networks) == 1


async def test_scope_matching():
    scope = Scope.parse("example.com\n*.allowed.io\n10.0.0.0/8\n192.168.1.5")
    assert await scope.is_allowed("example.com")
    assert await scope.is_allowed("api.allowed.io")
    assert await scope.is_allowed("allowed.io")          # wildcard covers apex
    assert await scope.is_allowed("deep.sub.allowed.io")
    assert await scope.is_allowed("10.44.2.9")           # CIDR
    assert await scope.is_allowed("192.168.1.5")         # exact IP via hosts
    assert not await scope.is_allowed("evil.com")
    assert not await scope.is_allowed("notallowed.io")
    assert not await scope.is_allowed("11.0.0.1")


async def test_middleware_allows_in_scope():
    srv = _scoped_server("example.com\n*.allowed.io\n10.0.0.0/8\n127.0.0.0/8")
    async with Client(srv) as c:
        r = await c.call_tool("ping", {"url": "https://example.com/x"})
        assert "pong" in r.data
        r = await c.call_tool("ping", {"url": "https://api.allowed.io/"})
        assert "pong" in r.data
        r = await c.call_tool("ping", {"url": "http://10.3.3.3:8080/"})
        assert "pong" in r.data
        # hostname resolving into a CIDR range
        r = await c.call_tool("ping", {"url": "http://localhost/"})
        assert "pong" in r.data


async def test_middleware_denies_out_of_scope():
    srv = _scoped_server("example.com")
    async with Client(srv) as c:
        with pytest.raises(ToolError, match="outside the authorized scope"):
            await c.call_tool("ping", {"url": "https://evil.com/"})
        with pytest.raises(ToolError):
            await c.call_tool("ping", {"url": "http://10.0.0.1/"})


async def test_middleware_checks_nested_request_urls():
    srv = FastMCP("scoped-batch")

    @srv.tool
    def batch(requests: list[dict]) -> str:
        return "ok"

    srv.add_middleware(ScopeEnforcementMiddleware(Scope.parse("example.com")))
    async with Client(srv) as c:
        r = await c.call_tool(
            "batch", {"requests": [{"url": "https://example.com/a"}]})
        assert r.data == "ok"
        with pytest.raises(ToolError, match="outside the authorized scope"):
            await c.call_tool("batch", {"requests": [
                {"url": "https://example.com/a"},
                {"url": "https://evil.com/b"},
            ]})


async def test_middleware_ignores_playwright_a11y_refs():
    """browser_click(target='e5') must not be treated as a host."""
    srv = _scoped_server("example.com")
    async with Client(srv) as c:
        r = await c.call_tool("click", {"target": "e5"})
        assert r.data == "clicked e5"
        with pytest.raises(ToolError, match="outside the authorized scope"):
            await c.call_tool("click", {"target": "https://evil.com/"})


async def test_no_scope_is_unrestricted():
    srv = FastMCP("unscoped")

    @srv.tool
    def ping(url: str) -> str:
        return f"pong {url}"

    srv.add_middleware(ScopeEnforcementMiddleware(None))
    async with Client(srv) as c:
        r = await c.call_tool("ping", {"url": "https://anything.example/"})
        assert "pong" in r.data


async def test_scope_exclusions():
    scope_text = """
    example.com
    *.target.com
    10.0.0.0/8
    !forbidden.target.com
    !*.internal.target.com
    !10.99.0.0/16
    !10.1.1.1
    """
    scope = Scope.parse(scope_text)
    # Allowed inclusions
    assert await scope.is_allowed("example.com")
    assert await scope.is_allowed("api.target.com")
    assert await scope.is_allowed("target.com")
    assert await scope.is_allowed("10.0.1.5")

    # Exclusions override inclusions
    assert not await scope.is_allowed("forbidden.target.com")
    assert not await scope.is_allowed("sub.internal.target.com")
    assert not await scope.is_allowed("internal.target.com")
    assert not await scope.is_allowed("10.99.1.1")
    assert not await scope.is_allowed("10.1.1.1")


async def test_scope_is_allowed_target():
    scope = Scope.parse("example.com\n*.target.com\n!forbidden.target.com")
    assert await scope.is_allowed_target("https://example.com/api/v1")
    assert await scope.is_allowed_target("http://api.target.com:8080/graphql")
    assert not await scope.is_allowed_target("https://forbidden.target.com/secret")
    assert not await scope.is_allowed_target("https://other.com")

