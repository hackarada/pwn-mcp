"""Tests for the constrained allowlisted CLI runner."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from pwn_mcp.cli_run import extract_targets, validate_argv
from pwn_mcp.scope import Scope


def test_validate_rejects_unknown_tool():
    with pytest.raises(ValueError, match="not allowlisted"):
        validate_argv("bash", ["-c", "id"])


def test_validate_rejects_shell_meta():
    with pytest.raises(ValueError, match="metacharacters"):
        validate_argv("nmap", ["example.com", ";", "id"])


def test_validate_rejects_denied_flags():
    with pytest.raises(ValueError, match="blocked"):
        validate_argv("nuclei", ["-u", "https://example.com", "-l", "hosts.txt"])
    with pytest.raises(ValueError, match="blocked"):
        validate_argv("nmap", ["-iL", "hosts.txt", "example.com"])


def test_validate_rejects_absolute_paths():
    with pytest.raises(ValueError, match="Absolute paths"):
        validate_argv("nuclei", ["-t", "/etc/passwd"])


def test_validate_strips_leading_binary_name():
    _, args = validate_argv("nuclei", ["nuclei", "-u", "https://example.com", "-silent"])
    assert args == ["-u", "https://example.com", "-silent"]


def test_extract_nuclei_and_subfinder_targets():
    assert extract_targets("nuclei", ["-u", "https://App.Example.com/x", "-silent"]) == [
        "https://App.Example.com/x"
    ]
    assert extract_targets("subfinder", ["-d", "example.com", "-silent"]) == ["example.com"]
    assert extract_targets("nuclei", ["-u=https://example.com", "-tags", "xss"]) == [
        "https://example.com"
    ]


def test_extract_positional_targets():
    assert extract_targets("nmap", ["-sV", "-p", "80,443", "scanme.example"]) == [
        "scanme.example"
    ]
    assert extract_targets("whois", ["example.com"]) == ["example.com"]
    assert extract_targets("dig", ["example.com", "A", "+short"]) == ["example.com"]
    assert extract_targets("dig", ["@8.8.8.8", "example.com", "MX"]) == ["example.com"]


async def test_cli_tools_lists_allowlist(mcp_client: Client):
    r = await mcp_client.call_tool("scan_cli_tools", {})
    names = {t["tool"] for t in r.data["tools"]}
    assert names == {"dig", "nmap", "nuclei", "subfinder", "whois"}


async def test_cli_run_rejects_shell_and_unknown(mcp_client: Client):
    with pytest.raises(ToolError, match="not allowlisted"):
        await mcp_client.call_tool(
            "scan_cli_run", {"tool": "curl", "argv": ["https://example.com"]})
    with pytest.raises(ToolError, match="metacharacters"):
        await mcp_client.call_tool(
            "scan_cli_run",
            {"tool": "nmap", "argv": ["example.com|id"]},
        )


async def test_cli_run_scope_enforcement(mcp_client: Client, monkeypatch):
    import pwn_mcp.cli_run as cli_mod

    monkeypatch.setattr(
        cli_mod, "load_scope",
        lambda: Scope.parse("example.com\n", source="test-scope"),
    )
    with pytest.raises(ToolError, match="outside the authorized scope"):
        await mcp_client.call_tool(
            "scan_cli_run",
            {"tool": "nuclei", "argv": ["-u", "https://evil.com", "-silent"]},
        )


async def test_cli_run_whois_when_available(mcp_client: Client, monkeypatch):
    import pwn_mcp.cli_run as cli_mod
    import shutil

    if not shutil.which("whois"):
        pytest.skip("whois not installed")

    monkeypatch.setattr(cli_mod, "load_scope", lambda: None)
    r = await mcp_client.call_tool(
        "scan_cli_run",
        {"tool": "whois", "argv": ["example.com"], "timeout": 30},
    )
    assert r.data["tool"] == "whois"
    assert r.data["exit_code"] is not None
    assert r.data["scoped_hosts"] == ["example.com"]
    assert isinstance(r.data["output"], str)
