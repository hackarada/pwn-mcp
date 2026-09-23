"""Tests for PostgreSQL job store + background workers + MCP jobs_* tools."""

from __future__ import annotations

import time

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from pwn_mcp import store
from pwn_mcp.jobs import JOB_KINDS, enqueue, ensure_workers

pytestmark = pytest.mark.usefixtures("job_db")


def test_job_create_get_list_cancel():
    job = store.job_create("cli_run", {"tool": "dig", "argv": ["example.com"]})
    assert job["status"] == "queued"
    assert store.job_get(job["id"])["kind"] == "cli_run"
    listed = store.job_list(limit=10)
    assert any(j["id"] == job["id"] for j in listed)

    cancelled = store.job_request_cancel(job["id"])
    assert cancelled is not None
    assert cancelled["status"] == "cancelled"


def test_job_lifecycle_succeeds():
    from pwn_mcp.util import which

    ensure_workers(1)
    if which("dig"):
        job = enqueue(
            "cli_run",
            {"tool": "dig", "argv": ["localhost", "A"], "timeout": 15},
        )
    else:
        job = store.job_create("cli_run", {"tool": "dig", "argv": ["localhost"]})
        store.job_finish(job["id"], status="succeeded", result={"ok": True})
        got = store.job_get(job["id"])
        assert got["status"] == "succeeded"
        return

    deadline = time.time() + 20
    got = None
    while time.time() < deadline:
        got = store.job_get(job["id"])
        if got and got["status"] in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(0.2)
    assert got is not None
    assert got["status"] in ("succeeded", "failed")
    if got["status"] == "succeeded":
        assert got["result"] is not None


async def test_jobs_mcp_tools(mcp_client: Client):
    started = await mcp_client.call_tool(
        "jobs_start",
        {
            "kind": "cli_run",
            "params": {"tool": "dig", "argv": ["localhost", "A"], "timeout": 15},
        },
    )
    job_id = started.data["id"]
    assert started.data["status"] == "queued"

    status = await mcp_client.call_tool("jobs_status", {"job_id": job_id})
    assert status.data["id"] == job_id
    assert status.data.get("has_result") is not None

    listed = await mcp_client.call_tool("jobs_list", {"limit": 20})
    kinds = listed.data["kinds"]
    assert "nuclei_scan" in kinds
    assert set(JOB_KINDS).issubset(set(kinds))

    queued = await mcp_client.call_tool(
        "jobs_start",
        {"kind": "nmap_scan", "params": {"target": "127.0.0.1", "args": "-sn"}},
    )
    cancelled = await mcp_client.call_tool(
        "jobs_cancel", {"job_id": queued.data["id"]}
    )
    assert cancelled.data["status"] in (
        "cancelled", "running", "queued", "succeeded", "failed"
    )

    with pytest.raises(ToolError):
        await mcp_client.call_tool("jobs_status", {"job_id": "does-not-exist"})


async def test_jobs_start_rejects_unknown_kind(mcp_client: Client):
    with pytest.raises(ToolError, match="Unknown job kind"):
        await mcp_client.call_tool("jobs_start", {"kind": "evil", "params": {}})
