"""MCP tools for background long-running jobs."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from .. import store
from ..jobs import JOB_KINDS, enqueue, ensure_workers

mcp = FastMCP("jobs")

ensure_workers()


@mcp.tool(
    tags={"jobs"},
    annotations={"openWorldHint": False},
)
async def start(kind: str, params: dict[str, Any] | None = None) -> dict:
    """Enqueue a long-running job (survives tool-call timeouts).

    Poll with ``jobs_status`` / ``jobs_result``. Kinds: cli_run, nuclei_scan,
    nmap_scan, subfinder_enum, monitor_subs, hash_crack.

    Args:
        kind: Job kind.
        params: Kind-specific params, e.g. nuclei_scan needs {{url, args?}};
            cli_run needs {{tool, argv, timeout?}}; subfinder_enum needs {{domain}};
            monitor_subs needs {{domain, prior: [..]}}.
    """
    try:
        return enqueue(kind, params or {})
    except ValueError as e:
        raise ToolError(str(e)) from e


@mcp.tool(
    tags={"jobs"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def status(job_id: str) -> dict:
    """Get job status by id (queued|running|succeeded|failed|cancelled)."""
    job = store.job_get(job_id)
    if not job:
        raise ToolError(f"Job '{job_id}' not found")
    # Omit bulky result in status
    summary = {k: v for k, v in job.items() if k != "result"}
    summary["has_result"] = job.get("result") is not None
    return summary


@mcp.tool(
    tags={"jobs"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def result(job_id: str) -> dict:
    """Return full job record including result payload when finished."""
    job = store.job_get(job_id)
    if not job:
        raise ToolError(f"Job '{job_id}' not found")
    return job


@mcp.tool(
    name="list",
    tags={"jobs"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
async def list_jobs(limit: int = 50, status_filter: str | None = None) -> dict:
    """List recent jobs (newest first).

    Args:
        limit: Max rows (1-200).
        status_filter: Optional status filter.
    """
    return {
        "jobs": store.job_list(limit=limit, status=status_filter),
        "kinds": sorted(JOB_KINDS),
    }


@mcp.tool(
    tags={"jobs"},
    annotations={"openWorldHint": False},
)
async def cancel(job_id: str) -> dict:
    """Request cancellation of a queued or running job."""
    job = store.job_request_cancel(job_id)
    if not job:
        raise ToolError(f"Job '{job_id}' not found")
    return job
