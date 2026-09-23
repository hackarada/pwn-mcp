"""PostgreSQL persistence for long-running jobs.

Connection string: ``DATABASE_URL`` or ``PWN_MCP_DATABASE_URL``
(e.g. ``postgres://pwn:pwn@localhost:5432/pwn_mcp?sslmode=disable``).

Schema is managed by dbmate migrations in ``.migration/``.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_lock = threading.RLock()
_pool: ConnectionPool | None = None


def database_url() -> str:
    url = (
        os.environ.get("DATABASE_URL", "").strip()
        or os.environ.get("PWN_MCP_DATABASE_URL", "").strip()
    )
    if not url:
        raise RuntimeError(
            "DATABASE_URL (or PWN_MCP_DATABASE_URL) is required for the job store. "
            "Example: postgres://pwn:pwn@localhost:5432/pwn_mcp?sslmode=disable"
        )
    return url


def get_pool() -> ConnectionPool:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ConnectionPool(
                conninfo=database_url(),
                min_size=1,
                max_size=8,
                kwargs={"row_factory": dict_row},
                open=True,
            )
        return _pool


def reset_pool() -> None:
    """Close and clear the connection pool (tests / URL changes)."""
    global _pool
    with _lock:
        if _pool is not None:
            try:
                _pool.close()
            except Exception:
                pass
            _pool = None


def init_db() -> str:
    """Verify DB connectivity; schema comes from dbmate. Returns DATABASE_URL host hint."""
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return database_url()


def _now() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return str(value)


def _as_dict(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _row_to_job(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "params": _as_dict(row.get("params_json")) or {},
        "status": row["status"],
        "created_at": _iso(row.get("created_at")),
        "started_at": _iso(row.get("started_at")),
        "finished_at": _iso(row.get("finished_at")),
        "error": row.get("error"),
        "result": _as_dict(row.get("result_json")),
        "cancel_requested": bool(row.get("cancel_requested")),
    }


def job_create(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    job_id = new_id()
    created = _now()
    with get_pool().connection() as conn:
        conn.execute(
            """
            INSERT INTO jobs (id, kind, params_json, status, created_at)
            VALUES (%s, %s, %s::jsonb, %s, %s)
            """,
            (job_id, kind, json.dumps(params), "queued", created),
        )
        conn.commit()
    return {
        "id": job_id,
        "kind": kind,
        "params": params,
        "status": "queued",
        "created_at": _iso(created),
        "started_at": None,
        "finished_at": None,
        "error": None,
        "result": None,
        "cancel_requested": False,
    }


def job_get(job_id: str) -> dict[str, Any] | None:
    with get_pool().connection() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
    return _row_to_job(row) if row else None


def job_list(limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    with get_pool().connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE status = %s "
                "ORDER BY created_at DESC LIMIT %s",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT %s",
                (limit,),
            ).fetchall()
    return [_row_to_job(r) for r in rows]


def job_claim_next() -> dict[str, Any] | None:
    """Atomically claim one queued job (SKIP LOCKED for concurrent workers)."""
    started = _now()
    with get_pool().connection() as conn:
        row = conn.execute(
            """
            UPDATE jobs
            SET status = 'running', started_at = %s
            WHERE id = (
                SELECT id FROM jobs
                WHERE status = 'queued' AND cancel_requested = FALSE
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING *
            """,
            (started,),
        ).fetchone()
        conn.commit()
    return _row_to_job(row) if row else None


def job_request_cancel(job_id: str) -> dict[str, Any] | None:
    with get_pool().connection() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
        if not row:
            return None
        if row["status"] in ("succeeded", "failed", "cancelled"):
            return _row_to_job(row)
        if row["status"] == "queued":
            finished = _now()
            conn.execute(
                """
                UPDATE jobs
                SET status = 'cancelled',
                    cancel_requested = TRUE,
                    finished_at = %s,
                    error = %s
                WHERE id = %s
                """,
                (finished, "cancelled before start", job_id),
            )
        else:
            conn.execute(
                "UPDATE jobs SET cancel_requested = TRUE WHERE id = %s",
                (job_id,),
            )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
    return _row_to_job(updated) if updated else None


def job_is_cancel_requested(job_id: str) -> bool:
    with get_pool().connection() as conn:
        row = conn.execute(
            "SELECT cancel_requested FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
    return bool(row and row["cancel_requested"])


def job_finish(
    job_id: str,
    *,
    status: str,
    result: Any = None,
    error: str | None = None,
) -> dict[str, Any] | None:
    finished = _now()
    result_payload = json.dumps(result) if result is not None else None
    with get_pool().connection() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = %s,
                finished_at = %s,
                result_json = %s::jsonb,
                error = %s
            WHERE id = %s
            """,
            (status, finished, result_payload, error, job_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
    return _row_to_job(row) if row else None


def truncate_jobs() -> None:
    """Remove all jobs (test helper)."""
    with get_pool().connection() as conn:
        conn.execute("TRUNCATE jobs")
        conn.commit()
