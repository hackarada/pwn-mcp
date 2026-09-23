"""Embedded mitmproxy engine with scope enforcement and traffic telemetry for agents."""

from __future__ import annotations

import asyncio
import collections
import datetime
import logging
import os
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

from .scope import Scope, load_scope

logger = logging.getLogger("pwn_mcp.proxy")

CA_CERT_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")


class MitmScopeAndTelemetryAddon:
    """mitmproxy addon that enforces target scope, injects headers, and records flow history."""

    def __init__(
        self,
        scope: Scope | None = None,
        custom_headers: dict[str, str] | None = None,
        max_history: int = 1000,
    ) -> None:
        self.scope = scope
        self.custom_headers: dict[str, str] = dict(custom_headers or {})
        self.max_history = max_history
        self._lock = threading.Lock()
        self.history: collections.deque[dict[str, Any]] = collections.deque(maxlen=max_history)
        self.request_count = 0
        self.blocked_count = 0

    def _is_host_allowed_sync(self, host: str) -> bool:
        """Check scope in a thread-safe synchronous manner.

        Since mitmproxy's request hook runs inside its own event loop, we
        offload the async scope check to a separate executor thread so we
        can await the result without blocking mitmproxy's loop.
        """
        if self.scope is None:
            return True
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, self.scope.is_allowed(host))
            try:
                return future.result(timeout=3.0)
            except Exception:
                return True  # Fail open on scope check errors

    def request(self, flow: http.HTTPFlow) -> None:

        host = flow.request.pretty_host

        # Enforce scope if active
        if self.scope is not None:
            allowed = self._is_host_allowed_sync(host)
            if not allowed:
                with self._lock:
                    self.blocked_count += 1
                flow.response = http.Response.make(
                    403,
                    f"403 Forbidden: Target '{host}' is outside the authorized scope ({self.scope.source})\n".encode(),
                    {
                        "Content-Type": "text/plain",
                        "X-Pwn-Mcp": "Scope-Blocked",
                    },
                )
                self._record_flow(flow, scope_status="blocked", error="out_of_scope")
                return

        with self._lock:
            self.request_count += 1

        # Inject configured custom headers into outbound request
        for header, value in self.custom_headers.items():
            flow.request.headers[header] = value

    def response(self, flow: http.HTTPFlow) -> None:
        # Don't double-record flows blocked in request()
        if flow.response and flow.response.headers.get("X-Pwn-Mcp") == "Scope-Blocked":
            return
        self._record_flow(flow, scope_status="allowed")

    def error(self, flow: http.HTTPFlow) -> None:
        self._record_flow(
            flow,
            scope_status="allowed",
            error=str(flow.error.msg if flow.error else "Unknown error"),
        )



    def _record_flow(
        self,
        flow: http.HTTPFlow,
        scope_status: str,
        error: str | None = None,
    ) -> None:
        req = flow.request
        resp = flow.response

        # Body previews capped to avoid massive memory consumption
        req_body = ""
        if req and req.content:
            try:
                req_body = req.get_text()[:1000]
            except ValueError:
                req_body = f"<binary {len(req.content)} bytes>"

        resp_body = ""
        content_type = ""
        duration_ms = 0
        status_code = None

        if resp:
            status_code = resp.status_code
            content_type = resp.headers.get("content-type", "")
            if resp.content:
                try:
                    resp_body = resp.get_text()[:1000]
                except ValueError:
                    resp_body = f"<binary {len(resp.content)} bytes>"
            if flow.timestamp_start and resp.timestamp_end:
                duration_ms = max(0, round((resp.timestamp_end - flow.timestamp_start) * 1000))

        record = {
            "id": flow.id,
            "timestamp": flow.timestamp_start or time.time(),
            "iso_time": datetime.datetime.fromtimestamp(
                flow.timestamp_start or time.time(), datetime.timezone.utc
            ).isoformat(),
            "method": req.method.upper() if req else "",
            "url": req.pretty_url if req else "",
            "host": req.pretty_host if req else "",
            "port": req.port if req else 0,
            "path": req.path if req else "",
            "scheme": req.scheme if req else "",
            "status_code": status_code,
            "content_type": content_type,
            "duration_ms": duration_ms,
            "scope_status": scope_status,
            "error": error,
            "request_headers": dict(req.headers) if req else {},
            "response_headers": dict(resp.headers) if resp else {},
            "request_body_preview": req_body,
            "response_body_preview": resp_body,
        }

        with self._lock:
            self.history.append(record)


class ProxyManager:
    """Lifecycle manager for the embedded mitmproxy instance."""

    def __init__(self) -> None:
        self.master: DumpMaster | None = None
        self.addon: MitmScopeAndTelemetryAddon | None = None
        self.thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.host: str = "127.0.0.1"
        self.port: int = 8080
        self.scope: Scope | None = None
        self._lock = threading.RLock()  # RLock so is_running() can be called within start()'s lock

    def is_running(self) -> bool:
        with self._lock:
            return (
                self.master is not None
                and not self.master.should_exit.is_set()
                and self.thread is not None
                and self.thread.is_alive()
            )

    def start(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        custom_headers: dict[str, str] | None = None,
        scope: Scope | None = None,
    ) -> dict:
        """Start the embedded mitmproxy server in a background thread."""
        with self._lock:
            if self.is_running():
                return {
                    "status": "already_running",
                    "host": self.host,
                    "port": self.port,
                    "ca_cert_path": CA_CERT_PATH,
                }

            self.host = host
            self.port = port
            self.scope = scope if scope is not None else load_scope()
            self.addon = MitmScopeAndTelemetryAddon(
                scope=self.scope, custom_headers=custom_headers
            )

            started_event = threading.Event()
            error_holder: list[Exception] = []

            def _worker() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self.loop = loop

                opts = options.Options(
                    listen_host=self.host,
                    listen_port=self.port,
                )
                try:
                    master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
                    master.addons.add(self.addon)
                    self.master = master
                    started_event.set()
                    loop.run_until_complete(master.run())
                except Exception as exc:
                    error_holder.append(exc)
                    started_event.set()
                finally:
                    loop.close()

            self.thread = threading.Thread(target=_worker, name="pwn-mcp-mitmproxy", daemon=True)
            self.thread.start()

        started_event.wait(timeout=5.0)
        if error_holder:
            raise RuntimeError(f"Failed to start mitmproxy: {error_holder[0]}")

        # Brief settle time to verify socket is open
        time.sleep(0.3)
        return self.get_status()

    def stop(self) -> dict:
        """Shut down the running proxy server."""
        with self._lock:
            if not self.is_running():
                return {"status": "not_running"}

            if self.master:
                self.master.shutdown()
            thread = self.thread

        if thread and thread.is_alive():
            thread.join(timeout=3.0)

        with self._lock:
            self.master = None
            self.thread = None
            self.loop = None

        return {"status": "stopped"}

    def get_status(self) -> dict:
        """Return proxy operating status, certificate info, and traffic counters."""
        running = self.is_running()
        ca_exists = os.path.isfile(CA_CERT_PATH)
        req_count = self.addon.request_count if self.addon else 0
        blocked_count = self.addon.blocked_count if self.addon else 0
        history_len = len(self.addon.history) if self.addon else 0
        custom_headers = self.addon.custom_headers if self.addon else {}
        scope_desc = self.scope.describe() if self.scope else "unrestricted"

        proxy_url = f"http://{self.host}:{self.port}"
        return {
            "running": running,
            "host": self.host,
            "port": self.port,
            "proxy_url": proxy_url,
            "ca_cert_path": CA_CERT_PATH,
            "ca_cert_installed": ca_exists,
            "scope": scope_desc,
            "requests_total": req_count,
            "requests_blocked": blocked_count,
            "history_size": history_len,
            "custom_headers": custom_headers,
            "agent_env_setup": (
                f'export HTTP_PROXY="{proxy_url}" && '
                f'export HTTPS_PROXY="{proxy_url}" && '
                f'export SSL_CERT_FILE="{CA_CERT_PATH}"'
            ),
            "playwright_setup": f'--proxy-server="{proxy_url}" --ignore-certificate-errors',
        }

    def get_history(
        self,
        host: str | None = None,
        method: str | None = None,
        status: int | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query intercepted traffic records filtered by criteria."""
        if not self.addon:
            return []

        with self.addon._lock:
            records = list(self.addon.history)

        filtered = []
        for r in reversed(records):
            if host and host.lower() not in r["host"].lower():
                continue
            if method and method.upper() != r["method"]:
                continue
            if status is not None and r["status_code"] != status:
                continue
            filtered.append(r)
            if len(filtered) >= limit:
                break
        return filtered

    def get_flow(self, flow_id: str) -> dict | None:
        """Find a specific flow record by ID."""
        if not self.addon:
            return None
        with self.addon._lock:
            for r in self.addon.history:
                if r["id"] == flow_id:
                    return r
        return None

    def get_endpoints(self) -> dict:
        """Aggregate unique attack surface endpoints, paths, and query parameters."""
        if not self.addon:
            return {"endpoints": [], "total_unique": 0, "hosts": []}

        with self.addon._lock:
            records = list(self.addon.history)

        endpoints_map: dict[str, dict[str, Any]] = {}
        hosts_seen: set[str] = set()

        for r in records:
            if not r["url"] or r["scope_status"] == "blocked":
                continue
            hosts_seen.add(r["host"])
            parsed = urlparse(r["url"])
            key = f"{r['method']} {r['host']}{parsed.path}"
            qs_params = [k for k, _ in parse_qsl(parsed.query)]

            if key not in endpoints_map:
                endpoints_map[key] = {
                    "method": r["method"],
                    "host": r["host"],
                    "path": parsed.path,
                    "statuses": set(),
                    "query_params": set(),
                    "hits": 0,
                }
            if r["status_code"]:
                endpoints_map[key]["statuses"].add(r["status_code"])
            endpoints_map[key]["query_params"].update(qs_params)
            endpoints_map[key]["hits"] += 1

        summaries = [
            {
                "method": ep["method"],
                "host": ep["host"],
                "path": ep["path"],
                "statuses": sorted(ep["statuses"]),
                "query_params": sorted(ep["query_params"]),
                "hits": ep["hits"],
            }
            for ep in endpoints_map.values()
        ]
        summaries.sort(key=lambda x: (x["host"], x["path"], x["method"]))

        return {
            "endpoints": summaries,
            "total_unique": len(summaries),
            "hosts": sorted(hosts_seen),
        }

    def set_custom_headers(self, headers: dict[str, str]) -> dict:
        """Update custom headers injected into outbound traffic."""
        if not self.addon:
            return {"status": "proxy_not_initialized"}
        with self.addon._lock:
            self.addon.custom_headers.update(headers)
            current = dict(self.addon.custom_headers)
        return {"status": "updated", "custom_headers": current}

    def clear_history(self) -> dict:
        """Clear the in-memory traffic history buffer."""
        if not self.addon:
            return {"status": "not_running", "cleared": 0}
        with self.addon._lock:
            count = len(self.addon.history)
            self.addon.history.clear()
        return {"status": "cleared", "cleared_entries": count}


# Global singleton instance
proxy_manager = ProxyManager()
