"""Shared fixtures: in-memory MCP client + local HTTP test server."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastmcp import Client

from pwn_mcp.server import mcp

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_DATABASE_URL = (
    "postgres://pwn:pwn@127.0.0.1:5432/pwn_mcp?sslmode=disable"
)

PAGE = """<!doctype html>
<html><head>
<!-- TODO: remove debug flag before prod -->
<script src="/static/app.js"></script>
</head><body>
<a href="/about">About</a>
<a href="https://external.example/x">Ext</a>
<form action="/login" method="POST">
  <input name="user"><input name="pass">
</form>
<form action="/search" method="GET">
  <input name="q">
</form>
</body></html>"""

APP_JS = """\
const api = "https://api.example.internal/v1/users";
fetch("/api/session", {headers: {"X-Api-Key": "test_key_123"}});
const cfg = {api_key: "sk_live_abcdef1234567890"};
//# sourceMappingURL=app.js.map
"""

GRAPHQL_SCHEMA = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"name": "Query", "kind": "OBJECT"},
            {"name": "Mutation", "kind": "OBJECT"},
            {"name": "User", "kind": "OBJECT"},
            {"name": "AdminPanel", "kind": "OBJECT"},
            {"name": "String", "kind": "SCALAR"},
        ],
    }}
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence test server logs
        pass

    def _send(self, code, body=b"", headers=None, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        path = parsed.path

        if path == "/":
            self._send(200, PAGE.encode())
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
                            b"Sitemap: /sitemap.xml\n", ctype="text/plain")
        elif path == "/sitemap.xml":
            self._send(200, b"<?xml version='1.0'?><urlset>"
                            b"<url><loc>/a</loc></url><url><loc>/b</loc></url>"
                            b"</urlset>", ctype="application/xml")
        elif path == "/echo":
            q = qs.get("q", "")
            self._send(200, f"<html>You said: {q}</html>".encode())
        elif path == "/search":
            q = qs.get("q", "")
            self._send(200, f"results for {q}: none".encode())
        elif path == "/redirect":
            nxt = qs.get("next", "/")
            self._send(302, b"", {"Location": nxt})
        elif path == "/cors_reflect":
            origin = self.headers.get("Origin", "")
            self._send(200, b"{}", {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }, ctype="application/json")
        elif path == "/cors_wildcard":
            self._send(200, b"{}", {"Access-Control-Allow-Origin": "*"},
                       ctype="application/json")
        elif path == "/admin":
            self._send(200, b"admin panel")
        elif path == "/secret":
            self._send(403, b"forbidden")
        elif path == "/json":
            self._send(200, json.dumps({"ok": True}).encode(),
                       ctype="application/json")
        elif path == "/static/app.js":
            self._send(200, APP_JS.encode(), ctype="application/javascript")
        elif path == "/static/app.js.map":
            self._send(200, json.dumps({
                "version": 3,
                "sources": ["src/api/client.ts", "src/components/Login.tsx"],
            }).encode(), ctype="application/json")
        elif path == "/openapi.json":
            self._send(200, json.dumps({
                "openapi": "3.0.0",
                "paths": {"/users": {}, "/admin": {}},
            }).encode(), ctype="application/json")
        elif path == "/graphql":
            if qs.get("query"):
                self._send(200, json.dumps(GRAPHQL_SCHEMA).encode(),
                           ctype="application/json")
            else:
                self._send(400, b'{"errors":[{"message":"no query"}]}',
                           ctype="application/json")
        elif path == "/ssti":
            q = qs.get("q", "")
            if "{{7*7}}" in q or "${7*7}" in q:
                self._send(200, b"<html>rendered: 49</html>")
            else:
                self._send(200, f"<html>rendered: {q}</html>".encode())
        elif path == "/sqli":
            q = qs.get("q", "")
            if "'" in q:
                self._send(500, b"Database error: You have an error in your SQL syntax near ''")
            elif "1' OR '1'='1" in q:
                self._send(200, b"result: user1, user2, user3, user4, user5 (all data rows returned for true)")
            else:
                self._send(200, b"result: none")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        if self.path == "/graphql":
            if "__schema" in body:
                self._send(200, json.dumps(GRAPHQL_SCHEMA).encode(),
                           ctype="application/json")
            else:
                self._send(200, b'{"errors":[{"message":"Unknown field"}]}',
                           ctype="application/json")
            return
        self._send(200, f"posted:{body}".encode())


@pytest.fixture(scope="session")
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="session")
def database_url() -> str:
    """Postgres URL for job-store tests (dbmate-managed schema)."""
    url = (
        os.environ.get("DATABASE_URL", "").strip()
        or os.environ.get("PWN_MCP_DATABASE_URL", "").strip()
        or DEFAULT_TEST_DATABASE_URL
    )
    os.environ["DATABASE_URL"] = url
    migrations = ROOT / ".migration"
    result = subprocess.run(
        [
            "dbmate",
            "--url", url,
            "--migrations-dir", str(migrations),
            "--wait",
            "--wait-timeout", "30s",
            "up",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(
            "PostgreSQL not available for job tests. "
            "Start compose postgres (docker compose up -d postgres) "
            f"or set DATABASE_URL. dbmate: {result.stderr or result.stdout}"
        )
    return url


@pytest.fixture
def job_db(database_url: str):
    """Fresh jobs table for each test that needs the store."""
    from pwn_mcp import store

    store.reset_pool()
    store.init_db()
    store.truncate_jobs()
    yield database_url
    store.truncate_jobs()
    store.reset_pool()


@pytest.fixture
async def mcp_client():
    async with Client(mcp) as client:
        yield client
