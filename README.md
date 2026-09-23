# pwn-mcp

An [MCP](https://modelcontextprotocol.io) server built with
[FastMCP](https://gofastmcp.com) that exposes web, API, and SPA security
testing tools to LLM clients — designed for CTFs, bug bounty / VDP work,
and authorized internal testing.

**Only use these tools against targets you are authorized to test.**

## Install

```bash
uv sync
```

## Run

```bash
# stdio (default — for local MCP clients); picks up fastmcp.json
uv run fastmcp run

# or explicitly
uv run fastmcp run main.py:mcp
uv run fastmcp run -m pwn_mcp.server
uv run pwn-mcp            # console script

# HTTP transport
uv run fastmcp run -m pwn_mcp.server --transport http --port 8000
# or env-driven (used by Docker):
PWN_MCP_TRANSPORT=http PWN_MCP_HOST=0.0.0.0 PWN_MCP_PORT=8000 uv run pwn-mcp
```

### MCP client config (stdio)

```json
{
  "mcpServers": {
    "pwn-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pwn-mcp",
               "fastmcp", "run", "main.py:mcp"]
    }
  }
}
```

## Docker deploy

HTTP (Streamable) transport on port 8000. Endpoint: `http://<host>:8000/mcp`.

```bash
# build + run (includes nmap, whois, subfinder, nuclei)
docker compose up -d --build

# leaner image without ProjectDiscovery binaries:
INSTALL_PD_TOOLS=false docker compose up -d --build

# optional auth + scope + proxy (see .env.example)
cp .env.example .env
# edit .env, then:
docker compose up -d --build
```

Useful endpoints:

| Path | Purpose |
|---|---|
| `/mcp` | MCP Streamable HTTP endpoint |
| `/health` | Liveness probe (`OK`) |
| `/ready` | Readiness JSON (scope / proxy / auth flags) |

Client config (remote HTTP):

```json
{
  "mcpServers": {
    "pwn-mcp": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

Omit `headers` when `PWN_MCP_AUTH_TOKEN` is unset. Put TLS termination (Caddy/nginx/Traefik) in front for anything beyond a private network.

Image includes `nmap`, `whois`, `dig`, and ProjectDiscovery
`subfinder`, `nuclei`, `httpx`, `katana`, `naabu`, `dnsx` by default.
Set `INSTALL_PD_TOOLS=false` at build time for a leaner image.

Nuclei templates are fetched at image build and refreshed again on every
container start (`PWN_MCP_UPDATE_NUCLEI_TEMPLATES=true`, default). Templates are
stored in the `nuclei-templates` Docker volume so updates persist across
restarts. Disable startup refresh for air-gapped hosts.

Job state lives in **PostgreSQL** (`DATABASE_URL`). Schema is applied with
[dbmate](https://github.com/amacneil/dbmate) from `.migration/` on container
boot (and locally via `dbmate --migrations-dir .migration up`).

## Agent workflow

The **agent owns session memory** (what was found, next steps, URL lists).
MCP does not keep a recon notepad. Use MCP for **capabilities** and for
**jobs** when a scan would exceed a single tool-call timeout.

Typical loop:

1. `playbook_run(name="web2_recon", target="example.com")` — sync steps + job ids
2. Poll `jobs_status` / `jobs_result` for subfinder / nuclei
3. `recon_url_triage` on URL lists; `recon_tech_fingerprint` for stack→bug hints
4. Typed probes (`scan_ssrf_probe`, `scan_idor_probe`, …) or `scan_cli_run`
5. Long work → `jobs_start` (kinds: `cli_run`, `nuclei_scan`, `nmap_scan`,
   `subfinder_enum`, `monitor_subs`, `hash_crack`)

**Wrappers vs `scan_cli_run`:** prefer typed tools (`scan_nuclei_scan`,
`scan_httpx_probe`, …). Use `scan_cli_run` when you need flags the wrapper
does not expose. Shell metacharacters, absolute paths, and file I/O flags
are rejected; targets are scope-checked.

**5-minute kill signals:** only 403/static pages, no APIs/JS endpoints, empty
nuclei — move on. Stack→bug map is in server instructions and
`recon_tech_fingerprint.stack_bug_hints`.

## Tool catalog

| Namespace   | Tools |
|---|---|
| `recon_`    | `http_request`, `security_headers`, `tls_cert_info`, `tech_fingerprint`, `fetch_robots`, `dns_lookup`, `whois_lookup`, `cors_check`, `crawl_links`, `js_analyze`, `api_discover`, `websocket_probe`, `scope_check`, `secrets_scan`, `session_extract`, `url_triage` |
| `crypto_`   | `encode`, `decode`, `hash_text`, `hash_identify`, `jwt_decode`, `jwt_sign`, `jwt_attack`, `hash_crack_enqueue`, `transform`, `xor`, `caesar` |
| `scan_`     | `port_scan`, `nmap_scan`, `subdomain_enum`, `subfinder_enum`, `httpx_probe`, `katana_crawl`, `naabu_scan`, `dnsx_resolve`, `nuclei_list_tags`, `nuclei_list_templates`, `nuclei_templates_version`, `nuclei_scan`, `cli_tools`, `cli_run`, `dir_bruteforce`, `content_discover`, `param_fuzz`, `reflected_xss_probe`, `open_redirect_check`, `graphql_probe`, `graphql_deep`, `ssti_probe`, `sqli_probe`, `ssrf_probe`, `idor_probe`, `cache_probe`, `host_header_probe`, `subdomain_takeover_check`, `cloud_bucket_probe` |
| `proxy_`    | `start`, `stop`, `status`, `history`, `get_traffic`, `endpoints`, `set_headers`, `clear`, `intercept`, `held`, `resume`, `replay`, `match_replace`, `match_replace_list`, `export_har`, `export_burp` |
| `jobs_`     | `start`, `status`, `result`, `list`, `cancel` |
| `playbook_` | `list`, `run` (`recon_surface`, `api_pass`, `xss_pass`, `web2_recon`) |

Tools are pure Python (httpx, dnspython, cryptography, websockets) where possible.
Optional binaries activate only when present on `PATH` and return a clear
error otherwise. Allowlisted `cli_run` tools: `nuclei`, `subfinder`, `nmap`,
`whois`, `dig`, `httpx`, `katana`, `naabu`, `dnsx`, `ffuf`, `assetfinder`
(`ffuf` / `assetfinder` are allowlist-only — not baked into the Docker image).

`scan_cli_run` is a constrained no-shell executor for those CLIs when you need
flags the typed wrappers do not expose. Use `scan_cli_tools` to see what is
installed. Install ProjectDiscovery tools with
[pdtm](https://github.com/projectdiscovery/pdtm):

```bash
pdtm -i subfinder,nuclei,httpx,katana,naabu,dnsx
```

## Scope enforcement (optional)

Place a `scope.txt` in the working directory — or set
`PWN_MCP_SCOPE=/path/to/scope.txt` — to restrict all active tools to
authorized targets. `scope.txt` is gitignored; copy `scope.example.txt`
and edit it. One entry per line:

```
example.com          # exact host
*.example.com        # apex + all subdomains
10.0.0.0/8           # CIDR
192.168.1.10         # single IP
!blocked.example     # exclusion — strip this host even if a broader rule allows it
!10.0.0.0/24         # CIDR exclusion
!*.internal.corp     # wildcard exclusion
```

With a scope file present, any tool call whose `url`/`host`/`target`/`domain`
argument resolves outside the scope is rejected before execution. Exclusion
rules (prefixed with `!`) take precedence over inclusion rules and strip
specific hosts from an otherwise broad allowlist. With no scope file, the
server runs unrestricted (CTF mode). See `scope.example.txt`.

## Intercepting Proxy (agent traffic hub)

The `proxy_*` namespace exposes an embedded
[mitmproxy](https://mitmproxy.org)-based intercepting proxy that agents,
browsers, and scripts can route traffic through. It is designed as a
traffic-telemetry and scope-enforcement sidecar:

```
HTTP_PROXY=http://127.0.0.1:8080  →  pwn-mcp proxy  →  target
SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

**Agent setup (env vars for Playwright / curl / httpx / requests / Node):**
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
# For Node.js SDKs:
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
```

### Proxy tools

| Tool | Description |
|---|---|
| `proxy_start` | Start the proxy (optional port, host, custom headers) |
| `proxy_stop` | Stop and clean up |
| `proxy_status` | Current state, proxy URL, CA cert path, counters, intercept |
| `proxy_history` | Paginated flow history with host / method / status filters |
| `proxy_get_traffic` | Full detail (headers, body preview) for a specific flow ID |
| `proxy_endpoints` | Deduplicated endpoint inventory (host, path, methods, status codes) |
| `proxy_set_headers` | Inject or update custom headers forwarded on every request |
| `proxy_clear` | Purge the in-memory traffic history buffer |
| `proxy_intercept` / `proxy_held` / `proxy_resume` | Breakpoint: hold matching requests, edit, resume or drop |
| `proxy_replay` | Repeater — replay a history flow with overrides |
| `proxy_match_replace` | Match/replace rules on req/resp headers, body, URL |
| `proxy_export_har` / `proxy_export_burp` | Export history as HAR 1.2 or Burp-like XML |

### Auto-start

Set `PWN_MCP_PROXY_PORT=8080` (or any port) in the server environment to
start the proxy automatically when the MCP server starts:

```json
{
  "mcpServers": {
    "pwn-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pwn-mcp",
               "fastmcp", "run", "main.py:mcp"],
      "env": {
        "PWN_MCP_PROXY_PORT": "8080"
      }
    }
  }
}
```

The proxy enforces the active `scope.txt` at the wire level, meaning agents
that route traffic through the proxy cannot reach out-of-scope targets even
if they try. Blocked flows are recorded in history with `scope_status: blocked`.

### CA certificate trust

mitmproxy auto-generates a CA at `~/.mitmproxy/mitmproxy-ca-cert.pem` on
first run. Trust it system-wide or pass it as `SSL_CERT_FILE` to your agent
process to enable full HTTPS inspection.

## Development

```bash
uv run pytest              # needs Postgres (docker compose up -d postgres)
uv run fastmcp dev main.py:mcp   # MCP inspector
```

Migrations (dbmate):

```bash
export DATABASE_URL=postgres://pwn:pwn@127.0.0.1:5432/pwn_mcp?sslmode=disable
dbmate --migrations-dir .migration up
```

Layout: `src/pwn_mcp/servers/{recon,crypto,scan,proxy,jobs,playbook}.py` are
child FastMCP servers mounted with namespaces in `server.py`. `scope.py` +
`middleware.py` implement the scope guardrail. `proxy_server.py` manages the
mitmproxy lifecycle, intercept, and telemetry. `store.py` / `jobs.py` persist
background jobs in PostgreSQL (`DATABASE_URL`; migrations in `.migration/`).
Bundled wordlists live in
`src/pwn_mcp/data/`.
