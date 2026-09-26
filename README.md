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

1. Typed recon (`recon_tech_fingerprint`, `recon_fetch_robots`, `recon_js_analyze`)
2. `recon_probe_paths` on the paths those calls returned. Read `kind`.
   `spa_shell` means the body matched the site index.
3. Follow the documents that are not the shell: JSON bodies, directory listings,
   login routes, parameters on real responses
4. Typed probes (`scan_sqli_probe`, `scan_reflected_xss_probe`, …) or `scan_cli_run`
5. Long work → `jobs_start` (kinds: `cli_run`, `nuclei_scan`, `nmap_scan`,
   `subfinder_enum`, `monitor_subs`, `hash_crack`)

`playbook_run` only batches those calls and returns the step data. It does not
decide that the test is finished.

**Wrappers vs `scan_cli_run`:** prefer typed tools (`scan_nuclei_scan`,
`scan_httpx_probe`, …). Use `scan_cli_run` when you need flags the wrapper
does not expose. Shell metacharacters, absolute paths, and file I/O flags
are rejected; targets are scope-checked.

Stack→bug hints are observations on `recon_tech_fingerprint`, not a test plan.
The agent decides when a target has no distinct documents left to request.

## Tool catalog

| Namespace   | Tools |
|---|---|
| `recon_`    | `http_request`, `http_batch`, `security_headers`, `tls_cert_info`, `tech_fingerprint`, `fetch_robots`, `dns_lookup`, `whois_lookup`, `cors_check`, `crawl_links`, `js_analyze`, `api_discover`, `probe_paths`, `websocket_probe`, `scope_check`, `secrets_scan`, `session_extract`, `url_triage` |
| `crypto_`   | `encode`, `decode`, `hash_text`, `hash_identify`, `jwt_decode`, `jwt_sign`, `jwt_attack`, `totp`, `hash_crack_enqueue`, `transform`, `xor`, `caesar` |
| `scan_`     | `port_scan`, `nmap_scan`, `subdomain_enum`, `subfinder_enum`, `httpx_probe`, `katana_crawl`, `naabu_scan`, `dnsx_resolve`, `nuclei_list_tags`, `nuclei_list_templates`, `nuclei_templates_version`, `nuclei_scan`, `cli_tools`, `cli_run`, `dir_bruteforce`, `content_discover`, `param_fuzz`, `reflected_xss_probe`, `open_redirect_check`, `graphql_probe`, `graphql_deep`, `ssti_probe`, `sqli_probe`, `ssrf_probe`, `idor_probe`, `cache_probe`, `host_header_probe`, `subdomain_takeover_check`, `cloud_bucket_probe` |
| `proxy_`    | `start`, `stop`, `status`, `history`, `get_traffic`, `endpoints`, `set_headers`, `clear`, `intercept`, `held`, `resume`, `replay`, `match_replace`, `match_replace_list`, `export_har`, `export_burp` |
| `jobs_`     | `start`, `status`, `result`, `list`, `cancel` |
| `playbook_` | `list`, `run` (`recon_surface`, `api_pass`, `xss_pass`, `web2_recon`) |
| `browser_*` | Optional — Playwright MCP HTTP sidecar (`PWN_MCP_BROWSER=1` + `PWN_MCP_BROWSER_URL`): `navigate`, `snapshot`, `click`, `type`, `fill_form`, `tabs`, `evaluate`, `take_screenshot`, … |

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

## Browser (optional Playwright MCP sidecar)

SPA / DOM work needs a real browser. Mount
[Playwright MCP](https://playwright.dev/mcp/introduction) over **HTTP** via
FastMCP's [Proxy Provider](https://gofastmcp.com/servers/providers/proxy).
Each MCP client connection gets its own Playwright session, kept open
across tool calls, so page state survives navigate, snapshot, and click.
Tools keep their native names (`browser_navigate`, `browser_snapshot`, …).

Compose profile `browser` runs Microsoft's image
(`mcr.microsoft.com/playwright/mcp`) as a sidecar on the internal network
only (no host port). pwn-mcp proxies to it; clients still talk only to
`http://<host>:8000/mcp`.

```bash
# .env
PWN_MCP_BROWSER=1
PWN_MCP_BROWSER_URL=http://playwright:8931/mcp
PWN_MCP_PROXY_PORT=8080
PWN_MCP_BROWSER_PROXY=http://pwn-mcp:8080   # compose DNS, not 127.0.0.1

docker compose --profile browser up -d --build
```

Chromium's `--proxy-server` is set on the **sidecar** (default
`http://pwn-mcp:8080`) so navigations flow through `proxy_*` and out-of-scope
hosts are blocked at the wire. Scope middleware also rejects out-of-scope
`browser_navigate` URLs; Playwright element refs (`target: "e5"`) are not
treated as hosts.

The sidecar listens on the compose network with `--allowed-hosts=*`. Without
that, Playwright allows only `localhost:8931`, returns 403 to pwn-mcp, and
`browser_*` tools never show up in `tools/list`. The port is not published
on the host.

The sidecar uses `--shared-browser-context` so HTTP clients share one browser
context. pwn-mcp keeps that session for the life of the client connection.

Playwright advertises `outputSchema: {}`. The MCP tool schema requires
`type: "object"` whenever that field is present, and a client that checks
it rejects the entire `tools/list` payload. pwn-mcp rewrites sidecar
schemas before they are listed, so `browser_*` and the local tools stay
visible together.

`PWN_MCP_PROXY_PORT` is required when the browser is enabled. The entrypoint
waits until the sidecar accepts connections, then starts the MCP process, so
`browser_*` tools are not mounted against a closed port.

Chromium runs in the sidecar. `http://127.0.0.1:3000/` from a browser tool is
the sidecar, not an app published on the host. Open
`http://host.docker.internal:3000/` (or whichever host port the app uses).

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
child FastMCP servers mounted with namespaces in `server.py`. Optional
Playwright MCP is mounted via `browser.py` (FastMCP Proxy Provider over HTTP)
when `PWN_MCP_BROWSER=1` and `PWN_MCP_BROWSER_URL` point at the compose
`playwright` sidecar (`--profile browser`). `scope.py` + `middleware.py`
implement the scope guardrail. `proxy_server.py` manages the mitmproxy
lifecycle, intercept, and telemetry. `store.py` / `jobs.py` persist background
jobs in PostgreSQL (`DATABASE_URL`; migrations in `.migration/`). Bundled
wordlists live in `src/pwn_mcp/data/`.
