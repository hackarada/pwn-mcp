#!/bin/sh
set -eu

# Apply dbmate migrations when DATABASE_URL is set (Postgres job store).
if [ -n "${DATABASE_URL:-}" ] && command -v dbmate >/dev/null 2>&1; then
  MIGRATIONS_DIR="${DBMATE_MIGRATIONS_DIR:-/app/.migration}"
  echo "pwn-mcp: waiting for database and running migrations (${MIGRATIONS_DIR})..."
  dbmate --url "${DATABASE_URL}" --migrations-dir "${MIGRATIONS_DIR}" --wait up
  echo "pwn-mcp: migrations up to date"
fi

# Refresh ProjectDiscovery nuclei templates on boot (default: on).
# Disable with PWN_MCP_UPDATE_NUCLEI_TEMPLATES=false for air-gapped / faster starts.
if command -v nuclei >/dev/null 2>&1; then
  case "${PWN_MCP_UPDATE_NUCLEI_TEMPLATES:-true}" in
    1|true|TRUE|yes|YES|on|ON)
      echo "pwn-mcp: updating nuclei templates..."
      if nuclei -update-templates; then
        echo "pwn-mcp: nuclei templates up to date"
      else
        echo "pwn-mcp: warning: nuclei template update failed; using existing templates" >&2
      fi
      ;;
  esac
fi

# Browser tools are mounted at process start. Wait until the sidecar accepts
# connections, and require the intercepting proxy so Chromium is not pointed
# at a closed port.
case "${PWN_MCP_BROWSER:-}" in
  1|true|TRUE|yes|YES|on|ON)
    if [ -z "${PWN_MCP_BROWSER_URL:-}" ]; then
      echo "pwn-mcp: PWN_MCP_BROWSER is set but PWN_MCP_BROWSER_URL is empty" >&2
      exit 1
    fi
    if [ -z "${PWN_MCP_PROXY_PORT:-}" ]; then
      echo "pwn-mcp: PWN_MCP_BROWSER requires PWN_MCP_PROXY_PORT so browser traffic is not sent to a closed proxy" >&2
      exit 1
    fi
    echo "pwn-mcp: waiting for Playwright MCP at ${PWN_MCP_BROWSER_URL}..."
    i=0
    while [ "$i" -lt 90 ]; do
      if python -c '
import socket, sys
from urllib.parse import urlparse
parsed = urlparse(sys.argv[1])
host = parsed.hostname
port = parsed.port or (443 if parsed.scheme == "https" else 80)
if not host:
    sys.exit(1)
socket.create_connection((host, port), 2).close()
' "${PWN_MCP_BROWSER_URL}"; then
        echo "pwn-mcp: Playwright MCP is accepting connections"
        break
      fi
      i=$((i + 1))
      sleep 1
    done
    if [ "$i" -eq 90 ]; then
      echo "pwn-mcp: Playwright MCP did not accept connections at ${PWN_MCP_BROWSER_URL}" >&2
      exit 1
    fi
    ;;
esac

exec "$@"
