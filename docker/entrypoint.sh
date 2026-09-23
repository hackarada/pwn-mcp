#!/bin/sh
set -eu

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

exec "$@"
