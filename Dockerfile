# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm AS runtime

ARG INSTALL_PD_TOOLS=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        nmap \
        whois \
        dnsutils \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# dbmate for schema migrations (.migration/)
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
      x86_64) DBMATE_ARCH=amd64 ;; \
      aarch64|arm64) DBMATE_ARCH=arm64 ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/dbmate \
      "https://github.com/amacneil/dbmate/releases/download/v2.36.0/dbmate-linux-${DBMATE_ARCH}"; \
    chmod +x /usr/local/bin/dbmate

# ProjectDiscovery binaries (subfinder + nuclei) from GitHub releases.
# Asset names include the version, so resolve via the releases API.
RUN set -eux; \
    if [ "$INSTALL_PD_TOOLS" != "true" ]; then \
      apt-get purge -y unzip; \
      apt-get autoremove -y; \
      rm -rf /var/lib/apt/lists/*; \
      exit 0; \
    fi; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
      x86_64) PD_ARCH=amd64 ;; \
      aarch64|arm64) PD_ARCH=arm64 ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac; \
    download_pd() { \
      name="$1"; \
      url="$(curl -fsSL "https://api.github.com/repos/projectdiscovery/${name}/releases/latest" \
        | python3 -c "import json,sys; arch=sys.argv[1]; name=sys.argv[2]; \
assets=json.load(sys.stdin)['assets']; \
matches=[a['browser_download_url'] for a in assets \
  if a['name'].endswith(f'_linux_{arch}.zip') and name in a['name'] and 'checksum' not in a['name']]; \
assert matches, f'no asset for {name} linux/{arch}'; \
print(matches[0])" "$PD_ARCH" "$name")"; \
      curl -fsSL -o "/tmp/${name}.zip" "$url"; \
      unzip -qo "/tmp/${name}.zip" -d /usr/local/bin "$name"; \
      chmod +x "/usr/local/bin/${name}"; \
      rm -f "/tmp/${name}.zip"; \
    }; \
    download_pd subfinder; \
    download_pd nuclei; \
    download_pd httpx; \
    download_pd katana; \
    download_pd naabu; \
    download_pd dnsx; \
    apt-get purge -y unzip; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin pwnmcp \
    && mkdir -p /home/pwnmcp/.mitmproxy \
    && chown pwnmcp:pwnmcp /home/pwnmcp/.mitmproxy

# Fetch nuclei templates into the runtime user's home (used by scan_nuclei_scan).
RUN if [ "$INSTALL_PD_TOOLS" = "true" ]; then \
      set -eux; \
      mkdir -p /home/pwnmcp/nuclei-templates; \
      chown -R pwnmcp:pwnmcp /home/pwnmcp; \
      su -s /bin/sh pwnmcp -c 'nuclei -update-templates'; \
    fi

WORKDIR /app

COPY --from=builder --chown=pwnmcp:pwnmcp /app/.venv /app/.venv
COPY --chown=pwnmcp:pwnmcp scope.example.txt ./
COPY --chown=pwnmcp:pwnmcp .migration /app/.migration
COPY --chmod=755 docker/entrypoint.sh /entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PWN_MCP_TRANSPORT=http \
    PWN_MCP_HOST=0.0.0.0 \
    PWN_MCP_PORT=8000 \
    PWN_MCP_UPDATE_NUCLEI_TEMPLATES=true \
    DBMATE_MIGRATIONS_DIR=/app/.migration \
    HOME=/home/pwnmcp

USER pwnmcp

EXPOSE 8000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["pwn-mcp"]
