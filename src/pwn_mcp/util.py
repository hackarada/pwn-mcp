"""Shared helpers for pwn-mcp tool servers."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from urllib.parse import urlparse

MAX_BODY_CHARS = 8000

#: Argument names treated as scan/recon targets by scope enforcement.
TARGET_KEYS = ("url", "host", "target", "domain")

#: Playwright accessibility-tree element refs (e.g. e5, e12).
_A11Y_REF = re.compile(r"^[a-z]\d+$", re.IGNORECASE)
#: Single-label hostname / bare word (intranet, router).
_SINGLE_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)


def which(binary: str) -> str | None:
    """Return the path to a binary on PATH, or None."""
    return shutil.which(binary)


def is_probable_scan_target(value: str) -> bool:
    """True if *value* looks like a URL/host/IP, not an a11y ref or selector.

    Playwright MCP passes element refs (``e5``) as ``target``; those must not
    go through scope host checks. Real scan targets (``example.com``,
    ``https://…``, IPs, ``localhost``) still do.
    """
    v = value.strip()
    if not v:
        return False
    if "://" in v:
        return True
    if _A11Y_REF.fullmatch(v):
        return False
    if v.startswith((".", "#", "[", "/", "(")) or " " in v:
        return False
    host = target_host(v)
    if not host:
        return False
    if is_ip(host):
        return True
    if host in ("localhost", "localhost.localdomain"):
        return True
    if "." in host:
        return True
    return bool(_SINGLE_LABEL.fullmatch(host))


def run_cmd(args: list[str], timeout: float = 30.0) -> str:
    """Run a local binary and return combined output, truncated."""
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False
    )
    out = proc.stdout
    if proc.stderr:
        out += ("\n--- stderr ---\n" + proc.stderr) if out else proc.stderr
    if proc.returncode != 0:
        out = f"[exit code {proc.returncode}]\n{out}"
    return truncate(out.strip())


def truncate(text: str, limit: int = MAX_BODY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text)} chars total]"


def target_host(value: str) -> str:
    """Normalize a user-supplied target (URL, host[:port], domain, or IP) to a bare host."""
    value = value.strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower()
    # host:port or bare host
    host = value.split("/")[0]
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host.strip("[]").lower()  # strip [] from IPv6 literals


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
