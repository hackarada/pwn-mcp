"""Authorized-target scope loading and matching (Scope 2.0).

A scope file is a plain-text list, one entry per line:

    example.com          # exact host (apex only)
    *.example.com        # apex + all subdomains
    10.0.0.0/8           # CIDR range
    192.168.1.10         # single IP
    !dev.example.com     # negative scope / exclusion (exact host)
    !*.internal.example.com # negative scope / exclusion (wildcard)
    !10.99.0.0/16        # negative scope / exclusion (CIDR)

Blank lines and ``#`` comments are ignored. Exclusions (prefixed with ``!``)
always override inclusions. The scope is loaded from the ``PWN_MCP_SCOPE``
environment variable, or from ``./scope.txt`` in the working directory.
When no scope file exists the server runs unrestricted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from pathlib import Path

from .util import is_ip, target_host

logger = logging.getLogger("pwn_mcp.scope")

ENV_VAR = "PWN_MCP_SCOPE"
DEFAULT_FILE = "scope.txt"


class Scope:
    """A parsed authorized-target list with positive and negative rules."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.hosts: set[str] = set()
        self.wildcards: set[str] = set()
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.excluded_hosts: set[str] = set()
        self.excluded_wildcards: set[str] = set()
        self.excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._resolve_cache: dict[str, list[str]] = {}

    @classmethod
    def parse(cls, text: str, source: str = "<inline>") -> Scope:
        scope = cls(source)
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip().lower()
            if not entry:
                continue

            is_exclusion = entry.startswith("!")
            if is_exclusion:
                entry = entry[1:].strip()
                if not entry:
                    continue

            target_wildcards = scope.excluded_wildcards if is_exclusion else scope.wildcards
            target_networks = scope.excluded_networks if is_exclusion else scope.networks
            target_hosts = scope.excluded_hosts if is_exclusion else scope.hosts

            if entry.startswith("*."):
                target_wildcards.add(entry[2:])
            elif "/" in entry:
                try:
                    target_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    logger.warning("Ignoring invalid CIDR scope entry: %s", entry)
            else:
                target_hosts.add(entry)
        return scope

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        return cls.parse(Path(path).read_text(), source=str(path))

    @property
    def empty(self) -> bool:
        return not (self.hosts or self.wildcards or self.networks)

    async def is_allowed(self, host: str) -> bool:
        """True if host is in scope and not explicitly excluded.

        Hostnames are also resolved to IPs when the scope contains CIDR entries.
        """
        host = host.lower().strip("[]")

        # 1. Exclusions take precedence
        if await self._is_excluded(host):
            return False

        # 2. Check inclusions
        if host in self.hosts:
            return True
        for apex in self.wildcards:
            if host == apex or host.endswith("." + apex):
                return True
        if is_ip(host):
            return self._ip_allowed(host, self.networks)
        if self.networks:
            for ip in await self._resolve(host):
                if self._ip_allowed(ip, self.networks):
                    return True
        return False

    async def is_allowed_target(self, target: str) -> bool:
        """Check a raw target string (URL, host:port, IP) against scope."""
        host = target_host(target)
        if not host:
            return False
        return await self.is_allowed(host)

    async def _is_excluded(self, host: str) -> bool:
        if host in self.excluded_hosts:
            return True
        for apex in self.excluded_wildcards:
            if host == apex or host.endswith("." + apex):
                return True
        if is_ip(host):
            return self._ip_allowed(host, self.excluded_networks)
        if self.excluded_networks:
            for ip in await self._resolve(host):
                if self._ip_allowed(ip, self.excluded_networks):
                    return True
        return False

    def _ip_allowed(
        self, ip: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    ) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in networks)

    async def _resolve(self, host: str) -> list[str]:
        if host in self._resolve_cache:
            return self._resolve_cache[host]
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                host, None, proto=0
            )
            ips = sorted({info[4][0] for info in infos})
        except OSError:
            ips = []
        self._resolve_cache[host] = ips
        return ips

    def describe(self) -> str:
        parts = []
        if self.hosts:
            parts.append(f"hosts={sorted(self.hosts)}")
        if self.wildcards:
            parts.append(f"wildcards={sorted(self.wildcards)}")
        if self.networks:
            parts.append(f"networks={[str(n) for n in self.networks]}")
        if self.excluded_hosts:
            parts.append(f"excluded_hosts={sorted(self.excluded_hosts)}")
        if self.excluded_wildcards:
            parts.append(f"excluded_wildcards={sorted(self.excluded_wildcards)}")
        if self.excluded_networks:
            parts.append(f"excluded_networks={[str(n) for n in self.excluded_networks]}")
        return f"Scope({self.source}: {', '.join(parts) or 'empty'})"


def load_scope() -> Scope | None:
    """Load the scope from ``PWN_MCP_SCOPE`` or ``./scope.txt`` if present."""
    env_path = os.environ.get(ENV_VAR)
    if env_path:
        path = Path(env_path)
        if not path.is_file():
            logger.warning("%s points to missing file %s; running UNRESTRICTED", ENV_VAR, path)
            return None
        scope = Scope.from_file(path)
    elif Path(DEFAULT_FILE).is_file():
        scope = Scope.from_file(DEFAULT_FILE)
    else:
        return None
    if scope.empty:
        logger.warning("Scope file %s is empty; running UNRESTRICTED", scope.source)
        return None
    logger.info("Loaded %s", scope.describe())
    return scope
