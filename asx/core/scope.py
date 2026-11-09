"""Scope definition and enforcement.

Nothing is scanned unless it is explicitly inside the declared scope.
Wide port ranges on public targets require an explicit allowance flag.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    pass


@dataclass
class Scope:
    """Allowed targets for a scan."""

    hosts: list[str] = field(default_factory=list)
    allow_wide_port_scan: bool = False
    allow_active_checks: bool = False
    max_ports: int = 1000

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(
            hosts=list(data.get("hosts", [])),
            allow_wide_port_scan=bool(data.get("allow_wide_port_scan", False)),
            allow_active_checks=bool(data.get("allow_active_checks", False)),
            max_ports=int(data.get("max_ports", 1000)),
        )

    @classmethod
    def single(cls, target: str) -> "Scope":
        host = extract_host(target)
        return cls(hosts=[host])

    def check_host(self, target: str) -> str:
        host = extract_host(target)
        if self.hosts and host not in self.hosts:
            raise ScopeError(
                f"Target '{host}' is not in scope. Declared hosts: {', '.join(self.hosts)}"
            )
        return host

    def check_port_count(self, count: int) -> None:
        if count > self.max_ports and not self.allow_wide_port_scan:
            raise ScopeError(
                f"Refusing to scan {count} ports: scope.max_ports={self.max_ports}. "
                "Set allow_wide_port_scan: true in scope.yaml to override."
            )


def extract_host(target: str) -> str:
    if "://" in target:
        host = urlparse(target).hostname or ""
    else:
        host = target.split("/")[0].split(":")[0]
    if not host:
        raise ScopeError(f"Cannot parse host from target: {target!r}")
    return host.lower()


def is_private_host(host: str) -> bool:
    """True if the host resolves to a private/loopback address (or is localhost)."""
    if host in {"localhost", "ip6-localhost"}:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False
