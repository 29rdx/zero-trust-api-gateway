"""SSRF and DNS-Rebinding Guard for outbound API requests."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


class SSRFBlockedError(ValueError):
    """Raised when an outbound URL resolves to a disallowed network target."""


@dataclass(frozen=True)
class SSRFCheckResult:
    """Result of an SSRF URL validation."""

    url: str
    hostname: str
    resolved_ips: Tuple[str, ...]
    allowed: bool
    reason: str


_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud IMDS
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),        # IPv6 multicast
)

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.goog",
}


def _is_disallowed_ip(ip_str: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"invalid IP address: {ip_str}"

    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return f"disallowed non-public IP: {ip}"

    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return f"IP {ip} falls inside blocked CIDR {net}"
    return None


def _try_parse_obfuscated_ip(hostname: str) -> Optional[str]:
    """Detect decimal, hex (0x7f000001), or octal IPv4 literals."""
    host = hostname.strip()
    if not host:
        return None
    # Pure integer or hex integer form
    if host.startswith(("0x", "0X")):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except ValueError:
            return None
    if host.isdigit():
        try:
            val = int(host, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except ValueError:
            return None
    return None


def _default_resolver(hostname: str, port: int) -> List[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ips.append(sockaddr[0])
    return ips


def validate_outbound_url(
    url: str,
    *,
    allowed_schemes: Iterable[str] = ("https",),
    resolve_dns: bool = True,
    resolver: Optional[Callable[[str, int], List[str]]] = None,
) -> SSRFCheckResult:
    """
    Validates that an outbound URL uses an allowed scheme and does not resolve
    to internal, loopback, metadata, or obfuscated private IP targets.
    """
    if not url or not isinstance(url, str):
        raise SSRFBlockedError("URL must be a non-empty string")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    allowed_set = {s.lower() for s in allowed_schemes}
    if scheme not in allowed_set:
        raise SSRFBlockedError(f"Disallowed URL scheme '{scheme}'; allowed: {sorted(allowed_set)}")

    if parsed.username or parsed.password:
        raise SSRFBlockedError("Embedded URL credentials (user:pass@host) are forbidden")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise SSRFBlockedError("URL missing hostname")

    if hostname in _BLOCKED_HOSTNAMES or hostname.endswith((".local", ".internal", ".localhost")):
        raise SSRFBlockedError(f"Blocked internal hostname: {hostname}")

    obfuscated_ip = _try_parse_obfuscated_ip(hostname)
    if obfuscated_ip is not None:
        reason = _is_disallowed_ip(obfuscated_ip)
        if reason:
            raise SSRFBlockedError(f"Blocked obfuscated IP ({hostname} -> {obfuscated_ip}): {reason}")

    # Direct IP literal check
    direct_reason = _is_disallowed_ip(hostname)
    if direct_reason is not None and not direct_reason.startswith("invalid IP address"):
        raise SSRFBlockedError(direct_reason)

    resolved: List[str] = []
    if resolve_dns:
        port = parsed.port or (443 if scheme == "https" else 80)
        dns_fn = resolver or _default_resolver
        try:
            resolved = dns_fn(hostname, port)
        except OSError as exc:
            raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {exc}") from exc

        if not resolved:
            raise SSRFBlockedError(f"DNS resolution returned no addresses for {hostname}")

        for ip_str in resolved:
            reason = _is_disallowed_ip(ip_str)
            if reason:
                raise SSRFBlockedError(f"DNS rebinding / private resolution blocked for {hostname}: {reason}")

    return SSRFCheckResult(
        url=url,
        hostname=hostname,
        resolved_ips=tuple(resolved),
        allowed=True,
        reason="ok",
    )
