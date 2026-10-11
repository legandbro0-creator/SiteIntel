"""SSRF-aware destination validation.

Why this exists: if a server replies
    HTTP/1.1 302 Found
    Location: http://169.254.169.254/latest/meta-data/   (cloud metadata!)
and we blindly followed every redirect, our little mobile scanner would
become a tool for reaching internal services — a classic SSRF pattern.

Policy (deliberate and documented):
* Only http/https URLs, valid hostname, valid port.
* EVERY resolved address must be globally routable.  `ipaddress.is_global`
  covers loopback, private, link-local, CGNAT, multicast, reserved,
  unspecified AND IPv4-mapped IPv6 forms (::ffff:10.0.0.1).
* Resolution failure cannot prove safety → treated as blocked.
* The check is applied to CROSS-ORIGIN redirect hops (see http_info):
  following a link to a new host must prove the new host isn't internal.
* The user's OWN initial target is exempt — scanning http://127.0.0.1:8000
  (your own test server) is legitimate usage.

Honest limitation: DNS can re-resolve between our check and the actual
request (TOCTOU).  Full mitigation requires pinning the connection to the
validated IP; that is noted in the report, not hidden.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from core.errors import SSRFBlocked
from core.target import safe_join_url

# Outbound ports allowed for redirected requests (web services only).
ALLOWED_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443}


def _block_reason(ip_text: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return f"unparseable address {ip_text!r}"
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) must unwrap before the global check.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_multicast or not addr.is_global:
        kind = ("multicast" if addr.is_multicast else
                "loopback" if addr.is_loopback else
                "private" if addr.is_private else
                "link-local" if addr.is_link_local else
                "reserved/unspecified")
        return f"non-public address {addr} ({kind})"
    return None


def validate_destination(url: str, allowed_ports: set[int] | None = None) -> str:
    """Validate an ABSOLUTE redirect destination; return the normalized URL
    or raise SSRFBlocked with a precise reason."""
    allowed_ports = allowed_ports or ALLOWED_PORTS
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SSRFBlocked(url, f"unparseable URL ({exc})")

    if parts.scheme.lower() not in ("http", "https"):
        raise SSRFBlocked(url, f"scheme {parts.scheme!r} is not http/https")
    host = parts.hostname
    if not host:
        raise SSRFBlocked(url, "no hostname")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        raise SSRFBlocked(url, "invalid port")
    if port not in allowed_ports:
        raise SSRFBlocked(url, f"port {port} not in allowed outbound set {sorted(allowed_ports)}")

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlocked(url, f"host did not resolve, cannot prove it is public ({exc})")
    addresses = {sockaddr[0] for *_rest, sockaddr in infos}
    for addr in addresses:
        reason = _block_reason(addr)
        if reason:
            raise SSRFBlocked(url, reason)

    return safe_join_url(url, url)  # normalized absolute form
