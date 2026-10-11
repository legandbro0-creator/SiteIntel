"""Connectivity diagnostics (spec §3B) — approximate timings and,
crucially, HONEST per-family availability.

The v1 lesson: "IPv6: yes" was displayed merely because an AAAA record
existed — even when the connect() failed with "Network is unreachable".
Now DNS availability, TCP reachability and TLS negotiation are reported
independently per address family, with explicit statuses:

  AVAILABLE / UNAVAILABLE / FAILED / NOT TESTED / INCONCLUSIVE

and local-device limitations (no IPv6 route on this network) are told
apart from remote server behaviour.
"""
from __future__ import annotations

import errno
import socket
import ssl
import time

import config
from core.target import TargetInfo

AVAILABLE = "AVAILABLE"
UNAVAILABLE = "UNAVAILABLE"
FAILED = "FAILED"
NOT_TESTED = "NOT TESTED"
INCONCLUSIVE = "INCONCLUSIVE"

TIMING_LIMITATIONS = [
    "Timings are single, approximate samples from YOUR current network vantage point.",
    "Mobile radios, resolver caches, routing and CDN distance heavily affect results.",
    "A slow response is not proof of a server-side problem.",
    "One extra TCP(+TLS) handshake per address family is used to measure connect times.",
]

# Errno families that mean "the LOCAL device/network can't do this" rather
# than "the remote server is broken".
_LOCAL_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL}


def _classify_os_error(exc: OSError) -> tuple[str, bool]:
    """Return (message, is_local_limitation)."""
    err = exc.errno
    if err in _LOCAL_ERRNOS:
        return (f"{exc.strerror or exc} — local limitation: this device/network has no "
                "working route for that address family.", True)
    if err == errno.ECONNREFUSED:
        return (f"Connection refused — the host IS reachable but nothing listens on this port.", False)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ("Timed out — inconclusive: could be the server, a firewall, or this network.", False)
    return (f"{exc.strerror or exc}", False)


def _probe_family(addresses: list[str], port: int, tls: bool, server_name: str) -> dict:
    entry: dict = {"dns": AVAILABLE, "addresses": addresses,
                   "tcp": NOT_TESTED, "tcp_ms": None,
                   "tls": NOT_TESTED, "tls_ms": None,
                   "error": None, "local_limitation": False}
    ip = addresses[0]
    sock = None
    try:
        started = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=config.CONNECT_TIMEOUT)
        entry["tcp"] = AVAILABLE
        entry["tcp_ms"] = round((time.perf_counter() - started) * 1000, 1)
        if tls:
            ctx = ssl.create_default_context()
            started = time.perf_counter()
            ssock = ctx.wrap_socket(sock, server_hostname=server_name)
            sock = None  # ownership moved
            entry["tls"] = AVAILABLE
            entry["tls_ms"] = round((time.perf_counter() - started) * 1000, 1)
            entry["tls_version"] = ssock.version()
            ssock.close()
        else:
            entry["tls"] = NOT_TESTED
            entry["error"] = "Plain-HTTP target: no TLS to negotiate."
    except ssl.SSLCertVerificationError as exc:
        # The handshake happened; verification failed.  TLS availability ≠ validity.
        entry["tls"] = AVAILABLE
        entry["tls_ms"] = None
        entry["error"] = f"Certificate verification failed during probe: {exc}"
    except ssl.SSLError as exc:
        entry["tls"] = FAILED
        entry["error"] = f"TLS negotiation failed: {exc}"
    except OSError as exc:
        message, is_local = _classify_os_error(exc)
        if entry["tcp"] == NOT_TESTED:
            entry["tcp"] = FAILED
        entry["error"] = message
        entry["local_limitation"] = is_local
        if is_local:
            entry["tls"] = NOT_TESTED
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return entry


def measure_connectivity(target: TargetInfo) -> dict:
    host, port = target.idna_hostname, target.effective_port
    use_tls = target.scheme == "https"
    result: dict = {"host": host, "port": port, "limitations": TIMING_LIMITATIONS}

    try:
        started = time.perf_counter()
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        result["dns_resolution_ms"] = round((time.perf_counter() - started) * 1000, 1)
    except socket.gaierror as exc:
        return dict(result, status="error", error=f"OS-level DNS resolution failed: {exc}",
                    ipv4={"dns": UNAVAILABLE, "tcp": NOT_TESTED, "tls": NOT_TESTED},
                    ipv6={"dns": UNAVAILABLE, "tcp": NOT_TESTED, "tls": NOT_TESTED})

    v4 = sorted({sa[0] for fam, *_rest, sa in infos if fam == socket.AF_INET})
    v6 = sorted({sa[0] for fam, *_rest, sa in infos if fam == socket.AF_INET6})

    families: dict[str, dict] = {}
    for name, addrs in (("ipv4", v4), ("ipv6", v6)):
        if addrs:
            families[name] = _probe_family(addrs, port, use_tls, host)
        else:
            families[name] = {"dns": UNAVAILABLE, "addresses": [],
                              "tcp": NOT_TESTED, "tcp_ms": None,
                              "tls": NOT_TESTED, "tls_ms": None,
                              "error": f"No {'A' if name == 'ipv4' else 'AAAA'} records — "
                                       "nothing to connect to.",
                              "local_limitation": False}
    result["families"] = families
    result["status"] = "ok" if any(f["tcp"] == AVAILABLE for f in families.values()) else "error"
    if result["status"] == "error":
        result["error"] = "No TCP connection succeeded on any address family (see per-family detail)."
    return result
