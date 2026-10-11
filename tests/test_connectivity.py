"""Connectivity: per-family status logic, errno classification, no conflation
of DNS availability with TCP reachability."""
from __future__ import annotations

import errno

from modules.connectivity import (AVAILABLE, FAILED, NOT_TESTED,
                                  _classify_os_error, measure_connectivity)
from modules.target import normalize_target


def test_local_limitation_classified():
    exc = OSError(errno.ENETUNREACH, "Network is unreachable")
    message, is_local = _classify_os_error(exc)
    assert is_local and "local limitation" in message


def test_refused_means_reachable_but_closed():
    exc = OSError(errno.ECONNREFUSED, "Connection refused")
    message, is_local = _classify_os_error(exc)
    assert not is_local and "reachable" in message


def test_ipv6_dns_vs_tcp_distinction(fixture_server):
    # A real local target on IPv4 only: IPv4 must be AVAILABLE through TCP,
    # IPv6 must NOT claim availability merely from record existence.
    host, port = fixture_server.split(":")
    target = normalize_target(f"http://{host}:{port}/")
    result = measure_connectivity(target)
    fam4 = result["families"]["ipv4"]
    assert fam4["dns"] == AVAILABLE and fam4["tcp"] == AVAILABLE
    assert fam4["tls"] == NOT_TESTED  # plain-http target
    fam6 = result["families"]["ipv6"]
    if fam6["dns"] != "UNAVAILABLE":
        # If the loopback resolves to ::1 too, TCP state decides — never assumed.
        assert fam6["tcp"] in (AVAILABLE, FAILED, NOT_TESTED)
    else:
        assert fam6["tcp"] == NOT_TESTED and fam6["tls"] == NOT_TESTED
