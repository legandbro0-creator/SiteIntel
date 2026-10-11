"""SSRF destination validation — pure logic + address resolution of literals."""
from __future__ import annotations

import pytest

from core.errors import SSRFBlocked
from core.validation import validate_destination


def test_public_literal_allowed():
    assert validate_destination("http://93.184.215.14/").startswith("http://93.184.215.14")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",                 # loopback
    "http://127.0.0.1:8080/admin",       # alternative port, still loopback
    "http://10.0.0.5/",                  # RFC1918
    "http://172.16.3.4/",                # RFC1918
    "http://192.168.1.1/",               # RFC1918
    "http://169.254.169.254/latest",     # link-local cloud metadata
    "http://[::1]/",                     # IPv6 loopback
    "http://[fe80::1]/",                 # IPv6 link-local
    "http://[fd00::1]/",                 # IPv6 ULA (private)
    "http://0.0.0.0/",                   # unspecified
    "http://224.0.0.1/",                 # multicast
    "http://[::ffff:10.1.1.1]/",         # IPv4-mapped IPv6 private — must be caught
    "http://100.64.0.1/",                # CGNAT range — not global
    "ftp://93.184.215.14/",              # wrong scheme
    "file:///etc/passwd",
    "http://93.184.215.14:23/",          # port outside allowed outbound set
])
def test_restricted_destinations_blocked(url):
    with pytest.raises(SSRFBlocked) as excinfo:
        validate_destination(url)
    assert excinfo.value.reason


def test_unresolvable_host_blocked_because_safety_unprovable():
    with pytest.raises(SSRFBlocked):
        validate_destination("http://nonexistent.invalid/")


def test_error_carries_url_and_reason():
    try:
        validate_destination("http://192.168.0.1/")
    except SSRFBlocked as exc:
        assert exc.url == "http://192.168.0.1/"
        assert "192.168" in exc.reason and "private" in exc.reason
    else:  # pragma: no cover
        raise AssertionError("should have raised")
