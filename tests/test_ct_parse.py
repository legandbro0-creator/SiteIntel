"""Certificate Transparency parsing + subdomains logic — offline."""
from __future__ import annotations

from datetime import datetime, timezone

from modules.certificate_transparency import (_hostnames_in_scope,
                                              parse_entries)
from modules.subdomains import normalize_name

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def entry(cn, sans, serial="aa", until="2030-01-01T00:00:00"):
    return {"issuer_name": "CN=Test CA", "serial_number": serial,
            "common_name": cn, "name_value": "\n".join([cn, *sans]),
            "not_before": "2025-01-01T00:00:00", "not_after": until,
            "entry_timestamp": "2025-01-02T00:00:00"}


def test_dedup_and_expiry_classification():
    entries = [entry("a.example.com", []), entry("a.example.com", []),
               entry("b.example.com", [], serial="bb", until="2020-01-01T00:00:00")]
    parsed = parse_entries(entries, now=NOW)
    assert parsed["certificate_count"] == 2  # duplicate removed
    current = [c for c in parsed["certificates"] if c["expired"] is False]
    expired = [c for c in parsed["certificates"] if c["expired"] is True]
    assert len(current) == 1 and len(expired) == 1


def test_hostname_scope_and_wildcards():
    parsed = parse_entries([entry("shop.example.com", ["*.example.com", "other.org"])], now=NOW)
    scoped = _hostnames_in_scope(parsed["hostnames"], "example.com")
    assert "shop.example.com" in scoped and "example.com" in scoped
    assert "other.org" not in scoped


def test_subdomain_normalize():
    assert normalize_name("*.API.Example.COM.", "example.com") == "api.example.com"
    assert normalize_name("example.com", "example.com") == "example.com"
    assert normalize_name("evil-example.com", "example.com") is None
    assert normalize_name("user@host.example.com", "example.com") is None
    assert normalize_name(" spaced name.example.com", "example.com") is None


def test_expired_cert_not_flagged_as_problem():
    parsed = parse_entries([entry("old.example.com", [], until="2019-06-01T00:00:00")], now=NOW)
    expired = [c for c in parsed["certificates"] if c["expired"] is True]
    assert expired and expired[0]["not_after"] == "2019-06-01T00:00:00"
