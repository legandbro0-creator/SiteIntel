"""Module B tests — formatting and resolver logic; no live queries needed."""
from __future__ import annotations

import dns.rdata

from modules.dns_info import build_resolver, extract_ips, format_rdata


def r(text, rdtype):
    return dns.rdata.from_text("IN", rdtype, text)


def test_format_a_and_aaaa():
    assert format_rdata("A", r("93.184.215.14", "A")) == "93.184.215.14"
    assert format_rdata("AAAA", r("2606:2800:21f:cb07:6820:80da:af6b:8b2c", "AAAA")).count(":") >= 5


def test_format_mx_priority_first():
    assert format_rdata("MX", r("10 mail.example.com.", "MX")) == "10 mail.example.com."


def test_format_txt_concatenates_chunks():
    rec = r('"v=spf1 " "include:_spf.example.com ~all"', "TXT")
    assert format_rdata("TXT", rec) == "v=spf1 include:_spf.example.com ~all"


def test_format_caa_and_soa():
    assert 'issue' in format_rdata("CAA", r('0 issue "letsencrypt.org"', "CAA"))
    soa = r("ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300", "SOA")
    text = format_rdata("SOA", soa)
    assert "serial=2024010101" in text and "minimum=300" in text


def test_explicit_resolver_is_used_and_annotated():
    resolver, used, note = build_resolver(["9.9.9.9"])
    assert used == ["9.9.9.9"] and "--resolver" in note
    assert resolver.nameservers == ["9.9.9.9"]


def test_extract_ips_deduplicates():
    fake = {"results": {"A": {"records": ["1.2.3.4", "1.2.3.4"]},
                        "AAAA": {"records": ["::1"]}}}
    assert extract_ips(fake) == ["1.2.3.4", "::1"]
