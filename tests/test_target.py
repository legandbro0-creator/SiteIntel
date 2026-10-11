"""Target normalisation, IDN, redaction — pure, no network."""
from __future__ import annotations

import pytest

from core.errors import TargetError
from core.target import normalize_target, query_param_names, redact_url, safe_join_url


def test_bare_domain_assumes_https():
    t = normalize_target("example.com")
    assert t.scheme == "https" and t.scheme_assumed
    assert t.hostname == "example.com"
    assert t.registered_domain == "example.com"
    assert t.effective_port == 443


def test_full_url_with_path_query_fragment():
    t = normalize_target("https://blog.example.com/articles?id=7#top")
    assert t.hostname == "blog.example.com" and t.subdomain == "blog"
    assert t.registered_domain == "example.com"
    assert t.path == "/articles" and t.query == "id=7" and t.fragment == "top"
    assert "#" not in t.normalized_url


def test_custom_port_and_origin():
    t = normalize_target("http://example.com:8080/test")
    assert t.port == 8080 and t.origin == "http://example.com:8080"


def test_multi_part_suffix_domain():
    t = normalize_target("https://cdn.blog.example.co.uk/x")
    assert t.registered_domain == "example.co.uk" and t.subdomain == "cdn.blog"


def test_idn_to_punycode():
    t = normalize_target("https://münchen.de/")
    assert t.idna_hostname == "xn--mnchen-3ya.de" and t.hostname == "münchen.de"


def test_ip_literal_target():
    assert normalize_target("http://192.0.2.10:8000/").is_ip_literal
    assert normalize_target("http://[2001:db8::1]:8080/").hostname == "2001:db8::1"


def test_query_param_names_and_redaction():
    assert query_param_names("id=7&token=secret&empty=") == ["id", "token", "empty"]
    redacted = redact_url("https://x.test/p?id=7&token=AbCdEf&next=/home")
    assert "AbCdEf" not in redacted and "id=7" in redacted and "token=%3Credacted%3E" in redacted
    t = normalize_target("https://example.com/products?id=42&access_token=S3CRET")
    assert "S3CRET" not in t.display_url and "42" in t.display_url
    reported = t.to_dict()
    assert "S3CRET" not in reported["display_url"]
    assert reported["query_param_names"] == ["id", "access_token"]


def test_safe_join_url_relative_and_absolute():
    assert safe_join_url("https://a.com/x/y", "../z") == "https://a.com/z"
    assert safe_join_url("https://a.com/", "//b.com/path") == "https://b.com/path"
    assert safe_join_url("http://a.com/a", "?x=1") == "http://a.com/a?x=1"


@pytest.mark.parametrize("raw", [
    "", "   ", "ftp://example.com", "file:///etc/passwd",
    "https://exa mple.com/", "https://example.com:abc/",
    "https://-bad-.com/", "https://", "https://???/",
])
def test_invalid_inputs_rejected(raw):
    with pytest.raises(TargetError):
        normalize_target(raw)
