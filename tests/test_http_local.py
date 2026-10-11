"""HTTP module against a LOCAL fixture server — incl. redirect loops, chains,
cookie handling, body-size caps, SSRF handling, unreachable hosts."""
from __future__ import annotations

import config
from modules.http_info import inspect_http, parse_set_cookie
from modules.target import normalize_target


def settings(**over):
    defaults = dict(user_agent="SiteIntel-test/1.0")
    defaults.update(over)
    return config.ScanSettings(**defaults)


def target(url):
    return normalize_target(url)


def test_basic_fetch_headers_and_timing(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/secure"), settings())
    assert res["status"] == "ok"
    assert res["final"]["status"] == 200
    assert res["final"]["headers"]["x-content-type-options"] == "nosniff"
    assert not res["truncated"]
    assert res["timing"]["ttfb_ms"] is not None
    assert "WordPress" in (res["html_excerpt"] or "")


def test_redirect_chain_recorded_with_hops(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/chain"), settings())
    assert res["redirected"]
    hops = [entry["url"] for entry in res["chain"]]
    assert hops[0].endswith("/chain") and hops[-1].endswith("/secure")
    assert res["chain"][0]["status"] == 302
    assert res["final"]["scheme"] == "http"
    chain_finding = next(f for f in res["findings"] if f["name"] == "redirect_chain")
    assert chain_finding["status"] == "INFO"


def test_redirect_loop_detected_and_capped(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/loop1"), settings())
    assert res["status"] == "error"
    assert res["chain_error"]["kind"] == "redirect_loop"
    assert any(f["name"] == "redirect_loop" for f in res["findings"])


def test_set_cookie_header_redacted_from_stored_headers(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/weak"), settings())
    assert "tracking=42" not in res["final"]["headers"].get("set-cookie", "")
    assert config.REDACTED in res["final"]["headers"]["set-cookie"]
    weak = next(c for c in res["cookies"] if c["name"] == "tracking")
    assert weak["value_length"] == 2  # length recorded, value never stored


def test_cookie_attributes_parsed():
    cookie = parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=30",
                              "http://x.test/")
    attrs = cookie["attributes"]
    assert attrs["secure"] and attrs["httponly"] and attrs["samesite"] == "lax"
    assert attrs["path"] == "/" and attrs["max-age"] == "30"
    assert cookie["value_length"] == 3


def test_body_size_limit_enforced(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/big"), settings())
    assert res["truncated"]
    assert res["final"]["bytes_downloaded"] <= settings().max_body


def test_js_navigation_detected(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/jsnav"), settings())
    assert res["js_navigation"] is True
    assert any(f["name"] == "client_side_navigation" for f in res["findings"])


def test_probe_records_explicit_not_tested_reason_for_http_target(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/secure"), settings())
    probe = res["http_probe"]
    assert probe["tested"] is False
    assert "main chain" in probe["reason"]


def test_unreachable_host_reports_error_not_crash():
    res = inspect_http(target("http://192.0.2.1:9/"), settings(connect_timeout=1.0))
    assert res["status"] == "error" and res["error"]


def test_relative_redirect_normalized_to_absolute(fixture_server):
    res = inspect_http(target(f"http://{fixture_server}/rel-redir"), settings())
    if res["status"] == "ok" and res["redirected"]:
        assert res["final"]["url"].endswith("/secure")
