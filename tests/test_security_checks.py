"""Security checks — v2 taxonomy, pure synthetic dicts."""
from __future__ import annotations

from core.models import FAIL, INCONCLUSIVE, INFO, NOT_TESTED, PASS, WARN
from modules.security_checks import run_security_checks

FULL_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def http_result(headers=None, scheme="https", cookies=None, html="",
                probe="auto", chain=None, status=200):
    final = {"scheme": scheme, "headers": headers or {}, "status": status,
             "url": f"{scheme}://site.test/"}
    res = {"status": "ok", "final": final, "cookies": cookies or [],
           "html_excerpt": html,
           "chain": chain if chain is not None else [{"hop": 1, "url": final["url"], "status": status}]}
    if probe == "auto":
        res["http_probe"] = {"tested": True, "probe_url": "http://site.test/",
                             "hops": [{"hop": 1, "url": "http://site.test/", "status": 301,
                                       "location": "https://site.test/"}],
                             "ends_on_https": True, "final_status": 200}
    elif isinstance(probe, dict):
        res["http_probe"] = probe
    return res


def by_name(findings, prefix):
    return next(f for f in findings if f["name"] == prefix or f["name"].startswith(prefix))


def run(**kw):
    tls = kw.pop("tls", {"status": "ok", "tls_version": "TLSv1.3"})
    res = run_security_checks(http_result=kw.pop("http", http_result()), tls_result=tls,
                              metadata_result=None)
    assert res["status"] == "ok"
    return res["findings"], res["summary"]


def test_fully_configured_site_passes():
    findings, summary = run(http=http_result(headers=FULL_HEADERS, cookies=[{
        "name": "session", "source": "u",
        "attributes": {"secure": True, "httponly": True, "samesite": "lax",
                       "domain": None, "path": "/"}}], html="<html><body>https assets only</body></html>"))
    statuses = {f["name"]: f["status"] for f in findings}
    assert statuses["https_available"] == PASS
    assert statuses["http_to_https"] == PASS
    assert statuses["hsts"] == PASS and statuses["content_security_policy"] == PASS
    assert statuses["framing_protection"] == PASS  # via frame-ancestors
    assert statuses["mixed_content"] == PASS
    assert statuses["x_content_type_options"] == PASS
    for f in findings:
        assert "timestamp" in f and f["module"] == "security"
        assert f["severity"] in (None, "low")  # never high for config observations


def test_missing_hsts_is_warn_low_never_high():
    findings, _ = run(http=http_result(headers={}))
    hsts = by_name(findings, "hsts")
    assert hsts["status"] == WARN and hsts["severity"] == "low"
    assert "not an exploit" in hsts["limitations"][0] or "endpoint" in hsts["limitations"][0]


def test_malformed_hsts_distinguished_from_missing():
    findings, _ = run(http=http_result(headers={"strict-transport-security": "banana"}))
    assert by_name(findings, "hsts")["status"] == WARN
    assert "malformed" in by_name(findings, "hsts")["evidence"]


def test_frame_ancestors_satisfies_framing_without_xfo():
    findings, _ = run(http=http_result(headers={"content-security-policy": "frame-ancestors 'none'"}))
    assert by_name(findings, "framing_protection")["status"] == PASS
    findings2, _ = run(http=http_result(headers={"x-frame-options": "DENY"}))
    assert by_name(findings2, "framing_protection")["status"] == PASS
    findings3, _ = run(http=http_result(headers={}))
    assert by_name(findings3, "framing_protection")["status"] == WARN


def test_coop_coep_corp_absent_is_info_not_warn():
    findings, _ = run(http=http_result(headers={}))
    assert by_name(findings, "cross_origin_policies")["status"] == INFO
    findings2, _ = run(http=http_result(headers={"cross-origin-opener-policy": "same-origin"}))
    assert by_name(findings2, "coop")["status"] == PASS


def test_http_probe_false_means_warn():
    probe = {"tested": True, "probe_url": "http://site.test/",
             "hops": [{"hop": 1, "url": "http://site.test/", "status": 200, "location": None}],
             "ends_on_https": False, "final_status": 200}
    findings, _ = run(http=http_result(headers={}, probe=probe))
    assert by_name(findings, "http_to_https")["status"] == WARN


def test_probe_not_tested_is_explicitly_inconclusive():
    probe = {"tested": False, "reason": "IP-literal target"}
    findings, _ = run(http=http_result(headers={}, probe=probe, scheme="https"))
    assert by_name(findings, "http_to_https")["status"] == INCONCLUSIVE
    assert "IP-literal" in by_name(findings, "http_to_https")["evidence"]


def test_plain_http_chain_is_warn_not_conclusive_https_failure():
    findings, _ = run(http=http_result(scheme="http", headers={}, probe=None,
                                       chain=[{"hop": 1, "url": "http://site.test/", "status": 200}]),
                      tls={"status": "skipped"})
    assert by_name(findings, "https_available")["status"] == WARN
    assert by_name(findings, "http_to_https")["status"] == WARN


def test_invalid_certificate_is_fail_with_moderate_severity():
    findings, _ = run(http=http_result(headers={}),
                      tls={"status": "error", "failure_kind": "expired",
                           "error": "certificate expired 3 days ago"})
    https = by_name(findings, "https_available")
    assert https["status"] == FAIL and https["severity"] == "medium"


def test_cookie_values_never_in_evidence_and_flags_assessed():
    cookies = [{"name": "tracking", "source": "u", "value_length": 40,
                "attributes": {"secure": False, "httponly": False, "samesite": None,
                               "domain": None, "path": None}}]
    findings, _ = run(http=http_result(headers={}, cookies=cookies))
    finding = by_name(findings, "cookie:")
    assert finding["status"] == WARN
    assert "value omitted" in finding["evidence"]
    assert "SAME" not in finding["evidence"]


def test_httponly_only_missing_is_info_not_warn():
    cookies = [{"name": "ui-theme", "source": "u", "value_length": 5,
                "attributes": {"secure": True, "httponly": False, "samesite": "lax",
                               "domain": None, "path": "/"}}]
    findings, _ = run(http=http_result(headers={}, cookies=cookies))
    assert by_name(findings, "cookie:")["status"] == INFO


def test_mixed_content_and_localhost_exemption():
    html = '<script src="http://nasty.example/x.js"></script><img src="http://127.0.0.1/y.png">'
    findings, _ = run(http=http_result(headers={}, html=html))
    finding = by_name(findings, "mixed_content")
    assert finding["status"] == WARN and "nasty.example" in finding["evidence"]
    assert "127.0.0.1" not in finding["evidence"]


def test_empty_inputs_yield_module_error_not_crash():
    res = run_security_checks(http_result=None, tls_result=None, metadata_result=None)
    assert res["status"] == "error"


def test_evidence_structure_complete():
    findings, _ = run(http=http_result(headers={}))
    for f in findings:
        assert f["name"] and f["status"] and f["evidence"] is not None
        assert isinstance(f["limitations"], list)
        assert f["status"] in (PASS, WARN, FAIL, INFO, INCONCLUSIVE, NOT_TESTED)
