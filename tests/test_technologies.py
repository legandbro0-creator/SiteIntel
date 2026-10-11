"""Fingerprint matching: evidence, confidence, rule ids, false positives."""
from __future__ import annotations

from modules.technologies import detect_technologies, load_fingerprints


def detect(headers=None, html=None, cookies=None):
    return detect_technologies(headers=headers, html=html, cookies=cookies,
                               fingerprints=load_fingerprints())


def names(res):
    return {d["technology"]: d for d in res["detections"]}


def test_fingerprint_file_loads_with_ids():
    fps = load_fingerprints()
    assert len(fps) >= 15
    for fp in fps:
        assert fp["name"] and fp["rules"]
        assert all("id" in rule for rule in fp["rules"])


def test_nginx_server_header_high_confidence_with_rule_id():
    res = detect(headers={"Server": "nginx/1.24.0"})
    det = names(res)["Nginx"]
    assert det["confidence"] == "high"
    assert det["rule_ids"] and any("nginx" in rid for rid in det["rule_ids"])
    assert res["rules_matched"] >= 1 and res["rules_evaluated"] >= 15


def test_wordpress_multiple_evidence():
    html = '<meta name="generator" content="WordPress 6.5"><img src="/wp-content/uploads/x.png">'
    det = names(detect(html=html))["WordPress"]
    assert det["confidence"] == "high" and len(det["evidence"]) >= 2
    assert len(det["rule_ids"]) >= 2


def test_confusion_between_technologies_avoided():
    # jQuery pattern requires a version-ish or .js context.
    res = detect(html='<script src="/js/notjquery-like-library.js"></script>')
    assert "jQuery" not in names(res)
    res2 = detect(html='<script src="/js/jquery-3.7.1.min.js"></script>')
    assert "jQuery" in names(res2)


def test_server_header_singular_match():
    # "engineering blog generator" must not trip the nginx banner rule.
    res = detect(headers={"Server": "engineering-static-gen/2.0"})
    assert "Nginx" not in names(res)


def test_django_csrftoken_is_medium_not_certain():
    det = names(detect(cookies=[{"name": "csrftoken"}]))["Django"]
    assert det["confidence"] == "medium"


def test_no_evidence_no_detection():
    res = detect(headers={"Server": "gws"}, html="<html><body>plain</body></html>")
    assert res["detections"] == [] and res["rules_matched"] == 0


def test_skipped_without_http():
    assert detect_technologies(headers=None, html=None, cookies=None)["status"] == "skipped"
