"""Result model: schema coercion, statuses, timestamps."""
from __future__ import annotations

from core.models import (FAIL, INCONCLUSIVE, INFO, NOT_TESTED, PASS, WARN,
                         Finding, ModuleResult)


def test_finding_new_taxonomy_serializes():
    f = Finding(name="hsts", module="security", status=WARN, severity="low",
                evidence="missing", why="matters", limitations=["one response"],
                recommendation="review policy")
    d = f.to_dict()
    assert d["status"] == WARN and d["timestamp"] and d["module"] == "security"
    assert d["limitations"] == ["one response"]


def test_legacy_labels_map_into_taxonomy():
    for old, new in (("GOOD", PASS), ("REVIEW", WARN), ("UNKNOWN", INCONCLUSIVE), ("INFO", INFO)):
        assert Finding(name="x", module="m", status=old).status == new


def test_wrap_plain_payload_normalizes_vocabulary():
    res = ModuleResult.wrap("tls", {"status": "ok", "cert": {"issuer": "CA"},
                                    "findings": [{"id": "cert_validity", "label": "PASS",
                                                  "observed": "verified"}]})
    assert res.module == "tls" and res.status == "success"
    assert res.findings[0].name == "cert_validity"
    assert res.findings[0].evidence == "verified"


def test_wrap_error_payload():
    res = ModuleResult.wrap("dns", {"status": "error", "error": "resolver died"})
    assert res.status == "error" and "resolver died" in res.errors


def test_module_result_to_dict_is_json_clean():
    import json
    res = ModuleResult(module="http")
    res.add_finding(Finding(name="n", module="http", status=FAIL))
    res.add_error("boom")
    blob = json.dumps(res.to_dict())
    assert '"boom"' in blob and res.status == "partial"


def test_whole_result_model_vocabulary():
    assert {PASS, WARN, FAIL, INFO, INCONCLUSIVE, NOT_TESTED} == \
           {"PASS", "WARN", "FAIL", "INFO", "INCONCLUSIVE", "NOT_TESTED"}
