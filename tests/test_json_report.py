"""JSON export: schema, overwrite guard; diff: markers + volatile filtering."""
from __future__ import annotations

import json

import pytest

from core.models import Finding, ModuleResult
from output.diff import compare_reports
from output.json_report import build_report, write_report


def make_results(status_http="success", header_value="ECS", a_records=("93.184.215.14",)):
    http = ModuleResult(module="http", status=status_http)
    http.data = {"final": {"status": 200, "url": "https://example.com/",
                           "headers": {"server": header_value, "date": "Mon", "cf-ray": "x"}}}
    dns = ModuleResult(module="dns")
    dns.data = {"results": {"A": {"records": list(a_records), "status": "ok"}}}
    secu = ModuleResult(module="security")
    secu.data = {"summary": {"counts": {"PASS": 1}}}
    secu.findings.append(Finding(name="hsts", module="security", status="PASS",
                                 evidence="present"))
    return {"http": http, "dns": dns, "security": secu}


def make_report(header_value="ECS", a_records=("93.184.215.14",), http_status="success"):
    return build_report(tool_version="2.0.0", original_input="example.com",
                        target_dict={"idna_hostname": "example.com"},
                        results=make_results(http_status, header_value, a_records),
                        duration_ms=10, notes=[])


def test_report_schema_and_module_results(tmp_path):
    report = make_report()
    path = write_report(report, tmp_path / "r.json")
    loaded = json.loads(path.read_text())
    assert loaded["schema"] == 3 and loaded["tool"] == "SiteIntel"
    assert loaded["modules"]["http"]["status"] == "success"
    assert loaded["modules"]["security"]["findings"][0]["status"] == "PASS"
    assert loaded["module_status_summary"]["dns"] == "success"


def test_overwrite_refused_unless_requested(tmp_path):
    path = tmp_path / "r.json"
    write_report(make_report(), path)
    with pytest.raises(FileExistsError):
        write_report(make_report(), path)
    write_report(make_report(), path, overwrite=True)  # explicit is allowed


def test_diff_detects_changes_and_ignores_volatile_headers():
    old = make_report(header_value="ECS", a_records=("93.184.215.14",))
    new = make_report(header_value="gws", a_records=("203.0.113.9",))
    lines = "\n".join(compare_reports(old, new))
    assert "[+] DNS A: 203.0.113.9" in lines
    assert "[-] DNS A: 93.184.215.14" in lines
    assert "[~] HTTP header changed: server: ECS -> gws" in lines
    assert "cf-ray" not in lines and "date:" not in lines  # volatile, ignored


def test_diff_reports_module_status_differences():
    old = make_report()
    new = make_report(http_status="error")
    lines = "\n".join(compare_reports(old, new))
    assert "Module 'http' status differs" in lines


def test_diff_identical_reports_is_quiet():
    lines = compare_reports(make_report(), make_report())
    assert any("No meaningful changes" in line for line in lines)
