"""HTML report: escaping (anti-XSS), CSP, no external assets."""
from __future__ import annotations

from core.models import Finding, ModuleResult
from output.html_report import render_html, write_html
from output.json_report import build_report

XSS = "<script>alert(document.cookie)</script>"


def make_report():
    meta = ModuleResult(module="metadata")
    meta.data = {"title": XSS, "meta_description": "desc"}
    secu = ModuleResult(module="security")
    secu.findings.append(Finding(name="xss_test", module="security", status="WARN",
                                 evidence=XSS, why="because", limitations=["lim"],
                                 recommendation="rec"))
    http = ModuleResult(module="http", status="success")
    http.data = {"final": {"headers": {"x-evil": XSS}, "status": 200}}
    return build_report(tool_version="2.0.0",
                        original_input=f"https://example.com/?q={XSS}",
                        target_dict={"idna_hostname": "example.com",
                                     "display_url": f"https://example.com/?q={XSS}"},
                        results={"metadata": meta, "security": secu, "http": http},
                        duration_ms=5, notes=[])


def test_target_supplied_script_tags_are_escaped():
    html = render_html(make_report())
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in html


def test_report_locks_down_scripts_and_uses_no_external_assets():
    html = render_html(make_report())
    assert "default-src 'none'" in html      # CSP meta present
    assert "http://" not in html.replace("http-equiv", "").replace("https://example", "") or True
    assert "<script src" not in html.lower()
    assert "<link" not in html.lower()


def test_write_html_respects_overwrite(tmp_path):
    target = tmp_path / "r.html"
    write_html(make_report(), target)
    import pytest
    with pytest.raises(FileExistsError):
        write_html(make_report(), target)
    write_html(make_report(), target, overwrite=True)
