"""URL extras (robots/sitemap/favicon) against the local fixture."""
from __future__ import annotations

import config
from modules.urls import inspect_urls
from modules.target import normalize_target


def test_robots_sitemap_favicon(fixture_server):
    target = normalize_target(f"http://{fixture_server}/secure")
    settings = config.ScanSettings(user_agent="SiteIntel-test")
    result = inspect_urls(target, settings, metadata_result={"favicon": "/favicon.ico"})
    robots = result["robots"]
    assert robots["status"] == "ok"
    assert robots["disallow_count_all_agents_sample"] == 2
    assert "/admin" in robots["disallows"]
    assert result["sitemap"]["status"] == "ok"
    assert result["sitemap"]["loc_entries_estimate"] == 1
    fav = result["favicon"]
    assert fav["status"] == "ok" and fav["bytes"] == len(b"FAKEICONBYTES123456")
    assert len(fav["sha256"]) == 64
    robots_finding = next(f for f in result["findings"] if f["name"] == "robots_txt")
    assert "not access control" in " ".join(robots_finding["limitations"]) or \
           "NOT access control" in robots_finding["evidence"] + " ".join(robots_finding["limitations"])
