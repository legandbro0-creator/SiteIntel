"""URL & page intelligence extras (spec §14): robots.txt, sitemap.xml,
favicon hash.  All bounded, at most three small GETs to the scanned origin.

Teaching guardrails:
* robots.txt is advisory — "Disallow" is NOT access control.  Finding an
  interesting path there proves nothing about the path itself.
* sitemap.xml can be huge → strict byte cap; we COUNT <loc> entries.
* favicon hashes identify stock icons / shared infrastructure.
"""
from __future__ import annotations

import hashlib

import httpx

import config
from core.models import INFO, Finding
from core.target import TargetInfo

_MOD = "urls"


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation).to_dict()


def _fetch(client: httpx.Client, url: str) -> dict:
    try:
        with client.stream("GET", url) as response:
            body = bytearray()
            truncated = False
            for chunk in response.iter_bytes(8192):
                body.extend(chunk)
                if len(body) >= config.AUX_MAX_BYTES:
                    truncated = True
                    del body[config.AUX_MAX_BYTES:]
                    break
            if response.status_code == 404:
                return {"status": "absent", "http": 404}
            if response.status_code != 200:
                return {"status": "error", "error": f"HTTP {response.status_code}"}
            return {"status": "ok", "body": bytes(body), "truncated": truncated,
                    "content_type": response.headers.get("content-type", "")}
    except httpx.RequestError as exc:
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def _parse_robots(text: str) -> dict:
    disallows: list[str] = []
    sitemaps: list[str] = []
    current_agent = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            current_agent = value
        elif key == "disallow" and value and (current_agent in (None, "*")):
            if value not in disallows:
                disallows.append(value)
        elif key == "sitemap":
            sitemaps.append(value)
    return {"disallow_count_all_agents_sample": len(disallows), "disallows": disallows[:30],
            "sitemaps": sitemaps[:10]}


def inspect_urls(target: TargetInfo, settings, metadata_result: dict | None = None) -> dict:
    origin = target.origin
    findings: list[dict] = []
    result = {"status": "ok", "origin": origin, "robots": None, "sitemap": None, "favicon": None}
    try:
        client = httpx.Client(timeout=httpx.Timeout(connect=settings.connect_timeout, read=8.0,
                                                    write=8.0, pool=settings.connect_timeout),
                              headers={"User-Agent": settings.user_agent}, follow_redirects=True,
                              max_redirects=3)
    except Exception:
        client = None
    if client is None:
        return {"status": "error", "error": "could not create HTTP client"}
    with client:
        robots = _fetch(client, origin + "/robots.txt")
        if robots["status"] == "ok":
            parsed = _parse_robots(robots["body"].decode("utf-8", "replace"))
            robots.update(parsed)
            del robots["body"]
            findings.append(_f(
                "robots_txt", INFO,
                f"robots.txt present: {len(parsed['disallows'])} wildcard-Disallow path(s), "
                f"{len(parsed['sitemaps'])} sitemap reference(s)"
                + (" (truncated)" if robots.get("truncated") else ""),
                "It reveals what the owner asks crawlers to avoid — including admin or staging paths.",
                ["Disallow is ADVISORY, not access control; listed paths may or may not exist.",
                 f"Bounded to {config.AUX_MAX_BYTES // 1024} KB."],
                "Sensitive paths belong behind authentication, not in robots.txt."))
        elif robots["status"] == "absent":
            findings.append(_f("robots_txt", INFO, "No robots.txt (HTTP 404).",
                               "Nothing to report either way.", ["—"],
                               "Publish one to steer crawlers deliberately."))
        else:
            robots["note"] = "robots.txt unavailable"
        result["robots"] = robots

        sitemap_url = (result.get("robots", {}).get("sitemaps") or [None])[0] or origin + "/sitemap.xml"
        sitemap = _fetch(client, sitemap_url)
        if sitemap["status"] == "ok":
            count = sitemap["body"].lower().count(b"<loc>")
            result["sitemap"] = {"status": "ok", "url": sitemap_url, "loc_entries_estimate": count,
                                 "truncated": sitemap["truncated"]}
        else:
            result["sitemap"] = {"status": sitemap["status"], "url": sitemap_url,
                                 "error": sitemap.get("error")}

        favicon_path = (metadata_result or {}).get("favicon") or (origin + "/favicon.ico")
        if favicon_path.startswith("/"):
            favicon_path = origin + favicon_path
        if favicon_path.startswith(origin):
            favicon = _fetch(client, favicon_path)
            if favicon["status"] == "ok":
                result["favicon"] = {"status": "ok", "url": favicon_path,
                                     "bytes": len(favicon["body"]),
                                     "sha256": hashlib.sha256(favicon["body"]).hexdigest(),
                                     "content_type": favicon["content_type"]}
            else:
                result["favicon"] = {"status": favicon["status"], "url": favicon_path,
                                     "error": favicon.get("error")}
        else:
            result["favicon"] = {"status": "skipped", "note": "Favicon is on another origin; left unfetched."}

    result["findings"] = findings
    result["note"] = ("At most three small fetches to the scanned origin. "
                      "robots.txt is advisory metadata, not access control.")
    return result
