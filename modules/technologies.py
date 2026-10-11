"""Module F — evidence-based technology fingerprinting.

Rules live OUTSIDE the code in data/fingerprints.json so you can add/improve
detections without touching Python — that is the whole point of the exercise.

Every detection reports: technology, evidence list, confidence
(low/medium/high).  Confidence rules:
  * 'high'   — near-unambiguous marker (e.g. X-Generator header, wp-content).
  * 'medium' — strong marker shared by several stacks (e.g. csrftoken cookie).
  * 'low'    — hint only (e.g. phpsessid tells you PHP, not which framework).
We report the strongest confidence reached; multiple hits are listed as
multiple evidence strings.  We never say "this IS WordPress".  We say
"evidence suggests WordPress with HIGH confidence" and show the evidence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

FINGERPRINTS_PATH = Path(__file__).resolve().parent.parent / "data" / "fingerprints.json"
_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def load_fingerprints(path: Path | None = None) -> list[dict]:
    path = path or FINGERPRINTS_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of fingerprint objects")
    return data


def _header_evidence(rule: dict, headers: dict[str, str]) -> list[str]:
    name = rule["header"].lower()
    pattern = re.compile(rule["pattern"], re.IGNORECASE)
    out = []
    if name in headers and pattern.search(headers[name]):
        out.append(f"Header '{rule['header']}: {headers[name]}' matches /{rule['pattern']}/i")
    return out


def _html_evidence(rule: dict, html: str) -> list[str]:
    pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
    match = pattern.search(html)
    if not match:
        return []
    snippet = match.group(0)
    snippet = snippet[:120] + ("…" if len(snippet) > 120 else "")
    return [f"HTML matches /{rule['pattern']}/i → «{snippet}»"]


def _cookie_evidence(rule: dict, cookie_names: list[str]) -> list[str]:
    pattern = re.compile(rule["pattern"], re.IGNORECASE)
    hits = [name for name in cookie_names if pattern.search(name)]
    return [f"Cookie name '{name}' matches /{rule['pattern']}/i" for name in hits]


_RULE_EVALUATORS = {
    "header": _header_evidence,
    "html": _html_evidence,
    "cookie": _cookie_evidence,
}


def detect_technologies(*, headers: dict | None, html: str | None,
                        cookies: list[dict] | None,
                        fingerprints: list[dict] | None = None) -> dict:
    if headers is None and html is None and not cookies:
        return {"status": "skipped", "note": "No HTTP evidence to fingerprint.", "detections": []}

    headers_l = {k.lower(): v for k, v in (headers or {}).items()}
    cookie_names = [c.get("name", "") for c in (cookies or [])]
    fingerprints = fingerprints if fingerprints is not None else load_fingerprints()

    detections = []
    matched_total = 0
    for fp in fingerprints:
        evidence: list[str] = []
        matched_rules: list[dict] = []
        best = 0
        for rule in fp.get("rules", []):
            evaluator = _RULE_EVALUATORS.get(rule.get("type"))
            if not evaluator:
                continue
            if rule["type"] == "header":
                hits = evaluator(rule, headers_l)
            elif rule["type"] == "html":
                hits = evaluator(rule, html or "")
            else:
                hits = evaluator(rule, cookie_names)
            if hits:
                evidence.extend(hits)
                matched_rules.append(rule)
                best = max(best, _CONFIDENCE_RANK.get(rule.get("confidence", "low"), 1))
        if evidence:
            detections.append({
                "technology": fp["name"],
                "category": fp.get("category", "unknown"),
                "confidence": {1: "low", 2: "medium", 3: "high"}[best],
                "evidence": evidence,
                "rule_ids": sorted({(rule.get("id") or f"{fp['name']}/{i}")
                                    for i, rule in enumerate(matched_rules)}),
            })
            matched_total += len(matched_rules)

    detections.sort(key=lambda d: (-_CONFIDENCE_RANK[d["confidence"]], d["technology"]))
    return {
        "status": "ok",
        "detections": detections,
        "rule_count": len(fingerprints),
        "rules_evaluated": len(fingerprints),
        "rules_matched": matched_total,
        "note": ("Detections are passive inferences from public evidence, not certainties; "
                 "a matched rule is listed with its evidence, an unmatched one says nothing. "
                 "Edit data/fingerprints.json to add or improve rules."),
    }
