"""Standardized result model (spec §4/§6).

Two dataclasses used by EVERY module and rendered by output/:

  Finding      — one classified observation (PASS/WARN/FAIL/INFO/
                 INCONCLUSIVE/NOT_TESTED) with evidence, why-it-matters,
                 limitations, recommendation, optional severity, timestamp
                 and producing module.
  ModuleResult — status + data dict + findings + errors + duration, with
                 stable serialization for the JSON report.

Also keeps the legacy vocabulary mapping so old saved reports can be read.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# --- Finding statuses ------------------------------------------------------
PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
INFO, INCONCLUSIVE, NOT_TESTED = "INFO", "INCONCLUSIVE", "NOT_TESTED"
FINDING_STATUSES = (PASS, WARN, FAIL, INFO, INCONCLUSIVE, NOT_TESTED)

# --- Module statuses ---------------------------------------------------------
SUCCESS, PARTIAL, ERROR, SKIPPED = "success", "partial", "error", "skipped"
MODULE_STATUSES = (SUCCESS, PARTIAL, ERROR, SKIPPED)

# Severity is OPTIONAL and conservative: a missing header never scores "high".
SEVERITIES = ("none", "low", "medium", "high")

# Map the old GOOD/INFO/REVIEW/UNKNOWN vocabulary onto the new one, so both
# terminal renderers and diff can consume findings from either generation.
LEGACY_STATUS_MAP = {"GOOD": PASS, "REVIEW": WARN, "INFO": INFO, "UNKNOWN": INCONCLUSIVE,
                     "ok": SUCCESS, "no_records": ERROR}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    name: str
    module: str
    status: str
    evidence: str = ""
    why: str = ""
    limitations: list[str] = field(default_factory=list)
    recommendation: str = ""
    severity: str | None = None
    timestamp: str = field(default_factory=utcnow)

    def __post_init__(self):
        if self.status in LEGACY_STATUS_MAP:
            self.status = LEGACY_STATUS_MAP[self.status]
        assert self.status in FINDING_STATUSES, self.status
        if self.severity is not None:
            assert self.severity in SEVERITIES, self.severity

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    status: str = SUCCESS
    data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow)
    duration_ms: int = 0

    # -- construction helpers -------------------------------------------------
    def finish(self, status: str | None = None, duration_ms: int | None = None) -> "ModuleResult":
        if status:
            assert status in MODULE_STATUSES, status
            self.status = status
        if duration_ms is not None:
            self.duration_ms = duration_ms
        if self.errors and self.status == SUCCESS:
            self.status = PARTIAL
        return self

    def add_finding(self, finding: Finding) -> None:
        if finding.module != self.module:
            finding.module = self.module
        self.findings.append(finding)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        if self.status == SUCCESS:
            self.status = PARTIAL

    # -- intake of legacy/plain dict payloads ---------------------------------
    @staticmethod
    def _coerce_finding(module: str, raw) -> Finding:
        if isinstance(raw, Finding):
            if raw.module != module:
                raw.module = module
            return raw
        if isinstance(raw, dict):
            known = {k: raw.get(k) for k in
                     ("name", "status", "evidence", "why", "limitations",
                      "recommendation", "severity", "timestamp") if k in raw}
            # tolerate the v1 field names on the way in
            if "id" in raw and "name" not in known:
                known["name"] = raw["id"]
            if "label" in raw and "status" not in known:
                known["status"] = raw["label"]
            if "observed" in raw and "evidence" not in known:
                known["evidence"] = raw["observed"]
            if "why_it_matters" in raw and "why" not in known:
                known["why"] = raw["why_it_matters"]
            if "limitation" in raw and "limitations" not in known:
                known["limitations"] = [raw["limitation"]] if raw["limitation"] else []
            known.setdefault("name", "finding")
            known.setdefault("status", INFO)
            return Finding(module=module, **known)
        return Finding(module=module, name="finding", status=INFO, evidence=str(raw))

    @classmethod
    def wrap(cls, module: str, payload) -> "ModuleResult":
        """Normalize any module return into a ModuleResult."""
        if isinstance(payload, cls):
            return payload
        if not isinstance(payload, dict):
            return cls(module=module, status=ERROR, errors=[f"module returned {type(payload).__name__}"])
        status_map = {"ok": SUCCESS, "partial": PARTIAL, "error": ERROR,
                      "skipped": SKIPPED, "success": SUCCESS}
        status = status_map.get(str(payload.get("status", "ok")).lower(), SUCCESS)
        data = {k: v for k, v in payload.items() if k != "findings"}
        result = cls(module=module, status=status, data=data)
        for raw in payload.get("findings") or []:
            result.findings.append(cls._coerce_finding(module, raw))
        if payload.get("error"):
            result.errors.append(str(payload["error"]))
        return result

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "status": self.status,
            "data": _json_safe(self.data),
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
        }


def _json_safe(obj):
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        if isinstance(obj, dict):
            return {str(k): _json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_json_safe(v) for v in obj]
        return repr(obj)
