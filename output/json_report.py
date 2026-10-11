"""JSON export (spec §16): stable schema, safe writes.

* build_report() takes ModuleResult objects → their to_dict() form.
* write_report() REFUSES to overwrite an existing file unless the caller
  passes overwrite=True (main maps this to the --overwrite flag).
* No cookie values, no authorization data ever enter the report (they are
  redacted upstream in http_info / target), and everything routes through
  ensure_ascii=False UTF-8 JSON.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from core.models import ModuleResult

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
SCHEMA_VERSION = 3  # 1.x/2.x reports use no schema field; bump on breaking changes


def build_report(*, tool_version: str, original_input: str, target_dict: dict,
                 results: dict[str, ModuleResult], duration_ms: int,
                 notes: list[str]) -> dict:
    modules = {name: res.to_dict() for name, res in results.items()}
    return {
        "tool": "SiteIntel",
        "version": tool_version,
        "schema": SCHEMA_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": duration_ms,
        "input": original_input,
        "target": target_dict,
        "modules": modules,
        "module_status_summary": {name: res.status for name, res in results.items()},
        "notes": notes,
    }


def default_report_path(hostname: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9.-]+", "_", hostname) or "target"
    return REPORTS_DIR / f"{safe}-{stamp}.json"


def write_report(report: dict, path: str | Path | None = None,
                 hostname: str = "target", overwrite: bool = False) -> Path:
    target = Path(path).expanduser() if path else default_report_path(hostname)
    if target.is_dir():
        target = target / default_report_path(hostname).name
    if target.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite existing file: {target} (pass --overwrite to replace it)")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(target)
    return target


def load_report(path: str | Path) -> dict:
    return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
