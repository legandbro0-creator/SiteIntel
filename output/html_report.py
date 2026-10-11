"""Standalone HTML report (spec §17): dark terminal-inspired, phone-readable,
zero JavaScript, zero external assets.

Security posture (enforced at the TEMPLATE level):
* every interpolated value passes through html.escape — target-controlled
  strings (titles, headers, DNS TXT) can never inject markup,
* a restrictive CSP meta tag disables scripts entirely,
* no inline event handlers anywhere in the template.
"""
from __future__ import annotations

from html import escape as esc

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:12px}
h1{font-size:1.4rem;color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px}
h2{font-size:1.1rem;color:#58a6ff;margin:22px 0 6px}
.cards{display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px}
.card b{display:block;color:#8b949e;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;display:block;overflow-x:auto}
th,td{border:1px solid #30363d;padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{color:#8b949e;font-size:.8rem}
details{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:8px 10px;margin:8px 0}
summary{cursor:pointer;color:#58a6ff}
pre{white-space:pre-wrap;word-break:break-word;background:#0d1117;padding:8px;border-radius:6px}
.kv{color:#8b949e}
.PASS{color:#3fb950}.WARN{color:#d29922}.FAIL{color:#f85149}
.INFO{color:#58a6ff}.INCONCLUSIVE{color:#bc8cff}.NOT_TESTED{color:#8b949e}
.dim{color:#8b949e}.foot{margin-top:30px;color:#8b949e;font-size:.8rem;border-top:1px solid #30363d;padding-top:10px}
"""

_STATUS_CLASS = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL",
                 "INFO": "INFO", "INCONCLUSIVE": "INCONCLUSIVE", "NOT_TESTED": "NOT_TESTED",
                 "GOOD": "PASS", "REVIEW": "WARN", "UNKNOWN": "INCONCLUSIVE"}


def _e(value) -> str:
    return esc("—" if value is None else str(value), quote=True)


def _finding_html(f: dict) -> str:
    status = _STATUS_CLASS.get(f.get("status") or f.get("label") or "INFO", "INFO")
    label = f.get("status") or f.get("label") or "INFO"
    name = f.get("name") or f.get("id") or "finding"
    sev = f' <span class="dim">severity={_e(f["severity"])}</span>' if f.get("severity") else ""
    rows = []
    observed = f.get("evidence") or f.get("observed")
    if observed:
        rows.append(f"<div><span class='kv'>Observed:</span> {_e(observed)}</div>")
    why = f.get("why") or f.get("why_it_matters")
    if why:
        rows.append(f"<div><span class='kv'>Why it matters:</span> {_e(why)}</div>")
    limitations = f.get("limitations") or ([f["limitation"]] if f.get("limitation") else [])
    for lim in limitations:
        if lim and lim != "—":
            rows.append(f"<div><span class='kv'>Limitation:</span> {_e(lim)}</div>")
    if f.get("recommendation"):
        rows.append(f"<div><span class='kv'>Consider:</span> {_e(f['recommendation'])}</div>")
    return (f"<details><summary><b class='{status}'>[{_e(label)}]</b> {_e(name)}{sev}</summary>"
            + "".join(rows) + "</details>")


def _kv_pairs(data: dict) -> list[tuple[str, str]]:
    """Flatten a module's scalars into display pairs; complex values → JSON blocks."""
    import json as _json
    pairs = []
    for key, value in data.items():
        if value is None or isinstance(value, bool) or isinstance(value, (int, float)) or \
           (isinstance(value, str) and len(value) <= 300):
            pairs.append((key, value))
    return pairs


def _module_section(name: str, mod: dict) -> str:
    status = _e(mod.get("status", "unknown"))
    status_class = {"success": "PASS", "ok": "PASS", "partial": "WARN",
                    "error": "FAIL", "skipped": "dim"}.get(mod.get("status"), "INFO")
    out = [f"<h2>{_e(name)} <span class='{status_class}' style='font-size:.8em'>[{status}]</span>"
           f" <span class='dim' style='font-size:.75em'>{_e(mod.get('duration_ms', '—'))} ms</span></h2>"]
    if mod.get("errors"):
        out.append("<pre class='FAIL'>" + _e("; ".join(map(str, mod["errors"]))) + "</pre>")
    data = mod.get("data") if isinstance(mod.get("data"), dict) else mod
    if isinstance(data, dict):
        pairs = _kv_pairs({k: v for k, v in data.items()
                           if k not in ("html_excerpt", "findings")})
        if pairs:
            rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in pairs[:80])
            out.append(f"<table>{rows}</table>")
        import json as _json
        complex_keys = {k: v for k, v in data.items()
                        if isinstance(v, (list, dict)) and k not in ("findings",)}
        for key, value in list(complex_keys.items())[:12]:
            rendered = _json.dumps(value, ensure_ascii=False, indent=1)
            if len(rendered) > 4000:
                rendered = rendered[:4000] + "\n… (truncated in HTML view; full data in --json)"
            out.append(f"<details><summary>{_e(key)}</summary><pre>{_e(rendered)}</pre></details>")
    findings = mod.get("findings") or []
    if findings:
        out.append(f"<h3 class='dim' style='margin:10px 0 0'>{len(findings)} finding(s)</h3>")
        out.extend(_finding_html(f) for f in findings)
    return "".join(out)


def render_html(report: dict) -> str:
    target = report.get("target") or {}
    summary = report.get("module_status_summary") or \
        {name: (mod.get("status", "?") if isinstance(mod, dict) else "?")
         for name, mod in (report.get("modules") or {}).items()}
    cards = "".join(
        f"<div class='card'><b>{_e(label)}</b>{_e(value)}</div>"
        for label, value in (
            ("Target", report.get("input")),
            ("Normalised", target.get("display_url") or target.get("normalized_url")),
            ("Started (UTC)", report.get("timestamp_utc")),
            ("Duration", f"{report.get('duration_ms')} ms"),
            ("Tool", f"SiteIntel {report.get('version')}")))

    module_cards = "".join(
        f"<div class='card'><b>{_e(name)}</b>"
        f"<span class='{_STATUS_CLASS.get('PASS' if st in ('success', 'ok') else 'WARN' if st == 'partial' else 'FAIL' if st == 'error' else 'INFO', 'INFO')}'>{_e(st)}</span></div>"
        for name, st in summary.items())

    sections = []
    for name, mod in (report.get("modules") or {}).items():
        if isinstance(mod, dict):
            sections.append(_module_section(name, mod))

    notes = "".join(f"<div class='dim'>{_e(n)}</div>" for n in report.get("notes") or [])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SiteIntel report — {_e(report.get("input"))}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>SITEINTEL REPORT</h1>
<div class="cards">{cards}</div>
<h2 style="margin-top:26px">Module execution</h2>
<div class="cards">{module_cards}</div>
{''.join(sections)}
{notes}
<div class="foot">
Generated by SiteIntel {_e(report.get('version'))}. All target-derived text is HTML-escaped.
Findings are observations, not vulnerability claims. CSP of this document: default-src 'none'.
</div>
</body>
</html>"""


def write_html(report: dict, path, overwrite: bool = False):
    from pathlib import Path
    target = Path(path).expanduser()
    if target.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite existing file: {target} (pass --overwrite to replace it)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(report), encoding="utf-8")
    return target
