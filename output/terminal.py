"""Terminal output (spec §21): Rich when available, graceful plain fallback.

Consumes core.models.ModuleResult / Finding.  Rendering rules:
* findings use the v2 taxonomy colours (PASS/WARN/FAIL/INFO/INCONCLUSIVE/NOT_TESTED),
* IP results are structured kv blocks — nothing important is ever truncated
  to fit a column (long IPv6/prefixes/PTRs wrap),
* DNS TXT-ish values are summarised to 80 chars unless --full-dns,
* --quiet switches to a compact one-line-per-module overview,
* full evidence is always reachable via --json/--html exports.
"""
from __future__ import annotations

import shutil
import textwrap

from core.models import (FAIL, INCONCLUSIVE, INFO, NOT_TESTED, PASS, WARN,
                         ModuleResult)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _HAVE_RICH = True
except ImportError:
    _HAVE_RICH = False

_STATUS_COLORS = {PASS: "green", WARN: "yellow", FAIL: "red",
                  INFO: "cyan", INCONCLUSIVE: "magenta", NOT_TESTED: "dim"}
_STATUS_MARKS = {PASS: "+", WARN: "!", FAIL: "F", INFO: "i", INCONCLUSIVE: "~", NOT_TESTED: "-"}
_WIDTH = min(shutil.get_terminal_size((100, 40)).columns, 110)
TRUNC = 80


def _t(value, full: bool = False):
    if value is None:
        return "—"
    text = str(value)
    if full or len(text) <= TRUNC:
        return text
    return text[: TRUNC - 1] + "…"


# --------------------------------------------------------------------------
class PlainReporter:
    quiet = False

    def _wrap(self, text: str) -> list[str]:
        lines = []
        for paragraph in str(text).splitlines() or [""]:
            lines.extend(textwrap.wrap(paragraph, _WIDTH - 6) or [""])
        return lines

    def banner(self, pairs):
        bar = "=" * (_WIDTH - 1)
        print(f"\n{bar}\n  SITEINTEL REPORT\n{bar}")
        self.kv(pairs)

    def section(self, title: str):
        print(f"\n--- {title} ".ljust(_WIDTH - 1, "-"))

    def kv(self, pairs, title: str | None = None):
        if title:
            print(title)
        width = max((len(str(k)) for k, _ in pairs), default=0)
        for key, value in pairs:
            wrapped = self._wrap("—" if value is None else str(value))
            print(f"  {str(key):<{width}} : {wrapped[0]}")
            pad = " " * (width + 5)
            for line in wrapped[1:]:
                print(pad + line)

    def table(self, headers, rows, title: str | None = None):
        if title:
            print(title)
        rows = [["" if c is None else str(c) for c in row] for row in rows]
        widths = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                lines = cell.splitlines() or [""]
                widths[i] = min(max([widths[i], *[len(x) for x in lines]]), 60)
        fmt = "  " + " | ".join("{:" + str(w) + "}" for w in widths)
        print(fmt.format(*[str(h) for h in headers]))
        print(fmt.format(*["-" * w for w in widths]))
        for row in rows:
            # wrap each logical line of every cell to 60 cols, then print row line-by-line
            expanded = [[piece for line in (cell.splitlines() or [""])
                         for piece in (textwrap.wrap(line, 60) or [""])]
                        for cell in row]
            for line_idx in range(max(map(len, expanded))):
                print(fmt.format(*[(c[line_idx] if line_idx < len(c) else "")[:w]
                                     for c, w in zip(expanded, widths)]))

    def status(self, label: str, text: str):
        print(f"  [{_STATUS_MARKS.get(label, '?')}] {text}")

    def findings(self, findings):
        for f in findings:
            sev = f" severity={f.severity}" if f.severity else ""
            self.status(f.status, f"{f.name}{sev}")
            body = [("Observed", f.evidence), ("Why", f.why)]
            body += [("Limitation", lim) for lim in (f.limitations or []) if lim and lim != "—"]
            body.append(("Consider", f.recommendation))
            for heading, value in body:
                if not value or value == "—":
                    continue
                for line in self._wrap(f"{heading}: {value}"):
                    print("      " + line)
            print()

    def note(self, text):
        if not self.quiet:
            print(f"  note: {text}")

    def warn(self, text):
        print(f"  warning: {text}")

    def error(self, text):
        print(f"  ERROR: {text}")

    def compact(self, name: str, status: str, ms: int, errors: list[str]):
        print(f"  {name:<20} {status:<9} {ms:>6} ms" + (f"  errors: {'; '.join(errors)}" if errors else ""))


class RichReporter(PlainReporter):
    def __init__(self):
        self.console = Console(width=_WIDTH, highlight=False)

    def banner(self, pairs):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column()
        for key, value in pairs:
            grid.add_row(str(key), str(value))
        self.console.print(Panel(grid, title="[bold]SITEINTEL REPORT[/bold]",
                                 border_style="blue", expand=False))

    def section(self, title: str):
        self.console.rule(f"[bold blue]{title}")

    def kv(self, pairs, title: str | None = None):
        if title:
            self.console.print(f"[bold]{title}")
        table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
        table.add_column(style="cyan", justify="right", no_wrap=True)
        table.add_column()
        for key, value in pairs:
            table.add_row(str(key), "—" if value is None else str(value))
        self.console.print(table)

    def table(self, headers, rows, title: str | None = None):
        table = Table(title=title, header_style="bold", box=None, padding=(0, 1))
        for h in headers:
            table.add_column(str(h), overflow="fold")
        for row in rows:
            table.add_row(*["—" if c is None else str(c) for c in row])
        self.console.print(table)

    def status(self, label: str, text: str):
        color = _STATUS_COLORS.get(label, "white")
        self.console.print(f"  [{color}][{label}][/{color}] {text}")

    def findings(self, findings):
        for f in findings:
            color = _STATUS_COLORS.get(f.status, "white")
            sev = f" severity={f.severity}" if f.severity else ""
            self.console.print(f"  [{color}][{f.status}][/{color}] [bold]{f.name}[/bold][dim]{sev}[/dim]")
            parts = [("Observed", f.evidence), ("Why", f.why)]
            parts += [("Limitation", lim) for lim in (f.limitations or []) if lim and lim != "—"]
            parts.append(("Consider", f.recommendation))
            for heading, value in parts:
                if value and value != "—":
                    self.console.print(f"      [dim]{heading}:[/dim] {value}")
            self.console.print()

    def note(self, text):
        if not self.quiet:
            self.console.print(f"  [dim]note: {text}[/dim]")

    def warn(self, text):
        self.console.print(f"  [yellow]warning:[/yellow] {text}")

    def error(self, text):
        self.console.print(f"  [red]ERROR:[/red] {text}")

    def compact(self, name: str, status: str, ms: int, errors: list[str]):
        color = {"success": "green", "partial": "yellow", "error": "red", "skipped": "dim"}.get(status, "white")
        tail = f"  errors: {'; '.join(errors)}" if errors else ""
        self.console.print(f"  {name:<20} [{color}]{status:<9}[/{color}] {ms:>6} ms{tail}")


def get_reporter(color: bool = True, quiet: bool = False):
    if color and _HAVE_RICH:
        rep = RichReporter()
    else:
        rep = PlainReporter()
        if color and not _HAVE_RICH and not quiet:
            rep.note("Install 'rich' for coloured tables (pip install rich); using plain output.")
    rep.quiet = quiet
    return rep


# --------------------------------------------------------------------------
# Per-module renderers (ModuleResult in, rows out)
# --------------------------------------------------------------------------
def render_target(rep, t):
    rep.section("Target Summary")
    if t.registered_domain and t.registered_domain != t.idna_hostname:
        scope = f"hostname {t.hostname} (registrable domain: {t.registered_domain})"
    else:
        scope = f"registrable domain {t.registered_domain or t.idna_hostname}"
    pairs = [("Input", t.original_input), ("URL", t.display_url),
             ("Scope", scope),
             ("Scheme", t.scheme + (" (assumed)" if t.scheme_assumed else "")),
             ("Port", t.effective_port)]
    if t.query:
        pairs.append(("Query params", ", ".join(t.to_dict()["query_param_names"]) or "(values only)"))
    rep.kv(pairs)
    for warning in t.warnings:
        rep.warn(warning)


def _data(res: ModuleResult) -> dict:
    return res.data if isinstance(res, ModuleResult) else (res or {})


def render_dns(rep, res: ModuleResult, full_dns: bool = False):
    rep.section("DNS Records")
    d = _data(res)
    if res.status == "error":
        rep.error("; ".join(res.errors) or d.get("error", "DNS failed"))
    if d.get("note") and d.get("name_queried"):
        rep.note(d["note"])
        return
    rep.kv([("Name queried", d.get("name_queried")),
            ("Resolver(s)", ", ".join(d.get("resolver_used") or []))])
    if d.get("resolver_note"):
        rep.note(d["resolver_note"])
    rows, missing = [], []
    for rdtype, entry in (d.get("results") or {}).items():
        if entry.get("status") == "ok":
            for rec in entry["records"]:
                rows.append((rdtype, _t(rec, full_dns), entry.get("ttl")))
        elif entry.get("status") == "skipped":
            missing.append(f"{rdtype}: skipped (NXDOMAIN)")
        else:
            missing.append(f"{rdtype}: {entry.get('error', entry.get('status'))}")
    if rows:
        rep.table(["Type", "Value", "TTL"], rows)
        if not full_dns:
            rep.note("Long values summarised; --full-dns shows complete records (also in JSON/HTML exports).")
    if missing:
        rep.note("No data — " + "; ".join(missing))


def render_ip(rep, res: ModuleResult):
    rep.section("IP Intelligence")
    if res.status == "error":
        rep.error("; ".join(res.errors))
        return
    for entry in _data(res).get("addresses", []):
        ptr = entry.get("reverse_dns", {})
        rep.kv([
            ("IP", entry["ip"]),
            ("Family", entry["family"]),
            ("Reverse DNS", ", ".join(ptr.get("names", [])) or ("—" if ptr.get("status") == "ok" else ptr.get("status", "—"))),
            ("ASN", entry.get("asn") or ("failed" if entry.get("error") else "not published")),
            ("Organisation", entry.get("organisation") or "—"),
            ("Prefix", entry.get("prefix") or "—"),
        ])
        rep.note("—" * 20)
    for limitation in _data(res).get("limitations", []):
        rep.note(limitation)


def render_http(rep, res: ModuleResult):
    rep.section("HTTP Response")
    if res.status == "error":
        rep.error("; ".join(res.errors))
        if res.findings:
            rep.findings(res.findings)
        return
    d = _data(res)
    final = d.get("final") or {}
    timing = d.get("timing") or {}
    rep.kv([
        ("Status", f"{final.get('status')} {final.get('reason')} ({final.get('http_version')})"),
        ("Final URL", _t(final.get("url"), full=True)),
        ("Server", final.get("server_header")),
        ("Content-Type", final.get("content_type")),
        ("Size", f"{final.get('bytes_downloaded')} bytes"
                 + (" (TRUNCATED at limit)" if final.get("truncated") else "")),
        ("Compression", final.get("content_encoding")),
        ("Timings", f"TTFB {timing.get('ttfb_ms')} ms, total {timing.get('total_ms')} ms"),
    ])
    chain = d.get("chain") or []
    if len(chain) > 1:
        rep.table(["Hop", "URL", "Status", "Location"],
                  [(c["hop"], c.get("url"), c.get("status"), c.get("location")) for c in chain],
                  title="Redirect chain (every hop requested once)")
    if d.get("chain_error"):
        rep.warn(d["chain_error"]["message"])
    headers = final.get("headers") or {}
    if headers:
        rep.table(["Header", "Value"], [(k, _t(v)) for k, v in sorted(headers.items())],
                  title="Response headers")
    cookies = d.get("cookies") or []
    if cookies:
        rep.table(["Cookie", "Secure", "HttpOnly", "SameSite", "Domain", "Set by"],
                  [(c["name"], "yes" if c["attributes"]["secure"] else "NO",
                    "yes" if c["attributes"]["httponly"] else "NO",
                    c["attributes"]["samesite"] or "unset",
                    c["attributes"]["domain"] or "host-only", c["source"]) for c in cookies],
                  title="Cookies (values never stored or shown)")
    if d.get("js_navigation"):
        rep.note("HTML contains meta-refresh/JS navigation — a browser may navigate further; this scan did not execute it.")
    probe = d.get("http_probe")
    if probe and probe.get("tested") is False:
        rep.note(f"HTTP probe not applicable: {probe.get('reason')}")
    rep.note(d.get("head_vs_get_note", ""))
    if res.findings:
        rep.findings(res.findings)


def render_tls(rep, res: ModuleResult):
    rep.section("TLS Certificate")
    d = _data(res)
    if res.status == "skipped" or d.get("note") and res.status != "error" and not d.get("cert"):
        rep.note(d.get("note", "not tested"))
        return
    if res.status == "error":
        rep.status("WARN", d.get("error", "; ".join(res.errors)))
        rep.kv([("Failure kind", d.get("failure_kind")), ("Verified", d.get("verified"))])
    cert = d.get("cert")
    if cert:
        rep.kv([
            ("Verified", d.get("verified")),
            ("TLS version", d.get("tls_version")),
            ("Cipher", (d.get("cipher") or {}).get("name")),
            ("Subject", _t(cert.get("subject"), full=True)),
            ("Issuer", _t(cert.get("issuer"), full=True)),
            ("Valid from", cert.get("not_before")),
            ("Expires", f"{cert.get('not_after')} ({cert.get('days_until_expiry')} days)"),
            ("Hostname", d.get("hostname_match")),
            ("SANs", _t(", ".join(cert.get("subject_alt_names", [])[:12]))),
        ])
    for limitation in d.get("limitations", []):
        rep.note(limitation)


def render_metadata(rep, res: ModuleResult):
    rep.section("Page Metadata")
    d = _data(res)
    if res.status != "success" or d.get("note") and not d.get("title"):
        rep.note(d.get("note", "; ".join(res.errors) or "unavailable"))
        return
    rep.kv([
        ("Title", _t(d.get("title"))), ("Description", _t(d.get("meta_description"))),
        ("Canonical", _t(d.get("canonical_url"))), ("Language", d.get("language")),
        ("Robots", d.get("robots_meta")), ("Generator", d.get("generator_meta")),
        ("Favicon", _t(d.get("favicon"))),
        ("Links/Images", f"{d.get('link_count')} links, {d.get('image_count')} images"),
    ])
    if d.get("open_graph"):
        rep.table(["Open Graph", "Value"],
                  [(k, _t(v)) for k, v in list(d["open_graph"].items())[:8]])
    for label, items in (("Stylesheets", d.get("stylesheets")), ("Scripts", d.get("scripts"))):
        items = items or []
        for url in items[:5]:
            rep.note(f"{label}: {url}")
        if len(items) > 5:
            rep.note(f"{label}: …and {len(items) - 5} more (see JSON/HTML for full list)")
    rep.note(d.get("js_render_note", ""))


def render_technologies(rep, res: ModuleResult):
    rep.section("Technology Fingerprints")
    d = _data(res)
    if res.status != "success" or "detections" not in d:
        rep.note(d.get("note", "; ".join(res.errors) or "unavailable"))
        return
    detections = d.get("detections", [])
    if not detections:
        rep.note(f"No fingerprints matched ({d.get('rules_evaluated', d.get('rule_count', 0))} rules evaluated).")
    else:
        rep.table(["Technology", "Category", "Confidence", "Rules", "Evidence"],
                  [(det["technology"], det["category"], det["confidence"].upper(),
                    ", ".join(det.get("rule_ids", [])[:3]), _t("; ".join(det["evidence"])))
                   for det in detections])
    rep.note(f"{d.get('rules_evaluated', '?')} rules evaluated, {d.get('rules_matched', 0)} matched. {d.get('note', '')}")


def render_findings_section(rep, res: ModuleResult, title: str):
    rep.section(title)
    if res.status == "error" and not res.findings:
        rep.error("; ".join(res.errors))
        if _data(res).get("note"):
            rep.note(_data(res)["note"])
        return
    summary = _data(res).get("summary")
    if summary and summary.get("counts"):
        rep.kv([("Findings", "  ".join(f"[{k}]×{v}" for k, v in sorted(summary["counts"].items())) + f"  ({summary.get('total')} total)")])
    rep.findings(res.findings)
    if _data(res).get("note"):
        rep.note(_data(res)["note"])


def render_security(rep, res: ModuleResult):
    render_findings_section(rep, res, "Security Configuration")


def render_email_security(rep, res: ModuleResult):
    render_findings_section(rep, res, "Email Security (SPF / DMARC / DKIM / MTA-STS / TLS-RPT)")
    summary = _data(res).get("status_summary")
    if summary:
        rep.kv([("Mechanisms", "  ".join(f"{k}={v}" for k, v in summary.items()))])


def render_dnssec(rep, res: ModuleResult):
    rep.section("DNSSEC")
    d = _data(res)
    if res.status != "success":
        rep.note(d.get("note", "; ".join(res.errors)))
        return
    rep.kv([("Domain", d.get("domain_queried")),
            ("Validation", f"{d.get('validation_state')} — {d.get('validation_detail')}")])
    if d.get("records_observed"):
        rep.table(["Record", "Sample"],
                  [(k, _t("; ".join(v[:2]))) for k, v in d["records_observed"].items()],
                  title="Observed DNSSEC records")
    rep.findings(res.findings)
    rep.note(d.get("note", ""))


def render_ct(rep, res: ModuleResult):
    rep.section("Certificate Transparency (crt.sh)")
    d = _data(res)
    if res.status != "success":
        rep.error("; ".join(res.errors) or d.get("note", "unavailable"))
        rep.findings(res.findings)
        return
    rep.kv([
        ("Certificates", f"{d.get('certificate_count')} unique ({d.get('unexpired_count')} unexpired, "
                          f"{d.get('expired_count')} expired; cached: {'yes' if d.get('from_cache') else 'no'})"),
        ("In-scope hostnames", d.get("hostnames") and len(d["hostnames"])),
        ("Source", d.get("source")),
    ])
    for cert in (d.get("certificates") or [])[:8]:
        rep.kv([("Issuer", _t(cert.get("issuer"))), ("CN", _t(cert.get("common_name"))),
                ("Validity", f"{cert.get('not_before')} → {cert.get('not_after')}"
                             + (" (EXPIRED)" if cert.get("expired") else ""))])
        rep.note("—" * 20)
    if d.get("truncated_certificates"):
        rep.note(f"…and {d['truncated_certificates']} more certificates in the JSON/HTML export.")
    for limitation in d.get("limitations", []):
        rep.note(limitation)
    rep.findings(res.findings)


def render_subdomains(rep, res: ModuleResult):
    rep.section("Subdomain Intelligence")
    d = _data(res)
    if res.status != "success":
        rep.note(d.get("note", "; ".join(res.errors) or "unavailable"))
        return
    resolution = d.get("resolution") or {}
    rep.kv([("Discovered", d.get("discovered")),
            ("Resolved", resolution.get("resolved") if resolution.get("enabled") else "not tested (--resolve-subdomains)"),
            ("Unresolved", resolution.get("unresolved") if resolution.get("enabled") else "—"),
            ("Wildcard DNS", ("SUSPECTED" if resolution.get("wildcard_suspected") else "no") if resolution.get("enabled") else "—")])
    rows = []
    ip_lookup = {r["hostname"]: r for r in resolution.get("rows") or []}
    for entry in (d.get("entries") or [])[:20]:
        resolved = ip_lookup.get(entry["hostname"], {})
        rows.append((", ".join(entry["sources"]), entry["hostname"],
                     ", ".join(resolved.get("ips", [])) if resolved else "",
                     "*" if resolved.get("wildcard_match") else ""))
    if rows:
        rep.table(["Source", "Hostname", "IPs (if resolved)", "Wildcard"], rows)
    if d.get("discovered", 0) > 20:
        rep.note(f"…and {d['discovered'] - 20} more hostnames in the JSON/HTML export.")
    rep.findings(res.findings)
    for limitation in d.get("limitations", []):
        rep.note(limitation)


def render_ports(rep, res: ModuleResult):
    rep.section("Port & Service Checks (opt-in, authorized targets only)")
    d = _data(res)
    if res.status == "error":
        rep.error("; ".join(res.errors) or d.get("error", "unavailable"))
        return
    summary = d.get("summary") or {}
    rep.kv([("Ports", f"{summary.get('open', 0)} open / {summary.get('closed', 0)} closed / "
                      f"{summary.get('filtered_or_error', 0)} filtered "
                      f"({len(d.get('ports_checked') or [])} checked, {d.get('how')})")])
    rep.table(["Port", "State", "Service hint", "Passive banner"],
              [(r["port"], r["status"], r.get("service") or "—", _t(r.get("banner")))
               for r in d.get("results") or []])
    if d.get("nmap"):
        rep.table(["Port", "State", "nmap service"],
                  [(r["port"], r["state"], _t(r["service"])) for r in d["nmap"]["results"]],
                  title="nmap -sV (light)")
    rep.findings(res.findings)
    for note in d.get("limitations", []):
        rep.note(note)


def render_urls(rep, res: ModuleResult):
    rep.section("URL & Page Intelligence Extras")
    d = _data(res)
    rep.kv([
        ("robots.txt", (d.get("robots") or {}).get("status", "—")
                       + (f" ({(d.get('robots') or {}).get('disallow_count_all_agents_sample', 0)} disallows)"
                          if (d.get("robots") or {}).get("status") == "ok" else "")),
        ("sitemap.xml", (d.get("sitemap") or {}).get("status", "—")
                        + (f" (~{(d.get('sitemap') or {}).get('loc_entries_estimate')} entries)"
                           if (d.get("sitemap") or {}).get("status") == "ok" else "")),
        ("favicon", (d.get("favicon") or {}).get("status", "—")
                    + (f" sha256={_t(((d.get('favicon') or {}).get('sha256') or '')[:20])}…"
                       if (d.get("favicon") or {}).get("status") == "ok" else "")),
    ])
    robots = d.get("robots") or {}
    if robots.get("disallows"):
        rep.note("Disallow sample: " + ", ".join(robots["disallows"][:10])
                 + (" …" if len(robots["disallows"]) > 10 else ""))
    rep.findings(res.findings)
    if d.get("note"):
        rep.note(d["note"])


def render_registration(rep, res: ModuleResult):
    rep.section("Domain Registration (RDAP)")
    d = _data(res)
    if res.status == "skipped":
        rep.note(d.get("note", "skipped"))
        return
    if res.status != "success":
        rep.error(d.get("error", "; ".join(res.errors) or "RDAP lookup failed"))
        if d.get("note"):
            rep.note(d["note"])
        return
    rep.kv([
        ("Domain queried", d.get("domain_queried") + (" (cached)" if d.get("from_cache") else "")),
        ("Registrar", d.get("registrar")),
        ("Registrant org", d.get("registrant_organization")),
        ("Registered", d.get("registered")),
        ("Expires", d.get("expires")),
        ("Last changed", d.get("last_changed")),
        ("Statuses", ", ".join(d.get("statuses") or []) or None),
        ("Nameservers", ", ".join(d.get("nameservers") or []) or None),
        ("DNSSEC signed", d.get("dnssec")),
        ("Source", d.get("source_url")),
    ])
    for limitation in d.get("limitations", []):
        rep.note(limitation)


def render_connectivity(rep, res: ModuleResult, http_result: ModuleResult | None = None):
    rep.section("Connectivity Diagnostics")
    d = _data(res)
    if res.status == "error" and "families" not in d:
        rep.error("; ".join(res.errors) or d.get("error", "failed"))
        return
    if d.get("dns_resolution_ms") is not None:
        rep.kv([("DNS resolve", f"{d['dns_resolution_ms']} ms (OS resolver)")])
    rows = []
    for name, fam in (d.get("families") or {}).items():
        rows.append((name,
                     fam.get("dns"),
                     f"{fam.get('tcp')}" + (f" ({fam.get('tcp_ms')} ms)" if fam.get("tcp_ms") is not None else ""),
                     f"{fam.get('tls')}" + (f" ({fam.get('tls_ms')} ms)" if fam.get("tls_ms") is not None else ""),
                     "local" if fam.get("local_limitation") else "",
                     _t(fam.get("error"))))
    rep.table(["Family", "DNS", "TCP", "TLS", "Local limit", "Detail"], rows)
    if http_result and http_result.status == "success":
        timing = _data(http_result).get("timing") or {}
        if timing:
            rep.kv([("HTTP", f"TTFB {timing.get('ttfb_ms')} ms, total {timing.get('total_ms')} ms (single GET)")])
    for limitation in d.get("limitations", []):
        rep.note(limitation)


def render_compact(rep, results: list[ModuleResult]):
    rep.section("Module Summary (quiet mode)")
    for res in results:
        rep.compact(res.module, res.status, res.duration_ms, res.errors)
