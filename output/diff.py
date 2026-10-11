"""Scan comparison (spec §18): `python main.py diff old.json new.json`.

Design decisions:
* Reads BOTH report generations: v1 (module dicts hold data directly) and
  v2 (ModuleResult schema with .data/.findings).
* Volatile headers (date, cf-ray, age, …) are filtered — they change on
  every request and are not "differences".
* Missing data is distinguished from actual removal ("module did not run"
  ≠ "header removed").
* Markers: [+] added   [-] removed   [~] changed   [!] comparison caution
* A legend reminds the reader that CDN rotation, certificate renewal and
  config updates are LEGITIMATE changes.
"""
from __future__ import annotations

import config

LEGEND = ("Legend: [+] newly observed  [-] no longer observed  [~] changed  [!] caution\n"
          "Note: CDN/IP rotation, certificate renewal and deliberate config updates are "
          "common LEGITIMATE reasons for differences — changes are observations, not alarms.")


def _module_data(report: dict, name: str) -> tuple[dict, str]:
    """Return (data_dict, module_status) handling both report generations."""
    mod = (report.get("modules") or {}).get(name)
    if not isinstance(mod, dict):
        return {}, "not_run"
    if "data" in mod and isinstance(mod.get("data"), dict):  # v2 schema
        merged = dict(mod["data"])
        merged.setdefault("status", mod.get("status"))
        return merged, str(mod.get("status", "unknown"))
    status = str(mod.get("status", "unknown"))
    return mod, {"ok": "success"}.get(status, status)


def _findings_index(report: dict, name: str) -> dict[str, dict]:
    mod = (report.get("modules") or {}).get(name) or {}
    raw = mod.get("findings") or []
    out = {}
    for f in raw:
        if isinstance(f, dict):
            key = f.get("name") or f.get("id") or str(f)[:40]
            out[key] = {"status": f.get("status") or f.get("label"),
                        "evidence": f.get("evidence") or f.get("observed")}
    return out


def _set_lines(lines: list[str], label: str, before: set, after: set):
    for value in sorted(after - before):
        lines.append(f"[+] {label}: {value}")
    for value in sorted(before - after):
        lines.append(f"[-] {label}: {value}")


def _diff_dns(lines, old, new):
    for rdtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"):
        before = set((old.get("results", {}).get(rdtype, {}) or {}).get("records", []))
        after = set((new.get("results", {}).get(rdtype, {}) or {}).get("records", []))
        _set_lines(lines, f"DNS {rdtype}", before, after)


def _diff_http(lines, old, new):
    of, nf = old.get("final") or {}, new.get("final") or {}
    if of.get("status") != nf.get("status"):
        lines.append(f"[~] HTTP status: {of.get('status')} -> {nf.get('status')}")
    if of.get("url") != nf.get("url"):
        lines.append(f"[~] HTTP final URL: {of.get('url')} -> {nf.get('url')}")
    oh = {k: v for k, v in (of.get("headers") or {}).items() if k not in config.VOLATILE_HEADERS}
    nh = {k: v for k, v in (nf.get("headers") or {}).items() if k not in config.VOLATILE_HEADERS}
    for key in sorted(set(oh) | set(nh)):
        if key not in oh:
            lines.append(f"[+] HTTP header appeared: {key}: {nh.get(key)}")
        elif key not in nh:
            lines.append(f"[-] HTTP header no longer observed: {key}")
        elif oh[key] != nh[key]:
            lines.append(f"[~] HTTP header changed: {key}: {oh[key]} -> {nh[key]}")
    oc = {c["name"]: c["attributes"] for c in old.get("cookies") or []}
    nc = {c["name"]: c["attributes"] for c in new.get("cookies") or []}
    for name in sorted(set(oc) | set(nc)):
        if name not in oc:
            lines.append(f"[+] Cookie appeared: {name}")
        elif name not in nc:
            lines.append(f"[-] Cookie no longer set: {name}")
        elif oc[name] != nc[name]:
            lines.append(f"[~] Cookie attributes changed: {name}: {oc[name]} -> {nc[name]}")


def _diff_simple(lines, label, ov, nv):
    if ov != nv:
        lines.append(f"[~] {label}: {ov} -> {nv}")


def compare_reports(old: dict, new: dict) -> list[str]:
    lines = [f"Old: {old.get('timestamp_utc')}  ({old.get('input')})",
             f"New: {new.get('timestamp_utc')}  ({new.get('input')})", ""]

    # Module execution differences (failed vs ran) first — they explain missing data.
    all_modules = sorted(set(old.get("modules", {})) | set(new.get("modules", {})))
    for name in all_modules:
        _o, os_ = _module_data(old, name)
        _n, ns_ = _module_data(new, name)
        if os_ != ns_:
            lines.append(f"[!] Module '{name}' status differs: {os_} -> {ns_} "
                         "(missing data below may be a failed module, not a removed property)")

    _diff_dns(lines, _module_data(old, "dns")[0], _module_data(new, "dns")[0])
    # IP intel
    oas = {a.get("ip") for a in _module_data(old, "ip")[0].get("addresses") or []}
    nas = {a.get("ip") for a in _module_data(new, "ip")[0].get("addresses") or []}
    _set_lines(lines, "IP address", oas, nas)
    oasn = {a.get("ip"): a.get("asn") for a in _module_data(old, "ip")[0].get("addresses") or []}
    nasn = {a.get("ip"): a.get("asn") for a in _module_data(new, "ip")[0].get("addresses") or []}
    for ip in sorted(set(oasn) & set(nasn)):
        if oasn[ip] != nasn[ip]:
            lines.append(f"[~] ASN for {ip}: {oasn[ip]} -> {nasn[ip]}")

    _diff_http(lines, _module_data(old, "http")[0], _module_data(new, "http")[0])

    oc = (_module_data(old, "tls")[0].get("cert") or {})
    nc = (_module_data(new, "tls")[0].get("cert") or {})
    _diff_simple(lines, "TLS cert expiry", oc.get("not_after"), nc.get("not_after"))
    _diff_simple(lines, "TLS cert issuer", oc.get("issuer"), nc.get("issuer"))
    _diff_simple(lines, "TLS cert SANs", sorted(oc.get("subject_alt_names") or []),
                 sorted(nc.get("subject_alt_names") or []))

    for mod_name, key in (("technologies", "detections"),):
        ot = {d["technology"] for d in _module_data(old, mod_name)[0].get(key) or []}
        nt = {d["technology"] for d in _module_data(new, mod_name)[0].get(key) or []}
        _set_lines(lines, "Technology", ot, nt)

    old_sec, new_sec = _findings_index(old, "security"), _findings_index(new, "security")
    for name_ in sorted(set(old_sec) | set(new_sec)):
        before, after = old_sec.get(name_), new_sec.get(name_)
        if before is None:
            lines.append(f"[+] Security finding appeared: {name_} ({after['status']})")
        elif after is None:
            lines.append(f"[-] Security finding no longer reported: {name_}")
        elif before["status"] != after["status"] or before["evidence"] != after["evidence"]:
            lines.append(f"[~] Security finding {name_}: {before['status']} -> {after['status']}")

    osub = {e["hostname"] for e in _module_data(old, "subdomains")[0].get("entries") or []}
    nsub = {e["hostname"] for e in _module_data(new, "subdomains")[0].get("entries") or []}
    _set_lines(lines, "Subdomain (passive)", osub, nsub)

    omech = (_module_data(old, "email_security")[0].get("status_summary") or {})
    nmech = (_module_data(new, "email_security")[0].get("status_summary") or {})
    for mech in sorted(set(omech) | set(nmech)):
        if omech.get(mech) != nmech.get(mech):
            lines.append(f"[~] Email security {mech}: {omech.get(mech)} -> {nmech.get(mech)}")

    _diff_simple(lines, "DNSSEC validation state",
                 _module_data(old, "dnssec")[0].get("validation_state"),
                 _module_data(new, "dnssec")[0].get("validation_state"))

    if len([l for l in lines if l.startswith(("[+]", "[-]", "[~]", "[!]"))]) == 0:
        lines.append("No meaningful changes detected in compared fields.")
    lines += ["", LEGEND]
    return lines
