"""Passive subdomain discovery (spec §11).

Sources (all passive):
* Certificate Transparency hostnames (shares the CT module's cached data),
* SANs on the live TLS certificate (if the TLS module ran).

Rules:
* Normalise, lowercase, strip wildcards, dedupe WITH source attribution.
* Discovered ≠ live.  Resolution is reported SEPARATELY and only when
  --resolve-subdomains is passed (bounded concurrency, capped count).
* Wildcard DNS is probed with a random label; matches are flagged.
* NO brute-force wordlists by design — that is active enumeration and
  out of the default scope.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor

import config
from core.models import INFO, Finding
from modules.certificate_transparency import inspect_ct
from modules.dns_info import build_resolver

_MOD = "subdomains"


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation).to_dict()


def normalize_name(raw: str, domain: str) -> str | None:
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or " " in name or "@" in name:
        return None
    if name == domain or name.endswith("." + domain):
        return name
    return None


def _resolve_many(hostnames: list[str], servers: list[str]) -> dict[str, list[str]]:
    resolver = build_resolver(servers or None)[0]
    out: dict[str, list[str]] = {}

    def one(name: str) -> list[str]:
        ips: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                for rdata in resolver.resolve(name, rdtype):
                    ips.append(rdata.address)
            except Exception:
                pass
        return ips

    with ThreadPoolExecutor(max_workers=2) as pool:  # gentle concurrency
        for name, ips in zip(hostnames, pool.map(one, hostnames)):
            out[name] = ips
    return out


def discover_subdomains(target, settings, cache=None, ct_result: dict | None = None,
                        tls_result: dict | None = None) -> dict:
    domain = target.registered_domain
    if not domain:
        return {"status": "skipped", "note": "Subdomain discovery needs a registrable domain."}

    if ct_result is None or ct_result.get("status") not in ("ok",):
        ct_result = inspect_ct(domain, settings, cache)

    sources: dict[str, set[str]] = {}
    for name in ct_result.get("hostnames") or []:
        clean = normalize_name(name, domain)
        if clean:
            sources.setdefault(clean, set()).add("Certificate Transparency")
    sans = ((tls_result or {}).get("cert") or {}).get("subject_alt_names") or []
    for name in sans:
        clean = normalize_name(name, domain)
        if clean:
            sources.setdefault(clean, set()).add("TLS certificate SAN")

    entries = [{"hostname": name, "sources": sorted(srcs)}
               for name, srcs in sorted(sources.items())]
    findings = [_f("passive_discovery", INFO,
                   f"{len(entries)} unique in-scope hostname(s) from passive sources.",
                   "Passive sources enumerate names without touching the target.",
                   ["Discovered ≠ live, and names may be stale or internal-use.",
                    "Coverage is limited to the queried public sources (no brute force by design)."],
                   "Pass --resolve-subdomains to check which names currently resolve.")]

    resolution: dict = {"enabled": False}
    if settings.resolve_subdomains:
        servers = settings.resolver_servers or config.DNS_FALLBACK_RESOLVERS
        wildcard_probe = f"siteintel-probe-{secrets.token_hex(6)}.{domain}"
        try:
            wildcard_answers = _resolve_many([wildcard_probe], servers)[wildcard_probe]
        except Exception:
            wildcard_answers = []
        names = [e["hostname"] for e in entries[: config.SUBDOMAIN_RESOLVE_LIMIT]]
        answers = _resolve_many(names, servers) if names else {}
        rows = []
        for entry in entries[: config.SUBDOMAIN_RESOLVE_LIMIT]:
            ips = answers.get(entry["hostname"], [])
            rows.append({"hostname": entry["hostname"],
                         "ips": ips,
                         "status": "resolved" if ips else "unresolved",
                         "wildcard_match": bool(ips and wildcard_answers and set(ips) == set(wildcard_answers))})
        resolved = sum(1 for r in rows if r["status"] == "resolved")
        resolution = {"enabled": True,
                      "attempted": len(rows), "resolved": resolved,
                      "unresolved": len(rows) - resolved,
                      "wildcard_suspected": bool(wildcard_answers),
                      "skipped_over_limit": max(len(entries) - config.SUBDOMAIN_RESOLVE_LIMIT, 0),
                      "rows": rows}
        if wildcard_answers:
            findings.append(_f(
                "wildcard_dns", INFO,
                f"Random probe {wildcard_probe} resolved to {wildcard_answers} — wildcard DNS likely.",
                "Every invented name would resolve; discovered names are less individually meaningful.",
                ["Matching answers heuristically flags identical-IP entries only."],
                "Treat resolution counts as validation of scope, not proof of services."))
        findings.append(_f(
            "resolution_summary", INFO,
            f"Resolved {resolved}/{len(rows)} probed hostnames (limit {config.SUBDOMAIN_RESOLVE_LIMIT}).",
            "Resolution tells you a name has DNS today — not that a service is usable.",
            ["Resolving ≠ serving; purposes and hosts behind the IP are unknown."],
            "—"))

    return {"status": "ok", "domain_queried": domain,
            "discovered": len(entries), "entries": entries,
            "resolution": resolution, "findings": findings,
            "limitations": ["Subdomain lists come from public passive sources only.",
                            "No bruteforce, no guessing, no probing of services."]}
