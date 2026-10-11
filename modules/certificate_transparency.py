"""Certificate Transparency intelligence (spec §10) via crt.sh.

CT logs are append-only public ledgers of issued certificates.  They reveal
which hostnames CAs have issued certificates for — historically valuable
passive reconnaissance with NO contact to the target.

Rules:
* ONE request per domain, cached for a week (config.CACHE_TTL_CT).
* Deduplicate certificates, distinguish current from expired.
* A discovered hostname ≠ a live service.  An expired cert ≠ a current problem.
* Outage / 429 / 5xx / bad JSON → INCONCLUSIVE finding, never fabricated data.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

import config
from core.errors import ModuleError
from core.models import INCONCLUSIVE, INFO, Finding

_MOD = "certificate_transparency"
_MAX_DISPLAY_CERTS = 25


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation).to_dict()


def fetch_crtsh(domain: str, settings) -> list[dict]:
    """One GET against crt.sh; raises ModuleError with a clean explanation."""
    url = f"{config.CRT_SH_ENDPOINT}?q=%25.{domain}&output=json"
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=settings.connect_timeout,
                                                read=max(settings.read_timeout, 20.0), write=10.0,
                                                pool=settings.connect_timeout),
                          headers={"User-Agent": settings.user_agent}) as client:
            response = client.get(url)
    except httpx.RequestError as exc:
        raise ModuleError(f"crt.sh request failed: {type(exc).__name__}: {exc}")
    if response.status_code != 200:
        raise ModuleError(f"crt.sh returned HTTP {response.status_code} "
                          "(rate-limited or temporarily unavailable)")
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise ModuleError(f"crt.sh returned unparseable JSON: {exc}")
    return data if isinstance(data, list) else []


def parse_entries(entries: list[dict], now: datetime | None = None) -> dict:
    """Parse crt.sh JSON into deduplicated certs + hostnames (pure function)."""
    now = now or datetime.now(timezone.utc)
    seen: set[tuple] = set()
    certificates: list[dict] = []
    names: set[str] = set()
    for entry in entries:
        name_value = "\n".join(entry.get("name_value", "").splitlines())
        key = (entry.get("issuer_name", ""), entry.get("serial_number", ""),
               entry.get("not_before", ""), entry.get("not_after", ""), name_value)
        if key in seen:
            continue
        seen.add(key)
        sans = [n.strip().lower() for n in name_value.splitlines() if n.strip()] or \
               [n.strip().lower() for n in name_value.split() if n.strip()]
        names.update(sans)
        not_after = entry.get("not_after")
        expired = None
        if not_after:
            try:
                parsed = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                if parsed.tzinfo is None:  # crt.sh sometimes emits naive timestamps
                    parsed = parsed.replace(tzinfo=timezone.utc)
                expired = parsed < now
            except ValueError:
                expired = None
        certificates.append({
            "issuer": entry.get("issuer_name", "").split(",")[0][:80],
            "common_name": entry.get("common_name", ""),
            "sans": sorted(set(sans)),
            "not_before": entry.get("not_before"),
            "not_after": not_after,
            "logged": entry.get("entry_timestamp") or entry.get("min_entry_timestamp"),
            "expired": expired,
            "serial": entry.get("serial_number", "")[:64],
        })
    certificates.sort(key=lambda c: (c.get("not_after") or "", c["issuer"]))
    return {"certificate_count": len(certificates),
            "certificates": certificates,
            "hostnames": sorted(names)}


def _hostnames_in_scope(hostnames: list[str], domain: str) -> list[str]:
    out = []
    for name in hostnames:
        clean = name.lstrip("*.").lower().rstrip(".")
        if clean == domain or clean.endswith("." + domain):
            out.append(clean)
    return sorted(set(out))


def inspect_ct(domain: str, settings, cache=None) -> dict:
    if not domain:
        return {"status": "skipped", "note": "CT lookup needs a registrable domain (IP target)."}
    cached = cache.get(f"ct:{domain}") if cache else None
    if cached:
        cached["from_cache"] = True
        return cached
    try:
        entries = fetch_crtsh(domain, settings)
    except ModuleError as exc:
        return {"status": "error", "error": str(exc), "source": "crt.sh",
                "findings": [_f("ct_lookup", INCONCLUSIVE, str(exc),
                                "Public CT data is unavailable right now; nothing can be concluded.",
                                ["Historical findings from CT never prove current state anyway."],
                                "Retry later; results cache for a week when successful.")]}
    parsed = parse_entries(entries)
    hostnames = _hostnames_in_scope(parsed["hostnames"], domain)
    current = [c for c in parsed["certificates"] if c.get("expired") is False]
    expired = [c for c in parsed["certificates"] if c.get("expired") is True]
    findings = [_f(
        "ct_summary", INFO,
        f"{parsed['certificate_count']} unique logged certificate(s); "
        f"{len(current)} unexpired, {len(expired)} expired; "
        f"{len(hostnames)} unique in-scope hostnames.",
        "CT reveals what CAs have issued for this domain — a passive inventory.",
        ["Expired historical certificates do NOT indicate a current problem.",
         "Names in logs are not necessarily live or in use today.",
         "crt.sh coverage is public-log dependent and may lag."],
        "Review the hostname list for forgotten exposures you own.")]
    result = {"status": "ok", "domain_queried": domain, "source": "crt.sh (Certificate Transparency logs)",
              "certificate_count": parsed["certificate_count"],
              "unexpired_count": len(current), "expired_count": len(expired),
              "certificates": parsed["certificates"][:_MAX_DISPLAY_CERTS],
              "truncated_certificates": max(parsed["certificate_count"] - _MAX_DISPLAY_CERTS, 0),
              "hostnames": hostnames,
              "findings": findings,
              "limitations": ["Historical ≠ current; discovered ≠ live.",
                              "One request per domain; results cached up to a week."]}
    if cache:
        cache.set(f"ct:{domain}", result, ttl=config.CACHE_TTL_CT)
    return result
