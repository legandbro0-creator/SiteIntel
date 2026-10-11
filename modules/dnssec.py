"""DNSSEC analysis (spec §9) — honest about what was verified.

Discovered by queries: DS, DNSKEY, and (with the DO bit) RRSIG records.
Validation is separated from record DISCOVERY:

  validated    — the recursive resolver set the AD (Authenticated Data) bit,
                 meaning IT cryptographically validated the answer.
                 Limitation stated loudly: we trust the upstream resolver;
                 a client-side chain validation needs a validating library
                 or resolver (not installed by default on Termux).
  insecure     — zone simply unsigned (extremely common; not a defect).
  indeterminate— records exist but validation could not be confirmed.
  not_tested   — the environment couldn't even attempt it.
"""
from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

import config
from core.models import INCONCLUSIVE, INFO, PASS, Finding
from modules.dns_info import build_resolver, query_type

_MOD = "dnssec"


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation).to_dict()


def _has_rrsig(server: str, name: str, rdatatype: str) -> tuple[bool | None, str | None]:
    """Query with the DNSSEC OK (DO) bit; True if an RRSIG comes back."""
    try:
        message = dns.message.make_query(name, rdatatype, flags=dns.flags.RD,
                                         use_edns=0, payload=1232)
        message.ednsflags |= dns.flags.DO  # "DNSSEC OK — include RRSIGs if signed"
        response = dns.query.udp(message, server, timeout=config.DNS_TIMEOUT)
        rdatatype_rrsig = dns.rdatatype.from_text("RRSIG")
        for rrset in response.answer:
            if rrset.rdtype == rdatatype_rrsig:
                return True, None
        return False, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _ad_bit_validates(server: str, name: str) -> tuple[str, str]:
    """Ask the resolver with AD set; inspect whether AD comes back.

    Returns (state, detail): state ∈ validated / insecure / indeterminate / not_tested.
    Also runs a CD=1 (checking disabled) control query: SERVFAIL without CD
    but NOERROR with CD is the classic signature of BOGUS validation."""
    try:
        query = dns.message.make_query(name, "A",
                                       flags=dns.flags.from_text("AD RD"))
        response = dns.query.udp(query, server, timeout=config.DNS_TIMEOUT)
    except Exception as exc:
        return "not_tested", f"validation query failed: {type(exc).__name__}: {exc}"
    rcode = dns.rcode.to_text(response.rcode())
    if rcode == "SERVFAIL":
        try:
            control = dns.message.make_query(name, "A", flags=dns.flags.from_text("CD RD"))
            control_response = dns.query.udp(control, server, timeout=config.DNS_TIMEOUT)
            if dns.rcode.to_text(control_response.rcode()) == "NOERROR":
                return ("indeterminate",
                        "Resolver returned SERVFAIL for the validating query but NOERROR with "
                        "checking disabled — signature validation is likely FAILING (bogus).")
        except Exception:
            pass
        return "indeterminate", ("Resolver returned SERVFAIL; cannot tell validation failure "
                                 "from an ordinary resolver error.")
    if response.flags & dns.flags.AD:
        return "validated", "Resolver set the AD bit (it cryptographically validated the answer)."
    return "insecure", "Resolver did not set AD — consistent with an unsigned zone."


def analyze_dnssec(domain: str, settings) -> dict:
    if not domain:
        return {"status": "skipped", "note": "DNSSEC requires a domain (IP literal target skipped)."}
    resolver, servers, _ = build_resolver(settings.resolver_servers or None)
    server = servers[0] if servers else None
    findings: list[dict] = []
    records: dict[str, list[str]] = {}

    for rdtype in ("DS", "DNSKEY"):
        result = query_type(resolver, domain, rdtype)
        if result["status"] == "ok" and result["records"]:
            records[rdtype] = result["records"]
    rrsig, rrsig_error = (None, "no resolver available")
    if server:
        rrsig, rrsig_error = _has_rrsig(server, domain, "A")
    if rrsig:
        records["RRSIG(A)"] = ["(present — signature returned with the A record)"]

    if records:
        findings.append(_f(
            "dnssec_records", INFO,
            f"DNSSEC-related records at {domain}: " + "; ".join(
                f"{k}×{len(v)}" for k, v in sorted(records.items())),
            "Key/signature material exists and is being published.",
            ["Records EXISTING is not proof the zone VALIDATES — see dnssec_validation."],
            "—"))
    else:
        findings.append(_f(
            "dnssec_records", INFO,
            f"No DS/DNSKEY/RRSIG records discovered for {domain}.",
            "The zone reads as unsigned.",
            ["Timeouts are excluded: these results come from answered queries."],
            "Unsigned DNS is the common case; enable DNSSEC at your registrar+DNS host if you want it."))

    if server is None:
        validation_state, detail = "not_tested", "no resolver available"
    else:
        validation_state, detail = _ad_bit_validates(server, domain)

    if validation_state == "validated":
        findings.append(_f("dnssec_validation", PASS, detail,
                           "Answers for this zone carry authenticated data per the configured resolver.",
                           ["We trust the resolver's word (AD bit). True client-side chain validation "
                            "requires a validating library — not installed by default."],
                           "—"))
    elif validation_state == "insecure":
        findings.append(_f("dnssec_validation", INFO, detail,
                           "Consistent with an unsigned zone (common and not inherently wrong).",
                           ["AD-bit absence can also occur with signed zones if the resolver is "
                            "non-validating or strips AD; treat as 'not validated here'."],
                           "—"))
    else:
        findings.append(_f("dnssec_validation", INCONCLUSIVE, detail,
                           "Validation could not be confirmed from this vantage point.",
                           ["Diagnosis relies on resolver behaviour we cannot control."],
                           "Cross-check with: dig +dnssec +adflag <domain> A"))

    return {"status": "ok",
            "domain_queried": domain,
            "records_observed": records,
            "validation_state": validation_state,
            "validation_detail": detail,
            "resolver_used": servers,
            "findings": findings,
            "note": "Record DISCOVERY and cryptographic VALIDATION are reported separately."
                    + (f" (RRSIG probe note: {rrsig_error})" if rrsig_error else "")}
