"""Module B — DNS intelligence.

DNS is the internet's phone book: you ask a *resolver* questions like
"what IPv4 address (A record) does example.com have?" and it walks the
hierarchy root → TLD → authoritative nameserver to answer.

Failure taxonomy this module distinguishes:
    NXDOMAIN   — the name definitively does not exist.
    NoAnswer   — the name exists, but has no record of that type.
    NoNameservers — resolvers refused / SERVFAIL territory.
    Timeout    — nobody answered in time (mobile radio asleep? captive portal?).

On Android/Termux there is often no /etc/resolv.conf, so if dnspython finds
no system resolver we fall back to well-known public resolvers and SAY SO
(never silently).
"""
from __future__ import annotations

import dns.exception
import dns.rdata
import dns.resolver

import config

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]

RECORD_EXPLANATIONS = {
    "A":     "IPv4 address(es) this name points to.",
    "AAAA":  "IPv6 address(es) this name points to.",
    "CNAME": "Alias: this name is another name; follow the chain for addresses.",
    "MX":    "Mail exchangers accepting email for the domain (lower number = preferred).",
    "NS":    "Authoritative nameservers that hold this zone's records.",
    "TXT":   "Free text: SPF/alternate verification tokens/keys. Presence is NOT a security finding.",
    "CAA":   "Which certificate authorities may issue TLS certificates for this name.",
    "SOA":   "Start of authority: primary NS, admin mailbox, zone serial and timers.",
}


class DNSConfigurationError(Exception):
    pass


def build_resolver(servers: list[str] | None = None) -> tuple[dns.resolver.Resolver, list[str], str | None]:
    """Create a resolver; returns (resolver, nameservers_in_use, note)."""
    note = None
    if servers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(servers)
        note = f"Using resolver(s) from --resolver: {', '.join(servers)}"
    else:
        have_system = False
        try:
            resolver = dns.resolver.Resolver()          # reads /etc/resolv.conf
            have_system = bool(resolver.nameservers)
        except dns.resolver.NoResolverConfiguration:
            resolver = dns.resolver.Resolver(configure=False)
        if not have_system:
            resolver.nameservers = list(config.DNS_FALLBACK_RESOLVERS)
            note = (
                "No system DNS resolver found (normal on Android/Termux). "
                f"Falling back to public resolvers: {', '.join(resolver.nameservers)}. "
                "Use --resolver to choose your own."
            )
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_LIFETIME
    return resolver, list(resolver.nameservers), note


def format_rdata(rdtype: str, rdata: dns.rdata.Rdata) -> str:
    """Pretty-print one record. Per-type detail where it aids learning."""
    if rdtype in ("A", "AAAA"):
        return rdata.address
    if rdtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text()}"
    if rdtype == "SOA":
        return (f"{rdata.mname.to_text()} {rdata.rname.to_text()} "
                f"serial={rdata.serial} refresh={rdata.refresh} retry={rdata.retry} "
                f"expire={rdata.expire} minimum={rdata.minimum}")
    if rdtype == "TXT":
        # A TXT record is a list of byte strings legally concatenated (SPF etc.).
        return "".join(s.decode("utf-8", "replace") for s in rdata.strings)
    if rdtype == "CAA":
        return f"{rdata.flags} {rdata.tag.decode('ascii', 'replace')} \"{rdata.value.decode('utf-8', 'replace')}\""
    return rdata.to_text()


def _status_for_exception(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain", "The name does not exist (NXDOMAIN)."
    if isinstance(exc, dns.resolver.NoAnswer):
        return "no_records", "The name exists but has no records of this type."
    if isinstance(exc, dns.resolver.NoNameservers):
        return "servfail", "Nameservers failed to answer (SERVFAIL / refused)."
    if isinstance(exc, dns.exception.Timeout):
        return "timeout", f"No answer within {config.DNS_LIFETIME}s."
    return "error", f"{type(exc).__name__}: {exc}"


def query_type(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> dict:
    """Ask one question; return a structured, crash-free answer."""
    try:
        answer = resolver.resolve(name, rdtype)
        records = [format_rdata(rdtype, rdata) for rdata in answer]
        ttl = answer.rrset.ttl if answer.rrset is not None else None
        return {"status": "ok", "records": records, "ttl": ttl, "error": None}
    except Exception as exc:  # all dns.* failures map to statuses by design
        status, message = _status_for_exception(exc)
        return {"status": status, "records": [], "ttl": None, "error": message}


def collect_dns(hostname: str, servers: list[str] | None = None,
                types: list[str] | None = None) -> dict:
    """Query all record types once each. Skips remaining types on NXDOMAIN."""
    resolver, used, note = build_resolver(servers)
    types = types or RECORD_TYPES
    results: dict[str, dict] = {}
    nxdomain_seen = False
    for rdtype in types:
        if nxdomain_seen:
            results[rdtype] = {"status": "nxdomain", "records": [], "ttl": None,
                               "error": "Skipped: name already returned NXDOMAIN."}
            continue
        results[rdtype] = query_type(resolver, hostname, rdtype)
        if results[rdtype]["status"] == "nxdomain":
            nxdomain_seen = True
    return {
        "status": "ok" if not nxdomain_seen else "error",
        "name_queried": hostname,
        "resolver_used": used,
        "resolver_note": note,
        "results": results,
        "sources": ["Configured DNS resolver"],
    }


def extract_ips(dns_result: dict) -> list[str]:
    """Pull unique A+AAAA addresses out of a collect_dns() result."""
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        for rec in dns_result.get("results", {}).get(rdtype, {}).get("records", []):
            if rec not in ips:
                ips.append(rec)
    return ips
