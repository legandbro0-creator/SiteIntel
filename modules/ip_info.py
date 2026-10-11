"""Module C — IP & network intelligence.

What we can know for free and without API keys:
* PTR (reverse DNS) — the name the IP's owner gave it, if any.
* Team Cymru's DNS-based ASN service — network prefix + Autonomous System
  (the organisation routing that block).  Queried over ordinary DNS TXT
  records, so it works on Termux with zero extra tooling.

What we must NEVER pretend to know:
* "This IP == this website."  CDNs, shared hosting, reverse proxies and
  anycast mean one IP can front thousands of unrelated sites, or one site
  can be served from hundreds of IPs.
* Geography.  ASN country ≠ server location ≠ company HQ.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

import dns.resolver

import config

IP_LIMITATIONS = [
    "IPs may belong to a CDN/reverse proxy/shared host — they do not uniquely identify the website.",
    "Anycast: the same IP can be announced from many physical locations worldwide.",
    "ASN/prefix data comes from public routing registries (Team Cymru); it can be stale.",
    "Privacy-protected hosting can make ownership effectively invisible.",
]


def reverse_dns(resolver: dns.resolver.Resolver, ip: str) -> dict:
    try:
        name = dns.resolver.reversename.from_address(ip)
        answer = resolver.resolve(name, "PTR")
        return {"status": "ok", "names": [r.target.to_text().rstrip(".") for r in answer]}
    except dns.resolver.NXDOMAIN:
        return {"status": "no_records", "names": [], "error": "No PTR record published."}
    except Exception as exc:
        return {"status": "error", "names": [], "error": f"{type(exc).__name__}: {exc}"}


def _cymru_origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _first_txt(resolver: dns.resolver.Resolver, name: str) -> str | None:
    try:
        answer = resolver.resolve(name, "TXT")
        for rdata in answer:
            return b"".join(rdata.strings).decode("utf-8", "replace")
    except Exception:
        return None
    return None


def cymru_lookup(resolver: dns.resolver.Resolver, ip: str) -> dict:
    """Best-effort ASN/prefix/organisation via Team Cymru (no API key)."""
    txt = _first_txt(resolver, _cymru_origin_name(ip))
    if not txt:
        return {"asn": None, "prefix": None, "organisation": None, "source": None,
                "error": "No ASN data published (or lookup blocked)"}
    fields = [part.strip() for part in txt.split("|")]
    asn = fields[0] if fields and fields[0] and fields[0] != "NA" else None
    prefix = fields[1] if len(fields) > 1 else None
    organisation = None
    if asn:
        # e.g. "13335 | US | arin | 2010-06-28 | CLOUDFLARENET - Cloudflare, Inc., US"
        whois = _first_txt(resolver, f"AS{asn}.asn.cymru.com")
        if whois:
            wfields = [part.strip() for part in whois.split("|")]
            if len(wfields) >= 5:
                organisation = wfields[4]
    return {"asn": f"AS{asn}" if asn else None, "prefix": prefix,
            "organisation": organisation, "source": "Team Cymru DNS (whois)", "error": None}


def host_ips(host: str) -> list[str]:
    """Fallback address discovery when the DNS module did not run."""
    ips: list[str] = []
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def _lookup_one(ip: str, resolver_servers: list[str]) -> dict:
    family = "ipv6" if ":" in ip else "ipv4"
    # A fresh resolver per worker thread (dnspython resolvers are thread-safe
    # in recent versions, but fresh instances are cheap and unambiguous).
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = resolver_servers
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_LIFETIME
    ptr = reverse_dns(resolver, ip)
    asn = cymru_lookup(resolver, ip)
    return {
        "ip": ip,
        "family": family,
        "reverse_dns": ptr,
        "asn": asn["asn"],
        "prefix": asn["prefix"],
        "organisation": asn["organisation"],
        "asn_source": asn["source"],
        "error": asn["error"],
    }


def collect_ip_intel(ips: list[str], resolver_servers: list[str],
                     cache=None) -> dict:
    if not ips:
        return {"status": "error", "error": "No IP addresses to inspect (DNS resolution produced none).",
                "addresses": [], "limitations": IP_LIMITATIONS}
    ips = [ip for ip in ips if ip][: config.MAX_IP_LOOKUPS]
    entries: dict[str, dict] = {}
    todo: list[str] = []
    for ip in ips:
        cached = cache.get(f"ipintel:{ip}") if cache else None
        if cached:
            entries[ip] = cached
        else:
            todo.append(ip)
    if todo:
        with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as pool:
            fetched = list(pool.map(lambda ip: _lookup_one(ip, resolver_servers), todo))
        for entry in fetched:
            entries[entry["ip"]] = entry
            if cache:
                cache.set(f"ipintel:{entry['ip']}", entry)
    return {
        "status": "ok",
        "addresses": [entries[ip] for ip in ips if ip in entries],
        "truncated": len(ips) == config.MAX_IP_LOOKUPS,
        "limitations": IP_LIMITATIONS,
        "sources": ["PTR records", "Team Cymru DNS"],
    }
