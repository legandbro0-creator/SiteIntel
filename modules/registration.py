"""Module J — domain registration intelligence via RDAP.

RDAP (Registration Data Access Protocol, RFC 7480+) is the modern,
machine-readable successor to WHOIS: HTTPS + JSON instead of fragile TCP/43
scraping.  We start at rdap.org, a public redirector that routes each TLD to
its authoritative RDAP server, then follow the redirect to the registry.

Rules we live by:
* If a field is not published (privacy redaction is the norm now) we print
  "Not publicly available" — we never guess.
* Registration data is about the REGISTRABLE DOMAIN (example.com), not the
  hostname you scanned (blog.example.com).  The report says which was used.
* One HTTP GET per scan; results are cacheable for the TTL in config.
"""
from __future__ import annotations

import httpx

RDAP_ENTRYPOINT = "https://rdap.org/domain/"
_NA = "Not publicly available"


def _vcard_fn(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                return str(item[3])
    return None


def _find_registrar(entities: list, depth: int = 0) -> str | None:
    if depth > 3:
        return None
    for entity in entities or []:
        if "registrar" in (entity.get("roles") or []):
            return _vcard_fn(entity) or entity.get("handle")
        nested = _find_registrar(entity.get("entities") or [], depth + 1)
        if nested:
            return nested
    return None


def _event_date(events: list, wanted: tuple[str, ...]) -> str | None:
    for event in events or []:
        if event.get("eventAction") in wanted:
            return event.get("eventDate")
    return None


def _redaction_note(data: dict) -> str | None:
    for notice in data.get("notices") or []:
        title = str(notice.get("title", "")).lower()
        desc = " ".join(map(str, notice.get("description") or [])).lower()
        if "redact" in title or "redact" in desc:
            return ("Registry/registrar states some fields are redacted "
                    f"('{notice.get('title')}'). This is normal privacy practice.")
    return None


def _find_registrant_org(entities: list, depth: int = 0) -> str | None:
    if depth > 3:
        return None
    for entity in entities or []:
        if "registrant" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "org" and len(item) >= 4:
                        org = item[3]
                        text = org[0] if isinstance(org, list) and org else org
                        if text and "redacted" not in str(text).lower():
                            return str(text)
        nested = _find_registrant_org(entity.get("entities") or [], depth + 1)
        if nested:
            return nested
    return None


def lookup_registration(registered_domain: str | None, settings, cache=None) -> dict:
    if not registered_domain:
        return {"status": "skipped",
                "note": "No registrable domain (IP literal or localhost target) — RDAP skipped."}

    cached = cache.get(f"rdap:{registered_domain}") if cache else None
    if cached:
        cached["from_cache"] = True
        return cached

    url = RDAP_ENTRYPOINT + registered_domain
    try:
        with httpx.Client(follow_redirects=True, max_redirects=5,
                          timeout=settings.read_timeout,
                          headers={"User-Agent": settings.user_agent,
                                   "Accept": "application/rdap+json, application/json"}) as client:
            response = client.get(url)
        if response.status_code == 404:
            return {"status": "error",
                    "error": "RDAP server has no record for this domain (not registered, or TLD unsupported).",
                    "sources": ["RDAP via rdap.org → authoritative registry"]}
        if response.status_code == 429:
            return {"status": "error",
                    "error": "RDAP server rate-limited the request (HTTP 429). Results were not fetched; try later or with cached data.",
                    "sources": ["RDAP via rdap.org → authoritative registry"]}
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        return {"status": "error",
                "error": f"RDAP request failed: {type(exc).__name__}: {exc}",
                "note": "Registration data is an optional network dependency; the rest of the report stands.",
                "sources": ["RDAP via rdap.org → authoritative registry"]}
    except ValueError as exc:
        return {"status": "error", "error": f"RDAP returned invalid JSON: {exc}"}

    result = {
        "status": "ok",
        "domain_queried": registered_domain,
        "source_url": str(response.url),          # authoritative RDAP server after redirect
        "registrar": _find_registrar(data.get("entities") or []) or _NA,
        "registrant_organization": _find_registrant_org(data.get("entities") or []) or _NA,
        "registered": _event_date(data.get("events"), ("registration",)) or _NA,
        "expires": _event_date(data.get("events"), ("expiration",)) or _NA,
        "last_changed": _event_date(data.get("events"), ("last changed", "last update of RDAP database")) or _NA,
        "statuses": data.get("status") or [],
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers") or [] if ns.get("ldhName")],
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned", "not published"),
        "handle": data.get("handle") or _NA,
        "sources": ["RDAP via rdap.org → authoritative registry"],
        "limitations": [
            "Data applies to the REGISTRABLE DOMAIN, not necessarily the scanned hostname.",
            "Registrant identity is usually redacted for privacy and shown as 'Not publicly available'.",
            "Dates come from the registry's publication; accuracy is the registry's responsibility.",
        ],
    }
    note = _redaction_note(data)
    if note:
        result["limitations"].append(note)
    if cache:
        cache.set(f"rdap:{registered_domain}", {k: v for k, v in result.items() if k != "from_cache"})
    return result
