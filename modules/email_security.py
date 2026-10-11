"""Email security analysis (spec §8): SPF, DMARC, DKIM, MTA-STS, TLS-RPT.

DNS-borne anti-spoofing controls.  Passive and low-volume by default: a
handful of TXT lookups; the only HTTP fetch is the MTA-STS policy file,
performed ONLY when its DNS record exists.

Status vocabulary (used per mechanism): Present / Absent / Invalid /
Inconclusive / Not checked.

Teaching notes encoded in findings:
* SPF "-all" enforcement vs "~all" soft-fail vs the dangerous "+all".
* DMARC p=none is a MONITORING stance, not a defect — do not shame it.
* A DKIM selector is just a name; not finding a guessed selector proves
  nothing about DKIM coverage.
"""
from __future__ import annotations

import re

import httpx

import config
from core.models import (INCONCLUSIVE, INFO, NOT_TESTED, PASS, WARN, Finding)
from modules.dns_info import build_resolver, query_type

_MOD = "email_security"
DNS_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why, recommendation=recommendation,
                   limitations=limitations if isinstance(limitations, list) else [limitations]).to_dict()


def _txt(resolver, name) -> dict:
    return query_type(resolver, name, "TXT")


def _availability(query: dict, what: str) -> str:
    """ok-with-records handled by caller; here: record-absent vs inconclusive."""
    if query["status"] in ("no_records", "nxdomain"):
        return "absent"
    return "inconclusive"  # timeout / servfail / error — unknown, NOT absent


# --------------------------------------------------------------------------
def analyze_spf(resolver, domain) -> tuple[dict, list[dict]]:
    query = _txt(resolver, domain)
    if query["status"] == "ok":
        spf = [t for t in query["records"] if t.lower().startswith("v=spf1")]
        if not spf:
            return "absent", [_f("spf", WARN, "No SPF record (v=spf1 TXT) published.",
                                 "Receivers lack an SPF basis to reject forged sender addresses for this domain.",
                                 ["Some non-sending domains deliberately omit SPF.", "A syntax-invalid SPF would be worse than none."],
                                 "Publish exactly one 'v=spf1 … -all' (or ?all for exploratory setups).", "low")]
        too_many = len(spf) > 1
        policy = spf[0]
        tokens = policy.split()
        lookup_count = sum(1 for t in tokens if any(t.lower().startswith(m) for m in DNS_LOOKUP_MECHANISMS))
        ending = next((t for t in reversed(tokens) if t in ("-all", "~all", "?all", "+all")), None)
        detail = {"record": policy, "all_directive": ending, "dns_lookup_mechanisms": lookup_count,
                  "record_count": len(spf)}
        if too_many:
            return "invalid", [_f("spf", WARN, f"{len(spf)} SPF records published (exactly one is allowed by RFC 7208). "
                                               f"Records: {spf}", "Multiple SPF records make evaluation unpredictable.",
                                  ["Receivers may treat the domain as having no valid policy at all."],
                                  "Merge into a single v=spf1 record.", "low")]
        findings = []
        if ending == "+all":
            findings.append(_f("spf", WARN, f"SPF ends with '+all' — it AUTHORISES every sender: {policy}",
                               "This policy effectively disables SPF protection.",
                               ["May be intentional for unusual setups; still worth a deliberate decision."],
                               "Use '-all' (strict) or '~all' (transitional).", "low"))
        elif ending in ("-all", "~all", "?all"):
            label = {"-all": PASS, "~all": PASS, "?all": INFO}[ending]
            findings.append(_f("spf", label, f"SPF policy: {policy}",
                               {"-all": "Hard-fail: receivers may reject non-listed senders.",
                                "~all": "Soft-fail: transitional enforcement, counts but rarely rejects.",
                                "?all": "Neutral: SPF makes no claim about unlisted senders."}[ending],
                               ["SPF alone does not stop display-name or cousin-domain spoofing.",
                                "Forwarding breaks SPF — that is what DKIM/DMARC are for."],
                               "Consider '-all' once confirmed complete." if ending != "-all" else "—"))
        else:
            findings.append(_f("spf", WARN, f"SPF without an 'all' directive: {policy}",
                               "The policy lacks an explicit default stance.",
                               ["Receivers default to neutral — weaker but not broken."],
                               "Terminate with '-all' or '~all'.", "low"))
        if lookup_count > 10:
            findings.append(_f("spf_lookups", WARN, f"SPF references {lookup_count} DNS-lookup mechanisms (>10).",
                               "RFC 7208 limits SPF to 10 DNS lookups; excess is treated as PermError.",
                               ["Nested includes hide lookups; our count is a conservative surface estimate."],
                               "Flatten includes or use ip4:/ip6: ranges.", "low"))
        return ("present", findings) if ending else ("present", findings)
    availability = _availability(query, "SPF")
    if availability == "absent":
        return "absent", [_f("spf", WARN, "No TXT records for the domain at all; SPF absent.",
                             "Receivers lack an SPF basis for this domain.",
                             ["Non-sending domains may choose this."], "Publish 'v=spf1 -all' for parked domains.", "low")]
    return "inconclusive", [_f("spf", INCONCLUSIVE, f"SPF could not be determined: {query['error']}",
                               "DNS timeouts/errors are not evidence of absence.", ["—"], "Retry later or with --resolver.")]


def analyze_dmarc(resolver, domain) -> tuple[str, list[dict]]:
    query = _txt(resolver, f"_dmarc.{domain}")
    if query["status"] != "ok" or not any(t.upper().startswith("V=DMARC1") for t in query["records"]):
        availability = _availability(query, "DMARC")
        if availability == "absent":
            return "absent", [_f("dmarc", WARN, f"No DMARC record at _dmarc.{domain}.",
                                 "Receivers have no policy for handling messages that fail SPF+DKIM alignment.",
                                 ["DMARC is opt-in; many small domains operate without it.",
                                  "Absence is a posture gap, not an incident."],
                                 "Start with 'v=DMARC1; p=none; rua=mailto:dmarc@<domain>' and graduate to quarantine/reject.", "low")]
        return "inconclusive", [_f("dmarc", INCONCLUSIVE, f"DMARC could not be determined: {query['error']}",
                                   "DNS timeouts/errors are not evidence of absence.", ["—"], "Retry later.")]
    record = next(t for t in query["records"] if t.upper().startswith("V=DMARC1"))
    tags = {}
    for part in record.split(";")[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "")
    pct = tags.get("pct", "100")
    meanings = {"none": "monitoring only — failures are REPORTED, not blocked (a deliberate first stage, not a defect)",
                "quarantine": "failing mail should be treated with suspicion (spam folder)",
                "reject": "failing mail should be refused outright (strongest stance)"}
    if policy in ("reject",):
        status, rank = "present", PASS
    elif policy in ("quarantine",):
        status, rank = "present", PASS
    elif policy == "none":
        status, rank = "present", INFO
    else:
        return "invalid", [_f("dmarc", WARN, f"DMARC record malformed (p={policy or 'missing'}): {record}",
                              "Receivers cannot apply an unintelligible policy.", ["Tag parsing is simple k=v; unusual quoting may confuse it."],
                              "Fix to a valid record, e.g. 'v=DMARC1; p=quarantine; rua=mailto:…'.", "low")]
    findings = [_f("dmarc", rank, f"DMARC p={policy} (pct={pct}): {meanings.get(policy, policy)}.",
                   "DMARC ties SPF/DKIM results to the visible From: header and requests reports.",
                   [f"rua aggregate reports: {tags.get('rua', 'not requested')}",
                    "Policy effectiveness also depends on SP (subdomain) tag and deployment at receivers."],
                   "Graduate p=none → quarantine → reject after reviewing rua reports." if policy == "none" else "—")]
    return status, findings


def analyze_dkim(resolver, domain, selectors: list[str], guess: bool) -> tuple[str, list[dict]]:
    if not selectors and guess:
        selectors = list(config.DEFAULT_DKIM_SELECTORS)
    if not selectors:
        return "not_checked", [_f("dkim", NOT_TESTED,
                                  "No DKIM selectors provided. DKIM keys live under <selector>._domainkey.<domain>; "
                                  "selectors are chosen by the mail provider.",
                                  "—", ["NOT finding a guessed selector proves nothing about overall DKIM coverage."],
                                  "Re-run with --dkim-selector <name> (see your provider docs) or --dkim-guess.")]
    findings, seen = [], 0
    for selector in selectors:
        query = _txt(resolver, f"{selector}._domainkey.{domain}")
        if query["status"] == "ok":
            record = next((t for t in query["records"] if "p=" in t or t.upper().startswith("V=DKIM1")), None)
            if record:
                seen += 1
                empty = re.search(r"p=\s*(?:;|$)", record)
                evidence = f"selector '{selector}': {record[:140]}{'…' if len(record) > 140 else ''}"
                if empty:
                    findings.append(_f(f"dkim:{selector}", INFO, f"Selector '{selector}' published a REVOKED key (empty p=).",
                                       "Revocation is normal key hygiene for retired selectors.", ["—"], "—"))
                else:
                    findings.append(_f(f"dkim:{selector}", PASS, evidence,
                                       f"A public DKIM key exists for selector '{selector}'.",
                                       ["A published key proves the selector exists, not that mail is actually signed with it."],
                                       "—"))
        elif query["status"] in ("no_records", "nxdomain"):
            findings.append(_f(f"dkim:{selector}", INFO, f"No DKIM key at selector '{selector}'.",
                               "That selector is simply not used (or DNS did not return it).",
                               ["A guessed-but-missing selector proves nothing about DKIM as a whole."], "—"))
        else:
            findings.append(_f(f"dkim:{selector}", INCONCLUSIVE, f"{selector}: {query['error']}",
                               "DNS error — cannot tell presence from absence.", ["—"], "Retry later or with --resolver."))
    return ("present" if seen else "absent"), findings


def analyze_mta_sts(resolver, domain, settings) -> tuple[str, list[dict]]:
    query = _txt(resolver, f"_mta-sts.{domain}")
    if query["status"] != "ok" or not any(t.startswith("v=STSv1") for t in query["records"]):
        availability = _availability(query, "MTA-STS")
        if availability == "absent":
            return "absent", [_f("mta_sts", INFO, "No MTA-STS record (_mta-sts).",
                                 "MTA-STS tells sending servers to require TLS for this domain's mail.",
                                 ["MTA-STS is voluntary hardening; DANE is an alternative."],
                                 "Consider MTA-STS in 'testing' mode before 'enforce'.")]
        return "inconclusive", [_f("mta_sts", INCONCLUSIVE, f"MTA-STS could not be determined: {query['error']}",
                                   "—", ["—"], "Retry later.")]
    record = next(t for t in query["records"] if t.startswith("v=STSv1"))
    findings = [_f("mta_sts", PASS, f"MTA-STS DNS record: {record}",
                   "Senders know a policy exists and should refresh it when id= changes.",
                   ["The DNS record alone is not the policy — see policy finding."], "—")]
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        with httpx.Client(timeout=settings.read_timeout,
                          headers={"User-Agent": settings.user_agent},
                          follow_redirects=False) as client:
            response = client.get(policy_url)
        body = response.content[: config.AUX_MAX_BYTES].decode("utf-8", "replace")
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}")
        fields = dict(line.split(":", 1) for line in body.splitlines() if ":" in line)
        version = fields.get("version", "").strip()
        if version != "STSv1":
            findings.append(_f("mta_sts_policy", WARN, f"Policy file has unexpected version {version!r}: {policy_url}",
                               "A malformed policy will be ignored by senders.", ["Manual line-based parsing."],
                               "Serve 'version: STSv1' as the first line.", "low"))
        else:
            mode = fields.get("mode", "").strip()
            findings.append(_f(
                "mta_sts_policy", PASS,
                f"Policy mode={mode}, max_age={fields.get('max_age', '').strip()}, "
                f"mx patterns={len(fields.get('mx', '').split()) if fields.get('mx') else 0} from {policy_url}",
                {"enforce": "Senders must use TLS matching these MX patterns.",
                 "testing": "Failures are reported (TLS-RPT) but not enforced yet.",
                 "none": "Policy withdrawn."}.get(mode, f"mode={mode}"),
                [f"Truncated at {config.AUX_MAX_BYTES // 1024} KB; mx patterns not individually audited."],
                "Keep max_age ≥ weeks and move testing → enforce when stable."))
    except Exception as exc:
        findings.append(_f("mta_sts_policy", INCONCLUSIVE,
                           f"DNS record exists but the policy file could not be fetched: {type(exc).__name__}: {exc}",
                           "A stale/missing policy file breaks the mechanism it advertises.",
                           ["One fetch attempt, bounded size."],
                           "Ensure https://mta-sts.<domain>/.well-known/mta-sts.txt is reachable."))
    return "present", findings


def analyze_tls_rpt(resolver, domain) -> tuple[str, list[dict]]:
    query = _txt(resolver, f"_smtp._tls.{domain}")
    if query["status"] != "ok" or not any(t.upper().startswith("V=TLSRPTV1") for t in query["records"]):
        availability = _availability(query, "TLS-RPT")
        if availability == "absent":
            return "absent", [_f("tls_rpt", INFO, "No TLS-RPT record (_smtp._tls).",
                                 "TLS-RPT collects reports about failed TLS in mail delivery.",
                                 ["Optional; most useful once MTA-STS exists."],
                                 "Consider 'v=TLSRPTv1; rua=mailto:tls-reports@<domain>'.")]
        return "inconclusive", [_f("tls_rpt", INCONCLUSIVE, f"TLS-RPT could not be determined: {query['error']}",
                                   "—", ["—"], "Retry later.")]
    record = next(t for t in query["records"] if t.upper().startswith("V=TLSRPTV1"))
    rua_match = re.search(r"rua\s*=\s*([^;]+)", record, re.IGNORECASE)
    destinations = [d.strip() for d in rua_match.group(1).split(",")] if rua_match else []
    bad = [d for d in destinations if not d.startswith(("mailto:", "https:"))]
    status = PASS if not bad else WARN
    return "present", [_f("tls_rpt", status, f"TLS-RPT: {record[:160]}{'…' if len(record) > 160 else ''}",
                          "Mail senders will report TLS negotiation failures to these destinations.",
                          ["Report destinations are published intentionally; receiving is volume-dependent."]
                          + ([f"Unusual destination(s): {bad}"] if bad else []),
                          "—" if not bad else "Use mailto:/https: URIs per RFC 8460.", "low" if bad else None)]


def analyze_email_security(domain: str, settings) -> dict:
    if not domain:
        return {"status": "skipped", "note": "Email security requires a registrable domain (IP targets skipped).",
                "mechanisms": {}}
    resolver, _, note = build_resolver(settings.resolver_servers or None)
    mechanisms: dict[str, dict] = {}
    findings: list[dict] = []

    for key, fn, extra in (
        ("spf", analyze_spf, (resolver, domain)),
        ("dmarc", analyze_dmarc, (resolver, domain)),
        ("dkim", lambda r, d: analyze_dkim(r, d, list(settings.dkim_selectors), settings.dkim_guess),
         (resolver, domain)),
        ("mta_sts", lambda r, d: analyze_mta_sts(r, d, settings), (resolver, domain)),
        ("tls_rpt", analyze_tls_rpt, (resolver, domain)),
    ):
        try:
            status, fs = fn(*extra)
            mechanisms[key] = {"status": status}
            findings.extend(fs)
        except Exception as exc:
            mechanisms[key] = {"status": "inconclusive", "error": f"{type(exc).__name__}: {exc}"}
            findings.append(_f(key, INCONCLUSIVE, f"Check failed: {type(exc).__name__}: {exc}",
                               "—", ["Internal parsing error, not target behaviour."], "Report this if reproducible."))
    return {"status": "ok", "domain_queried": domain,
            "resolver_note": note, "mechanisms": mechanisms,
            "status_summary": {k: v["status"] for k, v in mechanisms.items()},
            "findings": findings,
            "note": "Passive DNS analysis (+ at most one MTA-STS policy fetch). "
                    "Optional mechanisms are NOT mandatory; 'absent' ≠ 'broken'."}
