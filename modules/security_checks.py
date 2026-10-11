"""Security configuration analysis (spec §4/§15) — v2 classification.

Every check yields a core.models.Finding with:
  status:     PASS / WARN / FAIL / INFO / INCONCLUSIVE / NOT_TESTED
  severity:   only set when WARN/FAIL, and conservative by charter:
              a missing header is NEVER more than "low" here, because a
              missing defence-in-depth control is not an exploit.
  evidence / why / limitations / recommendation, timestamp, module.

Rules of the house:
* FAIL means a clearly-defined test demonstrably violated a requirement —
  we rarely reach it from passive observation (e.g. certificate invalid).
* Modern controls satisfy the goal: missing X-Frame-Options is NOT flagged
  when CSP frame-ancestors is present (and vice-versa gets a note).
* We never claim "complete security" — one response from one endpoint.
"""
from __future__ import annotations

import re

from core.models import (FAIL, INCONCLUSIVE, INFO, NOT_TESTED, PASS, WARN,
                         Finding)

_MODULE = "security"


def _finding(name, status, evidence, why, limitations, recommendation,
             severity=None) -> Finding:
    return Finding(name=name, module=_MODULE, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation)


def _headers(http: dict | None) -> dict:
    return (http or {}).get("final", {}).get("headers", {}) or {}


def _final(http: dict | None) -> dict:
    return (http or {}).get("final") or {}


def _final_https(http: dict | None) -> bool:
    return _final(http).get("scheme") == "https"


def _http_ok(http: dict | None) -> bool:
    return bool(http) and http.get("status") == "ok" and _final(http)


# --------------------------------------------------------------------------
def check_https(http, tls) -> Finding:
    if tls and tls.get("status") == "ok":
        return _finding("https_available", PASS,
                        f"TLS {tls.get('tls_version')} negotiated; certificate chains to a trusted root.",
                        "Transport is encrypted and the server name is authenticated.",
                        ["Says nothing about code quality, data handling, or site honesty."],
                        "Keep auto-renewal monitored; alert before expiry.")
    if tls and tls.get("failure_kind") in ("expired", "self_signed", "hostname_mismatch", "chain_failure"):
        return _finding("https_available", FAIL, severity="medium",
                        evidence=tls.get("error", "certificate problem"),
                        why="Browsers will present full-page warnings; users may click through them.",
                        limitations=["Could be a transient misconfiguration, captive portal, or local clock skew."],
                        recommendation="Fix issuance/chain/hostname in the TLS stack you control.")
    if tls and tls.get("status") == "skipped" and _http_ok(http):
        return _finding("https_available", WARN, severity="low",
                        evidence="The scan target itself was plain http:// and the request was served without TLS.",
                        why="Everything in this request/response travelled readable and modifiable by the network.",
                        limitations=["HTTPS may still exist on port 443; only the scanned URL was measured."],
                        recommendation="Serve the canonical site over HTTPS; redirect HTTP to it.")
    return _finding("https_available", INCONCLUSIVE,
                    "No completed TLS handshake and no served plain-HTTP response.",
                    "Cannot judge transport security without a completed connection.",
                    ["A network failure here reveals network state, not server policy."],
                    "Re-run on a stable connection, explicitly with https://.")


def check_http_to_https(http) -> Finding:
    chain = (http or {}).get("chain") or []
    probe = (http or {}).get("http_probe")
    if not _http_ok(http) and not probe:
        return _finding("http_to_https", NOT_TESTED, "No HTTP evidence was collected.",
                        "—", ["HTTP module failed before any comparison could be made."],
                        "Re-run when reachable.")
    if chain and chain[0]["url"].startswith("http://") and _final(http).get("scheme") == "https" and len(chain) > 1:
        return _finding("http_to_https", PASS,
                        f"Requested {chain[0]['url']} and ended at {_final(http)['url']} "
                        f"({len(chain) - 1} redirect hop(s), all recorded).",
                        "Visitors starting from plain HTTP get upgraded to encryption automatically.",
                        ["The very first HTTP request is still unprotected — only HSTS closes that gap.",
                         "Only this URL was followed; other paths may differ."],
                        "Keep the redirect; deploy HSTS.")
    if probe is not None:
        if probe.get("tested") is False:
            return _finding("http_to_https", INCONCLUSIVE, probe.get("reason", "Probe not applicable."),
                            "The scanner decides explicitly what evidence exists instead of guessing.",
                            ["See the HTTP redirect chain for what was actually observed."], "—")
        if probe.get("error"):
            return _finding("http_to_https", INCONCLUSIVE,
                            f"Probe of {probe.get('probe_url')} failed: {probe['error']}",
                            "Upgrade behaviour for plain-HTTP visitors could not be measured.",
                            ["Probe failure ≠ no redirect; port 80 might be intentionally closed (arguably better)."],
                            "Deliberately pick a stance: redirect HTTP→HTTPS, or close port 80 and use HSTS preload.")
        if probe.get("ends_on_https"):
            hops = probe.get("hops", [])
            first = hops[0] if hops else {}
            return _finding("http_to_https", PASS,
                            f"Probe {probe.get('probe_url')} → {first.get('status')} "
                            f"{first.get('location')}, final scheme https after {max(len(hops) - 1, 0)} hop(s).",
                            "Plain-HTTP visitors are upgraded automatically.",
                            ["One path ('/') was probed once; conditions can differ per path/host.",
                             "JavaScript/meta-refresh navigation is not executed by this scanner."],
                            "Keep it; add HSTS.")
        if probe.get("ends_on_https") is False:
            return _finding("http_to_https", WARN, severity="low",
                            evidence=f"Probe {probe.get('probe_url')} ended at "
                                     f"{probe.get('hops', [{}])[-1].get('url')} with status {probe.get('final_status')} — still HTTP.",
                            why="Users starting on HTTP stay unencrypted on this path.",
                            limitations=["Only '/' was probed; the redirect may be conditional (host, UA, path)."],
                            recommendation="301-redirect all HTTP traffic to the HTTPS canonical URL.")
    if _final(http).get("scheme") == "https":
        return _finding("http_to_https", INCONCLUSIVE,
                        "Final URL is HTTPS, but the plain-HTTP upgrade path was not exercised.",
                        "—", ["Probe is skipped for IP targets and explicit http:// scans."],
                        "Check manually: curl -sI http://<host>/")
    if _final(http).get("scheme") == "http":
        return _finding("http_to_https", WARN, severity="low",
                        evidence=f"The scanned http:// URL was served over HTTP (final status "
                                 f"{_final(http).get('status')}) with no HTTPS upgrade.",
                        why="This endpoint answers over cleartext to anyone who asks.",
                        limitations=["Only this URL was measured; HTTPS may exist without being linked or redirected."],
                        recommendation="Serve HTTPS and redirect HTTP → HTTPS.")
    return _finding("http_to_https", INCONCLUSIVE, "Insufficient HTTP evidence.", "—",
                    ["Chain and probe were both inconclusive."], "Re-run when reachable.")


def check_hsts(headers: dict, https: bool) -> Finding:
    value = headers.get("strict-transport-security")
    if not https:
        return _finding("hsts", INCONCLUSIVE,
                        "Final response is plain HTTP; HSTS is only evaluated on HTTPS responses.",
                        "HSTS lets browsers remember 'always HTTPS for this host'.",
                        ["HSTS headers on plain-HTTP responses are ignored by browsers by design."],
                        "Deploy HTTPS first, then add Strict-Transport-Security.")
    if value:
        match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
        if match:
            days = int(match.group(1)) // 86400
            extras = "; ".join(x for x in ("includeSubDomains" if "includesubdomains" in value.lower() else "",
                                           "preload" if "preload" in value.lower() else "") if x)
            return _finding("hsts", PASS,
                            f"Strict-Transport-Security: {value} (≈{days} days{'; ' + extras if extras else ''}).",
                            "After first contact, browsers refuse plain HTTP for max-age seconds.",
                            ["Observed on one response; other endpoints might omit it."],
                            "max-age ≥ 6 months and includeSubDomains before considering preload.")
        return _finding("hsts", WARN, severity="low",
                        evidence=f"Header present but malformed: {value!r}.",
                        why="Without a valid max-age browsers ignore the policy.",
                        limitations=["Parsing is directive-based; unusual formatting may be misread."],
                        recommendation="Use 'max-age=31536000; includeSubDomains' syntax.")
    return _finding("hsts", WARN, severity="low",
                    evidence="No Strict-Transport-Security header on the tested HTTPS response.",
                    why="Without HSTS a first-time plain-HTTP request can be intercepted (SSL-strip class).",
                    limitations=["One response observed; policies may differ per endpoint. "
                                 "Missing HSTS is hardening gap, not an exploit."],
                    recommendation="Review intended HSTS deployment; 'max-age=31536000; includeSubDomains'.")


def check_csp(headers: dict) -> Finding:
    value = headers.get("content-security-policy")
    if value:
        weak = "unsafe-inline" in value or "unsafe-eval" in value
        return _finding("content_security_policy", PASS if not weak else INFO,
                        f"CSP: {value[:160]}{'…' if len(value) > 160 else ''}"
                        + (" (contains unsafe-inline/unsafe-eval)" if weak else ""),
                        "CSP constrains what scripts/styles may run — strong XSS damage control.",
                        ["Presence ≠ quality; directive-level auditing is out of scope here."],
                        "Tighten iteratively; prefer nonces/hashes over unsafe-inline." if weak else "Keep reviewing as content evolves.")
    return _finding("content_security_policy", WARN, severity="low",
                    evidence="No Content-Security-Policy header observed.",
                    why="No defence-in-depth layer against injected scripts.",
                    limitations=["Extremely common; NOT proof an XSS vulnerability exists.",
                                 "Other endpoints may send it."],
                    recommendation="Start with Content-Security-Policy-Report-Only and iterate.")


def check_nosniff(headers: dict) -> Finding:
    value = headers.get("x-content-type-options", "")
    if value.lower() == "nosniff":
        return _finding("x_content_type_options", PASS, "X-Content-Type-Options: nosniff",
                        "Prevents MIME-sniffing content confusion.", ["One response observed."], "—")
    if value:
        return _finding("x_content_type_options", WARN,
                        f"Unexpected value {value!r} (only 'nosniff' is defined).",
                        "A malformed directive provides no protection.",
                        ["Servers/proxies may rewrite values."],
                        "Set exactly: X-Content-Type-Options: nosniff.", severity="low")
    return _finding("x_content_type_options", WARN,
                    "X-Content-Type-Options absent.",
                    "Without it, some browsers MIME-sniff content.",
                    ["Risk concentrates on user-uploaded or mislabelled content."],
                    "Serve 'X-Content-Type-Options: nosniff' on all responses.", severity="low")


def check_referrer_policy(headers: dict) -> Finding:
    value = headers.get("referrer-policy")
    if value:
        return _finding("referrer_policy", PASS, f"Referrer-Policy: {value}",
                        "Controls URL leakage to third parties on outbound clicks.",
                        ["Single response observed."], "—")
    return _finding("referrer_policy", INFO,
                    "No Referrer-Policy; browsers use their default (strict-origin-when-cross-origin).",
                    "Query strings can otherwise leak user context across origins.",
                    ["Modern defaults are already privacy-reasonable."],
                    "Set 'strict-origin-when-cross-origin' or stricter if you need consistency.")


def check_permissions_policy(headers: dict) -> Finding:
    value = headers.get("permissions-policy")
    if value:
        return _finding("permissions_policy", PASS,
                        f"Permissions-Policy: {value[:140]}{'…' if len(value) > 140 else ''}",
                        "Restricts camera/mic/geolocation etc. for the page and its iframes.",
                        ["Directives not individually audited."], "—")
    return _finding("permissions_policy", INFO,
                    "No Permissions-Policy observed.",
                    "Third-party frames inherit broad default feature access.",
                    ["Most sites legitimately need no restrictions."],
                    "Consider 'camera=(), microphone=(), geolocation=()' as a baseline.")


def _parse_frame_ancestors(csp: str) -> str | None:
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts and parts[0].lower() == "frame-ancestors":
            return " ".join(parts[1:]) or "(empty)"
    return None


def check_framing(headers: dict) -> Finding:
    xfo = headers.get("x-frame-options")
    fa = _parse_frame_ancestors(headers.get("content-security-policy", "") or "") \
        if headers.get("content-security-policy") else None
    if fa:
        return _finding("framing_protection", PASS,
                        f"CSP frame-ancestors: {fa}" + (f" (X-Frame-Options also present: {xfo})" if xfo else
                                                        " (modern directive; X-Frame-Options unnecessary)"),
                        "Controls who may embed this page in frames (clickjacking defence).",
                        ["Observed value not audited for wildcard sources."],
                        "Keep frame-ancestors; XFO optional legacy fallback." if not xfo else "—")
    if xfo:
        xfo_up = xfo.upper()
        if xfo_up in ("DENY", "SAMEORIGIN") or xfo_up.startswith("ALLOW-FROM"):
            return _finding("framing_protection", PASS, f"X-Frame-Options: {xfo} (CSP frame-ancestors absent).",
                            "Legacy but effective clickjacking control for most browsers.",
                            ["No CSP frame-ancestors observed; modern apps should prefer it."],
                            "Add CSP frame-ancestors as the primary control.")
        return _finding("framing_protection", WARN,
                        f"Malformed X-Frame-Options value: {xfo!r}.",
                        "Invalid values are ignored by browsers.",
                        ["Proxy rewriting can garble values."],
                        "Use 'DENY' or 'SAMEORIGIN', or CSP frame-ancestors.", severity="low")
    return _finding("framing_protection", WARN,
                    "Neither CSP frame-ancestors nor X-Frame-Options observed.",
                    "Without framing rules the page could be embedded by hostile sites (clickjacking).",
                    ["Only matters if the page has click-sensitive actions; many APIs have none.",
                     "Policies may vary per endpoint."],
                    "Add 'frame-ancestors \"self\"' (or X-Frame-Options: SAMEORIGIN) where embedding is unwanted.",
                    severity="low")


def check_cross_origin(headers: dict) -> list[Finding]:
    out = []
    if headers.get("cross-origin-opener-policy"):
        out.append(_finding("coop", PASS, f"Cross-Origin-Opener-Policy: {headers['cross-origin-opener-policy']}",
                            "Isolates the browsing context from cross-origin windows (Spectre-class defences).",
                            ["Value not audited against the app's windowing needs."], "—"))
    if headers.get("cross-origin-resource-policy"):
        out.append(_finding("corp", PASS, f"Cross-Origin-Resource-Policy: {headers['cross-origin-resource-policy']}",
                            "Limits which origins may embed this resource.",
                            ["Single response observed."], "—"))
    if headers.get("cross-origin-embedder-policy"):
        out.append(_finding("coep", PASS, f"Cross-Origin-Embedder-Policy: {headers['cross-origin-embedder-policy']}",
                            "Requires subresources to opt into being embedded (enables isolation).",
                            ["Deployability depends on all subresources supporting it."], "—"))
    if not out:
        out.append(_finding("cross_origin_policies", INFO,
                            "No COOP/COEP/CORP headers observed.",
                            "These enable cross-origin isolation and Spectre-mitigation contexts.",
                            ["They are opt-in hardening, not baseline requirements; absence is not a defect."],
                            "Evaluate only if the app needs cross-origin isolation (SharedArrayBuffer etc.)."))
    return out


def check_cookies(cookies: list[dict], https: bool) -> list[Finding]:
    if not cookies:
        return [_finding("cookies", INFO, "No Set-Cookie headers observed on the fetched path.",
                         "Cookie flags protect tokens from network/JS access.",
                         ["Only the landing page was fetched; authenticated flows may set cookies later.",
                          "Cookie VALUES are never stored or displayed by this scanner."],
                         "Re-check on authenticated pages you own.")]
    findings = []
    for cookie in cookies:
        attrs, name = cookie["attributes"], cookie["name"]
        problems = []
        if https and not attrs["secure"]:
            problems.append("Secure")
        if not attrs["httponly"]:
            problems.append("HttpOnly")
        if attrs["samesite"] not in ("lax", "strict"):
            problems.append(f"SameSite={attrs['samesite'] or 'unset'}")
        observed = (f"Secure={attrs['secure']} HttpOnly={attrs['httponly']} "
                    f"SameSite={attrs['samesite'] or 'unset'} Domain={attrs['domain'] or 'host-only'} "
                    f"Path={attrs['path'] or 'default'} (value omitted; {cookie.get('value_length', '?')} chars)")
        if not problems:
            findings.append(_finding(f"cookie:{name}", PASS, observed,
                                     "Flags reduce token exposure to network observers, JS and CSRF.",
                                     ["Observed on one response; other endpoints/sessions may differ."], "—"))
        elif problems == ["HttpOnly"]:
            findings.append(_finding(f"cookie:{name}", INFO, observed,
                                     "JavaScript-accessible cookies are common for UI state; not every cookie is a session token.",
                                     ["Purpose inferred from name alone — treat as a question for the owner."],
                                     "If this holds auth/session data, add HttpOnly."))
        else:
            findings.append(_finding(
                f"cookie:{name}", WARN, severity="low", evidence=observed,
                why="Missing flags can expose tokens to sniffing (Secure), JS exfiltration (HttpOnly) or CSRF (SameSite).",
                limitations=["Attribute risk depends on the cookie's actual role — not stated by the server.",
                             "This scanner cannot tell a CSRF token from an analytics ID."],
                recommendation="For session cookies: Secure + HttpOnly + SameSite=Lax/Strict."))
    return findings


_MIXED_RE = re.compile(
    r"""<\s*(?:script|img|link|iframe|source|audio|video)[^>]+(?:src|href)\s*=\s*["']\s*(http://[^"'>\s]+)""",
    re.IGNORECASE)


def check_mixed_content(http: dict | None) -> Finding:
    if not _final_https(http):
        return _finding("mixed_content", NOT_TESTED, "Not an HTTPS page.",
                        "Only meaningful for pages delivered over HTTPS.", ["—"], "—")
    html = (http or {}).get("html_excerpt") or ""
    if not html:
        return _finding("mixed_content", INCONCLUSIVE, "No HTML body to inspect.", "—",
                        ["Body may have failed to download."],"—")
    hits = [h for h in _MIXED_RE.findall(html)
            if not h.startswith(("http://127.", "http://localhost"))]
    if hits:
        sample = ", ".join(hits[:3]) + ("…" if len(hits) > 3 else "")
        return _finding("mixed_content", WARN, severity="low",
                        evidence=f"{len(hits)} asset reference(s) use http:// on an HTTPS page: {sample}",
                        why="Browsers block active mixed content; passive content leaks privacy.",
                        limitations=["Regex over possibly-truncated initial HTML; JS-inserted assets not seen.",
                                     "Some URLs may auto-upgrade (CSP upgrade-insecure-requests)."],
                        recommendation="Load subresources over HTTPS; add CSP upgrade-insecure-requests.")
    return _finding("mixed_content", PASS, "No plain-HTTP sub-resource references found in the initial HTML.",
                    "Mixed content undermines the HTTPS guarantee.",
                    ["Initial HTML only; executed JS not observed."], "Keep subresources on HTTPS.")


_VERSIONY = re.compile(r"\d+(?:\.\d+)+")


def check_disclosure(headers: dict) -> list[Finding]:
    findings = []
    server = headers.get("server")
    if server and _VERSIONY.search(server):
        findings.append(_finding("server_banner", INFO,
                                 f"Server: {server}",
                                 "Version banners speed up CVE matching for attackers.",
                                 ["Hiding versions is hygiene, not security; patching is the real control."],
                                 "Minimise version detail (e.g. nginx server_tokens off)."))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if headers.get(name):
            findings.append(_finding(f"disclosure:{name}", INFO,
                                     f"{name}: {headers[name]}",
                                     "Advertises the runtime/framework to everyone.",
                                     ["Cosmetic risk; exploitation requires an actual weakness."],
                                     "Disable version-disclosing headers where convenient."))
    if not findings:
        findings.append(_finding("server_banner", INFO,
                                 "No versioned Server/X-Powered-By banners observed.",
                                 "Less free recon data.",
                                 ["Behaviour-based fingerprinting remains possible."], "—"))
    return findings


def run_security_checks(*, http_result: dict | None, tls_result: dict | None,
                        metadata_result: dict | None) -> dict:
    from core.models import Finding as _F  # local alias for clarity below
    try:
        if not http_result and not tls_result:
            return {"status": "error", "error": "No HTTP or TLS evidence supplied.", "findings": []}
        headers = _headers(http_result)
        https = _final_https(http_result)
        findings: list[Finding] = [
            check_https(http_result, tls_result),
            check_http_to_https(http_result),
            check_hsts(headers, https),
            check_csp(headers),
            check_nosniff(headers),
            check_referrer_policy(headers),
            check_permissions_policy(headers),
            check_framing(headers),
            check_mixed_content(http_result),
        ]
        findings.extend(check_cross_origin(headers))
        findings.extend(check_cookies((http_result or {}).get("cookies") or [], https))
        findings.extend(check_disclosure(headers))

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.status] = counts.get(f.status, 0) + 1
        return {"status": "ok",
                "findings": [f.to_dict() for f in findings],
                "summary": {"counts": counts, "total": len(findings)},
                "note": ("Configuration observations — NOT vulnerability claims. "
                         "Severity 'high' is never assigned to a merely-missing header.")}
    except Exception as exc:
        return {"status": "error", "findings": [],
                "error": f"Security checks failed internally: {type(exc).__name__}: {exc}"}
