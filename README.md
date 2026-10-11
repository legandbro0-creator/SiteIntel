# SiteIntel v2.0

A modular, terminal-based **website intelligence & security configuration analysis** framework in Python — built for **Termux on Android** (no root, no Docker, no desktop).

SiteIntel answers, in one organised report: *"What can be **publicly and passively** observed about this website, and what does each observation actually mean?"*

> **The project's charter:** collect evidence carefully, explain what it means, acknowledge what it cannot prove, and never confuse an observation with a vulnerability.

---

## 1. What it does

| Area | Contents |
|---|---|
| Target & URLs | normalisation, IDN→punycode, hostname vs registrable domain, query-param names (sensitive VALUES redacted), SSRF-validated redirect following |
| DNS | A/AAAA/CNAME/MX/NS/TXT/CAA/SOA + TTLs; NXDOMAIN vs timeout vs servfail vs no-records; Termux resolver fallback; `--full-dns` |
| IP intelligence | full (untruncated) IPv4/IPv6, PTR, ASN/prefix/org via Team Cymru (keyless), CDN/anycast caveats |
| Connectivity | per-family **DNS vs TCP vs TLS** statuses (AVAILABLE/UNAVAILABLE/FAILED/NOT TESTED/INCONCLUSIVE), local-limitation detection (`Network is unreachable` ≠ site down) |
| HTTP | manual redirect chain (loops capped, cross-origin hops SSRF-validated), headers, cookies (values never stored), size caps, TTFB/total, JS-navigation detection |
| TLS | verified handshake, issuer/validity/SANs, TLS version+cipher, classified failures (expired/self-signed/mismatch/chain) |
| Metadata | title/desc/canonical/lang/robots/OG/favicon/assets/link&image counts (initial HTML only, no JS) |
| URL extras | robots.txt, sitemap.xml (bounded), favicon sha256 (`--urls`) |
| Fingerprints | header/HTML/cookie rules with **rule IDs**, confidence, evidence; ~27 technologies in `data/fingerprints.json` |
| Security config | findings with **PASS/WARN/FAIL/INFO/INCONCLUSIVE/NOT_TESTED**, conservative severity, evidence/why/limitations/recommendation; HSTS, CSP, nosniff, Referrer/Permissions-Policy, **framing (XFO vs frame-ancestors)**, **COOP/COEP/CORP**, cookies, mixed content |
| Email security | SPF (incl. multi-record, `+all`, lookup count), DMARC (p=none explainer), DKIM (selectors), MTA-STS (+policy fetch), TLS-RPT (`--email-security`) |
| DNSSEC | DS/DNSKEY/RRSIG discovery **separated from** AD-bit validation state (`--dnssec`) |
| Cert Transparency | crt.sh: deduped certs, current vs expired, hostnames (`--ct`) |
| Subdomains | passive discovery (CT + cert SANs), sources, optional bounded resolution, wildcard detection (`--subdomains`) |
| Ports | **opt-in active** TCP connect checks, profiles/lists, passive banners, optional nmap (`--ports`) |
| Registration | RDAP registrar, created/expires/changed, statuses, NS, registrant org when published, redaction-aware (`--rdap`) |
| Reports | rich/plain terminal, `--json` (stable schema v3, no-overwrite guard), `--html` (standalone, CSP-locked, everything escaped), `diff old.json new.json` |

## 2. Install on Termux

```sh
pkg update && pkg install -y python
unzip siteintel-v2.0.zip && cd siteintel        # or: git clone <repo>
pip install -r requirements.txt                  # all pure Python
```

Optional:

```sh
pkg install -y python-cryptography   # nicer parsing of INVALID certs
pkg install -y nmap                  # for --nmap (with --ports)
pip install pytest                   # run the test suite
```

## 3. Usage

```sh
python main.py example.com                             # default core scan
python main.py https://shop.example.co.uk/products?id=42 --full
python main.py example.com --dns --full-dns
python main.py example.com --http --tls --json out.json
python main.py example.com --email-security --dnssec --dkim-selector google
python main.py example.com --subdomains --resolve-subdomains
python main.py example.com --ports                     # ACTIVE; authorized targets only
python main.py example.com --ports 22,80,443 --nmap
python main.py example.com --html report.html
python main.py diff reports/old.json reports/new.json
python main.py example.com --quiet --json daily.json
```

Flags (abridged): `--full` (all *passive* modules — never `--ports`), per-module flags `--dns --ip --conn --http --tls --tech --meta --security --rdap --email-security --dnssec --ct --subdomains --urls`, `--resolver IP` (repeat), `--timeout S`, `--user-agent "…"`, `--no-cache`, `--no-color`, `--quiet`, `--verbose`, `--full-dns`, `--overwrite`, `--version`. Active checks (ports) are opt-in only.

Exit codes: `0` clean · `1` finished with module errors · `2` bad input · `130` interrupted.

## 4. How a finding should be read

```
[WARN] hsts severity=low
      Observed: No Strict-Transport-Security header on the tested HTTPS response.
      Why: Without HSTS a first-time plain-HTTP request can be intercepted (SSL-strip class).
      Limitation: One response observed; policies may differ per endpoint. Missing HSTS is hardening gap, not an exploit.
      Consider: Review intended HSTS deployment; 'max-age=31536000; includeSubDomains'.
```

Observation ≠ vulnerability. Severity `high` is **never** assigned to a merely missing header — `FAIL` means a clear requirement demonstrably broke (e.g. an invalid certificate).

## 5. Architecture

```
siteintel/
├── main.py                 CLI + orchestration
├── config.py               every timeout/limit/profile + env overrides
├── core/                   models (Finding/ModuleResult, taxonomy), target
│                           (parse+redact), validation (SSRF), errors, runner (isolation)
├── modules/                dns_info, ip_info, connectivity, http_info, tls_info,
│                           page_metadata, urls, technologies, security_checks,
│                           email_security, dnssec, certificate_transparency,
│                           subdomains, ports, registration, cache
├── output/                 terminal (rich/plain/quiet), json_report, html_report, diff
├── data/fingerprints.json  editable rules with ids
├── tests/                  123 offline tests (local fixture server)
└── reports/                default export location
```

Data flows one way: **modules → core models → output renderers**. Modules never print.

## 6. Safety SSOT (read before scanning)

- Passive scan ≈ 2–8 GETs + DNS questions. `--ports` performs TCP connect() checks — **only** on the exact target you typed, never on redirect/discovered hosts. Run active checks only on systems you own or are authorized to assess.
- SSRF defence: cross-origin redirect hops are DNS+address validated (private/loopback/link-local/CGNAT/multicast/reserved are blocked); TOCTOU caveat is printed in reports.
- Cookie values are never stored or displayed. Sensitive query values are redacted. No auth data is logged.
- No exploitation, brute force, stealth, evasion, POSTs, crawling, or form submission anywhere in the codebase.

## 7. Honest limitations

- Public & passive by design; one page of one host; no JS execution (initial HTML only).
- Registrable-domain split is a built-in heuristic (not the full Public Suffix List).
- DNSSEC "validated" = the resolver's AD bit (we trust the resolver; full client-side chain validation is out of scope without extra libs).
- CT/subdomain data is public-log dependent: **historical ≠ current, discovered ≠ live**.
- ASN/prefix data comes from public routing registries; IPs identify infrastructure (CDN/hosting), not necessarily the application operator.
- Ports: passive banners only (no probes); mobile networks can make "filtered" ambiguous.
- External deps: crt.sh, Team Cymru DNS, rdap.org — free/keyless; outages are reported, never fabricated.

## 8. Testing

```sh
pip install pytest
python -m pytest -q        # 123 tests, all offline, ~15 s
```

Unit tests cover target parsing/redaction, SSRF validation (incl. IPv4-mapped IPv6), redirect loops/chains, body caps, cookie redaction, security taxonomy, email-security parsing (stub resolver), CT parsing/dedup, subdomain normalisation, port spec parsing + local open/closed ports, HTML escaping, JSON schema + overwrite guard, diff markers, and CLI parsing. Integration with the live internet is exercised manually (e.g. `example.com`) and never required by the suite.

## 9. Troubleshooting (Termux)

- **`No system DNS resolver found`** — normal on Android; SiteIntel falls back to public resolvers and prints a note. Pin your own with `--resolver 9.9.9.9`.
- **`pip install` fails** — `pkg install python` first; all required deps are pure Python.
- **Timeouts on mobile data** — raise `--timeout 15`; radios sleep.
- **`rich` missing** — output silently degrades to plain text; `pip install rich` restores colour.
- **Certificate errors on weird sites** — that's the TLS module working as intended; it reports *why* (expired/self-signed/mismatch/chain) without ever disabling verification for fetches.

## License

MIT — see `LICENSE`. Use responsibly and lawfully.
