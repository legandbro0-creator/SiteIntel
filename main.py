#!/usr/bin/env python3
"""SiteIntel v2 — modular website intelligence for the terminal (Termux-first).

Design rules honoured here:
* Passive by default; the ONLY active checks (TCP connect scans) are opt-in
  via --ports and restricted to the stated target.
* Every module runs inside core.runner's isolation boundary; one failure
  never kills the others and is reported, not hidden.
* Modules return data; output/ renders.  Findings use the v2 taxonomy.

Exit codes: 0 clean, 1 finished with module errors, 2 input/CLI error,
            130 interrupted.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config  # noqa: E402
from core.errors import TargetError  # noqa: E402
from core.models import ModuleResult  # noqa: E402
from core.runner import run_module  # noqa: E402
from core.target import normalize_target  # noqa: E402
from output import diff as output_diff  # noqa: E402
from output import html_report, json_report, terminal  # noqa: E402

MODULE_ORDER = ["dns", "ip", "connectivity", "http", "tls", "metadata", "urls",
                "technologies", "security", "email_security", "dnssec",
                "certificate_transparency", "subdomains", "ports", "registration"]
DEFAULT_MODULES = {"dns", "ip", "connectivity", "http", "tls",
                   "metadata", "technologies", "security"}
FULL_EXTRAS = {"registration", "email_security", "dnssec", "certificate_transparency",
               "subdomains", "urls"}  # NOT ports: active checks are never auto-enabled
FLAG_TO_MODULE = {"dns": "dns", "ip": "ip", "conn": "connectivity", "http": "http",
                  "tls": "tls", "tech": "technologies", "meta": "metadata",
                  "security": "security", "rdap": "registration",
                  "email_security": "email_security", "dnssec": "dnssec",
                  "ct": "certificate_transparency", "subdomains": "subdomains",
                  "ports": "ports", "urls": "urls"}
DEPENDENCIES = {"security": {"http", "tls", "metadata"},
                "technologies": {"http"},
                "metadata": {"http"},
                "subdomains": {"certificate_transparency"}}

REQUIRED_LIBS = {"httpx": "httpx", "dnspython": "dns", "beautifulsoup4": "bs4"}
REQUIRED_MODULES = {"dns", "ip", "http", "tls", "connectivity"}


def build_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siteintel",
        description="Passive website intelligence & security configuration analysis "
                    "(educational, non-destructive, Termux-tested).",
        epilog="Examples:\n"
               "  python main.py example.com\n"
               "  python main.py https://shop.example.co.uk/products?id=42 --full\n"
               "  python main.py example.com --email-security --dnssec --dkim-selector google\n"
               "  python main.py example.com --subdomains --resolve-subdomains\n"
               "  python main.py example.com --ports            (opt-in active check; authorized targets)\n"
               "  python main.py example.com --json report.json --html report.html\n"
               "  python main.py diff old.json new.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", help="domain or URL to inspect")
    parser.add_argument("--full", action="store_true",
                        help="all passive modules (RDAP, email security, DNSSEC, CT, subdomains, extras). "
                             "Never includes --ports.")
    flag_helps = {"dns": "DNS records only", "ip": "IP/ASN intelligence", "conn": "connectivity diagnostics",
                  "http": "HTTP analysis (manual, SSRF-validated redirects)", "tls": "TLS certificate",
                  "tech": "technology fingerprinting", "meta": "page metadata", "security": "security configuration",
                  "rdap": "domain registration (RDAP)", "email_security": "SPF/DMARC/DKIM/MTA-STS/TLS-RPT",
                  "dnssec": "DNSSEC records + validation state", "ct": "Certificate Transparency (crt.sh)",
                  "subdomains": "passive subdomain discovery", "ports": "OPT-IN TCP connect checks (--ports [profile|list])",
                  "urls": "robots.txt / sitemap.xml / favicon hash"}
    for flag, mod in FLAG_TO_MODULE.items():
        cli = "--" + flag.replace("_", "-")
        if flag == "ports":
            parser.add_argument(cli, nargs="?", const="web", metavar="PROFILE_OR_LIST",
                                help=flag_helps[flag] + " — active! authorized targets only")
        else:
            parser.add_argument(cli, action="store_true", help=flag_helps[flag])
    parser.add_argument("--resolve-subdomains", action="store_true",
                        help="also resolve discovered hostnames (bounded)")
    parser.add_argument("--dkim-selector", action="append", default=[], metavar="NAME",
                        help="check this DKIM selector (repeatable)")
    parser.add_argument("--dkim-guess", action="store_true",
                        help="try a small built-in list of common DKIM selectors")
    parser.add_argument("--nmap", action="store_true", help="with --ports: also run nmap if installed")
    parser.add_argument("--json", nargs="?", const="", metavar="PATH",
                        help="write JSON report (default: reports/<host>-<time>.json)")
    parser.add_argument("--html", metavar="PATH", help="write standalone HTML report")
    parser.add_argument("--overwrite", action="store_true",
                        help="allow --json/--html to replace an existing file")
    parser.add_argument("--full-dns", action="store_true",
                        help="show complete DNS values (default: summarised at 80 chars)")
    parser.add_argument("--resolver", action="append", default=[], metavar="IP",
                        help="DNS resolver to use (repeatable)")
    parser.add_argument("--timeout", type=float, default=None, metavar="SECONDS")
    parser.add_argument("--user-agent", default=None)
    parser.add_argument("--no-cache", action="store_true", help="bypass RDAP/CT/ASN cache")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--quiet", action="store_true", help="compact module-status output only")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="store_true")
    return parser


def parse_cli(argv):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["diff"]:
        diff_parser = argparse.ArgumentParser(prog="siteintel diff",
                                              description="Compare two SiteIntel JSON reports.")
        diff_parser.add_argument("old", help="old report JSON")
        diff_parser.add_argument("new", help="new report JSON")
        return "diff", diff_parser.parse_args(argv[1:])
    return "scan", build_scan_parser().parse_args(argv)


def select_modules(args) -> set[str]:
    chosen = {FLAG_TO_MODULE[f] for f in FLAG_TO_MODULE if getattr(args, f, False)}
    if args.full:
        chosen |= DEFAULT_MODULES | FULL_EXTRAS
    if not chosen:
        chosen = set(DEFAULT_MODULES)
    expanded = set(chosen)
    for name in list(chosen):
        expanded |= DEPENDENCIES.get(name, set())
    return expanded


def check_dependencies(rep) -> bool:
    missing = []
    for pip_name, import_name in REQUIRED_LIBS.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        rep.error("Missing dependencies: " + ", ".join(missing))
        rep.note("On Termux:  pkg install python && pip install -r requirements.txt")
        return False
    return True


def run_scan(args, rep) -> int:
    if not check_dependencies(rep):
        return 2
    try:
        target = normalize_target(args.target)
    except TargetError as exc:
        rep.error(str(exc))
        return 2

    settings = config.ScanSettings(
        user_agent=args.user_agent or config.USER_AGENT,
        connect_timeout=args.timeout or config.CONNECT_TIMEOUT,
        resolver_servers=args.resolver, use_cache=not args.no_cache,
        verbose=args.verbose, quiet=args.quiet, full_dns=args.full_dns,
        dkim_selectors=list(args.dkim_selector), dkim_guess=args.dkim_guess,
        resolve_subdomains=args.resolve_subdomains,
        ports=args.ports if getattr(args, "ports", None) is not None else None,
        nmap=args.nmap, overwrite=args.overwrite)
    cache = None
    if settings.use_cache:
        from modules.cache import JsonCache
        cache = JsonCache(config.CACHE_FILE, config.CACHE_TTL_SHORT)

    selected = select_modules(args)
    started = time.perf_counter()
    if args.quiet:
        rep.quiet = True
    rep.banner([
        ("Input", args.target),
        ("Normalised", target.display_url),
        ("Modules", ", ".join(m for m in MODULE_ORDER if m in selected)),
        ("Started", time.strftime("%Y-%m-%d %H:%M:%S %Z")),
    ])
    if not args.quiet:
        terminal.render_target(rep, target)

    from modules import (certificate_transparency, connectivity, dns_info,
                         dnssec, email_security, http_info, ip_info,
                         page_metadata, ports, registration, security_checks,
                         subdomains, technologies, tls_info, urls)

    results: dict[str, ModuleResult] = {}
    data: dict[str, dict] = {}

    def run(name: str, fn):
        if args.verbose and not args.quiet:
            rep.note(f"→ running module {name}")
        res = run_module(name, fn, verbose=args.verbose)
        results[name] = res
        data[name] = res.data
        return res

    if "dns" in selected:
        if target.is_ip_literal:
            res = ModuleResult(module="dns", status="skipped",
                               data={"note": "Target is an IP literal — no DNS name to query.",
                                     "name_queried": target.hostname})
            results["dns"] = data["dns"] = res
        else:
            run("dns", lambda: dns_info.collect_dns(target.idna_hostname,
                                                    settings.resolver_servers or None))
        if not args.quiet:
            terminal.render_dns(rep, results["dns"], full_dns=settings.full_dns)

    if "ip" in selected:
        if target.is_ip_literal:
            ips = [target.hostname]
        elif "dns" in data and data["dns"].get("results"):
            ips = dns_info.extract_ips(data["dns"])
        else:
            ips = ip_info.host_ips(target.idna_hostname)
        resolver_servers = (data.get("dns") or {}).get("resolver_used") \
            or settings.resolver_servers or config.DNS_FALLBACK_RESOLVERS
        run("ip", lambda: ip_info.collect_ip_intel(ips, resolver_servers, cache=cache))
        if not args.quiet:
            terminal.render_ip(rep, results["ip"])

    if "connectivity" in selected:
        run("connectivity", lambda: connectivity.measure_connectivity(target))

    if "http" in selected:
        run("http", lambda: http_info.inspect_http(target, settings))
        if not args.quiet:
            terminal.render_http(rep, results["http"])

    if "tls" in selected:
        run("tls", lambda: tls_info.inspect_tls(target))
        if not args.quiet:
            terminal.render_tls(rep, results["tls"])

    if "metadata" in selected:
        base_url = ((data.get("http") or {}).get("final") or {}).get("url", target.normalized_url)
        run("metadata", lambda: page_metadata.extract_metadata(
            (data.get("http") or {}).get("html_excerpt"), base_url))
        if not args.quiet:
            terminal.render_metadata(rep, results["metadata"])

    if "urls" in selected:
        run("urls", lambda: urls.inspect_urls(target, settings,
                                              metadata_result=data.get("metadata")))
        if not args.quiet:
            terminal.render_urls(rep, results["urls"])

    if "technologies" in selected:
        run("technologies", lambda: technologies.detect_technologies(
            headers=((data.get("http") or {}).get("final") or {}).get("headers"),
            html=(data.get("http") or {}).get("html_excerpt"),
            cookies=(data.get("http") or {}).get("cookies")))
        if not args.quiet:
            terminal.render_technologies(rep, results["technologies"])

    if "security" in selected:
        run("security", lambda: security_checks.run_security_checks(
            http_result=data.get("http"), tls_result=data.get("tls"),
            metadata_result=data.get("metadata")))
        if not args.quiet:
            terminal.render_security(rep, results["security"])

    if "connectivity" in selected and not args.quiet:
        terminal.render_connectivity(rep, results["connectivity"],
                                     http_result=results.get("http"))

    if "email_security" in selected:
        run("email_security", lambda: email_security.analyze_email_security(
            target.registered_domain, settings))
        if not args.quiet:
            terminal.render_email_security(rep, results["email_security"])

    if "dnssec" in selected:
        run("dnssec", lambda: dnssec.analyze_dnssec(
            target.idna_hostname if not target.is_ip_literal else None, settings))
        if not args.quiet:
            terminal.render_dnssec(rep, results["dnssec"])

    if "certificate_transparency" in selected:
        run("certificate_transparency", lambda: certificate_transparency.inspect_ct(
            target.registered_domain, settings, cache))
        if not args.quiet:
            terminal.render_ct(rep, results["certificate_transparency"])

    if "subdomains" in selected:
        run("subdomains", lambda: subdomains.discover_subdomains(
            target, settings, cache, ct_result=data.get("certificate_transparency"),
            tls_result=data.get("tls")))
        if not args.quiet:
            terminal.render_subdomains(rep, results["subdomains"])

    if "ports" in selected:
        run("ports", lambda: ports.run_port_checks(target, settings))
        if not args.quiet:
            terminal.render_ports(rep, results["ports"])

    if "registration" in selected:
        run("registration", lambda: registration.lookup_registration(
            target.registered_domain, settings, cache))
        if not args.quiet:
            terminal.render_registration(rep, results["registration"])

    # Strip heavy excerpt before reporting (it already served dependent modules).
    if "http" in results:
        results["http"].data.pop("html_excerpt", None)

    if cache:
        cache.save()

    duration_ms = int((time.perf_counter() - started) * 1000)
    failed = [name for name, res in results.items() if res.status == "error"]
    required_failed = [n for n in failed if n in REQUIRED_MODULES]

    if args.quiet:
        terminal.render_compact(rep, list(results.values()))
    else:
        rep.section("Scan Complete")
    rep.kv([("Duration", f"{duration_ms} ms"),
            ("Module errors", ", ".join(failed) if failed else "none")])

    report = None
    if args.json is not None or args.html:
        notes = []
        if required_failed:
            notes.append(f"REQUIRED MODULES FAILED: {', '.join(required_failed)} — "
                         "do not treat this report as a complete scan.")
        if "http" in results:
            notes.append("The raw HTML excerpt was removed from the report for size.")
        report = json_report.build_report(
            tool_version=config.VERSION, original_input=target.original_input,
            target_dict=target.to_dict(), results=results, duration_ms=duration_ms,
            notes=notes)
    if args.json is not None:
        try:
            path = json_report.write_report(report, args.json or None,
                                            target.idna_hostname, overwrite=settings.overwrite)
            rep.note(f"JSON report written to {path}")
        except FileExistsError as exc:
            rep.error(str(exc))
    if args.html:
        try:
            path = html_report.write_html(report, args.html, overwrite=settings.overwrite)
            rep.note(f"HTML report written to {path}")
        except FileExistsError as exc:
            rep.error(str(exc))
    return 1 if failed else 0


def run_diff(args, rep) -> int:
    try:
        old = json_report.load_report(args.old)
        new = json_report.load_report(args.new)
    except Exception as exc:
        rep.error(f"Could not load reports to compare: {exc}")
        return 2
    for line in output_diff.compare_reports(old, new):
        print(line)
    return 0


def main(argv=None) -> int:
    mode, args = parse_cli(argv)
    rep = terminal.get_reporter(color=not getattr(args, "no_color", False),
                                quiet=getattr(args, "quiet", False))
    if mode == "diff":
        return run_diff(args, rep)
    if args.version:
        print(f"SiteIntel {config.VERSION}")
        return 0
    if not args.target:
        build_scan_parser().print_help()
        return 2
    try:
        return run_scan(args, rep)
    except KeyboardInterrupt:
        rep.warn("Interrupted — partial results were printed above.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
