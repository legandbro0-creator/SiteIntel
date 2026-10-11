"""CLI parsing: command preservation, module selection, diff subcommand."""
from __future__ import annotations

from main import parse_cli, select_modules, DEFAULT_MODULES, FLAG_TO_MODULE


def scan_args(argv):
    mode, args = parse_cli(argv)
    assert mode == "scan"
    return args


def test_bare_target_still_works():
    args = scan_args(["google.com"])
    assert args.target == "google.com"
    assert select_modules(args) == DEFAULT_MODULES


def test_module_flags_select_only_chosen_plus_deps():
    args = scan_args(["example.com", "--tls", "--dns"])
    assert select_modules(args) == {"tls", "dns"}
    args2 = scan_args(["example.com", "--security"])
    assert {"http", "tls", "metadata", "security"} <= select_modules(args2)


def test_full_never_enables_ports():
    args = scan_args(["example.com", "--full"])
    selected = select_modules(args)
    assert "ports" not in selected
    assert {"registration", "email_security", "dnssec", "certificate_transparency"} <= selected


def test_ports_is_opt_in_with_default_profile():
    args = scan_args(["example.com", "--ports"])
    assert args.ports == "web" and select_modules(args) == {"ports"}
    args2 = scan_args(["example.com", "--ports", "22,80"])
    assert args2.ports == "22,80"


def test_diff_subcommand():
    mode, args = parse_cli(["diff", "old.json", "new.json"])
    assert mode == "diff" and args.old == "old.json" and args.new == "new.json"


def test_output_and_safety_flags():
    args = scan_args(["example.com", "--json", "r.json", "--html", "r.html",
                      "--full-dns", "--quiet", "--resolver", "9.9.9.9",
                      "--dkim-selector", "google", "--dkim-guess", "--overwrite"])
    assert args.json == "r.json" and args.html == "r.html"
    assert args.full_dns and args.quiet and args.overwrite
    assert args.resolver == ["9.9.9.9"] and args.dkim_selector == ["google"] and args.dkim_guess
