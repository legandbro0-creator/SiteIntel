"""Port checks: spec parsing, open/closed against the local fixture."""
from __future__ import annotations

import pytest

from core.errors import ModuleError
from core.models import INFO
from modules.ports import check_tcp, parse_port_spec, run_port_checks
from modules.target import normalize_target


def test_parse_profiles_and_csv():
    ports, how = parse_port_spec(None)
    assert ports == [80, 443, 8080, 8443] and how == "profile:web"
    ports, how = parse_port_spec("common")
    assert 22 in ports and "common" in how
    ports, how = parse_port_spec("22,80,443,443")
    assert ports == [22, 80, 443]


@pytest.mark.parametrize("bad", ["0", "65536", "abc", "22,xyz", ""])
def test_parse_rejects_bad_specs(bad):
    if bad == "":
        ports, _ = parse_port_spec(bad)  # empty → default profile
        assert ports == [80, 443, 8080, 8443]
        return
    with pytest.raises(ModuleError):
        parse_port_spec(bad)


def test_hard_limit_enforced():
    with pytest.raises(ModuleError):
        parse_port_spec(",".join(str(i) for i in range(1, 200)))


def test_check_tcp_open_and_closed(fixture_server):
    host, port = fixture_server.split(":")
    open_row = check_tcp(host, int(port))
    assert open_row["status"] == "open"
    closed_row = check_tcp(host, 1)  # tcp/1 is effectively never listening locally
    assert closed_row["status"] in ("closed", "filtered")


def test_run_port_checks_bounded(fixture_server):
    import config
    host, port = fixture_server.split(":")
    settings = config.ScanSettings(ports=str(port), quiet=True)
    target = normalize_target(f"http://{host}:{port}/")
    result = run_port_checks(target, settings)
    assert result["summary"]["open"] == 1
    assert result["results"][0]["port"] == int(port)
    summary_finding = next(f for f in result["findings"] if f["name"] == "tcp_connect_scan")
    assert summary_finding["status"] == INFO
    assert any("AUTHORIZED" in lim.upper() or "authorized" in lim for lim in result["limitations"])
