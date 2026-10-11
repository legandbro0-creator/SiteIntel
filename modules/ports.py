"""Opt-in port & service checks (spec §12) for AUTHORIZED targets only.

Default OFF.  Activated with --ports [profile-or-list].  Behaviour by charter:
* Only the USER-SPECIFIED target is ever probed — never hosts from redirects
  or passive discovery.
* Plain TCP connect() to a bounded port set (hard cap), polite timeouts,
  concurrency of a few threads — comparable to a few browser connections.
* Service identification: port-number mapping + PASSIVE banner read
  (we send nothing; many daemons greet first).  No probe bytes by default.
* No stealth, no timing tricks, no exploitation.  None.  Ever.
* Optional nmap when installed (--nmap); install on Termux: pkg install nmap
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import config
from core.errors import DependencyMissing, ModuleError
from core.models import INFO, WARN, Finding
from core.target import TargetInfo

_MOD = "ports"

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
}
# Plaintext legacy services worth a gentle note (not an alarm).
_PLAINTEXT_NOTES = {21: "FTP is plaintext — consider SFTP.",
                    23: "Telnet is plaintext — consider SSH.",
                    80: "HTTP is plaintext unless upgraded to HTTPS."}


def _f(name, status, evidence, why, limitations, recommendation, severity=None) -> dict:
    return Finding(name=name, module=_MOD, status=status, severity=severity,
                   evidence=evidence, why=why,
                   limitations=limitations if isinstance(limitations, list) else [limitations],
                   recommendation=recommendation).to_dict()


def parse_port_spec(spec: str | None) -> tuple[list[int], str]:
    """'web' | 'common' profile names or a CSV like '22,80,443'."""
    if not spec or spec == "web":
        return list(config.PORT_PROFILES["web"]), "profile:web"
    if spec == "common":
        return list(config.PORT_PROFILES["common"]), "profile:common"
    ports = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit() or not 1 <= int(chunk) <= 65535:
            raise ModuleError(f"Invalid port {chunk!r} in --ports list (use 1-65535).")
        if int(chunk) not in ports:
            ports.append(int(chunk))
    if not ports:
        raise ModuleError("Empty --ports list.")
    if len(ports) > config.PORT_HARD_LIMIT:
        raise ModuleError(f"Refusing {len(ports)} ports: hard cap is {config.PORT_HARD_LIMIT}.")
    return sorted(ports), "custom list"


def check_tcp(host: str, port: int) -> dict:
    """One connect(); passive banner read if the daemon greets us."""
    result = {"port": port, "status": "filtered", "service": SERVICE_HINTS.get(port, ""), "banner": None}
    try:
        with socket.create_connection((host, port), timeout=config.PORT_CONNECT_TIMEOUT) as sock:
            result["status"] = "open"
            sock.settimeout(1.2)
            try:
                banner = sock.recv(64)  # passive: we send NOTHING
                if banner:
                    text = banner.decode("utf-8", "replace").strip()
                    text = "".join(c if c.isprintable() else "." for c in text)[:64]
                    result["banner"] = text or None
            except (socket.timeout, TimeoutError, OSError):
                pass
    except ConnectionRefusedError:
        result["status"] = "closed"
    except (socket.timeout, TimeoutError):
        result["status"] = "filtered"
    except OSError as exc:
        result["status"] = f"error:{exc.__class__.__name__}"
    return result


def _nmap_scan(host: str, ports: list[int]) -> dict:
    nmap = shutil.which("nmap")
    if not nmap:
        raise DependencyMissing("nmap not found. On Termux:  pkg install nmap")
    cmd = [nmap, "-Pn", "-sV", "--version-light", "--host-timeout", "30s",
           "-p", ",".join(map(str, ports)), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise ModuleError("nmap timed out after 90 s")
    lines = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].endswith("/tcp"):
            lines.append({"port": parts[0], "state": parts[1],
                          "service": " ".join(parts[2:])[:80]})
    return {"command": " ".join(cmd), "results": lines,
            "exit_code": proc.returncode}


def run_port_checks(target: TargetInfo, settings) -> dict:
    ports, how = parse_port_spec(settings.ports)
    findings: list[dict] = []
    notes = [
        "ACTIVE check: TCP connect() on a bounded port list, explicitly enabled via --ports.",
        "Only run against systems you own or are explicitly AUTHORIZED to assess.",
        "Never redirected/discovered hosts — only your stated target.",
    ]
    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=config.PORT_MAX_WORKERS) as pool:
        for row in pool.map(lambda p: check_tcp(target.idna_hostname, p), ports):
            rows.append(row)
    rows.sort(key=lambda r: r["port"])

    opened = [r for r in rows if r["status"] == "open"]
    closed = [r for r in rows if r["status"] == "closed"]
    findings.append(_f(
        "tcp_connect_scan", INFO,
        f"{how}: {len(rows)} ports checked — {len(opened)} open, {len(closed)} closed, "
        f"{len(rows) - len(opened) - len(closed)} filtered/errored.",
        "Open ports are the reachable attack surface of this host from your network.",
        notes + ["'filtered' = timeout; from a mobile network that can also mean blocking."],
        "Every open service should be intentional, patched, and firewalled if private."))
    for row in opened:
        if row["port"] in _PLAINTEXT_NOTES:
            findings.append(_f(
                f"open:{row['port']}", WARN, severity="low",
                evidence=f"Port {row['port']}/tcp open ({row['service'] or 'unknown service'})"
                         + (f": {row['banner']}" if row['banner'] else ""),
                why=_PLAINTEXT_NOTES[row["port"]],
                limitations=["Connect() succeeded once; banners are passive and optional."],
                recommendation="Confirm exposure is intentional and patched."))

    nmap_data = None
    if settings.nmap:
        try:
            nmap_data = _nmap_scan(target.idna_hostname, ports)
        except (DependencyMissing, ModuleError) as exc:
            notes.append(str(exc))
    return {"status": "ok", "host": target.idna_hostname, "ports_checked": ports,
            "how": how, "results": rows, "nmap": nmap_data,
            "summary": {"open": len(opened), "closed": len(closed),
                        "filtered_or_error": len(rows) - len(opened) - len(closed)},
            "findings": findings, "limitations": notes}
