"""Module E — TLS certificate inspector.

TLS does three jobs: encryption, server authentication (the certificate), and
integrity.  This module examines the *authentication* part:

  1. First we do a REAL, fully-verified handshake (exactly like a browser).
  2. Only if verification fails do we reconnect WITHOUT verification purely to
     fetch the certificate so we can show you *why* it failed.  This never
     changes what the HTTP module trusts — verification is never globally
     disabled.

Failure taxonomy (each means something different!):
  expired            — cert's notAfter is in the past.
  self_signed        — cert signed by itself; no trust anchor.
  hostname_mismatch  — cert is for a different name.
  chain_failure      — missing intermediates / unknown issuer.
  unrelated_failure  — TCP/timeout/etc.; says nothing about the cert.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import config
from .target import TargetInfo


def _flatten_name(name_tuple) -> str:
    try:
        return "; ".join(f"{k}={v}" for group in name_tuple for k, v in group)
    except (TypeError, ValueError):
        return str(name_tuple)


def _parse_cert_time(value: str) -> datetime | None:
    # e.g. 'Oct  5 11:12:13 2026 GMT' (note double space before single-digit day)
    try:
        cleaned = " ".join(value.split())
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _display_from_peercert(cert: dict) -> dict:
    not_before = _parse_cert_time(cert.get("notBefore", ""))
    not_after = _parse_cert_time(cert.get("notAfter", ""))
    return {
        "subject": _flatten_name(cert.get("subject", ())),
        "issuer": _flatten_name(cert.get("issuer", ())),
        "serial_number": cert.get("serialNumber"),
        "not_before": not_before.isoformat() if not_before else cert.get("notBefore"),
        "not_after": not_after.isoformat() if not_after else cert.get("notAfter"),
        "days_until_expiry": (not_after - datetime.now(timezone.utc)).days if not_after else None,
        "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
    }


def _decode_der(der: bytes) -> dict | None:
    """Parse a DER certificate without verification.  Prefers `cryptography`
    (optional dep); falls back to ssl._ssl._test_decode_cert (private but
    universal on CPython, including Termux)."""
    try:
        from cryptography import x509  # type: ignore
        cert = x509.load_der_x509_certificate(der)
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            pass
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "X"),
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "days_until_expiry": (na - datetime.now(timezone.utc)).days,
            "subject_alt_names": sans,
        }
    except ImportError:
        pass
    except Exception:
        return None
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pem") as tmp:
            tmp.write(ssl.DER_cert_to_PEM_cert(der).encode())
            tmp.flush()
            return _display_from_peercert(ssl._ssl._test_decode_cert(tmp.name))  # noqa: SLF001
    except Exception:
        return None


def _cipher_dict(cipher_tuple) -> dict | None:
    if not cipher_tuple:
        return None
    return {"name": cipher_tuple[0], "protocol": cipher_tuple[1], "bits": cipher_tuple[2]}


def _classify_verification_error(exc: ssl.SSLCertVerificationError) -> tuple[str, str]:
    code = getattr(exc, "verify_code", None)
    message = getattr(exc, "verify_message", "") or str(exc)
    if code == 10 or "certificate has expired" in message.lower():
        return "expired", f"Certificate expired: {message}"
    if "hostname" in message.lower() or "doesn't match" in message.lower() or code == 62:
        return "hostname_mismatch", f"Certificate is not valid for this hostname: {message}"
    if code in (18, 19) or "self-signed" in message.lower():
        return "self_signed", f"Self-signed certificate (no trusted authority): {message}"
    if code in (20, 21) or "unable to get local issuer" in message.lower():
        return "chain_failure", f"Certificate chain could not be validated: {message}"
    return "chain_failure", f"Certificate verification failed: {message}"


def _fetch_unverified(host: str, port: int) -> dict:
    """Second handshake WITHOUT verification — display-only evidence of WHY
    verification failed.  Never used to trust the server for content."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=config.CONNECT_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return {
                "tls_version": ssock.version(),
                "cipher": _cipher_dict(ssock.cipher()),
                "cert": _decode_der(der) if der else None,
            }


def inspect_tls(target: TargetInfo) -> dict:
    if target.scheme != "https":
        return {"status": "skipped",
                "note": "Target uses plain http:// — there is no TLS session to inspect.",
                "limitations": []}

    host, port = target.idna_hostname, target.effective_port
    base = {"host": host, "port": port,
            "limitations": [
                "A valid, unexpired certificate does NOT prove the site is safe — only who operates it.",
                "CDN edge certificates often list many unrelated SANs; that is normal.",
            ]}

    ctx = ssl.create_default_context()  # full verification, like a browser
    try:
        with socket.create_connection((host, port), timeout=config.CONNECT_TIMEOUT) as sock:
            sock.settimeout(config.CONNECT_TIMEOUT)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return dict(base, status="ok", verified=True,
                            tls_version=ssock.version(),
                            cipher=_cipher_dict(ssock.cipher()),
                            cert=_display_from_peercert(cert),
                            hostname_match="matched")
    except ssl.SSLCertVerificationError as exc:
        kind, message = _classify_verification_error(exc)
        evidence = {}
        try:
            evidence = _fetch_unverified(host, port)
        except Exception as fetch_exc:
            evidence = {"error": f"Could not re-fetch certificate for display: {fetch_exc}"}
        return dict(base, status="error", verified=False,
                    failure_kind=kind, error=message,
                    hostname_match="mismatch" if kind == "hostname_mismatch" else "not_evaluated",
                    tls_version=evidence.get("tls_version"),
                    cipher=evidence.get("cipher"), cert=evidence.get("cert"))
    except ssl.SSLError as exc:
        return dict(base, status="error", verified=False, failure_kind="tls_handshake_error",
                    error=f"TLS handshake failed for a non-certificate reason: {exc}",
                    cert=None, hostname_match="not_evaluated")
    except (socket.timeout, TimeoutError):
        return dict(base, status="error", verified=False, failure_kind="timeout",
                    error=f"Connection to {host}:{port} timed out — nothing can be said about the certificate.",
                    cert=None, hostname_match="not_evaluated")
    except OSError as exc:
        return dict(base, status="error", verified=False, failure_kind="connection_failed",
                    error=f"Could not connect to {host}:{port}: {exc}",
                    cert=None, hostname_match="not_evaluated")
