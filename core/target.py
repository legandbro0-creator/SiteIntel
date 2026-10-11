"""Target (URL/domain) normalisation, validation and redaction.

Concepts this module enforces:
* scheme://hostname:port/path?query#fragment — and the fragment is never
  sent to a server.
* blog.example.com is a hostname; example.com is the registrable domain.
* IDN names (münchen.de) travel as punycode (xn--mnchen-3ya.de).
* Query parameter VALUES can carry tokens — display/report copies are
  redacted by default (the name list stays visible for analysis).

Invalid input raises TargetError with a human explanation.  We never
silently "fix" invalid input into an unrelated target.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import config
from core.errors import TargetError

__all__ = ["TargetError", "TargetInfo", "normalize_target", "redact_url", "query_param_names"]

# Heuristic-only public-suffix approximation (the full PSL is 200 KB+).
MULTI_PART_SUFFIXES = {
    "ac.in", "ac.jp", "ac.uk", "co.in", "co.jp", "co.nz", "co.uk",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw",
    "edu.au", "gov.in", "gov.uk", "net.au", "net.in", "org.au",
    "org.in", "org.uk", "or.jp", "ne.jp",
}
_HOSTNAME_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_ALLOWED_SCHEMES = ("http", "https")


@dataclass
class TargetInfo:
    original_input: str
    normalized_url: str
    scheme: str
    hostname: str
    idna_hostname: str
    registered_domain: str | None
    subdomain: str | None
    is_ip_literal: bool
    port: int | None
    path: str
    query: str
    fragment: str
    scheme_assumed: bool
    warnings: list[str] = field(default_factory=list)

    @property
    def effective_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)

    @property
    def display_url(self) -> str:
        """normalized_url with sensitive query values redacted (for output/reports)."""
        return redact_url(self.normalized_url)

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.idna_hostname}:{self.effective_port}"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["effective_port"] = self.effective_port
        data["display_url"] = self.display_url
        data["query_param_names"] = query_param_names(self.query)
        return data


def query_param_names(query: str) -> list[str]:
    """Names only — values are never needed for analysis."""
    return [name for name, _ in parse_qsl(query, keep_blank_values=True)]


def redact_url(url: str) -> str:
    """Replace VALUES of sensitive query parameters with <redacted>."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(name, config.REDACTED if name.lower() in config.SENSITIVE_QUERY_PARAMS else value)
                for name, value in pairs]
    return urlunsplit(parts._replace(query=urlencode(redacted, doseq=True)))


def to_idna(hostname: str) -> str:
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError(f"'{hostname}' is not a valid internationalised name: {exc}")


def registered_split(idna_host: str) -> tuple[str, str | None]:
    labels = idna_host.split(".")
    if len(labels) <= 2:
        return idna_host, None
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:]), ".".join(labels[:-3]) or None
    return ".".join(labels[-2:]), ".".join(labels[:-2]) or None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_target(raw: str) -> TargetInfo:
    warnings: list[str] = []
    original = raw
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Empty input. Give a domain like 'example.com' or a URL like 'https://example.com/path'.")

    scheme_assumed = "://" not in raw
    if scheme_assumed:
        raw = "https://" + raw
        warnings.append("No scheme given; assuming https:// (use http://… if you really want plain HTTP).")

    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise TargetError(f"Could not parse '{original}': {exc}")

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetError(f"Unsupported scheme '{parts.scheme}'. Only http:// and https:// are inspected.")

    if parts.username or parts.password:
        warnings.append("User-info (user:pass@host) ignored — never put credentials in scan targets.")

    hostname = parts.hostname
    if not hostname:
        raise TargetError(f"No hostname found in '{original}'.")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"Invalid port in '{original}': {exc}")

    if hostname.endswith("."):
        hostname = hostname.rstrip(".")
        warnings.append("Trailing dot (FQDN root marker) removed for display; lookups are equivalent.")

    is_ip = _is_ip_literal(hostname)
    if is_ip:
        idna_host, registered, subdomain = hostname, None, None
        warnings.append("Target is an IP literal: registrable-domain and RDAP steps will be skipped.")
    else:
        if "_" in hostname:
            warnings.append("Underscores are invalid in DNS hostnames; results may be inconsistent.")
        idna_host = to_idna(hostname)
        bad = [lb for lb in idna_host.split(".") if not _HOSTNAME_LABEL.match(lb)]
        if bad:
            raise TargetError(
                f"'{hostname}' contains invalid hostname label(s): {', '.join(bad)}. "
                "Labels are letters/digits/hyphens, 1–63 chars, not starting/ending with '-'.")
        registered, subdomain = registered_split(idna_host)

    if parts.fragment:
        warnings.append("Fragment (#…) dropped: fragments are never sent to a server.")

    path = parts.path or "/"
    normalized = f"{scheme}://{idna_host}{':' + str(port) if port else ''}{path}"
    if parts.query:
        normalized += "?" + parts.query

    return TargetInfo(
        original_input=original, normalized_url=normalized, scheme=scheme,
        hostname=hostname, idna_hostname=idna_host,
        registered_domain=registered, subdomain=subdomain, is_ip_literal=is_ip,
        port=port, path=path, query=parts.query, fragment=parts.fragment,
        scheme_assumed=scheme_assumed, warnings=warnings)


def safe_join_url(base: str, location: str) -> str:
    """Resolve a possibly-relative Location header against the current hop."""
    from urllib.parse import urljoin
    joined = urljoin(base, unquote(location.strip()) if "%" not in location else location.strip())
    # normalize: lowercase scheme/host, strip empty fragment
    parts = urlsplit(joined)
    path = quote(unquote(parts.path or "/"), safe="/%:@")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))
