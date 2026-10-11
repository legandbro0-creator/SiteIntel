"""Central configuration for SiteIntel v2.

Every timeout, byte limit and behavioural knob lives here so the rest of the
codebase never hides a magic number.  Everything can be overridden with
environment variables — handy on Termux where editing mid-session is awkward.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

VERSION = "2.0.0"

# --- Identity -------------------------------------------------------------
USER_AGENT = os.environ.get(
    "SITEINTEL_USER_AGENT",
    f"SiteIntel/{VERSION} (+educational recon tool; contact: owner-configured)",
)

# --- Network behaviour ----------------------------------------------------
CONNECT_TIMEOUT = float(os.environ.get("SITEINTEL_CONNECT_TIMEOUT", "8.0"))
READ_TIMEOUT = float(os.environ.get("SITEINTEL_READ_TIMEOUT", "12.0"))
DNS_TIMEOUT = float(os.environ.get("SITEINTEL_DNS_TIMEOUT", "4.0"))
DNS_LIFETIME = float(os.environ.get("SITEINTEL_DNS_LIFETIME", "6.0"))
MAX_REDIRECTS = int(os.environ.get("SITEINTEL_MAX_REDIRECTS", "8"))
PROBE_MAX_REDIRECTS = 3

# On 2 GB RAM you never download unbounded responses.
MAX_BODY_BYTES = int(os.environ.get("SITEINTEL_MAX_BODY_BYTES", str(512 * 1024)))
MAX_HTML_EXCERPT = int(os.environ.get("SITEINTEL_MAX_HTML_EXCERPT", str(192 * 1024)))
MAX_LIST_ITEMS = 50
MAX_IP_LOOKUPS = int(os.environ.get("SITEINTEL_MAX_IP_LOOKUPS", "6"))
MAX_WORKERS = 3

# Small auxiliary fetches (robots/sitemap/favicon/MTA-STS policy)
AUX_MAX_BYTES = int(os.environ.get("SITEINTEL_AUX_MAX_BYTES", str(64 * 1024)))

# Android/Termux often has no /etc/resolv.conf; announce the fallback loudly.
DNS_FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# --- Caching --------------------------------------------------------------
CACHE_TTL_SHORT = int(os.environ.get("SITEINTEL_CACHE_TTL", str(24 * 3600)))
CACHE_TTL_CT = int(os.environ.get("SITEINTEL_CACHE_TTL_CT", str(7 * 24 * 3600)))
CACHE_FILE = os.environ.get(
    "SITEINTEL_CACHE_FILE",
    os.path.expanduser(os.path.join("~", ".cache", "siteintel", "cache.json")),
)

# --- Email security -------------------------------------------------------
DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "k1", "dkim"]

# --- Subdomains -----------------------------------------------------------
SUBDOMAIN_RESOLVE_LIMIT = int(os.environ.get("SITEINTEL_SUBDOMAIN_RESOLVE_LIMIT", "20"))
CRT_SH_ENDPOINT = "https://crt.sh/"

# --- Ports (OPT-IN active checks) -----------------------------------------
PORT_CONNECT_TIMEOUT = float(os.environ.get("SITEINTEL_PORT_TIMEOUT", "2.0"))
PORT_MAX_WORKERS = 4
PORT_PROFILES = {
    "web": [80, 443, 8080, 8443],
    "common": [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995, 8080, 8443],
}
PORT_HARD_LIMIT = 64  # absolute cap on ports per scan, whatever the user asks

# Headers excluded from diff noise (fresh every request, or CDN-internal).
VOLATILE_HEADERS = {
    "date", "age", "expires", "cf-ray", "x-request-id", "x-amz-cf-id",
    "x-amz-cf-pop", "x-cache", "report-to", "nel", "server-timing",
    "set-cookie",  # values are redacted anyway; per-request tokens change
}

# Query-parameter names whose VALUES are redacted in displays and reports.
SENSITIVE_QUERY_PARAMS = {
    "token", "access_token", "id_token", "refresh_token", "auth", "key",
    "apikey", "api_key", "secret", "password", "passwd", "pwd", "session",
    "sessionid", "sid", "jwt", "signature", "sig", "code", "credential",
}
REDACTED = "<redacted>"


@dataclass
class ScanSettings:
    """Runtime options resolved from CLI flags and handed to every module."""
    user_agent: str = USER_AGENT
    connect_timeout: float = CONNECT_TIMEOUT
    read_timeout: float = READ_TIMEOUT
    max_redirects: int = MAX_REDIRECTS
    max_body: int = MAX_BODY_BYTES
    resolver_servers: list[str] = field(default_factory=list)
    use_cache: bool = True
    verbose: bool = False
    quiet: bool = False
    full_dns: bool = False
    # opt-in extras
    dkim_selectors: list[str] = field(default_factory=list)
    dkim_guess: bool = False
    resolve_subdomains: bool = False
    ports: str | None = None          # None = disabled (active checks are opt-in)
    nmap: bool = False
    overwrite: bool = False
