"""Deprecated import shim — the implementation moved to core/target.py.
Kept so existing scripts/imports (SiteIntel v1) keep working."""
from core.target import *  # noqa: F401,F403
from core.target import redact_url, safe_join_url, to_idna  # noqa: F401
