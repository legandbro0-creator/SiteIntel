"""Shared exception types.  Modules raise these for EXPECTED failure modes;
the runner converts them into structured module results — never crashes."""
from __future__ import annotations


class ModuleError(Exception):
    """An expected, user-explainable module failure (timeout, refused, ...)."""


class TargetError(ValueError):
    """The user input cannot become a safe, unambiguous target."""


class SSRFBlocked(Exception):
    """A redirect/probe destination failed SSRF validation."""

    def __init__(self, url: str, reason: str):
        self.url, self.reason = url, reason
        super().__init__(f"Blocked destination {url!r}: {reason}")


class DependencyMissing(ModuleError):
    """An optional external tool/dependency (e.g. nmap) is not installed."""
