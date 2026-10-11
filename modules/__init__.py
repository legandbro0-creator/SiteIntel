"""SiteIntel analysis modules.

Each module is intentionally small, typed, and returns plain dictionaries so
that results can be merged into the JSON report without any conversion glue.
Every module returns at least::

    {"status": "ok" | "partial" | "error" | "skipped", ...}

and never raises for *expected* failure modes (timeouts, NXDOMAIN, bad certs).
"""


class ModuleError(Exception):
    """An expected, user-explainable module failure (not a crash)."""
