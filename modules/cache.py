"""A tiny JSON cache with per-entry TTL (spec §19).

Used for slow, third-party lookups: RDAP (24 h), CT logs (7 d), ASN (24 h).
Rules honored here:
* transient failures are NEVER cached (callers only cache successful data);
* `--no-cache` bypasses reads and writes entirely (handled by callers);
* a broken/unreadable cache silently degrades to "cache miss" — the cache
  can never be the reason a scan fails;
* HTTP results are deliberately NOT cached: freshness of a live response is
  a feature, and duplicates within one scan are already eliminated by design.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class JsonCache:
    def __init__(self, path: str | Path, default_ttl: int):
        self.path = Path(path)
        self.default_ttl = default_ttl
        self._store: dict = {}
        self._dirty = False
        try:
            if self.path.is_file():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._store = data if isinstance(data, dict) else {}
        except Exception:
            self._store = {}

    def get(self, key: str):
        entry = self._store.get(key)
        if not isinstance(entry, dict):
            return None
        ttl = entry.get("_ttl", self.default_ttl)
        if time.time() - entry.get("_ts", 0) > ttl:
            return None
        return entry.get("_value")

    def set(self, key: str, value, ttl: int | None = None) -> None:
        self._store[key] = {"_ts": int(time.time()),
                            "_ttl": ttl or self.default_ttl, "_value": value}
        self._dirty = True

    def invalidate(self, key: str) -> None:
        if key in self._store:
            del self._store[key]
            self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._store), encoding="utf-8")
            tmp.replace(self.path)
        except Exception:
            pass  # convenience only, never a failure reason
