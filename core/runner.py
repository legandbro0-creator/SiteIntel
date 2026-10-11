"""Module execution boundary.

Runs one module function, times it, and converts ANY outcome — normal dict,
ModuleResult, expected ModuleError, or an unexpected bug — into a
ModuleResult.  One module failing can never kill the others; failures land
in the report where they belong.
"""
from __future__ import annotations

import time
import traceback

from core.errors import ModuleError
from core.models import ERROR, ModuleResult


def run_module(module: str, fn, verbose: bool = False) -> ModuleResult:
    started = time.perf_counter()
    try:
        payload = fn()
        result = ModuleResult.wrap(module, payload)
    except ModuleError as exc:
        result = ModuleResult(module=module, status=ERROR, errors=[str(exc)])
    except Exception as exc:  # noqa: BLE001 — isolation boundary by design
        detail = f"{type(exc).__name__}: {exc}"
        if verbose:
            detail += "\n" + traceback.format_exc()
        result = ModuleResult(module=module, status=ERROR, errors=[detail])
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result
