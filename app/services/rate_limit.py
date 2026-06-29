"""A small per-identity request rate limiter — a backstop against a runaway agent loop hammering the SMS.

Fixed 60-second window per identity (an API key id, or a constant for the legacy shared tokens). In-process
and lock-guarded; with the single-worker deployment that's exact, and if ever scaled to N workers each worker
enforces the cap independently (effective limit ~N×, still a backstop). The limit is read per call from the
``agent_rate_limit_per_min`` setting — 0 (default) means unlimited, so the limiter is a no-op until an admin
opts in, and a change takes effect immediately with no redeploy.

``allow(identity)`` is the whole API: True to proceed, False to refuse with 429. It never raises — a limiter
fault must not break or block the request path (it fails OPEN).
"""
from __future__ import annotations

import threading
import time

from . import app_settings

_WINDOW = 60.0
_lock = threading.Lock()
_counts: dict[str, tuple[float, int]] = {}   # identity -> (window_start_monotonic, count_in_window)


def _limit() -> int:
    try:
        return max(0, int(app_settings.get("agent_rate_limit_per_min") or 0))
    except Exception:  # noqa: BLE001
        return 0


def allow(identity: str) -> bool:
    """Record one request for ``identity`` and return whether it is within the per-minute cap. Unlimited
    (cap 0) short-circuits to True without touching the counter."""
    limit = _limit()
    if limit <= 0:
        return True
    ident = identity or "anon"
    now = time.monotonic()
    try:
        with _lock:
            start, count = _counts.get(ident, (now, 0))
            if now - start >= _WINDOW:
                start, count = now, 0          # window elapsed -> reset
            count += 1
            _counts[ident] = (start, count)
            return count <= limit
    except Exception:  # noqa: BLE001 — never block the request on a limiter fault
        return True


def reset() -> None:
    """Clear all counters (tests)."""
    with _lock:
        _counts.clear()
