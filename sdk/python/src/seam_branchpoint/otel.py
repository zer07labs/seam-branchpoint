"""OpenTelemetry span events for flag evaluations (extra `otel`). A no-op without `opentelemetry-api`.

`add_evaluation_event(attributes, unit=...)` adds one `feature_flag.evaluation` event to the current span. No active
(recording) span ⇒ no event and no error. Any attribute whose value equals the unit is dropped before the event is
built, so the raw unit never reaches telemetry (spec §3: only the HMAC tag ever leaves the process); callers never
pass `feature_flag.context.id` either. This module never raises.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

EVENT_NAME = "feature_flag.evaluation"
PROVIDER_NAME = "seam-branchpoint"
FORBIDDEN_KEYS = frozenset({"feature_flag.context.id"})

_lock = threading.Lock()
_loaded = False
_trace: Any = None


def _api() -> Any:
    """`opentelemetry.trace`, or None when `opentelemetry-api` is not installed (looked up once)."""
    global _loaded, _trace
    if not _loaded:
        with _lock:
            if not _loaded:
                try:
                    from opentelemetry import trace
                except ImportError:
                    trace = None
                _trace, _loaded = trace, True
    return _trace


def available() -> bool:
    """Whether `opentelemetry-api` is importable."""
    return _api() is not None


def add_evaluation_event(attributes: Mapping[str, str | bool | int | float], *, unit: str | None = None) -> bool:
    """Add one `feature_flag.evaluation` event to the current span. Returns True when an event was added."""
    try:
        trace = _api()
        if trace is None:
            return False
        span = trace.get_current_span()
        if not span.is_recording():
            return False
        attrs = {k: v for k, v in attributes.items()
                 if k not in FORBIDDEN_KEYS and v is not None and not (unit and v == unit)}
        span.add_event(EVENT_NAME, attrs)
        return True
    except Exception:  # noqa: BLE001 - telemetry never changes or breaks an evaluation
        return False
