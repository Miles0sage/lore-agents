"""phalanx.otel — OpenTelemetry export for @watch events and audit log.

Zero-import when opentelemetry is not installed (graceful degradation).
Enable with: pip install phalanx-agents[otel]
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Graceful degradation — all OTEL imports are optional
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False

try:
    from opentelemetry import trace as _trace
    from opentelemetry import metrics as _metrics
    from opentelemetry.trace import Tracer, NonRecordingSpan, SpanKind
    _OTEL_AVAILABLE = True
except ImportError:
    _trace = None  # type: ignore[assignment]
    _metrics = None  # type: ignore[assignment]
    Tracer = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Noop tracer fallback
# ---------------------------------------------------------------------------


class _NoopSpan:
    """Minimal span that implements context manager protocol."""

    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass


class _NoopTracer:
    """Returned when opentelemetry-api is not installed."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> "_NoopSpan":  # type: ignore[override]
        return _NoopSpan()

    def start_span(self, name: str, **kwargs: Any) -> "_NoopSpan":
        return _NoopSpan()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_tracer(name: str = "phalanx") -> Any:
    """Return an OpenTelemetry Tracer, or a NoopTracer if OTEL is unavailable."""
    if _OTEL_AVAILABLE and _trace is not None:
        return _trace.get_tracer(name)
    return _NoopTracer()


def record_watch_event(event: dict) -> None:
    """Emit an OTEL span for a @watch capture event.

    Span name: ``phalanx.watch.{event_type}`` where event_type is one of
    ``failure``, ``block``, or ``injection``.

    Attributes set (when present in *event*):
    - ``agent_id``
    - ``action``
    - ``error_type``  (for failure events)
    - ``confidence``  (for injection events)
    """
    if not _OTEL_AVAILABLE or _trace is None:
        return

    event_type = event.get("type", event.get("event_type", "failure"))
    span_name = f"phalanx.watch.{event_type}"
    tracer = get_tracer()

    with tracer.start_as_current_span(span_name) as span:
        for attr in ("agent_id", "action", "error_type"):
            val = event.get(attr)
            if val is not None:
                span.set_attribute(f"phalanx.{attr}", str(val))
        confidence = event.get("confidence")
        if confidence is not None:
            span.set_attribute("phalanx.confidence", float(confidence))


def record_policy_decision(result: Any) -> None:
    """Emit an OTEL span for a governance policy decision.

    Reads ``verdict``, ``agent_id``, ``action``, ``reason``, and ``rule``
    from the PolicyResult (or any object with those attributes).
    """
    if not _OTEL_AVAILABLE or _trace is None:
        return

    tracer = get_tracer()
    with tracer.start_as_current_span("phalanx.policy.decision") as span:
        for attr in ("verdict", "agent_id", "action", "reason", "rule"):
            val = getattr(result, attr, None)
            if val is not None:
                span.set_attribute(f"phalanx.{attr}", str(val))


def watch_otel_hook(failures_dir: Path) -> Callable[[], None]:
    """Return a callable that scans *failures_dir* for new JSON files and emits OTEL events.

    The returned callback is designed to be called periodically (e.g. every
    few seconds by a background thread or scheduler).  It maintains state via
    a set of already-processed filenames stored in a closure.

    Example::

        hook = watch_otel_hook(Path(".phalanx/failures"))
        # call periodically:
        hook()
    """
    _seen: set[str] = set()

    def _poll() -> None:
        failures_dir.mkdir(parents=True, exist_ok=True)
        for json_file in sorted(failures_dir.glob("*.json")):
            if json_file.name in _seen:
                continue
            _seen.add(json_file.name)
            try:
                event = json.loads(json_file.read_text())
            except Exception:
                continue
            record_watch_event(event)

    return _poll


def meter_fleet_stats(stats: dict) -> None:
    """Record fleet gauge metrics via OTEL Metrics.

    Expected keys in *stats*:
    - ``active_agents``   (int)
    - ``total_failures``  (int)
    - ``rules_count``     (int)
    - ``blocked_count``   (int)

    Missing keys are silently skipped.
    """
    if not _OTEL_AVAILABLE or _metrics is None:
        return

    meter = _metrics.get_meter("phalanx")

    _gauge_map = {
        "active_agents": "phalanx.fleet.active_agents",
        "total_failures": "phalanx.fleet.total_failures",
        "rules_count": "phalanx.fleet.rules_count",
        "blocked_count": "phalanx.fleet.blocked_count",
    }

    for key, metric_name in _gauge_map.items():
        value = stats.get(key)
        if value is None:
            continue
        gauge = meter.create_gauge(
            metric_name,
            description=f"Phalanx fleet stat: {key}",
        )
        gauge.set(int(value))
