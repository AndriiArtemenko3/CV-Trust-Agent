"""Sanitized telemetry sinks for decision traces.

Trace events intentionally use an allow-list of scalar attributes.  Source
records, notes, PDF text, mapper prompts, and model prose have no serialization
path through this module.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from cv_trust_agent.models import SafeTraceScalar, TraceEvent

ALLOWED_TRACE_ATTRIBUTES = frozenset(
    {
        "batch_state",
        "candidate_count",
        "excluded_count",
        "mapper_name",
        "plan_version",
        "previous_plan_version",
        "quarantined_count",
        "ranked_count",
        "ranking_scope",
        "route_count",
        "strategy",
        "usable_count",
    }
)


class TelemetrySink(Protocol):
    def emit(self, event: TraceEvent) -> None:
        """Persist or export one already-sanitized trace event."""


def sanitized_attributes(
    values: Mapping[str, SafeTraceScalar] | None = None,
    /,
    **extra: SafeTraceScalar,
) -> dict[str, SafeTraceScalar]:
    """Return allow-listed trace attributes or fail closed.

    Failing on unknown keys makes accidental logging of ``note``, ``text``,
    ``prompt``, or similar payloads visible during development rather than
    silently redacting evidence needed to diagnose a leak.
    """

    merged = dict(values or {})
    merged.update(extra)
    unknown = set(merged).difference(ALLOWED_TRACE_ATTRIBUTES)
    if unknown:
        unknown_list = ", ".join(sorted(unknown))
        raise ValueError(f"trace attributes are not allow-listed: {unknown_list}")
    return merged


class NullTelemetrySink:
    def emit(self, event: TraceEvent) -> None:
        del event


class MemoryTelemetrySink:
    """In-memory sink for tests and local inspection."""

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def emit(self, event: TraceEvent) -> None:
        self.events.append(event)


class JsonlTelemetrySink:
    """Append sanitized events to a JSONL file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: TraceEvent) -> None:
        line = event.model_dump_json(exclude_none=True) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(line)
