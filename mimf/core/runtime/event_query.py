from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, TypeVar

from .events import RuntimeEvent

T = TypeVar("T", bound=RuntimeEvent)


@dataclass(frozen=True)
class EventQuery:
    """
    Read-only query utilities for RuntimeEvent sequences.

    Security invariants
    - No mutation of events or contexts
    - Deterministic results
    """

    @staticmethod
    def by_type(events: Iterable[RuntimeEvent], event_type: Type[T]) -> Tuple[T, ...]:
        if not isinstance(event_type, type) or not issubclass(event_type, RuntimeEvent):
            raise TypeError("event_type must be a RuntimeEvent subclass")

        out: List[T] = []
        for e in events:
            if isinstance(e, event_type):
                out.append(e)
        return tuple(out)

    @staticmethod
    def by_plan_id(events: Iterable[RuntimeEvent], plan_id: str) -> Tuple[RuntimeEvent, ...]:
        if not isinstance(plan_id, str) or not plan_id:
            raise ValueError("plan_id must be a non-empty string")

        out: List[RuntimeEvent] = []
        for e in events:
            if getattr(e, "plan_id", None) == plan_id:
                out.append(e)
        return tuple(out)

    @staticmethod
    def time_range(
        events: Iterable[RuntimeEvent],
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> Tuple[RuntimeEvent, ...]:
        if start is not None and not isinstance(start, datetime):
            raise TypeError("start must be datetime or None")
        if end is not None and not isinstance(end, datetime):
            raise TypeError("end must be datetime or None")
        if start is not None and end is not None and start > end:
            raise ValueError("start must be <= end")

        out: List[RuntimeEvent] = []
        for e in events:
            ts = e.created_at
            if start is not None and ts < start:
                continue
            if end is not None and ts > end:
                continue
            out.append(e)
        return tuple(out)

    @staticmethod
    def summarize(events: Iterable[RuntimeEvent]) -> Dict[str, Any]:
        total = 0
        by_type: Dict[str, int] = {}

        first_ts: Optional[datetime] = None
        last_ts: Optional[datetime] = None

        for e in events:
            total += 1
            name = e.__class__.__name__
            by_type[name] = by_type.get(name, 0) + 1

            if first_ts is None or e.created_at < first_ts:
                first_ts = e.created_at
            if last_ts is None or e.created_at > last_ts:
                last_ts = e.created_at

        return {
            "total": total,
            "by_type": by_type,
            "first_created_at": first_ts,
            "last_created_at": last_ts,
        }
