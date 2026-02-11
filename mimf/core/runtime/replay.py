from __future__ import annotations

from dataclasses import fields
from typing import Iterable, Optional, Any, Dict

from .context import RuntimeContext
from .events import RuntimeEvent


class ReplayEngine:
    """
    Safe replay engine for runtime events.

    Rules
    Do not re-emit existing event objects into the same RuntimeContext.
    Replay creates a new RuntimeContext and reconstructs new event instances.
    Destination RuntimeContext seals and hash-chains the recreated events.
    """

    @staticmethod
    def _clone_event(event: RuntimeEvent) -> RuntimeEvent:
        if not isinstance(event, RuntimeEvent):
            raise TypeError("event must be a RuntimeEvent instance")

        init_kwargs: Dict[str, Any] = {}
        for f in fields(event):
            if f.init:
                init_kwargs[f.name] = getattr(event, f.name)

        cloned = event.__class__(**init_kwargs)

        object.__setattr__(cloned, "event_id", event.event_id)
        object.__setattr__(cloned, "created_at", event.created_at)

        return cloned

    def replay_into_new_context(
        self,
        source_events: Iterable[RuntimeEvent],
        *,
        context_id: str,
        actor_id: Optional[str] = None,
        operation_name: Optional[str] = "ReplayEngine:replay",
    ) -> RuntimeContext:
        ctx = RuntimeContext(
            context_id=context_id,
            actor_id=actor_id,
            operation_name=operation_name,
        )

        for event in source_events:
            cloned = self._clone_event(event)
            ctx.emit_event(cloned)

        return ctx
