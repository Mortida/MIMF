from datetime import datetime, UTC, timedelta
import pytest

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.event_query import EventQuery
from mimf.core.runtime.events import RuntimeEvent, InspectionEvent


def test_event_query_by_type_filters_correctly():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="a")
    ctx.emit_event(RuntimeEvent())
    ctx.emit_event(InspectionEvent(object_id="obj-1", snapshot={"x": 1}))

    inspection = EventQuery.by_type(ctx.get_events(), InspectionEvent)
    assert len(inspection) == 1
    assert isinstance(inspection[0], InspectionEvent)


def test_event_query_by_plan_id_filters_only_matching_events():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="a")
    ctx.emit_event(RuntimeEvent())

    class _PlanEvent(RuntimeEvent):
        def __init__(self, plan_id: str):
            super().__init__()
            self.plan_id = plan_id

    e1 = _PlanEvent("p-1")
    e2 = _PlanEvent("p-2")
    ctx.emit_event(e1)
    ctx.emit_event(e2)

    matched = EventQuery.by_plan_id(ctx.get_events(), "p-2")
    assert len(matched) == 1
    assert getattr(matched[0], "plan_id") == "p-2"


def test_event_query_time_range_filters_by_created_at():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="a")

    e1 = RuntimeEvent()
    e2 = RuntimeEvent()
    object.__setattr__(e1, "created_at", datetime.now(UTC) - timedelta(seconds=10))
    object.__setattr__(e2, "created_at", datetime.now(UTC))

    ctx.emit_event(e1)
    ctx.emit_event(e2)

    start = datetime.now(UTC) - timedelta(seconds=5)
    out = EventQuery.time_range(ctx.get_events(), start=start)
    assert len(out) == 1
    assert out[0].event_id == e2.event_id


def test_event_query_summarize_counts():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="a")
    ctx.emit_event(RuntimeEvent())
    ctx.emit_event(RuntimeEvent())
    summary = EventQuery.summarize(ctx.get_events())
    assert summary["total"] == 2
    assert summary["by_type"]["RuntimeEvent"] == 2


def test_event_query_validates_inputs_fail_closed():
    with pytest.raises(TypeError):
        EventQuery.by_type([], str)

    with pytest.raises(ValueError):
        EventQuery.by_plan_id([], "")

    with pytest.raises(ValueError):
        EventQuery.time_range([], start=datetime(2026, 1, 2), end=datetime(2026, 1, 1))
