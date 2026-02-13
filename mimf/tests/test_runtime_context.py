from datetime import UTC, datetime

import pytest

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import RuntimeEvent
from mimf.core.runtime.object import RuntimeObject


def test_runtime_context_add_object_registers_and_prevents_duplicates():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    ctx.add_object(obj)
    assert ctx.get_object("obj-1") is obj

    with pytest.raises(RuntimeError):
        ctx.add_object(obj)


def test_runtime_context_emit_event_seals_hash_chain_and_integrity_verifies():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    e1 = RuntimeEvent()
    e2 = RuntimeEvent()

    ctx.emit_event(e1)
    ctx.emit_event(e2)

    events = ctx.get_events()
    assert len(events) == 2

    assert events[0].previous_event_hash == "GENESIS"
    assert events[0].event_hash is not None

    assert events[1].previous_event_hash == events[0].event_hash
    assert events[1].event_hash is not None

    assert ctx.verify_integrity() is True


def test_runtime_context_rejects_timestamp_regression():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    e1 = RuntimeEvent()
    ctx.emit_event(e1)

    e2 = RuntimeEvent()
    object.__setattr__(e2, "created_at", e1.created_at.replace(year=e1.created_at.year - 1))

    with pytest.raises(RuntimeError):
        ctx.emit_event(e2)


def test_runtime_context_get_objects_and_get_events_are_immutable_views():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )
    ctx.add_object(obj)

    ctx.emit_event(RuntimeEvent())

    objects_view = ctx.get_objects()
    events_view = ctx.get_events()

    with pytest.raises(TypeError):
        objects_view["x"] = obj

    assert isinstance(events_view, tuple)
    with pytest.raises(AttributeError):
        events_view.append(RuntimeEvent())
