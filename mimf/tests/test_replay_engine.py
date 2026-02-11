from datetime import datetime, UTC

import pytest

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import RuntimeEvent, InspectionEvent
from mimf.core.runtime.object import RuntimeObject
from mimf.core.runtime.replay import ReplayEngine


def test_replay_into_new_context_produces_valid_chain_and_same_event_count():
    src = RuntimeContext(context_id="src", actor_id="a")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    src.emit_event(RuntimeEvent())
    src.emit_event(InspectionEvent(object_id=obj.object_id, snapshot={"x": 1}))

    engine = ReplayEngine()
    dst = engine.replay_into_new_context(
        src.get_events(),
        context_id="dst",
        actor_id="b",
    )

    assert len(dst.get_events()) == len(src.get_events())
    assert dst.verify_integrity() is True


def test_replay_rejects_non_events():
    engine = ReplayEngine()
    with pytest.raises(TypeError):
        engine.replay_into_new_context([object()], context_id="x")
