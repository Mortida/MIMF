from datetime import datetime, UTC

import pytest

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.core.runtime.object import RuntimeObject
from mimf.core.runtime.events import InspectionEvent


def test_inspector_emits_inspection_event_and_chain_is_valid():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    event = Inspector.inspect(obj, ctx)

    assert isinstance(event, InspectionEvent)
    assert event.object_id == obj.object_id
    assert event.snapshot["object_id"] == obj.object_id
    assert event.snapshot["object_type"] == obj.object_type
    assert event.snapshot["snapshot_hash"] == obj.snapshot_hash

    events = ctx.get_events()
    assert len(events) == 1
    assert events[0].previous_event_hash == "GENESIS"
    assert events[0].event_hash is not None
    assert ctx.verify_integrity() is True


def test_inspector_rejects_invalid_inputs():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    with pytest.raises(TypeError):
        Inspector.inspect("not-an-object", ctx)  # type: ignore[arg-type]

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    with pytest.raises(TypeError):
        Inspector.inspect(obj, "not-a-context")  # type: ignore[arg-type]
