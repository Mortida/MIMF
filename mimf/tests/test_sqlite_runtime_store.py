from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import InspectionEvent, PolicyEvaluationEvent
from mimf.core.runtime.object import RuntimeObject
from mimf.core.runtime.storage.sqlite_store import SQLiteRuntimeStore


def test_sqlite_store_roundtrip(tmp_path: Path) -> None:
    """Roundtrip RuntimeContext through SQLite."""

    ctx = RuntimeContext(context_id="ctx-1", actor_id="tester", operation_name="test")

    obj = RuntimeObject.create(
        object_id="o1",
        object_type="file",
        origin={"path": "/tmp/example"},
        metadata={"a": 1, "b": "x"},
        labels=frozenset({"PUBLIC"}),
        created_at=datetime.now(timezone.utc),
    )
    ctx.add_object(obj)

    ctx.emit_event(InspectionEvent(object_id=obj.object_id, snapshot=obj.snapshot()))
    ctx.emit_event(
        PolicyEvaluationEvent(
            plan_id="p1",
            target_object_id=obj.object_id,
            decision="ALLOW",
            policy_id="allow-all",
            reason="test",
            trace_id="t1",
            metadata={"k": "v"},
        )
    )

    assert ctx.verify_integrity() is True

    db_path = tmp_path / "mimf.db"
    store = SQLiteRuntimeStore(db_path)
    store.save_context(ctx)

    rows = store.list_contexts(limit=10)
    assert rows and rows[0]["context_id"] == "ctx-1"

    loaded = store.load_context("ctx-1")
    assert loaded.context_id == ctx.context_id
    assert loaded.actor_id == ctx.actor_id
    assert loaded.operation_name == ctx.operation_name

    assert loaded.verify_integrity() is True

    # Objects
    loaded_obj = loaded.get_object("o1")
    assert loaded_obj.snapshot_hash == obj.snapshot_hash
    assert loaded_obj.metadata == obj.metadata

    # Events
    orig_events = ctx.get_events()
    new_events = loaded.get_events()
    assert len(new_events) == len(orig_events)
    assert new_events[-1].event_hash == orig_events[-1].event_hash
    assert new_events[0].previous_event_hash == "GENESIS"


def test_sqlite_store_overwrite(tmp_path: Path) -> None:
    """Overwrite mode replaces an existing context."""

    db_path = tmp_path / "mimf.db"
    store = SQLiteRuntimeStore(db_path)

    ctx1 = RuntimeContext(context_id="ctx-2", operation_name="one")
    store.save_context(ctx1)

    ctx2 = RuntimeContext(context_id="ctx-2", operation_name="two")
    store.save_context(ctx2, overwrite=True)

    loaded = store.load_context("ctx-2")
    assert loaded.operation_name == "two"
