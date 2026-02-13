from datetime import datetime, timezone

from mimf.core.runtime.object import RuntimeObject


def test_runtime_object_is_immutable_and_defensively_copied():
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    origin = {"source": "unit-test"}
    metadata = {"k": {"nested": 1}}
    labels = frozenset({"safe", "test"})

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin=origin,
        metadata=metadata,
        labels=labels,
        created_at=created_at,
    )

    origin["source"] = "mutated-after"
    metadata["k"]["nested"] = 999

    snap = obj.snapshot()

    assert obj.origin["source"] == "unit-test"
    assert obj.metadata["k"]["nested"] == 1
    assert snap["origin"]["source"] == "unit-test"
    assert snap["metadata"]["k"]["nested"] == 1


def test_runtime_object_snapshot_hash_is_deterministic():
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    obj1 = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"a": "b"},
        metadata={"x": 1, "y": [2, 3]},
        labels=frozenset({"b", "a"}),
        created_at=created_at,
    )

    obj2 = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"a": "b"},
        metadata={"y": [2, 3], "x": 1},
        labels=frozenset({"a", "b"}),
        created_at=created_at,
    )

    assert obj1.snapshot_hash == obj2.snapshot_hash


def test_runtime_object_snapshot_hash_changes_when_content_changes():
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    obj1 = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"a": "b"},
        metadata={"x": 1},
        labels=frozenset({"a"}),
        created_at=created_at,
    )

    obj2 = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"a": "b"},
        metadata={"x": 2},
        labels=frozenset({"a"}),
        created_at=created_at,
    )

    assert obj1.snapshot_hash != obj2.snapshot_hash
