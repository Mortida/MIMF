from datetime import UTC, datetime

import pytest

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.mutation import MutationExecutor, MutationPlan, _validate
from mimf.core.runtime.object import RuntimeObject


class _NoopExecutor(MutationExecutor):
    executor_name = "noop"

    def _apply(self, plan: MutationPlan, obj: RuntimeObject) -> RuntimeObject:
        return RuntimeObject.create(
            object_id=obj.object_id,
            object_type=obj.object_type,
            origin=obj.origin,
            metadata=obj.metadata,
            labels=obj.labels,
            created_at=obj.created_at,
        )


def test_validate_rejects_target_mismatch():
    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    plan = MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-2",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    with pytest.raises(RuntimeError):
        _validate(plan, obj)


def test_validate_rejects_label_violation():
    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"restricted"}),
        created_at=datetime.now(UTC),
    )

    plan = MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    with pytest.raises(RuntimeError):
        _validate(plan, obj)


def test_executor_emits_events_and_returns_new_object():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    plan = MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="NOOP",
        changes={},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )

    ex = _NoopExecutor()
    new_obj = ex.execute(plan, obj, ctx)

    assert isinstance(new_obj, RuntimeObject)
    assert new_obj.object_id == obj.object_id

    events = ctx.get_events()
    assert len(events) == 3
    assert ctx.verify_integrity() is True
