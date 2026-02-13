from datetime import datetime, timezone

from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.default_executor import DefaultMutationExecutor
from mimf.core.runtime.events import MutationExecutionEvent, PolicyEvaluationEvent
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject


def test_default_executor_emits_execution_events_adds_object_and_preserves_integrity():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    obj = RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(timezone.utc),
    )

    plan = MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(timezone.utc),
    )

    ex = DefaultMutationExecutor()
    new_obj = ex.execute(plan, obj, ctx)

    assert new_obj.object_id == "obj-1"
    assert new_obj.metadata["a"] == 2

    events = ctx.get_events()
    assert len(events) == 2
    assert isinstance(events[0], MutationExecutionEvent)
    assert isinstance(events[1], MutationExecutionEvent)

    assert events[0].metadata["stage"] == "started"
    assert events[1].metadata["stage"] == "completed"
    assert events[0].applied is False
    assert events[1].applied is True

    assert not any(isinstance(e, PolicyEvaluationEvent) for e in events)
    assert ctx.verify_integrity() is True
