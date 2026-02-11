from datetime import datetime, UTC

import pytest

from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import InspectionEvent, PolicyEvaluationEvent
from mimf.core.runtime.mutation import MutationPlan, MutationExecutor
from mimf.core.runtime.mutation_pipeline import SafeMutationPipeline
from mimf.core.runtime.object import RuntimeObject


class _Decision:
    def __init__(self, status: DecisionStatus, policy_id: str, reason: str, trace_id: str):
        self.status = status
        self.policy_id = policy_id
        self.reason = reason
        self.trace_id = trace_id


class _FakePolicyEngine:
    def __init__(self, decision):
        self._decision = decision

    def evaluate(self, _ctx):
        return self._decision


class _ExecutorSpy(MutationExecutor):
    executor_name = "spy"
    called = False

    def _apply(self, plan, obj):
        return obj

    def execute(self, plan, obj, context):
        self.called = True
        return super().execute(plan, obj, context)


def _make_obj():
    return RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )


def _make_plan():
    return MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )


def test_pipeline_emits_inspection_then_policy_event_allow_executes():
    engine = _FakePolicyEngine(
        _Decision(DecisionStatus.ALLOW, "p-allow", "ok", "t-1")
    )
    pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=_ExecutorSpy)

    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")
    obj = _make_obj()
    plan = _make_plan()

    out_ctx = pipeline.execute(plan, obj, context=ctx)

    events = out_ctx.get_events()
    assert isinstance(events[0], InspectionEvent)
    assert isinstance(events[1], PolicyEvaluationEvent)

    assert out_ctx.verify_integrity() is True


def test_pipeline_denies_and_does_not_execute_executor():
    engine = _FakePolicyEngine(
        _Decision(DecisionStatus.DENY, "p-deny", "no", "t-2")
    )
    pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=_ExecutorSpy)

    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")
    obj = _make_obj()
    plan = _make_plan()

    with pytest.raises(PermissionError):
        pipeline.execute(plan, obj, context=ctx)

    events = ctx.get_events()
    assert isinstance(events[0], InspectionEvent)
    assert isinstance(events[1], PolicyEvaluationEvent)

    assert ctx.verify_integrity() is True
