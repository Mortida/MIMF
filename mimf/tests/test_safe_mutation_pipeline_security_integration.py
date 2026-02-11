# mimf/tests/test_safe_mutation_pipeline_security_integration.py

from __future__ import annotations

from datetime import datetime, UTC

import pytest

from mimf.core.runtime.mutation_pipeline import SafeMutationPipeline
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.object import RuntimeObject
from mimf.core.runtime.mutation import MutationPlan, MutationExecutor
from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability

from mimf.core.policy_engine.policy_models import DecisionStatus, PolicyDecision


class _PolicyEngineSpy:
    def __init__(self, decision: PolicyDecision):
        self._decision = decision
        self.last_context = None

    def evaluate(self, context):
        self.last_context = context
        return self._decision


class _ExecutorNoop(MutationExecutor):
    executor_name = "noop"

    def _apply(self, plan: MutationPlan, obj: RuntimeObject) -> RuntimeObject:
        return obj


def _make_obj() -> RuntimeObject:
    return RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )


def _make_plan() -> MutationPlan:
    return MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(UTC),
    )


def test_pipeline_injects_capabilities_and_boundary_into_policy_context_metadata():
    engine = _PolicyEngineSpy(
        PolicyDecision(
            status=DecisionStatus.ALLOW,
            policy_id="allow",
            reason="ok",
            trace_id="t",
        )
    )

    pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=_ExecutorNoop)

    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")
    obj = _make_obj()
    plan = _make_plan()

    boundary = SecurityBoundary.from_names("embedded-metadata", ["mutate_metadata"])
    pipeline.execute(
        plan=plan,
        runtime_object=obj,
        context=ctx,
        actor_id="actor-1",
        actor_capabilities=["mutate_metadata"],
        boundary=boundary,
        required_capability=Capability("mutate_metadata"),
    )

    pc = engine.last_context
    assert pc is not None

    meta = pc.metadata
    assert meta.get("actor_capabilities") == ["mutate_metadata"]
    assert meta.get("boundary") == boundary
    assert isinstance(meta.get("required_capability"), Capability)
    assert meta["required_capability"].name == "mutate_metadata"


def test_pipeline_denies_when_policy_engine_denies_even_with_capability_metadata():
    engine = _PolicyEngineSpy(
        PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id="deny",
            reason="no",
            trace_id="t",
        )
    )

    pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=_ExecutorNoop)

    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")
    obj = _make_obj()
    plan = _make_plan()

    boundary = SecurityBoundary.from_names("embedded-metadata", ["mutate_metadata"])

    with pytest.raises(PermissionError):
        pipeline.execute(
            plan=plan,
            runtime_object=obj,
            context=ctx,
            actor_id="actor-1",
            actor_capabilities=["mutate_metadata"],
            boundary=boundary,
            required_capability="mutate_metadata",
        )
