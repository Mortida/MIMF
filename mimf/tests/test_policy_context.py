from datetime import datetime, timezone

import pytest

from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject


def _make_obj() -> RuntimeObject:
    return RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=frozenset({"safe"}),
        created_at=datetime.now(timezone.utc),
    )


def _make_plan() -> MutationPlan:
    return MutationPlan(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE",
        changes={"a": 2},
        allowed_labels=frozenset({"safe"}),
        created_at=datetime.now(timezone.utc),
    )


def test_policy_context_metadata_is_immutable():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    with pytest.raises(TypeError):
        ctx.metadata["x"] = 1


def test_policy_context_from_runtime_includes_stable_core_fields():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    assert ctx.metadata["plan_id"] == "plan-1"
    assert ctx.metadata["target_object_id"] == "obj-1"
    assert ctx.metadata["mutation_type"] == "UPDATE"
    assert ctx.metadata["plan_type"] == "MutationPlan"
    assert ctx.metadata["target_type"] == "RuntimeObject"


def test_policy_context_with_metadata_creates_new_context_without_mutating_original():
    base = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    derived = base.with_metadata({"actor_capabilities": ["mutate_metadata"]})

    assert "actor_capabilities" not in base.metadata
    assert derived.metadata["actor_capabilities"] == ["mutate_metadata"]
    assert base.plan is derived.plan
    assert base.target is derived.target


def test_policy_context_rejects_non_mapping_metadata_and_non_string_keys():
    with pytest.raises(TypeError):
        PolicyContext(plan=_make_plan(), target=_make_obj(), metadata=123)

    with pytest.raises(TypeError):
        PolicyContext(plan=_make_plan(), target=_make_obj(), metadata={1: "x"})

    base = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    with pytest.raises(TypeError):
        base.with_metadata({1: "x"})
