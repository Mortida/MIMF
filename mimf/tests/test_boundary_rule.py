from datetime import datetime, UTC

from mimf.core.policy_engine.boundary_rule import BoundaryRule
from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject
from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability


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


def _ctx(meta):
    plan = _make_plan()
    obj = _make_obj()
    base = PolicyContext.from_runtime(plan=plan, target=obj)
    merged = dict(base.metadata)
    merged.update(meta)
    return PolicyContext(plan=plan, target=obj, metadata=merged)


def test_boundary_rule_allows_when_boundary_allows_capability():
    boundary = SecurityBoundary.from_names("embedded-metadata", ["mutate_metadata"])
    ctx = _ctx({"boundary": boundary, "required_capability": "mutate_metadata"})

    rule = BoundaryRule()
    d = rule.evaluate(ctx)

    assert d is not None
    assert d.status == DecisionStatus.ALLOW


def test_boundary_rule_denies_when_boundary_missing_capability():
    boundary = SecurityBoundary.from_names("embedded-metadata", ["inspect_metadata"])
    ctx = _ctx({"boundary": boundary, "required_capability": Capability("mutate_metadata")})

    rule = BoundaryRule()
    d = rule.evaluate(ctx)

    assert d is not None
    assert d.status == DecisionStatus.DENY


def test_boundary_rule_denies_when_missing_or_invalid_metadata():
    rule = BoundaryRule()

    ctx1 = _ctx({"required_capability": "mutate_metadata"})
    d1 = rule.evaluate(ctx1)
    assert d1 is not None
    assert d1.status == DecisionStatus.DENY

    boundary = SecurityBoundary.from_names("x", ["a"])
    ctx2 = _ctx({"boundary": boundary, "required_capability": 123})
    d2 = rule.evaluate(ctx2)
    assert d2 is not None
    assert d2.status == DecisionStatus.DENY
