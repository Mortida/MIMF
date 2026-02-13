from datetime import datetime, timezone

from mimf.core.policy_engine.capability_rule import CapabilityRule
from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject
from mimf.core.security.capabilities import Capability


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


def _make_ctx_with_caps(caps):
    plan = _make_plan()
    obj = _make_obj()

    base = PolicyContext.from_runtime(plan=plan, target=obj)
    merged = dict(base.metadata)
    merged["actor_capabilities"] = caps

    return PolicyContext(plan=plan, target=obj, metadata=merged)


def test_capability_rule_allows_when_capability_present_as_string():
    ctx = _make_ctx_with_caps(["mutate_metadata"])

    rule = CapabilityRule(required=Capability("mutate_metadata"))
    d = rule.evaluate(ctx)

    assert d is not None
    assert d.status == DecisionStatus.ALLOW


def test_capability_rule_denies_when_missing_capability():
    ctx = _make_ctx_with_caps(["inspect_metadata"])

    rule = CapabilityRule(required=Capability("mutate_metadata"))
    d = rule.evaluate(ctx)

    assert d is not None
    assert d.status == DecisionStatus.DENY


def test_capability_rule_denies_when_caps_missing_or_invalid():
    base = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())

    rule = CapabilityRule(required=Capability("mutate_metadata"))
    d1 = rule.evaluate(base)
    assert d1 is not None
    assert d1.status == DecisionStatus.DENY

    ctx2 = _make_ctx_with_caps(["ok", 123])
    d2 = rule.evaluate(ctx2)
    assert d2 is not None
    assert d2.status == DecisionStatus.DENY
