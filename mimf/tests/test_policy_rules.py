from datetime import UTC, datetime

from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.policy_engine.policy_rules import AllowAllRule, DenyAllRule, LabelAllowRule
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject


def _make_obj(labels=frozenset({"safe"})) -> RuntimeObject:
    return RuntimeObject.create(
        object_id="obj-1",
        object_type="file",
        origin={"source": "test"},
        metadata={"a": 1},
        labels=labels,
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


def test_allow_all_rule_allows():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    d = AllowAllRule().evaluate(ctx)
    assert d is not None
    assert d.status == DecisionStatus.ALLOW


def test_deny_all_rule_denies():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    d = DenyAllRule().evaluate(ctx)
    assert d is not None
    assert d.status == DecisionStatus.DENY


def test_label_allow_rule_allows_when_label_matches():
    ctx = PolicyContext.from_runtime(
        plan=_make_plan(), target=_make_obj(labels=frozenset({"safe"}))
    )
    d = LabelAllowRule(allowed_label="safe").evaluate(ctx)
    assert d is not None
    assert d.status == DecisionStatus.ALLOW


def test_label_allow_rule_denies_when_label_differs():
    ctx = PolicyContext.from_runtime(
        plan=_make_plan(), target=_make_obj(labels=frozenset({"danger"}))
    )
    d = LabelAllowRule(allowed_label="safe").evaluate(ctx)
    assert d is not None
    assert d.status == DecisionStatus.DENY
