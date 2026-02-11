from datetime import datetime, UTC
import pytest

from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.policy_engine.policy_rules import AllowAllRule, DenyAllRule, LabelAllowRule
from mimf.core.policy_engine.rule_based_engine import RuleBasedPolicyEngine
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


def test_rule_based_engine_returns_first_match():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj(labels=frozenset({"safe"})))

    engine = RuleBasedPolicyEngine(
        rules=[
            DenyAllRule(rule_id="deny-first"),
            AllowAllRule(rule_id="allow-second"),
        ],
        default_policy_id="fallback",
    )

    decision = engine.evaluate(ctx)
    assert decision.status == DecisionStatus.DENY
    assert decision.policy_id == "deny-first"


def test_rule_based_engine_denies_if_no_rules():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())

    engine = RuleBasedPolicyEngine(rules=[], default_policy_id="fallback")
    decision = engine.evaluate(ctx)

    assert decision.status == DecisionStatus.DENY
    assert decision.policy_id == "fallback"


def test_rule_based_engine_allows_when_label_rule_matches():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj(labels=frozenset({"safe"})))

    engine = RuleBasedPolicyEngine(
        rules=[LabelAllowRule(allowed_label="safe")],
        default_policy_id="fallback",
    )

    decision = engine.evaluate(ctx)
    assert decision.status == DecisionStatus.ALLOW


def test_rule_based_engine_fail_closed_on_bad_context():
    engine = RuleBasedPolicyEngine(rules=[AllowAllRule()], default_policy_id="fallback")
    with pytest.raises(TypeError):
        engine.evaluate("not-a-context")


def test_rule_based_engine_rejects_bad_rule_list():
    with pytest.raises(TypeError):
        RuleBasedPolicyEngine(rules=[object()], default_policy_id="fallback")
