from datetime import datetime, UTC

from mimf.core.policy_engine.policy_engine import PolicyEngine
from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus, PolicyDecision
from mimf.core.policy_engine.policy_rules import PolicyRule
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject


class _AllowRule(PolicyRule):
    rule_id = "allow"

    def evaluate(self, context: PolicyContext):
        return PolicyDecision(status=DecisionStatus.ALLOW, policy_id="allow", reason="ok", trace_id="")


class _DenyRule(PolicyRule):
    rule_id = "deny"

    def evaluate(self, context: PolicyContext):
        return PolicyDecision(status=DecisionStatus.DENY, policy_id="deny", reason="no", trace_id="")


class _NoneRule(PolicyRule):
    rule_id = "none"

    def evaluate(self, context: PolicyContext):
        return None


class _ExplodeRule(PolicyRule):
    rule_id = "explode"

    def evaluate(self, context: PolicyContext):
        raise RuntimeError("boom")


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


def test_policy_engine_returns_first_allow():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    engine = PolicyEngine(rules=[_NoneRule(), _AllowRule(), _DenyRule()])

    d = engine.evaluate(ctx)
    assert d.status == DecisionStatus.ALLOW
    assert d.policy_id == "allow"
    assert d.trace_id == "plan-1"


def test_policy_engine_returns_first_deny():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    engine = PolicyEngine(rules=[_NoneRule(), _DenyRule(), _AllowRule()])

    d = engine.evaluate(ctx)
    assert d.status == DecisionStatus.DENY
    assert d.policy_id == "deny"
    assert d.trace_id == "plan-1"


def test_policy_engine_fails_closed_on_rule_exception():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    engine = PolicyEngine(rules=[_ExplodeRule(), _AllowRule()])

    d = engine.evaluate(ctx)
    assert d.status == DecisionStatus.DENY
    assert d.policy_id == "explode"
    assert d.trace_id == "plan-1"


def test_policy_engine_denies_when_no_rule_decides():
    ctx = PolicyContext.from_runtime(plan=_make_plan(), target=_make_obj())
    engine = PolicyEngine(rules=[_NoneRule(), _NoneRule()])

    d = engine.evaluate(ctx)
    assert d.status == DecisionStatus.DENY
    assert d.policy_id == "policy-engine"
    assert d.trace_id == "plan-1"
