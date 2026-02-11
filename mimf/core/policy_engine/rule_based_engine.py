from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

from .policy_context import PolicyContext
from .policy_engine import PolicyEngine
from .policy_models import DecisionStatus, PolicyDecision
from .policy_rules import PolicyRule


@dataclass(frozen=True)
class RuleBasedPolicyEngine(PolicyEngine):
    """
    Policy engine that evaluates PolicyRule objects in order.

    Security invariants
    - Deterministic first-match evaluation
    - Fail closed if no rule applies
    - Type checks all rules at construction time
    """

    rules: List[PolicyRule] = field(default_factory=list)
    default_policy_id: str = "default-deny"

    def __post_init__(self) -> None:
        if not isinstance(self.default_policy_id, str) or not self.default_policy_id:
            raise ValueError("default_policy_id must be a non-empty string")

        for r in self.rules:
            if not isinstance(r, PolicyRule):
                raise TypeError("All rules must be PolicyRule instances")

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        if not isinstance(context, PolicyContext):
            raise TypeError("context must be a PolicyContext instance")

        for rule in self.rules:
            decision = rule.evaluate(context)
            if decision is not None:
                return decision

        trace_id = str(context.metadata.get("plan_id", ""))
        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id=self.default_policy_id,
            reason="No matching rule",
            trace_id=trace_id,
        )
