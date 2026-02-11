from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from .policy_context import PolicyContext
from .policy_models import DecisionStatus, PolicyDecision
from .policy_rules import PolicyRule


@dataclass(frozen=True)
class PolicyEngine:
    """
    Deterministic policy decision point (PDP).

    Security invariants
    - Fail closed on misconfiguration or exceptions
    - Deterministic evaluation order (as provided)
    - No mutation of PolicyContext
    - Traceability: produces a stable trace_id if present in context metadata
    """

    rules: List[PolicyRule]

    def __post_init__(self) -> None:
        if not isinstance(self.rules, list):
            raise TypeError("rules must be a list of PolicyRule instances")

        for r in self.rules:
            if not isinstance(r, PolicyRule):
                raise TypeError("rules must contain only PolicyRule instances")

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        if not isinstance(context, PolicyContext):
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id="policy-engine",
                reason="Invalid policy context",
                trace_id="",
            )

        trace_id = str(context.metadata.get("plan_id", ""))

        for rule in self.rules:
            try:
                decision = rule.evaluate(context)
            except Exception as e:
                return PolicyDecision(
                    status=DecisionStatus.DENY,
                    policy_id=getattr(rule, "rule_id", "unknown-rule"),
                    reason=f"Policy rule exception: {e.__class__.__name__}",
                    trace_id=trace_id,
                )

            if decision is None:
                continue

            if decision.trace_id == "":
                decision = PolicyDecision(
                    status=decision.status,
                    policy_id=decision.policy_id,
                    reason=decision.reason,
                    trace_id=trace_id,
                    metadata=dict(decision.metadata) if decision.metadata else None,
                )

            if decision.status == DecisionStatus.DENY:
                return decision

            if decision.status == DecisionStatus.ALLOW:
                return decision

        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id="policy-engine",
            reason="No rule produced a decision",
            trace_id=trace_id,
        )
