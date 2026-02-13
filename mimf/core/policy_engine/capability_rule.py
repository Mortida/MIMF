from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from mimf.core.security.capabilities import Capability

from .policy_context import PolicyContext
from .policy_models import DecisionStatus, PolicyDecision
from .policy_rules import PolicyRule


def _normalize_capabilities(raw: Any) -> Optional[List[Capability]]:
    if raw is None:
        return None

    if isinstance(raw, list):
        out: List[Capability] = []
        for item in raw:
            if isinstance(item, Capability):
                out.append(item)
            elif isinstance(item, str):
                out.append(Capability(item))
            else:
                return None
        return out

    return None


@dataclass(frozen=True)
class CapabilityRule(PolicyRule):
    """
    Deny unless required capability is present for the actor.

    Expected PolicyContext.metadata fields
    - actor_capabilities: list[str] or list[Capability]
    - plan_id: str (optional) used for trace_id
    """

    required: Capability
    rule_id: str = "capability-required"

    def __post_init__(self) -> None:
        if not isinstance(self.required, Capability):
            raise TypeError("required must be a Capability instance")

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        if not isinstance(context, PolicyContext):
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Invalid policy context",
                trace_id="",
            )

        trace_id = str(context.metadata.get("plan_id", ""))
        raw_caps = context.metadata.get("actor_capabilities")

        caps = _normalize_capabilities(raw_caps)
        if caps is None:
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Missing or invalid actor capabilities",
                trace_id=trace_id,
            )

        if self.required in set(caps):
            return PolicyDecision(
                status=DecisionStatus.ALLOW,
                policy_id=self.rule_id,
                reason=f"Capability present: {self.required.name}",
                trace_id=trace_id,
            )

        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id=self.rule_id,
            reason=f"Missing capability: {self.required.name}",
            trace_id=trace_id,
        )
