from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability
from .policy_context import PolicyContext
from .policy_models import DecisionStatus, PolicyDecision
from .policy_rules import PolicyRule


def _as_capability(value: Any) -> Optional[Capability]:
    if isinstance(value, Capability):
        return value
    if isinstance(value, str):
        return Capability(value)
    return None


@dataclass(frozen=True)
class BoundaryRule(PolicyRule):
    """
    Deny unless:
    - PolicyContext.metadata includes a SecurityBoundary under key 'boundary'
    - PolicyContext.metadata includes required capability under key 'required_capability'
    - boundary.allows(required_capability) is True
    """

    rule_id: str = "boundary-enforcement"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        if not isinstance(context, PolicyContext):
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Invalid policy context",
                trace_id="",
            )

        trace_id = str(context.metadata.get("plan_id", ""))

        boundary = context.metadata.get("boundary")
        if not isinstance(boundary, SecurityBoundary):
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Missing or invalid security boundary",
                trace_id=trace_id,
            )

        cap = _as_capability(context.metadata.get("required_capability"))
        if cap is None:
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Missing or invalid required capability",
                trace_id=trace_id,
            )

        if boundary.allows(cap):
            return PolicyDecision(
                status=DecisionStatus.ALLOW,
                policy_id=self.rule_id,
                reason=f"Boundary '{boundary.boundary_id}' allows capability '{cap.name}'",
                trace_id=trace_id,
            )

        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id=self.rule_id,
            reason=f"Boundary '{boundary.boundary_id}' denies capability '{cap.name}'",
            trace_id=trace_id,
        )
