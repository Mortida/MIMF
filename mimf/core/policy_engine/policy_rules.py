from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .policy_context import PolicyContext
from .policy_models import DecisionStatus, PolicyDecision


class PolicyRule:
    rule_id: str = "policy-rule"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        raise NotImplementedError


@dataclass(frozen=True)
class AllowAllRule(PolicyRule):
    rule_id: str = "allow-all"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        trace_id = str(context.metadata.get("plan_id", ""))
        return PolicyDecision(
            status=DecisionStatus.ALLOW,
            policy_id=self.rule_id,
            reason="Allow all",
            trace_id=trace_id,
        )


@dataclass(frozen=True)
class DenyAllRule(PolicyRule):
    rule_id: str = "deny-all"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        trace_id = str(context.metadata.get("plan_id", ""))
        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id=self.rule_id,
            reason="Deny all",
            trace_id=trace_id,
        )


@dataclass(frozen=True)
class LabelAllowRule(PolicyRule):
    allowed_label: str
    rule_id: str = "label-allow"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        trace_id = str(context.metadata.get("plan_id", ""))

        target = getattr(context, "target", None)
        labels = getattr(target, "labels", None)

        if not isinstance(self.allowed_label, str) or self.allowed_label == "":
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Invalid allowed_label configuration",
                trace_id=trace_id,
            )

        if labels is None:
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Missing target labels",
                trace_id=trace_id,
            )

        try:
            label_set = set(labels)
        except TypeError:
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Invalid target labels type",
                trace_id=trace_id,
            )

        if self.allowed_label in label_set:
            return PolicyDecision(
                status=DecisionStatus.ALLOW,
                policy_id=self.rule_id,
                reason=f"Label '{self.allowed_label}' allowed",
                trace_id=trace_id,
            )

        return PolicyDecision(
            status=DecisionStatus.DENY,
            policy_id=self.rule_id,
            reason=f"Label '{self.allowed_label}' not present",
            trace_id=trace_id,
        )
