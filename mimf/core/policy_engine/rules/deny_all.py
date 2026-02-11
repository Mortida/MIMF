from mimf.core.policy_engine.policy_models import PolicyDecision
from mimf.core.policy_engine.policy_models import DecisionStatus
from mimf.core.policy_engine.policy_models import PolicyRule
from mimf.core.policy_engine.policy_context import PolicyContext


class DenyAllRule(PolicyRule):
    """
    Safety baseline rule.
    Explicitly denies all mutations.
    """

    def __init__(self):
        super().__init__(policy_id="POLICY_DENY_ALL")

    def _evaluate(self, context: PolicyContext) -> PolicyDecision:
        return PolicyDecision.deny(
            reason="Global deny-all policy enforced",
            policy_id=self.policy_id,
        )
