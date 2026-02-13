from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import PolicyDecision, PolicyRule


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
