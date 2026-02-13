from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import PolicyDecision, PolicyRule
from mimf.core.security.capabilities import Capability


class RequiresCapabilityRule(PolicyRule):
    """
    Denies mutation unless the target object explicitly
    exposes the required capability.
    """

    __slots__ = ("_required_capability",)

    def __init__(self, required_capability: Capability):
        super().__init__(policy_id=f"REQUIRES_CAPABILITY:{required_capability.name}")
        self._required_capability = required_capability

    def _evaluate(self, context: PolicyContext) -> PolicyDecision:
        target = context.target_object

        # FAIL CLOSED: capability attribute missing
        if not hasattr(target, "capabilities"):
            return PolicyDecision.deny(
                reason="Target object exposes no capabilities",
                policy_id=self.policy_id,
            )

        # FAIL CLOSED: capability not present
        if self._required_capability not in target.capabilities:
            return PolicyDecision.deny(
                reason=f"Missing capability: {self._required_capability.name}",
                policy_id=self.policy_id,
            )

        return PolicyDecision.allow()
