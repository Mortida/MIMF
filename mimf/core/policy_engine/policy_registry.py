from typing import List
from mimf.core.policy_engine.policy_exceptions import PolicyConfigurationError


class PolicyRegistry:
    """
    Policy Administration Point (PAP)

    Stores active policy rules.
    """

    def __init__(self):
        self._rules: List = []

    def register(self, rule) -> None:
        if not hasattr(rule, "evaluate"):
            raise PolicyConfigurationError(
                "Policy rule must implement evaluate(context)"
            )
        self._rules.append(rule)

    def get_rules(self) -> List:
        # Return a copy to prevent external mutation
        return list(self._rules)
