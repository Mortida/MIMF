from dataclasses import dataclass
from datetime import datetime
from typing import FrozenSet, Dict, Any

@dataclass(frozen=True)
class PolicyDecision:
    """
    Immutable record of a policy evaluation result.
    """

    decision_id: str                # Unique identifier
    target_object_id: str           # Object evaluated
    allowed_labels: FrozenSet[str]  # Labels permitted by this policy
    denied_labels: FrozenSet[str]   # Labels denied by this policy
    metadata: Dict[str, Any]        # Extra info about evaluation
    created_at: datetime

