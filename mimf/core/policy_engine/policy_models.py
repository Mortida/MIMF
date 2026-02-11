from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class DecisionStatus(str, Enum):
    """
    Enumerated policy decision status.

    Using str Enum ensures stable serialization and safe comparisons.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class PolicyDecision:
    """
    Immutable policy decision record.

    Security invariants
    - Frozen dataclass prevents post-hoc tampering
    - status is a DecisionStatus enum (not free-form text)
    - to_dict returns JSON-safe primitives
    """

    status: DecisionStatus
    policy_id: Optional[str] = None
    reason: Optional[str] = None
    trace_id: str = ""
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "trace_id": self.trace_id,
            "metadata": dict(self.metadata) if self.metadata else {},
        }
