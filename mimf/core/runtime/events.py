from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import Any, Dict, Optional
from uuid import UUID, uuid4


def _json_safe(value: Any) -> Any:
    """Convert values into deterministic, JSON-safe representations.

    Security notes:
    - Do not attempt to serialize arbitrary objects (could leak secrets via repr).
    - Only handle a small whitelist of safe types.

    """

    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_json_safe(v) for v in value)
    return value


@dataclass(frozen=True)
class RuntimeEvent:
    """Immutable evidence unit for MIMF runtime operations.

    Responsibilities
    - Provide stable identity and timestamp
    - Provide deterministic payload export for hashing and storage
    - Carry hash-chain fields that are sealed by RuntimeContext

    Security invariants
    - Immutable after creation
    - Does not self-seal hashes
    - Deterministic JSON-safe payload export

    """

    event_id: UUID = field(default_factory=uuid4, init=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC), init=False)

    previous_event_hash: Optional[str] = field(default=None, init=False)
    event_hash: Optional[str] = field(default=None, init=False)

    @property
    def event_type(self) -> str:
        return self.__class__.__name__

    def to_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"event_type": self.event_type}
        for f in fields(self):
            if f.name in {"previous_event_hash", "event_hash"}:
                continue
            payload[f.name] = _json_safe(getattr(self, f.name))
        return payload

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(event_id={self.event_id}, "
            f"event_type={self.event_type}, created_at={self.created_at})"
        )


@dataclass(frozen=True)
class InspectionEvent(RuntimeEvent):
    """Forensic event representing an inspection snapshot of a runtime object."""

    object_id: str
    snapshot: Dict[str, Any]

    def to_payload(self) -> Dict[str, Any]:
        payload = super().to_payload()
        payload["object_id"] = self.object_id
        payload["snapshot"] = self.snapshot
        return payload


@dataclass(frozen=True)
class PolicyEvaluationEvent(RuntimeEvent):
    """Forensic record of a policy decision over a mutation plan.

    Stored fields are JSON-safe primitives and identifiers only.
    Sealing is performed by RuntimeContext.

    Security notes:
    - Keep metadata minimal; do not include full object metadata by default.
    """

    plan_id: str
    target_object_id: str
    decision: str
    policy_id: Optional[str] = None
    reason: Optional[str] = None
    trace_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, Any]:
        payload = super().to_payload()
        payload["plan_id"] = self.plan_id
        payload["target_object_id"] = self.target_object_id
        payload["decision"] = self.decision
        payload["policy_id"] = self.policy_id
        payload["reason"] = self.reason
        payload["trace_id"] = self.trace_id
        payload["metadata"] = self.metadata
        return payload


@dataclass(frozen=True)
class MutationExecutionEvent(RuntimeEvent):
    """Forensic record of executor activity for a mutation plan."""

    plan_id: str
    target_object_id: str
    mutation_type: str
    executor: str
    applied: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, Any]:
        payload = super().to_payload()
        payload["plan_id"] = self.plan_id
        payload["target_object_id"] = self.target_object_id
        payload["mutation_type"] = self.mutation_type
        payload["executor"] = self.executor
        payload["applied"] = self.applied
        payload["metadata"] = self.metadata
        return payload
