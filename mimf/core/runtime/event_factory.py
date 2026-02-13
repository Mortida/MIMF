from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Type
from uuid import UUID

from .events import (
    InspectionEvent,
    MutationExecutionEvent,
    PolicyEvaluationEvent,
    RuntimeEvent,
)

_EVENT_TYPES: Dict[str, Type[RuntimeEvent]] = {
    "InspectionEvent": InspectionEvent,
    "PolicyEvaluationEvent": PolicyEvaluationEvent,
    "MutationExecutionEvent": MutationExecutionEvent,
}


def _parse_dt(value: str) -> datetime:
    """Parse ISO8601 datetime produced by datetime.isoformat().

    Security: input is untrusted. Only accept ISO strings.

    """
    return datetime.fromisoformat(value)


def event_from_record(record: Dict[str, Any]) -> RuntimeEvent:
    """Reconstruct a RuntimeEvent subclass from a persisted record.

    Required keys
    - event_type: str
    - payload: dict (original to_payload output)
    - event_id: str (UUID)
    - created_at: ISO8601 str
    - previous_event_hash: str | None
    - event_hash: str | None

    Security notes
    - Treat record as untrusted.
    - Only allow known event types.
    - Only pass whitelisted constructor args.

    """

    et = record.get("event_type")
    if not isinstance(et, str) or et not in _EVENT_TYPES:
        raise ValueError(f"Unknown or missing event_type: {et!r}")

    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Missing or invalid payload")

    cls = _EVENT_TYPES[et]

    # Build constructor kwargs for each event type
    if cls is InspectionEvent:
        kwargs = {
            "object_id": payload.get("object_id"),
            "snapshot": payload.get("snapshot"),
        }
        if not isinstance(kwargs["object_id"], str) or not isinstance(kwargs["snapshot"], dict):
            raise ValueError("Invalid InspectionEvent payload")
        ev: RuntimeEvent = InspectionEvent(**kwargs)

    elif cls is PolicyEvaluationEvent:
        kwargs = {
            "plan_id": payload.get("plan_id"),
            "target_object_id": payload.get("target_object_id"),
            "decision": payload.get("decision"),
            "policy_id": payload.get("policy_id"),
            "reason": payload.get("reason"),
            "trace_id": payload.get("trace_id", ""),
            "metadata": payload.get("metadata", {}),
        }
        if not all(isinstance(kwargs[k], str) for k in ("plan_id", "target_object_id", "decision")):
            raise ValueError("Invalid PolicyEvaluationEvent payload")
        if kwargs["metadata"] is None:
            kwargs["metadata"] = {}
        if not isinstance(kwargs["metadata"], dict):
            raise ValueError("Invalid PolicyEvaluationEvent metadata")
        ev = PolicyEvaluationEvent(**kwargs)

    elif cls is MutationExecutionEvent:
        kwargs = {
            "plan_id": payload.get("plan_id"),
            "target_object_id": payload.get("target_object_id"),
            "mutation_type": payload.get("mutation_type"),
            "executor": payload.get("executor"),
            "applied": payload.get("applied"),
            "metadata": payload.get("metadata", {}),
        }
        if not all(
            isinstance(kwargs[k], str)
            for k in ("plan_id", "target_object_id", "mutation_type", "executor")
        ):
            raise ValueError("Invalid MutationExecutionEvent payload")
        if not isinstance(kwargs["applied"], bool):
            raise ValueError("Invalid MutationExecutionEvent applied")
        if kwargs["metadata"] is None:
            kwargs["metadata"] = {}
        if not isinstance(kwargs["metadata"], dict):
            raise ValueError("Invalid MutationExecutionEvent metadata")
        ev = MutationExecutionEvent(**kwargs)

    else:
        raise ValueError(f"Unhandled event type: {et}")

    # Seal persisted identity/timestamps + chain fields
    event_id = record.get("event_id")
    created_at = record.get("created_at")
    if not isinstance(event_id, str) or not isinstance(created_at, str):
        raise ValueError("Missing event_id/created_at")

    object.__setattr__(ev, "event_id", UUID(event_id))
    object.__setattr__(ev, "created_at", _parse_dt(created_at))

    object.__setattr__(ev, "previous_event_hash", record.get("previous_event_hash"))
    object.__setattr__(ev, "event_hash", record.get("event_hash"))

    return ev
