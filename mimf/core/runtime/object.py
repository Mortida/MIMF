from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet
from copy import deepcopy
import hashlib
import json


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    return value


def _stable_sha256(payload: Dict[str, Any]) -> str:
    safe_payload = _json_safe(payload)
    serialized = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RuntimeObject:
    """
    Immutable runtime snapshot for any object entering MIMF.

    Security invariants
    - Immutable: no in-place mutation of object fields
    - Deterministic identity: snapshot_hash is stable for identical content
    - Defensive copying: caller-held dicts cannot mutate internal state

    Complexity
    - create / compute_snapshot_hash: O(n) time and O(n) space where n is the
      total size of origin + metadata + labels when serialized.
    - snapshot: O(n) time and O(n) space due to deep copies.
    """

    object_id: str
    object_type: str
    origin: Dict[str, str]
    metadata: Dict[str, Any]
    labels: FrozenSet[str]
    created_at: datetime
    snapshot_hash: str

    @staticmethod
    def compute_snapshot_hash(
        object_id: str,
        object_type: str,
        origin: Dict[str, str],
        metadata: Dict[str, Any],
        labels: FrozenSet[str],
        created_at: datetime,
    ) -> str:
        return _stable_sha256(
            {
                "object_id": object_id,
                "object_type": object_type,
                "origin": origin,
                "metadata": metadata,
                "labels": sorted(labels),
                "created_at": created_at.isoformat(),
            }
        )

    @classmethod
    def create(
        cls,
        object_id: str,
        object_type: str,
        origin: Dict[str, str],
        metadata: Dict[str, Any],
        labels: FrozenSet[str],
        created_at: datetime,
    ) -> "RuntimeObject":
        origin_copy = deepcopy(origin)
        metadata_copy = deepcopy(metadata)
        labels_copy = frozenset(labels)

        snapshot_hash = cls.compute_snapshot_hash(
            object_id=object_id,
            object_type=object_type,
            origin=origin_copy,
            metadata=metadata_copy,
            labels=labels_copy,
            created_at=created_at,
        )

        return cls(
            object_id=object_id,
            object_type=object_type,
            origin=origin_copy,
            metadata=metadata_copy,
            labels=labels_copy,
            created_at=created_at,
            snapshot_hash=snapshot_hash,
        )

    def snapshot(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "object_type": self.object_type,
            "origin": deepcopy(self.origin),
            "metadata": deepcopy(self.metadata),
            "labels": sorted(self.labels),
            "created_at": self.created_at.isoformat(),
            "snapshot_hash": self.snapshot_hash,
        }

    def with_labels(self, labels: FrozenSet[str] | set[str]) -> "RuntimeObject":
        """Return a new RuntimeObject with updated labels.

        Security notes:
        - Labels are treated as classification tags and may impact policy.
        - Returns a new immutable object; no in-place mutation.

        Time:  O(n) due to snapshot hash recompute
        Space: O(n) due to defensive copying
        """

        return RuntimeObject.create(
            object_id=self.object_id,
            object_type=self.object_type,
            origin=self.origin,
            metadata=self.metadata,
            labels=frozenset(labels),
            created_at=self.created_at,
        )

    def with_metadata(self, metadata: Dict[str, Any]) -> "RuntimeObject":
        """Return a new RuntimeObject with updated metadata.

        Security notes:
        - Metadata may include sensitive content; policy should govern export.

        Time:  O(n) due to snapshot hash recompute
        Space: O(n)
        """

        return RuntimeObject.create(
            object_id=self.object_id,
            object_type=self.object_type,
            origin=self.origin,
            metadata=metadata,
            labels=self.labels,
            created_at=self.created_at,
        )


    @classmethod
    def from_snapshot(cls, snap: Dict[str, Any]) -> "RuntimeObject":
        """Reconstruct a RuntimeObject from a snapshot dict.

        Security notes:
        - Snapshot input is untrusted; validate required keys.

        Time:  O(n) due to deep copies + snapshot hash recompute
        Space: O(n)
        """

        required = {"object_id", "object_type", "origin", "metadata", "labels", "created_at"}
        missing = required - set(snap.keys())
        if missing:
            raise ValueError(f"snapshot missing keys: {sorted(missing)}")

        created_at = datetime.fromisoformat(str(snap["created_at"]))
        labels = frozenset(str(x) for x in (snap.get("labels") or []))

        return cls.create(
            object_id=str(snap["object_id"]),
            object_type=str(snap["object_type"]),
            origin=dict(snap["origin"]),
            metadata=dict(snap["metadata"]),
            labels=labels,
            created_at=created_at,
        )
