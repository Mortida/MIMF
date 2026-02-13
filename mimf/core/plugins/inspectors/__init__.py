from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet


@dataclass(frozen=True)
class RuntimeObject:
    """
    Immutable runtime envelope for any object entering the MIMF system.

    This object represents a snapshot in time and must NEVER be mutated.
    Any change produces a new RuntimeObject with a new snapshot_hash.
    """

    object_id: str
    object_type: str
    origin: Dict[str, str]
    snapshot_hash: str
    metadata: Dict[str, Any]
    labels: FrozenSet[str]
    created_at: datetime
