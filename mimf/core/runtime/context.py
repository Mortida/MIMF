from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Tuple

from .events import RuntimeEvent
from .hashing import stable_event_hash
from .object import RuntimeObject


@dataclass
class RuntimeContext:
    """
    Authoritative execution ledger for a single MIMF runtime operation.

    Responsibilities
    - Register RuntimeObjects for the operation
    - Record RuntimeEvents in an append-only hash-chained log
    - Enforce monotonic event timestamps
    - Provide immutable external views of objects and events
    - Verify the cryptographic integrity of the recorded event chain

    Security invariants
    - Append-only event log
    - Hash-chain integrity (previous_event_hash + event_hash)
    - Thread-safe mutation using a lock
    - Immutable external snapshots (callers cannot mutate internal state)

    """

    context_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: Optional[str] = None
    parent_context_id: Optional[str] = None
    operation_name: Optional[str] = None

    _objects: Dict[str, RuntimeObject] = field(default_factory=dict, init=False, repr=False)
    _events: List[RuntimeEvent] = field(default_factory=list, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def upsert_object(self, obj) -> None:
        """
        Insert or replace an object by object_id.

        Security:
        - Safe for in-place operations where object_id identity is stable.
        - Prior state should still be preserved via events/audit logs elsewhere.

        """
        if not isinstance(obj, RuntimeObject):
            raise TypeError("Only RuntimeObject instances may be upserted")

        with self._lock:
            self._objects[obj.object_id] = obj

    def add_object(self, obj: RuntimeObject) -> "RuntimeContext":
        """
        Register a RuntimeObject in this context.

        Contract
        - Only RuntimeObject instances are accepted.
        - object_id must be unique within this context.

        Raises
        - TypeError: if obj is not a RuntimeObject.
        - RuntimeError: if obj.object_id already exists.
        """

        if not isinstance(obj, RuntimeObject):
            raise TypeError("Only RuntimeObject instances may be registered")

        with self._lock:
            if obj.object_id in self._objects:
                raise RuntimeError(f"Duplicate object_id detected: {obj.object_id}")
            self._objects[obj.object_id] = obj

        return self

    def emit_event(self, event: RuntimeEvent) -> "RuntimeContext":
        """
        Append and seal a RuntimeEvent into the context's event log.

        Hash-chain rules
        - The first event uses previous_hash = "GENESIS".
        - Each next event links to the previous event_hash.
        - Timestamps must be monotonic (no time regression).

        Security note
        - RuntimeEvent is frozen (immutable). We seal hash fields using object.__setattr__
          inside this trusted boundary only.

        Raises
        - TypeError: if event is not a RuntimeEvent.
        - RuntimeError: if timestamp regression is detected or chain is corrupted.
        """

        if not isinstance(event, RuntimeEvent):
            raise TypeError("Only RuntimeEvent instances may be emitted")

        with self._lock:
            if self._events:
                last_event = self._events[-1]
                previous_hash = last_event.event_hash
                last_ts = last_event.created_at

                if previous_hash is None:
                    raise RuntimeError("Event chain corruption: last event is not sealed")

                if event.created_at < last_ts:
                    raise RuntimeError(
                        f"Event timestamp regression detected ({event.created_at} < {last_ts})"
                    )
            else:
                previous_hash = "GENESIS"

            event_data = event.to_payload()
            event_hash = stable_event_hash(event_data, previous_hash)

            object.__setattr__(event, "previous_event_hash", previous_hash)
            object.__setattr__(event, "event_hash", event_hash)

            self._events.append(event)

        return self

    def get_object(self, object_id: str) -> RuntimeObject:
        """
        Retrieve a registered RuntimeObject by ID.

        Raises
        - KeyError if object_id is not present.
        """

        with self._lock:
            return self._objects[object_id]

    def get_objects(self) -> Mapping[str, RuntimeObject]:
        """
        Return an immutable snapshot of registered objects.

        Security note
        - deepcopy prevents callers from mutating internal dictionaries referenced by objects.
        - MappingProxyType prevents mutation of the returned mapping itself.
        """

        with self._lock:
            return MappingProxyType(deepcopy(self._objects))

    def get_events(self) -> Tuple[RuntimeEvent, ...]:
        """
        Return an immutable snapshot of recorded events in order.
        """

        with self._lock:
            return tuple(self._events)

    def verify_integrity(self) -> bool:
        """
        Verify cryptographic integrity of the event hash-chain.

        Returns
        - True if the chain is valid.
        - False if any event hash does not match recomputed value.
        """

        with self._lock:
            previous_hash = "GENESIS"

            for event in self._events:
                event_data = event.to_payload()
                expected_hash = stable_event_hash(event_data, previous_hash)

                if event.event_hash != expected_hash:
                    return False

                previous_hash = event.event_hash

        return True

    def _compute_expected_hash_for_event(self, event: RuntimeEvent, previous_hash: str) -> str:
        event_data = event.to_payload()
        return stable_event_hash(event_data, previous_hash)

    def update_object(self, obj: RuntimeObject) -> None:
        """
        Replace an existing object with the same object_id.

        Security: preserves object identity; history should be captured via events.
        """
        if not isinstance(obj, RuntimeObject):
            raise TypeError("Only RuntimeObject instances may be updated")

        with self._lock:
            if obj.object_id not in self._objects:
                raise RuntimeError(f"Cannot update missing object_id: {obj.object_id}")
            self._objects[obj.object_id] = obj
