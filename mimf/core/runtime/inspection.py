from typing import Dict, Any
from .object import RuntimeObject
from .context import RuntimeContext
from .events import InspectionEvent

class Inspector:
    @staticmethod
    def inspect(obj: RuntimeObject, context: RuntimeContext) -> InspectionEvent:
        if not isinstance(obj, RuntimeObject):
            raise TypeError("obj must be a RuntimeObject")
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be a RuntimeContext")

        snapshot: Dict[str, Any] = {
            "object_id": obj.object_id,
            "object_type": obj.object_type,
            "labels": list(obj.labels),
            "metadata": dict(obj.metadata),
            "origin": obj.origin,
            "snapshot_hash": obj.snapshot_hash,
            "created_at": obj.created_at.isoformat()
        }

        event = InspectionEvent(object_id=obj.object_id, snapshot=snapshot)
        context.emit_event(event)
        return event

