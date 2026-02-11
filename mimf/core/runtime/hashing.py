import json
import hashlib
from datetime import datetime
from typing import Any

def _json_safe(value: Any) -> Any:
    """
    Convert values into a deterministic, JSON-serializable form.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    return value


def stable_event_hash(event_data: dict, previous_hash: str) -> str:
    """
    Compute deterministic hash for runtime events with previous hash linkage.
    """
    payload = {"event": event_data, "previous_event_hash": previous_hash}
    safe_payload = _json_safe(payload)
    serialized = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
