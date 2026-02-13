from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping


def to_jsonable(obj: Any) -> Any:
    """
    Convert common Python objects to JSON-serializable equivalents.

    Security considerations:
    - bytes are base64-encoded to avoid binary injection / encoding issues.
    - does NOT execute or import anything dynamically.

    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # datetime/date -> ISO 8601
    if isinstance(obj, (datetime, date)):
        # keep timezone info if present
        return obj.isoformat()

    # pathlib
    if isinstance(obj, Path):
        return str(obj)

    # bytes -> base64 string
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_b64__": base64.b64encode(bytes(obj)).decode("ascii")}

    # dataclasses
    if is_dataclass(obj):
        return to_jsonable(asdict(obj))

    # mappings
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}

    # iterables (including set/frozenset/tuple/list)
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]

    # fallback: string representation
    return str(obj)
