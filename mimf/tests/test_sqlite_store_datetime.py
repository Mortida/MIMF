import json
from datetime import datetime, timezone

from mimf.core.runtime.storage.sqlite_store import _json_dumps


def test_json_dumps_handles_datetime():
    s = _json_dumps({"t": datetime.now(timezone.utc)})
    obj = json.loads(s)
    assert "t" in obj
