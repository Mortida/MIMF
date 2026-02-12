import json
from datetime import datetime, UTC
from mimf.core.runtime.storage.sqlite_store import _json_dumps

def test_json_dumps_handles_datetime():
    s = _json_dumps({"t": datetime.now(UTC)})
    obj = json.loads(s)
    assert "t" in obj
