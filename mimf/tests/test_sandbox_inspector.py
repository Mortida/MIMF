from __future__ import annotations

import json
from pathlib import Path

from mimf.core.plugins.sandbox import inspect_file_sandboxed


def test_sandbox_json_inspector_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text(json.dumps({"hello": "world", "n": 1}), encoding="utf-8")

    res = inspect_file_sandboxed(plugin_id="builtin.json_inspector", path=str(p), timeout_seconds=10, memory_limit_mb=256)
    assert res.ok, res.error
    assert res.runtime_object is not None
    obj = res.runtime_object
    assert obj.object_type == "file"
    assert obj.origin.get("path")
    md = obj.metadata
    assert md.get("sha256")
    assert md.get("inspector_plugin_id") == "builtin.json_inspector"
