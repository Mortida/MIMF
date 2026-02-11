import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector


def test_builtin_json_inspector_inspects_file(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text(json.dumps({"a": 1, "b": 2}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    assert plugin.metadata.plugin_id == "builtin.json_inspector"

    obj = plugin.inspect_file(str(p))
    snap = obj.snapshot()
    assert snap["metadata"]["json_summary"]["parsed"] is True
    obj = plugin.inspect_file(str(p))

    assert obj.object_type == "file"
    snap = obj.snapshot()
    assert snap["origin"]["path"].endswith("sample.json")
    assert "sha256" in snap["metadata"]
    assert snap["metadata"]["json_summary"]["parsed"] is True
    assert snap["metadata"]["json_summary"]["top_level_type"] == "dict"

    ctx = RuntimeContext(context_id="t1")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    assert len(ctx.get_events()) == 1
    assert ctx.verify_integrity() is True


def test_json_sniffing_selects_json_inspector_without_extension(tmp_path: Path) -> None:
    # No .json extension, but content is JSON.
    p = tmp_path / "payload.data"
    p.write_text('{"x": 1, "y": 2}', encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    assert plugin.metadata.plugin_id == "builtin.json_inspector"
