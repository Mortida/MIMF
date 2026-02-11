from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector


def test_builtin_generic_inspector_handles_txt(tmp_path: Path) -> None:
    p = tmp_path / "note.txt"
    p.write_text("hello world\n", encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    assert plugin.metadata.plugin_id == "builtin.generic_file_inspector"

    obj = plugin.inspect_file(str(p))
    snap = obj.snapshot()

    assert snap["origin"]["path"].endswith("note.txt")
    assert snap["metadata"]["sha256"]
    assert len(snap["metadata"]["sha256"]) == 64
    assert snap["metadata"]["extension"] == ".txt"
