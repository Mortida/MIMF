import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle, verify_forensic_bundle


# bundle2
def test_forensic_bundle_build_and_verify(tmp_path: Path) -> None:
    # Create a tiny JSON file so we exercise: plugin -> context -> bundle.
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "X", "value": 42}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-1")
    ctx = RuntimeContext(context_id="ctx-1", operation_name="test:bundle")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    out_dir = tmp_path / "bundle"
    res = build_forensic_bundle(
        input_path=str(p),
        runtime_object=obj,
        context=ctx,
        out_dir=str(out_dir),
        include_original=False,
    )

    assert res.bundle_id

    assert Path(res.manifest_path).exists()
    assert (out_dir / "events.jsonl").exists()
    assert (out_dir / "objects.jsonl").exists()
    assert (out_dir / "file_summary.json").exists()
    assert (out_dir / "normalized.json").exists()
    assert (out_dir / "sources.json").exists()
    assert (out_dir / "hashes.txt").exists()

    # Bundle verifies.
    assert verify_forensic_bundle(str(out_dir)) is True


def test_forensic_bundle_can_include_original_file(tmp_path: Path) -> None:
    p = tmp_path / "sample.txt"
    p.write_text("hello", encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p), object_id="obj-2")

    ctx = RuntimeContext(context_id="ctx-2")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    out_dir = tmp_path / "bundle2"
    build_forensic_bundle(
        input_path=str(p),
        runtime_object=obj,
        context=ctx,
        out_dir=str(out_dir),
        include_original=True,
    )

    # Original is copied into bundle/original/
    orig_dir = out_dir / "original"
    assert orig_dir.exists()
    assert any(orig_dir.iterdir())
    assert (out_dir / "file_summary.json").exists()
    assert verify_forensic_bundle(str(out_dir)) is True
