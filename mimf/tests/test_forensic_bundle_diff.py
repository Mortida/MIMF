import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle
from mimf.forensic.diff import diff_bundles


def test_bundle_diff_detects_changed_artifact(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"x": 1}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj")
    ctx = RuntimeContext(context_id="ctx", operation_name="test:bundle")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    out_a = tmp_path / "bundle_a"
    build_forensic_bundle(input_path=str(p), runtime_object=obj, context=ctx, out_dir=str(out_a))

    # Build a second bundle, then tamper with normalized.json
    out_b = tmp_path / "bundle_b"
    build_forensic_bundle(input_path=str(p), runtime_object=obj, context=ctx, out_dir=str(out_b))
    (out_b / "normalized.json").write_text(
        (out_b / "normalized.json").read_text(encoding="utf-8") + "\n#tamper\n", encoding="utf-8"
    )

    d = diff_bundles(str(out_a), str(out_b), limit=50)
    assert "normalized.json" in (d.get("artifacts") or {}).get("changed", [])
