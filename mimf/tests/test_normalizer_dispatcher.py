from pathlib import Path

from mimf.core.normalization import build_normalization_plan
from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.plugins.file_info import sniff_file_info


def test_dispatcher_builds_json_normalization_plan(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text('{"a": 1, "b": 2}', encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))

    info = sniff_file_info(str(p))
    dispatch, plan = build_normalization_plan(obj, info, plan_id="p1")

    assert dispatch.normalizer_id == "json"
    assert plan.plan_id == "p1"
    assert plan.mutation_type == "normalize:json-metadata"
    assert plan.changes["normalized"]["document"]["format"] == "json"


def test_dispatcher_builds_pdf_normalization_plan(tmp_path: Path) -> None:
    p = tmp_path / "sample.pdf"
    p.write_bytes(b"%PDF-1.4\n%%EOF\n")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))

    info = sniff_file_info(str(p))
    dispatch, plan = build_normalization_plan(obj, info)

    assert dispatch.normalizer_id == "pdf"
    assert plan.mutation_type == "normalize:pdf-metadata"
