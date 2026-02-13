from pathlib import Path

from mimf.core.normalization import build_normalization_plan
from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.plugins.file_info import sniff_file_info


def test_dispatcher_falls_back_to_generic_normalizer(tmp_path: Path) -> None:
    p = tmp_path / "sample.txt"
    p.write_text("hello\n", encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))

    info = sniff_file_info(str(p))
    dispatch, plan = build_normalization_plan(obj, info)

    assert dispatch.normalizer_id == "generic"
    assert plan.mutation_type == "normalize:generic-metadata"
    assert plan.changes["normalized"]["document"]["content_type"] == info.mime_type
    assert plan.changes["normalized"]["schema"]["name"] == "mimf.document"
