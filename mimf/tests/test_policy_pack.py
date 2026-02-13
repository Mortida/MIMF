from __future__ import annotations

from pathlib import Path

from mimf.core.policy_engine.policy_pack import load_policy_pack, resolve_policy_pack_path


def test_load_policy_pack_default() -> None:
    root = Path(__file__).resolve().parents[2]
    base_dir = root / "policy_packs"
    path = resolve_policy_pack_path("default", base_dir=str(base_dir), allow_arbitrary_paths=False)
    pack = load_policy_pack(path)

    assert (
        pack.pack_id in {"default", "default.yaml", "default.yml"}
        or pack.pack_id == Path(path).stem
    )
    assert pack.export_mode == "redact"
    assert "export:document.basic" in pack.allow_capabilities


def test_policy_pack_name_resolution_blocks_traversal() -> None:
    root = Path(__file__).resolve().parents[2]
    base_dir = root / "policy_packs"
    try:
        resolve_policy_pack_path(
            "../secrets.yaml", base_dir=str(base_dir), allow_arbitrary_paths=False
        )
        assert False, "expected traversal to be blocked"
    except ValueError:
        assert True
