import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle
from mimf.forensic.bundle import verify_forensic_bundle_details
from mimf.forensic.custody import append_custody_event
from mimf.forensic.signing import generate_ed25519_keypair


def test_custody_append_and_verify(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "custody", "value": 1}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-c")
    ctx = RuntimeContext(context_id="ctx-c", operation_name="test:bundle")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    out_dir = tmp_path / "bundle"
    build_forensic_bundle(
        input_path=str(p),
        runtime_object=obj,
        context=ctx,
        out_dir=str(out_dir),
        include_original=False,
        sign=False,
    )

    keys_dir = tmp_path / "keys"
    kp = generate_ed25519_keypair(str(keys_dir), prefix="custody")

    append_custody_event(
        bundle_dir=str(out_dir),
        action="TRANSFERRED",
        actor_id="unit-test",
        note="handoff",
        signer_id="unit-test",
        signing_private_key_path=kp.private_key_path,
        embed_public_key=False,
    )

    details = verify_forensic_bundle_details(str(out_dir), public_key_path=kp.public_key_path)
    assert details["ok"] is True
    assert details["integrity_ok"] is True
    assert details["custody_present"] is True
    assert details["custody_ok"] is True
    assert details["custody_entry_count"] == 1
    assert details["custody_signature_present"] is True
    assert details["custody_signature_ok"] is True