import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle, append_custody_event
from mimf.forensic.custody import create_transfer_receipt
from mimf.forensic.signing import generate_ed25519_keypair
from mimf.forensic.timeline import load_bundle_timeline


def test_bundle_timeline_contains_events_and_custody(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "timeline", "value": 3}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-t")
    ctx = RuntimeContext(context_id="ctx-t", operation_name="test:bundle")
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

    # Add custody entry + transfer receipt
    keys_dir = tmp_path / "keys"
    sender = generate_ed25519_keypair(str(keys_dir), prefix="sender")

    append_custody_event(bundle_dir=str(out_dir), action="ACCESSED", actor_id="unit", note="viewed")
    create_transfer_receipt(
        bundle_dir=str(out_dir),
        from_actor_id="alice",
        to_actor_id="bob",
        note="handoff",
        signer_id="alice",
        signing_private_key_path=sender.private_key_path,
        embed_sender_public_key=False,
    )

    items = load_bundle_timeline(str(out_dir), limit_events=50, limit_custody=50)
    kinds = {it.kind for it in items}
    assert "event" in kinds
    assert "custody" in kinds
    assert "receipt" in kinds
