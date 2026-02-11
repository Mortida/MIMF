import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle
from mimf.forensic.bundle import verify_forensic_bundle_details
from mimf.forensic.custody import create_transfer_receipt, accept_transfer_receipt
from mimf.forensic.signing import generate_ed25519_keypair


def test_transfer_receipt_create_accept_and_verify(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "receipt", "value": 2}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-r")
    ctx = RuntimeContext(context_id="ctx-r", operation_name="test:bundle")
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
    sender = generate_ed25519_keypair(str(keys_dir), prefix="sender")
    receiver = generate_ed25519_keypair(str(keys_dir), prefix="receiver")

    create_transfer_receipt(
        bundle_dir=str(out_dir),
        from_actor_id="alice",
        to_actor_id="bob",
        note="handoff",
        signer_id="alice",
        signing_private_key_path=sender.private_key_path,
        embed_sender_public_key=False,
    )

    # Pending receipt should be detectable.
    details_pending = verify_forensic_bundle_details(
        str(out_dir),
        sender_public_key_path=sender.public_key_path,
        receiver_public_key_path=receiver.public_key_path,
    )
    assert details_pending["ok"] is True
    assert details_pending["custody_present"] is True
    assert details_pending["custody_receipt_count"] == 1
    assert details_pending["custody_receipt_pending"] == 1
    assert details_pending["receipt_sender_signature_ok"] is True
    # Receiver signature is absent, so we can't verify it.
    assert details_pending["receipt_receiver_signature_ok"] in (None, True)

    # Accept it.
    accept_transfer_receipt(
        bundle_dir=str(out_dir),
        receipt_relpath=None,
        receiver_actor_id="bob",
        signer_id="bob",
        signing_private_key_path=receiver.private_key_path,
        embed_receiver_public_key=False,
    )

    details_ok = verify_forensic_bundle_details(
        str(out_dir),
        sender_public_key_path=sender.public_key_path,
        receiver_public_key_path=receiver.public_key_path,
    )
    assert details_ok["ok"] is True
    assert details_ok["custody_receipt_pending"] == 0
    assert details_ok["receipt_sender_signature_ok"] is True
    assert details_ok["receipt_receiver_signature_ok"] is True
