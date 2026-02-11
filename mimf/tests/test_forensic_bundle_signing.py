import json
from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.forensic import build_forensic_bundle
from mimf.forensic.bundle import verify_forensic_bundle_details
from mimf.forensic.signing import generate_ed25519_keypair


def test_forensic_bundle_sign_and_verify(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "X", "value": 42}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-1")
    ctx = RuntimeContext(context_id="ctx-1", operation_name="test:bundle")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    keys_dir = tmp_path / "keys"
    kp = generate_ed25519_keypair(str(keys_dir), prefix="test")

    out_dir = tmp_path / "bundle_signed"
    build_forensic_bundle(
        input_path=str(p),
        runtime_object=obj,
        context=ctx,
        out_dir=str(out_dir),
        include_original=False,
        sign=True,
        signing_private_key_path=kp.private_key_path,
        signer_id="unit-test",
        embed_public_key=False,
    )

    details = verify_forensic_bundle_details(str(out_dir), public_key_path=kp.public_key_path)
    assert details["ok"] is True
    assert details["integrity_ok"] is True
    assert details["signature_present"] is True
    assert details["signature_ok"] is True
    assert details["signature_trusted"] is True


def test_forensic_bundle_signature_fails_on_tamper(tmp_path: Path) -> None:
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps({"case": "Y", "value": 7}), encoding="utf-8")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p), object_id="obj-2")
    ctx = RuntimeContext(context_id="ctx-2", operation_name="test:bundle")
    ctx.add_object(obj)
    Inspector.inspect(obj, ctx)

    keys_dir = tmp_path / "keys2"
    kp = generate_ed25519_keypair(str(keys_dir), prefix="test")

    out_dir = tmp_path / "bundle_signed2"
    build_forensic_bundle(
        input_path=str(p),
        runtime_object=obj,
        context=ctx,
        out_dir=str(out_dir),
        include_original=False,
        sign=True,
        signing_private_key_path=kp.private_key_path,
        signer_id="unit-test",
        embed_public_key=False,
    )

    # Tamper with an in_merkle artifact.
    normalized = out_dir / "normalized.json"
    normalized.write_text(normalized.read_text(encoding="utf-8") + "\n#tamper\n", encoding="utf-8")

    details = verify_forensic_bundle_details(str(out_dir), public_key_path=kp.public_key_path)
    assert details["integrity_ok"] is False
    # Signature may still verify against the old payload, but overall ok must fail.
    assert details["ok"] is False
