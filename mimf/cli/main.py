from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from mimf.cli.client_cmds import register_client_commands
from mimf.core.normalization import (
    apply_normalized_export_policy,
    build_normalization_plan,
    normalize_runtime_object,
)
from mimf.core.plugins import (
    PluginRegistry,
    inspect_file_sandboxed,
    load_builtin_plugins,
    select_file_inspector,
)
from mimf.core.plugins.file_info import sniff_file_info
from mimf.core.policy_engine.policy_engine import PolicyEngine
from mimf.core.policy_engine.policy_pack import load_policy_pack, resolve_policy_pack_path
from mimf.core.policy_engine.policy_rules import AllowAllRule
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.default_executor import DefaultMutationExecutor
from mimf.core.runtime.dry_run_executor import DryRunExecutor
from mimf.core.runtime.inspection import Inspector
from mimf.core.runtime.mutation_pipeline import SafeMutationPipeline
from mimf.core.runtime.storage.sqlite_store import SQLiteRuntimeStore
from mimf.core.security.boundaries import SecurityBoundary
from mimf.forensic import (
    accept_transfer_receipt,
    append_custody_event,
    build_forensic_bundle,
    create_transfer_receipt,
    diff_bundles,
    load_bundle_timeline,
    render_timeline_text,
)
from mimf.forensic.bundle import verify_forensic_bundle_details
from mimf.forensic.signing import generate_ed25519_keypair
from mimf.utils.json_safe import to_jsonable

# cmd_append_custody


def _json_default(o):
    # Lazy import keeps CLI startup light and avoids circular imports
    from mimf.utils.json_safe import to_jsonable

    return to_jsonable(o)


# output


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the MIMF API server.

    Security notes:
    - If MIMF_API_KEYS is set, requests must provide X-MIMF-API-Key.
    - Bind to 127.0.0.1 by default (safer than 0.0.0.0).

    """

    try:
        import uvicorn
    except Exception as e:
        print(f"error: uvicorn is required to serve the API: {e}", file=sys.stderr)
        return 2

    try:
        from mimf.api.server import create_app
    except Exception as e:
        print(f"error: API server dependencies missing: {e}", file=sys.stderr)
        return 2

    app = create_app(db_path=args.db)
    uvicorn.run(app, host=args.host, port=int(args.port), log_level=args.log_level)
    return 0


def _read_json(path: str) -> dict:
    """Read a JSON file."""

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _pretty_print_bundle_summary(
    bundle_dir: str,
    *,
    verify: bool = False,
    events: int = 0,
    pubkey: str | None = None,
    custody_pubkey: str | None = None,
    sender_pubkey: str | None = None,
    receiver_pubkey: str | None = None,
) -> None:
    """Print a human-friendly bundle summary.

    Security notes:
    - Never prints the original file bytes.
    - Respects whatever redaction/denial already exists in file_summary.json.

    """

    manifest = _read_json(os.path.join(bundle_dir, "manifest.json"))
    summary_path = os.path.join(bundle_dir, "file_summary.json")
    summary = _read_json(summary_path) if os.path.exists(summary_path) else {}

    integrity_ok = None
    signature_ok = None
    signature_present = False
    signature_trusted = False
    signer_id = None
    custody_present = False
    custody_ok = None
    custody_entries = None
    custody_sig_present = False
    custody_sig_ok = None
    if verify:
        details = verify_forensic_bundle_details(
            bundle_dir,
            public_key_path=pubkey,
            custody_public_key_path=custody_pubkey,
            sender_public_key_path=sender_pubkey,
            receiver_public_key_path=receiver_pubkey,
        )
        integrity_ok = bool(details.get("integrity_ok"))
        signature_ok = details.get("signature_ok")
        signature_present = bool(details.get("signature_present"))
        signature_trusted = bool(details.get("signature_trusted"))
        signer_id = details.get("signer_id")
        custody_present = bool(details.get("custody_present", False))
        custody_ok = details.get("custody_ok")
        custody_entries = details.get("custody_entry_count")
        custody_sig_present = bool(details.get("custody_signature_present", False))
        custody_sig_ok = details.get("custody_signature_ok")

    print("\n=== MIMF Forensic Bundle ===")
    print(f"Bundle ID: {manifest.get('bundle_id')}")
    if integrity_ok is not None:
        print(f"Integrity: {'OK' if integrity_ok else 'FAIL'}")
        if signature_present:
            s = "OK" if signature_ok else ("UNKNOWN" if signature_ok is None else "FAIL")
            t = "trusted" if signature_trusted else "untrusted"
            print(f"Signature: {s} ({t})  signer_id={signer_id}")

        if custody_present:
            c = "OK" if custody_ok else "FAIL"
            print(f"Custody: {c}  entries={custody_entries}")
            if custody_sig_present:
                cs = "OK" if custody_sig_ok else ("UNKNOWN" if custody_sig_ok is None else "FAIL")
                print(f"Custody signature: {cs}")

    inp = (summary.get("input") or {}) if isinstance(summary, dict) else {}
    ins = (summary.get("inspection") or {}) if isinstance(summary, dict) else {}
    ext = (summary.get("extraction") or {}) if isinstance(summary, dict) else {}
    pol = (summary.get("export_policy") or {}) if isinstance(summary, dict) else {}

    print("\n--- File ---")
    print(f"Name: {inp.get('filename')}")
    print(f"MIME: {inp.get('mime_type')}  (confidence: {inp.get('mime_confidence')})")
    print(f"Size: {inp.get('size_bytes')} bytes")
    print(f"SHA-256: {inp.get('sha256')}")
    if inp.get("absolute_path"):
        print(f"Path: {inp.get('absolute_path')}")

    print("\n--- Inspection ---")
    print(f"Object: {ins.get('object_id')}  labels={ins.get('labels')}")
    print(f"Inspector: {ins.get('inspector_plugin_id')}")

    sig = ins.get("signals") if isinstance(ins, dict) else {}
    if isinstance(sig, dict) and sig.get("pdf"):
        pdf = sig.get("pdf")
        print("\n--- PDF Signals ---")
        print(f"Version: {pdf.get('version')}  MagicOK: {pdf.get('magic_ok')}")
        print(f"Linearized: {pdf.get('is_linearized')}  EOF marker: {pdf.get('has_eof_marker')}")
        print(
            f"Info ref present: {pdf.get('info_ref_present')}  Resolved keys: {pdf.get('info_resolved_keys')}"
        )
        print(f"XMP present: {pdf.get('xmp_present')}  XMP sha256: {pdf.get('xmp_sha256')}")

    print("\n--- Normalized (policy-controlled) ---")
    print(f"Normalizer: {ext.get('normalizer_id')}  Schema: {ext.get('schema_version')}")
    doc = ext.get("document") if isinstance(ext, dict) else {}
    if isinstance(doc, dict):
        print(f"Title: {doc.get('title')}")
        print(f"Author: {doc.get('author')}")
        print(f"Created: {doc.get('created_iso') or doc.get('created')}")
        print(f"Modified: {doc.get('modified_iso') or doc.get('modified')}")

    print("\n--- Export Policy ---")
    print(f"Status: {pol.get('status')}  Reason: {pol.get('reason')}")
    if pol.get("redacted_fields"):
        print(f"Redacted fields: {pol.get('redacted_fields')}")
    if pol.get("missing_capabilities"):
        print(f"Missing capabilities: {pol.get('missing_capabilities')}")
        print(
            "Hint: re-run export-bundle with --boundary-capability / --actor-capability to allow identifying/tooling export."
        )

    if events and events > 0:
        ev_path = os.path.join(bundle_dir, "events.jsonl")
        if os.path.exists(ev_path):
            print("\n--- Events (first %d) ---" % events)
            try:
                with open(ev_path, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        if i >= events:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        obj = json.loads(line)
                        print(
                            f"{i + 1}. {obj.get('event_type')}  at {obj.get('created_at')}  id={obj.get('event_id')}"
                        )
            except Exception:
                print("(Could not read events.jsonl)")


def cmd_list_plugins(_: argparse.Namespace) -> int:
    """List loaded plugins."""
    registry = PluginRegistry()
    load_builtin_plugins(registry)

    for p in registry.list_plugins():
        md = p.metadata
        actions = ",".join(sorted(md.allowed_actions))
        print(f"{md.plugin_id}  v{md.version}  actions=[{actions}]  name={md.name}")
    return 0


def _inspect_file_maybe_sandbox(plugin, path: str, object_id: str | None, sandbox: bool):
    """Inspect file either in-process or via a subprocess sandbox.

    Security notes:
    - Sandbox is best-effort isolation to reduce crash/DoS risk from hostile files.

    """

    if not sandbox:
        return plugin.inspect_file(path, object_id=object_id)

    res = inspect_file_sandboxed(
        plugin_id=plugin.metadata.plugin_id,
        path=path,
        object_id=object_id,
    )
    if not res.ok or res.runtime_object is None:
        raise RuntimeError(f"sandbox inspection failed: {res.error}")
    return res.runtime_object


def cmd_inspect_file(args: argparse.Namespace) -> int:
    """Inspect a local file into a RuntimeObject and emit an InspectionEvent.

    Security notes:
    - Treat file contents as untrusted; plugins must enforce safe parsing limits.

    """

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: not a regular file: {path}", file=sys.stderr)
        return 2

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, path)

    context = RuntimeContext(
        context_id=args.context_id or f"context-inspect-{int(datetime.now(timezone.utc).timestamp())}",
        actor_id=args.actor_id,
        operation_name="CLI:inspect-file",
    )

    runtime_object = _inspect_file_maybe_sandbox(
        plugin, path, object_id=args.object_id, sandbox=bool(getattr(args, "sandbox", False))
    )
    context.add_object(runtime_object)

    inspection_event = Inspector.inspect(runtime_object, context)

    output = {
        "plugin_id": plugin.metadata.plugin_id,
        "runtime_object": runtime_object.snapshot(),
        "inspection_event": inspection_event.to_payload(),
        "integrity_ok": context.verify_integrity(),
        "event_count": len(context.get_events()),
    }

    from mimf.utils.json_safe import to_jsonable

    print(json.dumps(to_jsonable(to_jsonable(output)), indent=2, sort_keys=True))

    return 0


def cmd_normalize_file(args: argparse.Namespace) -> int:
    """Inspect a file and attach normalized metadata via a mutation plan.

    Supported normalizers in this build:
    - PDF (application/pdf)
    - JSON (application/json and *+json)

    Security notes:
    - Normalized output may include sensitive document fields (title/author).
    - Uses an allow-all policy for CLI convenience; production should use real rules.

    """

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: not a regular file: {path}", file=sys.stderr)
        return 2

    info = sniff_file_info(path)

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, path)

    runtime_object = _inspect_file_maybe_sandbox(
        plugin,
        path,
        object_id=args.object_id,
        sandbox=bool(getattr(args, "sandbox", False)),
    )

    try:
        dispatch, plan = build_normalization_plan(runtime_object, info, plan_id=args.plan_id)
    except Exception as e:
        print(f"error: no normalizer available: {e}", file=sys.stderr)
        return 2

    context = RuntimeContext(
        context_id=args.context_id or f"context-normalize-{int(datetime.now(timezone.utc).timestamp())}",
        actor_id=args.actor_id,
        operation_name="CLI:normalize-file",
    )
    context.add_object(runtime_object)
    inspection_event = Inspector.inspect(runtime_object, context)

    engine = PolicyEngine(rules=[AllowAllRule()])
    executor_cls = DefaultMutationExecutor if args.apply else DryRunExecutor
    pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=executor_cls)

    pipeline.execute(plan, runtime_object, context=context, actor_id=args.actor_id)

    new_obj = context.get_object(runtime_object.object_id)

    output = {
        "plugin_id": plugin.metadata.plugin_id,
        "normalizer_id": dispatch.normalizer_id,
        "schema_version": dispatch.schema_version,
        "plan_id": plan.plan_id,
        "mutation_type": plan.mutation_type,
        "applied": bool(args.apply),
        "before": runtime_object.snapshot(),
        "after": new_obj.snapshot() if new_obj else None,
        "inspection_event": {
            "event_id": inspection_event.event_id,
            "event_type": inspection_event.event_type,
            "created_at": inspection_event.created_at,
            "object_id": inspection_event.object_id,
        },
        "integrity_ok": context.verify_integrity(),
        "event_count": len(context.get_events()),
    }

    print(json.dumps(output, indent=2, sort_keys=True, default=_json_default))
    return 0


def cmd_show_normalized(args: argparse.Namespace) -> int:
    """Inspect a file and print only the normalized document schema.

    This command does NOT create a mutation plan and does NOT mutate anything.

    Security notes:
    - Normalized output may include sensitive fields (e.g., PDF title/author).
    - Treat output as untrusted if you plan to ingest it elsewhere.

    """

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: not a regular file: {path}", file=sys.stderr)
        return 2

    info = sniff_file_info(path)

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, path)

    runtime_object = _inspect_file_maybe_sandbox(
        plugin, path, object_id=args.object_id, sandbox=bool(getattr(args, "sandbox", False))
    )
    dispatch, normalized, sources = normalize_runtime_object(runtime_object, info)

    # POLICY_PACK_OVERRIDES
    # If a policy pack is provided, it overrides boundary/actor/strict for export.
    boundary_caps = list(args.boundary_capability or [])
    actor_caps = list(args.actor_capability or [])
    strict_export = bool(args.strict)
    if getattr(args, "policy_pack", None):
        base_dir = Path(__file__).resolve().parents[3] / "policy_packs"
        resolved = resolve_policy_pack_path(
            str(args.policy_pack),
            base_dir=str(base_dir),
            allow_arbitrary_paths=False,
        )
        pack = load_policy_pack(resolved)
        boundary_caps = list(pack.allow_capabilities)
        actor_caps = list(pack.allow_capabilities)
        strict_export = pack.export_mode == "deny"
    boundary = SecurityBoundary.from_names(
        boundary_id=args.boundary_id,
        capability_names=list(boundary_caps),
    )

    export_result = apply_normalized_export_policy(
        normalized=normalized,
        target_labels=getattr(runtime_object, "labels", []),
        boundary=boundary,
        actor_capabilities=list(actor_caps),
        strict=bool(strict_export),
    )

    if export_result.decision.status.value == "DENY":
        print(
            json.dumps(
                {
                    "error": "export denied by policy",
                    "policy": export_result.decision.to_dict(),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3

    output = {
        "plugin_id": plugin.metadata.plugin_id,
        "normalizer_id": dispatch.normalizer_id,
        "schema_version": dispatch.schema_version,
        "normalized": export_result.redacted,
        "sources": sources,
        "export_policy": export_result.decision.to_dict(),
        "redacted_fields": export_result.redacted_fields,
    }

    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0


def cmd_export_bundle(args: argparse.Namespace) -> int:
    """Inspect a file, optionally normalize (dry-run/apply), and export a forensic bundle.

    This is the first "real-world" deliverable of MIMF: a shareable evidence container.

    Security notes:
    - By default, the original file is NOT copied into the bundle.
    - Normalized output is controlled by export policy and redacted/denied accordingly.
    - Bundle contents are integrity-protected (hashes + Merkle root), but not signed.

    """

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: not a regular file: {path}", file=sys.stderr)
        return 2

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, path)

    context = RuntimeContext(
        context_id=args.context_id or f"context-bundle-{int(datetime.now(timezone.utc).timestamp())}",
        actor_id=args.actor_id,
        operation_name="CLI:export-bundle",
    )

    runtime_object = _inspect_file_maybe_sandbox(
        plugin, path, object_id=args.object_id, sandbox=bool(getattr(args, "sandbox", False))
    )
    context.add_object(runtime_object)
    Inspector.inspect(runtime_object, context)

    # Try to attach normalization to the object inside the context so it appears in objects.jsonl.
    # If normalization is unavailable, we still build a bundle (generic normalizer exists).
    info = sniff_file_info(path)
    try:
        dispatch, plan = build_normalization_plan(runtime_object, info, plan_id=args.plan_id)
        engine = PolicyEngine(rules=[AllowAllRule()])
        executor_cls = DefaultMutationExecutor if args.apply else DryRunExecutor
        pipeline = SafeMutationPipeline(policy_engine=engine, executor_cls=executor_cls)
        pipeline.execute(plan, runtime_object, context=context, actor_id=args.actor_id)
    except Exception:
        # Fail open for bundling: we can still export inspection + raw signals.
        pass

    out_dir = args.out
    if not out_dir:
        out_dir = os.path.join(os.getcwd(), f"mimf_bundle_{int(datetime.now(timezone.utc).timestamp())}")

    # POLICY_PACK_OVERRIDES_EXPORT
    policy_pack = getattr(args, "policy_pack", None)
    boundary_caps = list(args.boundary_capability or [])
    actor_caps = list(args.actor_capability or [])
    strict_export = bool(args.strict)
    if policy_pack:
        base_dir = str(Path(__file__).resolve().parents[2].parent / "policy_packs")
        pack_path = resolve_policy_pack_path(
            policy_pack, base_dir=base_dir, allow_arbitrary_paths=False
        )
        pack = load_policy_pack(pack_path)
        boundary_caps = list(pack.allow_capabilities)
        actor_caps = list(pack.allow_capabilities)
        strict_export = pack.export_mode == "deny"

    boundary = SecurityBoundary.from_names(
        boundary_id=args.boundary_id,
        capability_names=list(boundary_caps),
    )

    result = build_forensic_bundle(
        input_path=path,
        runtime_object=runtime_object,
        context=context,
        out_dir=out_dir,
        include_original=bool(args.include_original),
        include_absolute_path=bool(args.include_absolute_path),
        boundary=boundary,
        actor_capabilities=list(actor_caps),
        strict_export=bool(strict_export),
        sign=bool(args.sign),
        signing_private_key_path=args.key,
        signer_id=args.signer_id,
        embed_public_key=bool(args.embed_pubkey),
    )

    zip_path = None
    if args.zip:
        # shutil.make_archive returns the archive path without the extension argument.
        base = result.out_dir.rstrip(os.sep)
        zip_path = shutil.make_archive(base, "zip", root_dir=result.out_dir)

    # Optional: persist the RuntimeContext for later retrieval/audit
    persisted = None
    if bool(getattr(args, "persist", False)):
        if not getattr(args, "db", None):
            print("error: --persist requires --db", file=sys.stderr)
            return 2
        store = SQLiteRuntimeStore(Path(args.db))
        try:
            store.save_context(context, overwrite=bool(getattr(args, "overwrite_context", False)))
            persisted = {"db": str(store.db_path), "context_id": context.context_id}
        except sqlite3.IntegrityError as e:
            print(
                f"error: context already exists in DB (use --overwrite-context): {e}",
                file=sys.stderr,
            )
            return 3
    summary_path = os.path.join(result.out_dir, "file_summary.json")
    summary = _read_json(summary_path) if os.path.exists(summary_path) else {}

    output = {
        "bundle_id": result.bundle_id,
        "out_dir": result.out_dir,
        "manifest_path": result.manifest_path,
        "merkle_root": result.merkle_root,
        "event_chain_ok": result.event_chain_ok,
        "event_chain_tip": result.event_chain_tip,
        "file_summary_path": summary_path,
        "normalized_path": os.path.join(result.out_dir, "normalized.json"),
        "sources_path": os.path.join(result.out_dir, "sources.json"),
        "export_policy": (summary.get("export_policy") if isinstance(summary, dict) else None),
        "zip": zip_path,
        "persisted": persisted,
    }

    if args.pretty:
        _pretty_print_bundle_summary(result.out_dir, verify=False, events=int(args.events or 0))
    else:
        print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0


def cmd_show_bundle(args: argparse.Namespace) -> int:
    """Show a human-friendly summary of a bundle."""

    bundle_dir = os.path.abspath(args.bundle_dir)
    if not os.path.exists(bundle_dir):
        print(f"error: bundle not found: {bundle_dir}", file=sys.stderr)
        return 2
    if not os.path.isdir(bundle_dir):
        print(f"error: not a directory: {bundle_dir}", file=sys.stderr)
        return 2

    if args.json:
        # Dump combined view for tools.
        manifest = _read_json(os.path.join(bundle_dir, "manifest.json"))
        summary_path = os.path.join(bundle_dir, "file_summary.json")
        summary = _read_json(summary_path) if os.path.exists(summary_path) else {}
        out = {"manifest": manifest, "file_summary": summary}
        print(json.dumps(out, indent=2, sort_keys=True, default=str))
        return 0

    _pretty_print_bundle_summary(
        bundle_dir,
        verify=bool(args.verify),
        events=int(args.events or 0),
        pubkey=getattr(args, "pubkey", None),
        custody_pubkey=getattr(args, "custody_pubkey", None),
        sender_pubkey=getattr(args, "sender_pubkey", None),
        receiver_pubkey=getattr(args, "receiver_pubkey", None),
    )
    return 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    """Verify a forensic bundle directory."""

    details = verify_forensic_bundle_details(
        args.bundle_dir,
        public_key_path=args.pubkey,
        custody_public_key_path=getattr(args, "custody_pubkey", None),
        sender_public_key_path=getattr(args, "sender_pubkey", None),
        receiver_public_key_path=getattr(args, "receiver_pubkey", None),
    )
    print(json.dumps(details, indent=2, sort_keys=True))
    return 0 if details.get("ok") else 3


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair for signing bundles.

    Security notes:
    - Store the private key securely. Anyone with it can forge signatures.

    """

    out_dir = os.path.abspath(args.out_dir)
    kp = generate_ed25519_keypair(out_dir, prefix=args.prefix)
    print(
        json.dumps(
            {
                "private_key": kp.private_key_path,
                "public_key": kp.public_key_path,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_append_custody(args: argparse.Namespace) -> int:
    """Append a chain-of-custody event to an existing bundle.

    Security notes:
    - This does NOT rewrite existing bundle artifacts.
    - If signing is enabled, sign the addendum with an Ed25519 private key.

    """

    bundle_dir = os.path.abspath(args.bundle_dir)
    if not os.path.exists(bundle_dir) or not os.path.isdir(bundle_dir):
        print(f"error: bundle not found: {bundle_dir}", file=sys.stderr)
        return 2

    try:
        res = append_custody_event(
            bundle_dir=bundle_dir,
            action=args.action,
            actor_id=args.actor_id,
            note=args.note,
            signer_id=args.signer_id,
            signing_private_key_path=args.key,
            embed_public_key=bool(args.embed_pubkey),
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    out = {
        "bundle_dir": res.bundle_dir,
        "entry_relpath": res.entry_relpath,
        "entry_sha256": res.entry_sha256,
        "custody_merkle_root": res.custody_merkle_root,
        "addendum_path": res.addendum_path,
        "signature_path": res.signature_path,
    }
    print(json.dumps(to_jsonable(out), indent=2, sort_keys=True, default=str))
    return 0


def cmd_transfer_custody(args: argparse.Namespace) -> int:
    """Create a two-party transfer receipt (sender-signed).

    Security notes:
    - Receipt is additive evidence; does not rewrite base artifacts.
    - The sender signature binds to bundle base identifiers.

    """

    bundle_dir = os.path.abspath(args.bundle_dir)
    if not os.path.isdir(bundle_dir):
        print(f"error: bundle not found: {bundle_dir}", file=sys.stderr)
        return 2

    if not args.key:
        print("error: --key (sender private key) is required", file=sys.stderr)
        return 2

    try:
        res = create_transfer_receipt(
            bundle_dir=bundle_dir,
            from_actor_id=str(args.from_actor_id),
            to_actor_id=str(args.to_actor_id),
            note=args.note,
            signer_id=args.signer_id,
            signing_private_key_path=str(args.key),
            embed_sender_public_key=bool(args.embed_pubkey),
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    print(
        json.dumps(
            {
                "bundle_dir": res.bundle_dir,
                "receipt": res.receipt_relpath,
                "receipt_sha256": res.receipt_sha256,
                "custody_merkle_root": res.custody_merkle_root,
                "addendum_path": res.addendum_path,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_accept_transfer(args: argparse.Namespace) -> int:
    """Accept a transfer receipt by adding a receiver signature."""

    bundle_dir = os.path.abspath(args.bundle_dir)
    if not os.path.isdir(bundle_dir):
        print(f"error: bundle not found: {bundle_dir}", file=sys.stderr)
        return 2

    if not args.key:
        print("error: --key (receiver private key) is required", file=sys.stderr)
        return 2

    try:
        res = accept_transfer_receipt(
            bundle_dir=bundle_dir,
            receipt_relpath=args.receipt,
            receiver_actor_id=args.actor_id,
            signer_id=args.signer_id,
            signing_private_key_path=str(args.key),
            embed_receiver_public_key=bool(args.embed_pubkey),
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    print(
        json.dumps(
            {
                "bundle_dir": res.bundle_dir,
                "receipt": res.receipt_relpath,
                "receipt_sha256": res.receipt_sha256,
                "custody_merkle_root": res.custody_merkle_root,
                "addendum_path": res.addendum_path,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    """Render a chronological bundle timeline (events + custody + transfer receipts).

    Security notes:
    - Viewer only. No mutation.

    """

    bundle_dir = os.path.abspath(args.bundle_dir)
    if not os.path.isdir(bundle_dir):
        print(f"error: bundle not found: {bundle_dir}", file=sys.stderr)
        return 2

    items = load_bundle_timeline(
        bundle_dir,
        limit_events=int(args.events or 500),
        limit_custody=int(args.custody or 500),
    )

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "created_at": it.created_at,
                        "kind": it.kind,
                        "label": it.label,
                        "details": it.details,
                    }
                    for it in items
                ],
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
        return 0

    text = render_timeline_text(items, limit=int(args.limit or 0))
    print(text, end="")
    return 0


def cmd_bundle_diff(args: argparse.Namespace) -> int:
    """Diff two bundle directories."""

    try:
        d = diff_bundles(args.bundle_a, args.bundle_b, limit=int(args.limit or 200))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(d, indent=2, sort_keys=True, default=str))
        return 0

    # Pretty summary
    print("\n=== MIMF Bundle Diff ===")
    print(f"A: {d.get('bundle_a')}")
    print(f"B: {d.get('bundle_b')}")
    print(f"Same input SHA-256: {d.get('same_input_sha256')}")
    print(f"Input SHA-256 A: {d.get('input_sha256_a')}")
    print(f"Input SHA-256 B: {d.get('input_sha256_b')}")
    print(f"Merkle A: {d.get('merkle_root_a')}")
    print(f"Merkle B: {d.get('merkle_root_b')}")

    arts = d.get("artifacts") or {}
    print("\n--- Artifacts ---")
    print(
        f"Added: {len(arts.get('added') or [])}  Removed: {len(arts.get('removed') or [])}  Changed: {len(arts.get('changed') or [])}"
    )

    norm = d.get("normalized") or {}
    print("\n--- Normalized diffs ---")
    print(f"Diff count: {norm.get('diff_count')}")
    for it in (norm.get("doc_diffs") or [])[:10]:
        print(f"- {it.get('path')}: {it.get('a')} -> {it.get('b')}")
    if (norm.get("diff_count") or 0) > 10:
        print("(Showing first 10 diffs)")
    return 0


def cmd_db_init(args: argparse.Namespace) -> int:
    """Initialize a SQLite runtime store."""

    store = SQLiteRuntimeStore(Path(args.db))
    store.init_schema()
    print(json.dumps({"ok": True, "db": str(store.db_path)}, indent=2, sort_keys=True))
    return 0


def cmd_db_list_contexts(args: argparse.Namespace) -> int:
    """List contexts stored in a SQLite runtime store."""

    store = SQLiteRuntimeStore(Path(args.db))
    rows = store.list_contexts(limit=int(args.limit or 50))
    print(json.dumps(to_jsonable({"contexts": rows}), indent=2, sort_keys=True))
    return 0


def cmd_db_show_context(args: argparse.Namespace) -> int:
    """Show a stored context: objects + first N events.

    Security notes:
    - Stored metadata can be sensitive. This command prints raw snapshots.

    """

    store = SQLiteRuntimeStore(Path(args.db))
    ctx = store.load_context(str(args.context_id))

    # Summaries
    objects = list(ctx.get_objects().values())
    events = list(ctx.get_events())

    ev_n = max(0, int(args.events or 0))
    out = {
        "context": {
            "context_id": ctx.context_id,
            "created_at": ctx.created_at.isoformat(),
            "actor_id": ctx.actor_id,
            "parent_context_id": ctx.parent_context_id,
            "operation_name": ctx.operation_name,
            "object_count": len(objects),
            "event_count": len(events),
            "event_chain_ok": ctx.verify_integrity(),
            "event_chain_tip": (events[-1].event_hash if events else None),
        },
        "objects": [o.snapshot() for o in objects],
        "events": [
            e.to_payload()
            | {"previous_event_hash": e.previous_event_hash, "event_hash": e.event_hash}
            for e in events[:ev_n]
        ],
    }

    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    p = argparse.ArgumentParser(prog="mimf", description="MIMF CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("list-plugins", help="List built-in plugins")
    lp.set_defaults(func=cmd_list_plugins)

    ip = sub.add_parser("inspect-file", help="Inspect a local file")
    ip.add_argument("path", help="Path to file")
    ip.add_argument("--object-id", default=None, help="Override RuntimeObject.object_id")
    ip.add_argument("--context-id", default=None, help="Override RuntimeContext.context_id")
    ip.add_argument("--actor-id", default=None, help="Optional actor id")
    ip.add_argument("--sandbox", action="store_true", help="Run inspector in a subprocess sandbox")
    ip.set_defaults(func=cmd_inspect_file)

    np = sub.add_parser("normalize-file", help="Inspect a file and attach normalized metadata")
    np.add_argument("path", help="Path to file")
    np.add_argument("--object-id", default=None, help="Override RuntimeObject.object_id")
    np.add_argument("--context-id", default=None, help="Override RuntimeContext.context_id")
    np.add_argument("--actor-id", default=None, help="Optional actor id")
    np.add_argument("--plan-id", default=None, help="Override MutationPlan.plan_id")
    np.add_argument("--apply", action="store_true", help="Apply mutation (default is dry-run)")
    np.add_argument("--sandbox", action="store_true", help="Run inspector in a subprocess sandbox")
    np.set_defaults(func=cmd_normalize_file)

    sp = sub.add_parser(
        "show-normalized", help="Inspect a file and print normalized output (no mutation)"
    )
    sp.add_argument("path", help="Path to file")
    sp.add_argument("--object-id", default=None, help="Override RuntimeObject.object_id")
    sp.add_argument("--sandbox", action="store_true", help="Run inspector in a subprocess sandbox")
    sp.add_argument(
        "--policy-pack",
        default=None,
        help="Policy pack name/path (overrides boundary/actor/strict)",
    )
    sp.add_argument(
        "--boundary-id", default="export-bundle", help="Security boundary id for export"
    )
    sp.add_argument(
        "--boundary-capability",
        action="append",
        default=["export:document.basic"],
        help="Boundary allowed capability (repeatable)",
    )
    sp.add_argument(
        "--actor-capability",
        action="append",
        default=["export:document.basic"],
        help="Actor capability (repeatable)",
    )
    sp.add_argument(
        "--strict",
        action="store_true",
        help="Deny export instead of redacting when capabilities are missing",
    )
    sp.set_defaults(func=cmd_show_normalized)

    eb = sub.add_parser("export-bundle", help="Create a tamper-evident forensic export bundle")
    eb.add_argument("path", help="Path to file")
    eb.add_argument("--object-id", default=None, help="Override RuntimeObject.object_id")
    eb.add_argument("--sandbox", action="store_true", help="Run inspector in a subprocess sandbox")
    eb.add_argument("--context-id", default=None, help="Override RuntimeContext.context_id")
    eb.add_argument("--actor-id", default=None, help="Optional actor id")
    eb.add_argument("--plan-id", default=None, help="Override normalization MutationPlan.plan_id")
    eb.add_argument(
        "--policy-pack",
        default=None,
        help="Policy pack name/path (overrides boundary/actor/strict)",
    )
    eb.add_argument("--out", default=None, help="Output directory (created if missing)")
    eb.add_argument("--zip", action="store_true", help="Also create a .zip of the bundle directory")
    eb.add_argument(
        "--include-original", action="store_true", help="Copy the original file into the bundle"
    )
    eb.add_argument(
        "--include-absolute-path", action="store_true", help="Record absolute path in manifest"
    )
    eb.add_argument(
        "--apply", action="store_true", help="Apply normalization mutation (default is dry-run)"
    )
    eb.add_argument(
        "--boundary-id",
        default="export-bundle",
        help="Security boundary id used for normalized export",
    )
    eb.add_argument(
        "--boundary-capability",
        action="append",
        default=["export:document.basic"],
        help="Boundary allowed capability for export (repeatable)",
    )
    eb.add_argument(
        "--actor-capability",
        action="append",
        default=["export:document.basic"],
        help="Actor capability for export (repeatable)",
    )
    eb.add_argument(
        "--strict",
        action="store_true",
        help="Deny export instead of redacting when capabilities are missing",
    )
    eb.add_argument(
        "--pretty",
        action="store_true",
        help="Print a human-friendly report instead of JSON",
    )
    eb.add_argument(
        "--events",
        type=int,
        default=0,
        help="When using --pretty, include the first N events (default: 0)",
    )

    # Authenticity / signing
    eb.add_argument(
        "--sign",
        action="store_true",
        help="Create a detached Ed25519 signature for the bundle (authenticity)",
    )
    eb.add_argument(
        "--key",
        default=None,
        help="Path to Ed25519 PRIVATE key PEM (required with --sign)",
    )
    eb.add_argument(
        "--signer-id",
        default=None,
        help="Optional signer id (e.g., operator or system id)",
    )
    eb.add_argument(
        "--embed-pubkey",
        action="store_true",
        help="Embed the derived public key inside the bundle (convenient but not trusted)",
    )
    # Persistence (optional)
    eb.add_argument(
        "--db", default=None, help="SQLite DB path to persist RuntimeContext (optional)"
    )
    eb.add_argument(
        "--persist", action="store_true", help="Persist the RuntimeContext into --db after export"
    )
    eb.add_argument(
        "--overwrite-context",
        action="store_true",
        help="Overwrite existing context row when persisting",
    )

    eb.set_defaults(func=cmd_export_bundle)

    sb = sub.add_parser("show-bundle", help="Show a human-friendly summary of a bundle")
    sb.add_argument("bundle_dir", help="Path to bundle directory")
    sb.add_argument("--verify", action="store_true", help="Also verify bundle integrity")
    sb.add_argument(
        "--pubkey",
        default=None,
        help="Path to Ed25519 PUBLIC key PEM (enables signature verification)",
    )
    sb.add_argument(
        "--custody-pubkey",
        default=None,
        help="Path to Ed25519 PUBLIC key PEM for custody addendum (defaults to --pubkey)",
    )
    sb.add_argument(
        "--sender-pubkey",
        default=None,
        help="Path to sender Ed25519 PUBLIC key PEM (verifies transfer receipts)",
    )
    sb.add_argument(
        "--receiver-pubkey",
        default=None,
        help="Path to receiver Ed25519 PUBLIC key PEM (verifies transfer receipts)",
    )
    sb.add_argument(
        "--events",
        type=int,
        default=0,
        help="Include the first N events (default: 0)",
    )
    sb.add_argument("--json", action="store_true", help="Print raw JSON (manifest + file_summary)")
    sb.set_defaults(func=cmd_show_bundle)

    vb = sub.add_parser("verify-bundle", help="Verify a forensic bundle directory")
    vb.add_argument("bundle_dir", help="Path to bundle directory")
    vb.add_argument(
        "--pubkey",
        default=None,
        help="Path to Ed25519 PUBLIC key PEM (enables signature verification)",
    )
    vb.add_argument(
        "--custody-pubkey",
        default=None,
        help="Path to Ed25519 PUBLIC key PEM for custody addendum (defaults to --pubkey)",
    )
    vb.add_argument(
        "--sender-pubkey",
        default=None,
        help="Path to sender Ed25519 PUBLIC key PEM (verifies transfer receipts)",
    )
    vb.add_argument(
        "--receiver-pubkey",
        default=None,
        help="Path to receiver Ed25519 PUBLIC key PEM (verifies transfer receipts)",
    )
    vb.set_defaults(func=cmd_verify_bundle)

    kg = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing bundles")
    kg.add_argument("out_dir", help="Directory to write keys into")
    kg.add_argument(
        "--prefix",
        default="mimf_ed25519",
        help="Filename prefix for the generated key files",
    )
    kg.set_defaults(func=cmd_keygen)

    ce = sub.add_parser(
        "append-custody", help="Append a chain-of-custody event to an existing bundle"
    )
    ce.add_argument("bundle_dir", help="Path to bundle directory")
    ce.add_argument("action", help="Custody action (e.g., CREATED, TRANSFERRED, ACCESSED)")
    ce.add_argument("--actor-id", default=None, help="Optional actor id")
    ce.add_argument("--note", default=None, help="Optional free-text note")
    ce.add_argument("--signer-id", default=None, help="Optional signer id")
    ce.add_argument(
        "--key", default=None, help="Path to Ed25519 PRIVATE key PEM (signs custody addendum)"
    )
    ce.add_argument(
        "--embed-pubkey",
        action="store_true",
        help="Embed derived public key in custody/public_key.pem (convenient but not trusted)",
    )
    ce.set_defaults(func=cmd_append_custody)

    tr = sub.add_parser("transfer-custody", help="Create a sender-signed transfer receipt")
    tr.add_argument("bundle_dir", help="Path to bundle directory")
    tr.add_argument("from_actor_id", help="Sender/owner id")
    tr.add_argument("to_actor_id", help="Receiver id")
    tr.add_argument("--note", default=None, help="Optional free-text note")
    tr.add_argument("--signer-id", default=None, help="Optional signer id")
    tr.add_argument("--key", default=None, help="Path to Ed25519 PRIVATE key PEM (sender)")
    tr.add_argument(
        "--embed-pubkey",
        action="store_true",
        help="Embed sender public key inside the receipt (convenient but not trusted)",
    )
    tr.set_defaults(func=cmd_transfer_custody)

    ac = sub.add_parser("accept-transfer", help="Accept a transfer receipt (receiver-signed)")
    ac.add_argument("bundle_dir", help="Path to bundle directory")
    ac.add_argument(
        "--receipt", default=None, help="Receipt relpath (default: latest pending receipt)"
    )
    ac.add_argument("--actor-id", default=None, help="Receiver actor id")
    ac.add_argument("--signer-id", default=None, help="Optional signer id")
    ac.add_argument("--key", default=None, help="Path to Ed25519 PRIVATE key PEM (receiver)")
    ac.add_argument(
        "--embed-pubkey",
        action="store_true",
        help="Embed receiver public key inside the receipt (convenient but not trusted)",
    )
    ac.set_defaults(func=cmd_accept_transfer)

    tl = sub.add_parser("timeline", help="Show a chronological timeline for a bundle")
    tl.add_argument("bundle_dir", help="Path to bundle directory")
    tl.add_argument("--events", type=int, default=500, help="Max events to read from events.jsonl")
    tl.add_argument("--custody", type=int, default=500, help="Max custody artifacts to read")
    tl.add_argument("--limit", type=int, default=0, help="Limit timeline rows (0=all)")
    tl.add_argument("--json", action="store_true", help="Print JSON")
    tl.set_defaults(func=cmd_timeline)

    bd = sub.add_parser("bundle-diff", help="Diff two bundle directories")
    bd.add_argument("bundle_a", help="Path to bundle A")
    bd.add_argument("bundle_b", help="Path to bundle B")
    bd.add_argument("--limit", type=int, default=200, help="Max diff entries")
    bd.add_argument("--json", action="store_true", help="Print JSON diff")
    bd.set_defaults(func=cmd_bundle_diff)

    # --- SQLite runtime store commands ---
    dbi = sub.add_parser("db-init", help="Initialize a SQLite runtime store")
    dbi.add_argument("--db", required=True, help="Path to SQLite DB file")
    dbi.set_defaults(func=cmd_db_init)

    dbl = sub.add_parser("db-list-contexts", help="List contexts stored in a SQLite runtime store")
    dbl.add_argument("--db", required=True, help="Path to SQLite DB file")
    dbl.add_argument("--limit", type=int, default=50, help="Max contexts to show")
    dbl.set_defaults(func=cmd_db_list_contexts)

    dbs = sub.add_parser("db-show-context", help="Show a stored context (objects + events)")
    dbs.add_argument("context_id", help="Context ID")
    dbs.add_argument("--db", required=True, help="Path to SQLite DB file")
    dbs.add_argument("--events", type=int, default=25, help="Number of events to include")
    dbs.set_defaults(func=cmd_db_show_context)

    # --- API server ---
    sv = sub.add_parser("serve", help="Run the MIMF FastAPI server")
    sv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    sv.add_argument("--db", default=None, help="Optional SQLite DB path for persistence endpoints")
    sv.add_argument("--log-level", default="info", help="Uvicorn log level")
    sv.set_defaults(func=cmd_serve)

    # --- API client + demo ---
    register_client_commands(sub)

    return p


def main(argv: List[str] | None = None) -> int:
    """CLI entry."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
