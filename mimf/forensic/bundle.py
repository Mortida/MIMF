from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from mimf.core.normalization import (
    apply_normalized_export_policy,
    normalize_runtime_object,
)
from mimf.core.plugins.file_info import sniff_file_info
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.object import RuntimeObject
from mimf.core.security.boundaries import SecurityBoundary

from .merkle import merkle_root_hex, sha256_hex
from .signing import (
    SIGNATURE_JSON,
    SIGNATURE_SIG,
    PUBLIC_KEY_PEM,
    sign_detached_ed25519,
    maybe_load_public_key_pem,
    verify_detached_ed25519,
    export_public_key_pem_from_private,
    signing_metadata,
)

from .custody import verify_custody_addendum


_BUNDLE_SCHEMA = {
    "name": "mimf.forensic_bundle",
    # v1.1 adds artifact flag `in_merkle` and optional authenticity/signature files.
    "version": "1.1",
}


def _safe_basename(path: str) -> str:
    """Return a filename-safe basename.

    Security notes:
    - Prevent directory traversal by discarding directory components.
    - Replace path separators and control characters.

    Time:  O(n)
    Space: O(n)
    """

    base = os.path.basename(path)
    # Avoid weird control characters
    base = "".join(ch if ch.isprintable() else "_" for ch in base)
    base = base.replace(os.sep, "_")
    return base or "input"


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Stream SHA-256 of a file.

    Security notes:
    - Streaming avoids loading large files into memory.

    Time:  O(n)
    Space: O(1)
    """

    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class BundleArtifact:
    """One exported artifact entry."""

    name: str
    relpath: str
    sha256: str
    size_bytes: int
    content_type: str
    # Whether this artifact's hash was included in the bundle's Merkle root.
    # Note: some artifacts must be excluded to avoid circular dependencies
    # (e.g., hashes.txt) or to sign the bundle root (e.g., signature files).
    in_merkle: bool = True


@dataclass(frozen=True)
class BundleBuildResult:
    """Result of building a forensic bundle."""

    out_dir: str
    bundle_id: str
    manifest_path: str
    artifacts: List[BundleArtifact]
    merkle_root: str
    event_chain_ok: bool
    event_chain_tip: Optional[str]


def _pdf_date_to_iso(value: Optional[str]) -> Optional[str]:
    """Convert a common PDF date string into an ISO-8601 UTC-ish string.

    Accepts values like:
      D:20260113232345Z00'00'

    Security notes:
    - Input is attacker-controlled. Parser is strict and bounded.

    Time:  O(1)
    Space: O(1)
    """

    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v.startswith("D:"):
        return value

    # Minimal strict parser: YYYYMMDDHHmmSS
    core = v[2:16]
    if len(core) != 14 or not core.isdigit():
        return value
    try:
        dt = datetime(
            int(core[0:4]),
            int(core[4:6]),
            int(core[6:8]),
            int(core[8:10]),
            int(core[10:12]),
            int(core[12:14]),
            tzinfo=UTC,
        )
    except ValueError:
        return value
    return dt.isoformat()


def _build_file_summary(
    *,
    in_path: Path,
    info: Any,
    runtime_object: RuntimeObject,
    export_res: Any,
    normalizer_id: str,
    schema_version: str,
    normalized_out: Mapping[str, Any],
    sources_out: Any,
    include_absolute_path: bool,
) -> Dict[str, Any]:
    """Build a human-friendly, policy-controlled summary.

    Security notes:
    - Uses redacted/denied normalized output (never raw sensitive fields).
    - Avoids embedding raw file bytes.

    Time:  O(k) over extracted metadata keys (bounded)
    Space: O(k)
    """

    md = dict(getattr(runtime_object, "metadata", {}) or {})
    stat = dict(md.get("stat", {}) or {})

    # Inspector signals (safe, non-identifying). These can be useful even when
    # export policy redacts identifying/tooling fields.
    inspector_signals: Dict[str, Any] = {}
    pdf_meta = md.get("pdf")
    if isinstance(pdf_meta, Mapping):
        xmp = pdf_meta.get("xmp") if isinstance(pdf_meta.get("xmp"), Mapping) else {}
        info_resolved = pdf_meta.get("info_resolved") if isinstance(pdf_meta.get("info_resolved"), Mapping) else {}
        info_ref = pdf_meta.get("info_ref") if isinstance(pdf_meta.get("info_ref"), Mapping) else {}
        fields = xmp.get("fields") if isinstance(xmp.get("fields"), Mapping) else {}
        inspector_signals["pdf"] = {
            "magic_ok": pdf_meta.get("magic_ok"),
            "version": pdf_meta.get("version"),
            "is_linearized": pdf_meta.get("is_linearized"),
            "has_eof_marker": pdf_meta.get("has_eof_marker"),
            "info_ref_present": info_ref.get("present"),
            "info_resolved_keys": sorted(list(info_resolved.keys())),
            "xmp_present": xmp.get("present"),
            "xmp_sha256": xmp.get("sha256"),
            "xmp_fields_keys": sorted(list(fields.keys())),
            "xmp_creators_count": (
                len(fields.get("creators") or [])
                if isinstance(fields, Mapping) and isinstance(fields.get("creators"), list)
                else None
            ),
        }

    # PDF-friendly date normalization (if present in normalized doc)
    norm_doc = dict((normalized_out or {}).get("document", {}) or {})
    if isinstance(norm_doc.get("created"), str):
        norm_doc["created_iso"] = _pdf_date_to_iso(norm_doc.get("created"))
    if isinstance(norm_doc.get("modified"), str):
        norm_doc["modified_iso"] = _pdf_date_to_iso(norm_doc.get("modified"))

    # Signals: keep safe, high-value indicators even when identifying fields are redacted.
    signals = dict((normalized_out or {}).get("signals", {}) or {})

    missing_caps = []
    try:
        missing_caps = list((export_res.decision.metadata or {}).get("missing_capabilities", []) or [])
    except Exception:
        missing_caps = []

    return {
        "schema": {"name": "mimf.file_summary", "version": "1.0"},
        "input": {
            "filename": _safe_basename(str(in_path)),
            "absolute_path": str(in_path) if include_absolute_path else None,
            "size_bytes": int(in_path.stat().st_size),
            "sha256": md.get("sha256"),
            "extension": getattr(info, "extension", None),
            "mime_type": getattr(info, "mime_type", None),
            "mime_confidence": getattr(info, "mime_confidence", None),
            "stat": {
                "mtime": str(stat.get("mtime")) if stat.get("mtime") is not None else None,
                "ctime": str(stat.get("ctime")) if stat.get("ctime") is not None else None,
            },
        },
        "inspection": {
            "object_id": runtime_object.object_id,
            "object_type": getattr(runtime_object, "object_type", None),
            "labels": sorted(list(getattr(runtime_object, "labels", []) or [])),
            "inspector_plugin_id": md.get("inspector_plugin_id"),
            "signals": inspector_signals,
        },
        "extraction": {
            "normalizer_id": normalizer_id,
            "schema_version": schema_version,
            "document": norm_doc,
            "signals": signals,
            "sources_count": len(sources_out or []) if isinstance(sources_out, list) else None,
        },
        "export_policy": {
            "status": export_res.decision.status.value,
            "policy_id": export_res.decision.policy_id,
            "reason": export_res.decision.reason,
            "trace_id": export_res.decision.trace_id,
            "redacted_fields": list(export_res.redacted_fields or []),
            "missing_capabilities": missing_caps,
        },
    }


def build_forensic_bundle(
    *,
    input_path: str,
    runtime_object: RuntimeObject,
    context: RuntimeContext,
    out_dir: str,
    include_original: bool = False,
    include_absolute_path: bool = False,
    boundary: Optional[SecurityBoundary] = None,
    actor_capabilities: Optional[Iterable[str]] = None,
    strict_export: bool = False,
    sign: bool = False,
    signing_private_key_path: Optional[str] = None,
    signer_id: Optional[str] = None,
    embed_public_key: bool = False,
) -> BundleBuildResult:
    """Build a tamper-evident forensic bundle.

    Outputs (files)
    - manifest.json
    - hashes.txt
    - events.jsonl
    - objects.jsonl
    - normalized.json (policy-controlled)
    - sources.json
    - (optional) original/<filename>

    Security notes
    - Default is to NOT copy the original input file.
    - Normalized output is filtered by export policy.
    - Paths written inside the bundle are relative and sanitized.

    Time:  O(n + e + o) where n is input file size if include_original/hash, e events, o objects
    Space: O(1) extra besides JSON serialization buffers
    """

    in_path = Path(os.path.abspath(input_path))
    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError(str(in_path))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # --- export runtime evidence ---
    artifacts: List[BundleArtifact] = []

    def add_artifact(*, name: str, relpath: str, content_type: str, in_merkle: bool = True) -> None:
        """Hash and register an artifact.

        Time:  O(n) where n is artifact size (hashing)
        Space: O(1)
        """

        p = out / relpath
        artifacts.append(
            BundleArtifact(
                name=name,
                relpath=relpath,
                sha256=sha256_hex(p.read_bytes()),
                size_bytes=p.stat().st_size,
                content_type=content_type,
                in_merkle=bool(in_merkle),
            )
        )

    def write_json(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    def write_jsonl(path: Path, rows: List[Mapping[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(dict(r), sort_keys=True, default=str))
                f.write("\n")

    # events
    events_path = out / "events.jsonl"
    events_payloads = [e.to_payload() for e in context.get_events()]
    write_jsonl(events_path, events_payloads)
    add_artifact(name="events", relpath="events.jsonl", content_type="application/x-ndjson")

    # objects
    objects_path = out / "objects.jsonl"
    objs = context.get_objects()
    obj_payloads = [o.snapshot() for o in objs.values()]
    write_jsonl(objects_path, obj_payloads)
    add_artifact(name="objects", relpath="objects.jsonl", content_type="application/x-ndjson")

    # normalized + sources (policy filtered)
    info = sniff_file_info(str(in_path))
    dispatch, normalized, sources = normalize_runtime_object(runtime_object, info)

    boundary = boundary or SecurityBoundary.from_names(
        boundary_id="export-bundle",
        capability_names=["export:document.basic"],
    )

    export_res = apply_normalized_export_policy(
        normalized=normalized,
        target_labels=getattr(runtime_object, "labels", []),
        boundary=boundary,
        actor_capabilities=list(actor_capabilities or []),
        strict=bool(strict_export),
    )

    if export_res.decision.status.value == "DENY":
        # Fail-closed: export bundle can still be created, but normalized content is omitted.
        normalized_out: Mapping[str, Any] = {
            "error": "export denied by policy",
            "policy": export_res.decision.to_dict(),
        }
        sources_out: Any = []
    else:
        normalized_out = export_res.redacted
        sources_out = sources

    # One-stop summary for humans (policy-controlled)
    summary_path = out / "file_summary.json"
    summary_obj = _build_file_summary(
        in_path=in_path,
        info=info,
        runtime_object=runtime_object,
        export_res=export_res,
        normalizer_id=dispatch.normalizer_id,
        schema_version=dispatch.schema_version,
        normalized_out=normalized_out,
        sources_out=sources_out,
        include_absolute_path=bool(include_absolute_path),
    )
    write_json(summary_path, summary_obj)
    add_artifact(name="file_summary", relpath="file_summary.json", content_type="application/json")

    normalized_path = out / "normalized.json"
    write_json(
        normalized_path,
        {
            "normalizer_id": dispatch.normalizer_id,
            "schema_version": dispatch.schema_version,
            "normalized": normalized_out,
            "export_policy": export_res.decision.to_dict(),
            "redacted_fields": export_res.redacted_fields,
        },
    )
    add_artifact(name="normalized", relpath="normalized.json", content_type="application/json")

    sources_path = out / "sources.json"
    write_json(sources_path, {"sources": sources_out})
    add_artifact(name="sources", relpath="sources.json", content_type="application/json")

    # optional original copy
    if include_original:
        safe_name = _safe_basename(str(in_path))
        orig_rel = f"original/{safe_name}"
        orig_path = out / orig_rel
        orig_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(in_path), str(orig_path))
        artifacts.append(
            BundleArtifact(
                name="original",
                relpath=orig_rel,
                sha256=_sha256_file(orig_path),
                size_bytes=orig_path.stat().st_size,
                content_type=info.mime_type or "application/octet-stream",
                in_merkle=True,
            )
        )

    # Compute deterministic root from artifact hashes.
    # Exclude certain late artifacts to avoid circular dependencies.
    merkle_root = merkle_root_hex([a.sha256 for a in artifacts if a.in_merkle])

    # Event chain integrity summary.
    event_chain_ok = context.verify_integrity()
    tip = context.get_events()[-1].event_hash if context.get_events() else None

    # Bundle id: tie together merkle root + event chain tip.
    bundle_id = sha256_hex(f"{merkle_root}:{tip or 'NO_EVENTS'}".encode("utf-8"))[:16]

    signature_info: Optional[Dict[str, Any]] = None

    # --- optional authenticity: detached Ed25519 signature ---
    # We sign a canonical payload (not the whole manifest) to avoid circular
    # dependencies and to keep the signed claims minimal and stable.
    if sign:
        if not signing_private_key_path:
            raise ValueError("signing_private_key_path is required when sign=True")

        signed_payload: Dict[str, Any] = {
            "bundle_id": bundle_id,
            "merkle_root": merkle_root,
            "event_chain_tip": tip,
            # Bind artifact content to the signature.
            "artifacts": {a.relpath: a.sha256 for a in artifacts if a.in_merkle},
        }

        sig_b64 = sign_detached_ed25519(signing_private_key_path, signed_payload)

        sig_meta = dict(signing_metadata(signer_id=signer_id))
        sig_meta["signed_payload"] = signed_payload

        # Keep a reference for manifest/UI output.
        signature_info = sig_meta

        if embed_public_key:
            sig_meta["public_key_pem"] = export_public_key_pem_from_private(signing_private_key_path).decode(
                "utf-8", errors="replace"
            )

        sig_json_path = out / SIGNATURE_JSON
        sig_sig_path = out / SIGNATURE_SIG
        sig_sig_path.write_text(sig_b64 + "\n", encoding="utf-8")
        write_json(sig_json_path, sig_meta)

        # Signatures are not included in the Merkle root (otherwise circular).
        add_artifact(name="signature_json", relpath=SIGNATURE_JSON, content_type="application/json", in_merkle=False)
        add_artifact(name="signature_sig", relpath=SIGNATURE_SIG, content_type="text/plain", in_merkle=False)

        if embed_public_key:
            pub_path = out / PUBLIC_KEY_PEM
            pub_path.write_text(sig_meta.get("public_key_pem") + "\n", encoding="utf-8")
            add_artifact(name="public_key", relpath=PUBLIC_KEY_PEM, content_type="application/x-pem-file", in_merkle=False)

    # Write hashes.txt for humans.
    hashes_lines = [
        # Hash list is for humans. This includes signature files too.
        f"{a.sha256}  {a.relpath}" for a in sorted(artifacts, key=lambda x: x.relpath)
    ] + [
        f"MERKLE_ROOT  {merkle_root}",
        f"EVENT_CHAIN_OK  {event_chain_ok}",
        f"EVENT_CHAIN_TIP  {tip or ''}",
        f"BUNDLE_ID  {bundle_id}",
    ]
    hashes_path = out / "hashes.txt"
    hashes_path.write_text("\n".join(hashes_lines) + "\n", encoding="utf-8")
    # Exclude hashes.txt from Merkle root to avoid circular dependency.
    add_artifact(name="hashes", relpath="hashes.txt", content_type="text/plain", in_merkle=False)

    # Manifest last (it references hashes + merkle root, but we do not include manifest in merkle root).
    manifest = {
        "schema": _BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "created_at": datetime.now(UTC).isoformat(),
        "input": {
            "filename": _safe_basename(str(in_path)),
            "size_bytes": in_path.stat().st_size,
            "mime_type": info.mime_type,
            "sniff": {
                "extension": info.extension,
                "mime_confidence": getattr(info, "mime_confidence", ""),
            },
            "absolute_path": str(in_path) if include_absolute_path else None,
        },
        "runtime": {
            "context_id": context.context_id,
            "operation_name": context.operation_name,
            "actor_id": context.actor_id,
            "created_at": context.created_at.isoformat(),
            "event_chain_ok": event_chain_ok,
            "event_chain_tip": tip,
            "event_count": len(context.get_events()),
            "object_count": len(context.get_objects()),
        },
        "artifacts": [a.__dict__ for a in sorted(artifacts, key=lambda x: x.relpath)],
        "integrity": {
            "merkle_root": merkle_root,
            "bundle_tip": sha256_hex(f"{merkle_root}:{tip or 'NO_EVENTS'}".encode("utf-8")),
        },
        "authenticity": {
            "signed": bool(signature_info is not None),
            "signature_json": SIGNATURE_JSON if signature_info is not None else None,
            "signature_sig": SIGNATURE_SIG if signature_info is not None else None,
            "public_key": PUBLIC_KEY_PEM if (signature_info is not None and embed_public_key) else None,
            "signer_id": (signature_info or {}).get("signer_id") if signature_info else None,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "provenance_graph": {
            "nodes": [
                {"id": "input", "type": "file", "label": _safe_basename(str(in_path))},
                {"id": "obj", "type": "runtime_object", "label": runtime_object.object_id},
                {"id": "ctx", "type": "context", "label": context.context_id},
                {"id": "bundle", "type": "bundle", "label": bundle_id},
            ],
            "edges": [
                {"from": "input", "to": "obj", "type": "inspected_as"},
                {"from": "obj", "to": "ctx", "type": "registered_in"},
                {"from": "ctx", "to": "bundle", "type": "exported_into"},
            ],
        },
    }

    manifest_path = out / "manifest.json"
    write_json(manifest_path, manifest)

    return BundleBuildResult(
        out_dir=str(out),
        bundle_id=bundle_id,
        manifest_path=str(manifest_path),
        artifacts=artifacts,
        merkle_root=merkle_root,
        event_chain_ok=event_chain_ok,
        event_chain_tip=tip,
    )


def verify_forensic_bundle(bundle_dir: str) -> bool:
    """Verify a forensic bundle on disk.

    Checks
    - All artifact hashes match the manifest entries
    - Merkle root recomputes to manifest.integrity.merkle_root

    Security notes:
    - This verifies integrity, not authenticity.
    - For authenticity, add signing in a later milestone.

    Time:  O(total_bytes)
    Space: O(1)
    """

    details = verify_forensic_bundle_details(bundle_dir)
    return bool(details.get("ok"))


def verify_forensic_bundle_details(
    bundle_dir: str,
    *,
    public_key_path: Optional[str] = None,
    custody_public_key_path: Optional[str] = None,
    sender_public_key_path: Optional[str] = None,
    receiver_public_key_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a forensic bundle and return structured details.

    Security notes:
    - Integrity verification is local-only; does not contact any network.
    - Authenticity verification requires a trusted public key.

    Time:  O(total_bytes)
    Space: O(1)
    """

    root = Path(bundle_dir)
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "errors": ["missing manifest.json"]}

    errors: List[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_root = (manifest.get("integrity") or {}).get("merkle_root")
    artifacts = list(manifest.get("artifacts") or [])
    if not artifacts:
        return {"ok": False, "errors": ["missing artifacts list"]}

    # Verify each artifact hash from manifest.
    leaf_hashes: List[str] = []
    ALWAYS_EXCLUDE = {"manifest.json", "hashes.txt", SIGNATURE_JSON, SIGNATURE_SIG, PUBLIC_KEY_PEM}
    for a in artifacts:
        rel = a.get("relpath")
        expected = a.get("sha256")
        if not rel or not expected:
            errors.append("artifact missing relpath/sha256")
            continue
        p = root / rel
        if not p.exists() or not p.is_file():
            errors.append(f"missing artifact: {rel}")
            continue
        # Stream hashing to avoid memory spikes on large artifacts.
        actual = _sha256_file(p)
        if actual != expected:
            errors.append(f"hash mismatch: {rel}")

        in_merkle = a.get("in_merkle")
        if in_merkle is None:
            in_merkle = rel not in ALWAYS_EXCLUDE
        if bool(in_merkle):
            leaf_hashes.append(actual)

    actual_root = merkle_root_hex(leaf_hashes)
    integrity_ok = bool(expected_root) and actual_root == expected_root and not errors

    # Optional signature verification.
    authenticity = manifest.get("authenticity") or {}
    signature_present = bool((root / SIGNATURE_JSON).exists() and (root / SIGNATURE_SIG).exists())
    signature_ok: Optional[bool] = None
    signature_trusted: bool = False
    signer_id = authenticity.get("signer_id")

    if signature_present:
        try:
            sig_obj = json.loads((root / SIGNATURE_JSON).read_text(encoding="utf-8"))
            signed_payload = sig_obj.get("signed_payload") if isinstance(sig_obj, dict) else None
            sig_b64 = (root / SIGNATURE_SIG).read_text(encoding="utf-8").strip()

            pub = None
            if public_key_path:
                pub = maybe_load_public_key_pem(public_key_path)
                signature_trusted = bool(pub is not None)
            else:
                # Embedded keys are convenient, but not inherently trusted.
                embedded = sig_obj.get("public_key_pem") if isinstance(sig_obj, dict) else None
                if isinstance(embedded, str) and embedded.strip():
                    try:
                        from cryptography.hazmat.primitives import serialization
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

                        key = serialization.load_pem_public_key(embedded.encode("utf-8"))
                        if isinstance(key, Ed25519PublicKey):
                            pub = key
                    except Exception:
                        pub = None
                signature_trusted = False

            if not pub:
                signature_ok = None
            elif not isinstance(signed_payload, dict):
                signature_ok = False
                errors.append("signature.json missing signed_payload")
            else:
                signature_ok = verify_detached_ed25519(pub, signed_payload, sig_b64)
                if signature_ok is False:
                    errors.append("signature verification failed")

        except Exception:
            signature_ok = False
            errors.append("signature verification error")

    # Optional custody verification (addendum is outside the base Merkle root).
    custody_details = verify_custody_addendum(
        bundle_dir,
        public_key_path=custody_public_key_path or public_key_path,
        sender_public_key_path=sender_public_key_path,
        receiver_public_key_path=receiver_public_key_path,
    )

    ok = integrity_ok and (signature_ok in (None, True)) and bool(custody_details.get("custody_ok", True))
    out = {
        "ok": bool(ok),
        "integrity_ok": bool(integrity_ok),
        "expected_merkle_root": expected_root,
        "actual_merkle_root": actual_root,
        "signature_present": bool(signature_present),
        "signature_ok": signature_ok,
        "signature_trusted": bool(signature_trusted),
        "signer_id": signer_id,
        "errors": errors,
    }

    # Merge custody fields (namespaced).
    if isinstance(custody_details, dict):
        out.update(custody_details)
    return out
