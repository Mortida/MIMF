from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
from uuid import uuid4

from .merkle import merkle_root_hex, sha256_hex
from .signing import (
    export_public_key_pem_from_private,
    maybe_load_public_key_pem,
    sign_detached_ed25519,
    signing_metadata,
    verify_detached_ed25519,
)

CUSTODY_DIR = "custody"
RECEIPTS_DIR = f"{CUSTODY_DIR}/receipts"

ADDENDUM_JSON = f"{CUSTODY_DIR}/addendum.json"
ADDENDUM_SIG = f"{CUSTODY_DIR}/addendum.sig"
ADDENDUM_PUBKEY = f"{CUSTODY_DIR}/public_key.pem"

_ADDENDUM_SCHEMA = {"name": "mimf.bundle_addendum", "version": "1.1"}
_CUSTODY_EVENT_SCHEMA = {"name": "mimf.custody_event", "version": "1.0"}
_TRANSFER_RECEIPT_SCHEMA = {"name": "mimf.transfer_receipt", "version": "1.0"}


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Stream SHA-256 of a file."""

    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _canonical_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a deterministic JSON-ready dict.

    Security notes:
    - Canonicalization reduces signature ambiguity.

    """

    # json.dumps(sort_keys=True) later will do ordering; we ensure it's plain types.
    return json.loads(json.dumps(payload, sort_keys=True, default=str))


def _load_manifest_base(root: Path) -> Tuple[str, Optional[str], Optional[str], str]:
    """Load base identifiers from manifest.json.

    Returns: (bundle_id, merkle_root, event_chain_tip, manifest_sha256)

    """

    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError("missing manifest.json")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_bundle_id = str(manifest.get("bundle_id"))
    base_merkle_root = (manifest.get("integrity") or {}).get("merkle_root")
    base_event_tip = (manifest.get("runtime") or {}).get("event_chain_tip")
    base_manifest_sha256 = sha256_hex(manifest_path.read_bytes())
    return base_bundle_id, base_merkle_root, base_event_tip, base_manifest_sha256


def _load_addendum(root: Path) -> Dict[str, Any]:
    """Load addendum.json if present, else return a minimal structure."""

    addendum_file = root / ADDENDUM_JSON
    if not addendum_file.exists():
        return {}
    return json.loads(addendum_file.read_text(encoding="utf-8"))


def _compute_custody_merkle(entries: Mapping[str, str], receipts: Mapping[str, str]) -> str:
    """Compute custody Merkle root over entries + receipts in stored order."""

    leaf_hashes: List[str] = []
    # Preserve insertion order: dict preserves order in Python 3.7+
    for _, v in entries.items():
        leaf_hashes.append(str(v))
    for _, v in receipts.items():
        leaf_hashes.append(str(v))
    return merkle_root_hex(leaf_hashes)


def _write_addendum(
    root: Path,
    addendum_payload: Mapping[str, Any],
    *,
    signing_private_key_path: Optional[str] = None,
    signer_id: Optional[str] = None,
    embed_public_key: bool = False,
) -> Optional[str]:
    """Write addendum.json and optional detached signature.

    Security notes:
    - Signature (if present) covers only the canonical addendum payload (excluding authenticity).

    """

    payload = dict(addendum_payload)
    sig_path: Optional[str] = None

    if signing_private_key_path:
        meta = dict(signing_metadata(signer_id=signer_id))
        signed_claims = _canonical_payload(payload)
        meta["signed_payload"] = signed_claims
        if embed_public_key:
            meta["public_key_pem"] = export_public_key_pem_from_private(
                signing_private_key_path
            ).decode("utf-8", errors="replace")

        sig_b64 = sign_detached_ed25519(signing_private_key_path, signed_claims)
        (root / ADDENDUM_SIG).write_text(sig_b64 + "\n", encoding="utf-8")
        sig_path = str(root / ADDENDUM_SIG)

        payload = dict(payload)
        payload["authenticity"] = {
            "signer_id": meta.get("signer_id"),
            "signed_at": meta.get("signed_at"),
            "algorithm": meta.get("algorithm"),
        }
        if embed_public_key:
            (root / ADDENDUM_PUBKEY).write_text(meta.get("public_key_pem") + "\n", encoding="utf-8")

    (root / ADDENDUM_JSON).write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return sig_path


@dataclass(frozen=True)
class CustodyAppendResult:
    bundle_dir: str
    entry_relpath: str
    entry_sha256: str
    custody_merkle_root: str
    addendum_path: str
    signature_path: Optional[str]


def append_custody_event(
    *,
    bundle_dir: str,
    action: str,
    actor_id: Optional[str] = None,
    note: Optional[str] = None,
    signer_id: Optional[str] = None,
    signing_private_key_path: Optional[str] = None,
    embed_public_key: bool = False,
) -> CustodyAppendResult:
    """Append a chain-of-custody event to an existing bundle.

    Design
    - Does NOT rewrite existing bundle files.
    - Creates/updates custody/addendum.json (and optional addendum.sig).
    - Each custody entry is immutable once written.

    Security notes
    - Treat note/action as untrusted strings; we store them as data only.
    - If signing is enabled, signatures are detached and cover a canonical payload.

    """

    root = Path(bundle_dir)

    base_bundle_id, base_merkle_root, base_event_tip, base_manifest_sha256 = _load_manifest_base(
        root
    )

    custody_dir = root / CUSTODY_DIR
    custody_dir.mkdir(parents=True, exist_ok=True)

    add = _load_addendum(root)
    custody = add.get("custody") if isinstance(add.get("custody"), dict) else {}

    # Existing maps (preserve insertion order)
    entries = custody.get("entries") if isinstance(custody.get("entries"), dict) else {}
    receipts = custody.get("receipts") if isinstance(custody.get("receipts"), dict) else {}

    existing_entries: Dict[str, str] = {str(k): str(v) for k, v in entries.items()}
    existing_receipts: Dict[str, str] = {str(k): str(v) for k, v in receipts.items()}

    prev_entry_sha256: Optional[str] = (
        custody.get("tip_sha256") if isinstance(custody.get("tip_sha256"), str) else None
    )

    # Write new entry.
    now = datetime.now(UTC)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    entry_name = f"entry_{ts}_{uuid4().hex[:8]}.json"
    entry_rel = f"{CUSTODY_DIR}/{entry_name}"
    entry_path = root / entry_rel

    entry_obj: Dict[str, Any] = {
        "schema": _CUSTODY_EVENT_SCHEMA,
        "event_type": "CUSTODY",
        "created_at": now.isoformat(),
        "action": str(action),
        "actor_id": actor_id,
        "note": note,
        "base": {
            "bundle_id": base_bundle_id,
            "merkle_root": base_merkle_root,
            "event_chain_tip": base_event_tip,
            "manifest_sha256": base_manifest_sha256,
        },
        "prev_entry_sha256": prev_entry_sha256,
    }

    entry_path.write_text(
        json.dumps(entry_obj, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    entry_sha = _sha256_file(entry_path)

    existing_entries[entry_rel] = entry_sha

    custody_merkle_root = _compute_custody_merkle(existing_entries, existing_receipts)

    addendum_payload: Dict[str, Any] = {
        "schema": _ADDENDUM_SCHEMA,
        "created_at": now.isoformat(),
        "base": {
            "bundle_id": base_bundle_id,
            "merkle_root": base_merkle_root,
            "manifest_sha256": base_manifest_sha256,
        },
        "custody": {
            "entries": existing_entries,
            "entry_count": len(existing_entries),
            "tip_sha256": entry_sha,
            "receipts": existing_receipts,
            "receipt_count": len(existing_receipts),
            "receipt_tip_sha256": custody.get("receipt_tip_sha256"),
            "merkle_root": custody_merkle_root,
        },
    }

    sig_path = _write_addendum(
        root,
        addendum_payload,
        signing_private_key_path=signing_private_key_path,
        signer_id=signer_id,
        embed_public_key=embed_public_key,
    )

    return CustodyAppendResult(
        bundle_dir=str(root),
        entry_relpath=entry_rel,
        entry_sha256=entry_sha,
        custody_merkle_root=custody_merkle_root,
        addendum_path=str(root / ADDENDUM_JSON),
        signature_path=sig_path,
    )


@dataclass(frozen=True)
class TransferReceiptCreateResult:
    bundle_dir: str
    receipt_relpath: str
    receipt_sha256: str
    custody_merkle_root: str
    addendum_path: str


@dataclass(frozen=True)
class TransferReceiptAcceptResult:
    bundle_dir: str
    receipt_relpath: str
    receipt_sha256: str
    custody_merkle_root: str
    addendum_path: str


def create_transfer_receipt(
    *,
    bundle_dir: str,
    from_actor_id: str,
    to_actor_id: str,
    note: Optional[str] = None,
    signer_id: Optional[str] = None,
    signing_private_key_path: str,
    embed_sender_public_key: bool = False,
    related_entry_relpath: Optional[str] = None,
    related_entry_sha256: Optional[str] = None,
) -> TransferReceiptCreateResult:
    """Create a transfer receipt with a sender signature.

    Two-party design:
    - Sender signs the canonical transfer payload.
    - Receiver later signs the canonical object {transfer, sender_signature}.

    Security notes:
    - Does not rewrite base bundle artifacts.
    - Receipt is additive evidence.

    """

    root = Path(bundle_dir)
    base_bundle_id, base_merkle_root, base_event_tip, base_manifest_sha256 = _load_manifest_base(
        root
    )

    (root / RECEIPTS_DIR).mkdir(parents=True, exist_ok=True)

    add = _load_addendum(root)
    custody = add.get("custody") if isinstance(add.get("custody"), dict) else {}
    entries = custody.get("entries") if isinstance(custody.get("entries"), dict) else {}
    receipts = custody.get("receipts") if isinstance(custody.get("receipts"), dict) else {}

    existing_entries: Dict[str, str] = {str(k): str(v) for k, v in entries.items()}
    existing_receipts: Dict[str, str] = {str(k): str(v) for k, v in receipts.items()}

    now = datetime.now(UTC)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    receipt_name = f"receipt_{ts}_{uuid4().hex[:8]}.json"
    receipt_rel = f"{RECEIPTS_DIR}/{receipt_name}"
    receipt_path = root / receipt_rel

    transfer_payload: Dict[str, Any] = {
        "schema": {"name": "mimf.transfer", "version": "1.0"},
        "created_at": now.isoformat(),
        "from_actor_id": str(from_actor_id),
        "to_actor_id": str(to_actor_id),
        "note": note,
        "base": {
            "bundle_id": base_bundle_id,
            "merkle_root": base_merkle_root,
            "event_chain_tip": base_event_tip,
            "manifest_sha256": base_manifest_sha256,
        },
        "related_custody_entry": {
            "relpath": related_entry_relpath,
            "sha256": related_entry_sha256,
        },
    }

    sender_sig_b64 = sign_detached_ed25519(
        signing_private_key_path, _canonical_payload(transfer_payload)
    )

    receipt_obj: Dict[str, Any] = {
        "schema": _TRANSFER_RECEIPT_SCHEMA,
        "receipt_id": uuid4().hex,
        "transfer": transfer_payload,
        "signatures": {
            "sender": {
                **dict(signing_metadata(signer_id=signer_id)),
                "signature_b64": sender_sig_b64,
            },
            "receiver": None,
        },
    }

    if embed_sender_public_key:
        receipt_obj["public_keys"] = {
            "sender_public_key_pem": export_public_key_pem_from_private(
                signing_private_key_path
            ).decode("utf-8", errors="replace")
        }

    receipt_path.write_text(
        json.dumps(receipt_obj, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    receipt_sha = _sha256_file(receipt_path)

    existing_receipts[receipt_rel] = receipt_sha

    custody_merkle_root = _compute_custody_merkle(existing_entries, existing_receipts)

    addendum_payload: Dict[str, Any] = {
        "schema": _ADDENDUM_SCHEMA,
        "created_at": now.isoformat(),
        "base": {
            "bundle_id": base_bundle_id,
            "merkle_root": base_merkle_root,
            "manifest_sha256": base_manifest_sha256,
        },
        "custody": {
            "entries": existing_entries,
            "entry_count": len(existing_entries),
            "tip_sha256": custody.get("tip_sha256"),
            "receipts": existing_receipts,
            "receipt_count": len(existing_receipts),
            "receipt_tip_sha256": receipt_sha,
            "merkle_root": custody_merkle_root,
        },
    }

    _write_addendum(root, addendum_payload)

    return TransferReceiptCreateResult(
        bundle_dir=str(root),
        receipt_relpath=receipt_rel,
        receipt_sha256=receipt_sha,
        custody_merkle_root=custody_merkle_root,
        addendum_path=str(root / ADDENDUM_JSON),
    )


def _find_latest_pending_receipt(root: Path) -> Optional[str]:
    """Find the latest receipt missing a receiver signature."""

    add = _load_addendum(root)
    custody = add.get("custody") if isinstance(add.get("custody"), dict) else {}
    receipts = custody.get("receipts") if isinstance(custody.get("receipts"), dict) else {}
    last_pending: Optional[str] = None
    for rel in receipts.keys():
        p = root / str(rel)
        if not p.exists():
            continue
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            rec = (obj.get("signatures") or {}).get("receiver")
            if rec in (None, {}, ""):
                last_pending = str(rel)
        except Exception:
            continue
    return last_pending


def accept_transfer_receipt(
    *,
    bundle_dir: str,
    receipt_relpath: Optional[str] = None,
    receiver_actor_id: Optional[str] = None,
    signer_id: Optional[str] = None,
    signing_private_key_path: str,
    embed_receiver_public_key: bool = False,
) -> TransferReceiptAcceptResult:
    """Accept a transfer receipt by adding a receiver signature."""

    root = Path(bundle_dir)
    if receipt_relpath is None:
        receipt_relpath = _find_latest_pending_receipt(root)
    if not receipt_relpath:
        raise FileNotFoundError("no pending receipt found")

    receipt_path = root / str(receipt_relpath)
    if not receipt_path.exists():
        raise FileNotFoundError(f"missing receipt: {receipt_relpath}")

    obj = json.loads(receipt_path.read_text(encoding="utf-8"))
    transfer = obj.get("transfer")
    if not isinstance(transfer, dict):
        raise ValueError("receipt missing transfer payload")

    sigs = obj.get("signatures") if isinstance(obj.get("signatures"), dict) else {}
    sender = sigs.get("sender") if isinstance(sigs.get("sender"), dict) else None
    if not sender or not isinstance(sender.get("signature_b64"), str):
        raise ValueError("receipt missing sender signature")

    if sigs.get("receiver") not in (None, {}, ""):
        raise ValueError("receipt already has receiver signature")

    # Receiver signs (transfer + sender signature) to bind acceptance.
    receiver_payload = {
        "transfer": _canonical_payload(transfer),
        "sender_signature_b64": str(sender.get("signature_b64")),
        "receiver_actor_id": receiver_actor_id,
    }

    receiver_sig_b64 = sign_detached_ed25519(
        signing_private_key_path, _canonical_payload(receiver_payload)
    )

    sigs = dict(sigs)
    sigs["receiver"] = {
        **dict(signing_metadata(signer_id=signer_id)),
        "signature_b64": receiver_sig_b64,
        "actor_id": receiver_actor_id,
    }
    obj["signatures"] = sigs

    if embed_receiver_public_key:
        pk = obj.get("public_keys") if isinstance(obj.get("public_keys"), dict) else {}
        pk = dict(pk)
        pk["receiver_public_key_pem"] = export_public_key_pem_from_private(
            signing_private_key_path
        ).decode("utf-8", errors="replace")
        obj["public_keys"] = pk

    receipt_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    receipt_sha = _sha256_file(receipt_path)

    # Update addendum receipt hash.
    add = _load_addendum(root)
    custody = add.get("custody") if isinstance(add.get("custody"), dict) else {}
    entries = custody.get("entries") if isinstance(custody.get("entries"), dict) else {}
    receipts = custody.get("receipts") if isinstance(custody.get("receipts"), dict) else {}

    existing_entries: Dict[str, str] = {str(k): str(v) for k, v in entries.items()}
    existing_receipts: Dict[str, str] = {str(k): str(v) for k, v in receipts.items()}

    existing_receipts[str(receipt_relpath)] = receipt_sha

    custody_merkle_root = _compute_custody_merkle(existing_entries, existing_receipts)

    base_bundle_id, base_merkle_root, _, base_manifest_sha256 = _load_manifest_base(root)
    now = datetime.now(UTC)

    addendum_payload: Dict[str, Any] = {
        "schema": _ADDENDUM_SCHEMA,
        "created_at": now.isoformat(),
        "base": {
            "bundle_id": base_bundle_id,
            "merkle_root": base_merkle_root,
            "manifest_sha256": base_manifest_sha256,
        },
        "custody": {
            "entries": existing_entries,
            "entry_count": len(existing_entries),
            "tip_sha256": custody.get("tip_sha256"),
            "receipts": existing_receipts,
            "receipt_count": len(existing_receipts),
            "receipt_tip_sha256": receipt_sha,
            "merkle_root": custody_merkle_root,
        },
    }

    _write_addendum(root, addendum_payload)

    return TransferReceiptAcceptResult(
        bundle_dir=str(root),
        receipt_relpath=str(receipt_relpath),
        receipt_sha256=receipt_sha,
        custody_merkle_root=custody_merkle_root,
        addendum_path=str(root / ADDENDUM_JSON),
    )


def _verify_transfer_receipt_signatures(
    receipt_obj: Mapping[str, Any],
    *,
    sender_pubkey,
    receiver_pubkey,
) -> Tuple[Optional[bool], Optional[bool], List[str], bool]:
    """Verify sender/receiver signatures if keys are provided.

    Returns: (sender_ok, receiver_ok, errors, receiver_present)

    """

    errors: List[str] = []

    transfer = receipt_obj.get("transfer")
    if not isinstance(transfer, dict):
        return None, None, ["receipt missing transfer"], False

    sigs = receipt_obj.get("signatures") if isinstance(receipt_obj.get("signatures"), dict) else {}

    sender = sigs.get("sender") if isinstance(sigs.get("sender"), dict) else None
    receiver = sigs.get("receiver") if isinstance(sigs.get("receiver"), dict) else None

    sender_ok: Optional[bool] = None
    receiver_ok: Optional[bool] = None

    if sender_pubkey is not None:
        if not sender or not isinstance(sender.get("signature_b64"), str):
            sender_ok = False
            errors.append("missing sender signature")
        else:
            sender_ok = verify_detached_ed25519(
                sender_pubkey, _canonical_payload(transfer), str(sender.get("signature_b64"))
            )
            if sender_ok is False:
                errors.append("sender signature invalid")

    receiver_present = receiver is not None

    if receiver_pubkey is not None and receiver_present:
        if not isinstance(receiver.get("signature_b64"), str):
            receiver_ok = False
            errors.append("missing receiver signature")
        else:
            receiver_payload = {
                "transfer": _canonical_payload(transfer),
                "sender_signature_b64": (
                    sender.get("signature_b64") if isinstance(sender, dict) else None
                ),
                "receiver_actor_id": receiver.get("actor_id")
                if isinstance(receiver, dict)
                else None,
            }
            receiver_ok = verify_detached_ed25519(
                receiver_pubkey,
                _canonical_payload(receiver_payload),
                str(receiver.get("signature_b64")),
            )
            if receiver_ok is False:
                errors.append("receiver signature invalid")

    return sender_ok, receiver_ok, errors, receiver_present


def verify_custody_addendum(
    bundle_dir: str,
    *,
    public_key_path: Optional[str] = None,
    sender_public_key_path: Optional[str] = None,
    receiver_public_key_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify custody addendum (if present).

    Includes:
    - custody entries hashes
    - transfer receipts hashes
    - optional addendum signature verification
    - optional receipt signature verification if sender/receiver public keys are provided

    """

    root = Path(bundle_dir)
    add_path = root / ADDENDUM_JSON
    if not add_path.exists():
        return {"custody_present": False, "custody_ok": True}

    errors: List[str] = []
    add = json.loads(add_path.read_text(encoding="utf-8"))
    custody = add.get("custody") or {}

    entries = custody.get("entries") or {}
    receipts = custody.get("receipts") or {}

    expected_root = custody.get("merkle_root")
    expected_tip = custody.get("tip_sha256")
    expected_receipt_tip = custody.get("receipt_tip_sha256")

    if not isinstance(entries, dict):
        return {"custody_present": True, "custody_ok": False, "errors": ["entries not a dict"]}
    if not isinstance(receipts, dict):
        return {"custody_present": True, "custody_ok": False, "errors": ["receipts not a dict"]}

    # Verify each file hash from addendum.
    leaf_hashes: List[str] = []

    for rel, expected_sha in entries.items():
        p = root / str(rel)
        if not p.exists() or not p.is_file():
            errors.append(f"missing custody entry: {rel}")
            continue
        actual = _sha256_file(p)
        if str(expected_sha) != actual:
            errors.append(f"custody hash mismatch: {rel}")
        leaf_hashes.append(actual)

    receipt_pending_count = 0

    sender_pub = (
        maybe_load_public_key_pem(sender_public_key_path) if sender_public_key_path else None
    )
    receiver_pub = (
        maybe_load_public_key_pem(receiver_public_key_path) if receiver_public_key_path else None
    )

    receipt_sender_sig_ok: Optional[bool] = None
    receipt_receiver_sig_ok: Optional[bool] = None

    # For aggregate results: only compute True/False if we actually verified any.
    verified_sender_any = False
    verified_receiver_any = False

    for rel, expected_sha in receipts.items():
        p = root / str(rel)
        if not p.exists() or not p.is_file():
            errors.append(f"missing transfer receipt: {rel}")
            continue
        actual = _sha256_file(p)
        if str(expected_sha) != actual:
            errors.append(f"receipt hash mismatch: {rel}")
        leaf_hashes.append(actual)

        # Pending? (no receiver signature)
        try:
            robj = json.loads(p.read_text(encoding="utf-8"))
            recv = (robj.get("signatures") or {}).get("receiver")
            if recv in (None, {}, ""):
                receipt_pending_count += 1

            s_ok, r_ok, sig_errs, receiver_present = _verify_transfer_receipt_signatures(
                robj,
                sender_pubkey=sender_pub,
                receiver_pubkey=receiver_pub,
            )
            if sig_errs:
                errors.extend([f"{rel}: {e}" for e in sig_errs])

            if sender_pub is not None:
                verified_sender_any = True
                receipt_sender_sig_ok = (receipt_sender_sig_ok is not False) and (s_ok is not False)
            if receiver_pub is not None and receiver_present:
                verified_receiver_any = True
                receipt_receiver_sig_ok = (receipt_receiver_sig_ok is not False) and (
                    r_ok is not False
                )

        except Exception:
            # Non-fatal: hash verification already covers tampering.
            pass

    actual_root = merkle_root_hex(leaf_hashes)
    custody_ok = bool(expected_root) and actual_root == expected_root and not errors

    if expected_tip and isinstance(expected_tip, str) and entries:
        if expected_tip not in entries.values():
            errors.append("custody tip not in entries")
            custody_ok = False

    if expected_receipt_tip and isinstance(expected_receipt_tip, str) and receipts:
        if expected_receipt_tip not in receipts.values():
            errors.append("receipt tip not in receipts")
            custody_ok = False

    # Optional signature verification of addendum.
    sig_present = bool((root / ADDENDUM_SIG).exists())
    sig_ok: Optional[bool] = None
    sig_trusted = False
    signer_id = (add.get("authenticity") or {}).get("signer_id")

    if sig_present:
        sig_b64 = (root / ADDENDUM_SIG).read_text(encoding="utf-8").strip()
        signed_payload = _canonical_payload({k: v for k, v in add.items() if k != "authenticity"})

        pub = None
        if public_key_path:
            pub = maybe_load_public_key_pem(public_key_path)
            sig_trusted = bool(pub is not None)
        else:
            # Embedded custody public key is not trusted by default.
            embedded = None
            pub_path = root / ADDENDUM_PUBKEY
            if pub_path.exists():
                embedded = pub_path.read_text(encoding="utf-8")
            if isinstance(embedded, str) and embedded.strip():
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

                    key = serialization.load_pem_public_key(embedded.encode("utf-8"))
                    if isinstance(key, Ed25519PublicKey):
                        pub = key
                except Exception:
                    pub = None
            sig_trusted = False

        if not pub:
            sig_ok = None
        else:
            sig_ok = verify_detached_ed25519(pub, signed_payload, sig_b64)
            if sig_ok is False:
                errors.append("custody signature verification failed")
                custody_ok = False

    # Normalize aggregate receipt signature statuses
    if sender_pub is None or not verified_sender_any:
        receipt_sender_sig_ok = None
    else:
        receipt_sender_sig_ok = bool(receipt_sender_sig_ok)

    if receiver_pub is None or not verified_receiver_any:
        receipt_receiver_sig_ok = None
    else:
        receipt_receiver_sig_ok = bool(receipt_receiver_sig_ok)

    return {
        "custody_present": True,
        "custody_ok": bool(custody_ok),
        "custody_entry_count": int(custody.get("entry_count") or len(entries)),
        "custody_receipt_count": int(custody.get("receipt_count") or len(receipts)),
        "custody_receipt_pending": int(receipt_pending_count),
        "custody_expected_merkle_root": expected_root,
        "custody_actual_merkle_root": actual_root,
        "custody_signature_present": bool(sig_present),
        "custody_signature_ok": sig_ok,
        "custody_signature_trusted": bool(sig_trusted),
        "custody_signer_id": signer_id,
        "receipt_sender_signature_ok": receipt_sender_sig_ok,
        "receipt_receiver_signature_ok": receipt_receiver_sig_ok,
        "errors": errors,
    }
