from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Filenames used inside bundles.
SIGNATURE_JSON = "signature.json"
SIGNATURE_SIG = "signature.sig"
PUBLIC_KEY_PEM = "public_key.pem"


@dataclass(frozen=True)
class KeyPairPaths:
    """Generated key locations."""

    private_key_path: str
    public_key_path: str


def _canonical_json_bytes(obj: Mapping[str, Any]) -> bytes:
    """Canonical JSON serialization for signing.

    Security notes:
    - Uses stable key ordering and separators to avoid signature ambiguity.

    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def generate_ed25519_keypair(out_dir: str, *, prefix: str = "mimf_ed25519") -> KeyPairPaths:
    """Generate an Ed25519 keypair on disk (PEM).

    Security notes:
    - Private key is written unencrypted for simplicity; protect it with file permissions.
    - Consider encrypting at rest / using an HSM for production deployments.

    """

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_path = out / f"{prefix}_private.pem"
    pub_path = out / f"{prefix}_public.pem"

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

    return KeyPairPaths(private_key_path=str(priv_path), public_key_path=str(pub_path))


def load_private_key_pem(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM."""

    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("not an Ed25519 private key")
    return key


def load_public_key_pem(path: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM."""

    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    return key


def maybe_load_public_key_pem(path: Optional[str]) -> Optional[Ed25519PublicKey]:
    """Load a public key if a path is provided."""

    if not path:
        return None
    return load_public_key_pem(path)


def export_public_key_pem_from_private(private_key_path: str) -> bytes:
    """Derive and export the public key PEM from a private key."""

    priv = load_private_key_pem(private_key_path)
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_detached_ed25519(private_key_path: str, payload: Mapping[str, Any]) -> str:
    """Create a detached Ed25519 signature over a canonical JSON payload.

    Returns base64 signature.

    Security notes:
    - Only the canonical payload is signed (NOT the surrounding metadata).

    """

    priv = load_private_key_pem(private_key_path)
    msg = _canonical_json_bytes(payload)
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode("ascii")


def verify_detached_ed25519(
    public_key: Ed25519PublicKey, payload: Mapping[str, Any], signature_b64: str
) -> bool:
    """Verify a detached Ed25519 signature."""

    try:
        sig = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception:
        return False

    msg = _canonical_json_bytes(payload)
    try:
        public_key.verify(sig, msg)
        return True
    except Exception:
        return False


def signing_metadata(*, signer_id: Optional[str]) -> Mapping[str, Any]:
    """Standard signing metadata."""

    return {
        "schema": {"name": "mimf.bundle_signature", "version": "1.0"},
        "algorithm": "Ed25519",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "signer_id": signer_id,
    }
