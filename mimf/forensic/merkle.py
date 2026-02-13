from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest.

    Security notes:
    - SHA-256 provides strong collision resistance for integrity.
    - This is integrity-only; it does not provide authenticity.

    """

    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _hash_pair(left_hex: str, right_hex: str) -> str:
    """Hash a pair of hex digests deterministically."""

    return sha256_hex((left_hex + right_hex).encode("utf-8"))


def merkle_root_hex(leaves: Iterable[str]) -> str:
    """Compute a Merkle root from iterable of leaf hashes (hex strings).

    Rules
    - Input leaves are sorted lexicographically for deterministic roots.
    - If there is an odd number of nodes at a level, the last node is duplicated.
    - Empty input returns sha256("MIMF_EMPTY_MERKLE").

    Security notes:
    - Sorting makes the tree order-independent, which is useful for bundles.
    - Order-independence means the root does not encode artifact ordering.

    """

    nodes: List[str] = sorted(str(x) for x in leaves if str(x))
    if not nodes:
        return sha256_hex(b"MIMF_EMPTY_MERKLE")

    while len(nodes) > 1:
        nxt: List[str] = []
        i = 0
        while i < len(nodes):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            nxt.append(_hash_pair(left, right))
            i += 2
        nodes = nxt

    return nodes[0]


@dataclass(frozen=True)
class MerkleProof:
    """A simple inclusion proof placeholder.

    This is not yet used by the CLI, but the structure is here so we can extend
    bundles later with per-artifact inclusion proofs.

    Time/Space: O(p) where p is proof length.
    """

    leaf: str
    siblings: List[str]
