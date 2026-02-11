from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Stream SHA-256 of a file.

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


def _read_json(path: Path) -> Dict[str, Any]:
    """Read JSON if it exists.

    Time:  O(n)
    Space: O(n)
    """

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        # Be resilient: bundles may be tampered with, producing invalid JSON.
        return {"_parse_error": str(e)}


def _deep_diff(a: Any, b: Any, *, prefix: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    """Compute a bounded deep diff between two JSON-ish values.

    Output entries: {"path": str, "a": Any, "b": Any}

    Time:  O(n) over visited nodes (bounded by limit)
    Space: O(limit)
    """

    out: List[Dict[str, Any]] = []

    def rec(x: Any, y: Any, p: str) -> None:
        if len(out) >= limit:
            return
        if type(x) != type(y):
            out.append({"path": p or "$", "a": x, "b": y})
            return
        if isinstance(x, dict):
            keys = set(x.keys()) | set(y.keys())
            for k in sorted(keys):
                if len(out) >= limit:
                    return
                nx = x.get(k)
                ny = y.get(k)
                rec(nx, ny, f"{p}.{k}" if p else str(k))
            return
        if isinstance(x, list):
            if len(x) != len(y):
                out.append({"path": p or "$", "a": f"len={len(x)}", "b": f"len={len(y)}"})
            # Compare shared prefix only.
            for i in range(min(len(x), len(y))):
                if len(out) >= limit:
                    return
                rec(x[i], y[i], f"{p}[{i}]")
            return
        if x != y:
            out.append({"path": p or "$", "a": x, "b": y})

    rec(a, b, prefix)
    return out


def diff_bundles(
    bundle_a: str,
    bundle_b: str,
    *,
    limit: int = 200,
) -> Dict[str, Any]:
    """Diff two forensic bundle directories.

    Security notes:
    - This is a local comparison tool; it never reads original file bytes.

    Time:  O(size(manifests)+size(normalized))
    Space: O(limit)
    """

    a = Path(os.path.abspath(bundle_a))
    b = Path(os.path.abspath(bundle_b))
    if not a.exists() or not a.is_dir():
        raise FileNotFoundError(str(a))
    if not b.exists() or not b.is_dir():
        raise FileNotFoundError(str(b))

    man_a = _read_json(a / "manifest.json")
    man_b = _read_json(b / "manifest.json")

    sum_a = _read_json(a / "file_summary.json") if (a / "file_summary.json").exists() else {}
    sum_b = _read_json(b / "file_summary.json") if (b / "file_summary.json").exists() else {}

    norm_a = _read_json(a / "normalized.json") if (a / "normalized.json").exists() else {}
    norm_b = _read_json(b / "normalized.json") if (b / "normalized.json").exists() else {}

    # Artifact sets from manifest, but we compare *actual* file bytes.
    def artifact_paths(man: Mapping[str, Any]) -> List[str]:
        out: List[str] = []
        for it in (man.get("artifacts") or []):
            if isinstance(it, dict) and it.get("relpath"):
                out.append(str(it["relpath"]))
        return out

    rels = set(artifact_paths(man_a)) | set(artifact_paths(man_b))

    def actual_hash_map(root: Path, relpaths: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for rel in relpaths:
            p = root / rel
            if p.exists() and p.is_file():
                out[rel] = _sha256_file(p)
        return out

    rels_list = sorted(rels)
    art_a = actual_hash_map(a, rels_list)
    art_b = actual_hash_map(b, rels_list)
    keys = set(art_a.keys()) | set(art_b.keys())
    added = sorted([k for k in keys if k not in art_a])
    removed = sorted([k for k in keys if k not in art_b])
    changed = sorted([k for k in keys if k in art_a and k in art_b and art_a[k] != art_b[k]])

    # Compare normalized document payload (policy-controlled) and signals
    doc_a = ((norm_a.get("normalized") or {}).get("document") if isinstance(norm_a, dict) else {}) or {}
    doc_b = ((norm_b.get("normalized") or {}).get("document") if isinstance(norm_b, dict) else {}) or {}
    diffs_doc = _deep_diff(doc_a, doc_b, prefix="document", limit=limit)

    sig_a = ((norm_a.get("normalized") or {}).get("signals") if isinstance(norm_a, dict) else {}) or {}
    sig_b = ((norm_b.get("normalized") or {}).get("signals") if isinstance(norm_b, dict) else {}) or {}
    diffs_signals = _deep_diff(sig_a, sig_b, prefix="signals", limit=max(0, limit - len(diffs_doc)))

    sha_a = ((sum_a.get("input") or {}).get("sha256") if isinstance(sum_a, dict) else None)
    sha_b = ((sum_b.get("input") or {}).get("sha256") if isinstance(sum_b, dict) else None)

    return {
        "bundle_a": str(a),
        "bundle_b": str(b),
        "same_input_sha256": bool(sha_a and sha_b and sha_a == sha_b),
        "input_sha256_a": sha_a,
        "input_sha256_b": sha_b,
        "bundle_id_a": man_a.get("bundle_id"),
        "bundle_id_b": man_b.get("bundle_id"),
        "merkle_root_a": ((man_a.get("integrity") or {}).get("merkle_root")),
        "merkle_root_b": ((man_b.get("integrity") or {}).get("merkle_root")),
        "artifacts": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "counts": {"a": len(art_a), "b": len(art_b)},
        },
        "normalized": {
            "doc_diffs": diffs_doc,
            "signals_diffs": diffs_signals,
            "diff_count": len(diffs_doc) + len(diffs_signals),
        },
    }
