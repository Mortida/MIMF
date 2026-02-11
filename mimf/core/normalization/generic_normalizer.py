from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Dict, Mapping, Optional

from mimf.core.plugins.file_info import FileInfo
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject

from .schema import build_document


@dataclass(frozen=True)
class NormalizationResult:
    """Structured output of a normalization routine.

    Time:  O(1)
    Space: O(1)
    """

    schema_version: str
    normalized: Dict[str, Any]
    sources: Dict[str, Any]


def normalize_generic_metadata(obj: RuntimeObject, info: FileInfo) -> NormalizationResult:
    """Normalize generic file inspection metadata into the stable MIMF schema.

    This is the fallback normalizer for unknown file types.

    Expected inspector output (generic file inspector):
    - obj.metadata["sha256"]
    - obj.metadata["size_bytes"]
    - obj.metadata["extension"]
    - obj.metadata["is_probably_binary"]

    Security notes:
    - Never parses file content.
    - Treats all values as untrusted and best-effort.

    Time:  O(1)
    Space: O(1)
    """

    md: Mapping[str, Any] = getattr(obj, "metadata", {}) or {}

    sha256 = md.get("sha256") if isinstance(md.get("sha256"), str) else None
    size_bytes = md.get("size_bytes") if isinstance(md.get("size_bytes"), int) else None
    extension = md.get("extension") if isinstance(md.get("extension"), str) else None
    is_bin = md.get("is_probably_binary") if isinstance(md.get("is_probably_binary"), bool) else None

    content_type = (info.mime_type or "application/octet-stream")
    doc_format = (info.extension.lstrip(".") or "unknown") if isinstance(info.extension, str) else "unknown"

    normalized = build_document(
        doc_format=doc_format,
        content_type=content_type,
        # Document fields unknown for generic file types.
        title=None,
        author=None,
        subject=None,
        keywords=None,
        creator=None,
        producer=None,
        created=None,
        modified=None,
        signals={
            "sha256": sha256,
            "size_bytes": size_bytes,
            "extension": extension,
            "is_probably_binary": is_bin,
            "mime_type": info.mime_type,
            "sniff_confidence": info.mime_confidence,
        },
    )

    sources: Dict[str, Any] = {
        "fallback": True,
        "generic_fields_present": {
            "sha256": bool(sha256),
            "size_bytes": size_bytes is not None,
            "extension": bool(extension),
            "is_probably_binary": is_bin is not None,
        },
    }

    return NormalizationResult(schema_version="mimf.document@1.0", normalized=normalized, sources=sources)


def build_generic_normalization_plan(
    obj: RuntimeObject,
    info: FileInfo,
    *,
    plan_id: Optional[str] = None,
) -> MutationPlan:
    """Build a MutationPlan that attaches normalized generic metadata.

    Time:  O(1)
    Space: O(1)
    """

    res = normalize_generic_metadata(obj, info)
    now = datetime.now(UTC)

    return MutationPlan(
        plan_id=plan_id or f"normalize-generic-{int(now.timestamp())}",
        target_object_id=obj.object_id,
        mutation_type="normalize:generic-metadata",
        changes={
            "normalized": res.normalized,
            "normalized_sources": res.sources,
        },
        allowed_labels=frozenset(getattr(obj, "labels", frozenset())),
        created_at=now,
    )
