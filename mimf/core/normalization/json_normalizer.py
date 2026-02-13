from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, Mapping, Optional

from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject

from .schema import build_document


@dataclass(frozen=True)
class NormalizationResult:
    """Structured output of a normalization routine."""

    schema_version: str
    normalized: Dict[str, Any]
    sources: Dict[str, Any]


def normalize_json_metadata(obj: RuntimeObject) -> NormalizationResult:
    """Normalize JSON-derived inspection metadata into a stable MIMF schema.

    Expected inspector output:
    - obj.metadata["json_summary"]

    Security notes:
    - Treat all inputs as attacker-controlled.
    - This function never parses JSON content; it only uses the inspector's summary.

    """

    md: Mapping[str, Any] = getattr(obj, "metadata", {}) or {}
    summary = md.get("json_summary") if isinstance(md, Mapping) else None
    js = summary if isinstance(summary, Mapping) else {}

    normalized: Dict[str, Any] = build_document(
        doc_format="json",
        content_type="application/json",
        title=None,
        author=None,
        subject=None,
        keywords=None,
        creator=None,
        producer=None,
        created=None,
        modified=None,
        signals={
            "parsed": bool(js.get("parsed")),
            "top_level_type": js.get("top_level_type"),
            "top_level_keys": js.get("top_level_keys"),
            "top_level_length": js.get("top_level_length"),
            "note": js.get("note"),
        },
    )

    sources: Dict[str, Any] = {
        "json_summary_present": bool(js),
    }

    return NormalizationResult(
        schema_version="mimf.document@1.0", normalized=normalized, sources=sources
    )


def build_json_normalization_plan(
    obj: RuntimeObject,
    *,
    plan_id: Optional[str] = None,
) -> MutationPlan:
    """Build a MutationPlan that attaches normalized JSON metadata."""

    res = normalize_json_metadata(obj)
    now = datetime.now(UTC)

    return MutationPlan(
        plan_id=plan_id or f"normalize-json-{int(now.timestamp())}",
        target_object_id=obj.object_id,
        mutation_type="normalize:json-metadata",
        changes={
            "normalized": res.normalized,
            "normalized_sources": res.sources,
        },
        allowed_labels=frozenset(getattr(obj, "labels", frozenset())),
        created_at=now,
    )
