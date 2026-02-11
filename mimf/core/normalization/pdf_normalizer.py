from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Dict, Mapping, Optional

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


def _pick_first(*vals: Optional[str]) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip() != "":
            return v.strip()
    return None


def normalize_pdf_metadata(obj: RuntimeObject) -> NormalizationResult:
    """Normalize PDF-derived inspection metadata into a stable MIMF schema.

    Expected inspector output:
    - obj.metadata["pdf"]["info_resolved"] (preferred)
    - obj.metadata["pdf"]["info_guess"] (fallback)
    - obj.metadata["pdf"]["xmp"] (signals)

    Security notes:
    - Treat all inputs as attacker-controlled strings.
    - This function is deterministic and bounded.

    Time:  O(1)
    Space: O(1)
    """

    md: Mapping[str, Any] = getattr(obj, "metadata", {}) or {}
    pdf: Mapping[str, Any] = (md.get("pdf") or {}) if isinstance(md, Mapping) else {}

    info_resolved = pdf.get("info_resolved")
    info_guess = pdf.get("info_guess")

    resolved: Mapping[str, Any] = info_resolved if isinstance(info_resolved, Mapping) else {}
    guessed: Mapping[str, Any] = info_guess if isinstance(info_guess, Mapping) else {}

    title = _pick_first(
        resolved.get("Title"),
        guessed.get("Title"),
    )
    author = _pick_first(
        resolved.get("Author"),
        guessed.get("Author"),
    )
    subject = _pick_first(
        resolved.get("Subject"),
        guessed.get("Subject"),
    )
    keywords = _pick_first(
        resolved.get("Keywords"),
        guessed.get("Keywords"),
    )
    creator = _pick_first(
        resolved.get("Creator"),
        guessed.get("Creator"),
    )
    producer = _pick_first(
        resolved.get("Producer"),
        guessed.get("Producer"),
    )
    creation_date = _pick_first(
        resolved.get("CreationDate"),
        guessed.get("CreationDate"),
    )
    mod_date = _pick_first(
        resolved.get("ModDate"),
        guessed.get("ModDate"),
    )

    xmp = pdf.get("xmp") if isinstance(pdf.get("xmp"), Mapping) else {}
    xmp_present = bool(xmp.get("present"))
    xmp_sha256 = xmp.get("sha256") if isinstance(xmp.get("sha256"), str) else None

    # Optional extracted XMP fields (best-effort, bounded by inspector).
    xmp_fields = xmp.get("fields") if isinstance(xmp.get("fields"), Mapping) else {}
    xmp_title = xmp_fields.get("title") if isinstance(xmp_fields.get("title"), str) else None
    xmp_creators = xmp_fields.get("creators") if isinstance(xmp_fields.get("creators"), list) else []
    xmp_author = xmp_creators[0] if xmp_creators else None
    xmp_keywords = xmp_fields.get("keywords") if isinstance(xmp_fields.get("keywords"), str) else None
    xmp_creator_tool = xmp_fields.get("creator_tool") if isinstance(xmp_fields.get("creator_tool"), str) else None
    xmp_producer = xmp_fields.get("producer") if isinstance(xmp_fields.get("producer"), str) else None
    xmp_created = xmp_fields.get("create_date") if isinstance(xmp_fields.get("create_date"), str) else None
    xmp_modified = xmp_fields.get("modify_date") if isinstance(xmp_fields.get("modify_date"), str) else None

    # Prefer Info dict (resolved/guessed), but allow XMP to fill gaps.
    title = _pick_first(title, xmp_title)
    author = _pick_first(author, xmp_author)
    keywords = _pick_first(keywords, xmp_keywords)
    creator = _pick_first(creator, xmp_creator_tool)
    producer = _pick_first(producer, xmp_producer)
    creation_date = _pick_first(creation_date, xmp_created)
    mod_date = _pick_first(mod_date, xmp_modified)

    normalized: Dict[str, Any] = build_document(
        doc_format="pdf",
        content_type="application/pdf",
        title=title,
        author=author,
        subject=subject,
        keywords=keywords,
        creator=creator,
        producer=producer,
        created=creation_date,
        modified=mod_date,
        signals={
            "xmp_present": xmp_present,
            "xmp_sha256": xmp_sha256,
            "xmp_fields_present": bool(xmp_fields) and not bool(xmp_fields.get("blocked")) if isinstance(xmp_fields, Mapping) else False,
            "xmp_creators_count": len(xmp_creators) if isinstance(xmp_creators, list) else 0,
        },
    )

    sources: Dict[str, Any] = {
        "preferred": "info_resolved" if resolved else "info_guess",
        "info_resolved_present": bool(resolved),
        "info_guess_present": bool(guessed),
        "xmp_present": xmp_present,
        "xmp_fields_present": bool(xmp_fields) and not bool(xmp_fields.get("blocked")) if isinstance(xmp_fields, Mapping) else False,
    }

    return NormalizationResult(schema_version="mimf.document@1.0", normalized=normalized, sources=sources)


def build_pdf_normalization_plan(
    obj: RuntimeObject,
    *,
    plan_id: Optional[str] = None,
) -> MutationPlan:
    """Build a MutationPlan that attaches normalized PDF metadata.

    The plan updates the top-level metadata with a new key: "normalized".

    Security notes:
    - Output may still be sensitive (title/author). Treat exports accordingly.

    Time:  O(1)
    Space: O(1)
    """

    res = normalize_pdf_metadata(obj)
    now = datetime.now(UTC)

    return MutationPlan(
        plan_id=plan_id or f"normalize-pdf-{int(now.timestamp())}",
        target_object_id=obj.object_id,
        mutation_type="normalize:pdf-metadata",
        changes={
            "normalized": res.normalized,
            "normalized_sources": res.sources,
        },
        allowed_labels=frozenset(getattr(obj, "labels", frozenset())),
        created_at=now,
    )
