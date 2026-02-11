from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from mimf.core.plugins.file_info import FileInfo
from mimf.core.runtime.mutation import MutationPlan
from mimf.core.runtime.object import RuntimeObject

from .json_normalizer import build_json_normalization_plan, normalize_json_metadata
from .generic_normalizer import build_generic_normalization_plan, normalize_generic_metadata
from .pdf_normalizer import build_pdf_normalization_plan, normalize_pdf_metadata


@dataclass(frozen=True)
class NormalizationDispatch:
    """Outcome of selecting a normalizer.

    Time:  O(1)
    Space: O(1)
    """

    normalizer_id: str
    schema_version: str


def _is_json_mime(mime_type: str) -> bool:
    mt = (mime_type or "").lower()
    return mt in {"application/json", "text/json"} or mt.endswith("+json")


def select_normalizer(info: FileInfo) -> NormalizationDispatch:
    """Select a document normalizer based on FileInfo.

    Selection rules (deterministic):
    - application/pdf -> "pdf"
    - json-ish -> "json"

    Security notes:
    - Normalizers are pure functions (no file I/O) and should be deterministic.

    Time:  O(1)
    Space: O(1)
    """

    mt = (info.mime_type or "").lower()
    if mt == "application/pdf" or info.extension == ".pdf":
        return NormalizationDispatch(normalizer_id="pdf", schema_version="mimf.document@1.0")
    if _is_json_mime(mt) or info.extension == ".json":
        return NormalizationDispatch(normalizer_id="json", schema_version="mimf.document@1.0")
    # Fallback: always provide a generic normalization to keep pipelines stable.
    return NormalizationDispatch(normalizer_id="generic", schema_version="mimf.document@1.0")


def normalize_runtime_object(obj: RuntimeObject, info: FileInfo) -> Tuple[NormalizationDispatch, Dict[str, Any], Dict[str, Any]]:
    """Normalize an inspected RuntimeObject into a stable schema.

    Returns: (dispatch, normalized, sources)

    Time:  O(1)
    Space: O(1)
    """

    dispatch = select_normalizer(info)
    if dispatch.normalizer_id == "pdf":
        res = normalize_pdf_metadata(obj)
        return dispatch, res.normalized, res.sources
    if dispatch.normalizer_id == "json":
        res = normalize_json_metadata(obj)
        return dispatch, res.normalized, res.sources
    if dispatch.normalizer_id == "generic":
        res = normalize_generic_metadata(obj, info)
        return dispatch, res.normalized, res.sources
    raise ValueError(f"Unknown normalizer_id: {dispatch.normalizer_id}")


def build_normalization_plan(
    obj: RuntimeObject,
    info: FileInfo,
    *,
    plan_id: Optional[str] = None,
) -> Tuple[NormalizationDispatch, MutationPlan]:
    """Build a normalization MutationPlan for an inspected RuntimeObject.

    Time:  O(1)
    Space: O(1)
    """

    dispatch = select_normalizer(info)
    if dispatch.normalizer_id == "pdf":
        return dispatch, build_pdf_normalization_plan(obj, plan_id=plan_id)
    if dispatch.normalizer_id == "json":
        return dispatch, build_json_normalization_plan(obj, plan_id=plan_id)
    if dispatch.normalizer_id == "generic":
        return dispatch, build_generic_normalization_plan(obj, info, plan_id=plan_id)
    raise ValueError(f"Unknown normalizer_id: {dispatch.normalizer_id}")
