"""Normalization helpers for MIMF.

Normalization maps untrusted / messy metadata produced by inspectors into a
stable schema used by policy, audit, export, and UI.

Security notes:
- Never assume source metadata is well-formed or benign.
- Keep transforms deterministic and strictly bounded.
"""

from .export_policy import (
    ExportPolicyResult,
    apply_normalized_export_policy,
    redact_normalized_document,
)
from .generic_normalizer import build_generic_normalization_plan, normalize_generic_metadata
from .json_normalizer import build_json_normalization_plan, normalize_json_metadata
from .normalizer import (
    NormalizationDispatch,
    build_normalization_plan,
    normalize_runtime_object,
    select_normalizer,
)
from .pdf_normalizer import build_pdf_normalization_plan, normalize_pdf_metadata
from .schema import (
    SCHEMA_NAME,
    SCHEMA_TAG,
    SCHEMA_VERSION,
    SchemaContract,
    build_document,
    validate_normalized_document,
)

__all__ = [
    "NormalizationDispatch",
    "select_normalizer",
    "normalize_runtime_object",
    "build_normalization_plan",
    "normalize_pdf_metadata",
    "build_pdf_normalization_plan",
    "normalize_json_metadata",
    "build_json_normalization_plan",
    "normalize_generic_metadata",
    "build_generic_normalization_plan",
    "SchemaContract",
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "SCHEMA_TAG",
    "build_document",
    "validate_normalized_document",
    "apply_normalized_export_policy",
    "redact_normalized_document",
    "ExportPolicyResult",
]
