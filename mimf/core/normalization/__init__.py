"""Normalization helpers for MIMF.

Normalization maps untrusted / messy metadata produced by inspectors into a
stable schema used by policy, audit, export, and UI.

Security notes:
- Never assume source metadata is well-formed or benign.
- Keep transforms deterministic and strictly bounded.
"""

from .normalizer import build_normalization_plan, normalize_runtime_object, select_normalizer, NormalizationDispatch
from .pdf_normalizer import build_pdf_normalization_plan, normalize_pdf_metadata
from .json_normalizer import build_json_normalization_plan, normalize_json_metadata
from .generic_normalizer import build_generic_normalization_plan, normalize_generic_metadata
from .schema import SchemaContract, SCHEMA_NAME, SCHEMA_VERSION, SCHEMA_TAG, build_document, validate_normalized_document
from .export_policy import apply_normalized_export_policy, redact_normalized_document, ExportPolicyResult

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
