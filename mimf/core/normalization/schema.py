from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

SCHEMA_NAME: str = "mimf.document"
SCHEMA_VERSION: str = "1.0"
SCHEMA_TAG: str = f"{SCHEMA_NAME}@{SCHEMA_VERSION}"


_DOCUMENT_FIELDS = (
    "format",
    "content_type",
    "title",
    "author",
    "subject",
    "keywords",
    "creator",
    "producer",
    "created",
    "modified",
)


def build_document(
    *,
    doc_format: str,
    content_type: str,
    title: Optional[str] = None,
    author: Optional[str] = None,
    subject: Optional[str] = None,
    keywords: Optional[str] = None,
    creator: Optional[str] = None,
    producer: Optional[str] = None,
    created: Optional[str] = None,
    modified: Optional[str] = None,
    signals: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a normalized document payload that matches the MIMF schema contract.

    Security notes:
    - Inputs are assumed attacker-controlled strings.
    - This helper is intentionally small and deterministic.

    """

    normalized: Dict[str, Any] = {
        "schema": {"name": SCHEMA_NAME, "version": SCHEMA_VERSION},
        "document": {
            "format": doc_format,
            "content_type": content_type,
            "title": title,
            "author": author,
            "subject": subject,
            "keywords": keywords,
            "creator": creator,
            "producer": producer,
            "created": created,
            "modified": modified,
        },
        "signals": dict(signals or {}),
    }

    validate_normalized_document(normalized)
    return normalized


def validate_normalized_document(normalized: Mapping[str, Any]) -> None:
    """Validate the normalized document contract.

    This is a *shape validator* (not a semantic validator).

    Security notes:
    - Fail closed: raise ValueError on unexpected shapes.

    """

    if not isinstance(normalized, Mapping):
        raise ValueError("normalized must be a mapping")

    schema = normalized.get("schema")
    if not isinstance(schema, Mapping):
        raise ValueError("normalized.schema must be a mapping")
    if schema.get("name") != SCHEMA_NAME or schema.get("version") != SCHEMA_VERSION:
        raise ValueError("normalized.schema name/version mismatch")

    doc = normalized.get("document")
    if not isinstance(doc, Mapping):
        raise ValueError("normalized.document must be a mapping")
    for k in _DOCUMENT_FIELDS:
        if k not in doc:
            raise ValueError(f"normalized.document missing field: {k}")

    sig = normalized.get("signals")
    if not isinstance(sig, Mapping):
        raise ValueError("normalized.signals must be a mapping")


@dataclass(frozen=True)
class SchemaContract:
    """Schema contract constants."""

    name: str = SCHEMA_NAME
    version: str = SCHEMA_VERSION
    tag: str = SCHEMA_TAG
