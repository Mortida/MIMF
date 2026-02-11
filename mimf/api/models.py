from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class ApiError(BaseModel):
    """Standard API error payload."""

    error: str
    detail: Optional[str] = None


class FileInfoOut(BaseModel):
    """A safe summary of a file, derived from bounded sniffing."""

    filename: str
    extension: Optional[str] = None
    mime_type: Optional[str] = None
    mime_confidence: Optional[str] = None
    size_bytes: int
    sha256: Optional[str] = None


class InspectOut(BaseModel):
    """Inspection result."""

    file: FileInfoOut
    object_id: str
    object_type: str
    labels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    inspector_plugin_id: Optional[str] = None


class NormalizeOut(BaseModel):
    """Normalization result (policy-controlled)."""

    file: FileInfoOut
    normalizer_id: str
    schema_version: str
    normalized: Dict[str, Any]
    export_policy: Dict[str, Any]
    redacted_fields: List[str] = Field(default_factory=list)


class ExportBundleOut(BaseModel):
    """Metadata about a created bundle (the bundle bytes are returned separately)."""

    bundle_id: str
    merkle_root: str
    event_chain_ok: bool
    event_chain_tip: Optional[str] = None


class VerifyBundleOut(BaseModel):
    """Verification report for a bundle."""

    ok: bool
    details: Dict[str, Any] = Field(default_factory=dict)


class ContextSummaryOut(BaseModel):
    """A persisted RuntimeContext summary."""

    context_id: str
    created_at: str
    actor_id: Optional[str] = None
    parent_context_id: Optional[str] = None
    operation_name: Optional[str] = None
    object_count: int = 0
    event_count: int = 0


class ContextDetailOut(BaseModel):
    """A persisted RuntimeContext detail view."""

    context: ContextSummaryOut
    objects: List[Dict[str, Any]] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    integrity_ok: bool = True
