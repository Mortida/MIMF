from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from mimf.core.policy_engine.normalized_export_rule import NormalizedExportRule
from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_engine import PolicyEngine
from mimf.core.policy_engine.policy_models import PolicyDecision
from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability

_IDENTIFYING_FIELDS: Set[str] = {"title", "author", "subject", "keywords"}
_TOOLING_FIELDS: Set[str] = {"creator", "producer"}


@dataclass(frozen=True)
class ExportPolicyResult:
    """Outcome of applying an export policy to a normalized document."""

    decision: PolicyDecision
    redacted: Dict[str, Any]
    redacted_fields: List[str]


def _presence_from_normalized(normalized: Mapping[str, Any]) -> Dict[str, bool]:
    """Compute field presence map for policy evaluation."""

    doc = normalized.get("document") if isinstance(normalized.get("document"), Mapping) else {}
    out: Dict[str, bool] = {}
    for k in _IDENTIFYING_FIELDS | _TOOLING_FIELDS:
        v = doc.get(k) if isinstance(doc, Mapping) else None
        out[k] = v is not None and str(v).strip() != ""
    return out


def _deep_copy_document(normalized: Mapping[str, Any]) -> Dict[str, Any]:
    # normalized payloads are small and JSON-shaped; shallow copies suffice.
    out = dict(normalized)
    doc = normalized.get("document")
    out["document"] = dict(doc) if isinstance(doc, Mapping) else {}
    sig = normalized.get("signals")
    out["signals"] = dict(sig) if isinstance(sig, Mapping) else {}
    schema = normalized.get("schema")
    out["schema"] = dict(schema) if isinstance(schema, Mapping) else {}
    return out


def redact_normalized_document(
    normalized: Mapping[str, Any], *, redact_fields: Iterable[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Return a redacted copy of a normalized document.

    Redaction sets the targeted fields to None under normalized["document"].

    """

    redacted_fields = sorted({str(f) for f in redact_fields})
    out = _deep_copy_document(normalized)
    doc = out.get("document")
    if not isinstance(doc, dict):
        return out, redacted_fields

    for f in redacted_fields:
        if f in doc:
            doc[f] = None

    return out, redacted_fields


def apply_normalized_export_policy(
    *,
    normalized: Mapping[str, Any],
    target_labels: Optional[Iterable[str]] = None,
    boundary: Optional[SecurityBoundary] = None,
    actor_capabilities: Optional[Iterable[str]] = None,
    strict: bool = False,
    engine: Optional[PolicyEngine] = None,
) -> ExportPolicyResult:
    """Apply export policy to a normalized document and return a redacted view.

    Default behavior is "fail closed" by redacting identifying/tooling fields unless
    both the boundary and actor capabilities explicitly permit export.

    Security notes:
    - This is an *export* control, not a mutation control.
    - Use strict=True to deny instead of redacting.

    """

    raw_caps = list(actor_capabilities or [])
    norm_caps: List[str] = []
    for c in raw_caps:
        if not isinstance(c, str):
            continue
        try:
            norm_caps.append(Capability(c).name)
        except Exception:
            # Fail closed: ignore invalid capability strings.
            continue

    # Provide a safe default boundary if none is supplied.
    if boundary is None:
        boundary = SecurityBoundary.from_names(
            boundary_id="export-bundle",
            capability_names=["export:document.basic"],
        )

    # Build a tiny plan-like object so PolicyContext has a stable trace_id.
    plan = type(
        "ExportPlan",
        (),
        {
            "plan_id": f"export-{int(datetime.now(UTC).timestamp())}",
            "mutation_type": "export:normalized",
        },
    )()

    # Compute presence map from the normalized payload.
    presence = _presence_from_normalized(normalized)

    # Use a dedicated policy engine for export if not provided.
    pe = engine or PolicyEngine(rules=[NormalizedExportRule()])

    ctx = PolicyContext.from_runtime(
        plan=plan,
        target=type(
            "ExportTarget", (), {"object_id": "", "labels": frozenset(target_labels or [])}
        )(),
        metadata={
            "boundary": boundary,
            "actor_capabilities": norm_caps,
            "export_strict": bool(strict),
            "export_field_presence": presence,
        },
    )

    decision = pe.evaluate(ctx)

    redact_fields = []
    if decision.metadata and isinstance(decision.metadata, Mapping):
        rf = decision.metadata.get("redact_fields")
        if isinstance(rf, list):
            redact_fields = [str(x) for x in rf]

    redacted, redacted_fields = redact_normalized_document(normalized, redact_fields=redact_fields)

    return ExportPolicyResult(decision=decision, redacted=redacted, redacted_fields=redacted_fields)
