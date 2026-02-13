from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Set

from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability

from .policy_context import PolicyContext
from .policy_models import DecisionStatus, PolicyDecision
from .policy_rules import PolicyRule


def _normalize_capabilities(raw: Any) -> List[Capability]:
    """Normalize a raw capability list.

    Accepts list[str] or list[Capability]. Invalid inputs return empty list.

    """

    if not isinstance(raw, list):
        return []

    out: List[Capability] = []
    for item in raw:
        if isinstance(item, Capability):
            out.append(item)
        elif isinstance(item, str):
            try:
                out.append(Capability(item))
            except Exception:
                return []
        else:
            return []
    return out


_CAP_IDENTIFYING = Capability("export:document.identifying")
_CAP_TOOLING = Capability("export:document.tooling")

_IDENTIFYING_FIELDS: Set[str] = {"title", "author", "subject", "keywords"}
_TOOLING_FIELDS: Set[str] = {"creator", "producer"}


@dataclass(frozen=True)
class NormalizedExportRule(PolicyRule):
    """Field-level export control for normalized document payloads.

    This rule is designed for *export/printing* flows (e.g., CLI "show-normalized").
    It does not mutate objects; instead it returns directives in PolicyDecision.metadata:

    - redact_fields: list[str]
    - missing_capabilities: list[str]

    Expected PolicyContext.metadata fields
    - boundary: SecurityBoundary (optional)
    - actor_capabilities: list[str] | list[Capability] (optional)
    - export_strict: bool (optional) -> deny instead of redact
    - export_field_presence: mapping[str, bool] (optional)

    Security notes:
    - Fail closed: on invalid metadata shapes, redact identifying/tooling fields.

    """

    rule_id: str = "normalized-export-fields"

    def evaluate(self, context: PolicyContext) -> Optional[PolicyDecision]:
        if not isinstance(context, PolicyContext):
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason="Invalid policy context",
                trace_id="",
            )

        trace_id = str(context.metadata.get("plan_id", ""))
        strict = bool(context.metadata.get("export_strict", False))

        boundary = context.metadata.get("boundary")
        if boundary is not None and not isinstance(boundary, SecurityBoundary):
            boundary = None

        actor_caps = set(_normalize_capabilities(context.metadata.get("actor_capabilities")))

        # Determine which sensitive fields are present in the export payload.
        presence = context.metadata.get("export_field_presence")
        if isinstance(presence, Mapping):
            present_identifying = any(bool(presence.get(k)) for k in _IDENTIFYING_FIELDS)
            present_tooling = any(bool(presence.get(k)) for k in _TOOLING_FIELDS)
        else:
            # Fail closed: assume sensitive fields may be present.
            present_identifying = True
            present_tooling = True

        missing: List[str] = []
        redact: Set[str] = set()

        def _allowed(cap: Capability) -> bool:
            if cap not in actor_caps:
                return False
            if boundary is None:
                return False
            try:
                return boundary.allows(cap)
            except Exception:
                return False

        if present_identifying and not _allowed(_CAP_IDENTIFYING):
            missing.append(_CAP_IDENTIFYING.name)
            redact |= _IDENTIFYING_FIELDS

        if present_tooling and not _allowed(_CAP_TOOLING):
            missing.append(_CAP_TOOLING.name)
            redact |= _TOOLING_FIELDS

        if strict and (missing or boundary is None):
            why = (
                "Missing export capabilities" if missing else "Missing or invalid security boundary"
            )
            return PolicyDecision(
                status=DecisionStatus.DENY,
                policy_id=self.rule_id,
                reason=why,
                trace_id=trace_id,
                metadata={
                    "missing_capabilities": missing,
                    "redact_fields": sorted(redact),
                },
            )

        if redact:
            return PolicyDecision(
                status=DecisionStatus.ALLOW,
                policy_id=self.rule_id,
                reason="Redact sensitive fields for export",
                trace_id=trace_id,
                metadata={
                    "missing_capabilities": missing,
                    "redact_fields": sorted(redact),
                },
            )

        return PolicyDecision(
            status=DecisionStatus.ALLOW,
            policy_id=self.rule_id,
            reason="Export allowed",
            trace_id=trace_id,
            metadata={
                "missing_capabilities": [],
                "redact_fields": [],
            },
        )
