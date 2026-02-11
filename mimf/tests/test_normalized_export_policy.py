from __future__ import annotations

from mimf.core.normalization import build_document, apply_normalized_export_policy
from mimf.core.security.boundaries import SecurityBoundary


def _sample_normalized():
    return build_document(
        doc_format="pdf",
        content_type="application/pdf",
        title="Secret",
        author="Alice",
        subject="S",
        keywords="k",
        creator="Tool",
        producer="Prod",
        created="2020-01-01",
        modified="2020-01-02",
        signals={"x": True},
    )


def test_export_policy_redacts_by_default() -> None:
    normalized = _sample_normalized()

    # Default boundary only has export:document.basic.
    res = apply_normalized_export_policy(normalized=normalized)

    doc = res.redacted.get("document", {})
    assert doc.get("title") is None
    assert doc.get("author") is None
    assert doc.get("creator") is None
    assert "title" in set(res.redacted_fields)
    assert "creator" in set(res.redacted_fields)


def test_export_policy_allows_with_boundary_and_actor_caps() -> None:
    normalized = _sample_normalized()

    boundary = SecurityBoundary.from_names(
        "export-bundle",
        [
            "export:document.basic",
            "export:document.identifying",
            "export:document.tooling",
        ],
    )

    res = apply_normalized_export_policy(
        normalized=normalized,
        boundary=boundary,
        actor_capabilities=[
            "export:document.basic",
            "export:document.identifying",
            "export:document.tooling",
        ],
    )

    doc = res.redacted.get("document", {})
    assert doc.get("title") == "Secret"
    assert doc.get("author") == "Alice"
    assert doc.get("creator") == "Tool"
    assert res.redacted_fields == []


def test_export_policy_strict_denies_when_missing_caps() -> None:
    normalized = _sample_normalized()
    boundary = SecurityBoundary.from_names("export-bundle", ["export:document.basic"])

    res = apply_normalized_export_policy(
        normalized=normalized,
        boundary=boundary,
        actor_capabilities=["export:document.basic"],
        strict=True,
    )

    assert res.decision.status.value == "DENY"