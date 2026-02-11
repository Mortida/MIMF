from pathlib import Path

from mimf.core.normalization.pdf_normalizer import build_pdf_normalization_plan, normalize_pdf_metadata
from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector


def _write_pdf_with_indirect_info(path: Path) -> None:
    content = (
        b"%PDF-1.4\n"
        b"2 0 obj\n<< /Title (Indirect Title) /Author (Bob) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /Info 2 0 R >>\n"
        b"%%EOF\n"
    )
    path.write_bytes(content)


def test_pdf_normalizer_prefers_resolved_fields(tmp_path: Path) -> None:
    p = tmp_path / "indirect.pdf"
    _write_pdf_with_indirect_info(p)

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))

    obj = plugin.inspect_file(str(p))
    res = normalize_pdf_metadata(obj)

    doc = res.normalized["document"]
    assert doc["title"] == "Indirect Title"
    assert doc["author"] == "Bob"
    assert doc["format"] == "pdf"

    plan = build_pdf_normalization_plan(obj, plan_id="plan-1")
    assert plan.plan_id == "plan-1"
    assert plan.mutation_type == "normalize:pdf-metadata"
    assert "normalized" in plan.changes


def test_pdf_normalizer_uses_xmp_when_info_missing(tmp_path: Path) -> None:
    p = tmp_path / "xmp_only.pdf"
    xmp = (
        b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
        b"<rdf:Description rdf:about='' xmlns:dc='http://purl.org/dc/elements/1.1/'>"
        b"<dc:title><rdf:Alt><rdf:li>From XMP</rdf:li></rdf:Alt></dc:title>"
        b"<dc:creator><rdf:Seq><rdf:li>Alice</rdf:li></rdf:Seq></dc:creator>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta>"
    )
    p.write_bytes(b"%PDF-1.7\n" + xmp + b"\n%%EOF\n")

    registry = PluginRegistry()
    load_builtin_plugins(registry)
    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))

    res = normalize_pdf_metadata(obj)
    doc = res.normalized["document"]
    assert doc["title"] == "From XMP"
    assert doc["author"] == "Alice"
