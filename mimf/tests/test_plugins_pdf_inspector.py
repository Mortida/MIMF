from pathlib import Path

from mimf.core.plugins import PluginRegistry, load_builtin_plugins, select_file_inspector


def _write_minimal_pdf(path: Path) -> None:
    # Minimal PDF-like bytes (header + body + EOF marker).
    # Security note: this is test data only; the inspector never parses PDF structure.
    xmp = (
        b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\n"
        b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>\n"
        b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n"
        b"<rdf:Description rdf:about=''>\n"
        b"<dc:title xmlns:dc='http://purl.org/dc/elements/1.1/'>Test Title</dc:title>\n"
        b"</rdf:Description>\n"
        b"</rdf:RDF>\n"
        b"</x:xmpmeta>\n"
        b"<?xpacket end='w'?>\n"
    )

    content = (
        b"%PDF-1.7\n"
        b"%\xe2\xe3\xcf\xd3\n"
        + xmp
        + b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        + b"trailer\n<< /Root 1 0 R /Info << /Title (Test Title) /Author (Alice) /Creator (UnitTest) >> >>\n"
        + b"%%EOF\n"
    )
    path.write_bytes(content)


def _write_pdf_with_indirect_info(path: Path) -> None:
    # Minimal PDF with /Info as an indirect object reference.
    # Inspector should resolve "2 0 obj" and extract basic fields.
    content = (
        b"%PDF-1.4\n"
        b"2 0 obj\n<< /Title (Indirect Title) /Author (Bob) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /Info 2 0 R >>\n"
        b"%%EOF\n"
    )
    path.write_bytes(content)


def test_builtin_pdf_inspector_selected_for_pdf_extension(tmp_path: Path) -> None:
    p = tmp_path / "sample.pdf"
    _write_minimal_pdf(p)

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    assert plugin.metadata.plugin_id == "builtin.pdf_inspector"

    obj = plugin.inspect_file(str(p))
    snap = obj.snapshot()
    assert snap["metadata"]["pdf"]["magic_ok"] is True
    assert snap["metadata"]["pdf"]["version"] == "1.7"
    assert snap["metadata"]["pdf"]["has_eof_marker"] is True


def test_pdf_sniffing_selects_pdf_inspector_without_extension(tmp_path: Path) -> None:
    # No .pdf extension, but magic header is present.
    p = tmp_path / "payload.bin"
    _write_minimal_pdf(p)

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    assert plugin.metadata.plugin_id == "builtin.pdf_inspector"


def test_pdf_inspector_extracts_info_and_xmp_signals(tmp_path: Path) -> None:
    p = tmp_path / "meta.pdf"
    _write_minimal_pdf(p)

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))
    snap = obj.snapshot()

    pdf = snap["metadata"]["pdf"]
    assert pdf["info_guess"]["Title"] == "Test Title"
    assert pdf["info_guess"]["Author"] == "Alice"
    assert pdf["info_guess"]["Creator"] == "UnitTest"

    assert pdf["xmp"]["present"] is True
    assert int(pdf["xmp"]["len_bytes"]) > 0
    assert isinstance(pdf["xmp"]["sha256"], str)
    assert "x:xmpmeta" in pdf["xmp"]["preview"]
    # Best-effort extracted fields
    assert pdf["xmp"]["fields"]["title"] == "Test Title"


def test_pdf_inspector_extracts_xmp_creators_list(tmp_path: Path) -> None:
    p = tmp_path / "creators.pdf"

    xmp = (
        b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\n"
        b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>\n"
        b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n"
        b"<rdf:Description rdf:about='' xmlns:dc='http://purl.org/dc/elements/1.1/'>\n"
        b"<dc:creator><rdf:Seq><rdf:li>Alice</rdf:li><rdf:li>Bob</rdf:li></rdf:Seq></dc:creator>\n"
        b"</rdf:Description>\n"
        b"</rdf:RDF>\n"
        b"</x:xmpmeta>\n"
        b"<?xpacket end='w'?>\n"
    )
    content = b"%PDF-1.7\n" + xmp + b"%%EOF\n"
    p.write_bytes(content)

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))
    pdf = obj.snapshot()["metadata"]["pdf"]

    assert pdf["xmp"]["fields"]["creators"] == ["Alice", "Bob"]


def test_pdf_inspector_resolves_indirect_info_ref(tmp_path: Path) -> None:
    p = tmp_path / "indirect.pdf"
    _write_pdf_with_indirect_info(p)

    registry = PluginRegistry()
    load_builtin_plugins(registry)

    plugin = select_file_inspector(registry, str(p))
    obj = plugin.inspect_file(str(p))
    snap = obj.snapshot()

    pdf = snap["metadata"]["pdf"]
    assert pdf["info_ref"]["present"] is True
    assert int(pdf["info_ref"]["obj"]) == 2
    assert int(pdf["info_ref"]["gen"]) == 0

    # Resolved fields should include the indirect object values.
    assert pdf["info_resolved"]["Title"] == "Indirect Title"
    assert pdf["info_resolved"]["Author"] == "Bob"
