from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Dict, Optional, Tuple

from mimf.core.plugins.capabilities import FileInspectorCapabilities
from mimf.core.plugins.contracts import PluginMetadata
from mimf.core.plugins.file_info import FileInfo
from mimf.core.plugins.file_inspector import FileInspectorPlugin
from mimf.core.runtime.object import RuntimeObject


def _sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file and return its SHA-256.

    Security notes:
    - Streaming avoids loading untrusted files into memory.

    Time:  O(n) where n is file size
    Space: O(1)
    """

    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _read_prefix(path: str, *, n: int) -> bytes:
    """Read up to n bytes from the start of a file.

    Security notes:
    - Bounded read.

    Time:  O(1) (bounded)
    Space: O(1)
    """

    with open(path, "rb") as f:
        return f.read(n)


def _read_suffix(path: str, *, n: int) -> bytes:
    """Read up to n bytes from the end of a file.

    Security notes:
    - Bounded read.

    Time:  O(1) (bounded)
    Space: O(1)
    """

    with open(path, "rb") as f:
        try:
            f.seek(-n, os.SEEK_END)
        except OSError:
            f.seek(0)
        return f.read(n)


def _parse_pdf_version(prefix: bytes) -> Optional[str]:
    """Parse the %PDF-x.y version string from a prefix.

    Security notes:
    - Does not attempt to parse the PDF structure.

    Time:  O(1)
    Space: O(1)
    """

    if not prefix.startswith(b"%PDF-"):
        return None
    # Example header: b"%PDF-1.7\n"
    rest = prefix[5:20]
    # Read until whitespace/control
    ver_bytes = bytearray()
    for b in rest:
        if b in b" \t\r\n\x0c\x00":
            break
        ver_bytes.append(b)
    try:
        v = ver_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    return v or None


def _strip_control_chars(text: str, *, max_len: int) -> str:
    """Return a bounded, printable-ish string.

    Security notes:
    - PDF metadata can be attacker-controlled. We strip control chars and bound length.

    Time:  O(n)
    Space: O(n)
    """

    out = []
    for ch in text:
        # Keep common whitespace, drop other control chars.
        if ch in ("\t", "\n", "\r"):
            out.append(ch)
            continue
        if ord(ch) < 32 or ord(ch) == 127:
            continue
        out.append(ch)
        if len(out) >= max_len:
            break
    return "".join(out)


def _parse_pdf_literal_string(data: bytes, start: int, *, max_bytes: int) -> Tuple[Optional[bytes], int]:
    """Parse a PDF literal string starting at `start` (expects '(').

    Supports nested parentheses and common backslash escapes.

    Time:  O(k) where k is parsed bytes (bounded)
    Space: O(k)
    """

    if start >= len(data) or data[start] != ord("("):
        return None, start

    i = start + 1
    depth = 1
    out = bytearray()

    while i < len(data) and depth > 0 and len(out) < max_bytes:
        b = data[i]

        if b == ord("\\"):
            # Escape sequence
            i += 1
            if i >= len(data):
                break
            nb = data[i]
            # Octal escapes: \ddd (up to 3 octal digits)
            if ord("0") <= nb <= ord("7"):
                oct_digits = [nb]
                for _ in range(2):
                    if i + 1 < len(data) and ord("0") <= data[i + 1] <= ord("7"):
                        i += 1
                        oct_digits.append(data[i])
                    else:
                        break
                try:
                    out.append(int(bytes(oct_digits), 8) & 0xFF)
                except ValueError:
                    pass
            else:
                mapping = {
                    ord("n"): ord("\n"),
                    ord("r"): ord("\r"),
                    ord("t"): ord("\t"),
                    ord("b"): 0x08,
                    ord("f"): 0x0C,
                    ord("("): ord("("),
                    ord(")"): ord(")"),
                    ord("\\"): ord("\\"),
                }
                out.append(mapping.get(nb, nb))
            i += 1
            continue

        if b == ord("("):
            depth += 1
            out.append(b)
            i += 1
            continue
        if b == ord(")"):
            depth -= 1
            if depth == 0:
                i += 1
                break
            out.append(b)
            i += 1
            continue

        out.append(b)
        i += 1

    return bytes(out), i


def _parse_pdf_hex_string(data: bytes, start: int, *, max_bytes: int) -> Tuple[Optional[bytes], int]:
    """Parse a PDF hex string starting at `start` (expects '<').

    Time:  O(k) (bounded)
    Space: O(k)
    """

    if start >= len(data) or data[start] != ord("<"):
        return None, start

    i = start + 1
    hex_digits = bytearray()

    while i < len(data) and len(hex_digits) < max_bytes * 2:
        b = data[i]
        if b == ord(">"):
            i += 1
            break
        # ignore whitespace
        if b in b" \t\r\n\x0c\x00":
            i += 1
            continue
        # accept hex chars
        if (ord("0") <= b <= ord("9")) or (ord("A") <= b <= ord("F")) or (ord("a") <= b <= ord("f")):
            hex_digits.append(b)
        i += 1

    # If odd number of digits, pad with 0 (PDF spec behavior)
    if len(hex_digits) % 2 == 1:
        hex_digits.append(ord("0"))

    out = bytearray()
    for j in range(0, len(hex_digits), 2):
        if len(out) >= max_bytes:
            break
        try:
            out.append(int(hex_digits[j : j + 2].decode("ascii"), 16) & 0xFF)
        except ValueError:
            break

    return bytes(out), i


def _extract_info_fields(scan: bytes, *, max_value_bytes: int = 2048) -> Dict[str, str]:
    """Best-effort extraction of common /Info dictionary string fields.

    This does NOT parse the PDF object graph. It simply searches for known keys
    and reads an adjacent literal or hex string.

    Security notes:
    - Bound scanning and parsing to prevent pathological inputs.

    Time:  O(n * k) where n=len(scan) and k=#keys (small)
    Space: O(1) aside from extracted values
    """

    keys = [
        (b"/Title", "Title"),
        (b"/Author", "Author"),
        (b"/Subject", "Subject"),
        (b"/Keywords", "Keywords"),
        (b"/Creator", "Creator"),
        (b"/Producer", "Producer"),
        (b"/CreationDate", "CreationDate"),
        (b"/ModDate", "ModDate"),
    ]

    found: Dict[str, str] = {}

    for needle, out_key in keys:
        idx = scan.find(needle)
        if idx == -1:
            continue

        i = idx + len(needle)
        # skip whitespace
        while i < len(scan) and scan[i] in b" \t\r\n\x0c\x00":
            i += 1

        raw: Optional[bytes] = None
        end = i
        if i < len(scan) and scan[i] == ord("("):
            raw, end = _parse_pdf_literal_string(scan, i, max_bytes=max_value_bytes)
        elif i < len(scan) and scan[i] == ord("<"):
            raw, end = _parse_pdf_hex_string(scan, i, max_bytes=max_value_bytes)

        if raw:
            txt = raw.decode("latin-1", errors="replace")
            txt = _strip_control_chars(txt, max_len=256)
            if txt:
                found[out_key] = txt

    return found


def _extract_xmp(scan: bytes, *, max_bytes: int = 64 * 1024) -> Optional[bytes]:
    """Extract an XMP packet (best-effort) from a bounded scan buffer.

    Looks for <x:xmpmeta ... </x:xmpmeta>.

    Time:  O(n)
    Space: O(1) aside from extracted slice
    """

    start = scan.find(b"<x:xmpmeta")
    if start == -1:
        # Some PDFs use an xpacket wrapper; still usually contains <x:xmpmeta
        start = scan.find(b"<?xpacket")
        if start == -1:
            return None
        # Try to locate xmpmeta after xpacket
        xmp2 = scan.find(b"<x:xmpmeta", start)
        if xmp2 != -1:
            start = xmp2
        else:
            return None

    end = scan.find(b"</x:xmpmeta>", start)
    if end == -1:
        return None
    end += len(b"</x:xmpmeta>")

    if end - start > max_bytes:
        end = start + max_bytes

    return scan[start:end]


def _strip_xml_tags(text: str, *, max_len: int) -> str:
    """Very small helper to remove XML/HTML-like tags.

    Security notes:
    - This is NOT a general XML parser.
    - Used only for best-effort extraction on bounded inputs.

    Time:  O(n)
    Space: O(n)
    """

    # Remove tags and collapse whitespace.
    no_tags = re.sub(r"<[^>]+>", " ", text)
    no_tags = re.sub(r"\s+", " ", no_tags).strip()
    return _strip_control_chars(no_tags, max_len=max_len)


def _extract_xmp_fields(xmp_bytes: bytes) -> Dict[str, Any]:
    """Extract a small set of common XMP fields from an XMP packet.

    We intentionally avoid full XML parsing here (DoS risks) and instead use
    bounded, best-effort regex extraction.

    Extracted fields (when present):
    - title (dc:title)
    - creators (dc:creator)
    - description (dc:description)
    - subjects (dc:subject)
    - keywords (pdf:Keywords)
    - creator_tool (xmp:CreatorTool)
    - producer (pdf:Producer)
    - create_date (xmp:CreateDate)
    - modify_date (xmp:ModifyDate)

    Security notes:
    - Rejects packets containing DTD/entity declarations.
    - Bounds output size and strips control chars.

    Time:  O(n) where n is xmp_bytes length (bounded upstream)
    Space: O(n)
    """

    xml = xmp_bytes.decode("utf-8", errors="replace")
    # Basic hardening against entity expansion.
    head = xml[:4096].lower()
    if "<!doctype" in head or "<!entity" in head:
        return {"blocked": True, "reason": "xmp_contains_doctype_or_entity"}

    def first_group(pattern: str) -> Optional[str]:
        m = re.search(pattern, xml, flags=re.IGNORECASE | re.DOTALL)
        if not m:
            return None
        return m.group(1)

    def list_items(block: str) -> list[str]:
        items = re.findall(r"<rdf:li[^>]*>(.*?)</rdf:li>", block, flags=re.IGNORECASE | re.DOTALL)
        out: list[str] = []
        for it in items:
            val = _strip_xml_tags(it, max_len=256)
            if val:
                out.append(val)
        return out

    # Title
    title_block = first_group(r"<dc:title[^>]*>(.*?)</dc:title>")
    title: Optional[str] = None
    if title_block:
        # Prefer rdf:li if present
        items = list_items(title_block)
        if items:
            title = items[0]
        else:
            title = _strip_xml_tags(title_block, max_len=256)

    # Creator list
    creators_block = first_group(r"<dc:creator[^>]*>(.*?)</dc:creator>")
    creators: list[str] = []
    if creators_block:
        creators = list_items(creators_block)
        if not creators:
            v = _strip_xml_tags(creators_block, max_len=256)
            if v:
                creators = [v]

    # Description
    desc_block = first_group(r"<dc:description[^>]*>(.*?)</dc:description>")
    description: Optional[str] = None
    if desc_block:
        items = list_items(desc_block)
        description = items[0] if items else _strip_xml_tags(desc_block, max_len=256)

    # Subjects
    subj_block = first_group(r"<dc:subject[^>]*>(.*?)</dc:subject>")
    subjects: list[str] = []
    if subj_block:
        subjects = list_items(subj_block)
        if not subjects:
            v = _strip_xml_tags(subj_block, max_len=256)
            if v:
                subjects = [v]

    keywords_block = first_group(r"<pdf:Keywords[^>]*>(.*?)</pdf:Keywords>")
    keywords = _strip_xml_tags(keywords_block, max_len=256) if keywords_block else None

    creator_tool_block = first_group(r"<xmp:CreatorTool[^>]*>(.*?)</xmp:CreatorTool>")
    creator_tool = _strip_xml_tags(creator_tool_block, max_len=256) if creator_tool_block else None

    producer_block = first_group(r"<pdf:Producer[^>]*>(.*?)</pdf:Producer>")
    producer = _strip_xml_tags(producer_block, max_len=256) if producer_block else None

    create_date_block = first_group(r"<xmp:CreateDate[^>]*>(.*?)</xmp:CreateDate>")
    create_date = _strip_xml_tags(create_date_block, max_len=64) if create_date_block else None

    modify_date_block = first_group(r"<xmp:ModifyDate[^>]*>(.*?)</xmp:ModifyDate>")
    modify_date = _strip_xml_tags(modify_date_block, max_len=64) if modify_date_block else None

    fields: Dict[str, Any] = {}
    if title:
        fields["title"] = title
    if creators:
        fields["creators"] = creators
    if description:
        fields["description"] = description
    if subjects:
        fields["subjects"] = subjects
    if keywords:
        fields["keywords"] = keywords
    if creator_tool:
        fields["creator_tool"] = creator_tool
    if producer:
        fields["producer"] = producer
    if create_date:
        fields["create_date"] = create_date
    if modify_date:
        fields["modify_date"] = modify_date

    return fields
def _find_info_ref(scan: bytes) -> Optional[Tuple[int, int]]:
    """Find a trailer-style /Info indirect reference: /Info <obj> <gen> R.

    Security notes:
    - Best-effort pattern match on bounded data; does not parse PDF grammar.

    Time:  O(n)
    Space: O(1)
    """

    idx = scan.find(b"/Info")
    if idx == -1:
        return None

    i = idx + len(b"/Info")
    while i < len(scan) and scan[i] in b" \t\r\n\x0c\x00":
        i += 1

    # read obj number
    j = i
    while j < len(scan) and ord("0") <= scan[j] <= ord("9"):
        j += 1
    if j == i:
        return None
    try:
        obj_num = int(scan[i:j].decode("ascii"), 10)
    except Exception:
        return None

    i = j
    while i < len(scan) and scan[i] in b" \t\r\n\x0c\x00":
        i += 1

    # read gen number
    j = i
    while j < len(scan) and ord("0") <= scan[j] <= ord("9"):
        j += 1
    if j == i:
        return None
    try:
        gen_num = int(scan[i:j].decode("ascii"), 10)
    except Exception:
        return None

    i = j
    while i < len(scan) and scan[i] in b" \t\r\n\x0c\x00":
        i += 1

    if i < len(scan) and scan[i] == ord("R"):
        return obj_num, gen_num
    return None


def _stream_find_bytes(path: str, needle: bytes, *, max_scan_bytes: int, chunk_size: int = 1024 * 1024) -> Optional[int]:
    """Stream-scan a file for `needle` and return the first byte offset.

    Security notes:
    - Bounded total scan to avoid pathological file sizes.
    - Uses overlap to avoid missing matches across chunk boundaries.

    Time:  O(min(n, max_scan_bytes))
    Space: O(chunk_size)
    """

    if not needle:
        return None

    overlap = max(64, len(needle) + 16)
    scanned = 0
    prev = b""

    with open(path, "rb") as f:
        while scanned < max_scan_bytes:
            to_read = min(chunk_size, max_scan_bytes - scanned)
            chunk = f.read(to_read)
            if not chunk:
                break
            buf = prev + chunk
            idx = buf.find(needle)
            if idx != -1:
                # offset accounts for prev overlap
                return (scanned - len(prev)) + idx
            scanned += len(chunk)
            prev = buf[-overlap:]

    return None


def _read_window(path: str, offset: int, *, window_bytes: int) -> bytes:
    """Read a bounded window from a file at a specific offset.

    Time:  O(1) (bounded)
    Space: O(window_bytes)
    """

    with open(path, "rb") as f:
        f.seek(max(0, offset))
        return f.read(window_bytes)


def _resolve_info_indirect_object(
    path: str,
    *,
    obj_num: int,
    gen_num: int,
    max_scan_bytes: int = 8 * 1024 * 1024,
    window_bytes: int = 256 * 1024,
) -> Optional[bytes]:
    """Resolve an indirect object (best-effort) and return its raw bytes.

    This is NOT a full PDF parser. It only searches for the byte pattern
    "<obj> <gen> obj" and then returns a bounded window up to `endobj`.

    Security notes:
    - Bounded scanning and window reads.
    - Does not execute or interpret any PDF actions.

    Time:  O(min(n, max_scan_bytes))
    Space: O(window_bytes)
    """

    header = f"{obj_num} {gen_num} obj".encode("ascii", errors="strict")
    off = _stream_find_bytes(path, header, max_scan_bytes=max_scan_bytes)
    if off is None:
        return None

    win = _read_window(path, off, window_bytes=window_bytes)
    end = win.find(b"endobj")
    if end != -1:
        end += len(b"endobj")
        return win[:end]
    return win


@dataclass
class PdfFileInspector(FileInspectorPlugin):
    """Built-in skeleton inspector for PDF files (metadata-only).

    This plugin intentionally does NOT parse PDF object graphs.
    It extracts only bounded, safe signals:
    - SHA-256 (streamed)
    - size + basic stat timestamps
    - header version (from %PDF-x.y)
    - "linearized" hint (prefix scan)
    - "%%EOF" trailer marker hint (suffix scan)

    Security notes:
    - Treat PDF as untrusted; do not execute embedded scripts.
    - Do not fully parse PDF (future work can use hardened parsers in a sandbox).

    Time:
    - inspect_file: O(n) for hashing + O(1) prefix/suffix reads
    Space:
    - O(1)
    """

    header_bytes: int = 2048
    trailer_bytes: int = 2048

    # Bounded scans for best-effort metadata signals (still no PDF parsing).
    scan_prefix_bytes: int = 256 * 1024
    scan_suffix_bytes: int = 256 * 1024

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            plugin_id="builtin.pdf_inspector",
            name="Built-in PDF Inspector (Metadata Signals)",
            version="0.3",
            author="MIMF",
            allowed_actions=frozenset({"inspect_file"}),
            created_at=datetime.now(UTC),
        )

    @property
    def capabilities(self) -> FileInspectorCapabilities:
        """Declarative selection hints.

        - PDF by magic header (%PDF-) and/or extension (.pdf).

        Time:  O(1)
        Space: O(1)
        """

        return FileInspectorCapabilities(
            supported_mime_types=frozenset({"application/pdf"}),
            supported_extensions=frozenset({".pdf"}),
            max_size_bytes=None,
            priority_bias=80,
        )

    def initialize(self) -> None:
        return

    def teardown(self) -> None:
        return

    def execute(self, context) -> None:
        # Not used for file inspectors (kept for PluginInterface compatibility)
        return

    # --- Selection helpers ---

    def can_handle(self, path: str) -> bool:
        """Legacy path-based compatibility.

        Time:  O(len(path))
        Space: O(1)
        """
        return path.lower().endswith(".pdf")

    def can_handle_file(self, info: FileInfo) -> bool:
        """FileInfo-aware handler check.

        Security notes:
        - Does not parse file content.

        Time:  O(1)
        Space: O(1)
        """
        if info.extension == ".pdf":
            return True
        return info.mime_type.lower() == "application/pdf"

    def match_score(self, path: str) -> int:
        """Legacy scoring (path-only).

        Time:  O(1)
        Space: O(1)
        """
        return 120

    def match_score_file(self, info: FileInfo) -> int:
        """FileInfo-aware scoring.

        Prefers high-confidence magic detection.

        Time:  O(1)
        Space: O(1)
        """
        score = 110
        if info.extension == ".pdf":
            score += 30
        if info.mime_type.lower() == "application/pdf":
            score += 60
            if info.mime_confidence == "high":
                score += 30
            elif info.mime_confidence == "medium":
                score += 10
        return score

    # --- Inspection ---

    def inspect_file(self, path: str, *, object_id: str | None = None) -> RuntimeObject:
        abs_path = os.path.abspath(path)

        st = os.stat(abs_path)
        size_bytes = int(st.st_size)

        prefix = _read_prefix(abs_path, n=self.header_bytes)
        suffix = _read_suffix(abs_path, n=self.trailer_bytes)

        # Best-effort bounded scans for metadata signals.
        scan_prefix = _read_prefix(abs_path, n=min(self.scan_prefix_bytes, size_bytes))
        scan_suffix = _read_suffix(abs_path, n=min(self.scan_suffix_bytes, size_bytes))

        pdf_version = _parse_pdf_version(prefix)
        magic_ok = prefix.startswith(b"%PDF-")
        is_linearized = b"/Linearized" in prefix
        has_eof_marker = b"%%EOF" in suffix

        # Info dict guess (string fields only) from bounded scans.
        info_guess: Dict[str, str] = {}
        info_guess.update(_extract_info_fields(scan_prefix))
        # Trailer/EOF region is more likely to contain /Info references/strings
        info_guess.update(_extract_info_fields(scan_suffix))

        # If trailer contains an indirect reference: /Info <obj> <gen> R
        info_ref = _find_info_ref(scan_suffix)
        info_resolved: Dict[str, str] = {}
        if info_ref is not None:
            obj_num, gen_num = info_ref
            raw_obj = _resolve_info_indirect_object(abs_path, obj_num=obj_num, gen_num=gen_num)
            if raw_obj:
                info_resolved = _extract_info_fields(raw_obj)

        # XMP packet (store hash + preview only)
        xmp_bytes = _extract_xmp(scan_prefix + b"\n" + scan_suffix)
        xmp_meta: Dict[str, Any] = {"present": bool(xmp_bytes)}
        if xmp_bytes:
            xmp_meta["len_bytes"] = len(xmp_bytes)
            xmp_meta["sha256"] = hashlib.sha256(xmp_bytes).hexdigest()
            preview = xmp_bytes.decode("utf-8", errors="replace")
            xmp_meta["preview"] = _strip_control_chars(preview, max_len=512)
            fields = _extract_xmp_fields(xmp_bytes)
            xmp_meta["fields"] = fields
            # If extraction was blocked due to DTD/entity, still include reason.
            xmp_meta["fields_present"] = bool(fields) and not bool(fields.get("blocked"))

        sha256 = _sha256_file(abs_path)

        created_at = datetime.now(UTC)

        pdf_meta: Dict[str, Any] = {
            "magic_ok": bool(magic_ok),
            "version": pdf_version,
            "is_linearized": bool(is_linearized),
            "has_eof_marker": bool(has_eof_marker),
            "info_guess": info_guess,
            "info_ref": {"present": info_ref is not None, "obj": (info_ref[0] if info_ref else None), "gen": (info_ref[1] if info_ref else None)},
            "info_resolved": info_resolved,
            "xmp": xmp_meta,
        }

        return RuntimeObject.create(
            object_id=object_id or f"file:{abs_path}",
            object_type="file",
            origin={"scheme": "file", "path": abs_path},
            metadata={
                "inspector_plugin_id": self.metadata.plugin_id,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "pdf": pdf_meta,
                "stat": {
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=UTC),
                    "ctime": datetime.fromtimestamp(st.st_ctime, tz=UTC),
                },
            },
            labels=frozenset({"UNTRUSTED"}),
            created_at=created_at,
        )
