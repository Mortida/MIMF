from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from defusedxml import ElementTree as DefusedET

from mimf.core.plugins.capabilities import FileInspectorCapabilities
from mimf.core.plugins.contracts import PluginMetadata
from mimf.core.plugins.file_info import FileInfo
from mimf.core.plugins.file_inspector import FileInspectorPlugin
from mimf.core.runtime.object import RuntimeObject

# Zip safety limits (defense-in-depth against zip bombs)
_MAX_ZIP_ENTRIES = 5000
_MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50MB
_MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024  # 10MB


def _sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    """
    Security: streaming hash (no full-file load).
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---- Fix #1: correct field names on FileInspectorCapabilities ----
_CAPS = FileInspectorCapabilities(
    supported_extensions={".docx"},
    supported_mime_types={
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
)

# ---- Fix #2: correct fields on PluginMetadata (no description/kind) ----
_META = PluginMetadata(
    plugin_id="builtin.docx_inspector",
    name="DOCX Inspector",
    version="1.0.0",
    author="MIMF Core",
    allowed_actions=frozenset({"inspect"}),
    created_at=datetime.now(timezone.utc),
)


@dataclass(frozen=True)
class DocxInspectionResult:
    """
    Raw extracted DOCX metadata (pre-normalization).

    Security:
    - Uses defusedxml to avoid entity expansion attacks.
    - Reads only docProps/core.xml and docProps/app.xml.
    """

    file_type: str
    properties: Dict[str, Any]


class DocxFileInspector(FileInspectorPlugin):
    """
    Built-in DOCX file inspector.

      - E = zip entries scanned (bounded),
      - U = uncompressed bytes read (bounded),
      - N = file size for hashing (streamed).

    Security considerations:
    - Zip bomb limits: entry count, per-entry size, total uncompressed size
    - XML parsing via defusedxml
    - Only reads expected members (docProps/core.xml, docProps/app.xml)
    """

    @property
    def metadata(self) -> PluginMetadata:
        return _META

    @property
    def capabilities(self) -> FileInspectorCapabilities:
        return _CAPS

    def initialize(self) -> None:
        return

    def teardown(self) -> None:
        return

    def execute(self, *args, **kwargs):
        # Not used for file inspectors; required by PluginInterface.
        raise NotImplementedError("Use inspect_file(...) for DOCX inspection.")

    def can_handle_file(self, file_info: FileInfo) -> bool:
        # Extension match is the most reliable here because MIME sniffing
        # often returns application/zip for OOXML.
        return self.match_score_file(file_info) > 0

    def match_score_file(self, file_info: FileInfo) -> int:
        score = 0
        if file_info.extension.lower() in self.capabilities.supported_extensions:
            score += 80
        if (file_info.mime_type or "").lower() in self.capabilities.supported_mime_types:
            score += 40
        return score

    def inspect_file(self, path: str, file_info: FileInfo) -> RuntimeObject:
        p = Path(path)
        st = p.stat()

        docx_meta = self._extract_docx_metadata(path)

        return RuntimeObject(
            object_id=f"file:{p.resolve()}",
            object_type="file",
            labels=frozenset({"docx"}),
            metadata={
                "file": {
                    "path": str(p),
                    "size_bytes": st.st_size,
                    "mtime": st.st_mtime,
                    "sha256": _sha256_file(path),
                    "mime_type": file_info.mime_type,
                    "extension": file_info.extension,
                },
                "docx": docx_meta,
            },
            origin="inspector:builtin.docx_inspector",
            created_at=datetime.now(timezone.utc),
        )

    def _extract_docx_metadata(self, path: str) -> Dict[str, Any]:
        p = Path(path)
        if p.suffix.lower() != ".docx":
            raise ValueError("DocxFileInspector only supports .docx")

        with zipfile.ZipFile(p, "r") as zf:
            self._enforce_zip_limits(zf)
            core = self._read_xml_as_dict(zf, "docProps/core.xml")
            app = self._read_xml_as_dict(zf, "docProps/app.xml")

        return {
            "core": core or {},
            "app": app or {},
        }

    def _enforce_zip_limits(self, zf: zipfile.ZipFile) -> None:
        infos = zf.infolist()
        if len(infos) > _MAX_ZIP_ENTRIES:
            raise ValueError(f"ZIP has too many entries: {len(infos)} > {_MAX_ZIP_ENTRIES}")

        total = 0
        for info in infos:
            if info.file_size > _MAX_SINGLE_FILE_BYTES:
                raise ValueError(f"ZIP entry too large: {info.filename} ({info.file_size} bytes)")
            total += info.file_size
            if total > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError(f"ZIP total too large: {total} bytes")

    def _read_xml_as_dict(self, zf: zipfile.ZipFile, member: str) -> Optional[Dict[str, Any]]:
        try:
            with zf.open(member, "r") as f:
                data = f.read()
        except KeyError:
            return None

        root = DefusedET.fromstring(data)
        out: Dict[str, Any] = {}
        for child in list(root):
            tag = self._strip_ns(child.tag)
            text = (child.text or "").strip()
            if text:
                out[tag] = text
        return out

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag
