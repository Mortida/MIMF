from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import zipfile

from defusedxml import ElementTree as DefusedET

_MAX_ZIP_ENTRIES = 5000
_MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class DocxInspectionResult:
    file_type: str
    properties: Dict[str, Any]


class DocxInspector:
    supported_suffixes = {".docx"}

    def inspect(self, path: Path) -> DocxInspectionResult:
        """
        Inspect a DOCX (ZIP) and extract metadata from docProps/core.xml and docProps/app.xml.

        Security:
        - ZIP bomb protection (entry count + size limits)
        - Safe XML parsing via defusedxml
        - Reads only docProps/*, does not execute macros

        Time:  O(E + U) bounded by limits
        Space: O(S) bounded by limits
        """
        if path.suffix.lower() not in self.supported_suffixes:
            raise ValueError(f"Unsupported file type: {path.suffix}")

        with zipfile.ZipFile(path, "r") as zf:
            self._enforce_zip_limits(zf)
            core = self._read_xml_as_dict(zf, "docProps/core.xml")
            app = self._read_xml_as_dict(zf, "docProps/app.xml")

        props: Dict[str, Any] = {}
        if core:
            props["core"] = core
        if app:
            props["app"] = app

        return DocxInspectionResult(file_type="docx", properties=props)

    def _enforce_zip_limits(self, zf: zipfile.ZipFile) -> None:
        infos = zf.infolist()
        if len(infos) > _MAX_ZIP_ENTRIES:
            raise ValueError(f"ZIP has too many entries: {len(infos)} > {_MAX_ZIP_ENTRIES}")

        total = 0
        for info in infos:
            if info.file_size > _MAX_SINGLE_FILE_BYTES:
                raise ValueError(f"ZIP entry too large: {info.filename} ({info.file_size})")
            total += info.file_size
            if total > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError(f"ZIP total too large: {total}")

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
