from __future__ import annotations

import fnmatch
import mimetypes
import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Metadata-only view of a local file used for plugin selection.

    Security notes:
    - File contents are untrusted. Selection should not execute code.
    - Sniffing reads only a small prefix (bounded).

    """

    path: str
    size_bytes: int
    extension: str
    mime_type: str
    mime_confidence: str  # "high" | "medium" | "low"


def sniff_file_info(path: str, *, prefix_bytes: int = 512) -> FileInfo:
    """Compute FileInfo for a path.

    Security notes:
    - Reads at most prefix_bytes from the file.
    - Never trusts filename alone.

    """

    abs_path = os.path.abspath(path)
    st = os.stat(abs_path)
    size_bytes = int(st.st_size)
    ext = os.path.splitext(abs_path)[1].lower()

    # 1) Extension-based guess (low confidence)
    guessed_mime, _enc = mimetypes.guess_type(abs_path)
    mime = guessed_mime or "application/octet-stream"
    confidence = "low" if guessed_mime else "low"

    # 2) Cheap magic-number sniffing (medium/high)
    head = b""
    try:
        with open(abs_path, "rb") as f:
            head = f.read(prefix_bytes)
    except OSError:
        # If we cannot read, keep the guess (still return FileInfo)
        return FileInfo(
            path=abs_path,
            size_bytes=size_bytes,
            extension=ext,
            mime_type=mime,
            mime_confidence=confidence,
        )

    magic_mime = _magic_mime(head)
    if magic_mime is not None:
        mime = magic_mime
        confidence = "high"

    # 3) JSON heuristic (if not already strongly identified)
    if confidence != "high":
        json_mime = _json_heuristic_mime(head)
        if json_mime is not None:
            mime = json_mime
            confidence = "medium"

    return FileInfo(
        path=abs_path,
        size_bytes=size_bytes,
        extension=ext,
        mime_type=mime,
        mime_confidence=confidence,
    )


def _magic_mime(prefix: bytes) -> Optional[str]:
    """Detect mime from common magic headers."""

    if prefix.startswith(b"%PDF-"):
        return "application/pdf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith(b"GIF87a") or prefix.startswith(b"GIF89a"):
        return "image/gif"
    if prefix.startswith(b"PK\x03\x04"):
        return "application/zip"
    if prefix.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if prefix.startswith(b"\x7fELF"):
        return "application/x-elf"
    return None


def _json_heuristic_mime(prefix: bytes) -> Optional[str]:
    """Heuristic JSON detection from a bounded prefix.

    Security notes:
    - Does not parse JSON; only checks leading non-whitespace.

    """

    # Strip BOM + whitespace
    p = prefix
    if p.startswith(b"\xef\xbb\xbf"):
        p = p[3:]
    p = p.lstrip()
    if not p:
        return None
    if p.startswith(b"{") or p.startswith(b"["):
        return "application/json"
    return None


def mime_matches(pattern: str, mime: str) -> bool:
    """Match a mime against a simple pattern.

    Supported patterns:
    - "*" or "*/*" matches all
    - "type/*" matches any subtype
    - exact match

    """

    pat = pattern.strip().lower()
    m = mime.strip().lower()

    if pat in {"*", "*/*"}:
        return True
    if "*" in pat:
        # Support simple glob patterns (e.g., "application/*", "application/*+json").
        return fnmatch.fnmatchcase(m, pat)
    return pat == m
