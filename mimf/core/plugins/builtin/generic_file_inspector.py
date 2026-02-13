from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Dict

from mimf.core.plugins.capabilities import FileInspectorCapabilities
from mimf.core.plugins.contracts import PluginMetadata
from mimf.core.plugins.file_info import FileInfo
from mimf.core.plugins.file_inspector import FileInspectorPlugin
from mimf.core.runtime.object import RuntimeObject


def _sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file and return its SHA-256.

    Security notes:
    - Streaming avoids loading untrusted files into memory.

    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _is_probably_binary(path: str, *, sample_bytes: int = 4096) -> bool:
    """Heuristic binary detector using a small prefix sample.

    Security notes:
    - Reads only a bounded prefix of the file.

    """
    with open(path, "rb") as f:
        sample = f.read(sample_bytes)
    return b"\x00" in sample


@dataclass
class GenericFileInspector(FileInspectorPlugin):
    """Built-in generic inspector for any regular file.

    Produces a RuntimeObject with:
    - origin: {"scheme": "file", "path": <abs_path>}
    - metadata: sha256, size_bytes, extension, and a small binary heuristic

    Security notes:
    - Treat file content as untrusted.
    - Avoid parsing/executing file content.

    - inspect_file: O(n) hashing + O(1) stat/sample
    - O(1)
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            plugin_id="builtin.generic_file_inspector",
            name="Built-in Generic File Inspector",
            version="0.2",
            author="MIMF",
            allowed_actions=frozenset({"inspect_file"}),
            created_at=datetime.now(UTC),
        )

    @property
    def capabilities(self) -> FileInspectorCapabilities:
        """Fallback capabilities: matches everything."""
        return FileInspectorCapabilities(
            supported_mime_types=frozenset({"*"}),
            supported_extensions=frozenset({"*"}),
            max_size_bytes=None,
            priority_bias=0,
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
        """Legacy compatibility: always True."""
        return True

    def can_handle_file(self, info: FileInfo) -> bool:
        """FileInfo-aware compatibility: always True."""
        return True

    def match_score(self, path: str) -> int:
        """Lowest-priority fallback."""
        return 1

    def match_score_file(self, info: FileInfo) -> int:
        """Lowest-priority fallback."""
        return 1

    # --- Inspection ---

    def inspect_file(self, path: str, *, object_id: str | None = None) -> RuntimeObject:
        abs_path = os.path.abspath(path)

        st = os.stat(abs_path)
        size_bytes = int(st.st_size)
        sha256 = _sha256_file(abs_path)

        ext = os.path.splitext(abs_path)[1].lower()
        is_binary = _is_probably_binary(abs_path)

        created_at = datetime.now(UTC)

        origin: Dict[str, str] = {"scheme": "file", "path": abs_path}

        return RuntimeObject.create(
            object_id=object_id or f"file:{abs_path}",
            object_type="file",
            origin=origin,
            metadata={
                "inspector_plugin_id": self.metadata.plugin_id,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "extension": ext,
                "is_probably_binary": is_binary,
                "stat": {
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=UTC),
                    "ctime": datetime.fromtimestamp(st.st_ctime, tz=UTC),
                },
            },
            labels=frozenset({"UNTRUSTED"}),
            created_at=created_at,
        )
