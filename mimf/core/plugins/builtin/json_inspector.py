from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Dict

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


@dataclass
class JsonFileInspector(FileInspectorPlugin):
    """Built-in inspector for JSON files.

    Produces a RuntimeObject with:
    - origin: {"scheme": "file", "path": <abs_path>}
    - metadata: sha256, size_bytes, and a safe JSON summary

    Security notes:
    - Enforces a max_bytes_for_parse limit before parsing JSON.
    - Never executes embedded code; uses the stdlib json parser.

    Time:
    - inspect_file: O(n) hashing + O(n) parsing (if under limit)
    Space:
    - O(1) for hashing stream; O(n) for JSON parse (if under limit)
    """

    max_bytes_for_parse: int = 5 * 1024 * 1024  # 5MB

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            plugin_id="builtin.json_inspector",
            name="Built-in JSON Inspector",
            version="0.2",
            author="MIMF",
            allowed_actions=frozenset({"inspect_file"}),
            created_at=datetime.now(UTC),
        )

    @property
    def capabilities(self) -> FileInspectorCapabilities:
        """Declarative selection hints.

        - JSON by extension or mime.

        Security notes:
        - Capabilities are hints; selector remains defensive.

        Time:  O(1)
        Space: O(1)
        """
        return FileInspectorCapabilities(
            supported_mime_types=frozenset({
                "application/json",
                "text/json",
                "application/*+json",
            }),
            supported_extensions=frozenset({".json"}),
            # Prevent accidental selection for extremely large files.
            max_size_bytes=self.max_bytes_for_parse * 10,
            priority_bias=50,
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
        return path.lower().endswith(".json")

    def can_handle_file(self, info: FileInfo) -> bool:
        """FileInfo-aware handler check.

        Security notes:
        - Does not parse file content.

        Time:  O(1)
        Space: O(1)
        """
        if info.extension == ".json":
            return True
        mt = info.mime_type.lower()
        return mt in {"application/json", "text/json"} or mt.endswith("+json")

    def match_score(self, path: str) -> int:
        """Legacy scoring (path-only).

        Time:  O(1)
        Space: O(1)
        """
        return 100

    def match_score_file(self, info: FileInfo) -> int:
        """FileInfo-aware scoring.

        Prefers strong JSON signal (mime confidence) over extension.

        Time:  O(1)
        Space: O(1)
        """
        score = 90
        if info.extension == ".json":
            score += 20
        mt = info.mime_type.lower()
        if mt in {"application/json", "text/json"} or mt.endswith("+json"):
            score += 40
            if info.mime_confidence == "high":
                score += 20
            elif info.mime_confidence == "medium":
                score += 10
        return score

    # --- Inspection ---

    def inspect_file(self, path: str, *, object_id: str | None = None) -> RuntimeObject:
        abs_path = os.path.abspath(path)

        st = os.stat(abs_path)
        size_bytes = int(st.st_size)
        sha256 = _sha256_file(abs_path)

        summary: Dict[str, Any] = {
            "parsed": False,
            "top_level_type": None,
            "top_level_keys": None,
            "top_level_length": None,
            "note": None,
        }

        # Parse only if the file is small enough.
        if size_bytes <= self.max_bytes_for_parse:
            with open(abs_path, "rb") as f:
                raw = f.read()
            try:
                obj = json.loads(raw.decode("utf-8"))
                summary["parsed"] = True
                summary["top_level_type"] = type(obj).__name__
                if isinstance(obj, dict):
                    summary["top_level_keys"] = len(obj)
                elif isinstance(obj, list):
                    summary["top_level_length"] = len(obj)
            except UnicodeDecodeError:
                summary["note"] = "not utf-8; skipped parse"
            except json.JSONDecodeError:
                summary["note"] = "invalid json; skipped parse"
        else:
            summary["note"] = f"file too large to parse (>{self.max_bytes_for_parse} bytes)"

        created_at = datetime.now(UTC)

        return RuntimeObject.create(
            object_id=object_id or f"file:{abs_path}",
            object_type="file",
            origin={"scheme": "file", "path": abs_path},
            metadata={
                "inspector_plugin_id": self.metadata.plugin_id,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "json_summary": summary,
            },
            labels=frozenset({"UNTRUSTED"}),
            created_at=created_at,
        )
