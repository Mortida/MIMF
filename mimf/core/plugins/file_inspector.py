from __future__ import annotations

from typing import Protocol, runtime_checkable

from mimf.core.runtime.object import RuntimeObject

from .capabilities import FileInspectorCapabilities
from .contracts import PluginInterface


@runtime_checkable
class FileInspectorPlugin(PluginInterface, Protocol):
    """Plugin contract for inspecting a local file into a RuntimeObject.

    Security notes:
    - Treat file content as untrusted input.
    - Enforce size limits before parsing.
    - Never execute embedded code (e.g., avoid eval).

    - can_handle: implementation-specific, should be O(1) or O(len(path))
    - inspect_file: at least O(n) to read file for hashing/metadata where n=file size

    Notes
    - The selector computes a FileInfo object (mime + size + extension) once.
      Plugins may optionally provide `can_handle_file(info)` and/or
      `match_score_file(info)` for better decisions without reading file contents.
    """

    @property
    def capabilities(self) -> FileInspectorCapabilities:
        """Declared capability filters for this inspector.

        Security notes:
        - This is a hint, not a guarantee.

        """
        ...

    def can_handle(self, path: str) -> bool: ...

    # Optional enhanced APIs (selector uses them if present):
    # - can_handle_file(self, info: FileInfo) -> bool
    # - match_score_file(self, info: FileInfo) -> int

    def match_score(self, path: str) -> int:
        """Return a relative match score for this path.

        Higher is better.

        Security notes:
        - Must be cheap and side-effect free.
        - Must not read the file contents.

        """
        ...

    def inspect_file(self, path: str, *, object_id: str | None = None) -> RuntimeObject: ...
