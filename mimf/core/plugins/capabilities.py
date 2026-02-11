from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional

from .file_info import FileInfo, mime_matches


@dataclass(frozen=True, slots=True)
class FileInspectorCapabilities:
    """Capabilities used to filter/select file inspector plugins.

    Security notes
    - Capabilities are declared by plugin authors; treat them as hints.
    - Selection must remain deterministic even if a plugin misdeclares.

    Time:  O(a+b) for matching where a=#mime patterns, b=#extensions
    Space: O(1)
    """

    supported_mime_types: FrozenSet[str] = field(default_factory=lambda: frozenset({"*"}))
    supported_extensions: FrozenSet[str] = field(default_factory=lambda: frozenset({"*"}))

    # Optional hard limit a plugin is willing to handle safely.
    max_size_bytes: Optional[int] = None

    # Constant bias added to match_score (lets specific plugins win ties).
    priority_bias: int = 0

    def matches(self, info: FileInfo) -> bool:
        """Return True if this capability set is compatible with FileInfo.

        Time:  O(a+b) bounded by number of patterns
        Space: O(1)
        """

        if self.max_size_bytes is not None and info.size_bytes > self.max_size_bytes:
            return False

        ext = info.extension.lower()
        ext_ok = ("*" in self.supported_extensions) or (ext in self.supported_extensions)

        # Fast-path: any mime accepted
        if "*" in self.supported_mime_types or "*/*" in self.supported_mime_types:
            # If plugin also constrains extensions, allow either signal.
            return ext_ok or ("*" in self.supported_extensions)

        mime_ok = False
        for pat in self.supported_mime_types:
            if mime_matches(pat, info.mime_type):
                mime_ok = True
                break

        # If plugin declares both extension(s) and mime(s), treat them as
        # alternative signals: either may match.
        if "*" not in self.supported_extensions and "*" not in self.supported_mime_types:
            return ext_ok or mime_ok

        # Otherwise, whichever dimension is constrained decides.
        return ext_ok and mime_ok
