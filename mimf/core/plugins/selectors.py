from __future__ import annotations

from typing import List

from .file_info import sniff_file_info, FileInfo

from .file_inspector import FileInspectorPlugin
from .registry import PluginRegistry


def select_file_inspector(registry: PluginRegistry, path: str) -> FileInspectorPlugin:
    """Select the best file inspector for a given path.

    Selection rules:
    1) Compute FileInfo (size, extension, guessed/sniffed mime) once.
    2) Filter inspectors by declared capabilities.matches(FileInfo).
    3) Optionally apply plugin.can_handle_file(FileInfo) if provided, otherwise can_handle(path).
    4) Choose the highest match score (match_score_file if provided, otherwise match_score).
    5) Add capabilities.priority_bias and tie-break deterministically by plugin_id.

    Security notes:
    - Plugins are code execution; only load trusted plugins.
    - Defensive: a buggy plugin match_score must not break selection.

    Time:  O(p) where p is number of registered plugins (plus O(1) sniff)
    Space: O(p) for candidate list
    """

    info: FileInfo = sniff_file_info(path)

    candidates: List[FileInspectorPlugin] = []
    for plugin in registry.iter_plugins():
        if not isinstance(plugin, FileInspectorPlugin):
            continue

        # 1) Capability filter (fast, declarative)
        try:
            if not plugin.capabilities.matches(info):
                continue
        except Exception:
            # Defensive: a buggy capabilities implementation shouldn't brick selection.
            continue

        # 2) Optional file-aware can_handle
        if hasattr(plugin, "can_handle_file"):
            try:
                if not bool(getattr(plugin, "can_handle_file")(info)):
                    continue
            except Exception:
                continue
        else:
            # 3) Legacy path-based can_handle
            try:
                if not plugin.can_handle(info.path):
                    continue
            except Exception:
                continue

        candidates.append(plugin)

    if not candidates:
        raise RuntimeError(f"No file inspector plugin found for: {path}")

    def _score(p: FileInspectorPlugin) -> int:
        try:
            base = 0
            if hasattr(p, "match_score_file"):
                base = int(getattr(p, "match_score_file")(info))
            else:
                base = int(p.match_score(info.path))
            return base + int(getattr(p.capabilities, "priority_bias", 0))
        except Exception:
            # Do not let a single plugin break selection.
            return 0

    # Sort highest score first, stable deterministic tie-breaker.
    candidates.sort(key=lambda p: (_score(p), p.metadata.plugin_id), reverse=True)
    return candidates[0]
