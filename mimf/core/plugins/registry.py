from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .contracts import PluginInterface


@dataclass
class PluginRegistry:
    """In-memory registry for loaded plugins.

    Security notes:
    - Plugins are code execution. Only load trusted plugins.
    - Prefer an allowlist + signed plugins for real deployments.

    - register: O(1) average
    - get: O(1) average
    - list_plugins: O(n)
    - O(n) for n registered plugins
    """

    _plugins: Dict[str, PluginInterface] = field(default_factory=dict, init=False, repr=False)

    def register(self, plugin: PluginInterface) -> None:
        """Register a plugin by plugin_id."""
        pid = plugin.metadata.plugin_id
        if pid in self._plugins:
            raise RuntimeError(f"Duplicate plugin_id: {pid}")
        self._plugins[pid] = plugin

    def get(self, plugin_id: str) -> PluginInterface:
        """Retrieve a plugin by id."""
        return self._plugins[plugin_id]

    def try_get(self, plugin_id: str) -> Optional[PluginInterface]:
        """Retrieve a plugin or None."""
        return self._plugins.get(plugin_id)

    def list_plugins(self) -> List[PluginInterface]:
        """List plugins in insertion order."""
        return list(self._plugins.values())

    def iter_plugins(self) -> Iterable[PluginInterface]:
        """Iterate plugins."""
        return self._plugins.values()
