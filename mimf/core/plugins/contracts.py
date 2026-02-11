from dataclasses import dataclass
from typing import FrozenSet, Dict, Protocol
from datetime import datetime

@dataclass(frozen=True)
class PluginMetadata:
    """
    Immutable metadata describing a plugin.
    """
    plugin_id: str                 # Unique identifier
    name: str                      # Human-readable name
    version: str                   # Plugin version
    author: str                    # Author or organization
    allowed_actions: FrozenSet[str]  # Actions plugin can perform
    created_at: datetime

# ------------------------------
# Plugin Interface / Protocol
# ------------------------------

class PluginInterface(Protocol):
    """
    Protocol all plugins must implement.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.
        """
        ...

    def initialize(self) -> None:
        """
        Called once when the plugin is loaded.
        """
        ...

    def execute(self, context) -> None:
        """
        Perform plugin logic in the given RuntimeContext.
        """
        ...

    def teardown(self) -> None:
        """
        Called once when the plugin is unloaded.
        """
        ...
