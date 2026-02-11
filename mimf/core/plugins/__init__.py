from .contracts import PluginMetadata, PluginInterface
from .registry import PluginRegistry
from .loader import load_builtin_plugins
from .file_inspector import FileInspectorPlugin
from .file_info import FileInfo, sniff_file_info
from .capabilities import FileInspectorCapabilities
from .selectors import select_file_inspector
from .sandbox import SandboxResult, inspect_file_sandboxed

__all__ = [
    "PluginMetadata",
    "PluginInterface",
    "PluginRegistry",
    "load_builtin_plugins",
    "FileInspectorPlugin",
    "FileInfo",
    "sniff_file_info",
    "FileInspectorCapabilities",
    "select_file_inspector",
    "SandboxResult",
    "inspect_file_sandboxed",
]
