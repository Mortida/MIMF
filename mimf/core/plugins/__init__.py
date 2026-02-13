from .capabilities import FileInspectorCapabilities
from .contracts import PluginInterface, PluginMetadata
from .file_info import FileInfo, sniff_file_info
from .file_inspector import FileInspectorPlugin
from .loader import load_builtin_plugins
from .registry import PluginRegistry
from .sandbox import SandboxResult, inspect_file_sandboxed
from .selectors import select_file_inspector

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
