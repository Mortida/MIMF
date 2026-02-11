from __future__ import annotations

from mimf.core.plugins.registry import PluginRegistry
from mimf.core.plugins.builtin.json_inspector import JsonFileInspector
from mimf.core.plugins.builtin.pdf_inspector import PdfFileInspector
from mimf.core.plugins.builtin.generic_file_inspector import GenericFileInspector
from mimf.core.plugins.builtin.docx_inspector import DocxFileInspector


def load_builtin_plugins(registry: PluginRegistry) -> None:
    """Load built-in (trusted) plugins into the registry.

    Security notes:
    - Built-ins are part of the trusted codebase.
    - External plugins should be loaded only via strict allowlisting/signed artifacts.

    Time:  O(k) where k is number of built-in plugins
    Space: O(k)
    """
    plugins = [
        GenericFileInspector(),
        PdfFileInspector(),
        JsonFileInspector(),
        DocxFileInspector(),
    ]

    for p in plugins:
        p.initialize()
        registry.register(p)
