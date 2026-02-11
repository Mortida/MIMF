from __future__ import annotations

"""
Backwards-compatibility shim.

Canonical location (built-in plugins live here):
    mimf.core.plugins.builtin.docx_inspector

This module remains to avoid breaking any old imports:
    mimf.core.plugins.docx_inspector
"""

from .builtin.docx_inspector import DocxFileInspector

__all__ = ["DocxFileInspector"]
