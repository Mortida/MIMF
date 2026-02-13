"""
Backward-compatible import path.

Prefer importing from:
    mimf.core.plugins.builtin.docx_inspector
"""

from __future__ import annotations

from .builtin.docx_inspector import DocxFileInspector

__all__ = ["DocxFileInspector"]
