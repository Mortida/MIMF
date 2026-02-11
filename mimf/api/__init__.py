"""MIMF API package.

This module provides an optional FastAPI service layer around the core MIMF
inspection/normalization/export pipelines.
"""

from .server import create_app  # noqa: F401

