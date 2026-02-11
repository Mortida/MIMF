from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    """
    Immutable capability identifier.

    Security invariants
    - Immutable and hashable for safe set membership
    - Normalized name to avoid bypass via casing/whitespace
    """

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError("Capability name must be a string")

        normalized = self.name.strip()
        if not normalized:
            raise ValueError("Capability name must be non-empty")

        object.__setattr__(self, "name", normalized.lower())
