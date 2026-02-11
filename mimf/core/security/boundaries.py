from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Iterable

from .capabilities import Capability


@dataclass(frozen=True)
class SecurityBoundary:
    """
    Represents an explicit security boundary.

    Examples
    - filesystem-metadata
    - embedded-metadata
    - raw-bytes
    - export-bundle

    Security invariants
    - Immutable configuration
    - Capabilities stored as a frozenset
    - Deterministic permission checks
    """

    boundary_id: str
    allowed_capabilities: FrozenSet[Capability] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.boundary_id, str):
            raise TypeError("boundary_id must be a string")

        bid = self.boundary_id.strip()
        if not bid:
            raise ValueError("boundary_id must be non-empty")

        object.__setattr__(self, "boundary_id", bid)

        caps = self.allowed_capabilities
        if not isinstance(caps, frozenset):
            try:
                caps = frozenset(caps)
            except TypeError as e:
                raise TypeError("allowed_capabilities must be iterable of Capability") from e

        for c in caps:
            if not isinstance(c, Capability):
                raise TypeError("allowed_capabilities must contain only Capability instances")

        object.__setattr__(self, "allowed_capabilities", caps)

    @classmethod
    def from_names(cls, boundary_id: str, capability_names: Iterable[str]) -> "SecurityBoundary":
        caps = frozenset(Capability(name) for name in capability_names)
        return cls(boundary_id=boundary_id, allowed_capabilities=caps)

    def allows(self, capability: Capability) -> bool:
        if not isinstance(capability, Capability):
            raise TypeError("capability must be a Capability instance")
        return capability in self.allowed_capabilities
