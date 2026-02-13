from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional


def _freeze_mapping(value: Optional[Mapping[str, Any]]) -> MappingProxyType:
    if value is None:
        return MappingProxyType({})

    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")

    copied: Dict[str, Any] = dict(value)

    for k in copied.keys():
        if not isinstance(k, str):
            raise TypeError("metadata keys must be strings")

    return MappingProxyType(copied)


@dataclass(frozen=True)
class PolicyContext:
    """
    Immutable policy input snapshot.

    Security and correctness
    metadata is an immutable mappingproxy
    construction copies incoming metadata to prevent shared mutable state
    use with_metadata to create derived contexts rather than mutating in place
    """

    plan: Any
    target: Any
    metadata: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))

    @classmethod
    def from_runtime(
        cls, *, plan: Any, target: Any, metadata: Optional[Mapping[str, Any]] = None
    ) -> "PolicyContext":
        base: Dict[str, Any] = {
            "plan_id": getattr(plan, "plan_id", ""),
            "mutation_type": getattr(plan, "mutation_type", type(plan).__name__),
            "target_object_id": getattr(target, "object_id", ""),
            "plan_type": type(plan).__name__,
            "target_type": type(target).__name__,
        }

        if metadata is not None:
            if not isinstance(metadata, Mapping):
                raise TypeError("metadata must be a mapping")
            base.update(dict(metadata))

        return cls(plan=plan, target=target, metadata=base)

    def with_metadata(self, patch: Mapping[str, Any]) -> "PolicyContext":
        """
        Return a new PolicyContext with metadata merged (base then patch).

        Fail closed on invalid patch types or non-string keys.
        """
        if not isinstance(patch, Mapping):
            raise TypeError("patch must be a mapping")

        merged: Dict[str, Any] = dict(self.metadata)
        patch_dict: Dict[str, Any] = dict(patch)

        for k in patch_dict.keys():
            if not isinstance(k, str):
                raise TypeError("metadata keys must be strings")

        merged.update(patch_dict)
        return PolicyContext(plan=self.plan, target=self.target, metadata=merged)
