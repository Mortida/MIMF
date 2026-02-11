import pytest

from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability


def test_security_boundary_allows_capabilities_deterministically():
    b = SecurityBoundary.from_names(
        "embedded-metadata",
        ["mutate_metadata", "inspect_metadata"],
    )

    assert b.boundary_id == "embedded-metadata"
    assert b.allows(Capability("mutate_metadata")) is True
    assert b.allows(Capability("unknown")) is False


def test_security_boundary_rejects_bad_inputs_fail_closed():
    with pytest.raises(ValueError):
        SecurityBoundary(boundary_id="   ")

    with pytest.raises(TypeError):
        SecurityBoundary(boundary_id="x", allowed_capabilities=frozenset({"not-cap"}))

    b = SecurityBoundary.from_names("x", ["a"])
    with pytest.raises(TypeError):
        b.allows("a")
