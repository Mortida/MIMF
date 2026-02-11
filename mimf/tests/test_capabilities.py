import pytest

from mimf.core.security.capabilities import Capability


def test_capability_normalizes_and_is_hashable():
    c = Capability("  MUTATE_METADATA  ")
    assert c.name == "mutate_metadata"

    s = {c}
    assert Capability("mutate_metadata") in s


def test_capability_rejects_invalid_names_fail_closed():
    with pytest.raises(TypeError):
        Capability(123)

    with pytest.raises(ValueError):
        Capability("   ")
