import json
import pytest
from datetime import UTC

from mimf.core.runtime.events import RuntimeEvent


def test_runtime_event_has_identity_and_utc_timestamp():
    evt = RuntimeEvent()
    assert evt.event_id is not None
    assert evt.created_at.tzinfo is UTC


def test_runtime_event_is_immutable():
    evt = RuntimeEvent()
    with pytest.raises(Exception):
        evt.previous_event_hash = "X"


def test_runtime_event_payload_excludes_hash_fields_and_is_json_safe():
    evt = RuntimeEvent()
    payload = evt.to_payload()

    assert "event_type" in payload
    assert "event_id" in payload
    assert "created_at" in payload

    assert "previous_event_hash" not in payload
    assert "event_hash" not in payload

    json.dumps(payload)


def test_runtime_event_payload_is_deterministic_for_same_event_instance():
    evt = RuntimeEvent()
    p1 = evt.to_payload()
    p2 = evt.to_payload()
    assert p1 == p2
