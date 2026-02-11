from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import MutationExecutionEvent


def test_mutation_execution_event_seals_and_integrity_is_valid():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    evt = MutationExecutionEvent(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE_METADATA",
        executor="dry-run",
        applied=False,
        metadata={"stage": "started"},
    )

    ctx.emit_event(evt)

    events = ctx.get_events()
    assert len(events) == 1
    assert events[0].previous_event_hash == "GENESIS"
    assert events[0].event_hash is not None
    assert ctx.verify_integrity() is True


def test_mutation_execution_event_payload_contains_required_fields():
    evt = MutationExecutionEvent(
        plan_id="plan-1",
        target_object_id="obj-1",
        mutation_type="UPDATE_METADATA",
        executor="default",
        applied=True,
        metadata={"stage": "completed"},
    )

    payload = evt.to_payload()
    assert payload["plan_id"] == "plan-1"
    assert payload["target_object_id"] == "obj-1"
    assert payload["mutation_type"] == "UPDATE_METADATA"
    assert payload["executor"] == "default"
    assert payload["applied"] is True
