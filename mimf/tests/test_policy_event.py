from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import PolicyEvaluationEvent


def test_policy_evaluation_event_seals_and_integrity_is_valid():
    ctx = RuntimeContext(context_id="ctx-1", actor_id="actor-1")

    evt = PolicyEvaluationEvent(
        plan_id="plan-1",
        target_object_id="obj-1",
        decision="ALLOW",
        policy_id="policy-1",
        reason="unit-test",
        trace_id="trace-1",
        metadata={"k": "v"},
    )

    ctx.emit_event(evt)

    events = ctx.get_events()
    assert len(events) == 1
    assert events[0].previous_event_hash == "GENESIS"
    assert events[0].event_hash is not None
    assert ctx.verify_integrity() is True


def test_policy_evaluation_event_payload_contains_required_fields():
    evt = PolicyEvaluationEvent(
        plan_id="plan-1",
        target_object_id="obj-1",
        decision="DENY",
    )

    payload = evt.to_payload()
    assert payload["plan_id"] == "plan-1"
    assert payload["target_object_id"] == "obj-1"
    assert payload["decision"] == "DENY"
