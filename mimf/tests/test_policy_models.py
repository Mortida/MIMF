import pytest

from mimf.core.policy_engine.policy_models import DecisionStatus, PolicyDecision


def test_policy_decision_is_immutable_and_serializes_safely():
    decision = PolicyDecision(
        status=DecisionStatus.ALLOW,
        policy_id="p-1",
        reason="ok",
        trace_id="t-1",
        metadata={"x": 1},
    )

    assert decision.status == DecisionStatus.ALLOW
    assert decision.to_dict()["status"] == "ALLOW"
    assert decision.to_dict()["policy_id"] == "p-1"
    assert decision.to_dict()["metadata"]["x"] == 1

    with pytest.raises(Exception):
        decision.policy_id = "p-2"


def test_decision_status_is_enum_and_blocks_typos():
    assert DecisionStatus("ALLOW") == DecisionStatus.ALLOW

    with pytest.raises(ValueError):
        DecisionStatus("ALOW")
