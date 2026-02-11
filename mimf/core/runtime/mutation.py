from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet, Optional

from .context import RuntimeContext
from .events import MutationExecutionEvent, PolicyEvaluationEvent
from .object import RuntimeObject


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    policy_id: Optional[str] = None
    reason: Optional[str] = None
    trace_id: str = ""


@dataclass(frozen=True)
class MutationPlan:
    plan_id: str
    target_object_id: str
    mutation_type: str
    changes: Dict[str, Any]
    allowed_labels: FrozenSet[str]
    created_at: datetime


def _validate(plan: MutationPlan, obj: RuntimeObject) -> None:
    if obj.object_id != plan.target_object_id:
        raise RuntimeError("MutationPlan target mismatch")
    if not obj.labels.issubset(plan.allowed_labels):
        raise RuntimeError(f"Label violation: {obj.labels} not allowed by plan")


class MutationExecutor(ABC):
    executor_name: str = "abstract"

    def execute(
        self,
        plan: MutationPlan,
        obj: RuntimeObject,
        context: RuntimeContext,
    ) -> RuntimeObject:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be a RuntimeContext instance")

        _validate(plan, obj)

        policy_decision = self._evaluate_policy(plan, obj, context)

        context.emit_event(
            PolicyEvaluationEvent(
                plan_id=plan.plan_id,
                target_object_id=obj.object_id,
                decision=policy_decision.decision,
                policy_id=policy_decision.policy_id,
                reason=policy_decision.reason,
                trace_id=policy_decision.trace_id,
                metadata={"stage": "policy-evaluation"},
            )
        )

        context.emit_event(
            MutationExecutionEvent(
                plan_id=plan.plan_id,
                target_object_id=obj.object_id,
                mutation_type=plan.mutation_type,
                executor=self.executor_name,
                applied=False,
                metadata={"stage": "started"},
            )
        )

        new_obj = self._apply(plan, obj)

        context.add_object(new_obj)

        context.emit_event(
            MutationExecutionEvent(
                plan_id=plan.plan_id,
                target_object_id=new_obj.object_id,
                mutation_type=plan.mutation_type,
                executor=self.executor_name,
                applied=True,
                metadata={"stage": "completed"},
            )
        )

        return new_obj

    @abstractmethod
    def _apply(self, plan: MutationPlan, obj: RuntimeObject) -> RuntimeObject:
        raise NotImplementedError

    def _evaluate_policy(
        self,
        plan: MutationPlan,
        obj: RuntimeObject,
        context: RuntimeContext,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision="ALLOW",
            policy_id="default",
            reason="No restrictions applied",
            trace_id=plan.plan_id,
        )
