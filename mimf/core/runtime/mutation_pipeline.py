# mimf/core/runtime/mutation_pipeline.py

from __future__ import annotations

from typing import Optional, Type, Iterable, Union, Any

from mimf.core.policy_engine.policy_engine import PolicyEngine
from mimf.core.policy_engine.policy_context import PolicyContext
from mimf.core.policy_engine.policy_models import DecisionStatus, PolicyDecision
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.events import InspectionEvent, PolicyEvaluationEvent
from mimf.core.security.boundaries import SecurityBoundary
from mimf.core.security.capabilities import Capability

from .mutation import MutationPlan, MutationExecutor
from .object import RuntimeObject
from .dry_run_executor import DryRunExecutor


class SafeMutationPipeline:
    """
    Policy Enforcement Point (PEP) for MIMF.

    Security and forensic invariants:
    - Evaluates policy before any executor runs
    - Emits inspection and policy events to RuntimeContext
    - Does not mutate RuntimeObject in-place
    - Fails closed (DENY -> raise PermissionError)
    - Can inject security intent into PolicyContext metadata (capabilities + boundary)
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        executor_cls: Type[MutationExecutor] = DryRunExecutor,
    ) -> None:
        if policy_engine is None:
            raise RuntimeError("PolicyEngine is mandatory")

        if not issubclass(executor_cls, MutationExecutor):
            raise TypeError("executor_cls must subclass MutationExecutor")

        self._policy_engine = policy_engine
        self._executor_cls = executor_cls

    def execute(
        self,
        plan: MutationPlan,
        runtime_object: RuntimeObject,
        context: Optional[RuntimeContext] = None,
        actor_id: Optional[str] = None,
        actor_capabilities: Optional[Iterable[Union[str, Capability]]] = None,
        boundary: Optional[SecurityBoundary] = None,
        required_capability: Optional[Union[str, Capability]] = None,
    ) -> RuntimeContext:
        """
        Execute a mutation plan under strict policy enforcement.

        If provided, actor_capabilities / boundary / required_capability are injected into the
        PolicyContext metadata in an immutable-safe way (new PolicyContext created with merged metadata).
        """

        if context is None:
            context = RuntimeContext(
                context_id=f"context-{plan.plan_id}",
                actor_id=actor_id,
                operation_name=f"MutationPipeline:{plan.mutation_type}",
            )

        inspection_event = InspectionEvent(
            object_id=runtime_object.object_id,
            snapshot=runtime_object.snapshot(),
        )
        context.emit_event(inspection_event)

        base_pc = PolicyContext.from_runtime(plan=plan, target=runtime_object)

        merged_meta: dict[str, Any] = dict(base_pc.metadata)

        if actor_capabilities is not None:
            normalized_caps: list[str] = []
            for c in actor_capabilities:
                if isinstance(c, Capability):
                    normalized_caps.append(c.name)
                elif isinstance(c, str):
                    normalized_caps.append(Capability(c).name)
                else:
                    normalized_caps = []
                    break

            merged_meta["actor_capabilities"] = normalized_caps

        if boundary is not None:
            merged_meta["boundary"] = boundary

        if required_capability is not None:
            if isinstance(required_capability, Capability):
                merged_meta["required_capability"] = required_capability
            elif isinstance(required_capability, str):
                merged_meta["required_capability"] = Capability(required_capability)
            else:
                merged_meta["required_capability"] = None

        policy_context = PolicyContext(plan=plan, target=runtime_object, metadata=merged_meta)

        decision: PolicyDecision = self._policy_engine.evaluate(policy_context)

        policy_event = PolicyEvaluationEvent(
            plan_id=plan.plan_id,
            target_object_id=runtime_object.object_id,
            decision=decision.status.value,
            policy_id=decision.policy_id,
            reason=decision.reason,
            trace_id=decision.trace_id,
            metadata={
                "mutation_type": plan.mutation_type,
            },
        )
        context.emit_event(policy_event)

        if decision.status == DecisionStatus.DENY:
            raise PermissionError(f"POLICY DENIED [{decision.policy_id}]: {decision.reason}")

        executor = self._executor_cls()
        executor.execute(plan, runtime_object, context)

        return context
