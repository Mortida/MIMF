from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict

from .context import RuntimeContext
from .events import MutationExecutionEvent
from .mutation import MutationExecutor, MutationPlan, _validate
from .object import RuntimeObject


class DefaultMutationExecutor(MutationExecutor):
    """
    Real-run executor that applies mutation changes by producing a new RuntimeObject.

    Contract
    - Does not evaluate policy (handled by SafeMutationPipeline).
    - Does not mutate RuntimeObject in place.
    - Emits MutationExecutionEvent records for audit and forensics.
    - Registers the new object in RuntimeContext.
    """

    # context.add_object(new_obj)
    executor_name = "default"

    def _apply(self, plan: MutationPlan, obj: RuntimeObject) -> RuntimeObject:
        new_metadata: Dict[str, Any] = dict(obj.metadata)
        new_metadata.update(plan.changes)

        if hasattr(RuntimeObject, "create") and callable(getattr(RuntimeObject, "create")):
            return RuntimeObject.create(
                object_id=obj.object_id,
                object_type=obj.object_type,
                origin=obj.origin,
                metadata=new_metadata,
                labels=obj.labels,
                created_at=datetime.now(UTC),
            )

        return RuntimeObject(
            object_id=obj.object_id,
            object_type=obj.object_type,
            origin=obj.origin,
            snapshot_hash=getattr(obj, "snapshot_hash", ""),
            metadata=new_metadata,
            labels=obj.labels,
            created_at=datetime.now(UTC),
        )

    def execute(
        self,
        plan: MutationPlan,
        obj: RuntimeObject,
        context: RuntimeContext,
    ) -> RuntimeObject:
        if not isinstance(plan, MutationPlan):
            raise TypeError("plan must be a MutationPlan instance")
        if not isinstance(obj, RuntimeObject):
            raise TypeError("obj must be a RuntimeObject instance")
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be a RuntimeContext instance")

        _validate(plan, obj)

        context.emit_event(
            MutationExecutionEvent(
                plan_id=plan.plan_id,
                target_object_id=obj.object_id,
                mutation_type=plan.mutation_type,
                executor=self.executor_name,
                applied=False,
                metadata={"stage": "started", "dry_run": False},
            )
        )

        new_obj = self._apply(plan, obj)
        context.upsert_object(new_obj)

        context.emit_event(
            MutationExecutionEvent(
                plan_id=plan.plan_id,
                target_object_id=new_obj.object_id,
                mutation_type=plan.mutation_type,
                executor=self.executor_name,
                applied=True,
                metadata={
                    "stage": "completed",
                    "dry_run": False,
                    "changes": plan.changes,
                    "allowed_labels": list(plan.allowed_labels),
                },
            )
        )

        return new_obj
