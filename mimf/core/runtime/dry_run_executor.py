from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict

from .context import RuntimeContext
from .events import MutationExecutionEvent
from .mutation import MutationExecutor, MutationPlan, _validate
from .object import RuntimeObject

# context.update_object(new_obj)


class DryRunExecutor(MutationExecutor):
    """
    Dry-run executor that simulates a mutation plan without mutating the original object.

    Contract
    - Does not evaluate policy (handled by SafeMutationPipeline).
    - Does not mutate RuntimeObject in place.
    - Emits MutationExecutionEvent records for audit and forensics.
    - Registers the simulated object in RuntimeContext.
    """

    executor_name = "dry-run"

    def _apply(self, plan: MutationPlan, obj: RuntimeObject) -> RuntimeObject:
        """
        Produce a new RuntimeObject representing the simulated post-mutation state.
        This is a pure function relative to the input object.
        """
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
        """
        Execute a dry-run mutation.

        Emits
        - MutationExecutionEvent(stage=started, applied=False)
        - MutationExecutionEvent(stage=completed, applied=False)

        Returns
        - The simulated RuntimeObject
        """
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
                metadata={"stage": "started", "dry_run": True},
            )
        )

        new_obj = self._apply(plan, obj)
        # Upsert: add if missing, else update
        try:
            context.update_object(new_obj)
        except RuntimeError:
            context.add_object(new_obj)

        context.emit_event(
            MutationExecutionEvent(
                plan_id=plan.plan_id,
                target_object_id=new_obj.object_id,
                mutation_type=plan.mutation_type,
                executor=self.executor_name,
                applied=False,
                metadata={
                    "stage": "completed",
                    "dry_run": True,
                    "changes": plan.changes,
                    "allowed_labels": list(plan.allowed_labels),
                },
            )
        )

        return new_obj
