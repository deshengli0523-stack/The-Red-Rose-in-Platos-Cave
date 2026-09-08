"""P8 lifecycle MCP registrations and production rebuild adapter contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, final

from consultation_kb.lifecycle.rebuild import (
    ArtifactBuilder,
    BuildContext,
    BuiltArtifact,
    RebuildCoordinator,
    RebuildCoordinatorError,
    RebuildPlan,
)
from consultation_kb.lifecycle.rebuild_registry import (
    BuilderDescriptor,
    BuilderRegistry,
    DatabaseScope,
)

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    CancelRebuildInput,
    CommitDeleteInput,
    DRAFT_WRITE_ANNOTATIONS,
    FORMAL_WRITE_ANNOTATIONS,
    GetRebuildReportInput,
    GetRebuildStatusInput,
    PreviewDeleteInput,
    PreviewRebuildInput,
    READ_ANNOTATIONS,
    RollbackVersionInput,
    StartRebuildInput,
)


class ProductionBuilderCallable(Protocol):
    """Existing production artifact builder adapted to the P8 build context."""

    def __call__(self, context: BuildContext) -> BuiltArtifact: ...


@dataclass(frozen=True, slots=True)
class ProductionArtifactBuilderAdapter:
    """Explicit adapter; declarations alone are never considered executable."""

    descriptor: BuilderDescriptor
    implementation: Callable[[BuildContext], BuiltArtifact]

    def __post_init__(self) -> None:
        BuilderDescriptor.model_validate(self.descriptor)
        if not callable(self.implementation):
            raise TypeError("REBUILD_PRODUCTION_BUILDER_REQUIRED")

    def build(self, context: BuildContext) -> BuiltArtifact:
        return self.implementation(context)


@final
class ProductionBuilderSet:
    """Restart-stable exact builder map for one database scope.

    Composition must inject adapters for every descriptor that can be queued.
    This class intentionally has no fallback synthetic builder.
    """

    def __init__(
        self,
        *,
        database_scope: DatabaseScope,
        registry: BuilderRegistry,
        adapters: Mapping[str, ArtifactBuilder],
    ) -> None:
        if database_scope not in {"global", "client"}:
            raise ValueError("REBUILD_DATABASE_SCOPE_INVALID")
        self._scope = database_scope
        self._registry = registry
        self._adapters = dict(adapters)
        declared = {
            descriptor.builder_id: descriptor
            for descriptor in registry.descriptors
            if descriptor.database_scope == database_scope
        }
        if set(self._adapters) != set(declared):
            raise RebuildCoordinatorError("REBUILD_PRODUCTION_BUILDERS_INCOMPLETE")
        if any(
            adapter.descriptor != declared[builder_id]
            for builder_id, adapter in self._adapters.items()
        ):
            raise RebuildCoordinatorError("REBUILD_PRODUCTION_BUILDER_MISMATCH")

    @property
    def adapters(self) -> Mapping[str, ArtifactBuilder]:
        return dict(self._adapters)

    def assert_resolvable(self, plan: RebuildPlan) -> None:
        exact = RebuildPlan.model_validate(plan)
        if exact.database_scope != self._scope:
            raise RebuildCoordinatorError("REBUILD_DATABASE_SCOPE_MISMATCH")
        descriptors = self._registry.plan(
            database_scope=self._scope,
            purpose=exact.purpose,
        )
        for descriptor in descriptors:
            adapter = self._adapters.get(descriptor.builder_id)
            if adapter is None or adapter.descriptor != descriptor:
                raise RebuildCoordinatorError("REBUILD_BUILDER_UNAVAILABLE")


def require_executable_rebuild(
    coordinator: RebuildCoordinator,
    plan: RebuildPlan,
    *,
    production_builders: ProductionBuilderSet,
) -> None:
    """Shared pre-enqueue gate used by global and scoped-worker adapters."""

    production_builders.assert_resolvable(plan)
    coordinator.assert_executable(plan)


def build_lifecycle_handlers(
    context: McpHandlerContext,
) -> tuple[ToolHandler, ...]:
    """Bind P8 lifecycle tools to the already-bound session router.

    A binding is required even for global status calls.  It is an opaque task
    scope, not a client selector; therefore no lifecycle request can switch
    subjects or smuggle a client root into the global handler.
    """

    formal = (
        ("rollback_version", RollbackVersionInput),
        ("start_rebuild", StartRebuildInput),
        ("cancel_rebuild", CancelRebuildInput),
        ("commit_delete", CommitDeleteInput),
    )
    reads = (
        ("get_rebuild_status", GetRebuildStatusInput),
        ("get_rebuild_report", GetRebuildReportInput),
    )
    handlers: dict[str, ToolHandler] = {}
    for name, input_model in formal:
        handlers[name] = make_handler(
            name=name,
            input_model=input_model,
            annotations=FORMAL_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        )
    for name, read_input_model in reads:
        handlers[name] = make_handler(
            name=name,
            input_model=read_input_model,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        )
    handlers["preview_delete"] = make_handler(
        name="preview_delete",
        input_model=PreviewDeleteInput,
        annotations=DRAFT_WRITE_ANNOTATIONS,
        context=context,
        service_slot="session",
        requires_session_binding=True,
    )
    handlers["preview_rebuild"] = make_handler(
        name="preview_rebuild",
        input_model=PreviewRebuildInput,
        annotations=DRAFT_WRITE_ANNOTATIONS,
        context=context,
        service_slot="session",
        requires_session_binding=True,
    )
    return tuple(
        handlers[name]
        for name in (
            "rollback_version",
            "start_rebuild",
            "get_rebuild_status",
            "get_rebuild_report",
            "cancel_rebuild",
            "preview_rebuild",
            "preview_delete",
            "commit_delete",
        )
    )


__all__ = [
    "ProductionArtifactBuilderAdapter",
    "ProductionBuilderCallable",
    "ProductionBuilderSet",
    "build_lifecycle_handlers",
    "require_executable_rebuild",
]
