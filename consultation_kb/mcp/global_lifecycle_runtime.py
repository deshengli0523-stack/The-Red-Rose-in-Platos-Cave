"""Production global rebuild operations behind the lifecycle MCP boundary."""

from __future__ import annotations

import hmac
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn, Protocol, cast, final

from pydantic import ValidationError, model_validator

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
)
from consultation_kb.approvals.store import (
    ApprovalError,
    ApprovalService,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.errors import (
    ChannelUnavailableError,
    ScopedObjectAccessDeniedError,
    WorkflowErrorCode,
    WorkflowOperationalError,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.lifecycle.deletion import (
    DeletionApprovalMismatch,
    DeletionError,
    DeletionService,
)
from consultation_kb.models.deletion import (
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.lifecycle.production_rebuild import (
    ProductionRebuildError,
    load_production_rebuild_config,
    resolve_global_rebuild,
)
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinatorError,
    RebuildPlan,
    RebuildRequest,
)
from consultation_kb.lifecycle.rebuild_jobs import (
    RebuildCancellationRejected,
    RebuildJob,
    RebuildJobError,
    RebuildJobNotFound,
    RebuildJobRepository,
    RebuildJobStateConflict,
)
from consultation_kb.lifecycle.rebuild_registry import BuilderRegistryError
from consultation_kb.lifecycle.rollback import (
    RollbackBaseVersion,
    RollbackError,
    SqliteRollbackWorkflow,
)
from consultation_kb.models.common import ObjectId, Sha256Hex, StrictModel
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.worker_protocol import ArchiveContentRef
from consultation_kb.storage.deletion_inventory import (
    DeletionInventoryError,
    SqliteDeletionInventoryAdapter,
)
from consultation_kb.vault.content_store import (
    ContentHashMismatch,
    ContentScopeMismatch,
    ContentStore,
    InvalidContentReference,
)

from .context import BoundTransport
from .schemas import (
    CancelRebuildInput,
    GetRebuildReportInput,
    GetRebuildStatusInput,
    LifecycleBaseVersion,
    CommitDeleteInput,
    PreviewDeleteInput,
    PreviewRebuildInput,
    RollbackVersionInput,
    StartRebuildInput,
)


class _ApprovalRuntime(Protocol):
    def issue_for_execution(
        self,
        request_id: str,
        descriptor: DraftDescriptor,
        *,
        operation_id: str,
    ) -> ApprovalExecutionTicket: ...

    def acknowledge(self, proof: ApprovalExecutionProof) -> object: ...


class _ExecutionRuntime(Protocol):
    def apply_in_transaction(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        callback: Callable[[sqlite3.Connection], object],
    ) -> ApprovalExecutionProof: ...


@dataclass(frozen=True, slots=True)
class TargetScopedDeletionAuthority:
    """Exact-scope approval and target execution pair for one deletion plan."""

    approval_service: ApprovalService
    execution_guard: ApprovalExecutionGuard

    def __post_init__(self) -> None:
        if not isinstance(self.approval_service, ApprovalService):
            raise TypeError("GLOBAL_DELETION_APPROVAL_SERVICE_REQUIRED")
        if not isinstance(self.execution_guard, ApprovalExecutionGuard):
            raise TypeError("GLOBAL_DELETION_EXECUTION_GUARD_REQUIRED")


class _GlobalDeletionPlanEnvelope(StrictModel):
    schema_version: Literal["global_deletion_plan.v1"] = (
        "global_deletion_plan.v1"
    )
    operation_id: ObjectId
    plan: DeletionPlan


class _GlobalRebuildPlanEnvelope(StrictModel):
    schema_version: Literal["global_rebuild_plan.v1"] = (
        "global_rebuild_plan.v1"
    )
    action: Literal["start", "cancel"]
    operation_id: ObjectId
    plan: RebuildPlan | None = None
    job_id: ObjectId | None = None
    job_plan_sha256: Sha256Hex | None = None
    base_versions: tuple[LifecycleBaseVersion, ...]
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _exact_action(self) -> "_GlobalRebuildPlanEnvelope":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if keys != tuple(sorted(set(keys))) or len(keys) != 1:
            raise ValueError("GLOBAL_REBUILD_BASE_INVALID")
        base = self.base_versions[0]
        if self.action == "start":
            if (
                self.plan is None
                or self.job_id is not None
                or self.job_plan_sha256 is not None
                or self.plan_sha256 != self.plan.plan_sha256
                or base.authority_key != "tombstone_epoch"
                or base.scope_sha256 != self.plan.scope_sha256
                or base.version != self.plan.tombstone_epoch
                or self.descriptor
                != DraftDescriptor(
                    purpose="rebuild",
                    target_id=f"global_rebuild:{self.plan.purpose}",
                    base_version=self.plan.tombstone_epoch,
                    draft_sha256=self.plan.plan_sha256,
                )
            ):
                raise ValueError("GLOBAL_REBUILD_START_PLAN_INVALID")
            return self
        if (
            self.plan is not None
            or self.job_id is None
            or self.job_plan_sha256 is None
            or base.authority_key != "tombstone_epoch"
        ):
            raise ValueError("GLOBAL_REBUILD_CANCEL_PLAN_INVALID")
        expected = canonical_sha256(
            {
                "domain": "consultation_kb.rebuild_cancel_plan.v1",
                "database_scope": "global",
                "job_id": self.job_id,
                "job_plan_sha256": self.job_plan_sha256,
                "base_versions": [
                    value.model_dump(mode="json")
                    for value in self.base_versions
                ],
            }
        )
        if self.plan_sha256 != expected or self.descriptor != DraftDescriptor(
            purpose="rebuild",
            target_id=f"global_rebuild_cancel:{self.job_id}",
            base_version=base.version,
            draft_sha256=expected,
        ):
            raise ValueError("GLOBAL_REBUILD_CANCEL_PLAN_INVALID")
        return self


def _job_result(job: RebuildJob, *, include_report: bool) -> dict[str, object]:
    value: dict[str, object] = {
        "job_id": job.job_id,
        "purpose": job.purpose,
        "state": job.state,
        "attempt_count": job.attempt_count,
        "plan_sha256": job.plan_sha256,
        "builder_dag_sha256": job.builder_dag_sha256,
        "input_authority_versions_sha256": (
            job.input_authority_versions_sha256
        ),
        "tombstone_epoch": job.tombstone_epoch,
        "output_manifest_set_sha256": job.output_manifest_set_sha256,
        "equivalence_report_sha256": job.equivalence_report_sha256,
        "last_error_code": job.last_error_code,
        "updated_at": job.updated_at,
    }
    if include_report:
        value.update(
            {
                "policy_sha256": job.policy_sha256,
                "model_descriptor_sha256": job.model_descriptor_sha256,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
                "cancelled_at": job.cancelled_at,
            }
        )
    return value


@final
class ProductionGlobalLifecycleRuntime:
    """Global-only rebuild adapter; no client locator is accepted or retained."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        global_root: Path,
        scope_sha256: str,
        approval_service: ApprovalService | _ApprovalRuntime | None = None,
        execution_guard: ApprovalExecutionGuard | _ExecutionRuntime | None = None,
        rollback_workflow: SqliteRollbackWorkflow | None = None,
        target_approval_factory: (
            Callable[[str], TargetScopedDeletionAuthority] | None
        ) = None,
        content_store: ContentStore | None = None,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("GLOBAL_LIFECYCLE_SQLITE_REQUIRED")
        if not isinstance(global_root, Path) or not global_root.is_absolute():
            raise TypeError("GLOBAL_LIFECYCLE_ROOT_REQUIRED")
        resolved_root = global_root.resolve(strict=False)
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        main_rows = tuple(
            row
            for row in database_rows
            if len(row) == 3 and row[1] == "main"
        )
        if (
            resolved_root.name.casefold() != "global"
            or len(main_rows) != 1
            or type(main_rows[0][2]) is not str
            or not main_rows[0][2]
            or Path(str(main_rows[0][2])).resolve(strict=False)
            != (resolved_root / "catalog.sqlite3").resolve(strict=False)
        ):
            raise TypeError("GLOBAL_LIFECYCLE_DATABASE_REQUIRED")
        if re.fullmatch(r"[0-9a-f]{64}", scope_sha256) is None:
            raise ValueError("GLOBAL_LIFECYCLE_SCOPE_INVALID")
        if (approval_service is None) != (execution_guard is None):
            raise TypeError("GLOBAL_LIFECYCLE_APPROVAL_AUTHORITY_INCOMPLETE")
        self._connection = connection
        self._global_root = resolved_root
        self._scope_sha256 = scope_sha256
        self._approvals = approval_service
        self._guard = execution_guard
        if rollback_workflow is not None and (
            not isinstance(rollback_workflow, SqliteRollbackWorkflow)
            or getattr(rollback_workflow, "_connection", None) is not connection
            or getattr(rollback_workflow, "_database_scope", None) != "global"
            or str(getattr(rollback_workflow, "_scope_sha256", ""))
            != scope_sha256
        ):
            raise TypeError("GLOBAL_ROLLBACK_WORKFLOW_INVALID")
        self._rollback = rollback_workflow
        self._target_approval_factory = target_approval_factory
        self._content_store = (
            ContentStore(resolved_root) if content_store is None else content_store
        )
        if type(self._content_store) is not ContentStore:
            raise TypeError("GLOBAL_LIFECYCLE_CONTENT_STORE_REQUIRED")
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory(self._clock)
        self._jobs = RebuildJobRepository(connection, database_scope="global")

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        if (
            binding is None
            or not hmac.compare_digest(
                str(getattr(request, "session_handle", "")),
                binding.session_handle,
            )
        ):
            raise ScopedObjectAccessDeniedError
        if (
            getattr(request, "database_scope", None) != "global"
            or not hmac.compare_digest(
                str(getattr(request, "scope_sha256", "")),
                self._scope_sha256,
            )
        ):
            raise ScopedObjectAccessDeniedError
        try:
            if tool_name == "get_rebuild_status":
                return self._status(cast(GetRebuildStatusInput, request), report=False)
            if tool_name == "get_rebuild_report":
                return self._status(cast(GetRebuildReportInput, request), report=True)
            if tool_name == "preview_rebuild":
                return self._preview_rebuild(cast(PreviewRebuildInput, request))
            if tool_name == "start_rebuild":
                return self._start(cast(StartRebuildInput, request))
            if tool_name == "cancel_rebuild":
                return self._cancel(cast(CancelRebuildInput, request))
            if tool_name == "preview_delete":
                return self._preview_delete(cast(PreviewDeleteInput, request))
            if tool_name == "commit_delete":
                return self._commit_delete(cast(CommitDeleteInput, request))
            if tool_name == "rollback_version":
                return self._rollback_version(
                    cast(RollbackVersionInput, request)
                )
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        except RebuildJobNotFound:
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_JOB_NOT_FOUND
            ) from None
        except RebuildCancellationRejected:
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_CANCELLATION_AFTER_ACTIVATION
            ) from None
        except RebuildJobStateConflict:
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_JOB_STATE_CONFLICT
            ) from None
        except ApprovalError:
            raise WorkflowOperationalError(
                WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
            ) from None
        except RollbackError as error:
            raise WorkflowOperationalError(
                WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
                if error.code
                in {
                    "ROLLBACK_APPROVAL_REQUIRED",
                    "ROLLBACK_APPROVAL_BINDING_MISMATCH",
                }
                else WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH
            ) from None
        except DeletionApprovalMismatch:
            self._approval_required()
        except (
            ContentHashMismatch,
            ContentScopeMismatch,
            DeletionError,
            DeletionInventoryError,
            InvalidContentReference,
            ValidationError,
        ):
            self._plan_mismatch()
        except (BuilderRegistryError, ProductionRebuildError, RebuildCoordinatorError):
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE
            ) from None
        except RebuildJobError:
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_JOB_STATE_CONFLICT
            ) from None

    def _rollback_version(
        self,
        request: RollbackVersionInput,
    ) -> dict[str, object]:
        workflow = self._rollback
        approvals = self._approvals
        if workflow is None or not isinstance(approvals, ApprovalService):
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        if request.action == "preview":
            target_kind = request.target_kind
            target_id = request.target_id
            current_version = request.current_version
            restore_version = request.restore_version
            reason = request.reason
            if (
                target_kind is None
                or target_id is None
                or current_version is None
                or restore_version is None
                or reason is None
                or target_kind == "profile_fact"
            ):
                self._plan_mismatch()
            if target_kind == "wiki":
                preview = workflow.preview_wiki(
                    wiki_id=target_id,
                    current_version=current_version,
                    restore_version=restore_version,
                    reason=reason,
                )
            elif target_kind == "theory":
                preview = workflow.preview_theory(
                    theory_id=target_id,
                    current_version=current_version,
                    restore_version=restore_version,
                    reason=reason,
                )
            else:
                source_plan_ref = request.source_plan_ref
                if source_plan_ref is None:
                    self._plan_mismatch()
                preview = workflow.preview_artifact(
                    artifact_key=target_id,
                    current_version=current_version,
                    restore_version=restore_version,
                    reason=reason,
                    source_plan_ref=source_plan_ref,
                )
            approval = approvals.request(
                preview.descriptor,
                diff_object_ref=preview.plan_ref.version_ref,
            )
            return {
                **preview.model_dump(mode="json", exclude={"descriptor"}),
                "approval_request_id": approval.request_id,
                "approval_operation_id": preview.proposed_operation_id,
                "approval_state": approval.state,
                "approval_expires_at": approval.expires_at,
            }

        plan_ref = request.plan_ref
        operation_id = request.approval_operation_id
        approval_request_id = request.approval_request_id
        plan_sha256 = request.plan_sha256
        base_versions = request.base_versions
        if (
            plan_ref is None
            or operation_id is None
            or approval_request_id is None
            or plan_sha256 is None
            or base_versions is None
        ):
            self._plan_mismatch()
        approval_request = approvals.get(approval_request_id)
        rollback_base_versions = tuple(
            RollbackBaseVersion.model_validate(value.model_dump(mode="json"))
            for value in base_versions
        )
        workflow.preflight_commit(
            plan_ref=plan_ref,
            plan_sha256=plan_sha256,
            base_versions=rollback_base_versions,
            approval_operation_id=operation_id,
            approval_request=approval_request,
        )
        ticket = approvals.issue_for_execution(
            approval_request_id,
            approval_request.descriptor,
            operation_id=operation_id,
        )
        committed = workflow.commit(
            plan_ref=plan_ref,
            plan_sha256=plan_sha256,
            base_versions=rollback_base_versions,
            ticket=ticket,
            approval_request=approval_request,
        )
        acknowledged = approvals.acknowledge(committed.proof)
        if (
            acknowledged.operation_id != operation_id
            or acknowledged.state != "acknowledged"
        ):
            self._approval_required()
        return committed.summary.model_dump(mode="json")

    def _status(
        self,
        request: GetRebuildStatusInput | GetRebuildReportInput,
        *,
        report: bool,
    ) -> dict[str, object]:
        job = self._jobs.get(request.job_id)
        self._require_job_scope(job)
        result = _job_result(job, include_report=report)
        if report:
            result["journal"] = tuple(
                {
                    "sequence": entry.sequence,
                    "state": entry.state,
                    "evidence_sha256": entry.evidence_sha256,
                    "occurred_at": entry.occurred_at,
                }
                for entry in self._jobs.journal(job.job_id)
            )
        return result

    def _preview_rebuild(
        self,
        request: PreviewRebuildInput,
    ) -> dict[str, object]:
        approvals = self._approvals
        if not isinstance(approvals, ApprovalService):
            self._approval_required()
        assert isinstance(approvals, ApprovalService)
        if request.action == "start":
            production = load_production_rebuild_config(
                self._global_root,
                database_scope="global",
                scope_sha256=self._scope_sha256,
            )
            if (
                request.purpose != "all"
                or (
                    request.policy_sha256 is not None
                    and request.policy_sha256 != production.policy_sha256
                )
                or (
                    request.model_descriptor_sha256 is not None
                    and request.model_descriptor_sha256
                    != production.model_descriptor_sha256
                )
            ):
                self._plan_mismatch()
            coordinator = resolve_global_rebuild(
                self._connection,
                self._global_root,
                self._scope_sha256,
            )
            plan = coordinator.plan(
                RebuildRequest(
                    database_scope="global",
                    source_intent_id=request.source_intent_id,
                    scope_sha256=self._scope_sha256,
                    purpose="all",
                    policy_sha256=production.policy_sha256,
                    model_descriptor_sha256=(
                        production.model_descriptor_sha256
                    ),
                )
            )
            base_versions = (
                LifecycleBaseVersion(
                    authority_key="tombstone_epoch",
                    scope_sha256=self._scope_sha256,
                    version=plan.tombstone_epoch,
                ),
            )
            descriptor = DraftDescriptor(
                purpose="rebuild",
                target_id="global_rebuild:all",
                base_version=plan.tombstone_epoch,
                draft_sha256=plan.plan_sha256,
            )
            envelope = _GlobalRebuildPlanEnvelope(
                action="start",
                operation_id=self._ids.object_id("rebuild_operation"),
                plan=plan,
                base_versions=base_versions,
                plan_sha256=plan.plan_sha256,
                descriptor=descriptor,
            )
        else:
            assert request.job_id is not None
            job = self._jobs.get(request.job_id)
            self._require_job_scope(job)
            if job.source_intent_id is not None:
                raise WorkflowOperationalError(
                    WorkflowErrorCode.REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN
                )
            if job.state in {"activating", "succeeded"}:
                raise RebuildCancellationRejected
            current = self._current_tombstone_epoch()
            base_versions = (
                LifecycleBaseVersion(
                    authority_key="tombstone_epoch",
                    scope_sha256=self._scope_sha256,
                    version=current,
                ),
            )
            plan_sha256 = canonical_sha256(
                {
                    "domain": "consultation_kb.rebuild_cancel_plan.v1",
                    "database_scope": "global",
                    "job_id": job.job_id,
                    "job_plan_sha256": job.plan_sha256,
                    "base_versions": [
                        value.model_dump(mode="json")
                        for value in base_versions
                    ],
                }
            )
            descriptor = DraftDescriptor(
                purpose="rebuild",
                target_id=f"global_rebuild_cancel:{job.job_id}",
                base_version=current,
                draft_sha256=plan_sha256,
            )
            envelope = _GlobalRebuildPlanEnvelope(
                action="cancel",
                operation_id=self._ids.object_id("rebuild_operation"),
                job_id=job.job_id,
                job_plan_sha256=job.plan_sha256,
                base_versions=base_versions,
                plan_sha256=plan_sha256,
                descriptor=descriptor,
            )
        plan_ref = self._store_rebuild_envelope(envelope)
        approval = approvals.request(
            envelope.descriptor,
            diff_object_ref=plan_ref.version_ref,
        )
        return {
            "status": "pending_local_review",
            "action": envelope.action,
            "plan_ref": plan_ref,
            "plan_sha256": envelope.plan_sha256,
            "proposed_operation_id": envelope.operation_id,
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
            "approval_expires_at": approval.expires_at,
            "base_versions": envelope.base_versions,
            "purpose": None if envelope.plan is None else envelope.plan.purpose,
            "source_intent_id": (
                None if envelope.plan is None else envelope.plan.source_intent_id
            ),
            "job_id": envelope.job_id,
        }

    def _start(self, request: StartRebuildInput) -> dict[str, object]:
        envelope = self._read_rebuild_envelope(request.plan_ref)
        if (
            envelope.action != "start"
            or envelope.plan is None
            or envelope.operation_id != request.approval_operation_id
            or envelope.plan_sha256 != request.plan_sha256
            or envelope.base_versions != request.base_versions
            or envelope.plan.purpose != "all"
        ):
            self._plan_mismatch()
        self._require_rebuild_approval(request, envelope)
        plan = envelope.plan
        production = load_production_rebuild_config(
            self._global_root,
            database_scope="global",
            scope_sha256=self._scope_sha256,
        )
        if (
            plan.policy_sha256 != production.policy_sha256
            or plan.model_descriptor_sha256
            != production.model_descriptor_sha256
        ):
            self._plan_mismatch()
        coordinator = resolve_global_rebuild(
            self._connection,
            self._global_root,
            self._scope_sha256,
        )
        current_plan = coordinator.plan(
            RebuildRequest(
                database_scope="global",
                source_intent_id=plan.source_intent_id,
                scope_sha256=self._scope_sha256,
                purpose=plan.purpose,
                policy_sha256=production.policy_sha256,
                model_descriptor_sha256=production.model_descriptor_sha256,
            )
        )
        if current_plan != plan:
            self._plan_mismatch()

        def enqueue(target: sqlite3.Connection) -> None:
            if target is not self._connection or not target.in_transaction:
                self._approval_required()
            if coordinator.plan(
                RebuildRequest(
                    database_scope="global",
                    source_intent_id=plan.source_intent_id,
                    scope_sha256=self._scope_sha256,
                    purpose=plan.purpose,
                    policy_sha256=plan.policy_sha256,
                    model_descriptor_sha256=plan.model_descriptor_sha256,
                )
            ) != plan:
                self._plan_mismatch()
            coordinator.start_in_transaction(
                plan,
                idempotency_key=request.idempotency_key,
                approval_operation_id=request.approval_operation_id,
                approval_request_id=request.approval_request_id,
            )

        self._execute_approved(request, envelope.descriptor, enqueue)
        job = self._job_for_execution(request, plan.plan_sha256)
        return _job_result(job, include_report=False)

    def _cancel(self, request: CancelRebuildInput) -> dict[str, object]:
        envelope = self._read_rebuild_envelope(request.plan_ref)
        if (
            envelope.action != "cancel"
            or envelope.job_id is None
            or envelope.job_plan_sha256 is None
            or envelope.operation_id != request.approval_operation_id
            or envelope.plan_sha256 != request.plan_sha256
            or envelope.base_versions != request.base_versions
        ):
            self._plan_mismatch()
        self._require_rebuild_approval(request, envelope)
        job = self._jobs.get(envelope.job_id)
        self._require_job_scope(job)
        if job.source_intent_id is not None:
            raise WorkflowOperationalError(
                WorkflowErrorCode.REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN
            )
        if not hmac.compare_digest(
            job.plan_sha256,
            envelope.job_plan_sha256,
        ):
            self._plan_mismatch()
        base = self._require_base(request.base_versions)
        current = self._current_tombstone_epoch()
        if base.version != current:
            self._plan_mismatch()
        def cancel(target: sqlite3.Connection) -> None:
            if target is not self._connection or not target.in_transaction:
                self._approval_required()
            self._jobs.cancel_before_activation_in_transaction(job.job_id)

        self._execute_approved(request, envelope.descriptor, cancel)
        return _job_result(self._jobs.get(job.job_id), include_report=False)

    def _store_rebuild_envelope(
        self,
        envelope: _GlobalRebuildPlanEnvelope,
    ) -> ArchiveContentRef:
        store = self._rebuild_content_store()
        plan_object_id = self._ids.object_id("lifecycle_plan")
        stored = store.finalize(
            store.stage_bytes(
                canonical_json_bytes(envelope.model_dump(mode="json")),
                purpose="rebuild",
                manifest_id=plan_object_id,
                media_type="application/json",
            )
        )
        return ArchiveContentRef(
            object_id=plan_object_id,
            version=1,
            content_sha256=stored.content_sha256,
            media_type="application/json",
            size_bytes=stored.size_bytes,
        )

    def _read_rebuild_envelope(
        self,
        plan_ref: ArchiveContentRef,
    ) -> _GlobalRebuildPlanEnvelope:
        store = self._rebuild_content_store()
        payload = store.read_verified(
            store.reference(
                content_sha256=plan_ref.content_sha256,
                media_type=plan_ref.media_type,
                size_bytes=plan_ref.size_bytes,
            )
        )
        return _GlobalRebuildPlanEnvelope.model_validate_json(
            payload,
            strict=True,
        )

    def _rebuild_content_store(self) -> ContentStore:
        config = load_production_rebuild_config(
            self._global_root,
            database_scope="global",
            scope_sha256=self._scope_sha256,
        )
        candidate = (
            self._global_root / Path(config.cas_directory)
        ).resolve(strict=False)
        if candidate == self._global_root or not candidate.is_relative_to(
            self._global_root
        ):
            raise ProductionRebuildError("REBUILD_PRODUCTION_PATH_INVALID")
        return ContentStore(candidate)

    def _require_rebuild_approval(
        self,
        request: StartRebuildInput | CancelRebuildInput,
        envelope: _GlobalRebuildPlanEnvelope,
    ) -> None:
        approvals = self._approvals
        if not isinstance(approvals, ApprovalService):
            self._approval_required()
        assert isinstance(approvals, ApprovalService)
        approval = approvals.get(request.approval_request_id)
        if (
            approval.descriptor != envelope.descriptor
            or approval.diff_object_ref != request.plan_ref.version_ref
        ):
            self._approval_required()

    def _preview_delete(self, request: PreviewDeleteInput) -> dict[str, object]:
        if request.target_type not in {
            "case",
            "case_authorization",
            "passage",
            "claim",
        } or (
            request.target_id is None
            or request.target_version is None
            or request.target_content_sha256 is None
        ):
            raise ScopedObjectAccessDeniedError
        target = DeletionTarget(
            target_type=request.target_type,
            object_ref=DeletionObjectRef(
                object_type=request.target_type,
                object_id=request.target_id,
                version=request.target_version,
                content_sha256=request.target_content_sha256,
                authority_scope="global",
            ),
        )
        plan = DeletionService.for_preview(
            self._connection,
            inventory_adapter=SqliteDeletionInventoryAdapter(
                self._connection,
                authority_scope="global",
            ),
            clock=self._clock,
        ).preview(
            DeletionPreviewRequest(
                request_id=self._ids.object_id("deletion_request"),
                target=target,
                reason_code=request.reason_code,
                requested_at=self._clock.now(),
            )
        )
        operation_id = self._ids.object_id("deletion_operation")
        plan_object_id = self._ids.object_id("lifecycle_plan")
        payload = canonical_json_bytes(
            _GlobalDeletionPlanEnvelope(
                operation_id=operation_id,
                plan=plan,
            ).model_dump(mode="json")
        )
        stored = self._content_store.finalize(
            self._content_store.stage_bytes(
                payload,
                purpose="delete",
                manifest_id=plan_object_id,
                media_type="application/json",
            )
        )
        plan_ref = ArchiveContentRef(
            object_id=plan_object_id,
            version=1,
            content_sha256=stored.content_sha256,
            media_type="application/json",
            size_bytes=stored.size_bytes,
        )
        authority = self._target_authority(plan.target_scope_hash)
        approval = authority.approval_service.request(
            plan.descriptor,
            diff_object_ref=plan_ref.version_ref,
        )
        return {
            "status": "pending_local_review",
            "plan_ref": plan_ref,
            "plan_sha256": plan.plan_sha256,
            "target_scope_hash": plan.target_scope_hash,
            "proposed_operation_id": operation_id,
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
            "approval_expires_at": approval.expires_at,
            "base_deletion_version": plan.base_deletion_version,
            "base_versions": tuple(
                LifecycleBaseVersion.model_validate(
                    value.model_dump(mode="json")
                )
                for value in plan.base_versions
            ),
            "action_count": len(plan.actions),
            "retained_audit_count": len(plan.retained_audit_refs),
        }

    def _commit_delete(self, request: CommitDeleteInput) -> dict[str, object]:
        payload = self._content_store.read_verified(
            self._content_store.reference(
                content_sha256=request.plan_ref.content_sha256,
                media_type=request.plan_ref.media_type,
                size_bytes=request.plan_ref.size_bytes,
            )
        )
        envelope = _GlobalDeletionPlanEnvelope.model_validate_json(
            payload,
            strict=True,
        )
        plan = envelope.plan
        expected_bases = tuple(
            LifecycleBaseVersion.model_validate(value.model_dump(mode="json"))
            for value in plan.base_versions
        )
        if (
            envelope.operation_id != request.approval_operation_id
            or plan.plan_sha256 != request.plan_sha256
            or plan.target_scope_hash != request.target_scope_hash
            or expected_bases != request.base_versions
        ):
            self._plan_mismatch()
        authority = self._target_authority(plan.target_scope_hash)
        approval = authority.approval_service.get(request.approval_request_id)
        if (
            approval.descriptor != plan.descriptor
            or approval.diff_object_ref != request.plan_ref.version_ref
        ):
            self._approval_required()
        ticket = ApprovalExecutionTicket.model_validate(
            authority.approval_service.issue_for_execution(
                request.approval_request_id,
                plan.descriptor,
                operation_id=request.approval_operation_id,
            )
        )
        if (
            ticket.operation_id != envelope.operation_id
            or ticket.request_id != request.approval_request_id
            or ticket.descriptor != plan.descriptor
            or not hmac.compare_digest(
                ticket.target_scope_hash,
                plan.target_scope_hash,
            )
        ):
            self._approval_required()
        result, proof = DeletionService(
            self._connection,
            approval_guard=authority.execution_guard,
            clock=self._clock,
            inventory_adapter=SqliteDeletionInventoryAdapter(
                self._connection,
                authority_scope="global",
            ),
        ).commit_tombstone_attested(plan, ticket)
        authority.approval_service.acknowledge(proof)
        return {
            "status": "tombstone_committed",
            **result.model_dump(mode="json"),
        }

    def _target_authority(
        self,
        target_scope_hash: str,
    ) -> TargetScopedDeletionAuthority:
        factory = self._target_approval_factory
        if factory is None:
            self._approval_required()
        assert factory is not None
        authority = factory(target_scope_hash)
        if not isinstance(authority, TargetScopedDeletionAuthority):
            self._approval_required()
        return authority

    def _execute_approved(
        self,
        request: StartRebuildInput | CancelRebuildInput,
        descriptor: DraftDescriptor,
        callback: Callable[[sqlite3.Connection], None],
    ) -> None:
        approvals = self._approvals
        guard = self._guard
        if approvals is None or guard is None:
            raise WorkflowOperationalError(
                WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
            )
        ticket = ApprovalExecutionTicket.model_validate(
            approvals.issue_for_execution(
                request.approval_request_id,
                descriptor,
                operation_id=request.approval_operation_id,
            )
        )
        if (
            ticket.operation_id != request.approval_operation_id
            or ticket.request_id != request.approval_request_id
            or ticket.descriptor != descriptor
            or not hmac.compare_digest(
                ticket.target_scope_hash,
                self._scope_sha256,
            )
        ):
            self._approval_required()
        proof = guard.apply_in_transaction(ticket, descriptor, callback)
        approvals.acknowledge(proof)

    def _require_plan_request(
        self,
        request: StartRebuildInput,
        plan: RebuildPlan,
    ) -> None:
        base = self._require_base(request.base_versions)
        if (
            not hmac.compare_digest(request.plan_sha256, plan.plan_sha256)
            or base.version != plan.tombstone_epoch
        ):
            self._plan_mismatch()

    def _require_base(
        self,
        values: tuple[LifecycleBaseVersion, ...],
    ) -> LifecycleBaseVersion:
        if len(values) != 1:
            self._plan_mismatch()
        value = values[0]
        if (
            value.authority_key != "tombstone_epoch"
            or not hmac.compare_digest(value.scope_sha256, self._scope_sha256)
        ):
            self._plan_mismatch()
        return value

    def _current_tombstone_epoch(self) -> int:
        row = self._connection.execute(
            "SELECT tombstone_epoch FROM deletion_authority_state "
            "WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise RebuildJobStateConflict
        return int(row[0])

    def _job_for_execution(
        self,
        request: StartRebuildInput,
        plan_sha256: str,
    ) -> RebuildJob:
        row = self._connection.execute(
            "SELECT job_id FROM rebuild_jobs WHERE "
            "approval_operation_id = ? AND approval_request_id = ? "
            "AND plan_sha256 = ? AND scope_sha256 = ?",
            (
                request.approval_operation_id,
                request.approval_request_id,
                plan_sha256,
                self._scope_sha256,
            ),
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise RebuildJobStateConflict
        return self._jobs.get(str(row[0]))

    def _require_job_scope(self, job: RebuildJob) -> None:
        if (
            job.database_scope != "global"
            or not hmac.compare_digest(job.scope_sha256, self._scope_sha256)
        ):
            raise ScopedObjectAccessDeniedError

    @staticmethod
    def _plan_mismatch() -> NoReturn:
        raise WorkflowOperationalError(WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH)

    @staticmethod
    def _approval_required() -> NoReturn:
        raise WorkflowOperationalError(
            WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
        )


__all__ = [
    "ProductionGlobalLifecycleRuntime",
    "TargetScopedDeletionAuthority",
]
