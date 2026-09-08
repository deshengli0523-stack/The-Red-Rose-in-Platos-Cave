"""Current-client deletion orchestration over the global authority database.

The public MCP boundary never supplies a client identifier, filesystem path,
or SQL fragment.  ``SessionRuntimeManager`` resolves the already-bound client
and passes that private authority into this adapter.  The adapter then builds
and commits the ordinary exact :class:`DeletionPlan`; physical removal remains
a restart-safe follow-up owned by :class:`WholeClientCleanupCoordinator`.
"""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Callable
from typing import Literal, Protocol, cast

from pydantic import ValidationError

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import ApprovalExecutionTicket
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.common import ObjectId, StrictModel, UtcDateTime
from consultation_kb.models.deletion import (
    DeletionBaseVersion,
    DeletionCommitResult,
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.security.worker_protocol import ArchiveContentRef
from consultation_kb.storage.deletion_inventory import (
    SqliteDeletionInventoryAdapter,
    client_authority_sha256,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import (
    ContentHashMismatch,
    ContentScopeMismatch,
    ContentStore,
    InvalidContentReference,
)

from .cleanup_authority import CleanupAuthorityResolver
from .deletion import DeletionError, DeletionService
from .whole_client_cleanup import (
    ClientContributorHasher,
    ClientScopeQuiescer,
    WholeClientCleanupCoordinator,
    WholeClientCleanupResult,
)


class WholeClientSagaError(RuntimeError):
    """Fixed-code, content-free whole-client lifecycle failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WholeClientDeletionApprovalAuthority(Protocol):
    approval_service: ApprovalService
    execution_guard: ApprovalExecutionGuard


class _WholeClientDeletionEnvelope(StrictModel):
    schema_version: Literal["whole_client_deletion_plan.v1"] = (
        "whole_client_deletion_plan.v1"
    )
    operation_id: ObjectId
    plan: DeletionPlan


class WholeClientDeletionPreview(StrictModel):
    """Body-free preview safe to return through the public text boundary."""

    status: Literal["pending_local_review"] = "pending_local_review"
    plan_ref: ArchiveContentRef
    plan_sha256: str
    target_scope_hash: str
    proposed_operation_id: ObjectId
    approval_request_id: ObjectId
    approval_state: str
    approval_expires_at: UtcDateTime
    base_deletion_version: int
    base_versions: tuple[DeletionBaseVersion, ...]
    action_count: int
    retained_audit_count: int


class WholeClientDeletionCommit(StrictModel):
    """Committed zero-recall authority plus its durable cleanup state."""

    status: Literal["tombstone_committed"] = "tombstone_committed"
    result: DeletionCommitResult
    client_scope_state: Literal["closed"] = "closed"
    physical_cleanup_state: Literal["pending", "succeeded"] = "pending"


class WholeClientDeletionSaga:
    """Preview/commit the bound client and replay physical cleanup by intent.

    The global tombstone transaction and later client-vault removal are a
    recoverable saga, not a cross-database transaction.  A successful commit
    first makes every affected global object non-retrievable and persists all
    cleanup/rebuild/backup intents.  Only then is the live client worker closed.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        approval_factory: Callable[[str], object],
        contributor_hasher: ClientContributorHasher,
        quiescer: ClientScopeQuiescer,
        clock: Clock,
        id_factory: IdFactory,
        cleanup_coordinator: WholeClientCleanupCoordinator | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("WHOLE_CLIENT_SAGA_SQLITE_REQUIRED")
        if not isinstance(content_store, ContentStore):
            raise TypeError("WHOLE_CLIENT_SAGA_CAS_REQUIRED")
        if not callable(approval_factory):
            raise TypeError("WHOLE_CLIENT_SAGA_APPROVAL_FACTORY_REQUIRED")
        if not callable(getattr(contributor_hasher, "hash_client_id", None)):
            raise TypeError("WHOLE_CLIENT_SAGA_HASHER_REQUIRED")
        if not callable(getattr(quiescer, "close_and_verify", None)) or not callable(
            getattr(quiescer, "verify_closed", None)
        ):
            raise TypeError("WHOLE_CLIENT_SAGA_QUIESCER_REQUIRED")
        if type(id_factory) is not IdFactory:
            raise TypeError("WHOLE_CLIENT_SAGA_ID_FACTORY_REQUIRED")
        self._connection = connection
        self._store = content_store
        self._approval_factory = approval_factory
        self._hasher = contributor_hasher
        self._quiescer = quiescer
        self._clock = clock
        self._ids = id_factory
        self._cleanup = cleanup_coordinator

    def preview(
        self,
        *,
        bound_client_id: str,
        reason_code: str,
    ) -> WholeClientDeletionPreview:
        """Build an exact global closure from the live internal binding."""

        target = self._active_target(bound_client_id)
        contributor_hash = self._hasher.hash_client_id(bound_client_id)
        adapter = SqliteDeletionInventoryAdapter(
            self._connection,
            authority_scope="global",
            contributor_client_hash=contributor_hash,
        )
        plan = DeletionService.for_preview(
            self._connection,
            inventory_adapter=adapter,
            clock=self._clock,
        ).preview(
            DeletionPreviewRequest(
                request_id=self._ids.object_id("deletion_request"),
                target=target,
                reason_code=reason_code,
                requested_at=self._clock.now(),
            )
        )
        operation_id = self._ids.object_id("deletion_operation")
        plan_ref = self._store_envelope(
            _WholeClientDeletionEnvelope(
                operation_id=operation_id,
                plan=plan,
            )
        )
        authority = self._authority(plan.target_scope_hash)
        approval = authority.approval_service.request(
            plan.descriptor,
            diff_object_ref=plan_ref.version_ref,
        )
        return WholeClientDeletionPreview(
            plan_ref=plan_ref,
            plan_sha256=plan.plan_sha256,
            target_scope_hash=plan.target_scope_hash,
            proposed_operation_id=operation_id,
            approval_request_id=approval.request_id,
            approval_state=approval.state,
            approval_expires_at=approval.expires_at,
            base_deletion_version=plan.base_deletion_version,
            base_versions=plan.base_versions,
            action_count=len(plan.actions),
            retained_audit_count=len(plan.retained_audit_refs),
        )

    def commit(
        self,
        *,
        bound_client_id: str,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        target_scope_hash: str,
        base_versions: tuple[DeletionBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
    ) -> WholeClientDeletionCommit:
        """Atomically tombstone globally, then close the exact live client."""

        envelope = self._read_envelope(plan_ref)
        plan = envelope.plan
        if (
            envelope.operation_id != approval_operation_id
            or plan.plan_sha256 != plan_sha256
            or plan.target_scope_hash != target_scope_hash
            or plan.base_versions != base_versions
            or plan.target.target_type != "client"
            or plan.target.client_id != bound_client_id
            or plan.target.object_ref.object_id != bound_client_id
            or plan.descriptor.client_id != bound_client_id
            or plan.descriptor.session_id is not None
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_PLAN_BINDING_MISMATCH")
        authority = self._authority(plan.target_scope_hash)
        approval = authority.approval_service.get(approval_request_id)
        if (
            approval.descriptor != plan.descriptor
            or approval.diff_object_ref != plan_ref.version_ref
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_APPROVAL_BINDING_MISMATCH")
        ticket = ApprovalExecutionTicket.model_validate(
            authority.approval_service.issue_for_execution(
                approval_request_id,
                plan.descriptor,
                operation_id=approval_operation_id,
            )
        )
        if (
            ticket.operation_id != envelope.operation_id
            or ticket.request_id != approval_request_id
            or ticket.descriptor != plan.descriptor
            or not hmac.compare_digest(
                ticket.target_scope_hash,
                plan.target_scope_hash,
            )
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_APPROVAL_BINDING_MISMATCH")
        guard = authority.execution_guard
        if self._execution_applied(ticket):
            proof = guard.apply_in_transaction(
                ticket,
                plan.descriptor,
                self._refuse_replay_write,
            )
            result = self._recover_committed_result(plan)
        else:
            try:
                result, proof = DeletionService(
                    self._connection,
                    approval_guard=guard,
                    clock=self._clock,
                    inventory_adapter=SqliteDeletionInventoryAdapter(
                        self._connection,
                        authority_scope="global",
                        contributor_client_hash=self._hasher.hash_client_id(
                            bound_client_id
                        ),
                    ),
                ).commit_tombstone_attested(plan, ticket)
            except DeletionError:
                # Another process may have committed and advanced cleanup after
                # the preflight read.  Only an exact APPLIED execution permits
                # recovery; all other deletion errors remain fail-closed.
                if not self._execution_applied(ticket):
                    raise
                proof = guard.apply_in_transaction(
                    ticket,
                    plan.descriptor,
                    self._refuse_replay_write,
                )
                result = self._recover_committed_result(plan)
        authority.approval_service.acknowledge(proof)

        # This occurs strictly after the durable tombstone transaction.  Any
        # exception leaves zero-recall authority in place and the physical
        # cleanup intent available for restart recovery.
        quiescence = self._quiescer.close_and_verify(bound_client_id)
        if (
            quiescence.client_id != bound_client_id
            or not quiescence.worker_handles_closed
            or not quiescence.sqlite_handles_closed
            or not quiescence.mmap_handles_closed
            or not self._quiescer.verify_closed(quiescence)
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_QUIESCENCE_PENDING")
        cleanup_state: Literal["pending", "succeeded"] = "pending"
        if self._cleanup is not None:
            cleanup = self._cleanup.process(self._root_intent_id(plan))
            cleanup_state = (
                "succeeded" if cleanup.state == "succeeded" else "pending"
            )
        return WholeClientDeletionCommit(
            result=result,
            physical_cleanup_state=cleanup_state,
        )

    def replay_cleanup_intent(self, intent_id: str) -> WholeClientCleanupResult:
        """Replay one opaque global intent without accepting a client path."""

        coordinator = self._cleanup
        if coordinator is None:
            raise WholeClientSagaError("WHOLE_CLIENT_CLEANUP_UNAVAILABLE")
        return coordinator.process(intent_id)

    def recover_pending_cleanup(self) -> tuple[WholeClientCleanupResult, ...]:
        """Replay only durable client-root intents after process restart."""

        coordinator = self._cleanup
        if coordinator is None:
            return ()
        rows = self._connection.execute(
            "SELECT intent_id FROM deletion_queue_intents "
            "WHERE action_type = 'physical_delete' AND object_type = 'client' "
            "AND state IN ('PENDING','FAILED','CLAIMED') ORDER BY created_at, intent_id"
        ).fetchall()
        results: list[WholeClientCleanupResult] = []
        for row in rows:
            results.append(coordinator.process(str(row[0])))
        return tuple(results)

    def _active_target(self, client_id: str) -> DeletionTarget:
        rows = self._connection.execute(
            "SELECT directory_object_id, alias_lookup_sha256, state, created_at "
            "FROM clients WHERE client_id = ?",
            (client_id,),
        ).fetchall()
        if len(rows) != 1 or rows[0][2] != "ACTIVE":
            raise WholeClientSagaError("WHOLE_CLIENT_SCOPE_DENIED")
        directory_object_id, alias_lookup_sha256, _state, created_at = rows[0]
        return DeletionTarget(
            target_type="client",
            object_ref=DeletionObjectRef(
                object_type="client",
                object_id=client_id,
                version=1,
                content_sha256=client_authority_sha256(
                    client_id=client_id,
                    directory_object_id=str(directory_object_id),
                    alias_lookup_sha256=str(alias_lookup_sha256),
                    created_at=str(created_at),
                ),
                authority_scope="global",
            ),
            client_id=client_id,
        )

    def _root_intent_id(self, plan: DeletionPlan) -> str:
        rows = self._connection.execute(
            "SELECT intent_id FROM deletion_queue_intents "
            "WHERE request_id = ? AND action_type = 'physical_delete' "
            "AND object_type = 'client'",
            (plan.request_id,),
        ).fetchall()
        if len(rows) != 1 or type(rows[0][0]) is not str:
            raise WholeClientSagaError("WHOLE_CLIENT_ROOT_INTENT_INVALID")
        return str(rows[0][0])

    @staticmethod
    def _refuse_replay_write(_connection: sqlite3.Connection) -> None:
        raise WholeClientSagaError("WHOLE_CLIENT_REPLAY_WRITE_FORBIDDEN")

    def _execution_applied(self, ticket: ApprovalExecutionTicket) -> bool:
        row = self._connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, state, "
            "applied_commit_version FROM approval_executions "
            "WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if row is None:
            return False
        expected = (
            ticket.request_id,
            ticket.descriptor_sha256,
            ticket.descriptor.draft_sha256,
            ticket.descriptor.base_version,
            ticket.target_scope_hash,
            "APPLIED",
        )
        if tuple(row[:6]) != expected:
            raise WholeClientSagaError("WHOLE_CLIENT_EXECUTION_MISMATCH")
        try:
            commit_version = int(row[6])
        except (TypeError, ValueError):
            raise WholeClientSagaError("WHOLE_CLIENT_EXECUTION_MISMATCH") from None
        if commit_version <= 0:
            raise WholeClientSagaError("WHOLE_CLIENT_EXECUTION_MISMATCH")
        return True

    def _recover_committed_result(
        self,
        plan: DeletionPlan,
    ) -> DeletionCommitResult:
        """Re-attest a progressed saga without replaying its target callback."""

        request = self._connection.execute(
            "SELECT plan_sha256, committed_deletion_version, tombstone_epoch, "
            "state, queue_state FROM deletion_requests WHERE request_id = ?",
            (plan.request_id,),
        ).fetchone()
        if request is None or tuple(request[:3]) != (
            plan.plan_sha256,
            plan.next_deletion_version,
            plan.next_tombstone_epoch,
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_COMMIT_RECOVERY_INVALID")
        lifecycle_state, queue_state = str(request[3]), str(request[4])
        if (lifecycle_state, queue_state) not in {
            ("TOMBSTONED", "PENDING"),
            ("TOMBSTONED", "RUNNING"),
            ("TOMBSTONED", "PARTIAL"),
            ("TOMBSTONED", "FAILED"),
            ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED"),
        }:
            raise WholeClientSagaError("WHOLE_CLIENT_COMMIT_RECOVERY_INVALID")
        authority_state = self._connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        catalog_state = self._connection.execute(
            "SELECT authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if (
            authority_state is None
            or int(authority_state[0]) < plan.next_deletion_version
            or int(authority_state[1]) < plan.next_tombstone_epoch
            or catalog_state is None
            or int(catalog_state[0]) < plan.next_authorization_epoch
            or int(catalog_state[1]) < plan.next_tombstone_epoch
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_COMMIT_RECOVERY_INVALID")

        root = plan.target.object_ref
        root_lineage = lineage_hash(root.object_type, root.object_id)
        tombstone_actions = tuple(
            action
            for action in plan.actions
            if action.action_type == "tombstone_now"
        )
        for ordinal, action in enumerate(tombstone_actions, start=1):
            tombstone_id = (
                f"tombstone_{ordinal:04d}_{plan.request_id[-36:]}"
            )
            durable = self._connection.execute(
                "SELECT target_type, target_id_hash, source_lineage_hash, "
                "reason_code FROM tombstones WHERE tombstone_id = ?",
                (tombstone_id,),
            ).fetchall()
            expected = (
                action.target_ref.object_type,
                target_hash(
                    action.target_ref.object_type,
                    action.target_ref.object_id,
                ),
                root_lineage,
                action.reason_code,
            )
            if len(durable) != 1 or tuple(durable[0]) != expected:
                raise WholeClientSagaError(
                    "WHOLE_CLIENT_COMMIT_RECOVERY_INVALID"
                )

        queue_actions = tuple(
            action
            for action in plan.actions
            if action.action_type
            in {"physical_delete", "rebuild", "backup_expiry"}
        )
        resolver = CleanupAuthorityResolver(
            self._connection,
            authority_scope="global",
        )
        for ordinal, action in enumerate(queue_actions, start=1):
            intent_id = (
                "deletion_queue_intent_"
                f"{ordinal:04d}_{plan.request_id[-36:]}"
            )
            recovered = resolver.resolve(
                intent_id,
                expected_action_type=action.action_type,
            )
            if (
                recovered.request_id != plan.request_id
                or recovered.action_id != action.action_id
                or recovered.object_type != action.target_ref.object_type
                or recovered.target_version != action.target_ref.version
                or recovered.target_content_sha256
                != action.target_ref.content_sha256
                or recovered.target_id_hash
                != target_hash(
                    action.target_ref.object_type,
                    action.target_ref.object_id,
                )
            ):
                raise WholeClientSagaError(
                    "WHOLE_CLIENT_COMMIT_RECOVERY_INVALID"
                )
        queue_count = self._connection.execute(
            "SELECT count(*) FROM deletion_queue_intents WHERE request_id = ?",
            (plan.request_id,),
        ).fetchone()
        if queue_count != (len(queue_actions),):
            raise WholeClientSagaError("WHOLE_CLIENT_COMMIT_RECOVERY_INVALID")
        retired = self._connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (plan.target.object_ref.object_id,),
        ).fetchone()
        if retired != ("RETIRED",):
            raise WholeClientSagaError("WHOLE_CLIENT_COMMIT_RECOVERY_INVALID")
        return DeletionCommitResult(
            request_id=plan.request_id,
            plan_sha256=plan.plan_sha256,
            deletion_version=plan.next_deletion_version,
            tombstone_epoch=plan.next_tombstone_epoch,
            authorization_epoch=plan.next_authorization_epoch,
            tombstone_count=len(tombstone_actions),
            queue_intent_count=len(queue_actions),
            queue_wake_state="pending",
        )

    def _authority(
        self,
        target_scope_hash: str,
    ) -> WholeClientDeletionApprovalAuthority:
        authority = self._approval_factory(target_scope_hash)
        if not isinstance(
            getattr(authority, "approval_service", None), ApprovalService
        ) or not isinstance(
            getattr(authority, "execution_guard", None), ApprovalExecutionGuard
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_APPROVAL_UNAVAILABLE")
        return cast(WholeClientDeletionApprovalAuthority, authority)

    def _store_envelope(
        self,
        envelope: _WholeClientDeletionEnvelope,
    ) -> ArchiveContentRef:
        object_id = self._ids.object_id("lifecycle_plan")
        stored = self._store.finalize(
            self._store.stage_bytes(
                canonical_json_bytes(envelope.model_dump(mode="json")),
                purpose="delete",
                manifest_id=object_id,
                media_type="application/json",
            )
        )
        return ArchiveContentRef(
            object_id=object_id,
            version=1,
            content_sha256=stored.content_sha256,
            media_type="application/json",
            size_bytes=stored.size_bytes,
        )

    def _read_envelope(
        self,
        plan_ref: ArchiveContentRef,
    ) -> _WholeClientDeletionEnvelope:
        try:
            payload = self._store.read_verified(
                self._store.reference(
                    content_sha256=plan_ref.content_sha256,
                    media_type=plan_ref.media_type,
                    size_bytes=plan_ref.size_bytes,
                )
            )
            return _WholeClientDeletionEnvelope.model_validate_json(
                payload,
                strict=True,
            )
        except (
            ContentHashMismatch,
            ContentScopeMismatch,
            InvalidContentReference,
            ValidationError,
        ):
            raise WholeClientSagaError("WHOLE_CLIENT_PLAN_UNAVAILABLE") from None


__all__ = [
    "WholeClientDeletionApprovalAuthority",
    "WholeClientDeletionCommit",
    "WholeClientDeletionPreview",
    "WholeClientDeletionSaga",
    "WholeClientSagaError",
]
