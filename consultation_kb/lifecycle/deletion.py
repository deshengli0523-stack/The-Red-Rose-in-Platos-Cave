"""Approval-guarded tombstone commit and durable follow-up intents."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Literal

from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationError,
    CaseIndexRebuildSnapshot,
    invalidate_pending_case_indexes_in_transaction,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.lifecycle.deletion_plan import DeletionPlanBuilder
from consultation_kb.models.deletion import (
    DeletionCommitResult,
    DeletionInventory,
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    deletion_intent_authority_sha256,
)
from consultation_kb.storage.deletion_inventory import (
    SqliteDeletionInventoryAdapter,
    client_authority_sha256,
    session_authority_sha256,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash


class DeletionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DeletionApprovalMismatch(DeletionError):
    def __init__(self) -> None:
        super().__init__("DELETION_APPROVAL_MISMATCH")


class DeletionPlanStale(DeletionError):
    def __init__(self, code: str = "DELETION_PLAN_STALE") -> None:
        super().__init__(code)


QueueWaker = Callable[[str], None]


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _derived_id(kind: str, ordinal: int, request_id: str) -> str:
    return f"{kind}_{ordinal:04d}_{request_id[-36:]}"


class DeletionService:
    """Preview exact closure, then atomically install query authority denial.

    Physical cleanup is never performed here. The target transaction stores
    durable PENDING intents; only after that transaction commits is an optional
    worker wake attempted. A failed wake therefore cannot restore visibility.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        approval_guard: ApprovalExecutionGuard,
        clock: Clock | None = None,
        queue_waker: QueueWaker | None = None,
        inventory_adapter: SqliteDeletionInventoryAdapter | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("DELETION_SQLITE_CONNECTION_REQUIRED")
        if not isinstance(approval_guard, ApprovalExecutionGuard):
            raise TypeError("DELETION_APPROVAL_GUARD_REQUIRED")
        if getattr(approval_guard, "_connection", None) is not connection:
            raise DeletionApprovalMismatch
        self._connection = connection
        self._guard: ApprovalExecutionGuard | None = approval_guard
        self._clock = clock if clock is not None else SystemClock()
        self._queue_waker = queue_waker
        if inventory_adapter is not None and not isinstance(
            inventory_adapter, SqliteDeletionInventoryAdapter
        ):
            raise TypeError("DELETION_INVENTORY_ADAPTER_REQUIRED")
        self._inventory_adapter = inventory_adapter
        self._planner = DeletionPlanBuilder()

    @classmethod
    def for_preview(
        cls,
        connection: sqlite3.Connection,
        *,
        inventory_adapter: SqliteDeletionInventoryAdapter,
        clock: Clock | None = None,
    ) -> "DeletionService":
        """Build a read-only planner without creating approval authority.

        This is used by scoped workers before an approval request exists.  The
        resulting service cannot commit; ``commit_tombstone`` fails closed if
        called on it.
        """

        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("DELETION_SQLITE_CONNECTION_REQUIRED")
        if not isinstance(inventory_adapter, SqliteDeletionInventoryAdapter):
            raise TypeError("DELETION_INVENTORY_ADAPTER_REQUIRED")
        service = cls.__new__(cls)
        service._connection = connection
        service._guard = None
        service._clock = clock if clock is not None else SystemClock()
        service._queue_waker = None
        service._inventory_adapter = inventory_adapter
        service._planner = DeletionPlanBuilder()
        return service

    def preview(
        self,
        request: DeletionPreviewRequest,
        inventory: DeletionInventory | None = None,
    ) -> DeletionPlan:
        snapshot = inventory
        if snapshot is None:
            if self._inventory_adapter is None:
                raise DeletionError("DELETION_INVENTORY_REQUIRED")
            snapshot = self._inventory_adapter.snapshot(request)
        return self._planner.preview(request, snapshot)

    def preflight(self, plan: DeletionPlan) -> None:
        """Read-only target-authority validation before receipt issuance."""

        exact = DeletionPlan.model_validate(plan)
        self._assert_current_versions(exact)
        self._assert_exact_authority(exact)

    def commit_tombstone(
        self,
        plan: DeletionPlan,
        ticket: ApprovalExecutionTicket,
    ) -> DeletionCommitResult:
        result, _proof = self.commit_tombstone_attested(plan, ticket)
        return result

    def commit_tombstone_attested(
        self,
        plan: DeletionPlan,
        ticket: ApprovalExecutionTicket,
    ) -> tuple[DeletionCommitResult, ApprovalExecutionProof]:
        """Commit and return the exact target proof for caller acknowledgement."""

        if self._guard is None:
            raise DeletionApprovalMismatch
        exact = DeletionPlan.model_validate(plan)
        approved = ApprovalExecutionTicket.model_validate(ticket)
        if (
            approved.descriptor != exact.descriptor
            or approved.descriptor_sha256 != approved.receipt.descriptor_sha256
            or approved.target_scope_hash != exact.target_scope_hash
        ):
            raise DeletionApprovalMismatch

        def commit_authority(connection: sqlite3.Connection) -> None:
            if connection is not self._connection or not connection.in_transaction:
                raise DeletionApprovalMismatch
            self._assert_current_versions(exact)
            self._assert_exact_authority(exact)
            self._invalidate_pending_case_indexes(
                exact,
                authority_request_id=approved.request_id,
            )
            self._write_request(exact, approved)
            self._write_tombstones(exact)
            self._write_revocations(exact)
            self._apply_authority_effects(exact)
            self._write_security_events(exact)
            self._write_queue_intents(exact)
            changed = connection.execute(
                """
                UPDATE deletion_authority_state
                   SET deletion_version = ?, tombstone_epoch = ?
                 WHERE singleton = 1
                   AND deletion_version = ? AND tombstone_epoch = ?
                """,
                (
                    exact.next_deletion_version,
                    exact.next_tombstone_epoch,
                    exact.base_deletion_version,
                    exact.base_tombstone_epoch,
                ),
            ).rowcount
            if changed != 1:
                raise DeletionPlanStale("DELETION_AUTHORITY_VERSION_STALE")

        guard = self._guard
        if guard is None:
            raise DeletionApprovalMismatch
        proof = guard.apply_in_transaction(
            approved,
            exact.descriptor,
            commit_authority,
        )
        if (
            proof.operation_id != approved.operation_id
            or proof.request_id != approved.request_id
            or proof.descriptor_sha256 != approved.descriptor_sha256
            or proof.draft_sha256 != exact.plan_sha256
            or proof.target_scope_hash != exact.target_scope_hash
            or proof.state != "applied"
        ):
            raise DeletionApprovalMismatch

        wake_state: Literal["notified", "pending"] = "pending"
        if self._queue_waker is not None:
            try:
                self._queue_waker(exact.request_id)
            except Exception:
                # The DB intent is the recovery authority. Transport failures are
                # intentionally not allowed to roll back a committed tombstone.
                wake_state = "pending"
            else:
                wake_state = "notified"
        return self._committed_result(exact, wake_state=wake_state), proof

    def _invalidate_pending_case_indexes(
        self,
        plan: DeletionPlan,
        *,
        authority_request_id: str,
    ) -> None:
        if not self._table_exists("case_index_rebuild_invalidations"):
            return
        planned = plan.pending_case_index_invalidation
        try:
            if planned is None:
                if snapshot_pending_case_index_invalidations(
                    self._connection
                ).identities:
                    raise DeletionPlanStale(
                        "DELETION_CASE_INDEX_INVALIDATION_SET_STALE"
                    )
                return
            expected = CaseIndexRebuildSnapshot.model_validate_json(
                planned.model_dump_json(),
                strict=True,
            )
            if expected.identity_sha256 != planned.identity_sha256:
                raise DeletionPlanStale(
                    "DELETION_CASE_INDEX_INVALIDATION_SET_STALE"
                )
            invalidate_pending_case_indexes_in_transaction(
                self._connection,
                expected_snapshot=expected,
                authority_request_id=authority_request_id,
                reason_code=plan.reason_code,
                next_authorization_epoch=plan.next_authorization_epoch,
                next_tombstone_epoch=plan.next_tombstone_epoch,
                invalidated_at=self._clock.now(),
            )
        except CaseIndexPublicationError:
            raise DeletionPlanStale(
                "DELETION_CASE_INDEX_INVALIDATION_SET_STALE"
            ) from None

    def _assert_current_versions(self, plan: DeletionPlan) -> None:
        state = self._connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        if state != (plan.base_deletion_version, plan.base_tombstone_epoch):
            raise DeletionPlanStale("DELETION_AUTHORITY_VERSION_STALE")
        catalog = None
        if self._table_exists("knowledge_catalog_state"):
            catalog = self._connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if catalog is None or catalog[1:] != (
                plan.base_authorization_epoch,
                plan.base_tombstone_epoch,
            ):
                raise DeletionPlanStale("DELETION_CATALOG_EPOCH_STALE")
        for base in plan.base_versions:
            row: tuple[object, ...] | None = None
            if catalog is not None and base.authority_key == "catalog":
                row = (int(catalog[0]),)
            elif catalog is not None and base.authority_key == "authorization":
                row = (int(catalog[1]),)
            elif base.authority_key in {"global_runtime", "client_runtime"}:
                active_rows = self._connection.execute(
                    "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
                ).fetchall()
                if len(active_rows) != 1:
                    raise DeletionPlanStale(
                        "DELETION_ACTIVE_EPOCH_CARDINALITY_STALE"
                    )
                row = (int(active_rows[0][0]),)
            elif (
                base.authority_key == "case_current"
                and plan.target.target_type in {"case", "case_authorization"}
                and self._table_exists("cases")
            ):
                cases = self._revoked_case_refs(plan)
                if len(cases) != 1:
                    raise DeletionPlanStale(
                        "DELETION_CASE_AUTHORIZATION_CLOSURE_STALE"
                    )
                row = self._connection.execute(
                    "SELECT current_version FROM cases WHERE case_id = ?",
                    (cases[0].object_id,),
                ).fetchone()
            elif (
                base.authority_key == "client_authority"
                and plan.target.target_type == "client"
                and self._table_exists("clients")
            ):
                row = (plan.target.object_ref.version,)
            elif (
                base.authority_key == "session_current"
                and plan.target.target_type == "session"
                and self._table_exists("sessions")
            ):
                row = self._connection.execute(
                    "SELECT last_closed_turn_ordinal FROM sessions "
                    "WHERE session_id = ?",
                    (plan.target.object_ref.object_id,),
                ).fetchone()
            else:
                row = self._connection.execute(
                    """
                    SELECT version FROM deletion_base_versions
                     WHERE authority_key = ? AND scope_sha256 = ?
                    """,
                    (base.authority_key, base.scope_sha256),
                ).fetchone()
            if row != (base.version,):
                raise DeletionPlanStale("DELETION_BASE_VERSION_STALE")

    def _assert_exact_authority(self, plan: DeletionPlan) -> None:
        self._assert_not_tombstoned(plan.target.object_ref)
        if plan.target.target_type == "client" and self._table_exists("clients"):
            self._assert_exact_client_authority(plan)
        if plan.target.target_type == "session" and self._table_exists("sessions"):
            self._assert_exact_session_authority(plan)
        if plan.target.target_type in {"passage", "claim"}:
            self._assert_exact_knowledge_authority(plan)
        if plan.target.target_type == "case_authorization":
            cases = self._revoked_case_refs(plan)
            if len(cases) != 1:
                raise DeletionPlanStale(
                    "DELETION_CASE_AUTHORIZATION_CLOSURE_STALE"
                )
            case = cases[0]
            self._assert_not_tombstoned(case)
            authorizations = self._case_authorizations(plan, case)
            if authorizations != (plan.target.object_ref,):
                raise DeletionPlanStale(
                    "DELETION_CASE_AUTHORIZATION_CLOSURE_STALE"
                )
            self._assert_case_ref_authority(case, authorizations[0])
            return
        if plan.target.target_type != "case" or not self._table_exists("cases"):
            return
        case = plan.target.object_ref
        authorizations = self._case_authorizations(plan, case)
        if len(authorizations) != 1:
            raise DeletionPlanStale("DELETION_CASE_AUTHORIZATION_CLOSURE_STALE")
        authorization = authorizations[0]
        self._assert_case_ref_authority(case, authorization)

    def _assert_not_tombstoned(self, reference: DeletionObjectRef) -> None:
        direct = self._connection.execute(
            """
            SELECT count(*) FROM tombstones
             WHERE (target_type = ? AND target_id_hash = ?)
                OR source_lineage_hash = ?
            """,
            (
                reference.object_type,
                target_hash(reference.object_type, reference.object_id),
                lineage_hash(reference.object_type, reference.object_id),
            ),
        ).fetchone()
        if direct != (0,):
            raise DeletionPlanStale("DELETION_TARGET_ALREADY_TOMBSTONED")

    def _assert_exact_session_authority(self, plan: DeletionPlan) -> None:
        session = plan.target.object_ref
        row = self._connection.execute(
            """
            SELECT client_id, client_scope_hash, client_snapshot_version,
                   client_snapshot_canonical_sha256, started_at,
                   last_closed_turn_ordinal
              FROM sessions WHERE session_id = ?
            """,
            (session.object_id,),
        ).fetchone()
        if row is None or row[0] != plan.target.client_id:
            raise DeletionPlanStale("DELETION_SESSION_AUTHORITY_STALE")
        expected_hash = session_authority_sha256(
            session_id=session.object_id,
            client_id=str(row[0]),
            client_scope_hash=str(row[1]),
            client_snapshot_version=int(str(row[2])),
            client_snapshot_canonical_sha256=(
                None if row[3] is None else str(row[3])
            ),
            started_at=str(row[4]),
        )
        if (
            session.version != int(str(row[5]))
            or session.content_sha256 != expected_hash
        ):
            raise DeletionPlanStale("DELETION_SESSION_AUTHORITY_STALE")

    def _assert_exact_knowledge_authority(self, plan: DeletionPlan) -> None:
        reference = plan.target.object_ref
        query = {
            "passage": (
                "SELECT normalized_text_sha256, review_status FROM passages "
                "WHERE passage_id = ? AND version = ?"
            ),
            "claim": (
                "SELECT claim_sha256, review_status FROM claims "
                "WHERE claim_id = ? AND version = ?"
            ),
        }[plan.target.target_type]
        rows = self._connection.execute(
            query, (reference.object_id, reference.version)
        ).fetchall()
        if len(rows) != 1 or tuple(rows[0]) != (
            reference.content_sha256,
            "APPROVED",
        ):
            raise DeletionPlanStale("DELETION_KNOWLEDGE_AUTHORITY_STALE")

    def _assert_exact_client_authority(self, plan: DeletionPlan) -> None:
        client = plan.target.object_ref
        row = self._connection.execute(
            """
            SELECT directory_object_id, alias_lookup_sha256, state, created_at
              FROM clients WHERE client_id = ?
            """,
            (client.object_id,),
        ).fetchone()
        if row is None or row[2] != "ACTIVE":
            raise DeletionPlanStale("DELETION_CLIENT_AUTHORITY_STALE")
        expected_hash = client_authority_sha256(
            client_id=client.object_id,
            directory_object_id=str(row[0]),
            alias_lookup_sha256=str(row[1]),
            created_at=str(row[3]),
        )
        if expected_hash != client.content_sha256:
            raise DeletionPlanStale("DELETION_CLIENT_AUTHORITY_STALE")
        capability_refs = tuple(
            node.object_ref
            for node in plan.closure_nodes
            if node.object_ref.object_type == "client_capability"
        )
        rows = self._connection.execute(
            """
            SELECT capability_id, capability_epoch, token_sha256
              FROM capabilities
             WHERE client_id = ? AND state = 'ACTIVE'
             ORDER BY capability_id
            """,
            (client.object_id,),
        ).fetchall()
        current_capabilities = tuple(
            sorted(
                (
                    str(row[0]),
                    int(str(row[1])),
                    str(row[2]),
                )
                for row in rows
            )
        )
        planned_capabilities = tuple(
            sorted(
                (
                    reference.object_id,
                    reference.version,
                    reference.content_sha256,
                )
                for reference in capability_refs
            )
        )
        if current_capabilities != planned_capabilities:
            raise DeletionPlanStale("DELETION_CLIENT_CAPABILITY_CLOSURE_STALE")
        for case in self._revoked_case_refs(plan):
            self._assert_not_tombstoned(case)
            authorizations = self._case_authorizations(plan, case)
            if len(authorizations) != 1:
                raise DeletionPlanStale(
                    "DELETION_CASE_AUTHORIZATION_CLOSURE_STALE"
                )
            self._assert_case_ref_authority(case, authorizations[0])

    def _case_authorizations(
        self,
        plan: DeletionPlan,
        case: DeletionObjectRef,
    ) -> tuple[DeletionObjectRef, ...]:
        case_ref = DeletionObjectRef.model_validate(case)
        return tuple(
            edge.dependent_ref
            for edge in plan.closure_edges
            if edge.relation == "case_reuse_authorization"
            and edge.source_ref == case_ref
            and edge.dependent_ref.object_type == "case_authorization"
        )

    def _assert_case_ref_authority(
        self,
        case: DeletionObjectRef,
        authorization: DeletionObjectRef,
    ) -> None:
        case_ref = self._validated_ref(case)
        authorization_ref = self._validated_ref(authorization)
        rows = self._connection.execute(
            """
            SELECT c.state, c.current_version, cv.state,
                   cv.global_content_sha256, ca.authorization_id,
                   ca.authorization_version, ca.authorization_sha256,
                   ca.reuse_authorized, ca.revoked_at
              FROM cases AS c
              JOIN case_versions AS cv
                ON cv.case_id = c.case_id AND cv.version = c.current_version
              JOIN case_authorizations AS ca
                ON ca.case_id = cv.case_id AND ca.case_version = cv.version
             WHERE c.case_id = ? AND cv.version = ?
            """,
            (case_ref.object_id, case_ref.version),
        ).fetchall()
        expected = (
            "ACTIVE",
            case_ref.version,
            "ACTIVE",
            case_ref.content_sha256,
            authorization_ref.object_id,
            authorization_ref.version,
            authorization_ref.content_sha256,
            1,
            None,
        )
        if len(rows) != 1 or tuple(rows[0]) != expected:
            raise DeletionPlanStale("DELETION_CASE_AUTHORITY_STALE")

    @staticmethod
    def _validated_ref(value: DeletionObjectRef) -> DeletionObjectRef:
        return DeletionObjectRef.model_validate(value)

    def _apply_authority_effects(self, plan: DeletionPlan) -> None:
        if self._table_exists("cases"):
            for case in self._revoked_case_refs(plan):
                self._apply_case_revocation(case)
            self._apply_case_derivative_revocations(plan)
        if plan.target.target_type == "client" and self._table_exists("clients"):
            self._apply_client_revocation(plan)
        if plan.target.target_type in {"passage", "claim"}:
            self._apply_knowledge_revocations(plan)
        if self._table_exists("artifact_versions"):
            for node in plan.closure_nodes:
                reference = node.object_ref
                if reference.object_type != "artifact_version":
                    continue
                row = self._connection.execute(
                    "SELECT state, metadata_sha256 FROM artifact_versions "
                    "WHERE artifact_id = ? AND version = ?",
                    (reference.object_id, reference.version),
                ).fetchone()
                if row is None:
                    raise DeletionPlanStale("DELETION_ARTIFACT_CLOSURE_STALE")
                if row != ("CURRENT", reference.content_sha256):
                    raise DeletionPlanStale("DELETION_ARTIFACT_CLOSURE_STALE")
                changed = self._connection.execute(
                    "UPDATE artifact_versions SET state = 'STALE' "
                    "WHERE artifact_id = ? AND version = ? AND state = 'CURRENT' "
                    "AND metadata_sha256 = ?",
                    (
                        reference.object_id,
                        reference.version,
                        reference.content_sha256,
                    ),
                ).rowcount
                if changed != 1:
                    raise DeletionPlanStale("DELETION_ARTIFACT_CLOSURE_STALE")

    def _revoked_case_refs(
        self, plan: DeletionPlan
    ) -> tuple[DeletionObjectRef, ...]:
        return tuple(
            sorted(
                {
                    action.target_ref
                    for action in plan.actions
                    if action.authority_effect == "revoke_case"
                },
                key=lambda value: (
                    value.object_id,
                    value.version,
                    value.content_sha256,
                ),
            )
        )

    def _apply_case_revocation(self, case: DeletionObjectRef) -> None:
        case_ref = self._validated_ref(case)
        now = _utc_text(self._clock.now())
        changed_version = self._connection.execute(
            """
            UPDATE case_versions SET state = 'REVOKED', revoked_at = ?
             WHERE case_id = ? AND version = ? AND state = 'ACTIVE'
               AND global_content_sha256 = ?
            """,
            (
                now,
                case_ref.object_id,
                case_ref.version,
                case_ref.content_sha256,
            ),
        ).rowcount
        if changed_version != 1:
            raise DeletionPlanStale("DELETION_CASE_VERSION_STALE")
        changed_case = self._connection.execute(
            """
            UPDATE cases SET state = 'REVOKED', updated_at = ?
             WHERE case_id = ? AND state = 'ACTIVE' AND current_version = ?
            """,
            (now, case_ref.object_id, case_ref.version),
        ).rowcount
        if changed_case != 1:
            raise DeletionPlanStale("DELETION_CASE_VERSION_STALE")

    def _apply_case_derivative_revocations(self, plan: DeletionPlan) -> None:
        if self._table_exists("case_patterns"):
            for node in plan.closure_nodes:
                reference = node.object_ref
                if node.role != "case_pattern":
                    continue
                row = self._connection.execute(
                    "SELECT state FROM case_patterns WHERE pattern_id = ? "
                    "AND version = ? AND global_content_sha256 = ?",
                    (
                        reference.object_id,
                        reference.version,
                        reference.content_sha256,
                    ),
                ).fetchone()
                if row is None:
                    raise DeletionPlanStale("DELETION_CASE_PATTERN_STALE")
                if row != ("ACTIVE",):
                    raise DeletionPlanStale("DELETION_CASE_PATTERN_STALE")
                changed = self._connection.execute(
                    "UPDATE case_patterns SET state = 'REVOKED' "
                    "WHERE pattern_id = ? AND version = ? AND state = 'ACTIVE' "
                    "AND global_content_sha256 = ?",
                    (
                        reference.object_id,
                        reference.version,
                        reference.content_sha256,
                    ),
                ).rowcount
                if changed != 1:
                    raise DeletionPlanStale("DELETION_CASE_PATTERN_STALE")
        if self._table_exists("case_leave_one_out_variants"):
            for node in plan.closure_nodes:
                reference = node.object_ref
                if reference.object_type != "case_leave_one_out":
                    continue
                changed = self._connection.execute(
                    "UPDATE case_leave_one_out_variants SET state = 'REVOKED' "
                    "WHERE mapping_id = ? AND mapping_version = ? "
                    "AND mapping_sha256 = ? AND state = 'ACTIVE'",
                    (
                        reference.object_id,
                        reference.version,
                        reference.content_sha256,
                    ),
                ).rowcount
                if changed != 1:
                    raise DeletionPlanStale("DELETION_CASE_LOO_STALE")

    def _apply_client_revocation(self, plan: DeletionPlan) -> None:
        client = plan.target.object_ref
        now = _utc_text(self._clock.now())
        for node in plan.closure_nodes:
            reference = node.object_ref
            if reference.object_type != "client_capability":
                continue
            changed = self._connection.execute(
                """
                UPDATE capabilities
                   SET state = 'REVOKED', revoked_at = ?,
                       capability_epoch = capability_epoch + 1
                 WHERE capability_id = ? AND capability_epoch = ?
                   AND token_sha256 = ? AND client_id = ? AND state = 'ACTIVE'
                """,
                (
                    now,
                    reference.object_id,
                    reference.version,
                    reference.content_sha256,
                    client.object_id,
                ),
            ).rowcount
            if changed != 1:
                raise DeletionPlanStale("DELETION_CLIENT_CAPABILITY_STALE")
        changed = self._connection.execute(
            "UPDATE clients SET state = 'RETIRED' "
            "WHERE client_id = ? AND state = 'ACTIVE'",
            (client.object_id,),
        ).rowcount
        if changed != 1:
            raise DeletionPlanStale("DELETION_CLIENT_AUTHORITY_STALE")

    def _apply_knowledge_revocations(self, plan: DeletionPlan) -> None:
        for node in plan.closure_nodes:
            reference = node.object_ref
            if reference.object_type == "passage":
                query = (
                    "SELECT review_status, normalized_text_sha256 FROM passages "
                    "WHERE passage_id = ? AND version = ?"
                )
                update = (
                    "UPDATE passages SET review_status = 'REVOKED' "
                    "WHERE passage_id = ? AND version = ? "
                    "AND normalized_text_sha256 = ? AND review_status = 'APPROVED'"
                )
            elif reference.object_type == "claim":
                query = (
                    "SELECT review_status, claim_sha256 FROM claims "
                    "WHERE claim_id = ? AND version = ?"
                )
                update = (
                    "UPDATE claims SET review_status = 'REVOKED' "
                    "WHERE claim_id = ? AND version = ? "
                    "AND claim_sha256 = ? AND review_status = 'APPROVED'"
                )
            else:
                continue
            row = self._connection.execute(
                query, (reference.object_id, reference.version)
            ).fetchone()
            if row is None or str(row[1]) != reference.content_sha256:
                raise DeletionPlanStale("DELETION_KNOWLEDGE_CLOSURE_STALE")
            if row[0] != "APPROVED":
                continue
            changed = self._connection.execute(
                update,
                (
                    reference.object_id,
                    reference.version,
                    reference.content_sha256,
                ),
            ).rowcount
            if changed != 1:
                raise DeletionPlanStale("DELETION_KNOWLEDGE_CLOSURE_STALE")

    def _write_security_events(self, plan: DeletionPlan) -> None:
        if not self._table_exists("knowledge_catalog_state"):
            return
        catalog_version = next(
            (
                base.version
                for base in plan.base_versions
                if base.authority_key == "catalog"
            ),
            None,
        )
        if catalog_version is None:
            raise DeletionPlanStale("DELETION_CATALOG_BASE_MISSING")
        now = _utc_text(self._clock.now())
        event_kinds = ["TOMBSTONE"]
        if plan.next_authorization_epoch != plan.base_authorization_epoch:
            event_kinds.insert(0, "AUTHORIZATION")
        for event_kind in event_kinds:
            changed = self._connection.execute(
                """
                INSERT OR IGNORE INTO security_invalidation_events(
                    upstream_type, upstream_id, catalog_version,
                    event_kind, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    plan.target.object_ref.object_type,
                    plan.target.object_ref.object_id,
                    catalog_version,
                    event_kind,
                    now,
                ),
            ).rowcount
            if changed != 1:
                raise DeletionPlanStale("DELETION_SECURITY_EVENT_STALE")
        if plan.next_authorization_epoch != plan.base_authorization_epoch:
            changed = self._connection.execute(
                """
                UPDATE knowledge_catalog_state
                   SET authorization_epoch = ?
                 WHERE singleton = 1 AND catalog_version = ?
                   AND authorization_epoch = ? AND tombstone_epoch = ?
                """,
                (
                    plan.next_authorization_epoch,
                    catalog_version,
                    plan.base_authorization_epoch,
                    plan.base_tombstone_epoch,
                ),
            ).rowcount
            if changed != 1:
                raise DeletionPlanStale("DELETION_AUTHORIZATION_EPOCH_STALE")

    def _table_exists(self, name: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            ).fetchone()
            is not None
        )

    def _write_request(
        self,
        plan: DeletionPlan,
        ticket: ApprovalExecutionTicket,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO deletion_requests(
                request_id, operation_id, plan_sha256,
                target_type, target_id_hash, target_scope_hash,
                base_deletion_version, committed_deletion_version,
                tombstone_epoch, approval_request_id,
                approval_descriptor_sha256, approval_target_scope_hash,
                state, queue_state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'TOMBSTONED', 'PENDING', ?)
            """,
            (
                plan.request_id,
                ticket.operation_id,
                plan.plan_sha256,
                plan.target.target_type,
                target_hash(
                    plan.target.object_ref.object_type,
                    plan.target.object_ref.object_id,
                ),
                plan.target_scope_hash,
                plan.base_deletion_version,
                plan.next_deletion_version,
                plan.next_tombstone_epoch,
                ticket.request_id,
                ticket.descriptor_sha256,
                ticket.target_scope_hash,
                _utc_text(self._clock.now()),
            ),
        )

    def _write_tombstones(self, plan: DeletionPlan) -> None:
        root = plan.target.object_ref
        root_lineage_hash = lineage_hash(root.object_type, root.object_id)
        actions = tuple(
            action
            for action in plan.actions
            if action.action_type == "tombstone_now"
        )
        for ordinal, action in enumerate(actions, start=1):
            try:
                inserted = self._connection.execute(
                    """
                    INSERT INTO tombstones(
                        tombstone_id, target_type, target_id_hash,
                        source_lineage_hash, reason_code, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        _derived_id("tombstone", ordinal, plan.request_id),
                        action.target_ref.object_type,
                        target_hash(
                            action.target_ref.object_type,
                            action.target_ref.object_id,
                        ),
                        root_lineage_hash,
                        action.reason_code,
                        _utc_text(self._clock.now()),
                    ),
                ).rowcount
            except sqlite3.IntegrityError:
                raise DeletionPlanStale(
                    "DELETION_TOMBSTONE_INSERT_STALE"
                ) from None
            if inserted != 1:
                raise DeletionPlanStale("DELETION_TOMBSTONE_INSERT_STALE")

    def _write_revocations(self, plan: DeletionPlan) -> None:
        actions = tuple(
            action
            for action in plan.actions
            if action.action_type == "tombstone_now"
            and action.authority_effect != "none"
        )
        for action in actions:
            self._connection.execute(
                """
                INSERT INTO deletion_revocations(
                    request_id, action_id, effect, object_type,
                    target_id_hash, object_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.request_id,
                    action.action_id,
                    action.authority_effect,
                    action.target_ref.object_type,
                    target_hash(
                        action.target_ref.object_type,
                        action.target_ref.object_id,
                    ),
                    action.target_ref.version,
                    _utc_text(self._clock.now()),
                ),
            )

    def _write_queue_intents(self, plan: DeletionPlan) -> None:
        actions = tuple(
            action
            for action in plan.actions
            if action.action_type
            in {"physical_delete", "rebuild", "backup_expiry"}
        )
        root = plan.target.object_ref
        root_target_id_hash = target_hash(root.object_type, root.object_id)
        root_lineage_hash = lineage_hash(root.object_type, root.object_id)
        for ordinal, action in enumerate(actions, start=1):
            intent_id = _derived_id(
                "deletion_queue_intent", ordinal, plan.request_id
            )
            action_target_id_hash = target_hash(
                action.target_ref.object_type,
                action.target_ref.object_id,
            )
            created_at = _utc_text(self._clock.now())
            self._connection.execute(
                """
                INSERT INTO deletion_queue_intents(
                    intent_id, request_id, action_id, action_type,
                    object_type, target_id_hash, target_version,
                    target_content_sha256, authority_scope,
                    state, attempt_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?)
                """,
                (
                    intent_id,
                    plan.request_id,
                    action.action_id,
                    action.action_type,
                    action.target_ref.object_type,
                    action_target_id_hash,
                    action.target_ref.version,
                    action.target_ref.content_sha256,
                    action.target_ref.authority_scope,
                    created_at,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO deletion_intent_authority_proofs(
                    intent_id, request_id, action_id, deletion_plan_sha256,
                    root_object_type, root_target_id_hash, root_lineage_hash,
                    action_descriptor_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent_id,
                    plan.request_id,
                    action.action_id,
                    plan.plan_sha256,
                    root.object_type,
                    root_target_id_hash,
                    root_lineage_hash,
                    deletion_intent_authority_sha256(
                        intent_id=intent_id,
                        request_id=plan.request_id,
                        action_id=action.action_id,
                        action_type=action.action_type,
                        object_type=action.target_ref.object_type,
                        target_id_hash=action_target_id_hash,
                        target_version=action.target_ref.version,
                        target_content_sha256=(
                            action.target_ref.content_sha256
                        ),
                        authority_scope=action.target_ref.authority_scope,
                        deletion_plan_sha256=plan.plan_sha256,
                        root_object_type=root.object_type,
                        root_target_id_hash=root_target_id_hash,
                        root_lineage_hash=root_lineage_hash,
                    ),
                    created_at,
                ),
            )

    def _committed_result(
        self,
        plan: DeletionPlan,
        *,
        wake_state: Literal["notified", "pending"],
    ) -> DeletionCommitResult:
        row = self._connection.execute(
            """
            SELECT plan_sha256, committed_deletion_version, tombstone_epoch,
                   state, queue_state
              FROM deletion_requests WHERE request_id = ?
            """,
            (plan.request_id,),
        ).fetchone()
        if row != (
            plan.plan_sha256,
            plan.next_deletion_version,
            plan.next_tombstone_epoch,
            "TOMBSTONED",
            "PENDING",
        ):
            raise DeletionError("DELETION_COMMIT_UNAVAILABLE")
        if self._table_exists("knowledge_catalog_state"):
            catalog = self._connection.execute(
                "SELECT authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if catalog != (
                plan.next_authorization_epoch,
                plan.next_tombstone_epoch,
            ):
                raise DeletionError("DELETION_CATALOG_COMMIT_UNAVAILABLE")
        tombstone_actions = tuple(
            action
            for action in plan.actions
            if action.action_type == "tombstone_now"
        )
        root = plan.target.object_ref
        root_lineage_hash = lineage_hash(root.object_type, root.object_id)
        for ordinal, action in enumerate(tombstone_actions, start=1):
            durable = self._connection.execute(
                "SELECT target_type, target_id_hash, source_lineage_hash, "
                "reason_code FROM tombstones WHERE tombstone_id = ?",
                (_derived_id("tombstone", ordinal, plan.request_id),),
            ).fetchall()
            expected = (
                action.target_ref.object_type,
                target_hash(
                    action.target_ref.object_type,
                    action.target_ref.object_id,
                ),
                root_lineage_hash,
                action.reason_code,
            )
            if len(durable) != 1 or tuple(durable[0]) != expected:
                raise DeletionError("DELETION_TOMBSTONE_COMMIT_UNAVAILABLE")
        tombstone_count = len(tombstone_actions)
        queue_intent_count = self._connection.execute(
            "SELECT count(*) FROM deletion_queue_intents WHERE request_id = ?",
            (plan.request_id,),
        ).fetchone()
        if queue_intent_count is None or type(queue_intent_count[0]) is not int:
            raise DeletionError("DELETION_QUEUE_INTENT_UNAVAILABLE")
        expected_revocations = sum(
            action.action_type == "tombstone_now"
            and action.authority_effect != "none"
            for action in plan.actions
        )
        revocation_count = self._connection.execute(
            "SELECT count(*) FROM deletion_revocations WHERE request_id = ?",
            (plan.request_id,),
        ).fetchone()
        if revocation_count != (expected_revocations,):
            raise DeletionError("DELETION_REVOCATION_COMMIT_UNAVAILABLE")
        if self._table_exists("cases"):
            for case in self._revoked_case_refs(plan):
                active_count = self._connection.execute(
                    """
                    SELECT count(*) FROM cases AS c
                    JOIN case_versions AS cv
                      ON cv.case_id = c.case_id AND cv.version = c.current_version
                    WHERE c.case_id = ?
                      AND (c.state = 'ACTIVE' OR cv.state = 'ACTIVE')
                    """,
                    (case.object_id,),
                ).fetchone()
                if active_count != (0,):
                    raise DeletionError("DELETION_CASE_STILL_ACTIVE")
        if plan.target.target_type == "client" and self._table_exists("clients"):
            state = self._connection.execute(
                "SELECT state FROM clients WHERE client_id = ?",
                (plan.target.object_ref.object_id,),
            ).fetchone()
            if state != ("RETIRED",):
                raise DeletionError("DELETION_CLIENT_STILL_ACTIVE")
        return DeletionCommitResult(
            request_id=plan.request_id,
            plan_sha256=plan.plan_sha256,
            deletion_version=plan.next_deletion_version,
            tombstone_epoch=plan.next_tombstone_epoch,
            authorization_epoch=plan.next_authorization_epoch,
            tombstone_count=tombstone_count,
            queue_intent_count=queue_intent_count[0],
            queue_wake_state=wake_state,
        )


__all__ = [
    "DeletionApprovalMismatch",
    "DeletionError",
    "DeletionPlanStale",
    "DeletionService",
    "QueueWaker",
]
