"""Strict leave-one-client-out regeneration and approval contracts."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import sqlite3
from typing import Callable, Literal, Protocol, cast, runtime_checkable

from pydantic import TypeAdapter, ValidationError

from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
    descriptor_sha256,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.archive.provenance import (
    CaseProvenanceError,
    CaseProvenanceService,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.cases import (
    CaseArtifactKind,
    CaseProvenanceRecord,
    LeaveOneOutBuildResult,
    LeaveOneOutDraft,
    LeaveOneOutIneligibility,
    LeaveOneOutVariantAuthority,
    RegeneratedCaseArtifact,
    leave_one_out_authority_payload,
    leave_one_out_draft_payload,
    version_ref_key,
)
from consultation_kb.models.common import Sha256Hex, VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.evidence import SourceGrade
from consultation_kb.storage.connection import transaction


_SHA_ADAPTER = TypeAdapter(Sha256Hex)
FaultHook = Callable[[str], None]


class LeaveOneOutError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@runtime_checkable
class LeaveOneOutRegenerator(Protocol):
    """Trusted, internal renderer that executes the exact reduced-input rule."""

    def regenerate(
        self,
        *,
        parent_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        regeneration_rule_ref: VersionRef,
        input_case_refs: tuple[VersionRef, ...],
        input_independent_source_refs: tuple[VersionRef, ...],
        operation_idempotency_key: str | None,
    ) -> RegeneratedCaseArtifact: ...


@runtime_checkable
class LeaveOneOutApprovalVerifier(Protocol):
    """Resolve one authentic P1 ticket to its exact durable approval record."""

    def verify_leave_one_out_approval(
        self,
        *,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
    ) -> VersionRef | None: ...


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _ref_json(value: VersionRef) -> str:
    return _canonical_json(value.model_dump(mode="json"))


def _refs_json(values: tuple[VersionRef, ...]) -> str:
    return _canonical_json([item.model_dump(mode="json") for item in values])


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise LeaveOneOutError("LOO_TIMESTAMP_NOT_UTC")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise LeaveOneOutError("LOO_AUTHORITY_ROW_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LeaveOneOutError("LOO_AUTHORITY_ROW_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LeaveOneOutError("LOO_AUTHORITY_ROW_INVALID")
    return parsed


def _approval_descriptor(value: LeaveOneOutVariantAuthority) -> DraftDescriptor:
    approval_scope_sha256 = canonical_sha256(
        {
            "allowed_uses": sorted(value.allowed_uses),
            "authority_manifest_ref": value.authority_manifest_ref.model_dump(
                mode="json"
            ),
            "draft_ref": value.draft_ref.model_dump(mode="json"),
            "schema_version": "leave_one_out_approval_scope.v1",
        }
    )
    return DraftDescriptor(
        purpose="case_publish",
        target_id=value.draft_ref.object_id,
        client_id=None,
        base_version=value.parent_ref.version,
        draft_sha256=approval_scope_sha256,
        session_id=None,
    )


def leave_one_out_approval_execution_ref(
    ticket: ApprovalExecutionTicket,
) -> VersionRef:
    """Bind immutable ticket fields shared by CLAIMED and APPLIED rows."""

    exact = ApprovalExecutionTicket.model_validate(ticket)
    return VersionRef(
        object_id=exact.operation_id,
        version=1,
        content_sha256=canonical_sha256(
            {
                "approved_at": exact.receipt.approved_at.isoformat(),
                "descriptor_base_version": exact.descriptor.base_version,
                "descriptor_sha256": exact.descriptor_sha256,
                "draft_sha256": exact.descriptor.draft_sha256,
                "expires_at": exact.receipt.expires_at.isoformat(),
                "nonce_sha256": hashlib.sha256(
                    exact.receipt.nonce.encode("ascii")
                ).hexdigest(),
                "operation_id": exact.operation_id,
                "request_id": exact.request_id,
                "schema_version": "loo_approval_execution_binding.v1",
                "target_scope_hash": exact.target_scope_hash,
            }
        ),
    )


class LeaveOneOutAuthorityRepository:
    """Persist immutable regeneration proof and exact LOO authority mappings."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("LOO authority repository requires SQLite")
        self._connection = connection
        self._clock = clock if clock is not None else SystemClock()

    def prepare(
        self,
        authority: LeaveOneOutVariantAuthority,
        *,
        regeneration: RegeneratedCaseArtifact,
        created_at: datetime,
    ) -> LeaveOneOutVariantAuthority:
        """Verify an already-atomic prepare; never backfill an APPLIED approval."""

        exact, _rebuilt, _created_at = self._validate_prepare_inputs(
            authority,
            regeneration=regeneration,
            created_at=created_at,
        )
        stored = self._select_mapping(
            parent_ref=exact.parent_ref,
            excluded_client_hash=exact.excluded_client_hash,
            active_only=False,
        )
        if (
            stored is None
            or stored[0] != exact
            or stored[1] not in {"PREPARED", "ACTIVE"}
        ):
            raise LeaveOneOutError("LOO_ATOMIC_PREPARE_REQUIRED")
        self._assert_backing_rows(exact, approval_state="APPLIED")
        return exact

    def prepare_guarded(
        self,
        authority: LeaveOneOutVariantAuthority,
        *,
        regeneration: RegeneratedCaseArtifact,
        approval_ticket: ApprovalExecutionTicket,
        approval_guard: ApprovalExecutionGuard,
        created_at: datetime,
        fault_hook: FaultHook | None = None,
    ) -> tuple[LeaveOneOutVariantAuthority, ApprovalExecutionProof]:
        """Claim approval, write all LOO rows, and apply in one SQLite commit."""

        exact, rebuilt, created_at_text = self._validate_prepare_inputs(
            authority,
            regeneration=regeneration,
            created_at=created_at,
        )
        ticket = ApprovalExecutionTicket.model_validate(approval_ticket)
        if not isinstance(approval_guard, ApprovalExecutionGuard):
            raise TypeError("LOO approval guard is invalid")
        if getattr(approval_guard, "_connection", None) is not self._connection:
            raise LeaveOneOutError("LOO_APPROVAL_TRANSACTION_MISMATCH")
        descriptor = self._assert_ticket_binding(exact, ticket)

        def prepare_claimed(connection: sqlite3.Connection) -> None:
            if connection is not self._connection or not connection.in_transaction:
                raise LeaveOneOutError("LOO_APPROVAL_TRANSACTION_MISMATCH")
            self._assert_backing_rows(
                exact,
                approval_state="CLAIMED",
                approval_ticket=ticket,
            )
            self._write_prepared_rows(
                exact,
                rebuilt,
                created_at_text=created_at_text,
            )
            if fault_hook is not None:
                fault_hook("after_business_write")

        proof = approval_guard.apply_in_transaction(
            ticket,
            descriptor,
            prepare_claimed,
        )
        if (
            proof.operation_id != ticket.operation_id
            or proof.request_id != ticket.request_id
            or proof.descriptor_sha256 != ticket.descriptor_sha256
            or proof.draft_sha256 != descriptor.draft_sha256
            or proof.target_scope_hash != ticket.target_scope_hash
            or proof.state != "applied"
        ):
            raise LeaveOneOutError("LOO_APPROVAL_PROOF_MISMATCH")
        stored = self._select_mapping(
            parent_ref=exact.parent_ref,
            excluded_client_hash=exact.excluded_client_hash,
            active_only=False,
        )
        if (
            stored is None
            or stored[0] != exact
            or stored[1] not in {"PREPARED", "ACTIVE"}
        ):
            raise LeaveOneOutError("LOO_APPROVAL_MAPPING_MISSING")
        self._assert_backing_rows(
            exact,
            approval_state="APPLIED",
            approval_ticket=ticket,
        )
        return exact, proof

    @staticmethod
    def _validate_prepare_inputs(
        authority: LeaveOneOutVariantAuthority,
        *,
        regeneration: RegeneratedCaseArtifact,
        created_at: datetime,
    ) -> tuple[LeaveOneOutVariantAuthority, RegeneratedCaseArtifact, str]:
        exact = LeaveOneOutVariantAuthority.model_validate(authority)
        rebuilt = RegeneratedCaseArtifact.model_validate(regeneration)
        if (
            exact.parent_ref != rebuilt.parent_ref
            or exact.variant_ref != rebuilt.variant_ref
            or exact.content_ref != rebuilt.content_ref
            or exact.regeneration_rule_ref != rebuilt.regeneration_rule_ref
            or exact.regeneration_request_sha256
            != rebuilt.regeneration_request_sha256
            or exact.regeneration_proof_ref != rebuilt.regeneration_proof_ref
        ):
            raise LeaveOneOutError("LOO_AUTHORITY_REGENERATION_MISMATCH")
        return exact, rebuilt, _utc_text(created_at)

    @staticmethod
    def _assert_ticket_binding(
        authority: LeaveOneOutVariantAuthority,
        ticket: ApprovalExecutionTicket,
    ) -> DraftDescriptor:
        descriptor = _approval_descriptor(authority)
        if (
            ticket.descriptor != descriptor
            or ticket.receipt.approved_at != authority.approved_at
            or leave_one_out_approval_execution_ref(ticket)
            != authority.approval_ref
        ):
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_BINDING_MISMATCH")
        return descriptor

    def _write_prepared_rows(
        self,
        authority: LeaveOneOutVariantAuthority,
        regeneration: RegeneratedCaseArtifact,
        *,
        created_at_text: str,
    ) -> None:
        proof_values = (
            regeneration.regeneration_proof_ref.object_id,
            regeneration.regeneration_proof_ref.version,
            regeneration.regeneration_proof_ref.content_sha256,
            regeneration.regeneration_request_sha256,
            _ref_json(regeneration.parent_ref),
            _ref_json(regeneration.variant_ref),
            _ref_json(regeneration.content_ref),
            _ref_json(regeneration.regeneration_rule_ref),
            _refs_json(regeneration.input_case_refs),
            _refs_json(regeneration.input_independent_source_refs),
            regeneration.rendered_text_sha256,
            created_at_text,
        )
        self._connection.execute(
            """
            INSERT OR IGNORE INTO case_regeneration_proofs(
                proof_id, proof_version, proof_sha256, request_sha256,
                parent_ref_json, variant_ref_json, content_ref_json,
                regeneration_rule_ref_json, input_case_refs_json,
                input_independent_source_refs_json,
                rendered_text_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            proof_values,
        )
        stored_proof = self._connection.execute(
            """
            SELECT proof_id, proof_version, proof_sha256, request_sha256,
                   parent_ref_json, variant_ref_json, content_ref_json,
                   regeneration_rule_ref_json, input_case_refs_json,
                   input_independent_source_refs_json,
                   rendered_text_sha256, created_at
              FROM case_regeneration_proofs
             WHERE proof_id = ? AND proof_version = ?
            """,
            (
                regeneration.regeneration_proof_ref.object_id,
                regeneration.regeneration_proof_ref.version,
            ),
        ).fetchone()
        if stored_proof is None or tuple(stored_proof) != proof_values:
            raise LeaveOneOutError("LOO_REGENERATION_PROOF_CONFLICT")
        values = self._mapping_values(
            authority,
            state="PREPARED",
            created_at=created_at_text,
        )
        self._connection.execute(
            """
            INSERT OR IGNORE INTO case_leave_one_out_variants(
                mapping_id, mapping_version, mapping_sha256,
                parent_object_id, parent_version, parent_sha256,
                excluded_client_hash,
                variant_object_id, variant_version, variant_sha256,
                content_object_id, content_version, content_sha256,
                authority_manifest_id, authority_manifest_version,
                authority_manifest_sha256,
                provenance_id, provenance_version,
                approval_id, approval_version, approval_sha256,
                approval_descriptor_sha256,
                draft_id, draft_version, draft_sha256,
                regeneration_rule_id, regeneration_rule_version,
                regeneration_rule_sha256, regeneration_request_sha256,
                regeneration_proof_id, regeneration_proof_version,
                regeneration_proof_sha256, allowed_uses_json,
                source_grade, remaining_independent_source_count,
                minimum_independent_source_count, review_status, state,
                approved_at, effective_to, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            values,
        )
        stored = self._select_mapping(
            parent_ref=authority.parent_ref,
            excluded_client_hash=authority.excluded_client_hash,
            active_only=False,
        )
        if stored is None or stored[0] != authority or stored[1] != "PREPARED":
            raise LeaveOneOutError("LOO_AUTHORITY_MAPPING_CONFLICT")

    def activate(
        self,
        mapping_ref: VersionRef,
    ) -> LeaveOneOutVariantAuthority:
        exact_ref = VersionRef.model_validate(mapping_ref)
        try:
            with transaction(self._connection):
                row = self._connection.execute(
                    """
                    SELECT authority_manifest_id
                      FROM case_leave_one_out_variants
                     WHERE mapping_id = ? AND mapping_version = ?
                       AND mapping_sha256 = ? AND state IN ('PREPARED', 'ACTIVE')
                    """,
                    (
                        exact_ref.object_id,
                        exact_ref.version,
                        exact_ref.content_sha256,
                    ),
                ).fetchone()
                if row is None:
                    raise LeaveOneOutError("LOO_AUTHORITY_NOT_PREPARED")
                authority = self._select_by_mapping_ref(
                    exact_ref,
                    active_only=False,
                )
                if authority is None:
                    raise LeaveOneOutError("LOO_AUTHORITY_NOT_PREPARED")
                self._assert_backing_rows(authority)
                manifest = self._connection.execute(
                    "SELECT state, verified FROM artifact_manifests WHERE manifest_id = ?",
                    (str(row[0]),),
                ).fetchone()
                if manifest is None or tuple(manifest) != ("ACTIVE", 1):
                    raise LeaveOneOutError("LOO_AUTHORITY_MANIFEST_NOT_ACTIVE")
                changed = self._connection.execute(
                    """
                    UPDATE case_leave_one_out_variants SET state = 'ACTIVE'
                     WHERE mapping_id = ? AND mapping_version = ?
                       AND mapping_sha256 = ? AND state = 'PREPARED'
                    """,
                    (
                        exact_ref.object_id,
                        exact_ref.version,
                        exact_ref.content_sha256,
                    ),
                ).rowcount
                if changed == 1:
                    self._invalidate_authority(
                        exact_ref,
                        transition="activation",
                    )
                stored = self._select_by_mapping_ref(exact_ref, active_only=True)
                if stored is None:
                    raise LeaveOneOutError("LOO_AUTHORITY_ACTIVATION_FAILED")
                return stored
        except LeaveOneOutError:
            raise
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LeaveOneOutError("LOO_AUTHORITY_ACTIVATION_FAILED") from exc

    def revoke(self, mapping_ref: VersionRef) -> None:
        exact_ref = VersionRef.model_validate(mapping_ref)
        try:
            with transaction(self._connection):
                changed = self._connection.execute(
                    """
                    UPDATE case_leave_one_out_variants SET state = 'REVOKED'
                     WHERE mapping_id = ? AND mapping_version = ?
                       AND mapping_sha256 = ? AND state IN ('PREPARED', 'ACTIVE')
                    """,
                    (
                        exact_ref.object_id,
                        exact_ref.version,
                        exact_ref.content_sha256,
                    ),
                ).rowcount
                if changed == 1:
                    self._invalidate_authority(
                        exact_ref,
                        transition="revocation",
                    )
                if changed == 0:
                    row = self._connection.execute(
                        """
                        SELECT state FROM case_leave_one_out_variants
                         WHERE mapping_id = ? AND mapping_version = ?
                           AND mapping_sha256 = ?
                        """,
                        (
                            exact_ref.object_id,
                            exact_ref.version,
                            exact_ref.content_sha256,
                        ),
                    ).fetchone()
                    if row is None or tuple(row) != ("REVOKED",):
                        raise LeaveOneOutError("LOO_AUTHORITY_NOT_FOUND")
        except LeaveOneOutError:
            raise
        except sqlite3.Error as exc:
            raise LeaveOneOutError("LOO_AUTHORITY_REVOCATION_FAILED") from exc

    def _invalidate_authority(
        self,
        mapping_ref: VersionRef,
        *,
        transition: str,
    ) -> None:
        event_columns: tuple[tuple[str, str], ...]
        if transition == "activation":
            event_columns = (("AUTHORIZATION", "authorization_epoch"),)
        elif transition == "revocation":
            event_columns = (
                ("AUTHORIZATION", "authorization_epoch"),
                ("TOMBSTONE", "tombstone_epoch"),
            )
        else:  # Defensive: callers are private and exhaustive.
            raise LeaveOneOutError("LOO_AUTHORITY_TRANSITION_INVALID")
        catalog = self._connection.execute(
            """
            SELECT catalog_version FROM knowledge_catalog_state
             WHERE singleton = 1
            """
        ).fetchone()
        if catalog is None:
            raise LeaveOneOutError("LOO_AUTHORITY_EPOCH_MISSING")
        catalog_version = int(catalog[0])
        created_at = _utc_text(self._clock.now())
        upstream_type = f"case_leave_one_out_{transition}"
        for event_kind, column in event_columns:
            inserted = self._connection.execute(
                """
                INSERT OR IGNORE INTO security_invalidation_events(
                    upstream_type, upstream_id, catalog_version,
                    event_kind, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    upstream_type,
                    mapping_ref.object_id,
                    catalog_version,
                    event_kind,
                    created_at,
                ),
            ).rowcount
            if inserted == 1:
                updated = self._connection.execute(
                    f"""
                    UPDATE knowledge_catalog_state
                       SET {column} = {column} + 1
                     WHERE singleton = 1
                    """
                ).rowcount
                if updated != 1:
                    raise LeaveOneOutError("LOO_AUTHORITY_EPOCH_MISSING")

    def resolve_active(
        self,
        *,
        parent_ref: VersionRef,
        excluded_client_hash: str,
    ) -> LeaveOneOutVariantAuthority | None:
        selected = self._select_mapping(
            parent_ref=VersionRef.model_validate(parent_ref),
            excluded_client_hash=_SHA_ADAPTER.validate_python(
                excluded_client_hash
            ),
            active_only=True,
        )
        if selected is None:
            return None
        self._assert_backing_rows(selected[0])
        return selected[0]

    def _assert_backing_rows(
        self,
        value: LeaveOneOutVariantAuthority,
        *,
        approval_state: Literal["CLAIMED", "APPLIED"] = "APPLIED",
        approval_ticket: ApprovalExecutionTicket | None = None,
    ) -> None:
        self._assert_approval_execution(
            value,
            expected_state=approval_state,
            approval_ticket=approval_ticket,
        )
        manifest = self._connection.execute(
            """
            SELECT manifest_sha256, state, verified, source_version
              FROM artifact_manifests WHERE manifest_id = ?
            """,
            (value.authority_manifest_ref.object_id,),
        ).fetchone()
        if (
            manifest is None
            or str(manifest[0]) != value.authority_manifest_ref.content_sha256
            or str(manifest[1]) not in {"VERIFIED", "ACTIVE"}
            or int(manifest[2]) != 1
            or str(manifest[3]) != str(value.authority_manifest_ref.version)
        ):
            raise LeaveOneOutError("LOO_AUTHORITY_MANIFEST_INVALID")
        provenance = self._connection.execute(
            """
            SELECT provenance_sha256, artifact_object_id, artifact_version,
                   artifact_sha256, source_grade, allowed_uses_json, effective_to
              FROM case_provenance
             WHERE provenance_id = ? AND provenance_version = ?
            """,
            (value.provenance_ref.object_id, value.provenance_ref.version),
        ).fetchone()
        expected_expiry = (
            None if value.effective_to is None else _utc_text(value.effective_to)
        )
        if provenance is None or tuple(provenance[:5]) != (
            value.provenance_ref.content_sha256,
            value.variant_ref.object_id,
            value.variant_ref.version,
            value.variant_ref.content_sha256,
            value.source_grade,
        ) or provenance[6] != expected_expiry:
            raise LeaveOneOutError("LOO_AUTHORITY_PROVENANCE_INVALID")
        try:
            provenance_uses = frozenset(json.loads(str(provenance[5])))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise LeaveOneOutError("LOO_AUTHORITY_PROVENANCE_INVALID") from None
        if not value.allowed_uses.issubset(provenance_uses):
            raise LeaveOneOutError("LOO_AUTHORITY_PROVENANCE_INVALID")

    def _assert_approval_execution(
        self,
        value: LeaveOneOutVariantAuthority,
        *,
        expected_state: Literal["CLAIMED", "APPLIED"],
        approval_ticket: ApprovalExecutionTicket | None,
    ) -> None:
        row = self._connection.execute(
            """
            SELECT execution.request_id, execution.descriptor_sha256,
                   execution.draft_sha256,
                   execution.descriptor_base_version,
                   execution.target_scope_hash, execution.nonce_sha256,
                   execution.state, execution.applied_commit_version,
                   execution.applied_at,
                   request.descriptor_sha256, request.descriptor_json,
                   request.purpose, request.target_scope_hash,
                   request.base_version, request.expires_at, request.state,
                   receipt.operation_id, receipt.confirmed_at, receipt.state
              FROM approval_executions AS execution
              JOIN approval_requests AS request
                ON request.request_id = execution.request_id
              JOIN approval_receipts AS receipt
                ON receipt.request_id = execution.request_id
             WHERE execution.operation_id = ?
            """,
            (value.approval_ref.object_id,),
        ).fetchone()
        if row is None:
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")
        try:
            expected_descriptor = _approval_descriptor(value)
            stored_descriptor = DraftDescriptor.model_validate_json(str(row[10]))
            expires_at = _parse_utc(row[14])
            confirmed_at = _parse_utc(row[17])
        except (TypeError, ValueError, ValidationError, LeaveOneOutError):
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID") from None
        expected_descriptor_sha256 = descriptor_sha256(expected_descriptor)
        if (
            str(row[1]) != value.approval_descriptor_sha256
            or str(row[1]) != expected_descriptor_sha256
            or str(row[2]) != expected_descriptor.draft_sha256
            or int(row[3]) != expected_descriptor.base_version
            or str(row[4]) != str(row[12])
            or str(row[6]) != expected_state
            or str(row[9]) != expected_descriptor_sha256
            or stored_descriptor != expected_descriptor
            or str(row[11]) != expected_descriptor.purpose
            or int(row[13]) != expected_descriptor.base_version
            or str(row[15]) not in {"ISSUED", "ACKNOWLEDGED"}
            or str(row[16]) != value.approval_ref.object_id
            or confirmed_at != value.approved_at
            or str(row[18]) not in {"ISSUED", "ACKNOWLEDGED"}
        ):
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")
        if expected_state == "CLAIMED":
            if row[7] is not None or row[8] is not None:
                raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")
        else:
            try:
                applied_commit_version = int(row[7])
                applied_at = _parse_utc(row[8])
            except (TypeError, ValueError, LeaveOneOutError):
                raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID") from None
            if (
                applied_commit_version <= 0
                or applied_at < confirmed_at
                or applied_at >= expires_at
            ):
                raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")
        expected_approval_ref = VersionRef(
            object_id=value.approval_ref.object_id,
            version=1,
            content_sha256=canonical_sha256(
                {
                    "approved_at": confirmed_at.isoformat(),
                    "descriptor_base_version": int(row[3]),
                    "descriptor_sha256": str(row[1]),
                    "draft_sha256": str(row[2]),
                    "expires_at": expires_at.isoformat(),
                    "nonce_sha256": str(row[5]),
                    "operation_id": value.approval_ref.object_id,
                    "request_id": str(row[0]),
                    "schema_version": "loo_approval_execution_binding.v1",
                    "target_scope_hash": str(row[4]),
                }
            ),
        )
        if value.approval_ref != expected_approval_ref:
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")
        if approval_ticket is not None:
            ticket = ApprovalExecutionTicket.model_validate(approval_ticket)
            if (
                self._assert_ticket_binding(value, ticket) != expected_descriptor
                or ticket.request_id != str(row[0])
                or ticket.target_scope_hash != str(row[4])
                or hashlib.sha256(ticket.receipt.nonce.encode("ascii")).hexdigest()
                != str(row[5])
                or ticket.receipt.approved_at != confirmed_at
                or ticket.receipt.expires_at != expires_at
            ):
                raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_INVALID")

    @staticmethod
    def _mapping_values(
        value: LeaveOneOutVariantAuthority,
        *,
        state: str,
        created_at: str,
    ) -> tuple[object, ...]:
        return (
            value.mapping_ref.object_id,
            value.mapping_ref.version,
            value.mapping_ref.content_sha256,
            value.parent_ref.object_id,
            value.parent_ref.version,
            value.parent_ref.content_sha256,
            value.excluded_client_hash,
            value.variant_ref.object_id,
            value.variant_ref.version,
            value.variant_ref.content_sha256,
            value.content_ref.object_id,
            value.content_ref.version,
            value.content_ref.content_sha256,
            value.authority_manifest_ref.object_id,
            value.authority_manifest_ref.version,
            value.authority_manifest_ref.content_sha256,
            value.provenance_ref.object_id,
            value.provenance_ref.version,
            value.approval_ref.object_id,
            value.approval_ref.version,
            value.approval_ref.content_sha256,
            value.approval_descriptor_sha256,
            value.draft_ref.object_id,
            value.draft_ref.version,
            value.draft_ref.content_sha256,
            value.regeneration_rule_ref.object_id,
            value.regeneration_rule_ref.version,
            value.regeneration_rule_ref.content_sha256,
            value.regeneration_request_sha256,
            value.regeneration_proof_ref.object_id,
            value.regeneration_proof_ref.version,
            value.regeneration_proof_ref.content_sha256,
            _canonical_json(sorted(value.allowed_uses)),
            value.source_grade,
            value.remaining_independent_source_count,
            value.minimum_independent_source_count,
            value.review_status,
            state,
            _utc_text(value.approved_at),
            None if value.effective_to is None else _utc_text(value.effective_to),
            created_at,
        )

    def _select_by_mapping_ref(
        self,
        mapping_ref: VersionRef,
        *,
        active_only: bool,
    ) -> LeaveOneOutVariantAuthority | None:
        state_clause = "AND loo.state = 'ACTIVE'" if active_only else ""
        row = self._connection.execute(
            self._select_sql(
                "loo.mapping_id = ? AND loo.mapping_version = ? "
                "AND loo.mapping_sha256 = ?",
                state_clause,
            ),
            (
                mapping_ref.object_id,
                mapping_ref.version,
                mapping_ref.content_sha256,
            ),
        ).fetchone()
        return None if row is None else self._authority_from_row(row)

    def _select_mapping(
        self,
        *,
        parent_ref: VersionRef,
        excluded_client_hash: str,
        active_only: bool,
    ) -> tuple[LeaveOneOutVariantAuthority, str] | None:
        state_clause = "AND loo.state = 'ACTIVE'" if active_only else ""
        row = self._connection.execute(
            self._select_sql(
                "loo.parent_object_id = ? AND loo.parent_version = ? "
                "AND loo.parent_sha256 = ? AND loo.excluded_client_hash = ?",
                state_clause,
            ),
            (
                parent_ref.object_id,
                parent_ref.version,
                parent_ref.content_sha256,
                excluded_client_hash,
            ),
        ).fetchone()
        if row is None:
            return None
        return self._authority_from_row(row), str(row[-1])

    @staticmethod
    def _select_sql(where: str, state_clause: str) -> str:
        return f"""
            SELECT loo.mapping_id, loo.mapping_version, loo.mapping_sha256,
                   loo.parent_object_id, loo.parent_version, loo.parent_sha256,
                   loo.excluded_client_hash,
                   loo.variant_object_id, loo.variant_version, loo.variant_sha256,
                   loo.content_object_id, loo.content_version, loo.content_sha256,
                   loo.authority_manifest_id, loo.authority_manifest_version,
                   loo.authority_manifest_sha256,
                   loo.provenance_id, loo.provenance_version,
                   cp.provenance_sha256,
                   loo.approval_id, loo.approval_version, loo.approval_sha256,
                   loo.approval_descriptor_sha256,
                   loo.draft_id, loo.draft_version, loo.draft_sha256,
                   loo.regeneration_rule_id, loo.regeneration_rule_version,
                   loo.regeneration_rule_sha256,
                   loo.regeneration_request_sha256,
                   loo.regeneration_proof_id, loo.regeneration_proof_version,
                   loo.regeneration_proof_sha256,
                   loo.allowed_uses_json, loo.approved_at, loo.effective_to,
                   loo.source_grade, loo.remaining_independent_source_count,
                   loo.minimum_independent_source_count, loo.state
              FROM case_leave_one_out_variants AS loo
              JOIN case_provenance AS cp
                ON cp.provenance_id = loo.provenance_id
               AND cp.provenance_version = loo.provenance_version
             WHERE {where} {state_clause}
        """

    @staticmethod
    def _authority_from_row(row: sqlite3.Row | tuple[object, ...]) -> LeaveOneOutVariantAuthority:
        try:
            allowed_uses = frozenset(json.loads(str(row[33])))
            return LeaveOneOutVariantAuthority(
                mapping_ref=VersionRef(
                    object_id=str(row[0]), version=int(str(row[1])), content_sha256=str(row[2])
                ),
                parent_ref=VersionRef(
                    object_id=str(row[3]), version=int(str(row[4])), content_sha256=str(row[5])
                ),
                excluded_client_hash=str(row[6]),
                variant_ref=VersionRef(
                    object_id=str(row[7]), version=int(str(row[8])), content_sha256=str(row[9])
                ),
                content_ref=VersionRef(
                    object_id=str(row[10]), version=int(str(row[11])), content_sha256=str(row[12])
                ),
                authority_manifest_ref=VersionRef(
                    object_id=str(row[13]), version=int(str(row[14])), content_sha256=str(row[15])
                ),
                provenance_ref=VersionRef(
                    object_id=str(row[16]), version=int(str(row[17])), content_sha256=str(row[18])
                ),
                approval_ref=VersionRef(
                    object_id=str(row[19]), version=int(str(row[20])), content_sha256=str(row[21])
                ),
                approval_version=int(str(row[20])),
                approval_descriptor_sha256=str(row[22]),
                draft_ref=VersionRef(
                    object_id=str(row[23]), version=int(str(row[24])), content_sha256=str(row[25])
                ),
                regeneration_rule_ref=VersionRef(
                    object_id=str(row[26]), version=int(str(row[27])), content_sha256=str(row[28])
                ),
                regeneration_request_sha256=str(row[29]),
                regeneration_proof_ref=VersionRef(
                    object_id=str(row[30]), version=int(str(row[31])), content_sha256=str(row[32])
                ),
                allowed_uses=allowed_uses,
                approved_at=_parse_utc(row[34]),
                effective_to=None if row[35] is None else _parse_utc(row[35]),
                source_grade=cast(SourceGrade, str(row[36])),
                remaining_independent_source_count=int(str(row[37])),
                minimum_independent_source_count=int(str(row[38])),
                mapping_sha256=str(row[2]),
            )
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
            raise LeaveOneOutError("LOO_AUTHORITY_ROW_INVALID") from None


class LeaveOneOutBuilder:
    """Regenerate exact variants; never delete contributor metadata in place."""

    def __init__(
        self,
        *,
        id_factory: IdFactory,
        provenance_service: CaseProvenanceService,
        regenerator: LeaveOneOutRegenerator,
        approval_verifier: LeaveOneOutApprovalVerifier | None = None,
    ) -> None:
        if not isinstance(id_factory, IdFactory):
            raise TypeError("leave-one-out builder requires IdFactory")
        if not isinstance(provenance_service, CaseProvenanceService):
            raise TypeError("leave-one-out builder requires CaseProvenanceService")
        if not isinstance(regenerator, LeaveOneOutRegenerator):
            raise TypeError("leave-one-out builder requires a trusted regenerator")
        if approval_verifier is not None and not isinstance(
            approval_verifier, LeaveOneOutApprovalVerifier
        ):
            raise TypeError("leave-one-out approval verifier is invalid")
        self._ids = id_factory
        self._provenance = provenance_service
        self._regenerator = regenerator
        self._approval_verifier = approval_verifier

    def build(
        self,
        parent: CaseProvenanceRecord,
        *,
        excluded_client_hash: str,
        minimum_independent_source_count: int = 2,
        operation_idempotency_key: str | None = None,
    ) -> LeaveOneOutBuildResult:
        lineage = CaseProvenanceRecord.model_validate(parent)
        try:
            lineage = self._provenance.assert_current(lineage)
        except CaseProvenanceError as exc:
            raise LeaveOneOutError(exc.code) from exc
        excluded = _SHA_ADAPTER.validate_python(excluded_client_hash)
        if type(minimum_independent_source_count) is not int or (
            minimum_independent_source_count <= 0
        ):
            raise ValueError("LOO minimum independent source count must be positive")
        if excluded not in lineage.contributor_client_hashes:
            raise LeaveOneOutError("LOO_EXCLUDED_CONTRIBUTOR_NOT_PRESENT")

        # Remove an entire case contribution whenever the excluded client took
        # part in it.  Removing only one hash would falsely claim the underlying
        # case no longer contains that client's contribution.
        remaining_cases = tuple(
            item
            for item in lineage.case_contributions
            if excluded not in item.contributor_client_hashes
        )
        remaining_independent = lineage.independent_evidence
        if not remaining_cases and not remaining_independent:
            raise LeaveOneOutError("LOO_NO_REMAINING_EVIDENCE")

        expected_case_refs = tuple(item.case_ref for item in remaining_cases)
        expected_independent_refs = tuple(
            item.evidence_ref for item in remaining_independent
        )
        try:
            regenerated = self._regenerator.regenerate(
                parent_ref=lineage.artifact_ref,
                artifact_kind=lineage.artifact_kind,
                regeneration_rule_ref=lineage.derivation_rule_ref,
                input_case_refs=expected_case_refs,
                input_independent_source_refs=expected_independent_refs,
                operation_idempotency_key=operation_idempotency_key,
            )
            rebuilt = RegeneratedCaseArtifact.model_validate(regenerated)
        except (TypeError, ValueError, ValidationError):
            raise LeaveOneOutError("LOO_REGENERATION_PROOF_INVALID") from None
        except Exception:
            raise LeaveOneOutError("LOO_REGENERATION_FAILED") from None
        if rebuilt.parent_ref != lineage.artifact_ref:
            raise LeaveOneOutError("LOO_PARENT_REFERENCE_MISMATCH")
        if rebuilt.regeneration_rule_ref != lineage.derivation_rule_ref:
            raise LeaveOneOutError("LOO_REGENERATION_RULE_VERSION_MISMATCH")
        if {
            version_ref_key(item) for item in rebuilt.input_case_refs
        } != {version_ref_key(item) for item in expected_case_refs}:
            raise LeaveOneOutError("LOO_REGENERATION_CASE_INPUT_MISMATCH")
        if {
            version_ref_key(item) for item in rebuilt.input_independent_source_refs
        } != {version_ref_key(item) for item in expected_independent_refs}:
            raise LeaveOneOutError("LOO_REGENERATION_SOURCE_INPUT_MISMATCH")

        try:
            variant_provenance = self._provenance.regenerate_from_exact_sources(
                rebuilt.variant_ref,
                lineage.artifact_kind,
                case_contributions=remaining_cases,
                independent_evidence=remaining_independent,
                derivation_rule_ref=rebuilt.regeneration_rule_ref,
                operation_idempotency_key=(
                    None
                    if operation_idempotency_key is None
                    else "loo-provenance:"
                    + canonical_sha256(
                        {"operation_idempotency_key": operation_idempotency_key}
                    )
                ),
            )
        except CaseProvenanceError as exc:
            raise LeaveOneOutError(exc.code) from exc

        remaining_contributors = frozenset(
            value
            for item in remaining_cases
            for value in item.contributor_client_hashes
        )
        if excluded in remaining_contributors:
            raise LeaveOneOutError("LOO_EXCLUDED_CONTRIBUTOR_REMAINS")
        independent_source_count = len(remaining_contributors) + len(
            {item.source_lineage_sha256 for item in remaining_independent}
        )
        ineligibility: LeaveOneOutIneligibility | None = None
        if independent_source_count < minimum_independent_source_count:
            ineligibility = "insufficient_independent_sources"
        elif (
            lineage.artifact_kind == "case_pattern"
            and (
                variant_provenance.source_grade != "K3"
                or len(remaining_cases) < 2
                or len(remaining_contributors) < 2
            )
        ):
            ineligibility = "grade_below_policy"
        elif (
            lineage.source_grade == "K3"
            and variant_provenance.source_grade.startswith("K")
            and variant_provenance.source_grade != "K3"
        ):
            ineligibility = "grade_below_policy"

        draft_id = self._ids.object_id("case_leave_one_out_draft")
        version = 1
        draft_sha256 = canonical_sha256(
            leave_one_out_draft_payload(
                draft_id=draft_id,
                version=version,
                artifact_kind=lineage.artifact_kind,
                parent_ref=lineage.artifact_ref,
                parent_provenance_ref=lineage.provenance_ref,
                excluded_client_hash=excluded,
                variant_ref=rebuilt.variant_ref,
                variant_provenance_ref=variant_provenance.provenance_ref,
                content_ref=rebuilt.content_ref,
                regeneration_rule_ref=rebuilt.regeneration_rule_ref,
                regeneration_request_sha256=(
                    rebuilt.regeneration_request_sha256
                ),
                regeneration_proof_ref=rebuilt.regeneration_proof_ref,
                remaining_case_count=len(remaining_cases),
                remaining_contributor_count=len(remaining_contributors),
                remaining_independent_evidence_count=len(remaining_independent),
                remaining_independent_source_count=independent_source_count,
                minimum_independent_source_count=minimum_independent_source_count,
                source_grade=variant_provenance.source_grade,
                provenance_scope=variant_provenance.provenance_scope,
                eligible_for_approval=ineligibility is None,
                ineligibility_reason=ineligibility,
            )
        )
        draft = LeaveOneOutDraft(
            draft_ref=VersionRef(
                object_id=draft_id,
                version=version,
                content_sha256=draft_sha256,
            ),
            artifact_kind=lineage.artifact_kind,
            parent_ref=lineage.artifact_ref,
            parent_provenance_ref=lineage.provenance_ref,
            excluded_client_hash=excluded,
            variant_ref=rebuilt.variant_ref,
            variant_provenance_ref=variant_provenance.provenance_ref,
            content_ref=rebuilt.content_ref,
            regeneration_rule_ref=rebuilt.regeneration_rule_ref,
            regeneration_request_sha256=rebuilt.regeneration_request_sha256,
            regeneration_proof_ref=rebuilt.regeneration_proof_ref,
            remaining_case_count=len(remaining_cases),
            remaining_contributor_count=len(remaining_contributors),
            remaining_independent_evidence_count=len(remaining_independent),
            remaining_independent_source_count=independent_source_count,
            minimum_independent_source_count=minimum_independent_source_count,
            source_grade=variant_provenance.source_grade,
            provenance_scope=variant_provenance.provenance_scope,
            eligible_for_approval=ineligibility is None,
            ineligibility_reason=ineligibility,
            draft_sha256=draft_sha256,
        )
        return LeaveOneOutBuildResult(
            draft=draft,
            parent_provenance=lineage,
            variant_provenance=variant_provenance,
            regeneration=rebuilt,
        )

    @staticmethod
    def approval_descriptor(
        result: LeaveOneOutBuildResult,
        *,
        authority_manifest_ref: VersionRef,
        allowed_uses: frozenset[str],
    ) -> DraftDescriptor:
        built = LeaveOneOutBuildResult.model_validate(result)
        authority_manifest = VersionRef.model_validate(authority_manifest_ref)
        if not allowed_uses or not allowed_uses.issubset(
            built.variant_provenance.allowed_uses
        ):
            raise LeaveOneOutError("LOO_ALLOWED_USE_EXPANSION")
        approval_scope_sha256 = canonical_sha256(
            {
                "allowed_uses": sorted(allowed_uses),
                "authority_manifest_ref": authority_manifest.model_dump(mode="json"),
                "draft_ref": built.draft.draft_ref.model_dump(mode="json"),
                "schema_version": "leave_one_out_approval_scope.v1",
            }
        )
        return DraftDescriptor(
            purpose="case_publish",
            target_id=built.draft.draft_ref.object_id,
            client_id=None,
            base_version=built.draft.parent_ref.version,
            draft_sha256=approval_scope_sha256,
            session_id=None,
        )

    def approve(
        self,
        result: LeaveOneOutBuildResult,
        *,
        approval_ticket: ApprovalExecutionTicket,
        authority_manifest_ref: VersionRef,
        allowed_uses: frozenset[str],
    ) -> LeaveOneOutVariantAuthority:
        built = LeaveOneOutBuildResult.model_validate(result)
        authority_manifest = VersionRef.model_validate(authority_manifest_ref)
        draft = built.draft
        try:
            self._provenance.assert_current(
                built.variant_provenance,
                expected_derivation_rule_ref=draft.regeneration_rule_ref,
            )
        except CaseProvenanceError as exc:
            raise LeaveOneOutError(exc.code) from exc
        if not draft.eligible_for_approval:
            raise LeaveOneOutError("LOO_VARIANT_NOT_ELIGIBLE")
        descriptor = self.approval_descriptor(
            built,
            authority_manifest_ref=authority_manifest,
            allowed_uses=allowed_uses,
        )
        try:
            ticket = ApprovalExecutionTicket.model_validate(approval_ticket)
        except (TypeError, ValueError, ValidationError):
            raise LeaveOneOutError("LOO_APPROVAL_TICKET_INVALID") from None
        if ticket.descriptor != descriptor:
            raise LeaveOneOutError("LOO_APPROVAL_DESCRIPTOR_MISMATCH")
        verifier = self._approval_verifier
        if verifier is None:
            raise LeaveOneOutError("LOO_APPROVAL_VERIFIER_REQUIRED")
        try:
            resolved_approval = verifier.verify_leave_one_out_approval(
                ticket=ticket,
                descriptor=descriptor,
            )
        except Exception:
            raise LeaveOneOutError("LOO_APPROVAL_VERIFICATION_FAILED") from None
        if resolved_approval is None:
            raise LeaveOneOutError("LOO_APPROVAL_NOT_AUTHORIZED")
        try:
            approval = VersionRef.model_validate(resolved_approval)
        except (TypeError, ValueError, ValidationError):
            raise LeaveOneOutError("LOO_APPROVAL_REFERENCE_INVALID") from None
        if approval != leave_one_out_approval_execution_ref(ticket):
            raise LeaveOneOutError("LOO_APPROVAL_EXECUTION_BINDING_MISMATCH")
        approved_at = ticket.receipt.approved_at
        if (
            built.variant_provenance.effective_to is not None
            and built.variant_provenance.effective_to <= approved_at
        ):
            raise LeaveOneOutError("LOO_VARIANT_EXPIRED_BEFORE_APPROVAL")

        mapping_id = self._ids.object_id("case_leave_one_out_variant")
        version = 1
        mapping_sha256 = canonical_sha256(
            leave_one_out_authority_payload(
                mapping_id=mapping_id,
                version=version,
                parent_ref=draft.parent_ref,
                excluded_client_hash=draft.excluded_client_hash,
                variant_ref=draft.variant_ref,
                content_ref=draft.content_ref,
                authority_manifest_ref=authority_manifest,
                provenance_ref=draft.variant_provenance_ref,
                approval_ref=approval,
                approval_version=approval.version,
                approval_descriptor_sha256=ticket.descriptor_sha256,
                draft_ref=draft.draft_ref,
                regeneration_rule_ref=draft.regeneration_rule_ref,
                regeneration_request_sha256=(
                    draft.regeneration_request_sha256
                ),
                regeneration_proof_ref=draft.regeneration_proof_ref,
                allowed_uses=allowed_uses,
                approved_at=approved_at,
                effective_to=built.variant_provenance.effective_to,
                source_grade=draft.source_grade,
                remaining_independent_source_count=(
                    draft.remaining_independent_source_count
                ),
                minimum_independent_source_count=(
                    draft.minimum_independent_source_count
                ),
            )
        )
        return LeaveOneOutVariantAuthority(
            mapping_ref=VersionRef(
                object_id=mapping_id,
                version=version,
                content_sha256=mapping_sha256,
            ),
            parent_ref=draft.parent_ref,
            excluded_client_hash=draft.excluded_client_hash,
            variant_ref=draft.variant_ref,
            content_ref=draft.content_ref,
            authority_manifest_ref=authority_manifest,
            provenance_ref=draft.variant_provenance_ref,
            approval_ref=approval,
            approval_version=approval.version,
            approval_descriptor_sha256=ticket.descriptor_sha256,
            draft_ref=draft.draft_ref,
            regeneration_rule_ref=draft.regeneration_rule_ref,
            regeneration_request_sha256=draft.regeneration_request_sha256,
            regeneration_proof_ref=draft.regeneration_proof_ref,
            allowed_uses=allowed_uses,
            approved_at=approved_at,
            effective_to=built.variant_provenance.effective_to,
            source_grade=draft.source_grade,
            remaining_independent_source_count=(
                draft.remaining_independent_source_count
            ),
            minimum_independent_source_count=(
                draft.minimum_independent_source_count
            ),
            mapping_sha256=mapping_sha256,
        )


__all__ = [
    "LeaveOneOutApprovalVerifier",
    "LeaveOneOutAuthorityRepository",
    "LeaveOneOutBuilder",
    "LeaveOneOutError",
    "LeaveOneOutRegenerator",
    "leave_one_out_approval_execution_ref",
]
