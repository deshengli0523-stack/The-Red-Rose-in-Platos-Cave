"""Target-transaction approval execution with idempotent crash recovery."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import datetime

from consultation_kb.core.clock import Clock
from consultation_kb.models.manifests import ApprovalExecution, DraftDescriptor
from consultation_kb.storage.connection import transaction

from .attestation import TargetExecutionAttestorSigner
from .models import ApprovalExecutionProof, ApprovalExecutionTicket
from .store import (
    ApprovalExpired,
    ApprovalMismatch,
    ApprovalService,
    ApprovalUnavailable,
    ApprovalUsed,
)


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _default_commit_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        """
        SELECT COALESCE(MAX(CAST(applied_commit_version AS INTEGER)), 0) + 1
          FROM approval_executions
        """
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] <= 0:
        raise ApprovalUnavailable("commit version allocation failed")
    return row[0]


class ApprovalExecutionGuard:
    """Apply one approved operation in the same transaction as its business write."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        approval_service: ApprovalService,
        execution_proof_signer: TargetExecutionAttestorSigner,
        clock: Clock,
        commit_version_allocator: Callable[[sqlite3.Connection], int] = (
            _default_commit_version
        ),
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("approval execution guard requires sqlite3.Connection")
        if not isinstance(execution_proof_signer, TargetExecutionAttestorSigner):
            raise TypeError("approval execution guard requires a target attestor")
        self._connection = connection
        self._approval_service = approval_service
        self._execution_proof_signer = execution_proof_signer
        self._clock = clock
        self._commit_version_allocator = commit_version_allocator
        self._fault_hook = fault_hook

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _existing(self, ticket: ApprovalExecutionTicket) -> ApprovalExecution | None:
        row = self._connection.execute(
            """
            SELECT request_id, descriptor_sha256, draft_sha256,
                   descriptor_base_version,
                   target_scope_hash, nonce_sha256, state,
                   applied_commit_version
              FROM approval_executions
             WHERE operation_id = ?
            """,
            (ticket.operation_id,),
        ).fetchone()
        if row is None:
            return None
        expected_nonce = hashlib.sha256(
            ticket.receipt.nonce.encode("ascii")
        ).hexdigest()
        if (
            row[0] != ticket.request_id
            or row[1] != ticket.descriptor_sha256
            or row[2] != ticket.descriptor.draft_sha256
            or row[3] != ticket.descriptor.base_version
            or row[4] != ticket.target_scope_hash
            or row[5] != expected_nonce
            or row[6] != "APPLIED"
        ):
            raise ApprovalMismatch("existing approval execution does not match")
        try:
            commit_version = int(row[7])
        except (TypeError, ValueError):
            raise ApprovalUnavailable("approval execution is unavailable") from None
        if commit_version <= 0:
            raise ApprovalUnavailable("approval execution is unavailable")
        return ApprovalExecution(
            operation_id=ticket.operation_id,
            request_id=ticket.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            target_scope_hash=ticket.target_scope_hash,
            state="applied",
            applied_commit_version=commit_version,
        )

    def apply_in_transaction(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        callback: Callable[[sqlite3.Connection], object],
    ) -> ApprovalExecutionProof:
        validated_ticket = ApprovalExecutionTicket.model_validate(ticket)
        validated_descriptor = DraftDescriptor.model_validate(descriptor)

        # This proves the service-side operation binding but deliberately permits
        # an expired ticket long enough to identify an already committed retry.
        receipt = self._approval_service.verify_ticket(
            validated_ticket,
            validated_descriptor,
            allow_expired=True,
        )
        with transaction(self._connection):
            existing = self._existing(validated_ticket)
            if existing is None:
                if self._clock.now() >= receipt.expires_at:
                    raise ApprovalExpired("approval receipt expired")

                nonce_sha256 = hashlib.sha256(receipt.nonce.encode("ascii")).hexdigest()
                conflict = self._connection.execute(
                    """
                    SELECT operation_id
                      FROM approval_executions
                     WHERE request_id = ? OR nonce_sha256 = ?
                    """,
                    (receipt.request_id, nonce_sha256),
                ).fetchone()
                if conflict is not None:
                    raise ApprovalUsed("approval was already used")

                # Claim the one-shot approval before the callback so every governed
                # business writer can prove that it is executing inside this exact
                # approval transaction.  A callback failure rolls this row back
                # together with every business write.
                self._connection.execute(
                    """
                    INSERT INTO approval_executions(
                        operation_id, request_id, descriptor_sha256, draft_sha256,
                        descriptor_base_version, target_scope_hash,
                        nonce_sha256, state,
                        applied_commit_version, applied_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
                    """,
                    (
                        validated_ticket.operation_id,
                        receipt.request_id,
                        receipt.descriptor_sha256,
                        validated_descriptor.draft_sha256,
                        validated_descriptor.base_version,
                        validated_ticket.target_scope_hash,
                        nonce_sha256,
                    ),
                )
                self._fault("after_approval_claim")

                callback(self._connection)
                commit_version = self._commit_version_allocator(self._connection)
                if type(commit_version) is not int or commit_version <= 0:
                    raise ApprovalUnavailable("commit version allocation failed")
                now = self._clock.now()
                changed = self._connection.execute(
                    """
                    UPDATE approval_executions
                       SET state = 'APPLIED', applied_commit_version = ?, applied_at = ?
                     WHERE operation_id = ? AND request_id = ?
                       AND descriptor_sha256 = ? AND draft_sha256 = ?
                       AND descriptor_base_version = ?
                       AND target_scope_hash = ?
                       AND nonce_sha256 = ? AND state = 'CLAIMED'
                       AND applied_commit_version IS NULL AND applied_at IS NULL
                    """,
                    (
                        commit_version,
                        _utc_text(now),
                        validated_ticket.operation_id,
                        receipt.request_id,
                        receipt.descriptor_sha256,
                        validated_descriptor.draft_sha256,
                        validated_descriptor.base_version,
                        validated_ticket.target_scope_hash,
                        nonce_sha256,
                    ),
                ).rowcount
                if changed != 1:
                    raise ApprovalUnavailable("approval execution claim was lost")
                self._fault("before_target_commit")
        # Re-read the authoritative APPLIED row only after the target transaction
        # has committed. A missing or altered row cannot receive an attestation.
        committed = self._existing(validated_ticket)
        if committed is None:
            raise ApprovalUnavailable("approval execution commit is unavailable")
        self._fault("after_target_commit_before_ack")
        nonce_sha256 = hashlib.sha256(receipt.nonce.encode("ascii")).hexdigest()
        return self._execution_proof_signer.attest(
            execution=committed,
            draft_sha256=validated_ticket.descriptor.draft_sha256,
            nonce_sha256=nonce_sha256,
            issuance_signature=validated_ticket.issuance_signature,
        )


__all__ = ["ApprovalExecutionGuard"]
