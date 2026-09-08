"""Transactional global store for one-shot approval requests and receipts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta

from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ObjectId, Sha256Hex, VersionRef
from consultation_kb.models.manifests import (
    ApprovalExecution,
    ApprovalReceipt,
    DraftDescriptor,
)
from consultation_kb.security.dpapi import SecretProtector
from consultation_kb.storage.connection import transaction

from .attestation import TargetExecutionProofVerifier
from .models import (
    ApprovalChallenge,
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
    ApprovalRequest,
    ApprovalRequestState,
    descriptor_sha256,
)
from .provider import ApprovalProvider


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_NONCE_PURPOSE = "approval_nonce"
_RECEIPT_PURPOSE = "approval_receipt"
_OBJECT_ID_ADAPTER = TypeAdapter(ObjectId)


class ApprovalError(RuntimeError):
    """Stable, content-free approval failure boundary."""


class ApprovalRequired(ApprovalError):
    pass


class ApprovalUnavailable(ApprovalError):
    pass


class ApprovalMismatch(ApprovalError):
    pass


class ApprovalExpired(ApprovalError):
    pass


class ApprovalUsed(ApprovalError):
    pass


class ApprovalProviderRejected(ApprovalError):
    pass


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc_text(value: object) -> datetime:
    if type(value) is not str:
        raise ApprovalUnavailable("approval record is unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApprovalUnavailable("approval record is unavailable") from None
    return parsed


def _canonical_model_bytes(model: ApprovalReceipt | DraftDescriptor) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _state_from_db(value: object) -> ApprovalRequestState:
    if type(value) is not str:
        raise ApprovalUnavailable("approval record is unavailable")
    states: dict[str, ApprovalRequestState] = {
        "PENDING": "pending",
        "CONFIRMED": "confirmed",
        "REJECTED": "rejected",
        "ISSUED": "confirmed",
        "ACKNOWLEDGED": "acknowledged",
    }
    try:
        return states[value]
    except KeyError:
        raise ApprovalUnavailable("approval record is unavailable") from None


class ApprovalService:
    """Create, confirm, bind and acknowledge approvals without exposing secrets."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        provider: ApprovalProvider,
        protector: SecretProtector,
        clock: Clock,
        id_factory: IdFactory,
        target_scope_hash: Sha256Hex,
        vault_id: str,
        execution_secret: bytes,
        execution_proof_verifier: TargetExecutionProofVerifier,
        ttl: timedelta = timedelta(minutes=5),
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("approval service requires sqlite3.Connection")
        if _SHA256_RE.fullmatch(target_scope_hash) is None:
            raise ValueError("target scope hash must be lowercase SHA-256")
        if type(vault_id) is not str or not vault_id.strip():
            raise ValueError("approval service requires a nonblank vault ID")
        if type(execution_secret) is not bytes or len(execution_secret) < 32:
            raise ValueError("execution secret must contain at least 256 bits")
        if not isinstance(execution_proof_verifier, TargetExecutionProofVerifier):
            raise TypeError("approval service requires an execution proof verifier")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise ValueError("approval TTL must be positive")
        self._connection = connection
        self._provider = provider
        self._protector = protector
        self._clock = clock
        self._id_factory = id_factory
        self._target_scope_hash = target_scope_hash
        self._vault_id = vault_id
        self._execution_secret = bytes(execution_secret)
        self._execution_proof_verifier = execution_proof_verifier
        self._ttl = ttl
        self._nonce_source = nonce_source

    @property
    def target_scope_hash(self) -> str:
        return self._target_scope_hash

    def request(
        self,
        descriptor: DraftDescriptor,
        *,
        diff_object_ref: VersionRef,
        request_id: str | None = None,
    ) -> ApprovalRequest:
        validated = DraftDescriptor.model_validate(descriptor)
        validated_diff_ref = VersionRef.model_validate(diff_object_ref)
        has_reserved_request_id = request_id is not None
        if request_id is None:
            validated_request_id = self._id_factory.object_id("approval_request")
        else:
            try:
                validated_request_id = _OBJECT_ID_ADAPTER.validate_python(request_id)
            except ValidationError:
                raise ApprovalError("approval request ID is invalid") from None
            if not validated_request_id.startswith("approval_request_"):
                raise ApprovalError("approval request ID is invalid")
        now = self._clock.now()
        expires_at = now + self._ttl
        expected_descriptor_sha256 = descriptor_sha256(validated)
        descriptor_json = _canonical_model_bytes(validated).decode("ascii")
        with transaction(self._connection):
            existing_row = self._connection.execute(
                "SELECT 1 FROM approval_requests WHERE request_id = ?",
                (validated_request_id,),
            ).fetchone()
            if existing_row is not None:
                if not has_reserved_request_id:
                    raise ApprovalUnavailable("approval request is unavailable")
                existing = self._load_request(validated_request_id)
                if (
                    not hmac.compare_digest(
                        existing.descriptor_sha256,
                        expected_descriptor_sha256,
                    )
                    or existing.descriptor != validated
                    or existing.diff_object_ref != validated_diff_ref
                ):
                    raise ApprovalUnavailable("approval request is unavailable")
                return existing

            raw_nonce = self._nonce_source(32)
            if type(raw_nonce) is not bytes or len(raw_nonce) != 32:
                raise ApprovalError("approval nonce generation failed")
            nonce = base64.urlsafe_b64encode(raw_nonce).rstrip(b"=").decode("ascii")
            nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            nonce_ciphertext = self._protector.protect(
                nonce.encode("ascii"),
                purpose=_NONCE_PURPOSE,
                vault_id=self._vault_id,
            )
            request = ApprovalRequest(
                request_id=validated_request_id,
                descriptor=validated,
                descriptor_sha256=expected_descriptor_sha256,
                diff_object_ref=validated_diff_ref,
                created_at=now,
                expires_at=expires_at,
                nonce_sha256=nonce_sha256,
                state="pending",
            )
            self._connection.execute(
                """
                INSERT INTO approval_requests(
                    request_id, descriptor_sha256, descriptor_json, diff_object_ref_json,
                    purpose, target_scope_hash, session_id, base_version, created_at,
                    expires_at, nonce_sha256, nonce_ciphertext, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
                """,
                (
                    request.request_id,
                    request.descriptor_sha256,
                    descriptor_json,
                    json.dumps(
                        request.diff_object_ref.model_dump(mode="json"),
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    validated.purpose,
                    self._target_scope_hash,
                    validated.session_id,
                    validated.base_version,
                    _utc_text(now),
                    _utc_text(expires_at),
                    nonce_sha256,
                    nonce_ciphertext,
                ),
            )
        return request

    def has_execution_binding(
        self,
        request_id: str,
        descriptor: DraftDescriptor,
    ) -> bool:
        """Return whether an approval has been irreversibly bound to an operation.

        This narrow control-plane query lets a domain workflow distinguish an
        expired, replaceable review request from a request whose confirmed
        receipt must remain replayable after a crash.  It returns no receipt,
        nonce, operation identifier, target scope, or user content.
        """

        validated = DraftDescriptor.model_validate(descriptor)
        request = self._load_request(request_id)
        if descriptor_sha256(validated) != request.descriptor_sha256:
            raise ApprovalMismatch("approved descriptor does not match")
        row = self._connection.execute(
            "SELECT operation_id FROM approval_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None or row[0] is None:
            return False
        try:
            _OBJECT_ID_ADAPTER.validate_python(row[0])
        except ValidationError:
            raise ApprovalUnavailable("approval binding is unavailable") from None
        return True

    def _load_request(self, request_id: str) -> ApprovalRequest:
        row = self._connection.execute(
            """
            SELECT descriptor_sha256, descriptor_json, diff_object_ref_json,
                   created_at, expires_at, nonce_sha256, state, target_scope_hash
              FROM approval_requests
             WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            raise ApprovalUnavailable("approval request is unavailable")
        if row[7] != self._target_scope_hash:
            raise ApprovalUnavailable("approval request is unavailable")
        try:
            descriptor = DraftDescriptor.model_validate_json(row[1])
            diff_object_ref = VersionRef.model_validate_json(row[2])
            return ApprovalRequest(
                request_id=request_id,
                descriptor=descriptor,
                descriptor_sha256=row[0],
                diff_object_ref=diff_object_ref,
                created_at=_parse_utc_text(row[3]),
                expires_at=_parse_utc_text(row[4]),
                nonce_sha256=row[5],
                state=_state_from_db(row[6]),
            )
        except ApprovalError:
            raise
        except (TypeError, ValueError):
            raise ApprovalUnavailable("approval record is unavailable") from None

    def get(self, request_id: str) -> ApprovalRequest:
        return self._load_request(request_id)

    def _load_nonce(self, request_id: str) -> str:
        row = self._connection.execute(
            "SELECT nonce_ciphertext FROM approval_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None or type(row[0]) is not bytes:
            raise ApprovalUnavailable("approval request is unavailable")
        try:
            plaintext = self._protector.unprotect(
                row[0], purpose=_NONCE_PURPOSE, vault_id=self._vault_id
            )
            return plaintext.decode("ascii", errors="strict")
        except Exception:
            raise ApprovalUnavailable("approval request is unavailable") from None

    def _challenge(self, request: ApprovalRequest) -> ApprovalChallenge:
        pending = request.model_copy(update={"state": "pending"})
        return ApprovalChallenge(
            request=pending,
            nonce=self._load_nonce(request.request_id),
        )

    def challenge_for_review(self, request_id: str) -> ApprovalChallenge:
        request = self._load_request(request_id)
        if request.state != "pending":
            raise ApprovalUsed("approval request is no longer pending")
        if self._clock.now() >= request.expires_at:
            raise ApprovalExpired("approval request expired")
        return self._challenge(request)

    def confirm(self, event: ApprovalReceipt) -> ApprovalReceipt:
        receipt = ApprovalReceipt.model_validate(event)
        with transaction(self._connection):
            request = self._load_request(receipt.request_id)
            if request.state != "pending":
                raise ApprovalUsed("approval request is no longer pending")
            if self._clock.now() >= request.expires_at:
                raise ApprovalExpired("approval request expired")
            challenge = self._challenge(request)
            if not self._provider.verify(receipt, challenge):
                raise ApprovalProviderRejected(
                    "approval provider rejected confirmation"
                )
            receipt_bytes = _canonical_model_bytes(receipt)
            protected_receipt = self._protector.protect(
                receipt_bytes,
                purpose=_RECEIPT_PURPOSE,
                vault_id=self._vault_id,
            )
            encoded_receipt = base64.b64encode(protected_receipt).decode("ascii")
            event_hash = hashlib.sha256(receipt_bytes).hexdigest()
            updated = self._connection.execute(
                """
                UPDATE approval_requests
                   SET state = 'CONFIRMED', provider_event_sha256 = ?, confirmed_at = ?
                 WHERE request_id = ? AND state = 'PENDING'
                """,
                (event_hash, _utc_text(receipt.approved_at), receipt.request_id),
            )
            if updated.rowcount != 1:
                raise ApprovalUsed("approval request is no longer pending")
            self._connection.execute(
                """
                INSERT INTO approval_receipts(
                    request_id, receipt_json, operation_id, confirmed_at,
                    acknowledged_at, state
                ) VALUES (?, ?, NULL, ?, NULL, 'ISSUED')
                """,
                (receipt.request_id, encoded_receipt, _utc_text(receipt.approved_at)),
            )
        return receipt

    def _load_receipt(self, request_id: str) -> ApprovalReceipt:
        row = self._connection.execute(
            "SELECT receipt_json FROM approval_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise ApprovalRequired("approval confirmation is required")
        try:
            ciphertext = base64.b64decode(row[0], validate=True)
            plaintext = self._protector.unprotect(
                ciphertext,
                purpose=_RECEIPT_PURPOSE,
                vault_id=self._vault_id,
            )
            return ApprovalReceipt.model_validate_json(plaintext)
        except Exception:
            raise ApprovalUnavailable("approval receipt is unavailable") from None

    def _ticket_payload(
        self,
        *,
        operation_id: str,
        receipt: ApprovalReceipt,
    ) -> bytes:
        payload = {
            "descriptor_sha256": receipt.descriptor_sha256,
            "nonce_sha256": hashlib.sha256(receipt.nonce.encode("ascii")).hexdigest(),
            "operation_id": operation_id,
            "provider_signature": receipt.signature,
            "request_id": receipt.request_id,
            "target_scope_hash": self._target_scope_hash,
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _ticket_signature(self, operation_id: str, receipt: ApprovalReceipt) -> str:
        return hmac.new(
            self._execution_secret,
            self._ticket_payload(operation_id=operation_id, receipt=receipt),
            hashlib.sha256,
        ).hexdigest()

    def _make_ticket(
        self,
        operation_id: str,
        descriptor: DraftDescriptor,
        receipt: ApprovalReceipt,
    ) -> ApprovalExecutionTicket:
        return ApprovalExecutionTicket(
            operation_id=operation_id,
            target_scope_hash=self._target_scope_hash,
            descriptor=descriptor,
            receipt=receipt,
            issuance_signature=self._ticket_signature(operation_id, receipt),
        )

    def issue_for_execution(
        self,
        request_id: str,
        descriptor: DraftDescriptor,
        *,
        operation_id: str,
    ) -> ApprovalExecutionTicket:
        validated = DraftDescriptor.model_validate(descriptor)
        validated_operation_id = _OBJECT_ID_ADAPTER.validate_python(operation_id)
        with transaction(self._connection):
            request = self._load_request(request_id)
            if descriptor_sha256(validated) != request.descriptor_sha256:
                raise ApprovalMismatch("approved descriptor does not match")
            receipt = self._load_receipt(request_id)
            challenge = self._challenge(request)
            if not self._provider.verify(receipt, challenge):
                raise ApprovalProviderRejected("approval receipt verification failed")
            row = self._connection.execute(
                "SELECT operation_id, state FROM approval_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise ApprovalRequired("approval confirmation is required")
            bound_operation = row[0]
            if bound_operation is not None:
                if bound_operation != validated_operation_id:
                    raise ApprovalUsed("approval is already bound to another operation")
                # Reconstructing the same ticket after a crash is safe even after
                # TTL: the target guard only permits an already committed retry.
                return self._make_ticket(validated_operation_id, validated, receipt)
            if self._clock.now() >= receipt.expires_at:
                raise ApprovalExpired("approval receipt expired")
            updated = self._connection.execute(
                """
                UPDATE approval_receipts
                   SET operation_id = ?
                 WHERE request_id = ? AND operation_id IS NULL
                """,
                (validated_operation_id, request_id),
            )
            if updated.rowcount != 1:
                raise ApprovalUsed("approval is already bound")
            self._connection.execute(
                "UPDATE approval_requests SET state = 'ISSUED' WHERE request_id = ?",
                (request_id,),
            )
        return self._make_ticket(validated_operation_id, validated, receipt)

    def bound_operation_id(
        self,
        request_id: str,
        descriptor: DraftDescriptor,
    ) -> str | None:
        """Return the exact durable execution binding for crash recovery.

        This is an internal control-plane lookup.  It validates the descriptor
        before returning an opaque operation ID and never exposes a receipt,
        nonce, body, path, or target-scope value.
        """

        validated = DraftDescriptor.model_validate(descriptor)
        request = self._load_request(request_id)
        if descriptor_sha256(validated) != request.descriptor_sha256:
            raise ApprovalMismatch("approved descriptor does not match")
        row = self._connection.execute(
            """
            SELECT receipt.operation_id, execution.state
              FROM approval_receipts AS receipt
              LEFT JOIN approval_executions AS execution
                ON execution.operation_id = receipt.operation_id
             WHERE receipt.request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if row[0] is None:
            return None
        # Only the narrow crash window after receipt binding and before the
        # target transaction is recoverable here.  Once APPLIED exists, normal
        # domain/catalog recovery owns idempotency and direct executor replay
        # remains a one-shot ApprovalUsed failure.
        if row[1] is not None:
            return None
        try:
            return _OBJECT_ID_ADAPTER.validate_python(row[0])
        except ValidationError:
            raise ApprovalUnavailable("approval binding is unavailable") from None

    def verify_ticket(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        allow_expired: bool,
    ) -> ApprovalReceipt:
        validated_ticket = ApprovalExecutionTicket.model_validate(ticket)
        validated_descriptor = DraftDescriptor.model_validate(descriptor)
        if validated_ticket.target_scope_hash != self._target_scope_hash:
            raise ApprovalMismatch("approval target scope does not match")
        if (
            descriptor_sha256(validated_descriptor)
            != validated_ticket.descriptor_sha256
        ):
            raise ApprovalMismatch("approved descriptor does not match")
        expected_signature = self._ticket_signature(
            validated_ticket.operation_id, validated_ticket.receipt
        )
        if not hmac.compare_digest(
            expected_signature, validated_ticket.issuance_signature
        ):
            raise ApprovalProviderRejected("approval execution ticket is invalid")
        row = self._connection.execute(
            """
            SELECT r.operation_id, q.target_scope_hash, q.descriptor_sha256
              FROM approval_receipts AS r
              JOIN approval_requests AS q ON q.request_id = r.request_id
             WHERE r.request_id = ?
            """,
            (validated_ticket.request_id,),
        ).fetchone()
        if row is None or row != (
            validated_ticket.operation_id,
            self._target_scope_hash,
            validated_ticket.descriptor_sha256,
        ):
            raise ApprovalUnavailable("approval binding is unavailable")
        request = self._load_request(validated_ticket.request_id)
        challenge = self._challenge(request)
        if not self._provider.verify(validated_ticket.receipt, challenge):
            raise ApprovalProviderRejected("approval receipt verification failed")
        if (
            not allow_expired
            and self._clock.now() >= validated_ticket.receipt.expires_at
        ):
            raise ApprovalExpired("approval receipt expired")
        return validated_ticket.receipt

    def acknowledge(self, proof: ApprovalExecutionProof) -> ApprovalExecution:
        if type(proof) is not ApprovalExecutionProof:
            raise ApprovalMismatch("target execution proof is required")
        execution = proof.execution
        if execution.target_scope_hash != self._target_scope_hash:
            raise ApprovalMismatch("approval target scope does not match")
        if not self._execution_proof_verifier.verify(proof):
            raise ApprovalMismatch("target execution proof is invalid")
        now = self._clock.now()
        with transaction(self._connection):
            request = self._load_request(execution.request_id)
            receipt = self._load_receipt(execution.request_id)
            ticket = ApprovalExecutionTicket(
                operation_id=execution.operation_id,
                target_scope_hash=execution.target_scope_hash,
                descriptor=request.descriptor,
                receipt=receipt,
                issuance_signature=proof.issuance_signature,
            )
            self.verify_ticket(
                ticket,
                request.descriptor,
                allow_expired=True,
            )
            expected_nonce_sha256 = hashlib.sha256(
                receipt.nonce.encode("ascii")
            ).hexdigest()
            if not hmac.compare_digest(
                request.descriptor.draft_sha256,
                proof.draft_sha256,
            ) or not hmac.compare_digest(
                expected_nonce_sha256,
                proof.nonce_sha256,
            ):
                raise ApprovalMismatch("target execution proof is invalid")
            row = self._connection.execute(
                """
                SELECT r.operation_id, q.descriptor_sha256, r.state
                  FROM approval_receipts AS r
                  JOIN approval_requests AS q ON q.request_id = r.request_id
                 WHERE r.request_id = ?
                """,
                (execution.request_id,),
            ).fetchone()
            if (
                row is None
                or row[0] != execution.operation_id
                or row[1] != execution.descriptor_sha256
            ):
                raise ApprovalMismatch("approval execution does not match issuance")
            if row[2] != "ACKNOWLEDGED":
                self._connection.execute(
                    """
                    UPDATE approval_receipts
                       SET state = 'ACKNOWLEDGED', acknowledged_at = ?
                     WHERE request_id = ?
                    """,
                    (_utc_text(now), execution.request_id),
                )
                self._connection.execute(
                    "UPDATE approval_requests SET state = 'ACKNOWLEDGED' WHERE request_id = ?",
                    (execution.request_id,),
                )
        return execution.model_copy(update={"state": "acknowledged"})


__all__ = [
    "ApprovalError",
    "ApprovalExpired",
    "ApprovalMismatch",
    "ApprovalProviderRejected",
    "ApprovalRequired",
    "ApprovalService",
    "ApprovalUnavailable",
    "ApprovalUsed",
    "SecretProtector",
]
