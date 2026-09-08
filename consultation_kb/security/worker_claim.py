"""Private, signed approval claims for the scoped worker control pipe.

These contracts deliberately do not participate in ``WorkerRequest`` or
``WorkerResponse``.  A model-facing caller can request a commit, but only the
trusted broker can turn a globally verified approval ticket into this claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import base64
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol, final, runtime_checkable

from pydantic import model_validator

from consultation_kb.archive.case_publisher import (
    CasePublication,
    CasePublishAuthoritySnapshot,
    CasePublishTransfer,
)
from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
    ApprovalRequest,
    descriptor_sha256,
)
from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.manifests import ApprovalExecution, DraftDescriptor
from consultation_kb.storage.outbox import CasePublishOutboxPayload, OutboxRecord
from consultation_kb.security.worker_protocol import (
    CommitClientTombstoneRequest,
    CommitClientTombstoneResponse,
    CommitClientRollbackRequest,
    CommitClientRollbackResponse,
    CommitFactMutationRequest,
    CommitFactMutationResponse,
    CommitPrivateArchiveRequest,
    CommitPrivateArchiveResponse,
    CommitProfileUpdateRequest,
    CommitProfileUpdateResponse,
    RebuildClientDerivativesRequest,
    RebuildClientDerivativesResponse,
    StageSharedCaseOutboxRequest,
    StageSharedCaseOutboxResponse,
    WorkerProtocolError,
)


_CLAIM_DOMAIN: Final = b"consultation-kb-scoped-worker-approved-commit-v1\0"
_RECOVERY_DOMAIN: Final = b"consultation-kb-scoped-worker-applied-recovery-v1\0"
_RECOVERY_NOT_APPLIED_DOMAIN: Final = (
    b"consultation-kb-scoped-worker-not-applied-result-v1\0"
)
_CLAIM_PREFIX: Final = b"CKB-APPROVED-COMMIT-1\0"
_RECOVERY_PREFIX: Final = b"CKB-APPLIED-RECOVERY-1\0"
_RECOVERY_NOT_APPLIED_PREFIX: Final = b"CKB-NOT-APPLIED-RESULT-1\0"
_RESULT_PREFIX: Final = b"CKB-APPROVED-RESULT-1\0"
_REVIEW_READ_PREFIX: Final = b"CKB-REVIEW-DIFF-READ-1\0"
_REVIEW_RESULT_PREFIX: Final = b"CKB-REVIEW-DIFF-RESULT-1\0"
_CASE_PUBLISH_RPC_DOMAIN: Final = b"consultation-kb-case-publish-rpc-v1\0"
_CASE_PUBLISH_RESULT_DOMAIN: Final = b"consultation-kb-case-publish-result-v1\0"
_CASE_PUBLISH_RPC_PREFIX: Final = b"CKB-CASE-PUBLISH-RPC-1\0"
_CASE_PUBLISH_RESULT_PREFIX: Final = b"CKB-CASE-PUBLISH-RESULT-1\0"
MAX_INTERNAL_FRAME_BYTES: Final = 262_144
MAX_CLAIM_TTL: Final = timedelta(seconds=30)


def _canonical_bytes(model: StrictModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


ApprovedCommitRequest = (
    CommitFactMutationRequest
    | CommitPrivateArchiveRequest
    | CommitProfileUpdateRequest
    | StageSharedCaseOutboxRequest
    | CommitClientTombstoneRequest
    | RebuildClientDerivativesRequest
    | CommitClientRollbackRequest
)
ApprovedCommitResponse = (
    CommitFactMutationResponse
    | CommitPrivateArchiveResponse
    | CommitProfileUpdateResponse
    | StageSharedCaseOutboxResponse
    | CommitClientTombstoneResponse
    | RebuildClientDerivativesResponse
    | CommitClientRollbackResponse
)


def approved_commit_request_sha256(request: ApprovedCommitRequest) -> str:
    """Bind an internal probe result to the exact worker request body."""

    return hashlib.sha256(_canonical_bytes(request)).hexdigest()


def _rollback_binding_matches(
    request: CommitClientRollbackRequest,
    *,
    descriptor: DraftDescriptor,
    ticket: ApprovalExecutionTicket,
    target_scope_hash: str,
    approval_request: ApprovalRequest | None,
) -> bool:
    client_fact_bases = tuple(
        value
        for value in request.base_versions
        if value.authority_key == "client_fact"
        and value.scope_sha256 == target_scope_hash
    )
    return (
        request.approval_request_id == ticket.request_id
        and descriptor.purpose == "rollback"
        and descriptor.draft_sha256 == request.plan_sha256
        and descriptor.client_id is not None
        and descriptor.session_id is not None
        and len(client_fact_bases) == 1
        and client_fact_bases[0].version == descriptor.base_version
        and all(
            value.scope_sha256 == target_scope_hash
            for value in request.base_versions
        )
        and approval_request is not None
        and approval_request.request_id == ticket.request_id
        and approval_request.descriptor == descriptor
        and approval_request.diff_object_ref == request.plan_ref.version_ref
    )


class CasePublishRpcPayload(StrictModel):
    """Body-free command sent only over the broker-authenticated private pipe."""

    internal_type: Literal["case_publish_rpc"] = "case_publish_rpc"
    rpc_id: ObjectId
    action: Literal["EXPORT", "AUTHORITY", "ACK"]
    issued_at: UtcDateTime
    expires_at: UtcDateTime
    event_id: ObjectId | None = None
    payload: CasePublishOutboxPayload | None = None
    publication: CasePublication | None = None
    as_of: UtcDateTime | None = None

    @model_validator(mode="after")
    def _exact_shape(self) -> "CasePublishRpcPayload":
        if (
            not self.issued_at < self.expires_at
            or self.expires_at - self.issued_at > MAX_CLAIM_TTL
        ):
            raise ValueError("case publish RPC expiry is invalid")
        if self.action == "EXPORT":
            valid = (
                self.payload is None
                and self.publication is None
                and self.as_of is None
            )
        elif self.action == "AUTHORITY":
            valid = (
                self.event_id is None
                and self.payload is not None
                and self.publication is None
                and self.as_of is not None
            )
        else:
            valid = (
                self.event_id is not None
                and self.payload is None
                and self.publication is not None
                and self.as_of is None
                and self.publication.source_event_id == self.event_id
            )
        if not valid:
            raise ValueError("case publish RPC shape is invalid")
        return self


class CasePublishRpcRequest(StrictModel):
    payload: CasePublishRpcPayload
    signature: Sha256Hex


class CasePublishRpcResultPayload(StrictModel):
    """Sealed result; transfer bodies exist only for the EXPORT response."""

    internal_type: Literal["case_publish_result"] = "case_publish_result"
    rpc_id: ObjectId
    action: Literal["EXPORT", "AUTHORITY", "ACK"]
    event: OutboxRecord | None = None
    transfer: CasePublishTransfer | None = None
    authority: CasePublishAuthoritySnapshot | None = None

    @model_validator(mode="after")
    def _exact_shape(self) -> "CasePublishRpcResultPayload":
        if self.action == "EXPORT":
            empty = self.event is None and self.transfer is None and self.authority is None
            complete = (
                self.event is not None
                and self.transfer is not None
                and self.authority is not None
                and self.event.event_id is not None
                and self.event.idempotency_key
                == self.transfer.outbox_payload.idempotency_key
            )
            valid = empty or complete
        elif self.action == "AUTHORITY":
            valid = self.event is None and self.transfer is None
        else:
            valid = (
                self.event is not None
                and self.event.state == "PUBLISHED"
                and self.transfer is None
                and self.authority is None
            )
        if not valid:
            raise ValueError("case publish RPC result shape is invalid")
        return self


class CasePublishRpcResult(StrictModel):
    payload: CasePublishRpcResultPayload
    signature: Sha256Hex


class ApprovedCommitClaimPayload(StrictModel):
    internal_type: Literal["approved_commit"] = "approved_commit"
    claim_id: ObjectId
    claim_nonce: NonEmptyStr
    issued_at: UtcDateTime
    expires_at: UtcDateTime
    target_scope_hash: Sha256Hex
    descriptor_sha256: Sha256Hex
    approval_nonce_sha256: Sha256Hex
    request: ApprovedCommitRequest
    descriptor: DraftDescriptor
    ticket: ApprovalExecutionTicket
    approval_request: ApprovalRequest | None = None

    @model_validator(mode="after")
    def _binding_is_complete(self) -> "ApprovedCommitClaimPayload":
        if not self.issued_at < self.expires_at:
            raise ValueError("internal approval claim expiry is invalid")
        if self.expires_at - self.issued_at > MAX_CLAIM_TTL:
            raise ValueError("internal approval claim TTL is too long")
        if (
            self.issued_at < self.ticket.receipt.approved_at
            or self.expires_at > self.ticket.receipt.expires_at
        ):
            raise ValueError("internal approval claim exceeds approval receipt")
        if self.target_scope_hash != self.ticket.target_scope_hash:
            raise ValueError("internal approval target mismatch")
        if self.descriptor != self.ticket.descriptor:
            raise ValueError("internal approval descriptor mismatch")
        if self.descriptor_sha256 != descriptor_sha256(self.descriptor):
            raise ValueError("internal approval descriptor hash mismatch")
        operation_id = self.request.approval_operation_id
        if operation_id is None or operation_id != self.ticket.operation_id:
            raise ValueError("internal approval operation mismatch")
        request = self.request
        if isinstance(request, CommitFactMutationRequest):
            if (
                request.preview_sha256 != self.descriptor.draft_sha256
                or request.base_commit_version != self.descriptor.base_version
            ):
                raise ValueError("internal fact approval binding mismatch")
        elif isinstance(request, CommitPrivateArchiveRequest):
            if (
                request.approval_request_id != self.ticket.request_id
                or self.descriptor.purpose != "private_archive_publish"
                or self.descriptor.target_id != request.draft_ref.object_id
                or self.descriptor.draft_sha256
                != request.draft_ref.content_sha256
                or self.descriptor.base_version != request.base_version
            ):
                raise ValueError("internal private archive approval mismatch")
        elif isinstance(request, CommitProfileUpdateRequest):
            if (
                request.approval_request_id != self.ticket.request_id
                or self.descriptor.purpose != "profile_update"
                or self.descriptor.base_version < 0
            ):
                raise ValueError("internal profile approval mismatch")
        elif isinstance(request, StageSharedCaseOutboxRequest):
            if (
                request.action != "COMMIT"
                or request.approval_request_id != self.ticket.request_id
                or request.candidate_ref is None
                or request.review_policy_draft_ref is None
                or self.descriptor.purpose != "case_publish"
                or self.descriptor.target_id != request.candidate_ref.object_id
                or self.descriptor.base_version != request.candidate_ref.version
                or self.descriptor.draft_sha256
                != request.review_policy_draft_ref.content_sha256
            ):
                raise ValueError("internal shared case approval mismatch")
        elif isinstance(request, CommitClientTombstoneRequest):
            if (
                request.approval_request_id != self.ticket.request_id
                or self.descriptor.purpose != "delete"
                or self.descriptor.draft_sha256 != request.plan_sha256
                or self.descriptor.base_version < 0
                or request.target_scope_hash != self.target_scope_hash
            ):
                raise ValueError("internal client deletion approval mismatch")
        elif isinstance(request, RebuildClientDerivativesRequest):
            bases = tuple(
                value
                for value in request.base_versions
                if value.authority_key == "tombstone_epoch"
                and value.scope_sha256 == self.target_scope_hash
            )
            if request.action == "START":
                valid = (
                    request.approval_request_id == self.ticket.request_id
                    and request.purpose == "all"
                    and request.plan_sha256 == self.descriptor.draft_sha256
                    and self.descriptor.purpose == "rebuild"
                    and self.descriptor.target_id
                    == f"client_rebuild:{request.purpose}"
                    and len(request.base_versions) == 1
                    and len(bases) == 1
                    and bases[0].version == self.descriptor.base_version
                )
            elif request.action == "CANCEL":
                valid = (
                    request.approval_request_id == self.ticket.request_id
                    and request.job_id is not None
                    and request.plan_sha256 == self.descriptor.draft_sha256
                    and self.descriptor.purpose == "rebuild"
                    and self.descriptor.target_id
                    == f"client_rebuild_cancel:{request.job_id}"
                    and len(request.base_versions) == 1
                    and len(bases) == 1
                    and bases[0].version == self.descriptor.base_version
                )
            else:
                valid = False
            if not valid:
                raise ValueError("internal client rebuild approval mismatch")
        elif isinstance(request, CommitClientRollbackRequest):
            if not _rollback_binding_matches(
                request,
                descriptor=self.descriptor,
                ticket=self.ticket,
                target_scope_hash=self.target_scope_hash,
                approval_request=self.approval_request,
            ):
                raise ValueError("internal client rollback approval mismatch")
        else:  # pragma: no cover - closed union
            raise ValueError("unsupported internal approval request")
        if (
            not isinstance(request, CommitClientRollbackRequest)
            and self.approval_request is not None
        ):
            raise ValueError("unexpected internal approval request body")
        expected_nonce = hashlib.sha256(
            self.ticket.receipt.nonce.encode("ascii", errors="strict")
        ).hexdigest()
        if not hmac.compare_digest(expected_nonce, self.approval_nonce_sha256):
            raise ValueError("internal approval nonce mismatch")
        return self


class ApprovedCommitClaim(StrictModel):
    payload: ApprovedCommitClaimPayload
    claim_signature: Sha256Hex


class AppliedCommitRecoveryPayload(StrictModel):
    # Kept at v1 for wire compatibility.  The sealed recovery channel now
    # covers every approved client-scoped commit, not only fact mutations.
    internal_type: Literal["recover_applied_fact_commit"] = (
        "recover_applied_fact_commit"
    )
    claim_id: ObjectId
    claim_nonce: NonEmptyStr
    issued_at: UtcDateTime
    expires_at: UtcDateTime
    target_scope_hash: Sha256Hex
    descriptor_sha256: Sha256Hex
    approval_nonce_sha256: Sha256Hex
    request: ApprovedCommitRequest
    descriptor: DraftDescriptor
    ticket: ApprovalExecutionTicket
    approval_request: ApprovalRequest | None = None

    @model_validator(mode="after")
    def _binding_is_complete(self) -> "AppliedCommitRecoveryPayload":
        if (
            not self.issued_at < self.expires_at
            or self.expires_at - self.issued_at > MAX_CLAIM_TTL
            or self.issued_at < self.ticket.receipt.approved_at
            or self.target_scope_hash != self.ticket.target_scope_hash
            or self.descriptor != self.ticket.descriptor
            or self.descriptor_sha256 != descriptor_sha256(self.descriptor)
            or self.request.approval_operation_id != self.ticket.operation_id
        ):
            raise ValueError("applied recovery binding mismatch")
        request = self.request
        if isinstance(request, CommitFactMutationRequest):
            valid = (
                request.preview_sha256 == self.descriptor.draft_sha256
                and request.base_commit_version == self.descriptor.base_version
            )
        elif isinstance(request, CommitPrivateArchiveRequest):
            valid = (
                request.approval_request_id == self.ticket.request_id
                and self.descriptor.purpose == "private_archive_publish"
                and self.descriptor.target_id == request.draft_ref.object_id
                and self.descriptor.draft_sha256
                == request.draft_ref.content_sha256
                and self.descriptor.base_version == request.base_version
            )
        elif isinstance(request, CommitProfileUpdateRequest):
            valid = (
                request.approval_request_id == self.ticket.request_id
                and self.descriptor.purpose == "profile_update"
                and self.descriptor.base_version >= 0
            )
        elif isinstance(request, StageSharedCaseOutboxRequest):
            valid = (
                request.action == "COMMIT"
                and request.approval_request_id == self.ticket.request_id
                and request.candidate_ref is not None
                and request.review_policy_draft_ref is not None
                and self.descriptor.purpose == "case_publish"
                and self.descriptor.target_id == request.candidate_ref.object_id
                and self.descriptor.base_version == request.candidate_ref.version
                and self.descriptor.draft_sha256
                == request.review_policy_draft_ref.content_sha256
            )
        elif isinstance(request, CommitClientTombstoneRequest):
            valid = (
                request.approval_request_id == self.ticket.request_id
                and self.descriptor.purpose == "delete"
                and self.descriptor.draft_sha256 == request.plan_sha256
                and self.descriptor.base_version >= 0
                and request.target_scope_hash == self.target_scope_hash
            )
        elif isinstance(request, RebuildClientDerivativesRequest):
            bases = tuple(
                value
                for value in request.base_versions
                if value.authority_key == "tombstone_epoch"
                and value.scope_sha256 == self.target_scope_hash
            )
            if request.action == "START":
                valid = (
                    request.approval_request_id == self.ticket.request_id
                    and request.purpose == "all"
                    and request.plan_sha256 == self.descriptor.draft_sha256
                    and self.descriptor.purpose == "rebuild"
                    and self.descriptor.target_id
                    == f"client_rebuild:{request.purpose}"
                    and len(request.base_versions) == 1
                    and len(bases) == 1
                    and bases[0].version == self.descriptor.base_version
                )
            elif request.action == "CANCEL":
                valid = (
                    request.approval_request_id == self.ticket.request_id
                    and request.job_id is not None
                    and request.plan_sha256 == self.descriptor.draft_sha256
                    and self.descriptor.purpose == "rebuild"
                    and self.descriptor.target_id
                    == f"client_rebuild_cancel:{request.job_id}"
                    and len(request.base_versions) == 1
                    and len(bases) == 1
                    and bases[0].version == self.descriptor.base_version
                )
            else:
                valid = False
        elif isinstance(request, CommitClientRollbackRequest):
            valid = _rollback_binding_matches(
                request,
                descriptor=self.descriptor,
                ticket=self.ticket,
                target_scope_hash=self.target_scope_hash,
                approval_request=self.approval_request,
            )
        else:  # pragma: no cover - closed union
            valid = False
        if not valid or (
            not isinstance(request, CommitClientRollbackRequest)
            and self.approval_request is not None
        ):
            raise ValueError("applied recovery request binding mismatch")
        expected_nonce = hashlib.sha256(
            self.ticket.receipt.nonce.encode("ascii", errors="strict")
        ).hexdigest()
        if not hmac.compare_digest(expected_nonce, self.approval_nonce_sha256):
            raise ValueError("applied recovery nonce mismatch")
        return self


class AppliedCommitRecoveryClaim(StrictModel):
    payload: AppliedCommitRecoveryPayload
    claim_signature: Sha256Hex


class AppliedCommitNotAppliedPayload(StrictModel):
    """Exact target absence returned only on the sealed recovery channel."""

    internal_type: Literal["approved_commit_not_applied"] = (
        "approved_commit_not_applied"
    )
    state: Literal["NOT_APPLIED"] = "NOT_APPLIED"
    claim_id: ObjectId
    claim_nonce_sha256: Sha256Hex
    worker_request_id: Uuid7String
    request_sha256: Sha256Hex
    approval_request_id: ObjectId
    operation_id: ObjectId
    descriptor_sha256: Sha256Hex
    draft_sha256: Sha256Hex
    descriptor_base_version: NonNegativeInt
    target_scope_hash: Sha256Hex
    approval_nonce_sha256: Sha256Hex


class AppliedCommitNotAppliedResult(StrictModel):
    payload: AppliedCommitNotAppliedPayload
    signature: Sha256Hex


class ApprovedCommitResult(StrictModel):
    internal_type: Literal["approved_commit_result"] = "approved_commit_result"
    response: ApprovedCommitResponse
    execution: ApprovalExecution
    attestor_id: NonEmptyStr
    draft_sha256: Sha256Hex
    nonce_sha256: Sha256Hex
    issuance_signature: Sha256Hex
    proof_signature: Sha256Hex

    @model_validator(mode="after")
    def _result_is_bound(self) -> "ApprovedCommitResult":
        if self.execution.state != "applied":
            raise ValueError("internal result requires applied execution")
        response_operation_id = self.response.approval_operation_id
        if response_operation_id is None or (
            self.execution.operation_id != response_operation_id
        ):
            raise ValueError("internal result operation mismatch")
        response_commit_version: int | None
        if isinstance(
            self.response,
            (CommitFactMutationResponse, CommitProfileUpdateResponse),
        ):
            response_commit_version = self.response.new_commit_version
        elif isinstance(
            self.response,
            (CommitPrivateArchiveResponse, StageSharedCaseOutboxResponse),
        ):
            response_commit_version = self.response.applied_commit_version
        elif isinstance(self.response, CommitClientTombstoneResponse):
            response_commit_version = self.response.deletion_version
        elif isinstance(self.response, RebuildClientDerivativesResponse):
            response_commit_version = self.response.applied_commit_version
        elif isinstance(self.response, CommitClientRollbackResponse):
            response_commit_version = self.response.applied_commit_version
        else:  # pragma: no cover - closed union
            response_commit_version = None
        if (
            response_commit_version is None
            or self.execution.applied_commit_version != response_commit_version
        ):
            raise ValueError("internal result commit mismatch")
        return self

    def proof(self) -> ApprovalExecutionProof:
        return ApprovalExecutionProof(
            execution=self.execution,
            attestor_id=self.attestor_id,
            draft_sha256=self.draft_sha256,
            nonce_sha256=self.nonce_sha256,
            issuance_signature=self.issuance_signature,
            signature=self.proof_signature,
        )


class ReviewDiffReadRequest(StrictModel):
    internal_type: Literal["read_review_diff"] = "read_review_diff"
    reference: VersionRef


class ReviewDiffReadResult(StrictModel):
    internal_type: Literal["review_diff_result"] = "review_diff_result"
    reference: VersionRef
    content_base64: NonEmptyStr

    def content(self) -> bytes:
        try:
            content = base64.b64decode(
                self.content_base64.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (UnicodeError, ValueError):
            raise WorkerProtocolError from None
        if hashlib.sha256(content).hexdigest() != self.reference.content_sha256:
            raise WorkerProtocolError
        return content


@runtime_checkable
class ApprovedCommitClaimSigner(Protocol):
    def sign(self, payload: ApprovedCommitClaimPayload) -> ApprovedCommitClaim: ...


@runtime_checkable
class ApprovedCommitClaimVerifier(Protocol):
    def verify(
        self,
        claim: ApprovedCommitClaim,
        *,
        now: datetime,
    ) -> ApprovedCommitClaimPayload: ...


def _secret(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise ValueError("internal claim secret must contain at least 256 bits")
    return bytes(value)


@final
class LocalHmacApprovedCommitClaimSigner:
    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def sign(self, payload: ApprovedCommitClaimPayload) -> ApprovedCommitClaim:
        validated = ApprovedCommitClaimPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _CLAIM_DOMAIN + _canonical_bytes(validated),
            hashlib.sha256,
        ).hexdigest()
        return ApprovedCommitClaim(payload=validated, claim_signature=signature)


@final
class LocalHmacApprovedCommitClaimVerifier:
    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def verify(
        self,
        claim: ApprovedCommitClaim,
        *,
        now: datetime,
    ) -> ApprovedCommitClaimPayload:
        validated = ApprovedCommitClaim.model_validate(claim)
        expected = hmac.new(
            self._secret,
            _CLAIM_DOMAIN + _canonical_bytes(validated.payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, validated.claim_signature):
            raise WorkerProtocolError
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise WorkerProtocolError
        if not validated.payload.issued_at <= now < validated.payload.expires_at:
            raise WorkerProtocolError
        return validated.payload


@final
class LocalHmacAppliedCommitRecoverySigner:
    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def sign(
        self,
        payload: AppliedCommitRecoveryPayload,
    ) -> AppliedCommitRecoveryClaim:
        validated = AppliedCommitRecoveryPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _RECOVERY_DOMAIN + _canonical_bytes(validated),
            hashlib.sha256,
        ).hexdigest()
        return AppliedCommitRecoveryClaim(
            payload=validated,
            claim_signature=signature,
        )


@final
class LocalHmacAppliedCommitRecoveryVerifier:
    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def verify(
        self,
        claim: AppliedCommitRecoveryClaim,
        *,
        now: datetime,
    ) -> AppliedCommitRecoveryPayload:
        validated = AppliedCommitRecoveryClaim.model_validate(claim)
        expected = hmac.new(
            self._secret,
            _RECOVERY_DOMAIN + _canonical_bytes(validated.payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, validated.claim_signature):
            raise WorkerProtocolError
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise WorkerProtocolError
        if not validated.payload.issued_at <= now < validated.payload.expires_at:
            raise WorkerProtocolError
        return validated.payload


@final
class LocalHmacAppliedCommitNotAppliedResult:
    """Authenticate a target-scoped exact-NOT_APPLIED probe response."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def sign(
        self,
        payload: AppliedCommitNotAppliedPayload,
    ) -> AppliedCommitNotAppliedResult:
        validated = AppliedCommitNotAppliedPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _RECOVERY_NOT_APPLIED_DOMAIN + _canonical_bytes(validated),
            hashlib.sha256,
        ).hexdigest()
        return AppliedCommitNotAppliedResult(
            payload=validated,
            signature=signature,
        )

    def verify(
        self,
        result: AppliedCommitNotAppliedResult,
    ) -> AppliedCommitNotAppliedPayload:
        validated = AppliedCommitNotAppliedResult.model_validate(result)
        expected = hmac.new(
            self._secret,
            _RECOVERY_NOT_APPLIED_DOMAIN + _canonical_bytes(validated.payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, validated.signature):
            raise WorkerProtocolError
        return validated.payload


@final
class LocalHmacCasePublishRpc:
    """Seal both directions of the internal shared-case publication RPC."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = _secret(secret)

    def sign_request(self, payload: CasePublishRpcPayload) -> CasePublishRpcRequest:
        validated = CasePublishRpcPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _CASE_PUBLISH_RPC_DOMAIN + _canonical_bytes(validated),
            hashlib.sha256,
        ).hexdigest()
        return CasePublishRpcRequest(payload=validated, signature=signature)

    def verify_request(
        self,
        request: CasePublishRpcRequest,
        *,
        now: datetime,
    ) -> CasePublishRpcPayload:
        validated = CasePublishRpcRequest.model_validate(request)
        expected = hmac.new(
            self._secret,
            _CASE_PUBLISH_RPC_DOMAIN + _canonical_bytes(validated.payload),
            hashlib.sha256,
        ).hexdigest()
        if (
            not hmac.compare_digest(expected, validated.signature)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
            or not validated.payload.issued_at <= now < validated.payload.expires_at
        ):
            raise WorkerProtocolError
        return validated.payload

    def sign_result(
        self,
        payload: CasePublishRpcResultPayload,
    ) -> CasePublishRpcResult:
        validated = CasePublishRpcResultPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _CASE_PUBLISH_RESULT_DOMAIN + _canonical_bytes(validated),
            hashlib.sha256,
        ).hexdigest()
        return CasePublishRpcResult(payload=validated, signature=signature)

    def verify_result(self, result: CasePublishRpcResult) -> CasePublishRpcResultPayload:
        validated = CasePublishRpcResult.model_validate(result)
        expected = hmac.new(
            self._secret,
            _CASE_PUBLISH_RESULT_DOMAIN + _canonical_bytes(validated.payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, validated.signature):
            raise WorkerProtocolError
        return validated.payload


def _encode(prefix: bytes, model: StrictModel) -> bytes:
    encoded = prefix + _canonical_bytes(model)
    if len(encoded) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    return encoded


def encode_case_publish_rpc(request: CasePublishRpcRequest) -> bytes:
    return _encode(
        _CASE_PUBLISH_RPC_PREFIX,
        CasePublishRpcRequest.model_validate(request),
    )


def decode_case_publish_rpc(frame: bytes) -> CasePublishRpcRequest:
    if type(frame) is not bytes or not frame.startswith(_CASE_PUBLISH_RPC_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_CASE_PUBLISH_RPC_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        request = CasePublishRpcRequest.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_case_publish_rpc(request) != frame:
        raise WorkerProtocolError
    return request


def is_case_publish_rpc_frame(frame: bytes) -> bool:
    return type(frame) is bytes and frame.startswith(_CASE_PUBLISH_RPC_PREFIX)


def encode_case_publish_result(result: CasePublishRpcResult) -> bytes:
    return _encode(
        _CASE_PUBLISH_RESULT_PREFIX,
        CasePublishRpcResult.model_validate(result),
    )


def decode_case_publish_result(frame: bytes) -> CasePublishRpcResult:
    if type(frame) is not bytes or not frame.startswith(_CASE_PUBLISH_RESULT_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_CASE_PUBLISH_RESULT_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        result = CasePublishRpcResult.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_case_publish_result(result) != frame:
        raise WorkerProtocolError
    return result


def encode_approved_commit_claim(claim: ApprovedCommitClaim) -> bytes:
    return _encode(_CLAIM_PREFIX, ApprovedCommitClaim.model_validate(claim))


def decode_approved_commit_claim(frame: bytes) -> ApprovedCommitClaim:
    if type(frame) is not bytes or not frame.startswith(_CLAIM_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_CLAIM_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        claim = ApprovedCommitClaim.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_approved_commit_claim(claim) != frame:
        raise WorkerProtocolError
    return claim


def is_approved_commit_claim_frame(frame: bytes) -> bool:
    return type(frame) is bytes and frame.startswith(_CLAIM_PREFIX)


def encode_applied_recovery_claim(claim: AppliedCommitRecoveryClaim) -> bytes:
    return _encode(
        _RECOVERY_PREFIX,
        AppliedCommitRecoveryClaim.model_validate(claim),
    )


def decode_applied_recovery_claim(frame: bytes) -> AppliedCommitRecoveryClaim:
    if type(frame) is not bytes or not frame.startswith(_RECOVERY_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_RECOVERY_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        claim = AppliedCommitRecoveryClaim.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_applied_recovery_claim(claim) != frame:
        raise WorkerProtocolError
    return claim


def is_applied_recovery_claim_frame(frame: bytes) -> bool:
    return type(frame) is bytes and frame.startswith(_RECOVERY_PREFIX)


def encode_applied_not_applied_result(
    result: AppliedCommitNotAppliedResult,
) -> bytes:
    return _encode(
        _RECOVERY_NOT_APPLIED_PREFIX,
        AppliedCommitNotAppliedResult.model_validate(result),
    )


def decode_applied_not_applied_result(
    frame: bytes,
) -> AppliedCommitNotAppliedResult:
    if type(frame) is not bytes or not frame.startswith(
        _RECOVERY_NOT_APPLIED_PREFIX
    ):
        raise WorkerProtocolError
    body = frame[len(_RECOVERY_NOT_APPLIED_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        result = AppliedCommitNotAppliedResult.model_validate_json(
            body,
            strict=True,
        )
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_applied_not_applied_result(result) != frame:
        raise WorkerProtocolError
    return result


def is_applied_not_applied_result_frame(frame: bytes) -> bool:
    return type(frame) is bytes and frame.startswith(
        _RECOVERY_NOT_APPLIED_PREFIX
    )


def encode_approved_commit_result(result: ApprovedCommitResult) -> bytes:
    return _encode(_RESULT_PREFIX, ApprovedCommitResult.model_validate(result))


def decode_approved_commit_result(frame: bytes) -> ApprovedCommitResult:
    if type(frame) is not bytes or not frame.startswith(_RESULT_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_RESULT_PREFIX) :]
    if not body or len(frame) > MAX_INTERNAL_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        result = ApprovedCommitResult.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_approved_commit_result(result) != frame:
        raise WorkerProtocolError
    return result


def encode_review_diff_read(request: ReviewDiffReadRequest) -> bytes:
    return _encode(_REVIEW_READ_PREFIX, ReviewDiffReadRequest.model_validate(request))


def decode_review_diff_read(frame: bytes) -> ReviewDiffReadRequest:
    if type(frame) is not bytes or not frame.startswith(_REVIEW_READ_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_REVIEW_READ_PREFIX) :]
    try:
        request = ReviewDiffReadRequest.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_review_diff_read(request) != frame:
        raise WorkerProtocolError
    return request


def is_review_diff_read_frame(frame: bytes) -> bool:
    return type(frame) is bytes and frame.startswith(_REVIEW_READ_PREFIX)


def encode_review_diff_result(
    reference: VersionRef,
    content: bytes,
) -> bytes:
    if type(content) is not bytes or hashlib.sha256(content).hexdigest() != (
        reference.content_sha256
    ):
        raise WorkerProtocolError
    result = ReviewDiffReadResult(
        reference=reference,
        content_base64=base64.b64encode(content, altchars=b"-_").decode("ascii"),
    )
    return _encode(_REVIEW_RESULT_PREFIX, result)


def decode_review_diff_result(frame: bytes) -> ReviewDiffReadResult:
    if type(frame) is not bytes or not frame.startswith(_REVIEW_RESULT_PREFIX):
        raise WorkerProtocolError
    body = frame[len(_REVIEW_RESULT_PREFIX) :]
    try:
        result = ReviewDiffReadResult.model_validate_json(body, strict=True)
    except (TypeError, ValueError):
        raise WorkerProtocolError from None
    if _encode(_REVIEW_RESULT_PREFIX, result) != frame:
        raise WorkerProtocolError
    result.content()
    return result


__all__ = [
    "ApprovedCommitRequest",
    "ApprovedCommitResponse",
    "ApprovedCommitClaim",
    "ApprovedCommitClaimPayload",
    "ApprovedCommitClaimSigner",
    "ApprovedCommitClaimVerifier",
    "ApprovedCommitResult",
    "AppliedCommitNotAppliedPayload",
    "AppliedCommitNotAppliedResult",
    "AppliedCommitRecoveryClaim",
    "AppliedCommitRecoveryPayload",
    "CasePublishRpcPayload",
    "CasePublishRpcRequest",
    "CasePublishRpcResult",
    "CasePublishRpcResultPayload",
    "LocalHmacApprovedCommitClaimSigner",
    "LocalHmacApprovedCommitClaimVerifier",
    "LocalHmacAppliedCommitRecoverySigner",
    "LocalHmacAppliedCommitRecoveryVerifier",
    "LocalHmacAppliedCommitNotAppliedResult",
    "LocalHmacCasePublishRpc",
    "MAX_CLAIM_TTL",
    "MAX_INTERNAL_FRAME_BYTES",
    "decode_approved_commit_claim",
    "decode_approved_commit_result",
    "decode_applied_not_applied_result",
    "decode_applied_recovery_claim",
    "decode_case_publish_result",
    "decode_case_publish_rpc",
    "decode_review_diff_read",
    "decode_review_diff_result",
    "encode_approved_commit_claim",
    "encode_approved_commit_result",
    "encode_applied_not_applied_result",
    "encode_applied_recovery_claim",
    "encode_case_publish_result",
    "encode_case_publish_rpc",
    "encode_review_diff_read",
    "encode_review_diff_result",
    "is_approved_commit_claim_frame",
    "is_applied_not_applied_result_frame",
    "is_applied_recovery_claim_frame",
    "is_case_publish_rpc_frame",
    "is_review_diff_read_frame",
    "ReviewDiffReadRequest",
    "ReviewDiffReadResult",
    "approved_commit_request_sha256",
]
