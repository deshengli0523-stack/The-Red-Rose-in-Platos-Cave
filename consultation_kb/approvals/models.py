"""Internal approval workflow contracts built on the frozen public models."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal, TypeAlias, final

from pydantic import model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.manifests import (
    ApprovalExecution,
    ApprovalReceipt,
    DraftDescriptor,
)


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ATTESTOR_ID_RE = re.compile(r"[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*\Z")


ApprovalRequestState: TypeAlias = Literal[
    "pending",
    "confirmed",
    "rejected",
    "acknowledged",
]


def canonical_descriptor_bytes(descriptor: DraftDescriptor) -> bytes:
    """Encode a descriptor deterministically without accepting unvalidated input."""

    validated = DraftDescriptor.model_validate(descriptor)
    return json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def descriptor_sha256(descriptor: DraftDescriptor) -> str:
    return hashlib.sha256(canonical_descriptor_bytes(descriptor)).hexdigest()


class ApprovalRequest(StrictModel):
    """Safe review view; the raw nonce and reusable receipt are excluded."""

    request_id: ObjectId
    descriptor: DraftDescriptor
    descriptor_sha256: Sha256Hex
    diff_object_ref: VersionRef
    created_at: UtcDateTime
    expires_at: UtcDateTime
    nonce_sha256: Sha256Hex
    state: ApprovalRequestState = "pending"

    @model_validator(mode="after")
    def _validate_request(self) -> "ApprovalRequest":
        if self.expires_at <= self.created_at:
            raise ValueError("approval request expiry must follow creation")
        if descriptor_sha256(self.descriptor) != self.descriptor_sha256:
            raise ValueError("approval request descriptor hash mismatch")
        return self


class ApprovalChallenge(StrictModel):
    """Provider-only challenge; never serialize this through model-facing tools."""

    request: ApprovalRequest
    nonce: NonEmptyStr

    @model_validator(mode="after")
    def _validate_nonce_hash(self) -> "ApprovalChallenge":
        actual = hashlib.sha256(self.nonce.encode("ascii", errors="strict")).hexdigest()
        if actual != self.request.nonce_sha256:
            raise ValueError("approval challenge nonce mismatch")
        if self.request.state != "pending":
            raise ValueError("approval challenge requires a pending request")
        return self


class ApprovalExecutionTicket(StrictModel):
    """Internal operation binding passed directly to a target execution guard."""

    operation_id: ObjectId
    target_scope_hash: Sha256Hex
    descriptor: DraftDescriptor
    receipt: ApprovalReceipt
    issuance_signature: Sha256Hex

    @model_validator(mode="after")
    def _validate_descriptor(self) -> "ApprovalExecutionTicket":
        actual = descriptor_sha256(self.descriptor)
        if actual != self.receipt.descriptor_sha256:
            raise ValueError("approval ticket descriptor hash mismatch")
        return self

    @property
    def request_id(self) -> str:
        return self.receipt.request_id

    @property
    def descriptor_sha256(self) -> str:
        return self.receipt.descriptor_sha256


@final
class ApprovalExecutionProof:
    """Opaque target-commit attestation; never expose it through Tool schemas."""

    __slots__ = (
        "_draft_sha256",
        "_execution",
        "_attestor_id",
        "_issuance_signature",
        "_nonce_sha256",
        "_signature",
    )
    _draft_sha256: str
    _execution: ApprovalExecution
    _attestor_id: str
    _issuance_signature: str
    _nonce_sha256: str
    _signature: str

    def __init__(
        self,
        *,
        execution: ApprovalExecution,
        attestor_id: str,
        draft_sha256: str,
        nonce_sha256: str,
        issuance_signature: str,
        signature: str,
    ) -> None:
        validated = ApprovalExecution.model_validate(execution)
        if validated.state != "applied":
            raise ValueError("execution proof requires an applied execution")
        values = (
            draft_sha256,
            nonce_sha256,
            issuance_signature,
            signature,
        )
        if any(
            type(value) is not str or _SHA256_RE.fullmatch(value) is None
            for value in values
        ):
            raise ValueError("execution proof hashes must be lowercase SHA-256")
        if (
            type(attestor_id) is not str
            or not 1 <= len(attestor_id) <= 64
            or _ATTESTOR_ID_RE.fullmatch(attestor_id) is None
        ):
            raise ValueError("execution proof attestor ID is invalid")
        object.__setattr__(self, "_execution", validated)
        object.__setattr__(self, "_attestor_id", attestor_id)
        object.__setattr__(self, "_draft_sha256", draft_sha256)
        object.__setattr__(self, "_nonce_sha256", nonce_sha256)
        object.__setattr__(self, "_issuance_signature", issuance_signature)
        object.__setattr__(self, "_signature", signature)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("APPROVAL_EXECUTION_PROOF_FROZEN")

    def __repr__(self) -> str:
        return (
            "ApprovalExecutionProof(operation_id="
            f"{self.operation_id!r}, state={self.state!r}, "
            f"applied_commit_version={self.applied_commit_version!r})"
        )

    def __eq__(self, other: object) -> bool:
        if type(other) is not ApprovalExecutionProof:
            return NotImplemented
        return (
            self._execution == other._execution
            and self._attestor_id == other._attestor_id
            and self._draft_sha256 == other._draft_sha256
            and self._nonce_sha256 == other._nonce_sha256
            and self._issuance_signature == other._issuance_signature
            and self._signature == other._signature
        )

    @property
    def operation_id(self) -> str:
        return self._execution.operation_id

    @property
    def attestor_id(self) -> str:
        return self._attestor_id

    @property
    def execution(self) -> ApprovalExecution:
        return self._execution

    @property
    def draft_sha256(self) -> str:
        return self._draft_sha256

    @property
    def nonce_sha256(self) -> str:
        return self._nonce_sha256

    @property
    def issuance_signature(self) -> str:
        return self._issuance_signature

    @property
    def signature(self) -> str:
        return self._signature

    @property
    def request_id(self) -> str:
        return self._execution.request_id

    @property
    def descriptor_sha256(self) -> str:
        return self._execution.descriptor_sha256

    @property
    def target_scope_hash(self) -> str:
        return self._execution.target_scope_hash

    @property
    def state(self) -> Literal["applied"]:
        return "applied"

    @property
    def applied_commit_version(self) -> int:
        value = self._execution.applied_commit_version
        if value is None:  # Defensive: constructor validation already excludes this.
            raise RuntimeError("APPROVAL_EXECUTION_PROOF_INVALID")
        return value


__all__ = [
    "ApprovalChallenge",
    "ApprovalExecutionTicket",
    "ApprovalRequest",
    "ApprovalRequestState",
    "canonical_descriptor_bytes",
    "descriptor_sha256",
]
