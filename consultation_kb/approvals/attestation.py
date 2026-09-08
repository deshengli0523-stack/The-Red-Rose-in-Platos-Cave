"""Target-side execution attestations with separated signer/verifier roles."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Protocol, final, runtime_checkable

from consultation_kb.models.manifests import ApprovalExecution

from .models import ApprovalExecutionProof


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ATTESTOR_ID_RE = re.compile(r"[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*\Z")
_PROOF_DOMAIN = b"consultation-kb-target-execution-attestation-v1\0"


def _attestor_id(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or _ATTESTOR_ID_RE.fullmatch(value) is None
    ):
        raise ValueError("target execution attestor ID is invalid")
    return value


def _secret(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise ValueError("target execution attestor secret must contain 256 bits")
    return bytes(value)


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError("target execution attestation hash is invalid")
    return value


def _payload(
    *,
    attestor_id: str,
    execution: ApprovalExecution,
    draft_sha256: str,
    nonce_sha256: str,
    issuance_signature: str,
) -> bytes:
    validated = ApprovalExecution.model_validate(execution)
    if validated.state != "applied":
        raise ValueError("target execution attestation requires APPLIED")
    encoded = json.dumps(
        {
            "applied_commit_version": validated.applied_commit_version,
            "attestor_id": _attestor_id(attestor_id),
            "descriptor_sha256": validated.descriptor_sha256,
            "draft_sha256": _sha256(draft_sha256),
            "issuance_signature": _sha256(issuance_signature),
            "nonce_sha256": _sha256(nonce_sha256),
            "operation_id": validated.operation_id,
            "request_id": validated.request_id,
            "state": "APPLIED",
            "target_scope_hash": validated.target_scope_hash,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return _PROOF_DOMAIN + encoded


@runtime_checkable
class TargetExecutionAttestorSigner(Protocol):
    """Signer capability injected only into the target transaction Guard."""

    @property
    def attestor_id(self) -> str: ...

    def attest(
        self,
        *,
        execution: ApprovalExecution,
        draft_sha256: str,
        nonce_sha256: str,
        issuance_signature: str,
    ) -> ApprovalExecutionProof: ...


@runtime_checkable
class TargetExecutionProofVerifier(Protocol):
    """Verification-only role held by the global approval Service."""

    @property
    def attestor_id(self) -> str: ...

    def verify(self, proof: ApprovalExecutionProof) -> bool: ...


@final
class LocalHmacTargetExecutionAttestor:
    __slots__ = ("_attestor_id", "_secret")

    def __init__(self, *, secret: bytes, attestor_id: str) -> None:
        self._secret = _secret(secret)
        self._attestor_id = _attestor_id(attestor_id)

    @property
    def attestor_id(self) -> str:
        return self._attestor_id

    def attest(
        self,
        *,
        execution: ApprovalExecution,
        draft_sha256: str,
        nonce_sha256: str,
        issuance_signature: str,
    ) -> ApprovalExecutionProof:
        payload = _payload(
            attestor_id=self._attestor_id,
            execution=execution,
            draft_sha256=draft_sha256,
            nonce_sha256=nonce_sha256,
            issuance_signature=issuance_signature,
        )
        signature = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return ApprovalExecutionProof(
            execution=execution,
            attestor_id=self._attestor_id,
            draft_sha256=draft_sha256,
            nonce_sha256=nonce_sha256,
            issuance_signature=issuance_signature,
            signature=signature,
        )


@final
class LocalHmacTargetExecutionProofVerifier:
    __slots__ = ("_attestor_id", "_secret")

    def __init__(self, *, secret: bytes, attestor_id: str) -> None:
        self._secret = _secret(secret)
        self._attestor_id = _attestor_id(attestor_id)

    @property
    def attestor_id(self) -> str:
        return self._attestor_id

    def verify(self, proof: ApprovalExecutionProof) -> bool:
        if type(proof) is not ApprovalExecutionProof:
            return False
        try:
            payload = _payload(
                attestor_id=proof.attestor_id,
                execution=proof.execution,
                draft_sha256=proof.draft_sha256,
                nonce_sha256=proof.nonce_sha256,
                issuance_signature=proof.issuance_signature,
            )
        except (TypeError, ValueError):
            return False
        if proof.attestor_id != self._attestor_id:
            return False
        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, proof.signature)


__all__ = [
    "LocalHmacTargetExecutionAttestor",
    "LocalHmacTargetExecutionProofVerifier",
    "TargetExecutionAttestorSigner",
    "TargetExecutionProofVerifier",
]
