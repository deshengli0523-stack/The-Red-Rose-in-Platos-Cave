"""Signed, portable proof for one ACTIVE global shared-case publication."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Protocol, final, runtime_checkable

from pydantic import model_validator

from consultation_kb.models.common import (
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    VersionRef,
)


_PROOF_DOMAIN = b"consultation-kb-global-case-publication-proof-v1\0"
_ATTESTOR_ID_RE = re.compile(r"[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*\Z")


def _attestor_id(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or _ATTESTOR_ID_RE.fullmatch(value) is None
    ):
        raise ValueError("case publication proof attestor ID is invalid")
    return value


def _secret(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise ValueError("case publication proof secret must contain 256 bits")
    return bytes(value)


class CasePublicationProofPayload(StrictModel):
    """Exact source approval plus independently derived global closure."""

    schema_version: str = "case_publication_proof.v1"
    source_event_id: ObjectId
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    approval_descriptor_sha256: Sha256Hex
    approval_draft_sha256: Sha256Hex
    approval_descriptor_base_version: NonNegativeInt
    approval_applied_commit_version: PositiveInt
    approval_target_scope_hash: Sha256Hex
    global_publication_operation_id: ObjectId
    publication_closure_sha256: Sha256Hex
    case_ref: VersionRef
    manifest_id: ObjectId
    provenance_ref: VersionRef
    published_global_version: PositiveInt
    authority_epoch: NonNegativeInt
    state: str = "ACTIVE"

    @model_validator(mode="after")
    def _exact_shape(self) -> "CasePublicationProofPayload":
        if (
            self.schema_version != "case_publication_proof.v1"
            or self.state != "ACTIVE"
            or self.published_global_version != self.case_ref.version
        ):
            raise ValueError("case publication proof payload is malformed")
        return self


class CasePublicationProof(StrictModel):
    payload: CasePublicationProofPayload
    attestor_id: str
    signature: Sha256Hex


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _signed_payload(*, attestor_id: str, payload: CasePublicationProofPayload) -> bytes:
    return _PROOF_DOMAIN + _canonical_json(
        {
            "attestor_id": _attestor_id(attestor_id),
            "payload": payload.model_dump(mode="json"),
        }
    )


def case_publication_proof_bytes(value: CasePublicationProof) -> bytes:
    exact = CasePublicationProof.model_validate(value)
    return _canonical_json(exact.model_dump(mode="json"))


def case_publication_proof_sha256(value: CasePublicationProof) -> str:
    return hashlib.sha256(case_publication_proof_bytes(value)).hexdigest()


@runtime_checkable
class CasePublicationProofSigner(Protocol):
    @property
    def attestor_id(self) -> str: ...

    def sign(self, payload: CasePublicationProofPayload) -> CasePublicationProof: ...


@runtime_checkable
class CasePublicationProofVerifier(Protocol):
    @property
    def attestor_id(self) -> str: ...

    def verify(self, proof: CasePublicationProof) -> bool: ...


@final
class LocalHmacCasePublicationProofSigner:
    __slots__ = ("_attestor_id", "_secret")

    def __init__(self, *, secret: bytes, attestor_id: str) -> None:
        self._secret = _secret(secret)
        self._attestor_id = _attestor_id(attestor_id)

    @property
    def attestor_id(self) -> str:
        return self._attestor_id

    def sign(self, payload: CasePublicationProofPayload) -> CasePublicationProof:
        exact = CasePublicationProofPayload.model_validate(payload)
        signature = hmac.new(
            self._secret,
            _signed_payload(attestor_id=self._attestor_id, payload=exact),
            hashlib.sha256,
        ).hexdigest()
        return CasePublicationProof(
            payload=exact,
            attestor_id=self._attestor_id,
            signature=signature,
        )


@final
class LocalHmacCasePublicationProofVerifier:
    __slots__ = ("_attestor_id", "_secret")

    def __init__(self, *, secret: bytes, attestor_id: str) -> None:
        self._secret = _secret(secret)
        self._attestor_id = _attestor_id(attestor_id)

    @property
    def attestor_id(self) -> str:
        return self._attestor_id

    def verify(self, proof: CasePublicationProof) -> bool:
        if type(proof) is not CasePublicationProof:
            return False
        try:
            exact = CasePublicationProof.model_validate(proof)
            signed = _signed_payload(
                attestor_id=exact.attestor_id,
                payload=exact.payload,
            )
        except (TypeError, ValueError):
            return False
        if exact.attestor_id != self._attestor_id:
            return False
        expected = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, exact.signature)


__all__ = [
    "CasePublicationProof",
    "CasePublicationProofPayload",
    "CasePublicationProofSigner",
    "CasePublicationProofVerifier",
    "LocalHmacCasePublicationProofSigner",
    "LocalHmacCasePublicationProofVerifier",
    "case_publication_proof_bytes",
    "case_publication_proof_sha256",
]
