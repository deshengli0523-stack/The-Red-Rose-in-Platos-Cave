from __future__ import annotations

import json

import pytest

from consultation_kb.archive.publication_proof import (
    CasePublicationProof,
    CasePublicationProofPayload,
    LocalHmacCasePublicationProofSigner,
    LocalHmacCasePublicationProofVerifier,
    case_publication_proof_bytes,
    case_publication_proof_sha256,
)
from consultation_kb.models.common import VersionRef


def _oid(kind: str, suffix: int) -> str:
    return f"{kind}_018f0000-0000-7000-8000-{suffix:012x}"


def _payload() -> CasePublicationProofPayload:
    return CasePublicationProofPayload(
        source_event_id=_oid("case_outbox_event", 1),
        approval_operation_id=_oid("case_publish_operation", 2),
        approval_request_id=_oid("case_publish_request", 3),
        approval_descriptor_sha256="1" * 64,
        approval_draft_sha256="2" * 64,
        approval_descriptor_base_version=1,
        approval_applied_commit_version=4,
        approval_target_scope_hash="3" * 64,
        global_publication_operation_id=_oid("global_case_publish", 5),
        publication_closure_sha256="4" * 64,
        case_ref=VersionRef(
            object_id=_oid("case", 6),
            version=1,
            content_sha256="5" * 64,
        ),
        manifest_id=_oid("artifact_manifest", 7),
        provenance_ref=VersionRef(
            object_id=_oid("case_provenance", 8),
            version=1,
            content_sha256="6" * 64,
        ),
        published_global_version=1,
        authority_epoch=4,
    )


def test_case_publication_proof_round_trips_canonically() -> None:
    proof = LocalHmacCasePublicationProofSigner(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    ).sign(_payload())
    decoded = CasePublicationProof.model_validate_json(
        case_publication_proof_bytes(proof),
        strict=True,
    )

    assert decoded == proof
    assert json.loads(case_publication_proof_bytes(proof))[
        "signature"
    ] == proof.signature
    assert len(case_publication_proof_sha256(proof)) == 64
    assert LocalHmacCasePublicationProofVerifier(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    ).verify(proof)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("approval_operation_id", _oid("case_publish_operation", 20)),
        ("approval_applied_commit_version", 5),
        ("approval_target_scope_hash", "7" * 64),
        ("publication_closure_sha256", "8" * 64),
    ),
)
def test_case_publication_proof_rejects_wrong_binding_or_closure(
    field: str,
    value: object,
) -> None:
    signer = LocalHmacCasePublicationProofSigner(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    )
    verifier = LocalHmacCasePublicationProofVerifier(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    )
    proof = signer.sign(_payload())
    tampered = proof.model_copy(
        update={
            "payload": proof.payload.model_copy(update={field: value}),
        }
    )

    assert not verifier.verify(tampered)


def test_case_publication_proof_rejects_invalid_signature_and_attestor() -> None:
    proof = LocalHmacCasePublicationProofSigner(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    ).sign(_payload())

    assert not LocalHmacCasePublicationProofVerifier(
        secret=b"x" * 32,
        attestor_id="global-case-publisher",
    ).verify(proof)
    assert not LocalHmacCasePublicationProofVerifier(
        secret=b"p" * 32,
        attestor_id="other-global-publisher",
    ).verify(proof)
    assert not LocalHmacCasePublicationProofVerifier(
        secret=b"p" * 32,
        attestor_id="global-case-publisher",
    ).verify(proof.model_copy(update={"signature": "0" * 64}))
