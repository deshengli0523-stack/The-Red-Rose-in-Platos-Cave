from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import QueryGuardrails, QueryPlan, Subquery
from consultation_kb.generation.evidence_registry import (
    GenerationRiskContextBinding,
    GenerationRetrievalMetadata,
    evidence_pack_bytes,
    generation_evidence_context_bytes,
)
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.session import StoredContentRef
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.security import worker_main
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    GenerationClientBinding,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    PrivateGenerationEvidence,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    WorkerProtocolError,
    decode_response,
)
from tests.consultation_kb.retrieval_support import (
    CLIENT_A,
    candidate,
    private_provenance,
)
from tests.consultation_kb.risk_support import deterministic_risk_authority
from consultation_kb.risk.repository import canonical_risk_observation_set_sha256
from tests.consultation_kb.unit.p6_quality_support import NOW, ref, uuid7
from tests.consultation_kb.unit.test_generation_evidence_registry import (
    _evidence_closure,
)


REQUEST_ID = uuid7(12_000)
SESSION_ID = uuid7(12_001)
TURN_ID = uuid7(12_002)
RUN_ID = uuid7(11_002)
FOREIGN_SESSION_ID = uuid7(12_003)
FOREIGN_TURN_ID = uuid7(12_004)
FOREIGN_RUN_ID = uuid7(12_005)
QUERY_PLAN_SHA256 = "a" * 64
RISK_AUTHORITY = deterministic_risk_authority(epoch=3, suffix=912_000)


def _risk_context_binding() -> GenerationRiskContextBinding:
    return GenerationRiskContextBinding(
        turn_id=TURN_ID,
        client_message_sha256="e" * 64,
        authority=RISK_AUTHORITY,
        evaluation_observation_ids=(),
        evaluation_set_sha256=canonical_risk_observation_set_sha256(()),
        evaluation_count=0,
        visible_observation_ids=(),
        visible_set_sha256=canonical_risk_observation_set_sha256(()),
        visible_count=0,
    )


def _binding() -> GenerationClientBinding:
    return GenerationClientBinding(
        client_snapshot_ref=ref("session_context", 12_100),
        client_runtime_epoch=4,
        client_tombstone_count=5,
        temporary_fact_refs=(),
    )


def _c1_input(binding: GenerationClientBinding | None = None) -> C1ApplicabilityInput:
    exact = _binding() if binding is None else binding
    plan = QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=TURN_ID,
            run_id=RUN_ID,
            parent_sha256s=(),
            created_at=NOW,
        ),
        intent="simple_empathic_clarification",
        client_snapshot_ref=exact.client_snapshot_ref,
        global_runtime_epoch=3,
        client_runtime_epoch=exact.client_runtime_epoch,
        tombstone_epoch=exact.client_tombstone_count,
        authorization_epoch=6,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="current_context",
                category="emotion_needs_relationship",
                question="Which current context is bound to this plan?",
                routes=("profile",),
                required_evidence_types=(),
                scope="client_private",
            ),
        ),
        route_omissions=(),
        rationale_summary="Bind one worker-projected client context slice.",
    )
    return C1ApplicabilityInput.bind(
        plan,
        client_snapshot_ref=exact.client_snapshot_ref,
        client_runtime_epoch=exact.client_runtime_epoch,
        client_tombstone_count=exact.client_tombstone_count,
        temporary_fact_refs=exact.temporary_fact_refs,
    )


def _store_request() -> StoreGenerationEvidencePackRequest:
    evidence_pack, run_objects = _evidence_closure()
    return StoreGenerationEvidencePackRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=QUERY_PLAN_SHA256,
        evidence_pack=evidence_pack,
        evidence_context=(),
        run_objects=run_objects,
        retrieval_metadata=GenerationRetrievalMetadata(
            route_candidate_counts={"wiki": 1},
            filtered_candidate_count=1,
            resolved_evidence_count=1,
            selected_evidence_count=1,
        ),
    )


def _store_response() -> StoreGenerationEvidencePackResponse:
    request = _store_request()
    encoded = evidence_pack_bytes(request.evidence_pack)
    digest = hashlib.sha256(encoded).hexdigest()
    context_encoded = generation_evidence_context_bytes(request.evidence_context)
    context_digest = hashlib.sha256(context_encoded).hexdigest()
    return StoreGenerationEvidencePackResponse(
        request_id=request.request_id,
        session_id=request.session_id,
        turn_id=request.turn_id,
        run_id=request.run_id,
        query_plan_sha256=request.query_plan_sha256,
        evidence_pack_ref=StoredContentRef(
            object_id=deterministic_object_id("evidence_pack", digest),
            content_sha256=digest,
            media_type="application/json",
            size_bytes=len(encoded),
        ),
        evidence_pack_sha256=digest,
        evidence_pack=request.evidence_pack,
        evidence_context_ref=StoredContentRef(
            object_id=deterministic_object_id(
                "evidence_context",
                context_digest,
            ),
            content_sha256=context_digest,
            media_type="application/json",
            size_bytes=len(context_encoded),
        ),
        evidence_context_sha256=context_digest,
        evidence_context=request.evidence_context,
        retrieval_metadata=request.retrieval_metadata,
    )


def test_generation_internal_operations_have_least_privilege_permissions() -> None:
    get_request = GetGenerationBindingRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
    )
    prepare_request = PrepareGenerationRetrievalRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=_c1_input().query_plan_sha256,
        risk_authority=RISK_AUTHORITY,
        query_categories=("continuity",),
    )

    assert ScopedWorkerBroker._permission(get_request) == "client_read"
    assert ScopedWorkerBroker._permission(prepare_request) == "client_read"
    assert ScopedWorkerBroker._permission(_store_request()) == "session_append"


def test_get_generation_binding_response_requires_exact_request_scope() -> None:
    request = GetGenerationBindingRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
    )
    response = GetGenerationBindingResponse(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        binding=_binding(),
    )

    assert ScopedWorkerBroker._response_matches(request, response)
    for update in (
        {"request_id": uuid7(12_010)},
        {"session_id": FOREIGN_SESSION_ID},
        {"turn_id": FOREIGN_TURN_ID},
    ):
        assert not ScopedWorkerBroker._response_matches(
            request,
            response.model_copy(update=update),
        )


def test_prepare_generation_retrieval_response_requires_exact_run_scope() -> None:
    c1_input = _c1_input()
    request = PrepareGenerationRetrievalRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=c1_input.query_plan_sha256,
        risk_authority=RISK_AUTHORITY,
        query_categories=("continuity", "current_profile"),
    )
    response = PrepareGenerationRetrievalResponse(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=c1_input.query_plan_sha256,
        binding=_binding(),
        c1_applicability_input=c1_input,
        risk_context_binding=_risk_context_binding(),
        private_evidence=(),
    )

    assert ScopedWorkerBroker._response_matches(request, response)
    for update in (
        {"request_id": uuid7(12_011)},
        {"session_id": FOREIGN_SESSION_ID},
        {"run_id": FOREIGN_RUN_ID},
    ):
        assert not ScopedWorkerBroker._response_matches(
            request,
            response.model_copy(update=update),
        )
    assert not ScopedWorkerBroker._response_matches(
        request,
        response.model_copy(
            update={
                "turn_id": FOREIGN_TURN_ID,
                "risk_context_binding": response.risk_context_binding.model_copy(
                    update={"turn_id": FOREIGN_TURN_ID}
                ),
            }
        ),
    )
    with pytest.raises(ValidationError, match="C1 applicability input binding mismatch"):
        response.model_copy(update={"query_plan_sha256": "f" * 64})
    assert not ScopedWorkerBroker._response_matches(
        request.model_copy(update={"query_plan_sha256": "f" * 64}),
        response,
    )


def test_store_generation_pack_response_requires_exact_plan_and_run_scope() -> None:
    request = _store_request()
    response = _store_response()

    assert ScopedWorkerBroker._response_matches(request, response)
    for update in (
        {"request_id": uuid7(12_012)},
        {"session_id": FOREIGN_SESSION_ID},
        {"turn_id": FOREIGN_TURN_ID},
        {"query_plan_sha256": "b" * 64},
    ):
        assert not ScopedWorkerBroker._response_matches(
            request,
            response.model_copy(update=update),
        )
    with pytest.raises(ValidationError, match="stored EvidencePack .* mismatch"):
        response.model_copy(update={"run_id": FOREIGN_RUN_ID})


def test_store_response_and_decoder_reject_forged_pack_hash_or_reference() -> None:
    response = _store_response()

    with pytest.raises(ValidationError, match="stored EvidencePack hash mismatch"):
        StoreGenerationEvidencePackResponse.model_validate(
            {
                **response.model_dump(mode="python"),
                "evidence_pack_sha256": "f" * 64,
            },
            strict=True,
        )

    wire = response.model_dump(mode="json")
    wire["evidence_pack_ref"]["content_sha256"] = "e" * 64
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        decode_response(
            json.dumps(
                wire,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )


def test_store_request_requires_explicit_exact_evidence_context() -> None:
    payload = _store_request().model_dump(mode="python")
    del payload["evidence_context"]

    with pytest.raises(ValidationError, match="evidence_context"):
        StoreGenerationEvidencePackRequest.model_validate(payload, strict=True)

def test_private_generation_evidence_rejects_body_hash_mismatch() -> None:
    body = "Synthetic private profile body."
    private = candidate(
        12_200,
        provenance=private_provenance(12_200, CLIENT_A),
        channel="profile",
        object_type="profile_section",
        text=body,
    )

    assert PrivateGenerationEvidence(candidate=private, body=body).body == body
    with pytest.raises(ValidationError, match="private generation evidence closure"):
        PrivateGenerationEvidence(candidate=private, body=body + " tampered")


def test_prepare_categories_are_nonempty_unique_and_canonical() -> None:
    base = {
        "request_id": REQUEST_ID,
        "session_id": SESSION_ID,
        "turn_id": TURN_ID,
        "run_id": RUN_ID,
        "query_plan_sha256": _c1_input().query_plan_sha256,
        "risk_authority": RISK_AUTHORITY,
    }
    for categories in (
        (),
        ("continuity", "continuity"),
        ("current_profile", "continuity"),
    ):
        with pytest.raises(ValidationError, match="categories must be canonical"):
            PrepareGenerationRetrievalRequest.model_validate(
                {**base, "query_categories": categories},
                strict=True,
            )


def test_prepare_request_rejects_caller_supplied_c1_applicability() -> None:
    with pytest.raises(ValidationError):
        PrepareGenerationRetrievalRequest.model_validate(
            {
                "request_id": REQUEST_ID,
                "session_id": SESSION_ID,
                "turn_id": TURN_ID,
                "run_id": RUN_ID,
                "query_plan_sha256": _c1_input().query_plan_sha256,
                "query_categories": ("continuity",),
                "c1_applicability_input": _c1_input().model_dump(mode="json"),
            },
            strict=True,
        )


def test_worker_second_line_rejects_foreign_session_for_all_generation_internal_ops() -> None:
    capability_token = "opaque-capability-token"
    bootstrap = worker_main._WorkerBootstrap(
        scope_root="C:\\opaque-client-root",
        global_descriptor_sha256="a" * 64,
        scope_marker_sha256="b" * 64,
        session_id=SESSION_ID,
        capability_token_sha256=hashlib.sha256(
            capability_token.encode("utf-8")
        ).hexdigest(),
    )
    foreign_requests = (
        GetGenerationBindingRequest(
            request_id=REQUEST_ID,
            session_id=FOREIGN_SESSION_ID,
            turn_id=TURN_ID,
        ),
        PrepareGenerationRetrievalRequest(
            request_id=REQUEST_ID,
            session_id=FOREIGN_SESSION_ID,
            turn_id=TURN_ID,
            run_id=RUN_ID,
            query_plan_sha256=_c1_input().query_plan_sha256,
            risk_authority=RISK_AUTHORITY,
            query_categories=("continuity",),
        ),
        _store_request().model_copy(update={"session_id": FOREIGN_SESSION_ID}),
    )

    for request in foreign_requests:
        with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
            worker_main._verify_request_session_binding(request, bootstrap)
