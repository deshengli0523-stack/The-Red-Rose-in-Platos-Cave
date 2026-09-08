from __future__ import annotations

import hashlib
from typing import cast

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    Subquery,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceContextItem,
    GenerationRiskContextBinding,
    GenerationRetrievalMetadata,
    evidence_pack_bytes,
    generation_evidence_context_bytes,
)
from consultation_kb.generation.retrieval_orchestrator import (
    GenerationRetrievalOutcome,
)
from consultation_kb.generation.stage_store import canonical_generation_bytes
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.retrieval_runtime import GenerationGlobalBinding
from consultation_kb.mcp.schemas import (
    GetGenerationStateInput,
    SubmitGenerationStageInput,
)
from consultation_kb.mcp.session_runtime import (
    SessionRuntimeError,
    SessionRuntimeManager,
    _LiveSession,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.models.session import StoredContentRef
from consultation_kb.retrieval.evidence_pack import RootManifestSet
from consultation_kb.risk.repository import canonical_risk_observation_set_sha256
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    BeginSessionResponse,
    GenerationClientBinding,
    GenerationStageWireRecord,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GetGenerationEvidenceForPlanRequest,
    GetGenerationEvidenceForPlanResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    PrepareTurnRiskEvaluationRequest,
    PrepareTurnRiskEvaluationResponse,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
)
from consultation_kb.storage.catalog import ClientCatalog
from tests.consultation_kb.unit.p6_quality_support import NOW, object_id, uuid7
from tests.consultation_kb.risk_support import deterministic_risk_authority
from tests.consultation_kb.unit.test_generation_evidence_registry import (
    _nonempty_evidence_closure,
)


SESSION_ID = uuid7(16_000)
TURN_ID = uuid7(11_001)
FOREIGN_SESSION_ID = uuid7(16_001)
SESSION_HANDLE = "opaque-generation-context-session"
CLIENT_ID = "client_" + "aaaaaaaaaaaa"


def _stored_ref(kind: str, payload: bytes) -> StoredContentRef:
    digest = hashlib.sha256(payload).hexdigest()
    return StoredContentRef(
        object_id=deterministic_object_id(kind, digest),
        content_sha256=digest,
        media_type="application/json",
        size_bytes=len(payload),
    )


def _fixtures() -> tuple[
    QueryPlan,
    GenerationClientBinding,
    GenerationGlobalBinding,
    GenerationRetrievalOutcome,
    tuple[GenerationEvidenceContextItem, ...],
    GenerationStageWireRecord,
]:
    pack, final_context, run_objects = _nonempty_evidence_closure()
    retrieved_context = tuple(
        item
        for item in final_context
        if item.context_kind == "retrieved_candidate"
    )
    binding = GenerationClientBinding(
        client_snapshot_ref=pack.client_snapshot_ref,
        client_runtime_epoch=pack.authority.client_runtime_epoch,
        client_tombstone_count=pack.authority.tombstone_epoch & 0xFFFFFFFF,
        temporary_fact_refs=pack.temporary_fact_refs,
    )
    global_binding = GenerationGlobalBinding(
        global_runtime_epoch=pack.authority.global_runtime_epoch,
        global_tombstone_epoch=pack.authority.tombstone_epoch & ~0xFFFFFFFF,
        authorization_epoch=pack.authority.authorization_epoch,
        authority_policy_ref=pack.authority.policy_ref,
        roots=RootManifestSet(
            catalog_version=1,
            wiki_manifest_ref=pack.wiki_manifest_ref,
            lexical_manifest_ref=pack.lexical_manifest_ref,
            vector_manifest_ref=pack.vector_manifest_ref,
            graph_manifest_ref=pack.graph_manifest_ref,
        ),
        available_routes=("wiki",),
        created_at=pack.authority.created_at,
    )
    plan = QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=TURN_ID,
            run_id=pack.run_id,
            parent_sha256s=(),
            created_at=NOW,
        ),
        intent="simple_empathic_clarification",
        client_snapshot_ref=binding.client_snapshot_ref,
        global_runtime_epoch=global_binding.global_runtime_epoch,
        client_runtime_epoch=binding.client_runtime_epoch,
        tombstone_epoch=(
            global_binding.global_tombstone_epoch
            | binding.client_tombstone_count
        ),
        authorization_epoch=global_binding.authorization_epoch,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="safe_guidance",
                category="emotion_needs_relationship",
                question="What approved guidance applies?",
                routes=("wiki",),
                required_evidence_types=(),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Retrieve one approved source.",
    )
    plan_bytes = canonical_generation_bytes(plan)
    plan_ref = _stored_ref("generation_stage", plan_bytes)
    wire = GenerationStageWireRecord(
        stage_revision_id=object_id("generation_stage_revision", 16_100),
        revision=1,
        stage="query_plan",
        artifact=plan_ref,
        parent_sha256s=plan.envelope.parent_sha256s,
        payload=plan,
        created_at=plan.envelope.created_at,
    )
    metadata = GenerationRetrievalMetadata(
        route_candidate_counts={"wiki": 1},
        filtered_candidate_count=1,
        resolved_evidence_count=1,
        selected_evidence_count=1,
    )
    outcome = GenerationRetrievalOutcome(
        evidence_pack=pack,
        evidence_pack_sha256=hashlib.sha256(evidence_pack_bytes(pack)).hexdigest(),
        evidence_context=retrieved_context,
        run_objects=run_objects,
        metadata=metadata,
    )
    return plan, binding, global_binding, outcome, final_context, wire


class _FakeGenerationRuntime:
    def __init__(
        self,
        binding: GenerationGlobalBinding,
        outcome: GenerationRetrievalOutcome,
        *,
        stale_on_binding_call: int | None = None,
    ) -> None:
        self.binding = binding
        self.outcome = outcome
        self.stale_on_binding_call = stale_on_binding_call
        self.binding_calls = 0
        self.retrieve_calls = 0
        self.c1_inputs: list[C1ApplicabilityInput] = []

    def generation_global_binding(self, *, binding: object) -> GenerationGlobalBinding:
        del binding
        self.binding_calls += 1
        if self.binding_calls == self.stale_on_binding_call:
            return self.binding.model_copy(
                update={"global_runtime_epoch": self.binding.global_runtime_epoch + 1}
            )
        return self.binding

    def retrieve_generation_plan(self, *args: object, **kwargs: object) -> GenerationRetrievalOutcome:
        del args
        self.retrieve_calls += 1
        c1_input = kwargs.get("c1_applicability_input")
        assert isinstance(c1_input, C1ApplicabilityInput)
        self.c1_inputs.append(c1_input)
        return self.outcome


class _FakeRiskRuntime:
    def current_authority(self):  # type: ignore[no-untyped-def]
        return deterministic_risk_authority(epoch=3, suffix=916_000)

    def evaluate_turn(self, **kwargs: object) -> tuple[()]:
        del kwargs
        return ()


class _FakeWorker:
    def __init__(
        self,
        *,
        plan: QueryPlan,
        binding: GenerationClientBinding,
        outcome: GenerationRetrievalOutcome,
        final_context: tuple[GenerationEvidenceContextItem, ...],
        wire: GenerationStageWireRecord,
        ready_at_start: bool = False,
        recovered_session_id: str = SESSION_ID,
        store_context: tuple[GenerationEvidenceContextItem, ...] | None = None,
        prepared_c1: C1ApplicabilityInput | None = None,
    ) -> None:
        self.plan = plan
        self.binding = binding
        self.outcome = outcome
        self.final_context = final_context
        self.wire = wire
        self.ready = ready_at_start
        self.recovered_session_id = recovered_session_id
        self.store_context = store_context
        self.prepared_c1 = (
            C1ApplicabilityInput.bind(
                plan,
                client_snapshot_ref=binding.client_snapshot_ref,
                client_runtime_epoch=binding.client_runtime_epoch,
                client_tombstone_count=binding.client_tombstone_count,
                temporary_fact_refs=binding.temporary_fact_refs,
            )
            if prepared_c1 is None
            else prepared_c1
        )
        self.calls: list[object] = []
        self.is_alive = True

    def _context_fields(
        self,
        context: tuple[GenerationEvidenceContextItem, ...],
    ) -> tuple[StoredContentRef, str]:
        payload = generation_evidence_context_bytes(context)
        reference = _stored_ref("evidence_context", payload)
        return reference, reference.content_sha256

    def call(self, request: object) -> object:
        self.calls.append(request)
        if isinstance(request, GetGenerationBindingRequest):
            return GetGenerationBindingResponse(
                request_id=request.request_id,
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                binding=self.binding,
            )
        if isinstance(request, SubmitGenerationStageRequest):
            return SubmitGenerationStageResponse(
                request_id=request.request_id,
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                run_id=self.plan.envelope.run_id,
                record=self.wire,
                turn_state="generation_in_progress",
                retrieval_status="pending",
            )
        if isinstance(request, GetGenerationEvidenceForPlanRequest):
            if not self.ready:
                return GetGenerationEvidenceForPlanResponse(
                    request_id=request.request_id,
                    session_id=self.recovered_session_id,
                    turn_id=TURN_ID,
                    run_id=self.plan.envelope.run_id,
                    query_plan_sha256=self.wire.artifact.content_sha256,
                    ready=False,
                )
            context_ref, context_sha256 = self._context_fields(self.final_context)
            pack_ref = _stored_ref(
                "evidence_pack",
                evidence_pack_bytes(self.outcome.evidence_pack),
            )
            return GetGenerationEvidenceForPlanResponse(
                request_id=request.request_id,
                session_id=self.recovered_session_id,
                turn_id=TURN_ID,
                run_id=self.plan.envelope.run_id,
                query_plan_sha256=self.wire.artifact.content_sha256,
                ready=True,
                evidence_pack_ref=pack_ref,
                evidence_pack_sha256=pack_ref.content_sha256,
                evidence_pack=self.outcome.evidence_pack,
                evidence_context_ref=context_ref,
                evidence_context_sha256=context_sha256,
                evidence_context=self.final_context,
                retrieval_metadata=self.outcome.metadata,
            )
        if isinstance(request, PrepareTurnRiskEvaluationRequest):
            message = "synthetic client message"
            message_sha256 = hashlib.sha256(message.encode("utf-8")).hexdigest()
            return PrepareTurnRiskEvaluationResponse(
                request_id=request.request_id,
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                client_message_ref=VersionRef(
                    object_id=object_id("client_message", 16_850),
                    version=1,
                    content_sha256=message_sha256,
                ),
                client_message_sha256=message_sha256,
                client_message=message,
                risk_authority=request.risk_authority,
                evaluation_revision=1,
                evaluation_status="completed",
                observation_set_sha256=canonical_risk_observation_set_sha256(()),
                observation_count=0,
            )
        if isinstance(request, PrepareGenerationRetrievalRequest):
            values = {
                "request_id": request.request_id,
                "session_id": SESSION_ID,
                "turn_id": TURN_ID,
                "run_id": self.plan.envelope.run_id,
                "query_plan_sha256": request.query_plan_sha256,
                "binding": self.binding,
                "c1_applicability_input": self.prepared_c1,
                "risk_context_binding": GenerationRiskContextBinding(
                    turn_id=TURN_ID,
                    client_message_sha256=hashlib.sha256(
                        b"synthetic client message"
                    ).hexdigest(),
                    authority=request.risk_authority,
                    evaluation_observation_ids=(),
                    evaluation_set_sha256=(
                        canonical_risk_observation_set_sha256(())
                    ),
                    evaluation_count=0,
                    visible_observation_ids=(),
                    visible_set_sha256=(
                        canonical_risk_observation_set_sha256(())
                    ),
                    visible_count=0,
                ),
                "private_evidence": (),
            }
            if (
                self.prepared_c1.query_plan_sha256
                != request.query_plan_sha256
            ):
                return PrepareGenerationRetrievalResponse.model_construct(
                    **values
                )
            return PrepareGenerationRetrievalResponse(
                **values
            )
        if isinstance(request, StoreGenerationEvidencePackRequest):
            self.ready = True
            context = self.final_context
            context_ref, context_sha256 = self._context_fields(context)
            pack_ref = _stored_ref(
                "evidence_pack",
                evidence_pack_bytes(request.evidence_pack),
            )
            response = StoreGenerationEvidencePackResponse(
                request_id=request.request_id,
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                run_id=self.plan.envelope.run_id,
                query_plan_sha256=self.wire.artifact.content_sha256,
                evidence_pack_ref=pack_ref,
                evidence_pack_sha256=pack_ref.content_sha256,
                evidence_pack=request.evidence_pack,
                evidence_context_ref=context_ref,
                evidence_context_sha256=context_sha256,
                evidence_context=context,
                retrieval_metadata=request.retrieval_metadata,
            )
            if self.store_context is None:
                return response
            foreign_ref, foreign_sha256 = self._context_fields(self.store_context)
            return StoreGenerationEvidencePackResponse.model_construct(
                **{
                    **response.model_dump(mode="python"),
                    "evidence_context_ref": foreign_ref,
                    "evidence_context_sha256": foreign_sha256,
                    "evidence_context": self.store_context,
                }
            )
        if isinstance(request, GetGenerationStateRequest):
            return GetGenerationStateResponse(
                request_id=request.request_id,
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                run_id=self.plan.envelope.run_id,
                turn_state="generation_in_progress",
                records=(self.wire,),
                risk_observations=(),
                client_binding=self.binding,
            )
        raise AssertionError(type(request).__name__)


def _manager(runtime: _FakeGenerationRuntime) -> SessionRuntimeManager:
    values = iter(range(16_200, 16_500))
    manager = SessionRuntimeManager(
        catalog=cast(ClientCatalog, object()),
        capability_service=cast(CapabilityService, object()),
        scope_broker=cast(ScopeBroker, object()),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: next(values)),
    )
    manager.configure_generation_retrieval(runtime)
    manager.configure_risk_evaluation(_FakeRiskRuntime())
    return manager


def _live(worker: _FakeWorker) -> _LiveSession:
    return _LiveSession(
        client_id=CLIENT_ID,
        session_id=SESSION_ID,
        session_handle=SESSION_HANDLE,
        capability_epoch=1,
        scope_marker_sha256="a" * 64,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
    )


def _request(plan: QueryPlan) -> SubmitGenerationStageInput:
    return SubmitGenerationStageInput(
        session_handle=SESSION_HANDLE,
        idempotency_key="generation-context-delivery",
        payload=plan,
    )


def test_fresh_and_recovered_query_plan_return_identical_frozen_body_context() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    runtime = _FakeGenerationRuntime(global_binding, outcome)
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
    )
    manager = _manager(runtime)
    live = _live(worker)
    transport = BoundTransport("transport-context", SESSION_HANDLE)

    fresh = manager._submit_generation_stage(
        live,
        _request(plan),
        binding=transport,
    )
    recovered = manager._submit_generation_stage(
        live,
        _request(plan),
        binding=transport,
    )

    assert fresh.retrieval_status == recovered.retrieval_status == "ready"
    assert fresh.evidence_context == recovered.evidence_context == final_context
    assert fresh.evidence_context_sha256 == recovered.evidence_context_sha256
    assert generation_evidence_context_bytes(fresh.evidence_context or ()) == (
        generation_evidence_context_bytes(recovered.evidence_context or ())
    )
    assert {item.context_kind for item in final_context} == {
        "retrieved_candidate",
        "temporary_fact",
    }
    assert CLIENT_ID not in fresh.model_dump_json()
    assert runtime.retrieve_calls == 1
    assert runtime.c1_inputs == [worker.prepared_c1]


def test_session_rejects_worker_projection_for_a_different_exact_plan() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    foreign_plan = plan.model_copy(
        update={"rationale_summary": "A different persisted plan body."}
    )
    forged = C1ApplicabilityInput.bind(
        foreign_plan,
        client_snapshot_ref=client.client_snapshot_ref,
        client_runtime_epoch=client.client_runtime_epoch,
        client_tombstone_count=client.client_tombstone_count,
        temporary_fact_refs=client.temporary_fact_refs,
    )
    runtime = _FakeGenerationRuntime(global_binding, outcome)
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
        prepared_c1=forged,
    )

    with pytest.raises(SessionRuntimeError, match="QUERY_PLAN_CORRECTION_REQUIRED"):
        _manager(runtime)._submit_generation_stage(
            _live(worker),
            _request(plan),
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )

    assert runtime.retrieve_calls == 0


def test_query_plan_ready_response_is_withheld_when_post_store_binding_changes() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    runtime = _FakeGenerationRuntime(
        global_binding,
        outcome,
        stale_on_binding_call=3,
    )
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
    )

    with pytest.raises(SessionRuntimeError, match="QUERY_PLAN_CORRECTION_REQUIRED"):
        _manager(runtime)._submit_generation_stage(
            _live(worker),
            _request(plan),
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )

    assert worker.ready


def test_generation_recovery_rejects_foreign_session_scope() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
        ready_at_start=True,
        recovered_session_id=FOREIGN_SESSION_ID,
    )

    with pytest.raises(SessionRuntimeError, match="GENERATION_EVIDENCE_RECOVERY_FAILED"):
        _manager(_FakeGenerationRuntime(global_binding, outcome))._submit_generation_stage(
            _live(worker),
            _request(plan),
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )


def test_generation_store_rejects_foreign_but_self_hashed_context() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    body = "foreign context"
    foreign_ref = VersionRef(
        object_id=object_id("text", 16_900),
        version=1,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
    )
    foreign_context = (
        GenerationEvidenceContextItem(
            evidence_id=object_id("evidence", 16_901),
            context_kind="retrieved_candidate",
            text_ref=foreign_ref,
            body=body,
        ),
    )
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
        store_context=foreign_context,
    )

    with pytest.raises(SessionRuntimeError, match="GENERATION_EVIDENCE_STORE_MISMATCH"):
        _manager(_FakeGenerationRuntime(global_binding, outcome))._submit_generation_stage(
            _live(worker),
            _request(plan),
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )


def test_pack_is_stale_after_a_new_temporary_fact_is_added() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    body = '{"replacement":"new current fact"}\n'
    new_ref = VersionRef(
        object_id=object_id("session_fact", 16_950),
        version=1,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
    )
    changed_binding = client.model_copy(
        update={
            "temporary_fact_refs": tuple(
                sorted(
                    (*client.temporary_fact_refs, new_ref),
                    key=lambda item: (
                        item.object_id,
                        item.version,
                        item.content_sha256,
                    ),
                )
            )
        }
    )
    worker = _FakeWorker(
        plan=plan,
        binding=changed_binding,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
        ready_at_start=True,
    )

    with pytest.raises(SessionRuntimeError, match="QUERY_PLAN_CORRECTION_REQUIRED"):
        _manager(_FakeGenerationRuntime(global_binding, outcome))._assert_generation_binding_current(
            _live(worker),
            turn_id=TURN_ID,
            run_id=plan.envelope.run_id,
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )


def test_generation_state_recovery_returns_the_same_safe_pack_and_body_context() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=outcome,
        final_context=final_context,
        wire=wire,
        ready_at_start=True,
    )

    state = _manager(_FakeGenerationRuntime(global_binding, outcome))._get_generation_state(
        _live(worker),
        GetGenerationStateInput(
            session_handle=SESSION_HANDLE,
            turn_id=TURN_ID,
            run_id=plan.envelope.run_id,
        ),
        binding=BoundTransport("transport-context", SESSION_HANDLE),
    )

    evidence = cast(dict[str, object], state["generation_evidence"])
    assert evidence["ready"] is True
    assert evidence["evidence_pack"] == outcome.evidence_pack.model_dump(
        mode="python"
    )
    assert evidence["evidence_context"] == tuple(
        item.model_dump(mode="python") for item in final_context
    )
    assert CLIENT_ID not in str(evidence)


def test_generation_state_recovery_rejects_self_hashed_pack_for_other_snapshot() -> None:
    plan, client, global_binding, outcome, final_context, wire = _fixtures()
    foreign_snapshot = outcome.evidence_pack.client_snapshot_ref.model_copy(
        update={"content_sha256": "f" * 64}
    )
    forged_pack = outcome.evidence_pack.model_copy(
        update={"client_snapshot_ref": foreign_snapshot}
    )
    forged_outcome = outcome.__class__(
        evidence_pack=forged_pack,
        evidence_pack_sha256=hashlib.sha256(
            evidence_pack_bytes(forged_pack)
        ).hexdigest(),
        evidence_context=outcome.evidence_context,
        run_objects=outcome.run_objects,
        metadata=outcome.metadata,
    )
    worker = _FakeWorker(
        plan=plan,
        binding=client,
        outcome=forged_outcome,
        final_context=final_context,
        wire=wire,
        ready_at_start=True,
    )

    with pytest.raises(SessionRuntimeError, match="QUERY_PLAN_CORRECTION_REQUIRED"):
        _manager(_FakeGenerationRuntime(global_binding, forged_outcome))._get_generation_state(
            _live(worker),
            GetGenerationStateInput(
                session_handle=SESSION_HANDLE,
                turn_id=TURN_ID,
                run_id=plan.envelope.run_id,
            ),
            binding=BoundTransport("transport-context", SESSION_HANDLE),
        )
