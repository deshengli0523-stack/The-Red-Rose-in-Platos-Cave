from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Literal

import pytest

from consultation_kb.core.errors import WorkflowOperationalError
from consultation_kb.generation.contracts import (
    ClientReplyCandidate,
    Conceptualization,
    ConceptualizationItem,
    ConsistencyRiskReview,
    CounselorInternalAnalysis,
    EvidenceAudit,
    EvidenceSemanticAssessment,
    EvidenceQualitySummary,
    FinalTurnBundle,
    FollowUpGuidance,
    GenerationStagePayload,
    QueryGuardrails,
    QueryPlan,
    ReplyDraft,
    ReplyDraftSet,
    ReplyClaim,
    RouteOmission,
    Subquery,
    TheoryComparison,
    TheorySelection,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceContextItem,
    GenerationRetrievalMetadata,
    GenerationRunObject,
)
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.consistency import (
    ActionDirection,
    ConsistencySnapshot,
    CorePosition,
    FactPosition,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    AuthoritySnapshotBinding,
    EvidenceCandidate,
    EvidenceChannel,
    EvidencePack,
    EvidenceProvenanceView,
    Provenance,
)
from consultation_kb.models.generation import GenerationStageEnvelope, GenerationStageName
from consultation_kb.retrieval.contracts import ExclusionProof, canonical_json_bytes
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    AppendClientTurnRequest,
    BeginSessionRequest,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    PersistRiskObservationsRequest,
    PersistRiskObservationsResponse,
    ReadSessionStateRequest,
    ReadSessionStateResponse,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
)
from tests.consultation_kb.integration.test_session_worker_boundary import (
    _Harness,
    _build_harness,
    _request_id,
)
from tests.consultation_kb.risk_support import deterministic_risk_authority
from tests.consultation_kb.unit.p6_quality_support import (
    NOW,
    candidate as quality_candidate,
    current_consistency_assessments,
    object_id,
    pack as quality_pack,
    ref,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("P6-GENERATION-PIPELINE"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


_RunObjectType = Literal["authority_snapshot", "exclusion_proof", "provenance"]
_EVIDENCE_INDEX = 15_000
_SOURCE_INDEX = 15_001
_PASSAGE_INDEX = 15_002
_FACT_KEY = "reported_tension"
_POSITION_KEY = "preserve_agency"
_ACTION_KEY = "clarify_needs"
_EVIDENCE_BODY = "Approved evidence for clarifying needs after a disagreement."
_GENTLE_TEXT = (
    "It sounds like the disagreement left you unsettled. We can first clarify "
    "what you need before deciding what to do."
)
_DIRECT_TEXT = (
    "You reported a disagreement that still feels unresolved. A useful next "
    "step is to name the need you want the conversation to address."
)
RISK_AUTHORITY = deterministic_risk_authority(epoch=7, suffix=914_000)


def _complete_empty_risk_evaluation(
    harness: _Harness,
    worker: ScopedWorkerBroker,
    *,
    turn_id: str,
) -> None:
    result = worker.call(
        PersistRiskObservationsRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            turn_id=turn_id,
            risk_authority=RISK_AUTHORITY,
            observations=(),
        )
    )
    assert isinstance(result, PersistRiskObservationsResponse)
    assert result.observation_count == 0


def _run_object(object_type: _RunObjectType, value: StrictModel) -> GenerationRunObject:
    payload = canonical_json_bytes(value.model_dump(mode="json"))
    digest = hashlib.sha256(payload).hexdigest()
    return GenerationRunObject(
        object_type=object_type,
        reference=VersionRef(
            object_id=deterministic_object_id(object_type, digest),
            version=1,
            content_sha256=digest,
        ),
        canonical_json=payload.decode("utf-8"),
    )


def _evidence_closure(
    *,
    run_id: str,
    client_snapshot_ref: VersionRef,
    client_runtime_epoch: int,
    tombstone_epoch: int,
    temporary_fact_refs: tuple[VersionRef, ...],
) -> tuple[
    EvidencePack,
    tuple[GenerationEvidenceContextItem, ...],
    tuple[GenerationRunObject, ...],
]:
    provenance = Provenance(
        source_ids=frozenset({object_id("source", _SOURCE_INDEX)}),
        passage_ids=frozenset({object_id("passage", _PASSAGE_INDEX)}),
        provenance_scope="global_source",
        derivation_rule_ref=ref("derivation_rule", _SOURCE_INDEX),
    )
    provenance_object = _run_object("provenance", provenance)
    base_evidence = quality_candidate(_EVIDENCE_INDEX)
    evidence_values = base_evidence.model_dump(mode="python")
    evidence_values["text_ref"] = VersionRef(
        object_id=base_evidence.text_ref.object_id,
        version=base_evidence.text_ref.version,
        content_sha256=hashlib.sha256(_EVIDENCE_BODY.encode("utf-8")).hexdigest(),
    )
    evidence_values["provenance"] = EvidenceProvenanceView(
        provenance_ref=provenance_object.reference,
        provenance_scope="global_source",
        derivation_rule_ref=provenance.derivation_rule_ref,
        source_count=1,
        passage_count=1,
        case_count=0,
        case_contributor_count=0,
        independent_source_count=1,
        client_exclusion_status="not_applicable",
    )
    evidence = EvidenceCandidate.model_validate(evidence_values, strict=True)

    policy_ref = ref("authority_policy", 15_100)
    authority = AuthoritativeFilterSnapshot(
        run_id=run_id,
        global_runtime_epoch=7,
        client_runtime_epoch=client_runtime_epoch,
        tombstone_epoch=tombstone_epoch,
        authorization_epoch=11,
        allowed_ref_ids=frozenset({evidence.evidence_id}),
        policy_ref=policy_ref,
        created_at=NOW,
    )
    proof = ExclusionProof(
        run_id=run_id,
        policy_ref=policy_ref,
        input_count=1,
        allowed_count=1,
        denied_count=0,
        candidate_ids_sha256=hashlib.sha256(
            canonical_json_bytes([evidence.evidence_id])
        ).hexdigest(),
        reasons={},
    )
    authority_object = _run_object("authority_snapshot", authority)
    proof_object = _run_object("exclusion_proof", proof)

    pack_values = quality_pack(supporting=(evidence,)).model_dump(mode="python")
    pack_values.update(
        {
            "run_id": run_id,
            "authority": AuthoritySnapshotBinding(
                snapshot_ref=authority_object.reference,
                run_id=run_id,
                global_runtime_epoch=authority.global_runtime_epoch,
                client_runtime_epoch=authority.client_runtime_epoch,
                tombstone_epoch=authority.tombstone_epoch,
                authorization_epoch=authority.authorization_epoch,
                policy_ref=authority.policy_ref,
                created_at=authority.created_at,
            ),
            "client_snapshot_ref": client_snapshot_ref,
            "temporary_fact_refs": temporary_fact_refs,
            "exclusion_proof_ref": proof_object.reference,
        }
    )
    pack = EvidencePack.model_validate(pack_values, strict=True)
    run_objects = tuple(
        sorted(
            (authority_object, proof_object, provenance_object),
            key=lambda item: (item.object_type, item.reference.object_id),
        )
    )
    context = (
        GenerationEvidenceContextItem(
            evidence_id=evidence.evidence_id,
            context_kind="retrieved_candidate",
            text_ref=evidence.text_ref,
            body=_EVIDENCE_BODY,
        ),
    )
    return pack, context, run_objects


def _envelope(
    stage: GenerationStageName,
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
) -> GenerationStageEnvelope:
    return GenerationStageEnvelope(
        stage=stage,
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=parent_sha256s,
        created_at=NOW,
    )


def _parents(previous_sha256: str, evidence_pack_sha256: str) -> tuple[str, ...]:
    return tuple(sorted({previous_sha256, evidence_pack_sha256}))


def _submit(
    harness: _Harness,
    worker: ScopedWorkerBroker,
    payload: GenerationStagePayload,
    *,
    key: str,
) -> SubmitGenerationStageResponse:
    response = worker.call(
        SubmitGenerationStageRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            idempotency_key=key,
            stage_payload=payload,
            risk_authority=(
                deterministic_risk_authority(
                    epoch=payload.global_runtime_epoch,
                    suffix=914_000,
                )
                if isinstance(payload, QueryPlan)
                else None
            ),
        )
    )
    assert isinstance(response, SubmitGenerationStageResponse)
    return response


def _query_plan(
    *,
    turn_id: str,
    run_id: str,
    client_snapshot_ref: VersionRef,
    client_runtime_epoch: int,
    tombstone_epoch: int,
) -> QueryPlan:
    omitted_routes: tuple[EvidenceChannel, ...] = (
        "profile",
        "client_history",
        "lexical",
        "vector",
        "global_graph",
        "case",
    )
    return QueryPlan(
        envelope=_envelope(
            "query_plan",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(),
        ),
        intent="simple_empathic_clarification",
        client_snapshot_ref=client_snapshot_ref,
        global_runtime_epoch=7,
        client_runtime_epoch=client_runtime_epoch,
        tombstone_epoch=tombstone_epoch,
        authorization_epoch=11,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="reflect_current_need",
                category="emotion_needs_relationship",
                question="What current need can be reflected without forcing a conclusion?",
                routes=("wiki",),
                required_evidence_types=(),
                scope="global_knowledge",
            ),
        ),
        route_omissions=tuple(
            RouteOmission(
                route=route,
                reason="This bounded clarification does not require this route.",
            )
            for route in omitted_routes
        ),
        rationale_summary="Use one governed knowledge route for a bounded clarification.",
    )


def _conceptualization(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
) -> Conceptualization:
    return Conceptualization(
        envelope=_envelope(
            "conceptualization",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        items=(
            ConceptualizationItem(
                item_id=_FACT_KEY,
                cognitive_type="client_reported",
                statement="The visitor reports unresolved tension after a disagreement.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
        ),
        key_emotions=("unsettled",),
        key_needs=("clarity",),
        alternative_explanations=("The disagreement may reflect different expectations.",),
        limitations=("The other person's perspective is not available.",),
        rationale_summary="Separate the reported experience from any untested explanation.",
    )


def _theory_comparison(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    pack: EvidencePack,
) -> TheoryComparison:
    revision = pack.c1_applicability.revision
    assert revision is not None
    return TheoryComparison(
        envelope=_envelope(
            "theory_comparison",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        primary_framework=TheorySelection(
            theory_ref=revision,
            role="primary_framework",
            source_grade="C1",
            empirical_support=pack.c1_applicability.empirical_support,
            applicability="applicable",
            boundaries=("Use the framework as guidance, not as a fact about the visitor.",),
            evidence_ids=(evidence_id,),
        ),
        comparisons=(),
        conflicts=(),
        clarification_questions=(),
        rationale_summary="Apply the exact active C1 revision within its stated boundary.",
    )


def _reply_drafts(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
) -> ReplyDraftSet:
    def draft(
        candidate_id: str,
        strategy: Literal["gentle_empathy", "direct_clarification"],
        text: str,
        claim_id: str,
    ) -> ReplyDraft:
        return ReplyDraft(
            candidate_id=candidate_id,
            strategy=strategy,
            text=text,
            core_positions=(_POSITION_KEY,),
            current_fact_ids=(_FACT_KEY,),
            action_directions=(_ACTION_KEY,),
            evidence_ids=(evidence_id,),
            claims=(
                ReplyClaim(
                    claim_id=claim_id,
                    claim_type="fact",
                    statement=text,
                    text_start_char=0,
                    text_end_char=len(text),
                    text_sha256=hashlib.sha256(
                        text.encode("utf-8")
                    ).hexdigest(),
                    evidence_ids=(evidence_id,),
                    evidence_fidelity="faithful",
                ),
            ),
        )

    return ReplyDraftSet(
        envelope=_envelope(
            "reply_drafts",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        candidates=(
            draft("gentle_candidate", "gentle_empathy", _GENTLE_TEXT, "gentle_report"),
            draft(
                "direct_candidate",
                "direct_clarification",
                _DIRECT_TEXT,
                "direct_report",
            ),
        ),
        shared_core_positions=(_POSITION_KEY,),
        shared_action_directions=(_ACTION_KEY,),
        rationale_summary="Vary tone while preserving the same facts, position, and action.",
    )


def _audit(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    evidence_body: str = _EVIDENCE_BODY,
) -> EvidenceAudit:
    assessments = tuple(
        EvidenceSemanticAssessment(
            claim_scope=scope,
            claim_id=claim_id,
            assessed_claim_type="fact",
            evidence_id=evidence_id,
            role="support",
            text_start_char=0,
            text_end_char=len(evidence_body),
            exact_excerpt=evidence_body,
            excerpt_sha256=hashlib.sha256(
                evidence_body.encode("utf-8")
            ).hexdigest(),
            semantic_status="supports",
        )
        for scope, claim_id in (
            ("analysis", _FACT_KEY),
            ("reply", "direct_report"),
            ("reply", "gentle_report"),
        )
    )
    return EvidenceAudit(
        envelope=_envelope(
            "evidence_audit",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        assessments=assessments,
        findings=(),
        decision="pass",
        retry_count=0,
        unresolved_reasons=(),
        rationale_summary="All decision-bearing audit fields match deterministic recomputation.",
    )


def _consistency_review(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    replies: ReplyDraftSet,
) -> ConsistencyRiskReview:
    snapshots = tuple(
        ConsistencySnapshot(
            snapshot_key=draft.candidate_id,
            source="current_candidate",
            facts=(
                FactPosition(
                    fact_key=_FACT_KEY,
                    state="affirmed",
                    evidence_ids=(evidence_id,),
                ),
            ),
            core_positions=(
                CorePosition(position_key=_POSITION_KEY, stance="support"),
            ),
            action_directions=(
                ActionDirection(action_key=_ACTION_KEY, disposition="explore"),
            ),
            conclusion=draft.text,
            conclusion_evidence_ids=(evidence_id,),
        )
        for draft in replies.candidates
    )
    return ConsistencyRiskReview(
        envelope=_envelope(
            "consistency_risk_review",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        current_candidate_snapshots=snapshots,
        semantic_assessments=current_consistency_assessments(replies, snapshots),
        consistency_findings=(),
        risk_observation_ids=(),
        decision="pass",
        retry_count=0,
        unresolved_reasons=(),
        rationale_summary="Candidates preserve one fact, position, and action direction.",
    )


def _final_bundle(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    replies: ReplyDraftSet,
    quality_evidence_ids: tuple[str, ...],
) -> FinalTurnBundle:
    labels = {
        "gentle_candidate": "Gentle reflection",
        "direct_candidate": "Direct clarification",
    }
    return FinalTurnBundle(
        envelope=_envelope(
            "final_bundle",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        counselor_internal=CounselorInternalAnalysis(
            summary="Separate the reported experience from any untested explanation.",
            key_fact_ids=(_FACT_KEY,),
            hypotheses=(),
            conflicts=(),
            uncertainty=("The other person's perspective is not available.",),
            evidence_ids=(evidence_id,),
            risk_observations=(),
        ),
        client_reply_candidates=tuple(
            ClientReplyCandidate(
                candidate_id=draft.candidate_id,
                label=labels[draft.candidate_id],
                strategy=draft.strategy,
                text=draft.text,
                core_positions=draft.core_positions,
                action_directions=draft.action_directions,
            )
            for draft in replies.candidates
        ),
        follow_up_guidance=FollowUpGuidance(
            suggested_questions=("What would feeling understood look like here?",),
            optional_actions=("Write down the need before the next conversation.",),
            observation_focus=("Notice whether the need becomes clearer.",),
            next_steps=("Let the counselor choose or edit one candidate.",),
        ),
        evidence_quality=EvidenceQualitySummary(
            status="sufficient",
            evidence_ids=quality_evidence_ids,
            unresolved_reasons=(),
            retry_count=0,
        ),
    )


def test_real_scoped_worker_runs_all_seven_generation_stages_and_blocks_bypass(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    try:
        worker.start()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        turn_id = harness.ids.uuid7()
        worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="I still feel unsettled after our disagreement.",
                risk_authority=RISK_AUTHORITY,
            )
        )
        binding_response = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
            )
        )
        assert isinstance(binding_response, GetGenerationBindingResponse)
        binding = binding_response.binding
        run_id = harness.ids.uuid7()

        plan = _query_plan(
            turn_id=turn_id,
            run_id=run_id,
            client_snapshot_ref=binding.client_snapshot_ref,
            client_runtime_epoch=binding.client_runtime_epoch,
            tombstone_epoch=binding.client_tombstone_count,
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="RISK_EVALUATION_INCOMPLETE",
        ):
            _submit(harness, worker, plan, key="pipeline-query-plan")
        _complete_empty_risk_evaluation(harness, worker, turn_id=turn_id)
        plan_response = _submit(harness, worker, plan, key="pipeline-query-plan")
        assert plan_response.retrieval_status == "pending"
        assert plan_response.turn_state == "generation_in_progress"
        plan_sha256 = plan_response.record.artifact.content_sha256

        pack, evidence_context, run_objects = _evidence_closure(
            run_id=run_id,
            client_snapshot_ref=binding.client_snapshot_ref,
            client_runtime_epoch=binding.client_runtime_epoch,
            tombstone_epoch=binding.client_tombstone_count,
            temporary_fact_refs=binding.temporary_fact_refs,
        )
        stored = worker.call(
            StoreGenerationEvidencePackRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=plan_sha256,
                evidence_pack=pack,
                evidence_context=evidence_context,
                run_objects=run_objects,
                retrieval_metadata=GenerationRetrievalMetadata(
                    route_candidate_counts={"wiki": 1},
                    filtered_candidate_count=1,
                    resolved_evidence_count=1,
                    selected_evidence_count=1,
                ),
            )
        )
        assert isinstance(stored, StoreGenerationEvidencePackResponse)
        assert stored.evidence_context == evidence_context
        pack_sha256 = stored.evidence_pack_sha256
        evidence_id = pack.supporting[0].evidence_id

        out_of_order = _reply_drafts(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(plan_sha256, pack_sha256),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_ORDER_INVALID",
        ):
            _submit(harness, worker, out_of_order, key="pipeline-out-of-order")

        conceptualization = _conceptualization(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(plan_sha256, pack_sha256),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
        )
        concept_response = _submit(
            harness,
            worker,
            conceptualization,
            key="pipeline-conceptualization",
        )

        theory = _theory_comparison(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                concept_response.record.artifact.content_sha256,
                pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
            pack=pack,
        )
        theory_response = _submit(harness, worker, theory, key="pipeline-theory")

        replies = _reply_drafts(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                theory_response.record.artifact.content_sha256,
                pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
        )
        reply_response = _submit(harness, worker, replies, key="pipeline-replies")

        audit = _audit(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                reply_response.record.artifact.content_sha256,
                pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
        )
        audit_response = _submit(harness, worker, audit, key="pipeline-audit")

        consistency = _consistency_review(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                audit_response.record.artifact.content_sha256,
                pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
            replies=replies,
        )
        consistency_response = _submit(
            harness,
            worker,
            consistency,
            key="pipeline-consistency",
        )

        final = _final_bundle(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                consistency_response.record.artifact.content_sha256,
                pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
            replies=replies,
            quality_evidence_ids=tuple(sorted(bound_evidence_ids(pack))),
        )
        bypassing_consistency = final.model_copy(
            update={
                "envelope": final.envelope.model_copy(
                    update={
                        "parent_sha256s": _parents(
                            audit_response.record.artifact.content_sha256,
                            pack_sha256,
                        )
                    }
                )
            }
        )
        with pytest.raises(WorkflowOperationalError, match="GENERATION_PARENT_MISMATCH"):
            _submit(
                harness,
                worker,
                bypassing_consistency,
                key="pipeline-final-bypass",
            )

        final_response = _submit(harness, worker, final, key="pipeline-final")
        assert final_response.turn_state == "awaiting_actual_reply"
        assert len(final_response.candidate_ids) == 2

        state = worker.call(
            GetGenerationStateRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
            )
        )
        assert isinstance(state, GetGenerationStateResponse)
        assert tuple(record.stage for record in state.records) == (
            "query_plan",
            "conceptualization",
            "theory_comparison",
            "reply_drafts",
            "evidence_audit",
            "consistency_risk_review",
            "final_bundle",
        )
        assert state.turn_state == "awaiting_actual_reply"
        assert state.risk_observations == ()

        session = worker.call(
            ReadSessionStateRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
            )
        )
        assert isinstance(session, ReadSessionStateResponse)
        assert tuple(
            candidate.text for candidate in session.recovery.pending_candidates
        ) == (_GENTLE_TEXT, _DIRECT_TEXT)
    finally:
        worker.close()
        harness.close()
