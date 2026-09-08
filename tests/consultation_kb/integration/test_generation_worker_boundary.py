from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.errors import WorkflowOperationalError
from consultation_kb.generation.consistency import ConsistencyReviewer
from consultation_kb.generation.consistency_validation import (
    GenerationConsistencyValidator,
)
from consultation_kb.generation.contracts import (
    AuditFinding,
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
    QueryPlan,
    QueryGuardrails,
    ReplyClaim,
    ReplyDraft,
    ReplyDraftSet,
    RouteOmission,
    Subquery,
    TheoryComparison,
)
from consultation_kb.generation.evidence_audit import EvidenceAuditor
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceContextItem,
    GenerationRetrievalMetadata,
    GenerationRunObject,
    evidence_pack_sha256,
)
from consultation_kb.generation.theory_policy import (
    TheoryUsePolicy,
    derive_hard_constraint_evidence_ids,
)
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
    EvidencePack,
    Provenance,
)
from consultation_kb.models.generation import (
    GenerationStageEnvelope,
    GenerationStageName,
)
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.models.session import CandidateDraft
from consultation_kb.retrieval.contracts import ExclusionProof, canonical_json_bytes
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskObservationSource,
    RiskTriggerSpan,
    canonical_risk_observation_set_sha256,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from consultation_kb.security.scoped_worker import ScopeDenied, ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    AcknowledgeRiskObservationRequest,
    AcknowledgeRiskObservationResponse,
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    BeginGenerationRequest,
    BeginGenerationResponse,
    BeginSessionRequest,
    BeginSessionResponse,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GetGenerationEvidenceForPlanRequest,
    GetGenerationEvidenceForPlanResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    PersistRiskObservationsRequest,
    PersistRiskObservationsResponse,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
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
from tests.consultation_kb.integration.test_client_history_scope import (
    _scoped_root,
)
from tests.consultation_kb.risk_support import deterministic_risk_authority
from tests.consultation_kb.unit.p6_quality_support import (
    NOW,
    candidate,
    current_consistency_assessments,
    object_id,
    pack,
    ref,
)
from consultation_kb.vault.content_store import ContentStore


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("GENERATION-WORKER-BOUNDARY-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


_EVIDENCE_BODY = "Approved global guidance for clarifying a changing relationship."
RISK_AUTHORITY = deterministic_risk_authority(epoch=7, suffix=913_000)


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


def _run_object(
    object_type: str,
    value: StrictModel,
) -> GenerationRunObject:
    payload = canonical_json_bytes(value.model_dump(mode="json"))
    digest = hashlib.sha256(payload).hexdigest()
    return GenerationRunObject.model_validate(
        {
            "object_type": object_type,
            "reference": VersionRef(
                object_id=deterministic_object_id(object_type, digest),
                version=1,
                content_sha256=digest,
            ),
            "canonical_json": payload.decode("utf-8"),
        },
        strict=True,
    )


def _envelope(
    stage: GenerationStageName,
    *,
    turn_id: str,
    run_id: str,
    previous_sha256: str | None = None,
    pack_sha256: str | None = None,
) -> GenerationStageEnvelope:
    parents: tuple[str, ...] = ()
    if previous_sha256 is not None:
        assert pack_sha256 is not None
        parents = tuple(sorted({previous_sha256, pack_sha256}))
    return GenerationStageEnvelope(
        stage=stage,
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=parents,
        created_at=NOW,
    )


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
                    suffix=913_000,
                )
                if isinstance(payload, QueryPlan)
                else None
            ),
        )
    )
    assert isinstance(response, SubmitGenerationStageResponse)
    return response


def _trusted_pack(
    *,
    run_id: str,
    binding: GetGenerationBindingResponse,
    global_runtime_epoch: int,
    authorization_epoch: int,
    with_contradiction: bool = False,
) -> tuple[
    EvidencePack,
    tuple[GenerationEvidenceContextItem, ...],
    tuple[GenerationRunObject, ...],
]:
    provenance = Provenance(
        source_ids=frozenset({object_id("source", 14_001)}),
        passage_ids=frozenset({object_id("passage", 14_002)}),
        provenance_scope="global_source",
        derivation_rule_ref=ref("derivation_rule", 14_003),
    )
    provenance_object = _run_object("provenance", provenance)
    base = candidate(14_010)
    evidence = base.model_copy(
        update={
            "text_ref": base.text_ref.model_copy(
                update={
                    "content_sha256": hashlib.sha256(
                        _EVIDENCE_BODY.encode("utf-8")
                    ).hexdigest()
                }
            ),
            "provenance": base.provenance.model_copy(
                update={
                    "provenance_ref": provenance_object.reference,
                    "derivation_rule_ref": provenance.derivation_rule_ref,
                }
            )
        }
    )
    authority = AuthoritativeFilterSnapshot(
        run_id=run_id,
        global_runtime_epoch=global_runtime_epoch,
        client_runtime_epoch=binding.binding.client_runtime_epoch,
        tombstone_epoch=binding.binding.client_tombstone_count,
        authorization_epoch=authorization_epoch,
        allowed_ref_ids=frozenset({evidence.text_ref.object_id}),
        policy_ref=ref("authority_policy", 14_020),
        created_at=NOW,
    )
    proof = ExclusionProof(
        run_id=run_id,
        policy_ref=authority.policy_ref,
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
    template = pack(
        supporting=(evidence,),
        contradicting=((evidence,) if with_contradiction else ()),
        c1_status="unavailable",
        effective_status="none",
    )
    values = template.model_dump(mode="python")
    values.update(
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
            "client_snapshot_ref": binding.binding.client_snapshot_ref,
            "temporary_fact_refs": binding.binding.temporary_fact_refs,
            "exclusion_proof_ref": proof_object.reference,
        }
    )
    evidence_pack = EvidencePack.model_validate(values, strict=True)
    objects = tuple(
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
    return evidence_pack, context, objects


def _reply_drafts(
    *,
    envelope: GenerationStageEnvelope,
    pack_sha256: str,
    evidence: EvidenceCandidate,
) -> ReplyDraftSet:
    evidence_ids = (evidence.evidence_id,)
    gentle_text = (
        "This uncertainty sounds difficult. We can first clarify when "
        "the recent change began and what you need now."
    )
    direct_text = (
        "Before deciding what the relationship means, map the timing of "
        "the reported change and the conversation around it."
    )
    shared_values = {
        "core_positions": ("clarify_before_deciding",),
        "current_fact_ids": ("reported_uncertainty",),
        "action_directions": ("gather_timeline",),
        "evidence_ids": evidence_ids,
    }
    candidates = (
        ReplyDraft(
            candidate_id="candidate_gentle",
            strategy="gentle_empathy",
            text=gentle_text,
            claims=(
                ReplyClaim(
                    claim_id="gentle_clarification",
                    claim_type="important_conclusion",
                    statement=gentle_text,
                    text_start_char=0,
                    text_end_char=len(gentle_text),
                    text_sha256=hashlib.sha256(
                        gentle_text.encode("utf-8")
                    ).hexdigest(),
                    evidence_ids=evidence_ids,
                    evidence_fidelity="faithful",
                ),
            ),
            **shared_values,
        ),
        ReplyDraft(
            candidate_id="candidate_direct",
            strategy="direct_clarification",
            text=direct_text,
            claims=(
                ReplyClaim(
                    claim_id="direct_clarification",
                    claim_type="important_conclusion",
                    statement=direct_text,
                    text_start_char=0,
                    text_end_char=len(direct_text),
                    text_sha256=hashlib.sha256(
                        direct_text.encode("utf-8")
                    ).hexdigest(),
                    evidence_ids=evidence_ids,
                    evidence_fidelity="faithful",
                ),
            ),
            **shared_values,
        ),
    )
    return ReplyDraftSet(
        envelope=envelope,
        evidence_pack_sha256=pack_sha256,
        candidates=candidates,
        shared_core_positions=("clarify_before_deciding",),
        shared_action_directions=("gather_timeline",),
        rationale_summary=(
            "Both candidates preserve the same facts, position, and action direction."
        ),
    )


def _snapshots(
    replies: ReplyDraftSet,
    *,
    hide_conflict: bool,
) -> tuple[ConsistencySnapshot, ...]:
    return tuple(
        ConsistencySnapshot(
            snapshot_key=draft.candidate_id,
            source="current_candidate",
            facts=tuple(
                FactPosition(
                    fact_key=fact_id,
                    state="affirmed",
                    evidence_ids=draft.evidence_ids,
                )
                for fact_id in draft.current_fact_ids
            ),
            core_positions=tuple(
                CorePosition(
                    position_key=position,
                    stance=(
                        "oppose"
                        if hide_conflict and index == 1
                        else "support"
                    ),
                )
                for position in draft.core_positions
            ),
            action_directions=tuple(
                ActionDirection(action_key=action, disposition="pursue")
                for action in draft.action_directions
            ),
            conclusion=draft.text,
            conclusion_evidence_ids=draft.evidence_ids,
        )
        for index, draft in enumerate(replies.candidates)
    )


def _final_bundle(
    *,
    envelope: GenerationStageEnvelope,
    pack_sha256: str,
    replies: ReplyDraftSet,
    evidence_id: str,
    quality_evidence_ids: tuple[str, ...],
    conflicts: tuple[str, ...] = (),
) -> FinalTurnBundle:
    labels = {
        "candidate_gentle": "Gentle clarification",
        "candidate_direct": "Direct clarification",
    }
    return FinalTurnBundle(
        envelope=envelope,
        evidence_pack_sha256=pack_sha256,
        counselor_internal=CounselorInternalAnalysis(
            summary="Separate the direct report from any interpretation.",
            key_fact_ids=("reported_uncertainty",),
            hypotheses=(),
            conflicts=conflicts,
            uncertainty=("Only the current report is available.",),
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
            suggested_questions=("When did you first notice the change?",),
            optional_actions=("Write down the sequence before drawing a conclusion.",),
            observation_focus=("Notice what is directly reported versus inferred.",),
            next_steps=("Clarify the timeline in the next exchange.",),
        ),
        evidence_quality=EvidenceQualitySummary(
            status="sufficient",
            evidence_ids=quality_evidence_ids,
            unresolved_reasons=(),
            retry_count=0,
        ),
    )


def _state(
    harness: _Harness,
    worker: ScopedWorkerBroker,
    *,
    turn_id: str,
    run_id: str,
) -> GetGenerationStateResponse:
    response = worker.call(
        GetGenerationStateRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            turn_id=turn_id,
            run_id=run_id,
        )
    )
    assert isinstance(response, GetGenerationStateResponse)
    return response


def test_prepare_retrieval_projects_c1_only_from_persisted_bound_evidence(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    worker.start()
    turn_id = harness.ids.uuid7()
    run_id = harness.ids.uuid7()
    try:
        begun = worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        assert isinstance(begun, BeginSessionResponse)
        appended = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="I want help understanding my current relationship.",
                risk_authority=RISK_AUTHORITY,
            )
        )
        assert isinstance(appended, AppendClientTurnResponse)
        _complete_empty_risk_evaluation(harness, worker, turn_id=turn_id)
        temporary = worker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="generation-c1-projection-fact",
                event_kind="ADD",
                cognitive_type="client_statement",
                value={
                    "c1_context": {
                        "schema_version": "c1_context_projection.v1",
                        "fields": [
                            {
                                "context_field": "domain",
                                "state": "values",
                                "value_keys": ["emotional_consultation"],
                            }
                        ],
                    }
                },
            )
        )
        assert isinstance(temporary, AppendTemporaryFactResponse)
        binding = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
            )
        )
        assert isinstance(binding, GetGenerationBindingResponse)
        plan = QueryPlan(
            envelope=_envelope(
                "query_plan",
                turn_id=turn_id,
                run_id=run_id,
            ),
            intent="theory_guidance",
            client_snapshot_ref=binding.binding.client_snapshot_ref,
            global_runtime_epoch=7,
            client_runtime_epoch=binding.binding.client_runtime_epoch,
            tombstone_epoch=binding.binding.client_tombstone_count,
            authorization_epoch=11,
            guardrails=QueryGuardrails(),
            subqueries=(
                Subquery(
                    subquery_id="governed_theory",
                    category="theory_method_boundary",
                    question="Which governed theory boundary applies?",
                    routes=("wiki",),
                    required_evidence_types=(
                        "theory_applicability",
                        "theory_boundary",
                    ),
                    scope="global_knowledge",
                ),
            ),
            route_omissions=tuple(
                RouteOmission(
                    route=route,
                    reason="Not needed for this worker projection test.",
                )
                for route in (
                    "profile",
                    "client_history",
                    "lexical",
                    "vector",
                    "global_graph",
                    "case",
                )
            ),
            rationale_summary="Use one governed source with bound C1 context.",
        )
        submitted = _submit(
            harness,
            worker,
            plan,
            key="generation-c1-projection-plan",
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_BINDING_MISMATCH",
        ):
            worker.call(
                PrepareGenerationRetrievalRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    turn_id=turn_id,
                    run_id=run_id,
                    query_plan_sha256="f" * 64,
                    risk_authority=RISK_AUTHORITY,
                    query_categories=("continuity",),
                )
            )
        prepared = worker.call(
            PrepareGenerationRetrievalRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=submitted.record.artifact.content_sha256,
                risk_authority=RISK_AUTHORITY,
                query_categories=("continuity",),
            )
        )
        assert isinstance(prepared, PrepareGenerationRetrievalResponse)
        projected = prepared.c1_applicability_input
        projected.assert_plan_closure(plan)
        assert projected.query_plan_sha256 == submitted.record.artifact.content_sha256
        assert projected.context_values() == {
            "domain": ("emotional_consultation",),
        }
        assert projected.assertions[0].source_evidence_ids == (
            binding.binding.temporary_fact_refs[0].object_id,
        )
        assert prepared.binding == binding.binding
        rendered = projected.model_dump_json()
        assert harness.client_a not in rendered
        assert "I want help" not in rendered
    finally:
        worker.close()
        harness.close()


@pytest.mark.acceptance_id("VER-01")
def test_private_generation_evidence_fails_closed_on_corrupt_active_client_cas(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    initial_worker = harness.worker()
    initial_worker.start()
    try:
        begun = initial_worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        assert isinstance(begun, BeginSessionResponse)
    finally:
        initial_worker.close()

    seed_root, _marker, expected = _scoped_root(tmp_path / "private-evidence-seed")
    shutil.copytree(
        seed_root / "cas",
        harness.client_a_root / "cas",
        dirs_exist_ok=True,
    )
    connection = sqlite3.connect(harness.client_a_root / "client.sqlite3")
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "ATTACH DATABASE ? AS seed",
            (str(seed_root / "client.sqlite3"),),
        )
        for table in (
            "publication_operations",
            "runtime_epochs",
            "artifact_manifests",
            "artifact_members",
            "active_artifacts",
        ):
            connection.execute(
                f"INSERT INTO main.{table} SELECT * FROM seed.{table}"
            )
        connection.execute(
            "UPDATE client_fact_authority "
            "SET commit_version = 1, client_id = ? WHERE singleton = 1",
            (harness.client_a,),
        )
        connection.commit()
    finally:
        connection.close()

    profile = expected[0]
    ContentStore(harness.client_a_root / "cas").reference(
        content_sha256=profile.reference.content_sha256,
        media_type=profile.metadata.media_type,
        size_bytes=profile.metadata.size_bytes,
    ).path.write_bytes(b"corrupt private profile")

    worker = harness.worker()
    try:
        with pytest.raises(ScopeDenied, match="^SCOPE_DENIED$"):
            worker.start()
        assert worker.closed
    finally:
        worker.close()
        harness.close()


def test_prepare_risk_context_carries_prior_visible_observation_across_turns(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    try:
        worker.start()
        begun = worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        assert isinstance(begun, BeginSessionResponse)

        first_turn = harness.ids.uuid7()
        first_message = "synthetic persistent counselor risk"
        first = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=first_turn,
                client_message=first_message,
                risk_authority=RISK_AUTHORITY,
            )
        )
        assert isinstance(first, AppendClientTurnResponse)
        rule_ref = ref("risk_rule", 0xE01)
        observation_id = object_id("risk_observation", 0xE02)
        trigger = first_message[:9]
        normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
            trigger
        )
        observation = InternalRiskObservationRecord(
            session_id=harness.session_id,
            observation=InternalRiskObservation(
                observation_id=observation_id,
                category="synthetic_persistent_observation",
                level="high",
                trigger_turn_ids=(first_turn,),
                rule_ref=rule_ref,
                detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                suggested_questions=("SYNTH-PERSISTENCE-VERIFY",),
            ),
            trigger_spans=(
                RiskTriggerSpan(
                    turn_id=first_turn,
                    content_ref=first.client_message_ref,
                    start_offset=0,
                    end_offset=9,
                    span_sha256=hashlib.sha256(trigger.encode("utf-8")).hexdigest(),
                    normalized_length=normalized_length,
                    normalized_span_sha256=normalized_span_sha256,
                ),
            ),
            sources=(
                RiskObservationSource(
                    source_kind="deterministic_rule",
                    source_ref=rule_ref,
                ),
            ),
            confidence=1.0,
        )
        persisted = worker.call(
            PersistRiskObservationsRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=first_turn,
                risk_authority=RISK_AUTHORITY,
                observations=(observation,),
            )
        )
        assert isinstance(persisted, PersistRiskObservationsResponse)

        first_run = harness.ids.uuid7()
        generation = worker.call(
            BeginGenerationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=first_turn,
                run_id=first_run,
            )
        )
        assert isinstance(generation, BeginGenerationResponse)
        candidates = worker.call(
            StoreCandidateSetRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=first_turn,
                run_id=first_run,
                idempotency_key="risk-persistence-first-candidates",
                candidates=(
                    CandidateDraft(label="one", text="candidate one"),
                    CandidateDraft(label="two", text="candidate two"),
                ),
            )
        )
        assert isinstance(candidates, StoreCandidateSetResponse)
        closed = worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=first_turn,
                idempotency_key="risk-persistence-first-close",
                mode="external_unknown",
                confirmed_at=datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc),
            )
        )
        assert isinstance(closed, RecordActualReplyResponse)

        second_turn = harness.ids.uuid7()
        second_run = harness.ids.uuid7()
        second = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=second_turn,
                client_message="ordinary follow-up with no new risk hit",
                risk_authority=RISK_AUTHORITY,
            )
        )
        assert isinstance(second, AppendClientTurnResponse)
        _complete_empty_risk_evaluation(harness, worker, turn_id=second_turn)
        binding = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=second_turn,
            )
        )
        assert isinstance(binding, GetGenerationBindingResponse)
        plan = QueryPlan(
            envelope=_envelope(
                "query_plan",
                turn_id=second_turn,
                run_id=second_run,
            ),
            intent="simple_empathic_clarification",
            client_snapshot_ref=binding.binding.client_snapshot_ref,
            global_runtime_epoch=7,
            client_runtime_epoch=binding.binding.client_runtime_epoch,
            tombstone_epoch=binding.binding.client_tombstone_count,
            authorization_epoch=11,
            guardrails=QueryGuardrails(),
            subqueries=(
                Subquery(
                    subquery_id="current_context",
                    category="emotion_needs_relationship",
                    question="What current context supports clarification?",
                    routes=("profile",),
                    required_evidence_types=(),
                    scope="client_private",
                ),
            ),
            route_omissions=tuple(
                RouteOmission(
                    route=route,
                    reason="Not needed for this risk persistence test.",
                )
                for route in (
                    "client_history",
                    "wiki",
                    "lexical",
                    "vector",
                    "global_graph",
                    "case",
                )
            ),
            rationale_summary="Carry visible counselor risk without client output.",
        )
        submitted = _submit(
            harness,
            worker,
            plan,
            key="risk-persistence-second-plan",
        )
        prepared = worker.call(
            PrepareGenerationRetrievalRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=second_turn,
                run_id=second_run,
                query_plan_sha256=submitted.record.artifact.content_sha256,
                risk_authority=RISK_AUTHORITY,
                query_categories=("current_profile",),
            )
        )
        assert isinstance(prepared, PrepareGenerationRetrievalResponse)
        risk = prepared.risk_context_binding
        assert risk.evaluation_observation_ids == ()
        assert risk.evaluation_count == 0
        assert risk.evaluation_set_sha256 == canonical_risk_observation_set_sha256(())
        assert risk.visible_observation_ids == (observation_id,)
        assert risk.visible_count == 1
        assert risk.visible_set_sha256 == canonical_risk_observation_set_sha256(
            (observation,)
        )
        assert risk.authority == RISK_AUTHORITY
    finally:
        worker.close()
        harness.close()


def test_real_worker_requires_acknowledge_before_explicit_risk_close(
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
        message = "synthetic counselor-only risk lifecycle turn"
        appended = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message=message,
                risk_authority=RISK_AUTHORITY,
            )
        )
        assert isinstance(appended, AppendClientTurnResponse)
        rule_ref = ref("risk_rule", 0xD01)
        observation_id = object_id("risk_observation", 0xD02)
        trigger = message[:9]
        normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
            trigger
        )
        observation = InternalRiskObservationRecord(
            session_id=harness.session_id,
            observation=InternalRiskObservation(
                observation_id=observation_id,
                category="synthetic_high_observation",
                level="high",
                trigger_turn_ids=(turn_id,),
                rule_ref=rule_ref,
                detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                suggested_questions=("SYNTH-QUESTION-HIGH-VERIFY",),
            ),
            trigger_spans=(
                RiskTriggerSpan(
                    turn_id=turn_id,
                    content_ref=appended.client_message_ref,
                    start_offset=0,
                    end_offset=9,
                    span_sha256=hashlib.sha256(trigger.encode("utf-8")).hexdigest(),
                    normalized_length=normalized_length,
                    normalized_span_sha256=normalized_span_sha256,
                ),
            ),
            sources=(
                RiskObservationSource(
                    source_kind="deterministic_rule",
                    source_ref=rule_ref,
                ),
            ),
            confidence=1.0,
        )
        persisted = worker.call(
            PersistRiskObservationsRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                risk_authority=RISK_AUTHORITY,
                observations=(observation,),
            )
        )
        assert isinstance(persisted, PersistRiskObservationsResponse)

        close_request = AcknowledgeRiskObservationRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            observation_id=observation_id,
            action="close",
            close_decision="counselor_confirmed_closed",
            close_reason="Counselor reviewed the later context.",
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="RISK_LIFECYCLE_CONFLICT",
        ):
            worker.call(close_request)

        acknowledged = worker.call(
            AcknowledgeRiskObservationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                observation_id=observation_id,
                action="acknowledge",
                counselor_disposition="Continue direct observation.",
            )
        )
        assert isinstance(acknowledged, AcknowledgeRiskObservationResponse)
        assert acknowledged.action == "acknowledge"
        assert acknowledged.observation.status == "acknowledged"

        closed = worker.call(close_request)
        assert isinstance(closed, AcknowledgeRiskObservationResponse)
        assert closed.action == "close"
        assert closed.observation.status == "closed"
        replayed = worker.call(
            close_request.model_copy(update={"request_id": _request_id(harness)})
        )
        assert isinstance(replayed, AcknowledgeRiskObservationResponse)
        assert replayed.observation == closed.observation
    finally:
        worker.close()
        harness.close()


def test_real_worker_recomputes_quality_gates_and_final_cannot_bypass_them(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    worker.start()
    turn_id = harness.ids.uuid7()
    run_id = harness.ids.uuid7()
    global_runtime_epoch = 7
    authorization_epoch = 11
    try:
        begun = worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        assert isinstance(begun, BeginSessionResponse)
        appended = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message=(
                    "I noticed a recent relationship change and feel uncertain "
                    "about what it means."
                ),
                risk_authority=RISK_AUTHORITY,
            )
        )
        assert isinstance(appended, AppendClientTurnResponse)
        _complete_empty_risk_evaluation(harness, worker, turn_id=turn_id)
        temporary = worker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="generation-boundary-temporary-fact",
                event_kind="ISSUE",
                cognitive_type="client_statement",
                value={"current_feeling": "uncertain"},
            )
        )
        assert isinstance(temporary, AppendTemporaryFactResponse)

        binding = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
            )
        )
        assert isinstance(binding, GetGenerationBindingResponse)
        query_plan = QueryPlan(
            envelope=_envelope(
                "query_plan",
                turn_id=turn_id,
                run_id=run_id,
            ),
            intent="simple_empathic_clarification",
            client_snapshot_ref=binding.binding.client_snapshot_ref,
            global_runtime_epoch=global_runtime_epoch,
            client_runtime_epoch=binding.binding.client_runtime_epoch,
            tombstone_epoch=binding.binding.client_tombstone_count,
            authorization_epoch=authorization_epoch,
            guardrails=QueryGuardrails(),
            subqueries=(
                Subquery(
                    subquery_id="current_change",
                    category="emotion_needs_relationship",
                    question="What evidence supports careful clarification?",
                    routes=("wiki",),
                    required_evidence_types=(),
                    scope="global_knowledge",
                ),
            ),
            route_omissions=tuple(
                RouteOmission(route=route, reason="Not needed for this bounded test.")
                for route in (
                    "profile",
                    "client_history",
                    "lexical",
                    "vector",
                    "global_graph",
                    "case",
                )
            ),
            rationale_summary="Use one bounded global source for a simple clarification.",
        )
        plan_response = _submit(
            harness,
            worker,
            query_plan,
            key="generation-boundary-query-plan",
        )
        assert plan_response.retrieval_status == "pending"

        evidence_pack, evidence_context, run_objects = _trusted_pack(
            run_id=run_id,
            binding=binding,
            global_runtime_epoch=global_runtime_epoch,
            authorization_epoch=authorization_epoch,
            with_contradiction=True,
        )
        stored_pack = worker.call(
            StoreGenerationEvidencePackRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=plan_response.record.artifact.content_sha256,
                evidence_pack=evidence_pack,
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
        assert isinstance(stored_pack, StoreGenerationEvidencePackResponse)
        pack_sha256 = evidence_pack_sha256(evidence_pack)
        assert stored_pack.evidence_pack_sha256 == pack_sha256
        assert tuple(
            item
            for item in stored_pack.evidence_context
            if item.context_kind == "retrieved_candidate"
        ) == evidence_context
        temporary_item = next(
            item
            for item in stored_pack.evidence_context
            if item.context_kind == "temporary_fact"
        )
        assert temporary_item.text_ref in evidence_pack.temporary_fact_refs
        assert temporary_item.body == '{"current_feeling":"uncertain"}\n'
        recovered_pack = worker.call(
            GetGenerationEvidenceForPlanRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=plan_response.record.artifact.content_sha256,
            )
        )
        assert isinstance(recovered_pack, GetGenerationEvidenceForPlanResponse)
        assert recovered_pack.ready
        assert recovered_pack.evidence_context == stored_pack.evidence_context
        assert recovered_pack.evidence_context_sha256 == (
            stored_pack.evidence_context_sha256
        )
        assert re.search(
            r"client_[a-z0-9]{12}",
            recovered_pack.model_dump_json(),
        ) is None
        evidence = evidence_pack.supporting[0]
        hard_constraints = derive_hard_constraint_evidence_ids(evidence_pack)
        assert hard_constraints == (evidence.evidence_id,)
        assert not TheoryUsePolicy().decide(
            evidence_pack,
            hard_constraint_evidence_ids=hard_constraints,
        ).specific_advice_allowed

        conceptualization = Conceptualization(
            envelope=_envelope(
                "conceptualization",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=plan_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            items=(
                ConceptualizationItem(
                    item_id="reported_uncertainty",
                    cognitive_type="client_reported",
                    statement=(
                        "The client reports uncertainty about a recent relationship change."
                    ),
                    supporting_evidence_ids=(evidence.evidence_id,),
                    uncertainty="low",
                ),
            ),
            key_emotions=("uncertainty",),
            key_needs=("clarity",),
            alternative_explanations=(
                "The meaning of the reported change is not yet established.",
            ),
            limitations=("Only the current report is available.",),
            rationale_summary="Separate the direct report from any interpretation.",
        )
        concept_response = _submit(
            harness,
            worker,
            conceptualization,
            key="generation-boundary-conceptualization",
        )

        theory = TheoryComparison(
            envelope=_envelope(
                "theory_comparison",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=concept_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            primary_framework=None,
            comparisons=(),
            conflicts=(),
            clarification_questions=(),
            rationale_summary="No active applicable C1 revision is frozen in this pack.",
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                theory,
                key="generation-boundary-theory-omitted-hard-conflict",
            )
        theory = theory.model_copy(
            update={
                "conflicts": (
                    "The frozen pack marks evidence that constrains specific advice.",
                )
            }
        )
        theory_response = _submit(
            harness,
            worker,
            theory,
            key="generation-boundary-theory",
        )

        replies = _reply_drafts(
            envelope=_envelope(
                "reply_drafts",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=theory_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            pack_sha256=pack_sha256,
            evidence=evidence,
        )
        suggestion_replies = replies.model_copy(
            update={
                "candidates": tuple(
                    draft.model_copy(
                        update={
                            "claims": tuple(
                                claim.model_copy(update={"claim_type": "suggestion"})
                                for claim in draft.claims
                            )
                        }
                    )
                    for draft in replies.candidates
                )
            }
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                suggestion_replies,
                key="generation-boundary-specific-advice-blocked",
            )
        forged_replies = replies.model_copy(
            update={
                "candidates": tuple(
                    draft.model_copy(
                        update={"current_fact_ids": ("forged_current_fact",)}
                    )
                    for draft in replies.candidates
                )
            }
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                forged_replies,
                key="generation-boundary-forged-current-facts",
            )
        assert not worker.closed
        assert tuple(
            record.stage
            for record in _state(
                harness,
                worker,
                turn_id=turn_id,
                run_id=run_id,
            ).records
        ) == ("query_plan", "conceptualization", "theory_comparison")
        reply_response = _submit(
            harness,
            worker,
            replies,
            key="generation-boundary-replies",
        )

        premature_final = _final_bundle(
            envelope=_envelope(
                "final_bundle",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=reply_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            pack_sha256=pack_sha256,
            replies=replies,
            evidence_id=evidence.evidence_id,
            quality_evidence_ids=tuple(sorted(bound_evidence_ids(evidence_pack))),
            conflicts=theory.conflicts,
        )
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            _submit(
                harness,
                worker,
                premature_final,
                key="generation-boundary-final-before-audit",
            )
        assert worker.closed

        worker = harness.worker()
        worker.start()
        assert tuple(record.stage for record in _state(
            harness, worker, turn_id=turn_id, run_id=run_id
        ).records) == (
            "query_plan",
            "conceptualization",
            "theory_comparison",
            "reply_drafts",
        )

        audit_envelope = _envelope(
            "evidence_audit",
            turn_id=turn_id,
            run_id=run_id,
            previous_sha256=reply_response.record.artifact.content_sha256,
            pack_sha256=pack_sha256,
        )
        assessments = tuple(
            EvidenceSemanticAssessment(
                claim_scope=scope,
                claim_id=claim_id,
                assessed_claim_type=(
                    "fact" if scope == "analysis" else "important_conclusion"
                ),
                evidence_id=evidence.evidence_id,
                role="support",
                text_start_char=0,
                text_end_char=len(_EVIDENCE_BODY),
                exact_excerpt=_EVIDENCE_BODY,
                excerpt_sha256=hashlib.sha256(
                    _EVIDENCE_BODY.encode("utf-8")
                ).hexdigest(),
                semantic_status="supports",
            )
            for scope, claim_id in (
                ("analysis", "reported_uncertainty"),
                ("reply", "direct_clarification"),
                ("reply", "gentle_clarification"),
            )
        )
        forged_audit = EvidenceAudit(
            envelope=audit_envelope,
            evidence_pack_sha256=pack_sha256,
            assessments=assessments,
            findings=(
                AuditFinding(
                    claim_id="reported_uncertainty",
                    evidence_ids=(evidence.evidence_id,),
                    fidelity="faithful",
                    severity="info",
                ),
            ),
            decision="pass",
            retry_count=0,
            unresolved_reasons=(),
            rationale_summary="Caller-authored pass must not be trusted.",
        )
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            _submit(
                harness,
                worker,
                forged_audit,
                key="generation-boundary-forged-audit",
            )
        assert worker.closed

        auditor = EvidenceAuditor()
        recomputed = auditor.audit_artifacts(
            evidence_pack=evidence_pack,
            conceptualization=conceptualization,
            reply_drafts=replies,
            assessments=assessments,
        )
        exact_audit = EvidenceAudit(
            envelope=audit_envelope,
            evidence_pack_sha256=pack_sha256,
            assessments=assessments,
            findings=tuple(
                auditor._contract_finding(finding)
                for finding in recomputed.findings
            ),
            decision=recomputed.decision,
            retry_count=recomputed.retry_count,
            unresolved_reasons=recomputed.unresolved_reasons,
            rationale_summary="All decision fields come from deterministic recomputation.",
        )
        wrong_excerpt = "X" + _EVIDENCE_BODY[1:]
        forged_source_audit = exact_audit.model_copy(
            update={
                "assessments": (
                    assessments[0].model_copy(
                        update={
                            "exact_excerpt": wrong_excerpt,
                            "excerpt_sha256": hashlib.sha256(
                                wrong_excerpt.encode("utf-8")
                            ).hexdigest(),
                        }
                    ),
                    *assessments[1:],
                )
            }
        )
        worker = harness.worker()
        worker.start()
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            _submit(
                harness,
                worker,
                forged_source_audit,
                key="generation-boundary-forged-audit-source-span",
            )
        assert worker.closed

        worker = harness.worker()
        worker.start()
        audit_response = _submit(
            harness,
            worker,
            exact_audit,
            key="generation-boundary-exact-audit",
        )
        assert audit_response.record.payload == exact_audit

        final_without_consistency = _final_bundle(
            envelope=_envelope(
                "final_bundle",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=audit_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            pack_sha256=pack_sha256,
            replies=replies,
            evidence_id=evidence.evidence_id,
            quality_evidence_ids=tuple(sorted(bound_evidence_ids(evidence_pack))),
            conflicts=theory.conflicts,
        )
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            _submit(
                harness,
                worker,
                final_without_consistency,
                key="generation-boundary-final-before-consistency",
            )
        assert worker.closed

        worker = harness.worker()
        worker.start()
        assert tuple(record.stage for record in _state(
            harness, worker, turn_id=turn_id, run_id=run_id
        ).records)[-1] == "evidence_audit"

        consistency_envelope = _envelope(
            "consistency_risk_review",
            turn_id=turn_id,
            run_id=run_id,
            previous_sha256=audit_response.record.artifact.content_sha256,
            pack_sha256=pack_sha256,
        )
        conflicting_snapshots = _snapshots(replies, hide_conflict=True)
        forged_consistency = ConsistencyRiskReview(
            envelope=consistency_envelope,
            evidence_pack_sha256=pack_sha256,
            current_candidate_snapshots=conflicting_snapshots,
            semantic_assessments=current_consistency_assessments(
                replies,
                conflicting_snapshots,
            ),
            consistency_findings=(),
            risk_observation_ids=(),
            decision="pass",
            retry_count=0,
            unresolved_reasons=(),
            rationale_summary="Caller-authored pass hides opposing structured stances.",
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                forged_consistency,
                key="generation-boundary-forged-consistency",
            )
        assert worker.is_alive
        assert tuple(record.stage for record in _state(
            harness, worker, turn_id=turn_id, run_id=run_id
        ).records)[-1] == "evidence_audit"

        consistent_snapshots = _snapshots(replies, hide_conflict=False)
        consistency_result = ConsistencyReviewer().review(
            current_candidates=consistent_snapshots,
        )
        validator = GenerationConsistencyValidator()
        snapshots_by_key = {
            snapshot.snapshot_key: snapshot for snapshot in consistent_snapshots
        }
        exact_consistency = ConsistencyRiskReview(
            envelope=consistency_envelope,
            evidence_pack_sha256=pack_sha256,
            current_candidate_snapshots=consistent_snapshots,
            semantic_assessments=current_consistency_assessments(
                replies,
                consistent_snapshots,
            ),
            consistency_findings=tuple(
                validator._project_finding(index, finding, snapshots_by_key)
                for index, finding in enumerate(
                    consistency_result.findings,
                    start=1,
                )
            ),
            conclusion_changes=consistency_result.conclusion_changes,
            risk_observation_ids=(),
            decision=consistency_result.decision,
            retry_count=consistency_result.retry_count,
            unresolved_reasons=validator._unresolved_reasons(
                consistency_result.decision
            ),
            rationale_summary="Structured consistency fields are recomputed exactly.",
        )
        consistency_response = _submit(
            harness,
            worker,
            exact_consistency,
            key="generation-boundary-exact-consistency",
        )

        final_bundle = _final_bundle(
            envelope=_envelope(
                "final_bundle",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=consistency_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            pack_sha256=pack_sha256,
            replies=replies,
            evidence_id=evidence.evidence_id,
            quality_evidence_ids=tuple(sorted(bound_evidence_ids(evidence_pack))),
            conflicts=theory.conflicts,
        )
        forged_internal = final_bundle.model_copy(
            update={
                "counselor_internal": final_bundle.counselor_internal.model_copy(
                    update={"summary": "A caller-authored opposite summary."}
                )
            }
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                forged_internal,
                key="generation-boundary-forged-final-internal",
            )
        forged_quality = final_bundle.model_copy(
            update={
                "evidence_quality": final_bundle.evidence_quality.model_copy(
                    update={
                        "status": "limited",
                        "unresolved_reasons": ("Caller-authored limitation.",),
                        "retry_count": 2,
                    }
                )
            }
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_STAGE_CONFLICT",
        ):
            _submit(
                harness,
                worker,
                forged_quality,
                key="generation-boundary-forged-final-quality",
            )
        final_response = _submit(
            harness,
            worker,
            final_bundle,
            key="generation-boundary-final-after-quality-gates",
        )
        assert final_response.turn_state == "awaiting_actual_reply"
        assert len(final_response.candidate_ids) == 2
        assert tuple(
            item.persistent_candidate_id
            for item in final_response.candidate_bindings
        ) == final_response.candidate_ids
        assert tuple(
            item.logical_candidate_id
            for item in final_response.candidate_bindings
        ) == tuple(
            item.candidate_id for item in final_bundle.client_reply_candidates
        )
        assert tuple(record.stage for record in _state(
            harness, worker, turn_id=turn_id, run_id=run_id
        ).records) == (
            "query_plan",
            "conceptualization",
            "theory_comparison",
            "reply_drafts",
            "evidence_audit",
            "consistency_risk_review",
            "final_bundle",
        )
    finally:
        worker.close()


def test_real_worker_rejects_old_pack_after_temporary_fact_changes(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    worker.start()
    turn_id = harness.ids.uuid7()
    run_id = harness.ids.uuid7()
    try:
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="The current situation may need correction.",
                risk_authority=RISK_AUTHORITY,
            )
        )
        _complete_empty_risk_evaluation(harness, worker, turn_id=turn_id)
        binding = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
            )
        )
        assert isinstance(binding, GetGenerationBindingResponse)
        plan = QueryPlan(
            envelope=_envelope("query_plan", turn_id=turn_id, run_id=run_id),
            intent="simple_empathic_clarification",
            client_snapshot_ref=binding.binding.client_snapshot_ref,
            global_runtime_epoch=7,
            client_runtime_epoch=binding.binding.client_runtime_epoch,
            tombstone_epoch=binding.binding.client_tombstone_count,
            authorization_epoch=11,
            guardrails=QueryGuardrails(),
            subqueries=(
                Subquery(
                    subquery_id="fact_change",
                    category="emotion_needs_relationship",
                    question="Which current fact now applies?",
                    routes=("wiki",),
                    required_evidence_types=(),
                    scope="global_knowledge",
                ),
            ),
            route_omissions=tuple(
                RouteOmission(
                    route=route,
                    reason="Not needed for this stale-pack boundary test.",
                )
                for route in (
                    "profile",
                    "client_history",
                    "lexical",
                    "vector",
                    "global_graph",
                    "case",
                )
            ),
            rationale_summary="Freeze the facts used by this retrieval run.",
        )
        plan_response = _submit(
            harness,
            worker,
            plan,
            key="generation-stale-pack-plan",
        )
        evidence_pack, evidence_context, run_objects = _trusted_pack(
            run_id=run_id,
            binding=binding,
            global_runtime_epoch=7,
            authorization_epoch=11,
        )
        worker.call(
            StoreGenerationEvidencePackRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=plan_response.record.artifact.content_sha256,
                evidence_pack=evidence_pack,
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
        worker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="generation-stale-pack-new-fact",
                event_kind="CORRECT",
                cognitive_type="client_statement",
                value={"relationship_status": "changed"},
                target_fact_id="relationship_status",
                target_fact_version=1,
            )
        )
        pack_sha256 = evidence_pack_sha256(evidence_pack)
        evidence = evidence_pack.supporting[0]
        stale_conceptualization = Conceptualization(
            envelope=_envelope(
                "conceptualization",
                turn_id=turn_id,
                run_id=run_id,
                previous_sha256=plan_response.record.artifact.content_sha256,
                pack_sha256=pack_sha256,
            ),
            evidence_pack_sha256=pack_sha256,
            items=(
                ConceptualizationItem(
                    item_id="old_pack_fact",
                    cognitive_type="client_reported",
                    statement="This item is bound to the now-stale evidence run.",
                    supporting_evidence_ids=(evidence.evidence_id,),
                    uncertainty="low",
                ),
            ),
            key_emotions=("uncertainty",),
            key_needs=("clarity",),
            alternative_explanations=(),
            limitations=("A new fact arrived after retrieval.",),
            rationale_summary="This artifact must not survive a changed fact set.",
        )

        with pytest.raises(
            WorkflowOperationalError,
            match="GENERATION_BINDING_MISMATCH",
        ):
            worker.call(
                SubmitGenerationStageRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    idempotency_key="generation-stale-pack-conceptualization",
                    stage_payload=stale_conceptualization,
                )
            )
    finally:
        worker.close()
        harness.close()
