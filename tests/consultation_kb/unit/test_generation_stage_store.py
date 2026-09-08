from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import (
    ClientReplyCandidate,
    Conceptualization,
    ConceptualizationItem,
    ConsistencyRiskReview,
    CounselorInternalAnalysis,
    EvidenceAudit,
    EvidenceQualitySummary,
    FinalTurnBundle,
    FollowUpGuidance,
    QueryGuardrails,
    QueryPlan,
    ReplyClaim,
    ReplyDraft,
    ReplyDraftSet,
    RouteOmission,
    Subquery,
    TheoryComparison,
)
from consultation_kb.generation.stage_store import (
    CandidateSetTransactionFinalizer,
    FinalBundleFinalizer,
    GenerationStageConflict,
    GenerationStageRevisionRequired,
    GenerationStageStore,
    GenerationTurnContext,
    PreparedFinalCandidateSet,
)
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.generation.state_machine import (
    GenerationParentMismatch,
    GenerationRetrySequenceError,
    GenerationStageOrderError,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.consistency import (
    ActionDirection,
    ConsistencySnapshot,
    CorePosition,
    FactPosition,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.models.session import CandidateSet
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.unit.p6_quality_support import (
    current_consistency_assessments,
)


SESSION_ID = "018f0000-0000-7000-8000-000000000101"
TURN_ID = "018f0000-0000-7000-8000-000000000102"
RUN_ID = "018f0000-0000-7000-8000-000000000103"
EVIDENCE_ID = "evidence_018f0000-0000-7000-8000-000000000104"
PACK_HASH = "e" * 64
NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


def _envelope(stage: str, *parents: str) -> GenerationStageEnvelope:
    return GenerationStageEnvelope.model_validate(
        {
            "stage": stage,
            "turn_id": TURN_ID,
            "run_id": RUN_ID,
            "parent_sha256s": tuple(sorted(parents)),
            "created_at": NOW,
        }
    )


def _query() -> QueryPlan:
    return QueryPlan(
        envelope=_envelope("query_plan"),
        intent="simple_empathic_clarification",
        client_snapshot_ref=VersionRef(
            object_id="client_snapshot_018f0000-0000-7000-8000-000000000105",
            version=1,
            content_sha256="a" * 64,
        ),
        global_runtime_epoch=1,
        client_runtime_epoch=1,
        tombstone_epoch=1,
        authorization_epoch=1,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="emotion",
                category="emotion_needs_relationship",
                question="What should be clarified first?",
                routes=("profile",),
                required_evidence_types=(),
                scope="client_private",
            ),
        ),
        route_omissions=tuple(
            RouteOmission(route=route, reason="not needed this turn")
            for route in (
                "client_history",
                "wiki",
                "lexical",
                "vector",
                "global_graph",
                "case",
            )
        ),
        rationale_summary="Use the smallest sufficient plan.",
    )


def _conceptualization(parent: str) -> Conceptualization:
    return Conceptualization(
        envelope=_envelope("conceptualization", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        items=(
            ConceptualizationItem(
                item_id="reported_uncertainty",
                cognitive_type="client_reported",
                statement="The client reports uncertainty.",
                supporting_evidence_ids=(EVIDENCE_ID,),
                uncertainty="low",
            ),
        ),
        key_emotions=("uncertainty",),
        key_needs=("clarity",),
        alternative_explanations=(),
        limitations=("The desired outcome is not yet clear.",),
        rationale_summary="Keep the report distinct from interpretation.",
    )


def _theory(parent: str) -> TheoryComparison:
    return TheoryComparison(
        envelope=_envelope("theory_comparison", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        primary_framework=None,
        comparisons=(),
        conflicts=(),
        clarification_questions=("Which outcome matters most?",),
        rationale_summary="Clarify the goal before selecting a framework.",
    )


def _reply(parent: str) -> ReplyDraftSet:
    gentle_text = "We can slow down and first name what feels most difficult."
    direct_text = "Which one question must be answered before you decide?"
    return ReplyDraftSet(
        envelope=_envelope("reply_drafts", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        candidates=(
            ReplyDraft(
                candidate_id="gentle",
                strategy="gentle_empathy",
                text=gentle_text,
                core_positions=("clarify_before_action",),
                current_fact_ids=("reported_uncertainty",),
                action_directions=("ask_one_question",),
                evidence_ids=(EVIDENCE_ID,),
                claims=(
                    ReplyClaim(
                        claim_id="gentle_body",
                        claim_type="important_conclusion",
                        statement=gentle_text,
                        evidence_ids=(EVIDENCE_ID,),
                        evidence_fidelity="interpretation",
                        text_start_char=0,
                        text_end_char=len(gentle_text),
                        text_sha256=text_sha256(gentle_text),
                    ),
                ),
            ),
            ReplyDraft(
                candidate_id="direct",
                strategy="direct_clarification",
                text=direct_text,
                core_positions=("clarify_before_action",),
                current_fact_ids=("reported_uncertainty",),
                action_directions=("ask_one_question",),
                evidence_ids=(EVIDENCE_ID,),
                claims=(
                    ReplyClaim(
                        claim_id="direct_body",
                        claim_type="open_question",
                        statement=direct_text,
                        evidence_ids=(),
                        evidence_fidelity="not_applicable",
                        text_start_char=0,
                        text_end_char=len(direct_text),
                        text_sha256=text_sha256(direct_text),
                        safe_template_id="which_question_before_deciding",
                    ),
                ),
            ),
        ),
        shared_core_positions=("clarify_before_action",),
        shared_action_directions=("ask_one_question",),
        rationale_summary="Vary tone without changing the conclusion.",
    )


def _audit(parent: str) -> EvidenceAudit:
    return EvidenceAudit(
        envelope=_envelope("evidence_audit", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        assessments=(),
        findings=(),
        decision="pass",
        rationale_summary="The structured reply claim resolves to the evidence pack.",
    )


def _review(parent: str) -> ConsistencyRiskReview:
    replies = _reply("d" * 64)
    snapshots = tuple(
        ConsistencySnapshot(
            snapshot_key=item.candidate_id,
            source="current_candidate",
            facts=tuple(
                FactPosition(
                    fact_key=fact_id,
                    state="affirmed",
                    evidence_ids=item.evidence_ids,
                )
                for fact_id in item.current_fact_ids
            ),
            core_positions=tuple(
                CorePosition(position_key=key, stance="support")
                for key in item.core_positions
            ),
            action_directions=tuple(
                ActionDirection(action_key=key, disposition="pursue")
                for key in item.action_directions
            ),
            conclusion=item.text,
            conclusion_evidence_ids=item.evidence_ids,
        )
        for item in replies.candidates
    )
    return ConsistencyRiskReview(
        envelope=_envelope("consistency_risk_review", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        current_candidate_snapshots=snapshots,
        semantic_assessments=current_consistency_assessments(replies, snapshots),
        consistency_findings=(),
        risk_observation_ids=(),
        decision="pass",
        rationale_summary="Core positions and actions match.",
    )


def _final(parent: str, replies: ReplyDraftSet) -> FinalTurnBundle:
    return FinalTurnBundle(
        envelope=_envelope("final_bundle", parent, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        counselor_internal=CounselorInternalAnalysis(
            summary="Clarify the immediate need before choosing an action.",
            key_fact_ids=("reported_uncertainty",),
            hypotheses=(),
            conflicts=(),
            uncertainty=("The desired outcome is unknown.",),
            evidence_ids=(EVIDENCE_ID,),
        ),
        client_reply_candidates=tuple(
            ClientReplyCandidate(
                candidate_id=item.candidate_id,
                label=item.candidate_id,
                strategy=item.strategy,
                text=item.text,
                core_positions=item.core_positions,
                action_directions=item.action_directions,
            )
            for item in replies.candidates
        ),
        follow_up_guidance=FollowUpGuidance(
            suggested_questions=("Which answer would help most now?",),
            optional_actions=("Write down one immediate question.",),
            observation_focus=("Notice whether urgency changes.",),
            next_steps=("Explore the selected question.",),
        ),
        evidence_quality=EvidenceQualitySummary(
            status="sufficient",
            evidence_ids=(EVIDENCE_ID,),
            unresolved_reasons=(),
        ),
    )


def _store(tmp_path: Path) -> tuple[sqlite3.Connection, SessionRepository, GenerationStageStore, GenerationTurnContext]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(NOW)
    values = iter(range(500, 2_000))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    repository.create_session(
        session_id=SESSION_ID,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="b" * 64,
        snapshot_version=0,
        snapshot_canonical_sha256="c" * 64,
        snapshot_bytes=b'{"empty":true}\n',
    )
    TurnService(repository).append(SESSION_ID, TURN_ID, "I do not know what to do.")
    context = GenerationTurnContext(session_id=SESSION_ID, turn_id=TURN_ID, run_id=RUN_ID)
    return connection, repository, GenerationStageStore(repository), context


def _submit_until_review(
    store: GenerationStageStore,
    context: GenerationTurnContext,
) -> tuple[ReplyDraftSet, str]:
    query = store.submit(context, stage="query_plan", payload=_query())
    concept = store.submit(
        context,
        stage="conceptualization",
        payload=_conceptualization(query.artifact.content_sha256),
    )
    theory = store.submit(
        context,
        stage="theory_comparison",
        payload=_theory(concept.artifact.content_sha256),
    )
    reply_payload = _reply(theory.artifact.content_sha256)
    reply = store.submit(context, stage="reply_drafts", payload=reply_payload)
    audit = store.submit(
        context,
        stage="evidence_audit",
        payload=_audit(reply.artifact.content_sha256),
    )
    review = store.submit(
        context,
        stage="consistency_risk_review",
        payload=_review(audit.artifact.content_sha256),
    )
    return reply_payload, review.artifact.content_sha256


def test_stage_store_enforces_order_parent_closure_and_append_only_revision(tmp_path: Path) -> None:
    connection, repository, store, context = _store(tmp_path)
    try:
        with pytest.raises(GenerationStageOrderError):
            store.submit(context, stage="reply_drafts", payload=_reply("d" * 64))

        first = store.submit(
            context,
            stage="query_plan",
            payload=_query(),
            idempotency_key="query-1",
        )
        assert first.revision == 1
        assert repository.get_turn(SESSION_ID, TURN_ID).state == "generation_in_progress"
        assert store.submit(
            context,
            stage="query_plan",
            payload=_query(),
            idempotency_key="query-1",
        ) == first

        changed = _query().model_copy(update={"rationale_summary": "A revised minimal route explanation."})
        with pytest.raises(GenerationStageConflict, match="GENERATION_STAGE_IDEMPOTENCY_CONFLICT"):
            store.submit(
                context,
                stage="query_plan",
                payload=changed,
                idempotency_key="query-1",
                revision_reason="correct route explanation",
            )
        with pytest.raises(GenerationStageRevisionRequired):
            store.submit(
                context,
                stage="query_plan",
                payload=changed,
                idempotency_key="query-2",
            )
        second = store.submit(
            context,
            stage="query_plan",
            payload=changed,
            idempotency_key="query-2",
            revision_reason="correct route explanation",
        )
        history = store.get_revision_history(context, stage="query_plan")
        assert second.revision == 2
        assert tuple(item.revision for item in history) == (1, 2)
        assert history[0].artifact.content_sha256 == first.artifact.content_sha256
        assert second.revision_reason is not None
        assert repository.read_content(second.revision_reason)

        with pytest.raises(GenerationParentMismatch):
            store.submit(
                context,
                stage="conceptualization",
                payload=_conceptualization(first.artifact.content_sha256),
            )
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(generation_stage_revisions)"
            ).fetchall()
        }
        assert not {"payload", "body", "content"} & columns
    finally:
        connection.close()


def test_reusing_historical_stage_body_is_explicitly_rejected(
    tmp_path: Path,
) -> None:
    connection, _repository, store, context = _store(tmp_path)
    try:
        original_payload = _query()
        original = store.submit(
            context,
            stage="query_plan",
            payload=original_payload,
        )
        changed_payload = original_payload.model_copy(
            update={"rationale_summary": "Use the revised route for this attempt."}
        )
        changed = store.submit(
            context,
            stage="query_plan",
            payload=changed_payload,
            idempotency_key="query-revision-two",
            revision_reason="revise the route",
        )

        with pytest.raises(
            GenerationStageConflict,
            match="GENERATION_STAGE_IDEMPOTENCY_STALE",
        ):
            store.submit(
                context,
                stage="query_plan",
                payload=original_payload,
                revision_reason="restore the earlier route after review",
            )
        with pytest.raises(
            GenerationStageConflict,
            match="GENERATION_STAGE_HISTORICAL_ARTIFACT",
        ):
            store.submit(
                context,
                stage="query_plan",
                payload=original_payload,
                idempotency_key="new-key-for-historical-body",
                revision_reason="restore the earlier route after review",
            )

        assert (original.revision, changed.revision) == (1, 2)
        assert store.get_latest(context, stage="query_plan") == changed
        assert store.get_revision_history(context, stage="query_plan") == (
            original,
            changed,
        )
    finally:
        connection.close()


def test_active_stage_body_cannot_register_an_unpersisted_idempotency_alias(
    tmp_path: Path,
) -> None:
    connection, _repository, store, context = _store(tmp_path)
    try:
        original_payload = _query()
        original = store.submit(
            context,
            stage="query_plan",
            payload=original_payload,
            idempotency_key="query-key-one",
        )

        with pytest.raises(
            GenerationStageConflict,
            match="GENERATION_STAGE_IDEMPOTENCY_CONFLICT",
        ):
            store.submit(
                context,
                stage="query_plan",
                payload=original_payload,
                idempotency_key="query-key-two",
            )

        changed_payload = original_payload.model_copy(
            update={"rationale_summary": "A different route explanation."}
        )
        changed = store.submit(
            context,
            stage="query_plan",
            payload=changed_payload,
            idempotency_key="query-key-two",
            revision_reason="correct the route explanation",
        )

        assert (original.revision, changed.revision) == (1, 2)
        assert store.submit(
            context,
            stage="query_plan",
            payload=changed_payload,
            idempotency_key="query-key-two",
        ) == changed
    finally:
        connection.close()


class _FailingFinalizer(FinalBundleFinalizer):
    def __init__(self, delegate: CandidateSetTransactionFinalizer) -> None:
        self._delegate = delegate

    def prepare(
        self,
        context: GenerationTurnContext,
        payload: FinalTurnBundle,
        *,
        idempotency_key: str,
    ) -> PreparedFinalCandidateSet:
        return self._delegate.prepare(context, payload, idempotency_key=idempotency_key)

    def finalize_in_transaction(
        self,
        prepared: PreparedFinalCandidateSet,
    ) -> CandidateSet:
        del prepared
        raise RuntimeError("injected finalizer failure")


def test_final_bundle_and_candidate_turn_states_share_one_transaction(tmp_path: Path) -> None:
    connection, repository, store, context = _store(tmp_path)
    try:
        replies, review_hash = _submit_until_review(store, context)
        payload = _final(review_hash, replies)
        failing = GenerationStageStore(
            repository,
            finalizer=_FailingFinalizer(CandidateSetTransactionFinalizer(repository)),
        )
        with pytest.raises(RuntimeError, match="injected finalizer failure"):
            failing.submit(context, stage="final_bundle", payload=payload)

        assert repository.get_turn(SESSION_ID, TURN_ID).state == "generation_in_progress"
        assert store.get_revision_history(context, stage="final_bundle") == ()
        assert connection.execute("SELECT count(*) FROM candidate_sets").fetchone() == (0,)

        final = store.submit(context, stage="final_bundle", payload=payload)
        assert final.stage == "final_bundle"
        assert repository.get_turn(SESSION_ID, TURN_ID).state == "awaiting_actual_reply"
        candidate_set = repository.get_candidate_set(SESSION_ID, TURN_ID)
        assert len(candidate_set.candidates) == 2
        assert store.submit(context, stage="final_bundle", payload=payload) == final
        assert connection.execute("SELECT count(*) FROM candidate_sets").fetchone() == (1,)

        changed_reply = replies.model_copy(
            update={"rationale_summary": "This change is too late after finalization."}
        )
        with pytest.raises(
            GenerationStageConflict,
            match="GENERATION_STAGE_REVISION_CLOSED",
        ):
            store.submit(
                context,
                stage="reply_drafts",
                payload=changed_reply,
                idempotency_key="reply-after-final",
                revision_reason="late correction",
            )
    finally:
        connection.close()


def test_early_revision_invalidates_downstream_until_chain_is_rebuilt(tmp_path: Path) -> None:
    connection, repository, store, context = _store(tmp_path)
    try:
        query = store.submit(context, stage="query_plan", payload=_query())
        concept = store.submit(
            context,
            stage="conceptualization",
            payload=_conceptualization(query.artifact.content_sha256),
        )
        theory = store.submit(
            context,
            stage="theory_comparison",
            payload=_theory(concept.artifact.content_sha256),
        )
        reply_payload = _reply(theory.artifact.content_sha256)
        reply = store.submit(context, stage="reply_drafts", payload=reply_payload)
        retry_audit = _audit(reply.artifact.content_sha256).model_copy(
            update={
                "decision": "rewrite",
                "unresolved_reasons": ("The wording needs a narrower claim.",),
            }
        )
        audit = store.submit(
            context,
            stage="evidence_audit",
            payload=retry_audit,
        )
        assert audit.revision == 1

        revised_reply_payload = reply_payload.model_copy(
            update={"rationale_summary": "Narrow the important conclusion before audit."}
        )
        revised_reply = store.submit(
            context,
            stage="reply_drafts",
            payload=revised_reply_payload,
            idempotency_key="reply-revision-2",
            revision_reason="evidence audit requested rewrite",
        )
        assert revised_reply.revision == 2
        assert tuple(item.stage for item in store.list_records(context)) == (
            "query_plan",
            "conceptualization",
            "theory_comparison",
            "reply_drafts",
        )
        with pytest.raises(KeyError):
            store.get_latest(context, stage="evidence_audit")
        assert len(store.get_revision_history(context, stage="evidence_audit")) == 1

        reset_audit_payload = _audit(revised_reply.artifact.content_sha256)
        with pytest.raises(GenerationRetrySequenceError):
            store.submit(
                context,
                stage="evidence_audit",
                payload=reset_audit_payload,
                idempotency_key="audit-invalid-reset",
                revision_reason="invalid retry reset",
            )
        revised_audit_payload = reset_audit_payload.model_copy(
            update={"retry_count": 1}
        )
        with pytest.raises(GenerationStageRevisionRequired):
            store.submit(
                context,
                stage="evidence_audit",
                payload=revised_audit_payload,
                idempotency_key="audit-revision-2",
            )
        revised_audit = store.submit(
            context,
            stage="evidence_audit",
            payload=revised_audit_payload,
            idempotency_key="audit-revision-2",
            revision_reason="re-audit rewritten reply",
        )
        assert revised_audit.revision == 2
        assert store.get_latest(context, stage="evidence_audit") == revised_audit
        assert repository.get_turn(SESSION_ID, TURN_ID).state == "generation_in_progress"
    finally:
        connection.close()
