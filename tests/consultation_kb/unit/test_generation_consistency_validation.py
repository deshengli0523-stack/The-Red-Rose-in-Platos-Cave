from __future__ import annotations

import pytest

from consultation_kb.generation.consistency import ConsistencyReviewer
from consultation_kb.generation.consistency_validation import (
    GenerationConsistencyValidationError,
    GenerationConsistencyValidator,
)
from consultation_kb.generation.contracts import (
    ConsistencyRiskReview,
    ConsistencySemanticAssessment,
)
from consultation_kb.generation.evidence_registry import GenerationEvidenceContextItem
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.consistency import (
    ActionDirection,
    ConclusionChangeRecord,
    ConsistencySnapshot,
    CorePosition,
    FactPosition,
)

from tests.consultation_kb.unit.p6_quality_support import candidate, envelope, pack
from tests.consultation_kb.unit.test_reply_drafts import _drafts


def _pack_with_context(evidence_pack=None):
    base = evidence_pack or pack()
    bodies: dict[str, str] = {}

    def bind(item):
        body = f"Frozen evidence body for {item.evidence_id}."
        bodies[item.evidence_id] = body
        return item.model_copy(
            update={
                "text_ref": item.text_ref.model_copy(
                    update={"content_sha256": text_sha256(body)}
                )
            }
        )

    supporting = tuple(bind(item) for item in base.supporting)
    contradicting = tuple(bind(item) for item in base.contradicting)
    bound = base.model_copy(
        update={"supporting": supporting, "contradicting": contradicting}
    )
    items = tuple(sorted((*supporting, *contradicting), key=lambda item: item.evidence_id))
    context = tuple(
        GenerationEvidenceContextItem(
            evidence_id=item.evidence_id,
            context_kind="retrieved_candidate",
            text_ref=item.text_ref,
            body=bodies[item.evidence_id],
        )
        for item in items
    )
    return bound, context


def _current_snapshots(
    evidence_pack=None,
    *,
    conflicting: bool = False,
) -> tuple[ConsistencySnapshot, ...]:
    evidence_pack = evidence_pack or pack()
    replies = _drafts(evidence_pack)
    return tuple(
        ConsistencySnapshot(
            snapshot_key=draft.candidate_id,
            source="current_candidate",
            facts=tuple(
                FactPosition(
                    fact_key=fact_key,
                    state="affirmed",
                    evidence_ids=draft.evidence_ids,
                )
                for fact_key in draft.current_fact_ids
            ),
            core_positions=tuple(
                CorePosition(
                    position_key=position_key,
                    stance=(
                        "oppose"
                        if conflicting and index == 1
                        else "support"
                    ),
                )
                for position_key in draft.core_positions
            ),
            action_directions=tuple(
                ActionDirection(action_key=action_key, disposition="pursue")
                for action_key in draft.action_directions
            ),
            conclusion=draft.text,
            conclusion_evidence_ids=draft.evidence_ids,
        )
        for index, draft in enumerate(replies.candidates)
    )


def _review(
    snapshots: tuple[ConsistencySnapshot, ...],
    *,
    evidence_pack=None,
    session_earlier: tuple[ConsistencySnapshot, ...] = (),
    client_profiles: tuple[ConsistencySnapshot, ...] = (),
    semantic_assessments: tuple[ConsistencySemanticAssessment, ...] | None = None,
    changes: tuple[ConclusionChangeRecord, ...] = (),
) -> ConsistencyRiskReview:
    evidence_pack = evidence_pack or pack()
    replies = _drafts(evidence_pack)
    assessments = (
        _current_semantic_assessment_payloads(snapshots, replies=replies)
        if semantic_assessments is None
        else semantic_assessments
    )
    return ConsistencyRiskReview(
        envelope=envelope("consistency_risk_review"),
        evidence_pack_sha256=canonical_sha256(evidence_pack.model_dump(mode="json")),
        current_candidate_snapshots=snapshots,
        session_earlier_snapshots=session_earlier,
        client_profile_snapshots=client_profiles,
        semantic_assessments=assessments,
        consistency_findings=(),
        conclusion_changes=changes,
        risk_observation_ids=(),
        decision="pass",
        rationale_summary="Structured snapshots are compared deterministically.",
    )


def _current_semantic_assessment_payloads(
    snapshots: tuple[ConsistencySnapshot, ...],
    *,
    replies,
    override: tuple[str, str, str] | None = None,
) -> tuple[ConsistencySemanticAssessment, ...]:
    text_by_candidate = {
        candidate.candidate_id: candidate.text for candidate in replies.candidates
    }
    payloads: list[ConsistencySemanticAssessment] = []
    for snapshot in snapshots:
        text = text_by_candidate[snapshot.snapshot_key]
        for axis_kind, values in (
            ("fact", tuple((item.fact_key, item.state) for item in snapshot.facts)),
            (
                "core_position",
                tuple(
                    (item.position_key, item.stance)
                    for item in snapshot.core_positions
                ),
            ),
            (
                "action_direction",
                tuple(
                    (item.action_key, item.disposition)
                    for item in snapshot.action_directions
                ),
            ),
        ):
            for subject_key, assessed_value in values:
                if override == (snapshot.snapshot_key, axis_kind, subject_key):
                    assessed_value = "oppose"
                payloads.append(
                    ConsistencySemanticAssessment(
                        snapshot_key=snapshot.snapshot_key,
                        axis_kind=axis_kind,
                        subject_key=subject_key,
                        assessed_value=assessed_value,
                        evidence_id=None,
                        text_start_char=0,
                        text_end_char=len(text),
                        exact_excerpt=text,
                        excerpt_sha256=text_sha256(text),
                    )
                )
    return tuple(sorted(payloads, key=lambda item: item.assessment_key()))


def _historical_semantic_assessments(
    snapshot: ConsistencySnapshot,
    *,
    evidence_context: tuple[GenerationEvidenceContextItem, ...],
) -> tuple[ConsistencySemanticAssessment, ...]:
    body_by_id = {item.evidence_id: item.body for item in evidence_context}
    axes = [
        *(
            ('fact', item.fact_key, item.state, evidence_id)
            for item in snapshot.facts
            for evidence_id in item.evidence_ids
        ),
        *(
            ('core_position', item.position_key, item.stance, evidence_id)
            for item in snapshot.core_positions
            for evidence_id in snapshot.conclusion_evidence_ids
        ),
        *(
            ('action_direction', item.action_key, item.disposition, evidence_id)
            for item in snapshot.action_directions
            for evidence_id in snapshot.conclusion_evidence_ids
        ),
        *(
            ("conclusion", "conclusion", "supports_conclusion", evidence_id)
            for evidence_id in snapshot.conclusion_evidence_ids
        ),
    ]
    return tuple(
        sorted(
            (
                ConsistencySemanticAssessment(
                    snapshot_key=snapshot.snapshot_key,
                    axis_kind=axis_kind,
                    subject_key=subject_key,
                    assessed_value=assessed_value,
                    evidence_id=evidence_id,
                    text_start_char=0,
                    text_end_char=len(body_by_id[evidence_id]),
                    exact_excerpt=body_by_id[evidence_id],
                    excerpt_sha256=text_sha256(body_by_id[evidence_id]),
                )
                for axis_kind, subject_key, assessed_value, evidence_id in axes
            ),
            key=lambda item: item.assessment_key(),
        )
    )


def test_valid_current_candidate_snapshots_recompute_to_pass() -> None:
    evidence_pack, evidence_context = _pack_with_context()
    replies = _drafts(evidence_pack)
    snapshots = _current_snapshots(evidence_pack)

    GenerationConsistencyValidator().require_valid(
        _review(snapshots, evidence_pack=evidence_pack),
        reply_drafts=replies,
        evidence_pack=evidence_pack,
        evidence_context=evidence_context,
    )


def test_current_snapshot_semantics_cannot_disagree_with_exact_reply_span() -> None:
    evidence_pack, evidence_context = _pack_with_context()
    replies = _drafts(evidence_pack)
    snapshots = _current_snapshots(evidence_pack)
    first = snapshots[0].core_positions[0]
    forged = _review(snapshots, evidence_pack=evidence_pack).model_copy(
        update={
            "semantic_assessments": _current_semantic_assessment_payloads(
                snapshots,
                replies=replies,
                override=(snapshots[0].snapshot_key, "core_position", first.position_key),
            )
        }
    )

    with pytest.raises(
        GenerationConsistencyValidationError,
        match="CONSISTENCY_SEMANTIC_VALUE_MISMATCH",
    ):
        GenerationConsistencyValidator().require_valid(
            forged,
            reply_drafts=replies,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
        )


def test_fake_pass_cannot_hide_opposing_candidate_stances() -> None:
    evidence_pack, evidence_context = _pack_with_context()
    replies = _drafts(evidence_pack)
    snapshots = _current_snapshots(evidence_pack, conflicting=True)

    with pytest.raises(
        GenerationConsistencyValidationError,
        match="RECOMPUTATION_MISMATCH",
    ):
        GenerationConsistencyValidator().require_valid(
            _review(snapshots, evidence_pack=evidence_pack),
            reply_drafts=replies,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
        )


def test_exact_rewrite_findings_are_accepted_for_candidate_conflict() -> None:
    evidence_pack, evidence_context = _pack_with_context()
    replies = _drafts(evidence_pack)
    snapshots = _current_snapshots(evidence_pack, conflicting=True)
    result = ConsistencyReviewer().review(current_candidates=snapshots)
    validator = GenerationConsistencyValidator()
    by_key = {item.snapshot_key: item for item in snapshots}
    exact = _review(snapshots, evidence_pack=evidence_pack).model_copy(
        update={
            "consistency_findings": tuple(
                validator._project_finding(index, finding, by_key)
                for index, finding in enumerate(result.findings, start=1)
            ),
            "decision": result.decision,
            "unresolved_reasons": ("unresolved_conflict",),
        }
    )

    validator.require_valid(
        exact,
        reply_drafts=replies,
        evidence_pack=evidence_pack,
        evidence_context=evidence_context,
    )


def test_history_evidence_cannot_be_omitted_and_change_requires_both_sides() -> None:
    current = candidate(1)
    raw_historical = candidate(2)
    raw_historical_second = candidate(3)
    historical = raw_historical.model_copy(
        update={
            "channel": "client_history",
            "provenance": raw_historical.provenance.model_copy(
                update={
                    "provenance_scope": "client_private",
                    "source_count": 0,
                    "passage_count": 0,
                    "case_count": 0,
                    "case_contributor_count": 0,
                    "independent_source_count": 0,
                    "client_exclusion_status": "current_subject_private",
                }
            ),
        }
    )
    historical_second = raw_historical_second.model_copy(
        update={
            "channel": "client_history",
            "provenance": raw_historical_second.provenance.model_copy(
                update={
                    "provenance_scope": "client_private",
                    "source_count": 0,
                    "passage_count": 0,
                    "case_count": 0,
                    "case_contributor_count": 0,
                    "independent_source_count": 0,
                    "client_exclusion_status": "current_subject_private",
                }
            ),
        }
    )
    evidence_pack, evidence_context = _pack_with_context(
        pack(supporting=(current, historical, historical_second))
    )
    replies = _drafts(evidence_pack)
    current_snapshots = _current_snapshots(evidence_pack)
    history_snapshot = ConsistencySnapshot(
        snapshot_key="earlier_turn",
        source="session_earlier",
        facts=(
            FactPosition(
                fact_key="current_relationship_change",
                state="affirmed",
                evidence_ids=tuple(
                    sorted((historical.evidence_id, historical_second.evidence_id))
                ),
            ),
        ),
        core_positions=(
            CorePosition(
                position_key="clarify_before_deciding",
                stance="oppose",
            ),
        ),
        action_directions=(
            ActionDirection(action_key="gather_timeline", disposition="pursue"),
        ),
        conclusion="Earlier advice used the opposite provisional position.",
        conclusion_evidence_ids=tuple(
            sorted((historical.evidence_id, historical_second.evidence_id))
        ),
    )
    validator = GenerationConsistencyValidator()

    with pytest.raises(
        GenerationConsistencyValidationError,
        match="HISTORICAL_EVIDENCE_MISMATCH",
    ):
        validator.require_valid(
            _review(current_snapshots, evidence_pack=evidence_pack),
            reply_drafts=replies,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
        )

    change = ConclusionChangeRecord(
        subject_key="clarify_before_deciding",
        old_conclusion="Do not use clarification as the immediate frame.",
        new_information="The current turn adds a directly reported change.",
        change_reason="New current evidence changes the provisional frame.",
        impact_on_advice="Clarification now precedes action.",
        impact_on_profile="Keep the change provisional pending review.",
        follow_up="Ask whether the new report remains true next turn.",
        previous_evidence_ids=(historical.evidence_id,),
        current_evidence_ids=(current.evidence_id,),
    )
    semantic_assessments = tuple(
        sorted(
            (
                *_current_semantic_assessment_payloads(
                    current_snapshots,
                    replies=replies,
                ),
                *_historical_semantic_assessments(
                    history_snapshot,
                    evidence_context=evidence_context,
                ),
            ),
            key=lambda item: item.assessment_key(),
        )
    )
    review = _review(
        current_snapshots,
        evidence_pack=evidence_pack,
        session_earlier=(history_snapshot,),
        semantic_assessments=semantic_assessments,
        changes=(change,),
    )
    validator.require_valid(
        review,
        reply_drafts=replies,
        evidence_pack=evidence_pack,
        evidence_context=evidence_context,
    )

    omitted_pair = next(
        item
        for item in review.semantic_assessments
        if item.snapshot_key == history_snapshot.snapshot_key
        and item.axis_kind == "core_position"
        and item.evidence_id == historical_second.evidence_id
    )
    incomplete = review.model_copy(
        update={
            "semantic_assessments": tuple(
                item
                for item in review.semantic_assessments
                if item != omitted_pair
            )
        }
    )
    with pytest.raises(
        GenerationConsistencyValidationError,
        match="CONSISTENCY_SEMANTIC_ASSESSMENT_SET_MISMATCH",
    ):
        validator.require_valid(
            incomplete,
            reply_drafts=replies,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
        )

    original = next(
        item for item in review.semantic_assessments if item.evidence_id is not None
    )
    forged_excerpt = "x" * len(original.exact_excerpt)
    forged_assessment = original.model_copy(
        update={
            "exact_excerpt": forged_excerpt,
            "excerpt_sha256": text_sha256(forged_excerpt),
        }
    )
    forged = review.model_copy(
        update={
            "semantic_assessments": tuple(
                forged_assessment if item == original else item
                for item in review.semantic_assessments
            )
        }
    )
    with pytest.raises(
        GenerationConsistencyValidationError,
        match="CONSISTENCY_HISTORICAL_SOURCE_MISMATCH",
    ):
        validator.require_valid(
            forged,
            reply_drafts=replies,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
        )


def test_client_profile_snapshot_binds_exact_profile_evidence_context() -> None:
    current = candidate(1)
    raw_profile = candidate(2)
    profile = raw_profile.model_copy(
        update={
            "channel": "profile",
            "provenance": raw_profile.provenance.model_copy(
                update={
                    "provenance_scope": "client_private",
                    "source_count": 0,
                    "passage_count": 0,
                    "case_count": 0,
                    "case_contributor_count": 0,
                    "independent_source_count": 0,
                    "client_exclusion_status": "current_subject_private",
                }
            ),
        }
    )
    evidence_pack, evidence_context = _pack_with_context(
        pack(supporting=(current, profile))
    )
    replies = _drafts(evidence_pack)
    current_snapshots = _current_snapshots(evidence_pack)
    profile_snapshot = ConsistencySnapshot(
        snapshot_key="latest_client_profile",
        source="client_profile",
        facts=(
            FactPosition(
                fact_key="current_relationship_change",
                state="affirmed",
                evidence_ids=(profile.evidence_id,),
            ),
        ),
        core_positions=(
            CorePosition(position_key="clarify_before_deciding", stance="support"),
        ),
        action_directions=(
            ActionDirection(action_key="gather_timeline", disposition="pursue"),
        ),
        conclusion="The latest profile keeps clarification as the working frame.",
        conclusion_evidence_ids=(profile.evidence_id,),
    )
    assessments = tuple(
        sorted(
            (
                *_current_semantic_assessment_payloads(
                    current_snapshots,
                    replies=replies,
                ),
                *_historical_semantic_assessments(
                    profile_snapshot,
                    evidence_context=evidence_context,
                ),
            ),
            key=lambda item: item.assessment_key(),
        )
    )
    review = _review(
        current_snapshots,
        evidence_pack=evidence_pack,
        client_profiles=(profile_snapshot,),
        semantic_assessments=assessments,
    )

    GenerationConsistencyValidator().require_valid(
        review,
        reply_drafts=replies,
        evidence_pack=evidence_pack,
        evidence_context=evidence_context,
    )
