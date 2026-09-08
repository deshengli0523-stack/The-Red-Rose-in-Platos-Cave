from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.archive.profile_diff import (
    ProfileDiffBuildInput,
    ProfileDiffBuilder,
    ProfileDiffDraft,
    ProfileDiffError,
    ProfileMutationCandidate,
    profile_diff_sha256,
)
from consultation_kb.models.archive import (
    ActualTranscript,
    ActualTranscriptTurn,
    actual_transcript_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.dependencies import (
    ImpactItem,
    ImpactProposal,
    RecommendedImpactMutation,
)
from consultation_kb.models.facts import (
    AddMutation,
    ConfirmMutation,
    CorrectMutation,
    FactEvent,
    FactEvidence,
    MergeMutation,
    ResolveMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.profile import (
    ProfileItem,
    ProfileSection,
    ProfileSnapshot,
    profile_sha256,
)
from consultation_kb.models.session import StoredContentRef, TemporaryFactEvent


NOW = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
CHANGE_AT = NOW + timedelta(days=1)
CLIENT_ID = "client_" + "a1b2c3d4e5f6"
SESSION_ID = "018f0000-0000-7000-8000-000000000701"
TURN_ID = "018f0000-0000-7000-8000-000000000702"


def _temporary_event_id(ordinal: int) -> str:
    return f"session_fact_018f0000-0000-7000-8000-00000000072{ordinal}"


def _event(
    event_id: str,
    fact_id: str,
    predicate: str,
    value: object,
    *,
    cognitive_type: str = "client_statement",
    source_kind: str = "session_statement",
    source_event_ids: tuple[str, ...] = (),
    effective_from: datetime = NOW,
) -> FactEvent:
    session_derived = source_kind == "session_derived"
    return FactEvent(
        event_id=event_id,
        fact_id=fact_id,
        client_id=CLIENT_ID,
        event_version=1,
        mutation_type="ADD",
        canonical_key=f"client|{predicate}|{fact_id}",
        subject="client",
        predicate=predicate,
        object_json=canonical_json(value),
        cognitive_type=cognitive_type,
        source_kind=source_kind,
        source_session_id=SESSION_ID,
        source_turn_id=TURN_ID,
        source_ref=None,
        effective_from=effective_from,
        effective_to=None,
        time_precision="day",
        timezone_name="Asia/Shanghai",
        recorded_at=NOW,
        approved_at=NOW,
        reported_at=NOW if source_kind in {"session_statement", "session_derived"} else None,
        observed_at=NOW if source_kind == "session_observation" else None,
        transaction_id="transaction-fixture",
        commit_version=7,
        publication_operation_id="publication-fixture",
        visible_runtime_epoch=7,
        review_status="approved",
        validity_status="active",
        resolution_status="open",
        epistemic_status="asserted" if not session_derived else "uncertain",
        fact_confidence=0.9,
        model_confidence=0.7 if session_derived else None,
        reviewer_id="counselor-fixture",
        review_reason="synthetic approved fixture",
        review_source="primary_counselor",
        privacy_level="private_client",
        allowed_purposes_json=canonical_json(["client_history"]),
        applicability_json=canonical_json({"scope": "client_private"}),
        source_anchor_json=canonical_json({"turn_id": TURN_ID}),
        supersedes_event_id=None,
        previous_event_id=None,
        replacement_event_id=None,
        source_event_ids=source_event_ids,
        relation_type=None,
    )


def _profile_item(event: FactEvent) -> ProfileItem:
    return ProfileItem(
        fact_id=event.fact_id,
        event_id=event.event_id,
        subject=event.subject,
        predicate=event.predicate,
        object_json=event.object_json,
        cognitive_type=event.cognitive_type,
        review_status=event.review_status,
        validity_status=event.validity_status,
        resolution_status=event.resolution_status,
        epistemic_status=event.epistemic_status,
        fact_confidence=event.fact_confidence,
        effective_from=event.effective_from,
        effective_to=event.effective_to,
        recorded_at=event.recorded_at,
        approved_at=event.approved_at,
        source_session_id=event.source_session_id,
        source_turn_id=event.source_turn_id,
        source_event_ids=event.source_event_ids,
    )


def _profile(
    sections: tuple[ProfileSection, ...],
    *,
    commit_version: int,
    source_hash: str,
) -> ProfileSnapshot:
    payload = {
        "schema_version": "client_profile.v1",
        "source_snapshot_sha256": source_hash,
        "source_client_commit_version": commit_version,
        "effective_at": CHANGE_AT.isoformat().replace("+00:00", "Z"),
        "known_at": CHANGE_AT.isoformat().replace("+00:00", "Z"),
        "fixed_epoch": 8,
        "sections": [item.model_dump(mode="json") for item in sections],
        "current_event_ids": [
            item.event_id for section in sections for item in section.items
        ],
    }
    return ProfileSnapshot.model_validate(
        {
            **payload,
            "effective_at": CHANGE_AT,
            "known_at": CHANGE_AT,
            "sections": sections,
            "current_event_ids": tuple(
                item.event_id for section in sections for item in section.items
            ),
            "canonical_sha256": profile_sha256(payload),
        },
        strict=True,
    )


def _candidate(
    ordinal: int,
    operation_id: str,
    mutation: object,
    old_value: object,
    new_value: object,
) -> ProfileMutationCandidate:
    return ProfileMutationCandidate.model_validate(
        {
            "operation_id": operation_id,
            "ordinal": ordinal,
            "mutation": mutation,
            "old_value_json": canonical_json(old_value),
            "new_value_json": canonical_json(new_value),
            "source_temporary_event_id": _temporary_event_id(ordinal),
            "source_content_sha256": f"{ordinal}" * 64,
            "source_turn_id": TURN_ID,
            "source_reason": f"actual session evidence for {operation_id}",
            "evidence_origin": "actual_client_statement",
            "cognitive_type": "client_statement",
            "confidence": 0.9,
        },
        strict=True,
    )


def _actual_transcript() -> ActualTranscript:
    turn = ActualTranscriptTurn(
        ordinal=1,
        turn_id=TURN_ID,
        client_message_ref=VersionRef(
            object_id="client_message_018f0000-0000-7000-8000-000000000711",
            version=1,
            content_sha256="d" * 64,
        ),
        client_message_text="I am now in a different relationship.",
        actual_reply_ref=VersionRef(
            object_id="actual_reply_018f0000-0000-7000-8000-000000000712",
            version=1,
            content_sha256="e" * 64,
        ),
        reply_text="Let us review what changed and what may still apply.",
        reply_source_type="edited",
        evidence_gap=False,
    )
    payload = actual_transcript_payload(
        session_id=SESSION_ID,
        turns=(turn,),
        incomplete_evidence=False,
        captured_at=NOW,
    )
    transcript_sha256 = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return ActualTranscript(
        actual_transcript_ref=VersionRef(
            object_id="actual_transcript_018f0000-0000-7000-8000-000000000713",
            version=1,
            content_sha256=transcript_sha256,
        ),
        session_id=SESSION_ID,
        turns=(turn,),
        incomplete_evidence=False,
        captured_at=NOW,
    )


def _temporary_event(
    ordinal: int,
    operation: str,
    *,
    target_fact_id: str | None,
) -> TemporaryFactEvent:
    return TemporaryFactEvent.model_validate(
        {
            "event_id": _temporary_event_id(ordinal),
            "session_id": SESSION_ID,
            "turn_id": TURN_ID,
            "event_kind": operation,
            "cognitive_type": "client_statement",
            "content": StoredContentRef(
                object_id=(
                    "session_fact_content_018f0000-0000-7000-8000-"
                    f"00000000073{ordinal}"
                ),
                content_sha256=f"{ordinal}" * 64,
                media_type="application/json",
                size_bytes=ordinal,
            ),
            "target_fact_id": target_fact_id,
            "target_fact_version": (
                None if target_fact_id is None else 1
            ),
            "recorded_at": NOW,
        },
        strict=True,
    )


def partner_change_request() -> ProfileDiffBuildInput:
    old_partner = _event(
        "event_old_partner",
        "fact_current_partner",
        "current_partner",
        {"role": "partner_alpha"},
    )
    arrangement = _event(
        "event_weekend_arrangement",
        "fact_weekend_arrangement",
        "weekend_arrangement",
        {"with": "partner_alpha"},
    )
    pattern = _event(
        "event_communication_pattern",
        "fact_communication_pattern",
        "communication_pattern",
        {"pattern": "withdraw_pursue"},
    )
    confirmed = _event(
        "event_confirmed_preference",
        "fact_confirmed_preference",
        "communication_preference",
        {"preference": "direct_clarification"},
    )
    duplicate_one = _event(
        "event_duplicate_one",
        "fact_duplicate_one",
        "support_preference",
        {"preference": "calm_pacing"},
    )
    duplicate_two = _event(
        "event_duplicate_two",
        "fact_duplicate_two",
        "support_preference",
        {"preference": "calm_pacing"},
    )
    resolved_issue = _event(
        "event_resolved_issue",
        "fact_resolved_issue",
        "unresolved_issue",
        {"issue": "whether_to_contact_previous_partner"},
    )
    new_partner = _event(
        "event_new_partner",
        "fact_current_partner_v2",
        "current_partner",
        {"role": "partner_beta"},
        effective_from=CHANGE_AT,
    )
    new_goal = _event(
        "event_new_goal",
        "fact_new_goal",
        "goal",
        {"goal": "build_stable_communication"},
        effective_from=CHANGE_AT,
    )
    merged = _event(
        "event_merged_preference",
        "fact_merged_preference",
        "support_preference",
        {"preference": "calm_pacing"},
        source_event_ids=(duplicate_one.event_id, duplicate_two.event_id),
        effective_from=CHANGE_AT,
    )

    base = _profile(
        (
            ProfileSection(name="relationships", items=(_profile_item(old_partner),)),
            ProfileSection(
                name="preferences",
                items=(
                    _profile_item(confirmed),
                    _profile_item(duplicate_one),
                    _profile_item(duplicate_two),
                ),
            ),
            ProfileSection(
                name="unresolved_issues", items=(_profile_item(resolved_issue),)
            ),
            ProfileSection(
                name="active_facts",
                items=(_profile_item(arrangement), _profile_item(pattern)),
            ),
        ),
        commit_version=7,
        source_hash="a" * 64,
    )
    projected = _profile(
        (
            ProfileSection(name="goals", items=(_profile_item(new_goal),)),
            ProfileSection(
                name="relationships", items=(_profile_item(new_partner),)
            ),
            ProfileSection(
                name="preferences",
                items=(_profile_item(confirmed), _profile_item(merged)),
            ),
            ProfileSection(name="unresolved_issues", items=()),
            ProfileSection(name="active_facts", items=()),
            ProfileSection(name="pending_review", items=(_profile_item(pattern),)),
        ),
        commit_version=8,
        source_hash="b" * 64,
    )

    mutations = (
        AddMutation(new_fact=new_goal),
        ConfirmMutation(
            target_event_id=confirmed.event_id,
            evidence=(
                FactEvidence(
                    evidence_id="evidence-confirmed-preference",
                    source_kind="session_statement",
                    source_ref=f"session:{SESSION_ID}:turn:{TURN_ID}",
                    supports=True,
                    evidence_confidence=0.92,
                ),
            ),
            calibrated_confidence=0.94,
            reason="client reconfirmed the preference",
        ),
        CorrectMutation(
            target_event_id=arrangement.event_id,
            correction_kind="validity",
            previous_value_json=arrangement.object_json,
            previous_validity_status="active",
            new_validity_status="invalidated",
            reason="the arrangement directly depended on the previous partner",
            effective_at=CHANGE_AT,
        ),
        SupersedeMutation(
            target_event_id=old_partner.event_id,
            replacement=new_partner,
            effective_at=CHANGE_AT,
            reason="client reports a current partner change",
        ),
        ResolveMutation(
            target_event_id=resolved_issue.event_id,
            resolved_at=CHANGE_AT,
            reason="the client reports the issue was resolved this session",
        ),
        MergeMutation(
            member_event_ids=(duplicate_one.event_id, duplicate_two.event_id),
            canonical_projection=merged,
            no_conflict_proof="same normalized predicate, value, and validity window",
            reason="duplicate expressions should have one current projection",
        ),
    )
    candidates = (
        _candidate(1, "op-add-goal", mutations[0], None, new_goal.object_value),
        _candidate(
            2,
            "op-confirm-preference",
            mutations[1],
            confirmed.object_value,
            confirmed.object_value,
        ),
        _candidate(
            3,
            "op-correct-arrangement",
            mutations[2],
            arrangement.object_value,
            {"validity": "invalidated"},
        ),
        _candidate(
            4,
            "op-supersede-partner",
            mutations[3],
            old_partner.object_value,
            new_partner.object_value,
        ),
        _candidate(
            5,
            "op-resolve-issue",
            mutations[4],
            resolved_issue.object_value,
            {"status": "resolved"},
        ),
        _candidate(
            6,
            "op-merge-duplicates",
            mutations[5],
            [duplicate_one.object_value, duplicate_two.object_value],
            merged.object_value,
        ),
    )
    impact = ImpactProposal(
        changed_fact_id=old_partner.fact_id,
        old_value="partner_alpha",
        new_value="partner_beta",
        direct_invalidations=(
            ImpactItem(
                fact_id=arrangement.fact_id,
                path_edge_ids=("edge-partner-arrangement",),
                path_confidence=1.0,
                classification="direct_invalidation",
                recommended_mutation=RecommendedImpactMutation(
                    operation="CORRECT",
                    correction_kind="validity",
                    new_validity_status="invalidated",
                ),
                reason="the arrangement directly names the previous partner",
            ),
        ),
        manual_reviews=(
            ImpactItem(
                fact_id=pattern.fact_id,
                path_edge_ids=("edge-partner-pattern",),
                path_confidence=0.68,
                classification="manual_review",
                recommended_mutation=RecommendedImpactMutation(operation="REVIEW"),
                reason="the general pattern may persist across relationships",
            ),
        ),
    )
    return ProfileDiffBuildInput(
        diff_id="profile_diff_partner_change",
        archive_bundle_id="archive_bundle_partner_change",
        client_id=CLIENT_ID,
        session_actual=_actual_transcript(),
        temporary_ledger=(
            _temporary_event(1, "ADD", target_fact_id=None),
            _temporary_event(2, "CONFIRM", target_fact_id=None),
            _temporary_event(
                3,
                "CORRECT",
                target_fact_id=arrangement.fact_id,
            ),
            _temporary_event(
                4,
                "SUPERSEDE",
                target_fact_id=old_partner.fact_id,
            ),
            _temporary_event(
                5,
                "RESOLVE",
                target_fact_id=resolved_issue.fact_id,
            ),
            _temporary_event(6, "MERGE", target_fact_id=None),
        ),
        base_profile=base,
        projected_profile=projected,
        candidates=candidates,
        dependency_impacts=(impact,),
    )


def build_partner_diff() -> ProfileDiffDraft:
    return ProfileDiffBuilder().build(partner_change_request())


def test_partner_change_matches_golden_and_preserves_direct_indirect_boundary() -> None:
    draft = build_partner_diff()
    golden_path = Path(__file__).parents[1] / "golden" / (
        "profile_diff_partner_change.json"
    )
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    assert [item.mutation.operation for item in draft.operations] == golden[
        "operations"
    ]
    assert [item.fact_id for item in draft.direct_impacts] == golden[
        "direct_impact_fact_ids"
    ]
    assert [item.fact_id for item in draft.indirect_reviews] == golden[
        "indirect_review_fact_ids"
    ]
    assert list(draft.current_view_removed_event_ids) == golden[
        "current_view_removed_event_ids"
    ]
    assert list(draft.preserved_history_event_ids) == golden[
        "preserved_history_event_ids"
    ]
    assert list(
        draft.projected_profile.minimum_next_session_summary.goal_fact_ids
    ) == golden["projected_goal_fact_ids"]
    assert list(
        draft.projected_profile.minimum_next_session_summary.pending_review_fact_ids
    ) == golden["pending_review_fact_ids"]
    assert "event_communication_pattern" not in (
        draft.current_view_removed_event_ids
    )
    assert profile_diff_sha256(draft) == draft.canonical_sha256


@pytest.mark.parametrize(
    ("origin", "cognitive_type"),
    (
        ("model_hypothesis", "hypothesis"),
        ("unselected_candidate", "recommendation"),
        ("external_reply_unknown", "interpretation"),
    ),
)
def test_untrusted_session_material_cannot_become_long_term_fact(
    origin: str,
    cognitive_type: str,
) -> None:
    request = partner_change_request()
    candidate = request.candidates[0].model_copy(
        update={"evidence_origin": origin, "cognitive_type": cognitive_type}
    )
    poisoned = request.model_copy(
        update={"candidates": (candidate,), "dependency_impacts": ()}
    )
    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_UNTRUSTED_LONG_TERM_EVIDENCE",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_client_statement_cannot_be_relabelled_as_objective_fact() -> None:
    request = partner_change_request()
    original = request.candidates[0]
    objective = _event(
        "event_objective_claim",
        "fact_objective_claim",
        "objective_status",
        {"status": "asserted_by_model"},
        cognitive_type="external_fact",
        source_kind="session_derived",
        effective_from=CHANGE_AT,
    )
    candidate = original.model_copy(
        update={"mutation": AddMutation(new_fact=objective)}
    )
    poisoned = request.model_copy(
        update={"candidates": (candidate,), "dependency_impacts": ()}
    )
    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_NEW_FACT_SOURCE_MISMATCH",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_confirm_evidence_must_match_the_actual_source_kind() -> None:
    request = partner_change_request()
    candidate = request.candidates[1]
    mutation = candidate.mutation
    assert isinstance(mutation, ConfirmMutation)
    mismatched = mutation.model_copy(
        update={
            "evidence": (
                FactEvidence(
                    evidence_id="evidence-wrong-source-kind",
                    source_kind="session_observation",
                    source_ref=f"session:{SESSION_ID}:turn:{TURN_ID}",
                    supports=True,
                    evidence_confidence=0.9,
                ),
            )
        }
    )
    poisoned_candidates = (
        request.candidates[:1]
        + (candidate.model_copy(update={"mutation": mismatched}),)
        + request.candidates[2:]
    )
    poisoned = request.model_copy(update={"candidates": poisoned_candidates})

    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_CONFIRM_EVIDENCE_MISMATCH",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_temporary_source_content_hash_must_match_the_bound_ledger_event() -> None:
    request = partner_change_request()
    candidate = request.candidates[0].model_copy(
        update={"source_content_sha256": "f" * 64}
    )
    poisoned = request.model_copy(
        update={"candidates": (candidate,), "dependency_impacts": ()}
    )

    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_TEMPORARY_SOURCE_MISMATCH",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_temporary_target_must_match_the_fact_being_changed() -> None:
    request = partner_change_request()
    original = request.temporary_ledger[2]
    poisoned_ledger = (
        *request.temporary_ledger[:2],
        original.model_copy(
            update={"target_fact_id": "fact_current_partner"}
        ),
        *request.temporary_ledger[3:],
    )
    poisoned = request.model_copy(update={"temporary_ledger": poisoned_ledger})

    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_TEMPORARY_TARGET_MISMATCH",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_projected_profile_cannot_add_an_unproposed_long_term_fact() -> None:
    request = partner_change_request()
    injected = _event(
        "event_unproposed_constraint",
        "fact_unproposed_constraint",
        "constraint",
        {"constraint": "model_injected"},
        effective_from=CHANGE_AT,
    )
    projected = _profile(
        (
            *request.projected_profile.sections,
            ProfileSection(
                name="constraints",
                items=(_profile_item(injected),),
            ),
        ),
        commit_version=8,
        source_hash="9" * 64,
    )
    poisoned = request.model_copy(update={"projected_profile": projected})

    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_PROJECTION_NOT_EXACT",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_indirect_review_can_never_be_removed_automatically() -> None:
    request = partner_change_request()
    impact = request.dependency_impacts[0]
    old_partner_event = next(
        item
        for section in request.base_profile.sections
        for item in section.items
        if item.fact_id == impact.changed_fact_id
    )
    poisoned_impact = impact.model_copy(
        update={
            "manual_reviews": (
                *impact.manual_reviews,
                ImpactItem(
                    fact_id=old_partner_event.fact_id,
                    path_edge_ids=("edge-indirect-old-partner",),
                    path_confidence=0.4,
                    classification="manual_review",
                    recommended_mutation=RecommendedImpactMutation(
                        operation="REVIEW"
                    ),
                    reason="synthetic inferred path must not auto-remove",
                ),
            )
        }
    )
    poisoned = request.model_copy(update={"dependency_impacts": (poisoned_impact,)})
    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_INDIRECT_IMPACT_AUTOMATICALLY_REMOVED",
    ):
        ProfileDiffBuilder().build(poisoned)


def test_indirect_review_must_reference_a_current_profile_fact() -> None:
    request = partner_change_request()
    impact = request.dependency_impacts[0]
    poisoned_impact = impact.model_copy(
        update={
            "manual_reviews": (
                *impact.manual_reviews,
                ImpactItem(
                    fact_id="fact_not_in_current_profile",
                    path_edge_ids=("edge-injected",),
                    path_confidence=0.4,
                    classification="manual_review",
                    recommended_mutation=RecommendedImpactMutation(
                        operation="REVIEW"
                    ),
                    reason="an unknown fact cannot enter the review queue",
                ),
            )
        }
    )
    poisoned = request.model_copy(update={"dependency_impacts": (poisoned_impact,)})

    with pytest.raises(
        ProfileDiffError,
        match="PROFILE_DIFF_INDIRECT_IMPACT_NOT_CURRENT",
    ):
        ProfileDiffBuilder().build(poisoned)
