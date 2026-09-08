from __future__ import annotations

import pytest

from consultation_kb.archive.profile_review import (
    ProfileDiffReviewError,
    ProfileDiffReviewService,
)
from consultation_kb.models.facts import ResolveMutation
from tests.consultation_kb.unit.test_profile_diff import build_partner_diff


def _state(draft: object) -> dict[str, object]:
    return {
        "current_profile_sha256": draft.base_profile_sha256,
        "current_session_sha256": draft.base_session_sha256,
        "current_client_commit_version": draft.base_client_commit_version,
    }


def test_preview_and_partial_approval_bind_exact_modified_selection() -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()
    preview = service.preview(draft, **_state(draft))
    resolved = next(
        item
        for item in draft.operations
        if item.operation_id == "op-resolve-issue"
    )
    modified = resolved.model_copy(
        update={"source_reason": "counselor confirmed resolution after review"}
    )

    prepared = service.approve_partial(
        preview,
        approved_operation_ids=(
            "op-correct-arrangement",
            "op-supersede-partner",
            "op-resolve-issue",
        ),
        modified_operations=(modified,),
        dismissed_indirect_review_fact_ids=("fact_communication_pattern",),
        **_state(draft),
    )

    assert preview.descriptor.purpose == "profile_update"
    assert preview.descriptor.draft_sha256 == draft.canonical_sha256
    assert [item.operation_id for item in prepared.selected_operations] == [
        "op-correct-arrangement",
        "op-supersede-partner",
        "op-resolve-issue",
    ]
    assert prepared.selected_operations[-1].source_reason == (
        "counselor confirmed resolution after review"
    )
    assert prepared.dismissed_indirect_review_fact_ids == (
        "fact_communication_pattern",
    )
    assert prepared.pending_indirect_review_fact_ids == ()
    assert prepared.unapproved_direct_impact_fact_ids == ()
    assert prepared.selection_sha256 == prepared.descriptor.draft_sha256
    assert prepared.selection_sha256 != draft.canonical_sha256
    assert prepared.requires_atomic_client_publication is True


def test_partial_approval_keeps_unselected_direct_impact_visible_for_review() -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()
    preview = service.preview(draft, **_state(draft))

    prepared = service.approve_partial(
        preview,
        approved_operation_ids=("op-supersede-partner",),
        **_state(draft),
    )

    assert prepared.unapproved_direct_impact_fact_ids == (
        "fact_weekend_arrangement",
    )
    assert prepared.pending_indirect_review_fact_ids == (
        "fact_communication_pattern",
    )

    with pytest.raises(ValueError, match="selection hash mismatch"):
        prepared.model_copy(update={"pending_indirect_review_fact_ids": ()})


def test_partial_approval_cannot_turn_indirect_review_into_invalidation() -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()
    preview = service.preview(draft, **_state(draft))
    resolved = next(
        item
        for item in draft.operations
        if item.operation_id == "op-resolve-issue"
    )
    malicious = resolved.model_copy(
        update={
            "mutation": ResolveMutation(
                target_event_id="event_communication_pattern",
                resolved_at=resolved.mutation.resolved_at,
                reason="must remain a manual review",
            )
        }
    )

    with pytest.raises(
        ProfileDiffReviewError,
        match="PROFILE_DIFF_PARTIAL_APPROVAL_OVERRIDE_INVALID",
    ):
        service.approve_partial(
            preview,
            approved_operation_ids=(resolved.operation_id,),
            modified_operations=(malicious,),
            **_state(draft),
        )


def test_modified_operation_cannot_describe_a_value_other_than_its_mutation() -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()
    preview = service.preview(draft, **_state(draft))
    supersede = next(
        item
        for item in draft.operations
        if item.operation_id == "op-supersede-partner"
    )
    mismatched = supersede.model_copy(
        update={"new_value_json": '{"role":"unbound_partner"}'}
    )

    with pytest.raises(
        ProfileDiffReviewError,
        match="PROFILE_DIFF_PARTIAL_APPROVAL_OVERRIDE_INVALID",
    ):
        service.approve_partial(
            preview,
            approved_operation_ids=(supersede.operation_id,),
            modified_operations=(mismatched,),
            **_state(draft),
        )


def test_reject_and_no_change_are_terminal_without_mutations() -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()

    rejected = service.reject(
        draft,
        reason="counselor rejects the proposed profile update",
        **_state(draft),
    )
    unchanged = service.no_change(
        draft,
        reason="counselor chooses to preserve the current profile",
        **_state(draft),
    )

    assert rejected.state == "REJECTED"
    assert unchanged.state == "NO_CHANGE"
    assert rejected.selected_operations == unchanged.selected_operations == ()
    assert rejected.source_diff_sha256 == unchanged.source_diff_sha256 == (
        draft.canonical_sha256
    )


@pytest.mark.parametrize(
    "changed",
    ("profile", "session", "commit"),
)
def test_profile_or_session_hash_and_commit_change_make_all_reviews_stale(
    changed: str,
) -> None:
    draft = build_partner_diff()
    service = ProfileDiffReviewService()
    current = _state(draft)
    preview = service.preview(draft, **current)
    if changed == "profile":
        current["current_profile_sha256"] = "f" * 64
    elif changed == "session":
        current["current_session_sha256"] = "e" * 64
    else:
        current["current_client_commit_version"] = (
            draft.base_client_commit_version + 1
        )

    with pytest.raises(ProfileDiffReviewError, match="PROFILE_DIFF_REVIEW_STALE"):
        service.preview(draft, **current)
    with pytest.raises(ProfileDiffReviewError, match="PROFILE_DIFF_REVIEW_STALE"):
        service.approve_partial(
            preview,
            approved_operation_ids=("op-supersede-partner",),
            **current,
        )
    with pytest.raises(ProfileDiffReviewError, match="PROFILE_DIFF_REVIEW_STALE"):
        service.no_change(
            draft,
            reason="stale no-change decision",
            **current,
        )
