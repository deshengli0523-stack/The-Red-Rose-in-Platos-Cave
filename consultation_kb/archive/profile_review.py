"""Counselor review decisions for immutable profile-diff drafts."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    Sha256Hex,
    StrictModel,
    Uuid7String,
)
from consultation_kb.models.facts import (
    AddMutation,
    ConfirmMutation,
    CorrectMutation,
    MergeMutation,
    ResolveMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.manifests import DraftDescriptor

from .profile_diff import (
    ProfileDiffDraft,
    ProfileDiffOperation,
    _new_fact,
    _removed_event_ids,
    _target_event_ids,
)


class ProfileDiffReviewError(RuntimeError):
    def __init__(self, code: str = "PROFILE_DIFF_REVIEW_INVALID") -> None:
        self.code = code
        super().__init__(code)


class ProfileDiffReviewItem(StrictModel):
    operation_id: NonEmptyStr
    operation: Literal["ADD", "CONFIRM", "CORRECT", "SUPERSEDE", "RESOLVE", "MERGE"]
    old_value_json: NonEmptyStr
    new_value_json: NonEmptyStr
    source_content_sha256: Sha256Hex
    source_turn_id: NonEmptyStr
    source_reason: NonEmptyStr
    confidence: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
    current_view_removed_event_ids: tuple[NonEmptyStr, ...] = ()
    direct_impact_fact_ids: tuple[NonEmptyStr, ...] = ()

    @field_validator(
        "current_view_removed_event_ids",
        "direct_impact_fact_ids",
    )
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("profile review item IDs must be unique")
        return tuple(sorted(value))


class ProfileDiffReviewPreview(StrictModel):
    schema_version: Literal["profile_diff_review_preview.v1"] = (
        "profile_diff_review_preview.v1"
    )
    draft: ProfileDiffDraft
    items: tuple[ProfileDiffReviewItem, ...]
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _exact_preview(self) -> "ProfileDiffReviewPreview":
        if tuple(item.operation_id for item in self.items) != tuple(
            item.operation_id for item in self.draft.operations
        ):
            raise ValueError("review items must exactly cover draft operations")
        for item, operation in zip(self.items, self.draft.operations, strict=True):
            if (
                item.operation != operation.mutation.operation
                or item.old_value_json != operation.old_value_json
                or item.new_value_json != operation.new_value_json
                or item.source_content_sha256
                != operation.source_content_sha256
                or item.source_turn_id != operation.source_turn_id
                or item.source_reason != operation.source_reason
                or item.confidence != operation.confidence
                or item.current_view_removed_event_ids
                != operation.current_view_removed_event_ids
                or item.direct_impact_fact_ids
                != operation.direct_impact_fact_ids
            ):
                raise ValueError("review item does not bind its draft operation")
        if (
            self.descriptor.purpose != "profile_update"
            or self.descriptor.target_id != self.draft.diff_id
            or self.descriptor.client_id != self.draft.client_id
            or self.descriptor.session_id != self.draft.session_id
            or self.descriptor.base_version
            != self.draft.base_client_commit_version
            or self.descriptor.draft_sha256 != self.draft.canonical_sha256
        ):
            raise ValueError("review descriptor does not bind the full draft")
        return self


class PreparedProfileDiffApproval(StrictModel):
    schema_version: Literal["profile_diff_partial_approval.v1"] = (
        "profile_diff_partial_approval.v1"
    )
    state: Literal["PREPARED"] = "PREPARED"
    diff_id: NonEmptyStr
    client_id: ClientId
    session_id: Uuid7String
    source_diff_sha256: Sha256Hex
    base_profile_sha256: Sha256Hex
    base_session_sha256: Sha256Hex
    base_client_commit_version: Annotated[int, Field(strict=True, ge=0)]
    selected_operations: tuple[ProfileDiffOperation, ...]
    dismissed_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()
    pending_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()
    unapproved_direct_impact_fact_ids: tuple[NonEmptyStr, ...] = ()
    selection_sha256: Sha256Hex
    descriptor: DraftDescriptor
    requires_atomic_client_publication: Literal[True] = True

    @field_validator(
        "dismissed_indirect_review_fact_ids",
        "pending_indirect_review_fact_ids",
        "unapproved_direct_impact_fact_ids",
    )
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("review decision fact IDs must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _selection_binding(self) -> "PreparedProfileDiffApproval":
        if not self.selected_operations:
            raise ValueError("partial approval requires at least one operation")
        if len({item.operation_id for item in self.selected_operations}) != len(
            self.selected_operations
        ):
            raise ValueError("selected profile operations must be unique")
        if tuple(item.ordinal for item in self.selected_operations) != tuple(
            sorted(item.ordinal for item in self.selected_operations)
        ):
            raise ValueError("selected profile operations must retain draft order")
        if set(self.dismissed_indirect_review_fact_ids) & set(
            self.pending_indirect_review_fact_ids
        ):
            raise ValueError("indirect reviews cannot be both pending and dismissed")
        payload = {
            "schema_version": self.schema_version,
            "diff_id": self.diff_id,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "source_diff_sha256": self.source_diff_sha256,
            "base_profile_sha256": self.base_profile_sha256,
            "base_session_sha256": self.base_session_sha256,
            "base_client_commit_version": self.base_client_commit_version,
            "selected_operations": [
                item.model_dump(mode="json") for item in self.selected_operations
            ],
            "dismissed_indirect_review_fact_ids": (
                self.dismissed_indirect_review_fact_ids
            ),
            "pending_indirect_review_fact_ids": (
                self.pending_indirect_review_fact_ids
            ),
            "unapproved_direct_impact_fact_ids": (
                self.unapproved_direct_impact_fact_ids
            ),
        }
        if _selection_sha256(payload) != self.selection_sha256:
            raise ValueError("partial approval selection hash mismatch")
        if (
            self.descriptor.purpose != "profile_update"
            or self.descriptor.target_id != self.diff_id
            or self.descriptor.client_id != self.client_id
            or self.descriptor.session_id != self.session_id
            or self.descriptor.base_version != self.base_client_commit_version
            or self.descriptor.draft_sha256 != self.selection_sha256
        ):
            raise ValueError("partial approval descriptor binding mismatch")
        return self


class TerminalProfileDiffDecision(StrictModel):
    schema_version: Literal["profile_diff_terminal_decision.v1"] = (
        "profile_diff_terminal_decision.v1"
    )
    state: Literal["REJECTED", "NO_CHANGE"]
    source_diff_sha256: Sha256Hex
    reason: NonEmptyStr
    selected_operations: tuple[()] = ()


def _selection_sha256(payload: object) -> str:
    return hashlib.sha256(
        (canonical_json(payload) + "\n").encode("utf-8")
    ).hexdigest()


def _modified_transition_is_consistent(
    base: ProfileDiffOperation,
    override: ProfileDiffOperation,
) -> bool:
    mutation = override.mutation
    if isinstance(mutation, AddMutation):
        expected = mutation.new_fact.object_json
    elif isinstance(mutation, ConfirmMutation):
        expected = base.old_value_json
    elif isinstance(mutation, CorrectMutation):
        if mutation.previous_value_json != base.old_value_json:
            return False
        if mutation.correction_kind == "value":
            if mutation.new_value_json is None:
                return False
            expected = mutation.new_value_json
        elif mutation.correction_kind == "validity":
            expected = canonical_json(
                {"validity": mutation.new_validity_status}
            )
        else:
            # A temporal correction may inherit one endpoint from the current
            # profile, which is not duplicated in the review object.  Preserve
            # the builder-validated mutation exactly; changed temporal bounds
            # require rebuilding the draft from the fixed base profile.
            return (
                mutation == base.mutation
                and override.new_value_json == base.new_value_json
            )
    elif isinstance(mutation, SupersedeMutation):
        expected = mutation.replacement.object_json
    elif isinstance(mutation, ResolveMutation):
        expected = canonical_json({"status": "resolved"})
    elif isinstance(mutation, MergeMutation):
        expected = mutation.canonical_projection.object_json
    else:  # pragma: no cover - closed discriminated union
        return False
    return override.new_value_json == expected


class ProfileDiffReviewService:
    """Prepare exact approvals; committing remains a scoped P2 worker operation."""

    @staticmethod
    def _assert_current(
        draft: ProfileDiffDraft,
        *,
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> None:
        if (
            current_profile_sha256 != draft.base_profile_sha256
            or current_session_sha256 != draft.base_session_sha256
            or current_client_commit_version
            != draft.base_client_commit_version
        ):
            raise ProfileDiffReviewError("PROFILE_DIFF_REVIEW_STALE")

    def preview(
        self,
        draft: ProfileDiffDraft,
        *,
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> ProfileDiffReviewPreview:
        exact = ProfileDiffDraft.model_validate(draft, strict=True)
        self._assert_current(
            exact,
            current_profile_sha256=current_profile_sha256,
            current_session_sha256=current_session_sha256,
            current_client_commit_version=current_client_commit_version,
        )
        return ProfileDiffReviewPreview(
            draft=exact,
            items=tuple(
                ProfileDiffReviewItem(
                    operation_id=item.operation_id,
                    operation=item.mutation.operation,
                    old_value_json=item.old_value_json,
                    new_value_json=item.new_value_json,
                    source_content_sha256=item.source_content_sha256,
                    source_turn_id=item.source_turn_id,
                    source_reason=item.source_reason,
                    confidence=item.confidence,
                    current_view_removed_event_ids=(
                        item.current_view_removed_event_ids
                    ),
                    direct_impact_fact_ids=item.direct_impact_fact_ids,
                )
                for item in exact.operations
            ),
            descriptor=DraftDescriptor(
                purpose="profile_update",
                target_id=exact.diff_id,
                client_id=exact.client_id,
                base_version=exact.base_client_commit_version,
                draft_sha256=exact.canonical_sha256,
                session_id=exact.session_id,
            ),
        )

    def approve_partial(
        self,
        preview: ProfileDiffReviewPreview,
        *,
        approved_operation_ids: tuple[str, ...],
        modified_operations: tuple[ProfileDiffOperation, ...] = (),
        dismissed_indirect_review_fact_ids: tuple[str, ...] = (),
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> PreparedProfileDiffApproval:
        exact = ProfileDiffReviewPreview.model_validate(preview, strict=True)
        self._assert_current(
            exact.draft,
            current_profile_sha256=current_profile_sha256,
            current_session_sha256=current_session_sha256,
            current_client_commit_version=current_client_commit_version,
        )
        if (
            not approved_operation_ids
            or len(approved_operation_ids) != len(set(approved_operation_ids))
        ):
            raise ProfileDiffReviewError(
                "PROFILE_DIFF_PARTIAL_APPROVAL_SELECTION_INVALID"
            )
        original = {
            item.operation_id: item for item in exact.draft.operations
        }
        approved_ids = set(approved_operation_ids)
        if not approved_ids.issubset(original):
            raise ProfileDiffReviewError(
                "PROFILE_DIFF_PARTIAL_APPROVAL_SELECTION_INVALID"
            )
        overrides = {item.operation_id: item for item in modified_operations}
        if len(overrides) != len(modified_operations) or not set(overrides).issubset(
            approved_ids
        ):
            raise ProfileDiffReviewError(
                "PROFILE_DIFF_PARTIAL_APPROVAL_OVERRIDE_INVALID"
            )
        for operation_id, override in overrides.items():
            base = original[operation_id]
            base_new_fact = _new_fact(base.mutation)
            override_new_fact = _new_fact(override.mutation)
            if (
                override.ordinal != base.ordinal
                or override.mutation.operation != base.mutation.operation
                or _target_event_ids(override.mutation)
                != _target_event_ids(base.mutation)
                or override.old_value_json != base.old_value_json
                or override.source_content_sha256
                != base.source_content_sha256
                or override.source_turn_id != base.source_turn_id
                or override.evidence_origin != base.evidence_origin
                or override.cognitive_type != base.cognitive_type
                or override.current_view_removed_event_ids
                != tuple(sorted(_removed_event_ids(override.mutation)))
                or override.current_view_removed_event_ids
                != base.current_view_removed_event_ids
                or override.direct_impact_fact_ids != base.direct_impact_fact_ids
                or (base_new_fact is None) != (override_new_fact is None)
                or not _modified_transition_is_consistent(base, override)
            ):
                raise ProfileDiffReviewError(
                    "PROFILE_DIFF_PARTIAL_APPROVAL_OVERRIDE_INVALID"
                )
            if base_new_fact is not None and override_new_fact is not None and (
                override_new_fact.event_id != base_new_fact.event_id
                or override_new_fact.fact_id != base_new_fact.fact_id
                or override_new_fact.client_id != base_new_fact.client_id
                or override_new_fact.source_session_id
                != base_new_fact.source_session_id
                or override_new_fact.source_turn_id != base_new_fact.source_turn_id
                or override_new_fact.cognitive_type != base_new_fact.cognitive_type
                or override_new_fact.source_kind != base_new_fact.source_kind
            ):
                raise ProfileDiffReviewError(
                    "PROFILE_DIFF_PARTIAL_APPROVAL_OVERRIDE_INVALID"
                )

        selected = tuple(
            overrides.get(item.operation_id, item)
            for item in exact.draft.operations
            if item.operation_id in approved_ids
        )
        indirect_ids = {item.fact_id for item in exact.draft.indirect_reviews}
        dismissed = set(dismissed_indirect_review_fact_ids)
        if not dismissed.issubset(indirect_ids):
            raise ProfileDiffReviewError(
                "PROFILE_DIFF_INDIRECT_REVIEW_DECISION_INVALID"
            )
        selected_direct = {
            fact_id
            for operation in selected
            for fact_id in operation.direct_impact_fact_ids
        }
        all_direct = {item.fact_id for item in exact.draft.direct_impacts}
        selection_payload = {
            "schema_version": "profile_diff_partial_approval.v1",
            "diff_id": exact.draft.diff_id,
            "client_id": exact.draft.client_id,
            "session_id": exact.draft.session_id,
            "source_diff_sha256": exact.draft.canonical_sha256,
            "base_profile_sha256": exact.draft.base_profile_sha256,
            "base_session_sha256": exact.draft.base_session_sha256,
            "base_client_commit_version": (
                exact.draft.base_client_commit_version
            ),
            "selected_operations": [
                item.model_dump(mode="json") for item in selected
            ],
            "dismissed_indirect_review_fact_ids": tuple(sorted(dismissed)),
            "pending_indirect_review_fact_ids": tuple(
                sorted(indirect_ids - dismissed)
            ),
            "unapproved_direct_impact_fact_ids": tuple(
                sorted(all_direct - selected_direct)
            ),
        }
        selection_sha256 = _selection_sha256(selection_payload)
        return PreparedProfileDiffApproval(
            diff_id=exact.draft.diff_id,
            client_id=exact.draft.client_id,
            session_id=exact.draft.session_id,
            source_diff_sha256=exact.draft.canonical_sha256,
            base_profile_sha256=exact.draft.base_profile_sha256,
            base_session_sha256=exact.draft.base_session_sha256,
            base_client_commit_version=exact.draft.base_client_commit_version,
            selected_operations=selected,
            dismissed_indirect_review_fact_ids=tuple(sorted(dismissed)),
            pending_indirect_review_fact_ids=tuple(
                sorted(indirect_ids - dismissed)
            ),
            unapproved_direct_impact_fact_ids=tuple(
                sorted(all_direct - selected_direct)
            ),
            selection_sha256=selection_sha256,
            descriptor=DraftDescriptor(
                purpose="profile_update",
                target_id=exact.draft.diff_id,
                client_id=exact.draft.client_id,
                base_version=exact.draft.base_client_commit_version,
                draft_sha256=selection_sha256,
                session_id=exact.draft.session_id,
            ),
        )

    def reject(
        self,
        draft: ProfileDiffDraft,
        *,
        reason: str,
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> TerminalProfileDiffDecision:
        return self._terminal(
            draft,
            state="REJECTED",
            reason=reason,
            current_profile_sha256=current_profile_sha256,
            current_session_sha256=current_session_sha256,
            current_client_commit_version=current_client_commit_version,
        )

    def no_change(
        self,
        draft: ProfileDiffDraft,
        *,
        reason: str,
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> TerminalProfileDiffDecision:
        return self._terminal(
            draft,
            state="NO_CHANGE",
            reason=reason,
            current_profile_sha256=current_profile_sha256,
            current_session_sha256=current_session_sha256,
            current_client_commit_version=current_client_commit_version,
        )

    def _terminal(
        self,
        draft: ProfileDiffDraft,
        *,
        state: Literal["REJECTED", "NO_CHANGE"],
        reason: str,
        current_profile_sha256: str,
        current_session_sha256: str,
        current_client_commit_version: int,
    ) -> TerminalProfileDiffDecision:
        exact = ProfileDiffDraft.model_validate(draft, strict=True)
        self._assert_current(
            exact,
            current_profile_sha256=current_profile_sha256,
            current_session_sha256=current_session_sha256,
            current_client_commit_version=current_client_commit_version,
        )
        try:
            return TerminalProfileDiffDecision(
                state=state,
                source_diff_sha256=exact.canonical_sha256,
                reason=reason,
            )
        except ValueError:
            raise ProfileDiffReviewError(
                "PROFILE_DIFF_TERMINAL_REASON_INVALID"
            ) from None


__all__ = [
    "PreparedProfileDiffApproval",
    "ProfileDiffReviewError",
    "ProfileDiffReviewItem",
    "ProfileDiffReviewPreview",
    "ProfileDiffReviewService",
    "TerminalProfileDiffDecision",
]
