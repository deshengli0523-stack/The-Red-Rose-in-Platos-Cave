"""Pure, review-first profile diffs derived from fixed session evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, cast

from pydantic import Field, field_validator, model_validator

from consultation_kb.models.archive import ActualTranscript
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    Sha256Hex,
    StrictModel,
    Uuid7String,
)
from consultation_kb.models.dependencies import ImpactItem, ImpactProposal
from consultation_kb.models.facts import (
    AddMutation,
    CognitiveType,
    ConfirmMutation,
    CorrectMutation,
    FactEvent,
    FactMutation,
    MergeMutation,
    ResolveMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.profile import ProfileItem, ProfileSnapshot
from consultation_kb.models.session import TemporaryFactEvent


class ProfileDiffError(RuntimeError):
    """Fail-closed profile-diff validation with stable machine codes."""

    def __init__(self, code: str = "PROFILE_DIFF_INVALID") -> None:
        self.code = code
        super().__init__(code)


EvidenceOrigin = Literal[
    "actual_client_statement",
    "counselor_observation",
    "model_hypothesis",
    "unselected_candidate",
    "external_reply_unknown",
]


class ProfileMutationCandidate(StrictModel):
    """One proposed P2 mutation plus its fixed, counselor-visible rationale."""

    operation_id: NonEmptyStr
    ordinal: Annotated[int, Field(strict=True, gt=0)]
    mutation: FactMutation
    old_value_json: NonEmptyStr
    new_value_json: NonEmptyStr
    source_temporary_event_id: NonEmptyStr
    source_content_sha256: Sha256Hex
    source_turn_id: Uuid7String
    source_reason: NonEmptyStr
    evidence_origin: EvidenceOrigin
    cognitive_type: CognitiveType
    confidence: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]

    @field_validator("old_value_json", "new_value_json")
    @classmethod
    def _canonical_values(cls, value: str) -> str:
        try:
            if canonical_json(json.loads(value)) != value:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("profile diff values must be canonical JSON") from None
        return value


class ProfileSummaryItem(StrictModel):
    fact_id: NonEmptyStr
    event_id: NonEmptyStr
    predicate: NonEmptyStr
    object_json: NonEmptyStr

    @field_validator("object_json")
    @classmethod
    def _canonical_object(cls, value: str) -> str:
        try:
            if canonical_json(json.loads(value)) != value:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("summary objects must be canonical JSON") from None
        return value


class MinimumNextSessionSummary(StrictModel):
    """Only the current facts needed to resume; never an appended session recap."""

    profile_sha256: Sha256Hex
    goal_fact_ids: tuple[NonEmptyStr, ...] = ()
    unresolved_issue_fact_ids: tuple[NonEmptyStr, ...] = ()
    preference_fact_ids: tuple[NonEmptyStr, ...] = ()
    constraint_fact_ids: tuple[NonEmptyStr, ...] = ()
    pending_review_fact_ids: tuple[NonEmptyStr, ...] = ()

    @field_validator(
        "goal_fact_ids",
        "unresolved_issue_fact_ids",
        "preference_fact_ids",
        "constraint_fact_ids",
        "pending_review_fact_ids",
    )
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("minimum summary fact IDs must be unique")
        return tuple(sorted(value))


class ProjectedProfileSummary(StrictModel):
    updated_profile_sha256: Sha256Hex
    goals: tuple[ProfileSummaryItem, ...] = ()
    unresolved_issues: tuple[ProfileSummaryItem, ...] = ()
    preferences: tuple[ProfileSummaryItem, ...] = ()
    constraints: tuple[ProfileSummaryItem, ...] = ()
    minimum_next_session_summary: MinimumNextSessionSummary

    @model_validator(mode="after")
    def _same_projection(self) -> "ProjectedProfileSummary":
        if (
            self.minimum_next_session_summary.profile_sha256
            != self.updated_profile_sha256
        ):
            raise ValueError("minimum summary must bind the projected profile")
        return self


class ProfileDiffOperation(StrictModel):
    operation_id: NonEmptyStr
    ordinal: Annotated[int, Field(strict=True, gt=0)]
    mutation: FactMutation
    old_value_json: NonEmptyStr
    new_value_json: NonEmptyStr
    source_content_sha256: Sha256Hex
    source_turn_id: Uuid7String
    source_reason: NonEmptyStr
    evidence_origin: Literal[
        "actual_client_statement", "counselor_observation"
    ]
    cognitive_type: Literal["client_statement", "consultant_observation"]
    confidence: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
    current_view_removed_event_ids: tuple[NonEmptyStr, ...] = ()
    direct_impact_fact_ids: tuple[NonEmptyStr, ...] = ()
    requires_human_approval: Literal[True] = True

    @field_validator("old_value_json", "new_value_json")
    @classmethod
    def _canonical_values(cls, value: str) -> str:
        try:
            if canonical_json(json.loads(value)) != value:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("profile diff values must be canonical JSON") from None
        return value

    @field_validator(
        "current_view_removed_event_ids",
        "direct_impact_fact_ids",
    )
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("profile operation IDs must be unique")
        return tuple(sorted(value))


class ProfileDiffDraft(StrictModel):
    schema_version: Literal["profile_diff.v1"] = "profile_diff.v1"
    diff_id: NonEmptyStr
    archive_bundle_id: NonEmptyStr
    client_id: ClientId
    session_id: Uuid7String
    base_client_commit_version: Annotated[int, Field(strict=True, ge=0)]
    base_profile_sha256: Sha256Hex
    base_session_sha256: Sha256Hex
    operations: tuple[ProfileDiffOperation, ...]
    direct_impacts: tuple[ImpactItem, ...] = ()
    indirect_reviews: tuple[ImpactItem, ...] = ()
    current_view_removed_event_ids: tuple[NonEmptyStr, ...] = ()
    current_view_removed_fact_ids: tuple[NonEmptyStr, ...] = ()
    preserved_history_event_ids: tuple[NonEmptyStr, ...] = ()
    projected_profile: ProjectedProfileSummary
    canonical_sha256: Sha256Hex

    @field_validator(
        "current_view_removed_event_ids",
        "current_view_removed_fact_ids",
        "preserved_history_event_ids",
    )
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("profile diff identity lists must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _closed_diff(self) -> "ProfileDiffDraft":
        if tuple(item.ordinal for item in self.operations) != tuple(
            range(1, len(self.operations) + 1)
        ):
            raise ValueError("profile diff operation ordinals must be contiguous")
        if len({item.operation_id for item in self.operations}) != len(
            self.operations
        ):
            raise ValueError("profile diff operation IDs must be unique")
        if any(item.classification != "direct_invalidation" for item in self.direct_impacts):
            raise ValueError("direct impacts must contain only direct invalidations")
        if any(item.classification != "manual_review" for item in self.indirect_reviews):
            raise ValueError("indirect impacts must contain only manual reviews")
        direct_ids = {item.fact_id for item in self.direct_impacts}
        indirect_ids = {item.fact_id for item in self.indirect_reviews}
        if direct_ids & indirect_ids:
            raise ValueError("direct impacts and indirect reviews must be disjoint")
        if not set(self.current_view_removed_event_ids).issubset(
            self.preserved_history_event_ids
        ):
            raise ValueError("current-view removals must remain in immutable history")
        if profile_diff_sha256(self) != self.canonical_sha256:
            raise ValueError("profile diff hash mismatch")
        return self


class ProfileDiffBuildInput(StrictModel):
    diff_id: NonEmptyStr
    archive_bundle_id: NonEmptyStr
    client_id: ClientId
    session_actual: ActualTranscript
    temporary_ledger: tuple[TemporaryFactEvent, ...]
    base_profile: ProfileSnapshot
    projected_profile: ProfileSnapshot
    candidates: tuple[ProfileMutationCandidate, ...]
    dependency_impacts: tuple[ImpactProposal, ...] = ()

    @model_validator(mode="after")
    def _base_binding(self) -> "ProfileDiffBuildInput":
        if self.base_profile.source_client_commit_version < 0:
            raise ValueError("base profile commit version is invalid")
        if self.projected_profile.source_client_commit_version != (
            self.base_profile.source_client_commit_version + 1
        ):
            raise ValueError("projected profile must target the next client commit")
        if any(
            item.session_id != self.session_actual.session_id
            for item in self.temporary_ledger
        ):
            raise ValueError("temporary facts must belong to the fixed session")
        if len({item.event_id for item in self.temporary_ledger}) != len(
            self.temporary_ledger
        ):
            raise ValueError("temporary fact event IDs must be unique")
        return self


def profile_diff_sha256(value: ProfileDiffDraft | dict[str, object]) -> str:
    payload = (
        value.model_dump(mode="json", exclude={"canonical_sha256"})
        if isinstance(value, ProfileDiffDraft)
        else value
    )
    return hashlib.sha256(
        (canonical_json(payload) + "\n").encode("utf-8")
    ).hexdigest()


def _new_fact(mutation: FactMutation) -> FactEvent | None:
    if isinstance(mutation, AddMutation):
        return mutation.new_fact
    if isinstance(mutation, SupersedeMutation):
        return mutation.replacement
    if isinstance(mutation, MergeMutation):
        return mutation.canonical_projection
    return None


def _removed_event_ids(mutation: FactMutation) -> tuple[str, ...]:
    if isinstance(
        mutation,
        (CorrectMutation, SupersedeMutation, ResolveMutation),
    ):
        return (mutation.target_event_id,)
    if isinstance(mutation, MergeMutation):
        return tuple(sorted(mutation.member_event_ids))
    return ()


def _target_event_ids(mutation: FactMutation) -> tuple[str, ...]:
    if isinstance(mutation, ConfirmMutation):
        return (mutation.target_event_id,)
    return _removed_event_ids(mutation)


def _profile_items(profile: ProfileSnapshot) -> tuple[ProfileItem, ...]:
    return tuple(item for section in profile.sections for item in section.items)


def _summary_items(
    profile: ProfileSnapshot,
    section_name: str,
) -> tuple[ProfileSummaryItem, ...]:
    section = next(
        (item for item in profile.sections if item.name == section_name),
        None,
    )
    if section is None:
        return ()
    return tuple(
        ProfileSummaryItem(
            fact_id=item.fact_id,
            event_id=item.event_id,
            predicate=item.predicate,
            object_json=item.object_json,
        )
        for item in section.items
    )


class ProfileDiffBuilder:
    """Build a mutation-only draft; never writes facts, profiles, or graphs."""

    _FORBIDDEN_EVIDENCE = frozenset(
        {"model_hypothesis", "unselected_candidate", "external_reply_unknown"}
    )

    def build(self, request: ProfileDiffBuildInput) -> ProfileDiffDraft:
        exact = ProfileDiffBuildInput.model_validate(request, strict=True)
        candidates = tuple(sorted(exact.candidates, key=lambda item: item.ordinal))
        if tuple(item.ordinal for item in candidates) != tuple(
            range(1, len(candidates) + 1)
        ):
            raise ProfileDiffError("PROFILE_DIFF_OPERATION_ORDER_INVALID")
        if len({item.operation_id for item in candidates}) != len(candidates):
            raise ProfileDiffError("PROFILE_DIFF_OPERATION_ID_DUPLICATE")

        base_items = _profile_items(exact.base_profile)
        base_by_event = {item.event_id: item for item in base_items}
        base_by_fact = {item.fact_id: item for item in base_items}
        if len(base_by_event) != len(base_items) or len(base_by_fact) != len(
            base_items
        ):
            raise ProfileDiffError("PROFILE_DIFF_BASE_PROFILE_AMBIGUOUS")
        temporary_by_id = {
            item.event_id: item for item in exact.temporary_ledger
        }

        removed_by_operation: dict[str, tuple[str, ...]] = {}
        changed_fact_ids: set[str] = set()
        explicit_new_event_ids: set[str] = set()
        for candidate in candidates:
            self._validate_candidate(
                exact,
                candidate,
                temporary_by_id=temporary_by_id,
                base_by_event=base_by_event,
            )
            removed = _removed_event_ids(candidate.mutation)
            if any(event_id not in base_by_event for event_id in removed):
                raise ProfileDiffError("PROFILE_DIFF_TARGET_NOT_CURRENT")
            if any(
                event_id not in base_by_event
                for event_id in _target_event_ids(candidate.mutation)
            ):
                raise ProfileDiffError("PROFILE_DIFF_TARGET_NOT_CURRENT")
            self._validate_transition_values(candidate, base_by_event)
            removed_by_operation[candidate.operation_id] = removed
            changed_fact_ids.update(
                base_by_event[event_id].fact_id
                for event_id in _target_event_ids(candidate.mutation)
                if event_id in base_by_event
            )
            new_fact = _new_fact(candidate.mutation)
            if new_fact is not None:
                changed_fact_ids.add(new_fact.fact_id)
                explicit_new_event_ids.add(new_fact.event_id)

        direct, indirect = self._collect_impacts(
            exact.dependency_impacts,
            changed_fact_ids=changed_fact_ids,
        )
        removed_event_ids = tuple(
            sorted(
                {
                    event_id
                    for values in removed_by_operation.values()
                    for event_id in values
                }
            )
        )
        removed_fact_ids = tuple(
            sorted({base_by_event[event_id].fact_id for event_id in removed_event_ids})
        )
        direct_fact_ids = {item.fact_id for item in direct}
        indirect_fact_ids = {item.fact_id for item in indirect}
        if not direct_fact_ids.issubset(removed_fact_ids):
            raise ProfileDiffError("PROFILE_DIFF_DIRECT_IMPACT_MUTATION_MISSING")
        if indirect_fact_ids & set(removed_fact_ids):
            raise ProfileDiffError("PROFILE_DIFF_INDIRECT_IMPACT_AUTOMATICALLY_REMOVED")
        if not indirect_fact_ids.issubset(base_by_fact):
            raise ProfileDiffError("PROFILE_DIFF_INDIRECT_IMPACT_NOT_CURRENT")

        projected_ids = set(exact.projected_profile.current_event_ids)
        if set(removed_event_ids) & projected_ids:
            raise ProfileDiffError("PROFILE_DIFF_CURRENT_REMOVAL_STILL_PROJECTED")
        if not explicit_new_event_ids.issubset(projected_ids):
            raise ProfileDiffError("PROFILE_DIFF_NEW_EVENT_NOT_PROJECTED")
        if any(
            base_by_fact[fact_id].event_id not in projected_ids
            for fact_id in indirect_fact_ids
            if fact_id in base_by_fact
        ):
            raise ProfileDiffError("PROFILE_DIFF_INDIRECT_REVIEW_NOT_RETAINED")
        expected_projected_ids = (
            set(exact.base_profile.current_event_ids) - set(removed_event_ids)
        ) | explicit_new_event_ids
        if projected_ids != expected_projected_ids:
            raise ProfileDiffError("PROFILE_DIFF_PROJECTION_NOT_EXACT")

        operations = tuple(
            ProfileDiffOperation(
                operation_id=candidate.operation_id,
                ordinal=candidate.ordinal,
                mutation=candidate.mutation,
                old_value_json=candidate.old_value_json,
                new_value_json=candidate.new_value_json,
                source_content_sha256=candidate.source_content_sha256,
                source_turn_id=candidate.source_turn_id,
                source_reason=candidate.source_reason,
                evidence_origin=cast(
                    Literal["actual_client_statement", "counselor_observation"],
                    candidate.evidence_origin,
                ),
                cognitive_type=cast(
                    Literal["client_statement", "consultant_observation"],
                    candidate.cognitive_type,
                ),
                confidence=candidate.confidence,
                current_view_removed_event_ids=removed_by_operation[
                    candidate.operation_id
                ],
                direct_impact_fact_ids=tuple(
                    sorted(
                        direct_fact_ids
                        & {
                            base_by_event[event_id].fact_id
                            for event_id in removed_by_operation[
                                candidate.operation_id
                            ]
                        }
                    )
                ),
            )
            for candidate in candidates
        )
        projected_summary = self._projected_summary(
            exact.projected_profile,
            pending_review_fact_ids=indirect_fact_ids,
        )
        payload: dict[str, object] = {
            "schema_version": "profile_diff.v1",
            "diff_id": exact.diff_id,
            "archive_bundle_id": exact.archive_bundle_id,
            "client_id": exact.client_id,
            "session_id": exact.session_actual.session_id,
            "base_client_commit_version": (
                exact.base_profile.source_client_commit_version
            ),
            "base_profile_sha256": exact.base_profile.canonical_sha256,
            "base_session_sha256": (
                exact.session_actual.actual_transcript_ref.content_sha256
            ),
            "operations": [item.model_dump(mode="json") for item in operations],
            "direct_impacts": [item.model_dump(mode="json") for item in direct],
            "indirect_reviews": [
                item.model_dump(mode="json") for item in indirect
            ],
            "current_view_removed_event_ids": removed_event_ids,
            "current_view_removed_fact_ids": removed_fact_ids,
            "preserved_history_event_ids": removed_event_ids,
            "projected_profile": projected_summary.model_dump(mode="json"),
        }
        return ProfileDiffDraft(
            diff_id=exact.diff_id,
            archive_bundle_id=exact.archive_bundle_id,
            client_id=exact.client_id,
            session_id=exact.session_actual.session_id,
            base_client_commit_version=(
                exact.base_profile.source_client_commit_version
            ),
            base_profile_sha256=exact.base_profile.canonical_sha256,
            base_session_sha256=(
                exact.session_actual.actual_transcript_ref.content_sha256
            ),
            operations=operations,
            direct_impacts=direct,
            indirect_reviews=indirect,
            current_view_removed_event_ids=removed_event_ids,
            current_view_removed_fact_ids=removed_fact_ids,
            preserved_history_event_ids=removed_event_ids,
            projected_profile=projected_summary,
            canonical_sha256=profile_diff_sha256(payload),
        )

    def _validate_candidate(
        self,
        request: ProfileDiffBuildInput,
        candidate: ProfileMutationCandidate,
        *,
        temporary_by_id: dict[str, TemporaryFactEvent],
        base_by_event: dict[str, ProfileItem],
    ) -> None:
        if candidate.evidence_origin in self._FORBIDDEN_EVIDENCE:
            raise ProfileDiffError("PROFILE_DIFF_UNTRUSTED_LONG_TERM_EVIDENCE")
        actual_turn_ids = {item.turn_id for item in request.session_actual.turns}
        if candidate.source_turn_id not in actual_turn_ids:
            raise ProfileDiffError("PROFILE_DIFF_SOURCE_TURN_NOT_ACTUAL")
        expected_cognitive = (
            "client_statement"
            if candidate.evidence_origin == "actual_client_statement"
            else "consultant_observation"
        )
        if candidate.cognitive_type != expected_cognitive:
            raise ProfileDiffError("PROFILE_DIFF_COGNITIVE_TYPE_MISMATCH")
        temporary = temporary_by_id.get(candidate.source_temporary_event_id)
        if (
            temporary is None
            or temporary.turn_id != candidate.source_turn_id
            or temporary.cognitive_type != candidate.cognitive_type
            or temporary.event_kind != candidate.mutation.operation
            or temporary.content.content_sha256
            != candidate.source_content_sha256
        ):
            raise ProfileDiffError("PROFILE_DIFF_TEMPORARY_SOURCE_MISMATCH")
        mutation = candidate.mutation
        if isinstance(
            mutation,
            (CorrectMutation, SupersedeMutation, ResolveMutation),
        ):
            target = base_by_event.get(mutation.target_event_id)
            if (
                target is not None
                and temporary.target_fact_id != target.fact_id
            ):
                raise ProfileDiffError("PROFILE_DIFF_TEMPORARY_TARGET_MISMATCH")
        if isinstance(mutation, ConfirmMutation):
            expected_source = (
                "session_statement"
                if expected_cognitive == "client_statement"
                else "session_observation"
            )
            if any(
                item.source_kind != expected_source
                for item in mutation.evidence
            ):
                raise ProfileDiffError("PROFILE_DIFF_CONFIRM_EVIDENCE_MISMATCH")
        new_fact = _new_fact(mutation)
        if new_fact is None:
            return
        expected_source = (
            "session_statement"
            if expected_cognitive == "client_statement"
            else "session_observation"
        )
        if (
            new_fact.client_id != request.client_id
            or new_fact.source_session_id != request.session_actual.session_id
            or new_fact.source_turn_id != candidate.source_turn_id
            or new_fact.cognitive_type != expected_cognitive
            or new_fact.source_kind != expected_source
        ):
            raise ProfileDiffError("PROFILE_DIFF_NEW_FACT_SOURCE_MISMATCH")

    @staticmethod
    def _validate_transition_values(
        candidate: ProfileMutationCandidate,
        base_by_event: dict[str, ProfileItem],
    ) -> None:
        mutation = candidate.mutation
        if isinstance(mutation, AddMutation):
            expected_old = canonical_json(None)
            expected_new = mutation.new_fact.object_json
        elif isinstance(mutation, ConfirmMutation):
            current = base_by_event[mutation.target_event_id]
            expected_old = current.object_json
            expected_new = current.object_json
        elif isinstance(mutation, CorrectMutation):
            current = base_by_event[mutation.target_event_id]
            expected_old = current.object_json
            if mutation.previous_value_json != current.object_json:
                raise ProfileDiffError("PROFILE_DIFF_CORRECTION_BASE_MISMATCH")
            if mutation.correction_kind == "value":
                if mutation.new_value_json is None:
                    raise ProfileDiffError(
                        "PROFILE_DIFF_CORRECTION_VALUE_MISSING"
                    )
                expected_new = mutation.new_value_json
            elif mutation.correction_kind == "validity":
                expected_new = canonical_json(
                    {"validity": mutation.new_validity_status}
                )
            else:
                effective_from = (
                    mutation.new_effective_from or current.effective_from
                )
                effective_to = (
                    mutation.new_effective_to
                    if mutation.new_effective_to is not None
                    else current.effective_to
                )
                expected_new = canonical_json(
                    {
                        "effective_from": effective_from.isoformat(),
                        "effective_to": (
                            None
                            if effective_to is None
                            else effective_to.isoformat()
                        ),
                    }
                )
        elif isinstance(mutation, SupersedeMutation):
            expected_old = base_by_event[mutation.target_event_id].object_json
            expected_new = mutation.replacement.object_json
        elif isinstance(mutation, ResolveMutation):
            expected_old = base_by_event[mutation.target_event_id].object_json
            expected_new = canonical_json({"status": "resolved"})
        else:
            expected_old = canonical_json(
                [
                    json.loads(base_by_event[event_id].object_json)
                    for event_id in mutation.member_event_ids
                ]
            )
            expected_new = mutation.canonical_projection.object_json
        if (
            candidate.old_value_json != expected_old
            or candidate.new_value_json != expected_new
        ):
            raise ProfileDiffError("PROFILE_DIFF_TRANSITION_VALUE_MISMATCH")

    @staticmethod
    def _collect_impacts(
        impacts: tuple[ImpactProposal, ...],
        *,
        changed_fact_ids: set[str],
    ) -> tuple[tuple[ImpactItem, ...], tuple[ImpactItem, ...]]:
        if any(item.changed_fact_id not in changed_fact_ids for item in impacts):
            raise ProfileDiffError("PROFILE_DIFF_IMPACT_SOURCE_NOT_CHANGED")
        direct = tuple(
            sorted(
                (
                    item
                    for proposal in impacts
                    for item in proposal.direct_invalidations
                ),
                key=lambda item: item.fact_id,
            )
        )
        indirect = tuple(
            sorted(
                (
                    item for proposal in impacts for item in proposal.manual_reviews
                ),
                key=lambda item: item.fact_id,
            )
        )
        all_ids = tuple(item.fact_id for item in (*direct, *indirect))
        if len(all_ids) != len(set(all_ids)):
            raise ProfileDiffError("PROFILE_DIFF_IMPACT_FACT_DUPLICATE")
        return direct, indirect

    @staticmethod
    def _projected_summary(
        profile: ProfileSnapshot,
        *,
        pending_review_fact_ids: set[str],
    ) -> ProjectedProfileSummary:
        goals = _summary_items(profile, "goals")
        unresolved = _summary_items(profile, "unresolved_issues")
        preferences = _summary_items(profile, "preferences")
        constraints = _summary_items(profile, "constraints")
        pending_section = _summary_items(profile, "pending_review")
        return ProjectedProfileSummary(
            updated_profile_sha256=profile.canonical_sha256,
            goals=goals,
            unresolved_issues=unresolved,
            preferences=preferences,
            constraints=constraints,
            minimum_next_session_summary=MinimumNextSessionSummary(
                profile_sha256=profile.canonical_sha256,
                goal_fact_ids=tuple(item.fact_id for item in goals),
                unresolved_issue_fact_ids=tuple(
                    item.fact_id for item in unresolved
                ),
                preference_fact_ids=tuple(
                    item.fact_id for item in preferences
                ),
                constraint_fact_ids=tuple(item.fact_id for item in constraints),
                pending_review_fact_ids=tuple(
                    sorted(
                        pending_review_fact_ids
                        | {item.fact_id for item in pending_section}
                    )
                ),
            ),
        )


__all__ = [
    "EvidenceOrigin",
    "MinimumNextSessionSummary",
    "ProfileDiffBuildInput",
    "ProfileDiffBuilder",
    "ProfileDiffDraft",
    "ProfileDiffError",
    "ProfileDiffOperation",
    "ProfileMutationCandidate",
    "ProfileSummaryItem",
    "ProjectedProfileSummary",
    "profile_diff_sha256",
]
