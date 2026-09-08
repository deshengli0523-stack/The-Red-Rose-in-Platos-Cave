"""Preview and commit the six governed client fact mutations."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, model_validator

from consultation_kb.client.normalization import DuplicateCandidate, classify_candidates
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import NonEmptyStr, StrictModel, UtcDateTime
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import (
    AddMutation,
    ConfirmMutation,
    CorrectMutation,
    FACT_MUTATION_ADAPTER,
    FactEvent,
    FactEvidence,
    FactMutation,
    MergeMutation,
    ResolveMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.client_ledger import FactEventRepository, StaleFactPreview


class FactMutationError(RuntimeError):
    """Base mutation error with a fixed external code."""


class DuplicateFact(FactMutationError):
    def __init__(self) -> None:
        super().__init__("DUPLICATE_FACT")


class MutationMismatch(FactMutationError):
    def __init__(self) -> None:
        super().__init__("MUTATION_APPROVAL_MISMATCH")


class MutationConflict(FactMutationError):
    def __init__(self) -> None:
        super().__init__("FACT_MUTATION_CONFLICT")


def _mutation_sha256(mutation: FactMutation, base_commit_version: int) -> str:
    payload = {
        "base_commit_version": base_commit_version,
        "mutation": mutation.model_dump(mode="json"),
        "schema_version": "fact_mutation_preview.v1",
    }
    return hashlib.sha256((canonical_json(payload) + "\n").encode("utf-8")).hexdigest()


class MutationPreview(StrictModel):
    mutation: FactMutation
    base_commit_version: int = Field(strict=True, ge=0)
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    human_diff: NonEmptyStr
    candidates: tuple[DuplicateCandidate, ...]
    direct_dependency_fact_ids: tuple[NonEmptyStr, ...] = ()
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _hash_matches(self) -> "MutationPreview":
        if _mutation_sha256(self.mutation, self.base_commit_version) != self.preview_sha256:
            raise ValueError("mutation preview hash mismatch")
        if self.descriptor.base_version != self.base_commit_version:
            raise ValueError("mutation descriptor base version mismatch")
        if self.descriptor.draft_sha256 != self.preview_sha256:
            raise ValueError("mutation descriptor hash mismatch")
        return self


class ApprovedMutation(StrictModel):
    """Approval binding; ``unit_test`` is rejected by production worker composition."""

    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_operation_id: NonEmptyStr
    runtime_epoch: int = Field(strict=True, gt=0)
    source: Literal["approval_guard", "unit_test"]
    approved_at: UtcDateTime | None = None


class MutationCommitResult(StrictModel):
    operation_id: NonEmptyStr
    new_commit_version: int = Field(strict=True, gt=0)
    event_ids: tuple[NonEmptyStr, ...]


class FactMutationService:
    CONFIDENCE_POLICY_VERSION = "independent-evidence.v1"

    def __init__(
        self,
        repository: FactEventRepository,
        *,
        id_factory: IdFactory | None = None,
        allow_test_approvals: bool = True,
    ) -> None:
        self._repository = repository
        self._ids = id_factory if id_factory is not None else IdFactory()
        self._allow_test_approvals = allow_test_approvals

    def preview(self, mutation: FactMutation) -> MutationPreview:
        validated = FACT_MUTATION_ADAPTER.validate_python(mutation, strict=True)
        self._validate_client_consistency(validated)
        base = self._repository.current_commit_version()
        current = self._repository.list_events()
        candidates: tuple[DuplicateCandidate, ...] = ()
        if isinstance(validated, AddMutation):
            candidates = classify_candidates(validated.new_fact, current)
            if any(item.classification == "exact_duplicate" for item in candidates):
                raise DuplicateFact
        elif isinstance(validated, MergeMutation):
            self._validate_merge(validated)
        else:
            self._repository.get_event(validated.target_event_id)
        preview_hash = _mutation_sha256(validated, base)
        client_id = self._client_id(validated)
        target_id = self._target_id(validated)
        return MutationPreview(
            mutation=validated,
            base_commit_version=base,
            preview_sha256=preview_hash,
            human_diff=self._human_diff(validated),
            candidates=candidates,
            direct_dependency_fact_ids=tuple(
                sorted(
                    {
                        edge.dependent_fact_id
                        for edge in self.dependency_edges(validated)
                        if edge.dependency_type == "direct_deterministic"
                    }
                )
            ),
            descriptor=DraftDescriptor(
                purpose="profile_update",
                target_id=target_id,
                client_id=client_id,
                base_version=base,
                draft_sha256=preview_hash,
                session_id=None,
            ),
        )

    def commit(
        self,
        preview: MutationPreview,
        approval: ApprovedMutation,
    ) -> MutationCommitResult:
        validated_preview = MutationPreview.model_validate(preview)
        validated_approval = ApprovedMutation.model_validate(approval)
        if (
            validated_approval.preview_sha256 != validated_preview.preview_sha256
            or (
                validated_approval.source == "unit_test"
                and not self._allow_test_approvals
            )
        ):
            raise MutationMismatch
        if self._repository.current_commit_version() != validated_preview.base_commit_version:
            raise StaleFactPreview
        now = validated_approval.approved_at or datetime.now(timezone.utc)
        events, merge_members, evidence = self.materialize(
            validated_preview.mutation,
            commit_version=validated_preview.base_commit_version + 1,
            operation_id=validated_approval.approval_operation_id,
            runtime_epoch=validated_approval.runtime_epoch,
            now=now,
        )
        new_version = self._repository.append_batch(
            base_commit_version=validated_preview.base_commit_version,
            events=events,
            merge_members=merge_members,
            evidence=evidence,
            dependencies=self.dependency_edges(validated_preview.mutation),
        )
        return MutationCommitResult(
            operation_id=validated_approval.approval_operation_id,
            new_commit_version=new_version,
            event_ids=tuple(event.event_id for event in events),
        )

    def materialize(
        self,
        mutation: FactMutation,
        *,
        commit_version: int,
        operation_id: str,
        runtime_epoch: int,
        now: datetime,
    ) -> tuple[
        tuple[FactEvent, ...],
        dict[str, tuple[str, ...]],
        dict[str, tuple[FactEvidence, ...]],
    ]:
        mutation = FACT_MUTATION_ADAPTER.validate_python(mutation, strict=True)
        self._validate_client_consistency(mutation)
        common: dict[str, object] = {
            "commit_version": commit_version,
            "publication_operation_id": operation_id,
            "visible_runtime_epoch": runtime_epoch,
            "transaction_id": operation_id,
            "recorded_at": now,
            "approved_at": now,
        }
        if isinstance(mutation, AddMutation):
            event = mutation.new_fact.model_copy(
                update={
                    **common,
                    "mutation_type": "ADD",
                    "event_version": 1,
                    "previous_event_id": None,
                    "supersedes_event_id": None,
                    "replacement_event_id": None,
                }
            )
            return (event,), {}, {}

        if isinstance(mutation, MergeMutation):
            projection = mutation.canonical_projection.model_copy(
                update={
                    **common,
                    "mutation_type": "MERGE",
                    "event_version": 1,
                    "previous_event_id": None,
                    "supersedes_event_id": None,
                    "replacement_event_id": None,
                    "source_event_ids": tuple(sorted(mutation.member_event_ids)),
                }
            )
            return (
                (projection,),
                {projection.event_id: tuple(mutation.member_event_ids)},
                {},
            )

        target = self._repository.get_event(mutation.target_event_id)
        new_event_id = self._ids.object_id("fact_event")
        lineage = tuple(sorted({*target.source_event_ids, target.event_id}))
        version_update: dict[str, object] = {
            **common,
            "event_id": new_event_id,
            "event_version": target.event_version + 1,
            "previous_event_id": target.event_id,
            "source_event_ids": lineage,
        }
        if isinstance(mutation, ConfirmMutation):
            confidence = 1.0 - (
                (1.0 - target.fact_confidence)
                * (1.0 - mutation.calibrated_confidence)
            )
            event = target.model_copy(
                update={
                    **version_update,
                    "mutation_type": "CONFIRM",
                    "fact_confidence": min(1.0, confidence),
                    "review_reason": mutation.reason,
                }
            )
            return (event,), {}, {event.event_id: mutation.evidence}
        if isinstance(mutation, CorrectMutation):
            if mutation.previous_value_json != target.object_json:
                raise MutationConflict
            updates: dict[str, object] = {
                **version_update,
                "mutation_type": "CORRECT",
                "review_reason": mutation.reason,
                "effective_from": mutation.effective_at,
            }
            if mutation.correction_kind == "value":
                updates["object_json"] = mutation.new_value_json
            elif mutation.correction_kind == "time":
                updates["effective_from"] = mutation.new_effective_from
                updates["effective_to"] = mutation.new_effective_to
            else:
                if mutation.previous_validity_status != target.validity_status:
                    raise MutationConflict
                updates["validity_status"] = "invalidated"
            return (target.model_copy(update=updates),), {}, {}
        if isinstance(mutation, ResolveMutation):
            event = target.model_copy(
                update={
                    **version_update,
                    "mutation_type": "RESOLVE",
                    "resolution_status": "resolved",
                    "effective_from": mutation.resolved_at,
                    "review_reason": mutation.reason,
                }
            )
            return (event,), {}, {}
        if isinstance(mutation, SupersedeMutation):
            if mutation.replacement.fact_id == target.fact_id:
                raise MutationConflict
            old_event = target.model_copy(
                update={
                    **version_update,
                    "mutation_type": "SUPERSEDE",
                    "validity_status": "superseded",
                    "effective_from": mutation.effective_at,
                    "replacement_event_id": mutation.replacement.event_id,
                    "review_reason": mutation.reason,
                }
            )
            replacement = mutation.replacement.model_copy(
                update={
                    **common,
                    "mutation_type": "SUPERSEDE",
                    "event_version": 1,
                    "previous_event_id": None,
                    "replacement_event_id": None,
                    "supersedes_event_id": target.event_id,
                    "source_event_ids": tuple(
                        sorted(
                            {
                                *mutation.replacement.source_event_ids,
                                target.event_id,
                            }
                        )
                    ),
                }
            )
            # Insert the replacement first because the immutable supersede event
            # carries a restrictive foreign key to it.
            return (replacement, old_event), {}, {}
        raise TypeError("unsupported fact mutation")

    def _validate_merge(self, mutation: MergeMutation) -> None:
        members = tuple(
            self._repository.get_event(event_id) for event_id in mutation.member_event_ids
        )
        if any(
            self._repository.get_latest_event(event.fact_id).event_id != event.event_id
            or not self._is_current_eligible(event)
            for event in members
        ):
            raise MutationConflict
        signatures = {
            (
                event.client_id,
                event.subject,
                event.predicate,
                event.object_json,
                event.effective_from,
                event.effective_to,
                event.cognitive_type,
                event.relation_type,
                event.privacy_level,
                event.allowed_purposes_json,
                event.applicability_json,
            )
            for event in members
        }
        projection_signature = (
            mutation.canonical_projection.client_id,
            mutation.canonical_projection.subject,
            mutation.canonical_projection.predicate,
            mutation.canonical_projection.object_json,
            mutation.canonical_projection.effective_from,
            mutation.canonical_projection.effective_to,
            mutation.canonical_projection.cognitive_type,
            mutation.canonical_projection.relation_type,
            mutation.canonical_projection.privacy_level,
            mutation.canonical_projection.allowed_purposes_json,
            mutation.canonical_projection.applicability_json,
        )
        if len(signatures) != 1 or projection_signature not in signatures:
            raise MutationConflict
        if {
            event.client_id for event in members
        } != {mutation.canonical_projection.client_id}:
            raise MutationConflict

    def _validate_client_consistency(self, mutation: FactMutation) -> None:
        if isinstance(mutation, AddMutation):
            client_id = mutation.new_fact.client_id
        elif isinstance(mutation, MergeMutation):
            self._validate_merge(mutation)
            client_id = mutation.canonical_projection.client_id
        else:
            target = self._repository.get_event(mutation.target_event_id)
            if (
                self._repository.get_latest_event(target.fact_id).event_id
                != target.event_id
                or not self._is_current_eligible(target)
            ):
                raise MutationConflict
            client_id = target.client_id
            if isinstance(mutation, CorrectMutation):
                if mutation.previous_value_json != target.object_json:
                    raise MutationConflict
                if (
                    mutation.correction_kind == "validity"
                    and mutation.previous_validity_status != target.validity_status
                ):
                    raise MutationConflict
                if mutation.correction_kind == "time" and (
                    mutation.new_effective_from,
                    mutation.new_effective_to,
                ) == (target.effective_from, target.effective_to):
                    raise MutationConflict
            if (
                isinstance(mutation, SupersedeMutation)
                and (
                    mutation.replacement.client_id != client_id
                    or mutation.replacement.fact_id == target.fact_id
                )
            ):
                raise MutationConflict
        bound_client_id = self._repository.bound_client_id()
        if bound_client_id is not None and bound_client_id != client_id:
            raise MutationConflict

    @staticmethod
    def _is_current_eligible(event: FactEvent) -> bool:
        return (
            event.review_status == "approved"
            and event.validity_status == "active"
            and event.resolution_status == "open"
        )

    @staticmethod
    def dependency_edges(mutation: FactMutation) -> tuple[DependencyEdge, ...]:
        if isinstance(mutation, (AddMutation, SupersedeMutation, MergeMutation)):
            return tuple(sorted(mutation.dependency_edges, key=lambda edge: edge.edge_id))
        return ()

    @staticmethod
    def _target_id(mutation: FactMutation) -> str:
        if isinstance(mutation, AddMutation):
            return mutation.new_fact.fact_id
        if isinstance(mutation, MergeMutation):
            return mutation.canonical_projection.fact_id
        return mutation.target_event_id

    def _client_id(self, mutation: FactMutation) -> str:
        if isinstance(mutation, AddMutation):
            return mutation.new_fact.client_id
        if isinstance(mutation, MergeMutation):
            return mutation.canonical_projection.client_id
        return self._repository.get_event(mutation.target_event_id).client_id

    @staticmethod
    def _human_diff(mutation: FactMutation) -> str:
        if isinstance(mutation, AddMutation):
            return f"ADD {mutation.new_fact.subject}.{mutation.new_fact.predicate}"
        if isinstance(mutation, ConfirmMutation):
            return f"CONFIRM {mutation.target_event_id} with {len(mutation.evidence)} source(s)"
        if isinstance(mutation, CorrectMutation):
            return f"CORRECT {mutation.target_event_id} ({mutation.correction_kind})"
        if isinstance(mutation, SupersedeMutation):
            return f"SUPERSEDE {mutation.target_event_id} -> {mutation.replacement.fact_id}"
        if isinstance(mutation, ResolveMutation):
            return f"RESOLVE {mutation.target_event_id}"
        return f"MERGE {len(mutation.member_event_ids)} events"


__all__ = [
    "ApprovedMutation",
    "DuplicateFact",
    "FactMutationService",
    "MutationCommitResult",
    "MutationConflict",
    "MutationMismatch",
    "MutationPreview",
]
