"""Deterministic reciprocal-rank fusion with evidence-preserving grouping."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Mapping, TypeAlias

from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.common import ObjectId, VersionRef
from consultation_kb.models.evidence import (
    C1ApplicabilityDecision,
    EmpiricalSupport,
    SourceGrade,
)
from consultation_kb.retrieval.contracts import CandidateRef


EvidenceStance: TypeAlias = Literal[
    "support", "contradiction", "alternative", "context"
]


class FusionContractError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FusionAuthorityBinding:
    run_id: str
    global_runtime_epoch: int
    client_runtime_epoch: int
    tombstone_epoch: int
    authorization_epoch: int
    policy_ref: VersionRef
    decision_sha256: str

    @classmethod
    def from_candidate(cls, candidate: CandidateRef) -> "FusionAuthorityBinding":
        value = candidate.filter_binding
        if value is None:
            raise FusionContractError("FUSION_FILTER_BINDING_REQUIRED")
        return cls(
            run_id=value.run_id,
            global_runtime_epoch=value.global_runtime_epoch,
            client_runtime_epoch=value.client_runtime_epoch,
            tombstone_epoch=value.tombstone_epoch,
            authorization_epoch=value.authorization_epoch,
            policy_ref=value.policy_ref,
            decision_sha256=value.decision_sha256,
        )


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _source_key(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class FusionEvidence:
    """One ranked Passage candidate plus its evidence role."""

    candidate: CandidateRef
    stance: EvidenceStance
    theory_ref: VersionRef | None = None
    empirical_support: EmpiricalSupport = "unassessed"

    def __post_init__(self) -> None:
        FusionAuthorityBinding.from_candidate(self.candidate)
        is_c1 = self.candidate.metadata.source_grade == "C1"
        if is_c1 != (self.theory_ref is not None):
            raise FusionContractError("FUSION_C1_THEORY_BINDING_INVALID")

    @property
    def claim_ref(self) -> VersionRef:
        return self.candidate.reference

    @property
    def passage_ref(self) -> VersionRef:
        return self.candidate.content_ref

    @property
    def source_keys(self) -> tuple[str, ...]:
        provenance = self.candidate.provenance
        values = {
            *(_source_key("source", value) for value in provenance.source_ids),
            *(_source_key("case", value) for value in provenance.case_ids),
        }
        if not values and provenance.provenance_scope == "client_private":
            values.add(_source_key("private", "current_subject"))
        return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class FusedPassage:
    """One losslessly expandable Passage inside a fused Claim group."""

    evidence_id: ObjectId
    candidate: CandidateRef
    source_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FusedCandidate:
    evidence_id: ObjectId
    claim_ref: VersionRef
    passage_refs: tuple[VersionRef, ...]
    members: tuple[CandidateRef, ...]
    passages: tuple[FusedPassage, ...]
    stance: EvidenceStance
    source_keys: tuple[str, ...]
    source_grade: SourceGrade
    empirical_support: EmpiricalSupport
    theory_ref: VersionRef | None
    rrf_score: float
    channel_ranks: Mapping[str, int]
    primary_framework: bool
    framework_boost: float
    authority_binding: FusionAuthorityBinding


def _ref_parts(reference: VersionRef) -> tuple[str, str, str]:
    return (
        reference.object_id,
        str(reference.version),
        reference.content_sha256,
    )


def _evidence_id(claim_ref: VersionRef, stance: EvidenceStance) -> ObjectId:
    return deterministic_object_id("evidence", *_ref_parts(claim_ref), stance)


def _passage_evidence_id(
    claim_ref: VersionRef,
    passage_ref: VersionRef,
    stance: EvidenceStance,
) -> ObjectId:
    return deterministic_object_id(
        "evidence",
        *_ref_parts(claim_ref),
        *_ref_parts(passage_ref),
        stance,
    )


class ReciprocalRankFusion:
    """Fuse channel ranks only; raw channel scores never cross this boundary."""

    def __init__(self, *, k: int = 60) -> None:
        if type(k) is not int or k <= 0:
            raise ValueError("RRF k must be a positive exact integer")
        self._k = k

    def fuse(
        self,
        channel_rankings: Mapping[str, tuple[FusionEvidence, ...]],
        *,
        c1_applicability: C1ApplicabilityDecision | None = None,
        limit: int | None = None,
        minimum_contradictions: int = 0,
        minimum_alternatives: int = 0,
    ) -> tuple[FusedCandidate, ...]:
        if limit is not None and (type(limit) is not int or limit <= 0):
            raise ValueError("fusion limit must be a positive exact integer")
        for value in (minimum_contradictions, minimum_alternatives):
            if type(value) is not int or value < 0:
                raise ValueError("fusion retention floors must be non-negative integers")

        groups: dict[
            tuple[tuple[str, int, str], EvidenceStance],
            list[tuple[str, int, FusionEvidence]],
        ] = {}
        authority_binding: FusionAuthorityBinding | None = None
        for channel in sorted(channel_rankings):
            if not channel:
                raise FusionContractError("FUSION_CHANNEL_INVALID")
            ranking = channel_rankings[channel]
            for rank, evidence in enumerate(ranking, start=1):
                if evidence.candidate.channel != channel:
                    raise FusionContractError("FUSION_CHANNEL_BINDING_INVALID")
                candidate_binding = FusionAuthorityBinding.from_candidate(
                    evidence.candidate
                )
                if authority_binding is None:
                    authority_binding = candidate_binding
                elif authority_binding != candidate_binding:
                    raise FusionContractError(
                        "FUSION_AUTHORITY_BINDING_MISMATCH"
                    )
                key = (_ref_key(evidence.claim_ref), evidence.stance)
                groups.setdefault(key, []).append((channel, rank, evidence))

        fused: list[FusedCandidate] = []
        for (_claim_key, stance), contributions in sorted(groups.items()):
            claim_ref = contributions[0][2].claim_ref
            grades = {
                contribution.candidate.metadata.source_grade
                for _, _, contribution in contributions
            }
            empirical = {
                contribution.empirical_support
                for _, _, contribution in contributions
            }
            theory_refs = {contribution.theory_ref for _, _, contribution in contributions}
            if len(grades) != 1 or len(empirical) != 1 or len(theory_refs) != 1:
                raise FusionContractError("FUSION_AUTHORITY_CONFLICT")

            channel_ranks: dict[str, int] = {}
            for channel, rank, _evidence in contributions:
                channel_ranks[channel] = min(channel_ranks.get(channel, rank), rank)
            rrf_score = math.fsum(
                1.0 / (self._k + rank) for rank in channel_ranks.values()
            )

            passages = tuple(
                sorted(
                    {item.passage_ref for _, _, item in contributions},
                    key=_ref_key,
                )
            )
            source_keys = tuple(
                sorted(
                    {
                        source
                        for _, _, item in contributions
                        for source in item.source_keys
                    }
                )
            )
            member_by_passage: dict[tuple[str, int, str], CandidateRef] = {}
            sources_by_passage: dict[tuple[str, int, str], set[str]] = {}
            for _, _, evidence in sorted(
                contributions,
                key=lambda item: (
                    _ref_key(item[2].passage_ref),
                    item[2].candidate.channel,
                ),
            ):
                passage_key = _ref_key(evidence.passage_ref)
                member_by_passage.setdefault(passage_key, evidence.candidate)
                sources_by_passage.setdefault(passage_key, set()).update(
                    evidence.source_keys
                )
            fused_passages = tuple(
                FusedPassage(
                    evidence_id=_passage_evidence_id(
                        claim_ref,
                        candidate.content_ref,
                        stance,
                    ),
                    candidate=candidate,
                    source_keys=tuple(sorted(sources_by_passage[passage_key])),
                )
                for passage_key, candidate in sorted(member_by_passage.items())
            )
            theory_ref = next(iter(theory_refs))
            primary = self._is_primary_c1(
                source_grade=next(iter(grades)),
                theory_ref=theory_ref,
                decision=c1_applicability,
            )
            fused.append(
                FusedCandidate(
                    evidence_id=_evidence_id(claim_ref, stance),
                    claim_ref=claim_ref,
                    passage_refs=passages,
                    members=tuple(member_by_passage.values()),
                    passages=fused_passages,
                    stance=stance,
                    source_keys=source_keys,
                    source_grade=next(iter(grades)),
                    empirical_support=next(iter(empirical)),
                    theory_ref=theory_ref,
                    rrf_score=rrf_score,
                    channel_ranks=MappingProxyType(dict(sorted(channel_ranks.items()))),
                    primary_framework=primary,
                    framework_boost=1.0 if primary else 0.0,
                    authority_binding=(
                        authority_binding
                        if authority_binding is not None
                        else FusionAuthorityBinding.from_candidate(
                            contributions[0][2].candidate
                        )
                    ),
                )
            )

        fused.sort(
            key=lambda item: (
                -int(item.primary_framework),
                -item.rrf_score,
                item.evidence_id,
            )
        )
        if limit is None or len(fused) <= limit:
            return tuple(fused)
        required_primary = 1 if any(item.primary_framework for item in fused) else 0
        if required_primary + minimum_contradictions + minimum_alternatives > limit:
            raise ValueError("fusion limit is smaller than mandatory retention floors")

        selected: set[str] = set()

        def reserve(values: list[FusedCandidate], count: int) -> None:
            for item in values:
                if len([value for value in values if value.evidence_id in selected]) >= count:
                    break
                selected.add(item.evidence_id)

        reserve([item for item in fused if item.primary_framework], required_primary)
        reserve(
            [item for item in fused if item.stance == "contradiction"],
            minimum_contradictions,
        )
        reserve(
            [item for item in fused if item.stance == "alternative"],
            minimum_alternatives,
        )
        for item in fused:
            if len(selected) >= limit:
                break
            selected.add(item.evidence_id)
        return tuple(item for item in fused if item.evidence_id in selected)

    @staticmethod
    def _is_primary_c1(
        *,
        source_grade: str,
        theory_ref: VersionRef | None,
        decision: C1ApplicabilityDecision | None,
    ) -> bool:
        return bool(
            source_grade == "C1"
            and theory_ref is not None
            and decision is not None
            and decision.status == "applicable"
            and decision.effective_status == "active"
            and decision.revision == theory_ref
        )


__all__ = [
    "EvidenceStance",
    "FusedCandidate",
    "FusedPassage",
    "FusionAuthorityBinding",
    "FusionContractError",
    "FusionEvidence",
    "ReciprocalRankFusion",
]
