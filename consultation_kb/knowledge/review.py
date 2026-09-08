"""Human review projections that keep source text and proposed claims separate."""

from __future__ import annotations

from collections.abc import Callable

from consultation_kb.models.common import NonEmptyStr, StrictModel, VersionRef
from consultation_kb.models.evidence import EvidenceLocator
from consultation_kb.models.knowledge import ClaimApplicability, ClaimDraft


class ResolvedEvidence(StrictModel):
    passage_ref: VersionRef
    original_text: NonEmptyStr
    context_before: NonEmptyStr | None
    context_after: NonEmptyStr | None
    locator: EvidenceLocator
    relation: str


class ClaimReviewView(StrictModel):
    proposed_claim: NonEmptyStr
    cognitive_type: str
    source_grade: str
    applicability: ClaimApplicability
    evidence: tuple[ResolvedEvidence, ...]
    conflict_candidate_refs: tuple[VersionRef, ...]
    diff_summary: NonEmptyStr


class ClaimReviewResolver:
    def __init__(
        self,
        resolver: Callable[[VersionRef], tuple[str, str | None, str | None, EvidenceLocator]],
    ) -> None:
        self._resolver = resolver

    def resolve(
        self,
        draft: ClaimDraft,
        *,
        conflict_candidate_refs: tuple[VersionRef, ...] = (),
    ) -> ClaimReviewView:
        validated = ClaimDraft.model_validate(draft)
        evidence: list[ResolvedEvidence] = []
        for reference in validated.evidence:
            original, before, after, locator = self._resolver(reference.passage_ref)
            evidence.append(
                ResolvedEvidence(
                    passage_ref=reference.passage_ref,
                    original_text=original,
                    context_before=before,
                    context_after=after,
                    locator=locator,
                    relation=reference.relation,
                )
            )
        return ClaimReviewView(
            proposed_claim=validated.text,
            cognitive_type=validated.cognitive_type,
            source_grade=validated.source_grade,
            applicability=validated.applicability,
            evidence=tuple(evidence),
            conflict_candidate_refs=conflict_candidate_refs,
            diff_summary=f"新增原子主张，证据 {len(evidence)} 条",
        )


__all__ = ["ClaimReviewResolver", "ClaimReviewView", "ResolvedEvidence"]
