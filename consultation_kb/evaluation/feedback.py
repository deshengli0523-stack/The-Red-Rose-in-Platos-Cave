"""Deterministic counselor-feedback analysis with a narrow write boundary.

Feedback may identify evaluation failures and may propose material for the P3
draft ingestion queue.  It cannot publish Wiki pages, CasePatterns, or client
long-term facts; those governed stores are intentionally absent from both the
artifact union and the sink protocol.
"""

from __future__ import annotations

from typing import Literal, Protocol, TypeAlias

from pydantic import model_validator
from typing_extensions import Self

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import (
    NonNegativeInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)
from consultation_kb.models.evaluation import SyntheticText


FeedbackDimension: TypeAlias = Literal[
    "consultation_helpfulness",
    "empathy",
    "specificity",
    "actionability",
    "autonomy_support",
    "fact_evidence_fidelity",
    "conflict_uncertainty_handling",
    "professional_boundaries",
]
FailureSlice: TypeAlias = Literal[
    "retrieval_missing_evidence",
    "generation_candidate_rejected",
    "generation_consultation_helpfulness",
    "generation_empathy",
    "generation_specificity",
    "generation_actionability",
    "generation_autonomy_support",
    "generation_fact_evidence_fidelity",
    "generation_conflict_uncertainty_handling",
    "generation_professional_boundaries",
    "profile_fact_correction",
    "outcome_not_improved",
    "runtime_degradation",
]
FindingSeverity: TypeAlias = Literal["low", "medium", "high"]


def _canonical_nonempty(values: tuple[str, ...], field_name: str) -> None:
    if not values or tuple(sorted(set(values))) != values:
        raise ValueError(f"{field_name} must be sorted, unique, and non-empty")


class CounselorEditDiff(StrictModel):
    candidate_sha256: Sha256Hex
    delivered_reply_sha256: Sha256Hex
    changed_dimensions: tuple[FeedbackDimension, ...]
    edit_reason_codes: tuple[SafePolicyKey, ...]
    changed_token_count: NonNegativeInt

    @model_validator(mode="after")
    def _diff_contract(self) -> Self:
        changed = self.candidate_sha256 != self.delivered_reply_sha256
        if changed:
            _canonical_nonempty(self.changed_dimensions, "changed_dimensions")
            _canonical_nonempty(self.edit_reason_codes, "edit_reason_codes")
            if self.changed_token_count == 0:
                raise ValueError("a changed reply must report changed tokens")
        elif (
            self.changed_dimensions
            or self.edit_reason_codes
            or self.changed_token_count
        ):
            raise ValueError("an unchanged reply cannot report an edit diff")
        return self


class EvidenceGap(StrictModel):
    gap_id: SafePolicyKey
    evidence_kind: SafePolicyKey
    reason_code: SafePolicyKey
    draft_summary: SyntheticText


class ClientFactCorrection(StrictModel):
    """Value-free signal; corrected client content stays in the client vault."""

    field_key: SafePolicyKey
    correction_kind: Literal["incorrect", "resolved", "superseded"]
    affected_dependency_count: NonNegativeInt


class FollowupOutcome(StrictModel):
    status: Literal["improved", "unchanged", "worsened", "unknown"]
    observed_after_sessions: NonNegativeInt
    reason_codes: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _outcome_contract(self) -> Self:
        if self.status == "unknown":
            if self.observed_after_sessions != 0:
                raise ValueError("unknown outcome cannot claim observed sessions")
        elif self.observed_after_sessions == 0:
            raise ValueError("known outcome requires at least one later session")
        if self.reason_codes and tuple(sorted(set(self.reason_codes))) != (
            self.reason_codes
        ):
            raise ValueError("outcome reason codes must be sorted and unique")
        return self


class CounselorFeedback(StrictModel):
    record_type: Literal["counselor_feedback"] = "counselor_feedback"
    schema_version: Literal["counselor_feedback.v1"] = "counselor_feedback.v1"
    feedback_id: SafePolicyKey
    case_id: SafePolicyKey
    candidate_disposition: Literal["accepted", "edited", "rejected"]
    selected_candidate_sha256: Sha256Hex
    edit_diff: CounselorEditDiff | None
    missing_evidence: tuple[EvidenceGap, ...]
    client_fact_corrections: tuple[ClientFactCorrection, ...]
    followup_outcome: FollowupOutcome | None
    degradation_codes: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _feedback_contract(self) -> Self:
        if not self.feedback_id.startswith("feedback_"):
            raise ValueError("feedback ID must use the feedback namespace")
        if self.candidate_disposition == "edited":
            if self.edit_diff is None:
                raise ValueError("edited candidate requires an exact edit diff")
            if self.edit_diff.candidate_sha256 != self.selected_candidate_sha256:
                raise ValueError("edit diff does not belong to selected candidate")
            if self.edit_diff.candidate_sha256 == self.edit_diff.delivered_reply_sha256:
                raise ValueError("edited candidate must differ from delivered reply")
        elif self.edit_diff is not None:
            raise ValueError("only an edited candidate may carry an edit diff")
        gap_ids = tuple(item.gap_id for item in self.missing_evidence)
        if tuple(sorted(set(gap_ids))) != gap_ids:
            raise ValueError("evidence gaps must be sorted and uniquely named")
        correction_keys = tuple(
            (item.field_key, item.correction_kind)
            for item in self.client_fact_corrections
        )
        if tuple(sorted(set(correction_keys))) != correction_keys:
            raise ValueError("client fact corrections must be sorted and unique")
        if (
            self.degradation_codes
            and tuple(sorted(set(self.degradation_codes))) != self.degradation_codes
        ):
            raise ValueError("degradation codes must be sorted and unique")
        return self

    @property
    def feedback_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class EvaluationFinding(StrictModel):
    artifact_kind: Literal["evaluation_finding"] = "evaluation_finding"
    schema_version: Literal["evaluation_finding.v1"] = "evaluation_finding.v1"
    finding_id: SafePolicyKey
    case_id: SafePolicyKey
    failure_slice: FailureSlice
    severity: FindingSeverity
    signal_codes: tuple[SafePolicyKey, ...]
    selected_candidate_sha256: Sha256Hex
    source_feedback_sha256: Sha256Hex

    @model_validator(mode="after")
    def _finding_contract(self) -> Self:
        if not self.finding_id.startswith("finding_"):
            raise ValueError("finding ID must use the finding namespace")
        _canonical_nonempty(self.signal_codes, "signal_codes")
        return self


class P3DraftProposal(StrictModel):
    """A review-only suggestion, never a published knowledge object."""

    artifact_kind: Literal["p3_draft_proposal"] = "p3_draft_proposal"
    schema_version: Literal["p3_draft_proposal.v1"] = "p3_draft_proposal.v1"
    proposal_id: SafePolicyKey
    case_id: SafePolicyKey
    proposal_kind: Literal["source_gap", "theory_clarification"]
    draft_summary: SyntheticText
    originating_finding_ids: tuple[SafePolicyKey, ...]
    source_feedback_sha256: Sha256Hex
    publication_target: Literal["p3_review_queue"] = "p3_review_queue"
    status: Literal["draft"] = "draft"
    human_review_required: Literal[True] = True

    @model_validator(mode="after")
    def _proposal_contract(self) -> Self:
        if not self.proposal_id.startswith("proposal_"):
            raise ValueError("proposal ID must use the proposal namespace")
        _canonical_nonempty(self.originating_finding_ids, "originating_finding_ids")
        return self


class FeedbackAnalysis(StrictModel):
    source_feedback_sha256: Sha256Hex
    findings: tuple[EvaluationFinding, ...]
    draft_proposals: tuple[P3DraftProposal, ...]

    @model_validator(mode="after")
    def _analysis_contract(self) -> Self:
        finding_ids = tuple(item.finding_id for item in self.findings)
        proposal_ids = tuple(item.proposal_id for item in self.draft_proposals)
        if tuple(sorted(set(finding_ids))) != finding_ids:
            raise ValueError("findings must be sorted and uniquely named")
        if tuple(sorted(set(proposal_ids))) != proposal_ids:
            raise ValueError("draft proposals must be sorted and uniquely named")
        if any(
            item.source_feedback_sha256 != self.source_feedback_sha256
            for item in self.findings
        ) or any(
            item.source_feedback_sha256 != self.source_feedback_sha256
            for item in self.draft_proposals
        ):
            raise ValueError("feedback analysis contains foreign artifacts")
        known_findings = set(finding_ids)
        if any(
            not set(item.originating_finding_ids).issubset(known_findings)
            for item in self.draft_proposals
        ):
            raise ValueError("draft proposal references an unknown finding")
        return self

    @property
    def artifacts(self) -> tuple[EvaluationFinding | P3DraftProposal, ...]:
        return (*self.findings, *self.draft_proposals)


class FeedbackArtifactSink(Protocol):
    """The only persistence authority exposed to ``FeedbackAnalyzer``."""

    def write_evaluation_finding(self, finding: EvaluationFinding) -> None: ...

    def write_p3_draft_proposal(self, proposal: P3DraftProposal) -> None: ...


_DIMENSION_TO_SLICE: dict[FeedbackDimension, FailureSlice] = {
    "consultation_helpfulness": "generation_consultation_helpfulness",
    "empathy": "generation_empathy",
    "specificity": "generation_specificity",
    "actionability": "generation_actionability",
    "autonomy_support": "generation_autonomy_support",
    "fact_evidence_fidelity": "generation_fact_evidence_fidelity",
    "conflict_uncertainty_handling": ("generation_conflict_uncertainty_handling"),
    "professional_boundaries": "generation_professional_boundaries",
}


def _stable_id(kind: str, payload: object) -> str:
    return f"{kind}_{canonical_sha256(payload)[:32]}"


class FeedbackAnalyzer:
    """Convert structured signals into bounded evaluation-only artifacts."""

    def analyze(self, feedback: CounselorFeedback) -> FeedbackAnalysis:
        exact = CounselorFeedback.model_validate(feedback)
        digest = exact.feedback_sha256
        findings: list[EvaluationFinding] = []

        def add_finding(
            failure_slice: FailureSlice,
            severity: FindingSeverity,
            signal_codes: tuple[str, ...],
            discriminator: str,
        ) -> EvaluationFinding:
            ordered_codes = tuple(sorted(set(signal_codes)))
            finding = EvaluationFinding(
                finding_id=_stable_id(
                    "finding",
                    {
                        "feedback_sha256": digest,
                        "failure_slice": failure_slice,
                        "discriminator": discriminator,
                    },
                ),
                case_id=exact.case_id,
                failure_slice=failure_slice,
                severity=severity,
                signal_codes=ordered_codes,
                selected_candidate_sha256=exact.selected_candidate_sha256,
                source_feedback_sha256=digest,
            )
            findings.append(finding)
            return finding

        if exact.candidate_disposition == "rejected":
            add_finding(
                "generation_candidate_rejected",
                "high",
                ("counselor_rejected_candidate",),
                "candidate_rejected",
            )
        if exact.edit_diff is not None:
            for dimension in exact.edit_diff.changed_dimensions:
                add_finding(
                    _DIMENSION_TO_SLICE[dimension],
                    "medium",
                    (*exact.edit_diff.edit_reason_codes, "counselor_edited_candidate"),
                    dimension,
                )

        gap_findings: dict[str, EvaluationFinding] = {}
        for gap in exact.missing_evidence:
            gap_findings[gap.gap_id] = add_finding(
                "retrieval_missing_evidence",
                "high",
                (gap.evidence_kind, gap.reason_code),
                gap.gap_id,
            )

        for correction in exact.client_fact_corrections:
            add_finding(
                "profile_fact_correction",
                "high" if correction.affected_dependency_count else "medium",
                (
                    f"correction_{correction.correction_kind}",
                    "client_fact_value_retained_in_client_scope",
                ),
                f"{correction.field_key}_{correction.correction_kind}",
            )

        if exact.followup_outcome is not None and exact.followup_outcome.status in {
            "unchanged",
            "worsened",
        }:
            add_finding(
                "outcome_not_improved",
                "high" if exact.followup_outcome.status == "worsened" else "medium",
                (
                    *exact.followup_outcome.reason_codes,
                    f"outcome_{exact.followup_outcome.status}",
                ),
                f"outcome_{exact.followup_outcome.status}",
            )

        for code in exact.degradation_codes:
            add_finding(
                "runtime_degradation",
                "medium",
                (code,),
                code,
            )

        proposals = tuple(
            P3DraftProposal(
                proposal_id=_stable_id(
                    "proposal",
                    {
                        "feedback_sha256": digest,
                        "gap_id": gap.gap_id,
                        "finding_id": gap_findings[gap.gap_id].finding_id,
                    },
                ),
                case_id=exact.case_id,
                proposal_kind=(
                    "theory_clarification"
                    if gap.evidence_kind == "theory"
                    else "source_gap"
                ),
                draft_summary=gap.draft_summary,
                originating_finding_ids=(gap_findings[gap.gap_id].finding_id,),
                source_feedback_sha256=digest,
            )
            for gap in exact.missing_evidence
        )
        return FeedbackAnalysis(
            source_feedback_sha256=digest,
            findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
            draft_proposals=tuple(sorted(proposals, key=lambda item: item.proposal_id)),
        )

    def persist(self, analysis: FeedbackAnalysis, sink: FeedbackArtifactSink) -> None:
        """Persist only evaluation findings and review-gated P3 drafts."""

        exact = FeedbackAnalysis.model_validate(analysis)
        for finding in exact.findings:
            sink.write_evaluation_finding(finding)
        for proposal in exact.draft_proposals:
            sink.write_p3_draft_proposal(proposal)


CounselorFeedbackRecord = CounselorFeedback


__all__ = [
    "ClientFactCorrection",
    "CounselorEditDiff",
    "CounselorFeedback",
    "CounselorFeedbackRecord",
    "EvaluationFinding",
    "EvidenceGap",
    "FailureSlice",
    "FeedbackAnalysis",
    "FeedbackAnalyzer",
    "FeedbackArtifactSink",
    "FeedbackDimension",
    "FollowupOutcome",
    "P3DraftProposal",
]
