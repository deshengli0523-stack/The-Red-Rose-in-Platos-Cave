from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.evaluation.feedback import (
    ClientFactCorrection,
    CounselorEditDiff,
    CounselorFeedback,
    EvidenceGap,
    FeedbackAnalyzer,
    FollowupOutcome,
    P3DraftProposal,
)


CANDIDATE_SHA = "a" * 64
DELIVERED_SHA = "b" * 64


def _feedback() -> CounselorFeedback:
    return CounselorFeedback(
        feedback_id="feedback_alpha",
        case_id="syn_case_feedback",
        candidate_disposition="edited",
        selected_candidate_sha256=CANDIDATE_SHA,
        edit_diff=CounselorEditDiff(
            candidate_sha256=CANDIDATE_SHA,
            delivered_reply_sha256=DELIVERED_SHA,
            changed_dimensions=("empathy", "specificity"),
            edit_reason_codes=("insufficient_context",),
            changed_token_count=18,
        ),
        missing_evidence=(
            EvidenceGap(
                gap_id="gap_theory_scope",
                evidence_kind="theory",
                reason_code="scope_rule_missing",
                draft_summary="补充该理论适用边界的受控资料候选。",
            ),
        ),
        client_fact_corrections=(
            ClientFactCorrection(
                field_key="current_relationship",
                correction_kind="superseded",
                affected_dependency_count=3,
            ),
        ),
        followup_outcome=FollowupOutcome(
            status="worsened",
            observed_after_sessions=1,
            reason_codes=("goal_not_advanced",),
        ),
        degradation_codes=("reranker_unavailable",),
    )


def test_feedback_analyzer_links_all_signals_to_failure_slices() -> None:
    analysis = FeedbackAnalyzer().analyze(_feedback())
    slices = {finding.failure_slice for finding in analysis.findings}

    assert slices == {
        "generation_empathy",
        "generation_specificity",
        "retrieval_missing_evidence",
        "profile_fact_correction",
        "outcome_not_improved",
        "runtime_degradation",
    }
    assert len(analysis.draft_proposals) == 1
    proposal = analysis.draft_proposals[0]
    assert proposal.artifact_kind == "p3_draft_proposal"
    assert proposal.publication_target == "p3_review_queue"
    assert proposal.status == "draft"
    assert proposal.human_review_required is True
    assert set(proposal.originating_finding_ids) <= {
        item.finding_id for item in analysis.findings
    }
    assert FeedbackAnalyzer().analyze(_feedback()) == analysis


class _RecordingSink:
    def __init__(self) -> None:
        self.kinds: list[str] = []
        self.direct_writes: list[str] = []

    def write_evaluation_finding(self, finding) -> None:
        self.kinds.append(finding.artifact_kind)

    def write_p3_draft_proposal(self, proposal) -> None:
        self.kinds.append(proposal.artifact_kind)

    def write_wiki(self, value) -> None:
        self.direct_writes.append("wiki")

    def write_case_pattern(self, value) -> None:
        self.direct_writes.append("case_pattern")

    def write_client_long_term_fact(self, value) -> None:
        self.direct_writes.append("client_long_term_fact")


def test_persistence_boundary_only_writes_findings_and_p3_drafts() -> None:
    analyzer = FeedbackAnalyzer()
    analysis = analyzer.analyze(_feedback())
    sink = _RecordingSink()

    analyzer.persist(analysis, sink)

    assert set(sink.kinds) == {"evaluation_finding", "p3_draft_proposal"}
    assert sink.direct_writes == []
    with pytest.raises(ValidationError):
        P3DraftProposal(
            proposal_id="proposal_forbidden",
            case_id="syn_case_feedback",
            proposal_kind="source_gap",
            draft_summary="一个尚待审核的候选。",
            originating_finding_ids=(analysis.findings[0].finding_id,),
            source_feedback_sha256=analysis.source_feedback_sha256,
            publication_target="wiki",
        )


def test_client_fact_correction_never_becomes_shared_knowledge_proposal() -> None:
    feedback = CounselorFeedback(
        feedback_id="feedback_fact_only",
        case_id="syn_case_fact_only",
        candidate_disposition="accepted",
        selected_candidate_sha256=CANDIDATE_SHA,
        edit_diff=None,
        missing_evidence=(),
        client_fact_corrections=(
            ClientFactCorrection(
                field_key="current_partner",
                correction_kind="superseded",
                affected_dependency_count=6,
            ),
        ),
        followup_outcome=None,
        degradation_codes=(),
    )

    analysis = FeedbackAnalyzer().analyze(feedback)

    assert {item.failure_slice for item in analysis.findings} == {
        "profile_fact_correction"
    }
    assert analysis.draft_proposals == ()


def test_edit_contract_rejects_untracked_or_fake_diffs() -> None:
    with pytest.raises(ValidationError, match="changed tokens"):
        CounselorEditDiff(
            candidate_sha256=CANDIDATE_SHA,
            delivered_reply_sha256=DELIVERED_SHA,
            changed_dimensions=("empathy",),
            edit_reason_codes=("tone_changed",),
            changed_token_count=0,
        )

    with pytest.raises(ValidationError, match="requires an exact edit diff"):
        CounselorFeedback(
            feedback_id="feedback_missing_diff",
            case_id="syn_case_missing_diff",
            candidate_disposition="edited",
            selected_candidate_sha256=CANDIDATE_SHA,
            edit_diff=None,
            missing_evidence=(),
            client_fact_corrections=(),
            followup_outcome=None,
            degradation_codes=(),
        )
