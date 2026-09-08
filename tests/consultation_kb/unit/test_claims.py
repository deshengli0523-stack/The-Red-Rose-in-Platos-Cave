from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import locator_policy_ref
from consultation_kb.knowledge.claims import ClaimGovernanceError, ClaimProposalService
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EvidenceLocator, Provenance, SourceGrade
from consultation_kb.models.knowledge import (
    ClaimApplicability,
    ClaimDraft,
    ClaimEvidenceRef,
)
from tests.consultation_kb.knowledge_support import DirectTestApprovalExecutor


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(100, 1000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, digit: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind), version=1, content_sha256=digit * 64
    )


def _draft(*, grade: SourceGrade = "C2") -> ClaimDraft:
    ids = _ids()
    source = _ref(ids, "source", "1")
    support = _ref(ids, "passage", "2")
    oppose = _ref(ids, "passage", "3")
    policy = _ref(ids, "policy", "4")
    values: dict[str, object] = {
        "text": "先澄清事实，现有证据同时存在支持与反证。",
        "cognitive_type": "paraphrase",
        "source_grade": grade,
        "empirical_support": "conflicting",
        "model_confidence": 0.7,
        "applicability": ClaimApplicability(
            domains=frozenset({"emotional_consultation"}),
            populations=frozenset(),
            contexts=frozenset(),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset(),
        ),
        "privacy_scope": "global",
        "allowed_uses": frozenset({"consultation"}),
        "evidence": (
            ClaimEvidenceRef(
                passage_ref=support, relation="supports", evidence_role="primary"
            ),
            ClaimEvidenceRef(
                passage_ref=oppose,
                relation="contradicts",
                evidence_role="counterevidence",
            ),
        ),
        "provenance": Provenance(
            source_ids=frozenset({source.object_id}),
            passage_ids=frozenset({support.object_id, oppose.object_id}),
            provenance_scope="global_source",
            derivation_rule_ref=policy,
        ),
    }
    if grade == "C1":
        values["theory_revision_ref"] = _ref(ids, "theory_revision", "5")
    return ClaimDraft.model_validate(values)


def _service() -> ClaimProposalService:
    ids = _ids()

    def resolve(reference: VersionRef):  # type: ignore[no-untyped-def]
        locator = EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(reference,),
            display_locator="lines:1-1",
            locator_policy_ref=locator_policy_ref(),
        )
        return "原文", "前文", "后文", locator

    return ClaimProposalService(
        review_resolver=ClaimReviewResolver(resolve),
        id_factory=ids,
        clock=FixedClock(NOW),
        approval_executor=DirectTestApprovalExecutor(ids),
    )


def test_model_claim_starts_as_draft_and_preserves_support_and_opposition() -> None:
    service = _service()
    proposal = service.propose(_draft())
    preview = service.preview(proposal.proposal_id)

    assert preview.descriptor.purpose == "claim_approve"
    assert [item.relation for item in preview.review.evidence] == [
        "supports",
        "contradicts",
    ]
    assert preview.review.proposed_claim != preview.review.evidence[0].original_text

    committed = service.commit(
        proposal.proposal_id,
        descriptor=preview.descriptor,
        approval_request_id=_ids().object_id("approval_request"),
    )
    assert committed.review_status == "approved"
    assert len(committed.passage_refs) == 2


def test_missing_or_non_passage_evidence_fails_closed() -> None:
    with pytest.raises(ValidationError, match="Passage evidence"):
        _draft().model_copy(update={"evidence": ()})

    ids = _ids()
    with pytest.raises(ValidationError, match="must reference a Passage"):
        _draft().model_copy(
            update={
                "evidence": (
                    ClaimEvidenceRef(
                        passage_ref=_ref(ids, "wiki", "6"),
                        relation="supports",
                        evidence_role="primary",
                    ),
                )
            }
        )


def test_generic_claim_service_cannot_promote_c1() -> None:
    with pytest.raises(ClaimGovernanceError, match="GENERIC_CLAIM_CANNOT_ASSIGN_C1"):
        _service().propose(_draft(grade="C1"))


def test_retrieval_text_never_serializes_controlled_client_ids() -> None:
    service = _service()
    proposal = service.propose(_draft())
    preview = service.preview(proposal.proposal_id)
    record = service.commit(
        proposal.proposal_id,
        descriptor=preview.descriptor,
        approval_request_id=_ids().object_id("approval_request"),
    )
    assert "client_" not in service.serialize_retrieval_text(record.claim_id)
