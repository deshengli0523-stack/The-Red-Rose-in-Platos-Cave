from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from consultation_kb.approvals.store import (
    ApprovalMismatch,
    ApprovalUnavailable,
    ApprovalUsed,
)
from consultation_kb.knowledge.applicability import (
    ApplicabilityGate,
    ScopePolicyManifest,
    derive_framework_priority,
)
from consultation_kb.knowledge.claims import ClaimGovernanceError
from consultation_kb.knowledge.lint import KnowledgeLinter
from consultation_kb.knowledge.theory import (
    PrimaryCounselorApprovalRequired,
    TheoryActivationForbidden,
    TheoryGovernanceError,
)
from consultation_kb.knowledge.wiki import WikiGovernanceError
from consultation_kb.knowledge.wiki_renderer import WikiRenderer
from consultation_kb.models.knowledge import ClaimDraft
from consultation_kb.models.evidence import Provenance
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.theory import TheoryRevisionDraft
from consultation_kb.models.wiki import WikiRevisionDraft
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[GlobalKnowledgeHarness]:
    value = build_global_knowledge_harness(tmp_path)
    try:
        yield value
    finally:
        value.close()


def _catalog_version(harness: GlobalKnowledgeHarness) -> int:
    row = harness.connection.execute(
        "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone()
    assert row is not None
    return int(row[0])


def _successor_theory_draft(
    harness: GlobalKnowledgeHarness,
    knowledge: PreparedKnowledge,
    *,
    declared_version: str,
) -> TheoryRevisionDraft:
    current = knowledge.theory
    return TheoryRevisionDraft(
        theory_id=current.theory_id,
        source_ref=current.source_ref,
        document_sha256=current.document_sha256,
        author=current.author,
        declared_version=declared_version,
        effective_from=harness.clock.now(),
        effective_to=current.effective_to,
        scope=current.scope,
        core_claims=(f"澄清事实后再解释关系模式（{declared_version}）",),
        methods=current.methods,
        contraindications=current.contraindications,
        counterexamples=current.counterexamples,
        passage_refs=current.passage_refs,
        citation_refs=current.citation_refs,
        empirical_support=current.empirical_support,
        scope_policy_ref=current.scope_policy_ref,
        supersedes_ref=knowledge.theory_service.version_ref(
            current.theory_id,
            current.revision,
        ),
    )


def _successor_wiki_draft(
    knowledge: PreparedKnowledge,
    *,
    suffix: str,
) -> WikiRevisionDraft:
    current = knowledge.wiki
    return WikiRevisionDraft(
        wiki_id=current.wiki_id,
        slug=current.slug,
        title=f"{current.title}（{suffix}）",
        base_revision=current.revision,
        diff_kind="correct",
        sections=tuple(
            section.model_copy(update={"body": f"{section.body}（{suffix}）"})
            for section in current.sections
        ),
        theory_revision_refs=current.theory_revision_refs,
        relationships=current.relationships,
        review_due_at=current.review_due_at,
        unresolved_questions=current.unresolved_questions,
    )


def test_real_p1_c1_wiki_publication_is_one_complete_epoch(
    harness: GlobalKnowledgeHarness,
) -> None:
    knowledge = prepare_governed_knowledge(harness)

    assert knowledge.theory.status == "prepared"
    assert knowledge.wiki.status == "prepared"
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM runtime_epochs"
    ).fetchone() == (0,)
    assert harness.connection.execute(
        "SELECT status FROM theory_revisions WHERE theory_id = ? AND revision = 1",
        (knowledge.theory.theory_id,),
    ).fetchone() == ("PREPARED",)
    assert harness.connection.execute(
        "SELECT review_status FROM wiki_revisions WHERE wiki_id = ? AND revision = 1",
        (knowledge.wiki.wiki_id,),
    ).fetchone() == ("PREPARED",)

    with pytest.raises(TheoryActivationForbidden):
        knowledge.theory_service.activate(knowledge.theory.theory_id, 1)
    with pytest.raises(
        WikiGovernanceError,
        match="WIKI_ACTIVATION_REQUIRES_COMBINED_PUBLICATION",
    ):
        knowledge.wiki_service.activate(knowledge.wiki.wiki_id, 1)

    lint_before = KnowledgeLinter(harness.connection, now=harness.clock.now()).run(
        _catalog_version(harness)
    )
    assert not lint_before.has_errors

    publication = prepare_global_publication(harness, knowledge)
    operation = publication.service.publish_theory_and_wiki(
        publication.operation_id,
        theory_id=knowledge.theory.theory_id,
        theory_revision=knowledge.theory.revision,
        wiki_id=knowledge.wiki.wiki_id,
        wiki_revision=knowledge.wiki.revision,
    )

    assert operation.state == "ACTIVE"
    assert operation.runtime_epoch == 1
    assert harness.connection.execute(
        "SELECT epoch, operation_id, state FROM runtime_epochs"
    ).fetchall() == [(1, publication.operation_id, "ACTIVE")]
    assert harness.connection.execute(
        "SELECT status FROM theory_revisions WHERE theory_id = ? AND revision = 1",
        (knowledge.theory.theory_id,),
    ).fetchone() == ("ACTIVE",)
    assert harness.connection.execute(
        "SELECT review_status FROM wiki_revisions WHERE wiki_id = ? AND revision = 1",
        (knowledge.wiki.wiki_id,),
    ).fetchone() == ("ACTIVE",)
    assert knowledge.theory_service.get_active(knowledge.theory.theory_id) is not None
    assert knowledge.wiki_service.get_active(knowledge.wiki.wiki_id) is not None

    # Every authority mutation in this slice consumed an attested P1 execution.
    applied = harness.connection.execute(
        "SELECT COUNT(*) FROM approval_executions WHERE state = 'APPLIED'"
    ).fetchone()
    assert applied is not None and int(applied[0]) >= 5

    policy = ScopePolicyManifest(
        policy_ref=knowledge.theory.scope_policy_ref,
        rule_members=frozenset(
            {"domain_match", "adult_population", "context_match"}
        ),
        context_fields=frozenset(
            {
                "domain",
                "population",
                "context",
                "conditions",
                "exclusions",
                "contraindications",
            }
        ),
    )
    applicability = ApplicabilityGate(policy).evaluate(
        revision=knowledge.theory_service.version_ref(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        ),
        scope=knowledge.theory.scope,
        context={
            "domain": "emotional_consultation",
            "population": "adult",
            "context": "relationship",
            "conditions": (),
            "exclusions": (),
            "contraindications": (),
        },
        effective_status="active",
        empirical_support=knowledge.theory.empirical_support,
    )
    assert applicability.status == "applicable"
    assert derive_framework_priority(applicability) == "highest"

    # C1 framework authority never rewrites T1/C2 evidence or empirical status.
    grades = harness.connection.execute(
        "SELECT source_grade, empirical_support FROM claims ORDER BY source_grade"
    ).fetchall()
    assert ("T1", "unassessed") in grades
    assert ("C2", "conflicting") in grades
    assert ("C1", "unassessed") in grades
    rendered = WikiRenderer().render(knowledge.wiki_service.get(knowledge.wiki.wiki_id, 1))
    assert "原文锚点" in rendered
    assert "ANALOGOUS_TO" in rendered
    assert knowledge.theory.claim_refs[0].object_id in rendered

    lint_after = KnowledgeLinter(harness.connection, now=harness.clock.now()).run(
        _catalog_version(harness)
    )
    assert not lint_after.has_errors


def test_real_p1_guard_rejects_fake_request_tamper_and_replay(
    harness: GlobalKnowledgeHarness,
) -> None:
    harness.connection.execute(
        "CREATE TABLE knowledge_guard_probe(value TEXT PRIMARY KEY)"
    )
    descriptor = DraftDescriptor(
        purpose="claim_approve",
        target_id=harness.ids.object_id("claim_proposal"),
        base_version=0,
        draft_sha256="4" * 64,
    )

    def apply(connection) -> None:  # type: ignore[no-untyped-def]
        connection.execute(
            "INSERT INTO knowledge_guard_probe(value) VALUES ('applied')"
        )

    with pytest.raises(ApprovalUnavailable):
        harness.executor.execute(
            approval_request_id=harness.ids.object_id("approval_request"),
            descriptor=descriptor,
            operation_kind="claim_approval_operation",
            apply=apply,
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM knowledge_guard_probe"
    ).fetchone() == (0,)

    approval_request_id = harness.confirm(descriptor)
    tampered = descriptor.model_copy(update={"draft_sha256": "5" * 64})
    with pytest.raises(ApprovalMismatch):
        harness.executor.execute(
            approval_request_id=approval_request_id,
            descriptor=tampered,
            operation_kind="claim_approval_operation",
            apply=apply,
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM knowledge_guard_probe"
    ).fetchone() == (0,)

    harness.executor.execute(
        approval_request_id=approval_request_id,
        descriptor=descriptor,
        operation_kind="claim_approval_operation",
        apply=apply,
    )
    with pytest.raises(ApprovalUsed):
        harness.executor.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind="claim_approval_operation",
            apply=apply,
        )
    assert harness.connection.execute(
        "SELECT value FROM knowledge_guard_probe"
    ).fetchall() == [("applied",)]


def test_authority_services_reject_fake_actor_stale_base_and_generic_c1(
    harness: GlobalKnowledgeHarness,
) -> None:
    knowledge = prepare_governed_knowledge(harness)
    theory_draft = _successor_theory_draft(
        harness,
        knowledge,
        declared_version="2.0",
    )
    theory_proposal = knowledge.theory_service.propose(theory_draft, actor="codex")
    theory_descriptor = knowledge.theory_service.preview(theory_proposal.request_id)
    fake_request = harness.ids.object_id("approval_request")

    with pytest.raises(PrimaryCounselorApprovalRequired):
        knowledge.theory_service.approve(
            theory_proposal.request_id,
            actor="codex",
            approval_request_id=fake_request,
        )
    with pytest.raises(ApprovalUnavailable):
        knowledge.theory_service.approve(
            theory_proposal.request_id,
            actor="primary_counselor",
            approval_request_id=fake_request,
        )
    tampered_request = harness.confirm(
        theory_descriptor.model_copy(update={"draft_sha256": "6" * 64})
    )
    with pytest.raises(ApprovalMismatch):
        knowledge.theory_service.approve(
            theory_proposal.request_id,
            actor="primary_counselor",
            approval_request_id=tampered_request,
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM theory_revisions WHERE theory_id = ?",
        (knowledge.theory.theory_id,),
    ).fetchone() == (1,)

    valid_request = harness.confirm(theory_descriptor)
    successor = knowledge.theory_service.approve(
        theory_proposal.request_id,
        actor="primary_counselor",
        approval_request_id=valid_request,
    )
    assert successor.revision == 2
    with pytest.raises((ApprovalMismatch, ApprovalUsed)):
        knowledge.theory_service.approve(
            theory_proposal.request_id,
            actor="primary_counselor",
            approval_request_id=valid_request,
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM theory_revisions WHERE theory_id = ?",
        (knowledge.theory.theory_id,),
    ).fetchone() == (2,)

    base_claim = knowledge.claim_drafts[0]
    generic_c1 = ClaimDraft(
        text=base_claim.text,
        cognitive_type=base_claim.cognitive_type,
        source_grade="C1",
        empirical_support=base_claim.empirical_support,
        model_confidence=base_claim.model_confidence,
        applicability=base_claim.applicability,
        privacy_scope=base_claim.privacy_scope,
        allowed_uses=base_claim.allowed_uses,
        evidence=base_claim.evidence,
        provenance=base_claim.provenance,
        theory_revision_ref=knowledge.theory_service.version_ref(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        ),
    )
    with pytest.raises(
        ClaimGovernanceError,
        match="GENERIC_CLAIM_CANNOT_ASSIGN_C1",
    ):
        knowledge.claim_service.propose(generic_c1)

    stale_claim = knowledge.claim_drafts[0].model_copy(
        update={"text": "目录变化前提出的陈旧主张"}
    )
    stale_proposal = knowledge.claim_service.propose(stale_claim)
    stale_preview = knowledge.claim_service.preview(stale_proposal.proposal_id)
    stale_approval = harness.confirm(stale_preview.descriptor)
    harness.connection.execute(
        "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
    )
    claim_count = harness.connection.execute("SELECT COUNT(*) FROM claims").fetchone()
    with pytest.raises(
        ClaimGovernanceError,
        match="CLAIM_CATALOG_VERSION_CONFLICT",
    ):
        knowledge.claim_service.commit(
            stale_proposal.proposal_id,
            descriptor=stale_preview.descriptor,
            approval_request_id=stale_approval,
        )
    assert harness.connection.execute("SELECT COUNT(*) FROM claims").fetchone() == claim_count

    first_wiki = knowledge.wiki_service.propose_diff(
        _successor_wiki_draft(knowledge, suffix="first")
    )
    second_wiki = knowledge.wiki_service.propose_diff(
        _successor_wiki_draft(knowledge, suffix="stale")
    )
    with pytest.raises(WikiGovernanceError, match="WIKI_REVIEWER_APPROVAL_REQUIRED"):
        knowledge.wiki_service.approve(
            first_wiki.proposal_id,
            actor="codex",
            approval_request_id=fake_request,
        )
    with pytest.raises(ApprovalUnavailable):
        knowledge.wiki_service.approve(
            first_wiki.proposal_id,
            actor="primary_counselor",
            approval_request_id=fake_request,
        )
    first_descriptor = knowledge.wiki_service.preview(first_wiki.proposal_id)
    knowledge.wiki_service.approve(
        first_wiki.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(first_descriptor),
    )
    stale_descriptor = knowledge.wiki_service.preview(second_wiki.proposal_id)
    stale_wiki_approval = harness.confirm(stale_descriptor)
    with pytest.raises(WikiGovernanceError, match="WIKI_BASE_VERSION_CONFLICT"):
        knowledge.wiki_service.approve(
            second_wiki.proposal_id,
            actor="primary_counselor",
            approval_request_id=stale_wiki_approval,
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM wiki_revisions WHERE wiki_id = ?",
        (knowledge.wiki.wiki_id,),
    ).fetchone() == (2,)


def test_revoked_c1_source_and_cross_scope_passage_fail_closed(
    harness: GlobalKnowledgeHarness,
) -> None:
    knowledge = prepare_governed_knowledge(harness)
    theory_draft = _successor_theory_draft(
        harness,
        knowledge,
        declared_version="revoked-source",
    )
    proposal = knowledge.theory_service.propose(theory_draft, actor="codex")
    descriptor = knowledge.theory_service.preview(proposal.request_id)
    harness.connection.execute(
        """
        UPDATE source_versions SET status = 'REVOKED'
         WHERE source_id = ? AND version = ?
        """,
        (
            knowledge.theory.source_ref.object_id,
            knowledge.theory.source_ref.version,
        ),
    )
    with pytest.raises(
        TheoryGovernanceError,
        match="THEORY_SOURCE_AUTHORITY_INVALID",
    ):
        knowledge.theory_service.approve(
            proposal.request_id,
            actor="primary_counselor",
            approval_request_id=harness.confirm(descriptor),
        )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM theory_revisions WHERE theory_id = ?",
        (knowledge.theory.theory_id,),
    ).fetchone() == (1,)

    base_claim = knowledge.claim_drafts[0].model_copy(
        update={"text": "伪装为全局来源的跨范围主张"}
    )
    passage_id = base_claim.evidence[0].passage_ref.object_id
    private_provenance = Provenance(
        passage_ids=frozenset({passage_id}),
        client_ids=frozenset({"client_" + "a" * 12}),
        provenance_scope="client_private",
        private_owner_client_id="client_" + "a" * 12,
        derivation_rule_ref=base_claim.provenance.derivation_rule_ref,
    )
    harness.connection.execute(
        """
        UPDATE passages SET privacy_scope = 'PRIVATE', provenance_json = ?
         WHERE passage_id = ?
        """,
        (private_provenance.model_dump_json(), passage_id),
    )
    claim_proposal = knowledge.claim_service.propose(base_claim)
    claim_preview = knowledge.claim_service.preview(claim_proposal.proposal_id)
    with pytest.raises(
        ClaimGovernanceError,
        match="PRIVATE_PROVENANCE_CANNOT_ESCAPE",
    ):
        knowledge.claim_service.commit(
            claim_proposal.proposal_id,
            descriptor=claim_preview.descriptor,
            approval_request_id=harness.confirm(claim_preview.descriptor),
        )
