from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from consultation_kb.approvals.models import ApprovalRequest
from consultation_kb.knowledge.proposal_repository import (
    KnowledgeProposalError,
    KnowledgeProposalRepository,
)
from consultation_kb.knowledge.wiki import WikiRevisionService
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.wiki import WikiRevisionDraft, WikiSection
from tests.consultation_kb.integration.test_knowledge_mcp_end_to_end import (
    _KnowledgeHarness,
    _build_harness,
)


def _wiki_proposal(tmp_path: Path):  # type: ignore[no-untyped-def]
    harness = _build_harness(tmp_path)
    repository = KnowledgeProposalRepository(
        harness.connection,
        content_store=harness.store,
        id_factory=harness.ids,
        clock=harness.clock,
    )
    service = WikiRevisionService(
        id_factory=harness.ids,
        clock=harness.clock,
    )
    draft = WikiRevisionDraft(
        wiki_id=harness.ids.object_id("wiki"),
        slug="durable-proposal",
        title="Durable proposal",
        base_revision=0,
        diff_kind="add",
        sections=(
            WikiSection(
                key="main",
                heading="Main",
                body="sensitive proposal body marker",
                claim_refs=(
                    VersionRef(
                        object_id=harness.ids.object_id("claim"),
                        version=1,
                        content_sha256="a" * 64,
                    ),
                ),
                passage_refs=(
                    VersionRef(
                        object_id=harness.ids.object_id("passage"),
                        version=1,
                        content_sha256="b" * 64,
                    ),
                ),
            ),
        ),
        theory_revision_refs=(),
        review_due_at=None,
    )
    proposal = service.propose_diff(draft)
    descriptor = service.preview(proposal.proposal_id)
    durable = repository.save_wiki(proposal, descriptor)
    return harness, repository, proposal, descriptor, durable


def _approval(
    harness: _KnowledgeHarness,
    descriptor: DraftDescriptor,
) -> ApprovalRequest:
    return harness.approvals.request(
        descriptor,
        diff_object_ref=VersionRef(
            object_id=harness.ids.object_id("approval_diff"),
            version=1,
            content_sha256=hashlib.sha256(
                descriptor.model_dump_json().encode("utf-8")
            ).hexdigest(),
        ),
    )


def test_proposal_ledger_is_hash_only_idempotent_and_rebinds_only_after_expiry(
    tmp_path: Path,
) -> None:
    harness, repository, proposal, descriptor, first = _wiki_proposal(tmp_path)
    try:
        replay = repository.save_wiki(proposal, descriptor)
        assert replay.operation_id == first.operation_id
        assert replay.operation_sha256 == first.operation_sha256
        assert replay.proposal_id == first.proposal_id

        columns = {
            str(row[1])
            for row in harness.connection.execute(
                "PRAGMA table_info(knowledge_proposal_operations)"
            )
        }
        assert not {"path", "body", "client_id", "draft_json"} & columns
        row_text = repr(
            harness.connection.execute(
                "SELECT * FROM knowledge_proposal_operations"
            ).fetchone()
        )
        assert "sensitive proposal body marker" not in row_text
        assert str(harness.root) not in row_text

        first_approval = _approval(harness, descriptor)
        repository.bind_approval(
            first.proposal_id,
            expected_kind="wiki",
            approval=first_approval,
        )
        harness.approvals.confirm(
            harness.signer.confirm(
                harness.approvals.challenge_for_review(first_approval.request_id)
            )
        )
        competing = _approval(harness, descriptor)
        with pytest.raises(
            KnowledgeProposalError,
            match="KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT",
        ):
            repository.bind_approval(
                first.proposal_id,
                expected_kind="wiki",
                approval=competing,
            )

        harness.clock.value += timedelta(minutes=6)
        replacement = _approval(harness, descriptor)
        rebound = repository.bind_approval(
            first.proposal_id,
            expected_kind="wiki",
            approval=replacement,
        )
        assert rebound.approval_request_id == replacement.request_id
        assert repository.load_for_approval(
            replacement.request_id,
            expected_kind="wiki",
        ).proposal_id == first.proposal_id
        with pytest.raises(
            KnowledgeProposalError,
            match="KNOWLEDGE_PROPOSAL_NOT_FOUND",
        ):
            repository.load_for_approval(
                first_approval.request_id,
                expected_kind="wiki",
            )
    finally:
        harness.close()


def test_proposal_cas_tamper_fails_with_fixed_code_not_storage_detail(
    tmp_path: Path,
) -> None:
    harness, repository, _proposal, _descriptor, durable = _wiki_proposal(tmp_path)
    try:
        forged_hash = "f" * 64
        harness.connection.execute(
            """
            UPDATE knowledge_proposal_operations
               SET proposal_object_ref = ?, proposal_object_sha256 = ?
             WHERE proposal_id = ?
            """,
            (f"sha256:{forged_hash}", forged_hash, durable.proposal_id),
        )
        with pytest.raises(KnowledgeProposalError) as captured:
            repository.load(durable.proposal_id, expected_kind="wiki")
        assert captured.value.code == "KNOWLEDGE_PROPOSAL_CONTENT_INVALID"
        assert str(harness.root) not in str(captured.value)
    finally:
        harness.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_id", "forged-wiki-target"),
        ("base_version", 1),
    ],
)
def test_repository_rejects_descriptor_not_derived_from_proposal_dto(
    tmp_path: Path,
    field: str,
    value: str | int,
) -> None:
    harness, repository, proposal, descriptor, _durable = _wiki_proposal(tmp_path)
    try:
        forged = descriptor.model_copy(update={field: value})
        with pytest.raises(
            KnowledgeProposalError,
            match="KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH",
        ):
            repository.save_wiki(proposal, forged)
    finally:
        harness.close()


def test_load_cross_checks_approval_row_not_only_proposal_columns(
    tmp_path: Path,
) -> None:
    harness, repository, _proposal, descriptor, durable = _wiki_proposal(tmp_path)
    try:
        approval = _approval(harness, descriptor)
        repository.bind_approval(
            durable.proposal_id,
            expected_kind="wiki",
            approval=approval,
        )
        harness.connection.execute(
            """
            UPDATE knowledge_proposal_operations
               SET approval_descriptor_sha256 = ?
             WHERE proposal_id = ?
            """,
            ("c" * 64, durable.proposal_id),
        )
        with pytest.raises(
            KnowledgeProposalError,
            match="KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT",
        ):
            repository.load(durable.proposal_id, expected_kind="wiki")
    finally:
        harness.close()
