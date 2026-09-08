from __future__ import annotations

import asyncio
import hashlib
import io
import itertools
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.approval import P1GovernedWriteExecutor
from consultation_kb.knowledge.extractors import DocumentExtractor
from consultation_kb.knowledge.passages import PassageCatalog
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.knowledge_runtime import (
    GlobalKnowledgeToolRuntime,
    build_global_knowledge_runtime,
)
from consultation_kb.mcp.schemas import (
    ApproveClaimInput,
    ApprovePassageInput,
    ApproveTheoryRevisionInput,
    ExtractPassagesInput,
    ListSourceInboxInput,
    ProposeClaimsInput,
    ProposeTheoryRevisionInput,
    ProposeWikiUpdateInput,
    PublishWikiInput,
    RegisterSourceDraftInput,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyFieldValueMembers,
)
from consultation_kb.models.theory import TheoryRevisionDraft, TheoryScope
from consultation_kb.models.wiki import WikiRevisionDraft, WikiSection
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector


class _TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


@dataclass
class _KnowledgeHarness:
    root: Path
    connection: sqlite3.Connection
    clock: MutableClock
    ids: IdFactory
    signer: LocalHmacApprovalSigner
    approvals: ApprovalService
    executor: P1GovernedWriteExecutor
    store: ContentStore

    def close(self) -> None:
        self.connection.close()


def _build_harness(tmp_path: Path) -> _KnowledgeHarness:
    root = tmp_path / "knowledge-vault"
    root.mkdir()
    connection = connect_database(root / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = MutableClock()
    random_values = itertools.count(1)
    nonce_values = itertools.count(1)
    ids = IdFactory(clock, lambda: next(random_values))
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    approvals = ApprovalService(
        connection,
        provider=LocalHmacApprovalVerifier(
            secret=b"p" * 32,
            provider_id="local-review-agent",
        ),
        protector=TestProtector(),
        clock=clock,
        id_factory=ids,
        target_scope_hash="a" * 64,
        vault_id="synthetic-global-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=approvals,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        clock=clock,
    )
    executor = P1GovernedWriteExecutor(
        approval_service=approvals,
        execution_guard=guard,
        id_factory=ids,
    )
    return _KnowledgeHarness(
        root=root,
        connection=connection,
        clock=clock,
        ids=ids,
        signer=signer,
        approvals=approvals,
        executor=executor,
        store=ContentStore(root / "global-content"),
    )


def _result(envelope: object) -> dict[str, object]:
    ok = getattr(envelope, "ok")
    assert ok, getattr(envelope, "error")
    value = getattr(envelope, "result")
    assert isinstance(value, dict)
    return value


def _claim_arguments(passage_ref: VersionRef) -> dict[str, object]:
    return {
        "claims": [
            {
                "text": "Acceptance and agreement are distinct.",
                "cognitive_type": "explicit",
                "source_grade": "C2",
                "empirical_support": "unassessed",
                "applicability": {
                    "domains": ["emotional_consultation"],
                    "populations": ["adult"],
                    "contexts": ["relationship"],
                    "required_conditions": [],
                    "exclusions": [],
                    "contraindications": ["medical_diagnosis"],
                },
                "allowed_uses": ["consultation"],
                "evidence": [
                    {
                        "passage_ref": passage_ref.model_dump(mode="json"),
                        "relation": "supports",
                        "evidence_role": "primary",
                    }
                ],
            }
        ]
    }


def _approve_locally(
    runtime: GlobalKnowledgeToolRuntime,
    harness: _KnowledgeHarness,
    request_id: str,
) -> str:
    request = harness.approvals.get(request_id)
    agent = runtime.build_review_agent(harness.signer)
    phrase = f"APPROVE {request.descriptor_sha256[:16]}\n"
    output = io.StringIO()
    agent.review(
        request_id,
        stdin=_TtyInput(phrase),
        stdout=output,
    )
    assert harness.approvals.get(request_id).state == "confirmed"
    return output.getvalue()


def _approved_scope_policy(
    harness: _KnowledgeHarness,
) -> VersionRef:
    repository = ScopePolicyRepository(
        harness.connection,
        content_store=harness.store,
        approval_executor=harness.executor,
        clock=harness.clock,
    )
    document = ScopePolicyDocument(
        policy_id=harness.ids.object_id("scope_policy"),
        version=1,
        evaluator_id="deterministic_c1_scope",
        evaluator_version=1,
        rule_members=frozenset(
            {
                "contraindication_match",
                "context_match",
                "domain_match",
                "population_match",
            }
        ),
        context_fields=frozenset(
            {"contraindications", "context", "domain", "population"}
        ),
        field_value_members=(
            ScopePolicyFieldValueMembers(
                context_field="context",
                value_members=frozenset({"relationship"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="contraindications",
                value_members=frozenset({"medical_diagnosis", "none_observed"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="domain",
                value_members=frozenset({"emotional_consultation"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="population",
                value_members=frozenset({"adult"}),
            ),
        ),
    )
    prepared = repository.prepare(document, effective_from=harness.clock.now())
    descriptor = repository.preview_approval(prepared.semantic_ref)
    request = harness.approvals.request(
        descriptor,
        diff_object_ref=VersionRef(
            object_id=harness.ids.object_id("approval_diff"),
            version=1,
            content_sha256=hashlib.sha256(
                descriptor.model_dump_json().encode("utf-8")
            ).hexdigest(),
        ),
    )
    challenge = harness.approvals.challenge_for_review(request.request_id)
    harness.approvals.confirm(harness.signer.confirm(challenge))
    return repository.approve(
        prepared.semantic_ref,
        approval_request_id=request.request_id,
    ).semantic_ref


def test_global_knowledge_mcp_closes_governed_drafts_and_reports_p8_dependency(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    config = AppConfig.from_values(repo, harness.root)
    runtime = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"h" * 32,
    )
    services = HandlerServices(
        read=runtime,
        graph=runtime,
        session=runtime,
        knowledge=runtime,
        write=runtime,
    )
    registry = build_handler_registry(
        McpHandlerContext(
            transport_session_id="knowledge-e2e-transport",
            bindings=TransportBindingRegistry(),
            services=services,
        )
    )

    source = runtime.inbox_root / "counseling" / "relationship.md"
    source.parent.mkdir(parents=True)
    source.write_text(
        "# Relationship counseling\n\nAcceptance is not agreement.\n",
        encoding="utf-8",
    )

    listed = _result(asyncio.run(registry["list_source_inbox"]({})))
    items = listed["items"]
    assert isinstance(items, list) and len(items) == 1
    item = items[0]
    assert isinstance(item, dict)
    assert set(item) == {
        "source_handle",
        "document_type",
        "source_kind",
        "size_bytes",
        "content_sha256",
    }
    handle = item["source_handle"]
    assert isinstance(handle, str) and handle.startswith("source-inbox-")

    source.write_text(
        "# Relationship counseling\n\nAcceptance is not agreement.\n"
        "Context matters.\n",
        encoding="utf-8",
    )
    stale = asyncio.run(
        registry["register_source_draft"](
            {
                "source_handle": handle,
                "metadata": {
                    "license": "user_authorized",
                    "domain": "emotional_consultation",
                    "language": "en",
                    "sensitivity": "internal",
                    "source_grade": "C2",
                    "document_type": "md",
                    "author": "synthetic_author",
                },
            }
        )
    )
    assert not stale.ok
    assert harness.connection.execute("SELECT COUNT(*) FROM sources").fetchone() == (
        0,
    )
    refreshed = _result(asyncio.run(registry["list_source_inbox"]({})))
    refreshed_items = refreshed["items"]
    assert isinstance(refreshed_items, list) and len(refreshed_items) == 1
    refreshed_item = refreshed_items[0]
    assert isinstance(refreshed_item, dict)
    refreshed_handle = refreshed_item["source_handle"]
    assert isinstance(refreshed_handle, str) and refreshed_handle != handle
    handle = refreshed_handle

    registered = _result(
        asyncio.run(
            registry["register_source_draft"](
                {
                    "source_handle": handle,
                    "metadata": {
                        "license": "user_authorized",
                        "domain": "emotional_consultation",
                        "language": "en",
                        "sensitivity": "internal",
                        "source_grade": "C2",
                        "document_type": "md",
                        "author": "synthetic_author",
                    },
                }
            )
        )
    )
    source_ref = VersionRef.model_validate(registered["source_ref"])
    extracted = _result(
        asyncio.run(
            registry["extract_passages"](
                {
                    "source_ref": source_ref.model_dump(mode="json"),
                    "extractor_version": DocumentExtractor.VERSION,
                }
            )
        )
    )
    assert extracted["status"] == "pending_passage_approval"
    assert extracted["blocking_code"] == "PASSAGE_APPROVAL_REQUIRED"
    passages = extracted["passages"]
    assert isinstance(passages, list) and passages
    passage_item = passages[-1]
    assert isinstance(passage_item, dict)
    passage_ref = VersionRef.model_validate(passage_item["passage_ref"])
    passage_approval_id = passage_item["approval_request_id"]
    assert isinstance(passage_approval_id, str)

    blocked_proposal = _result(
        asyncio.run(
            registry["propose_claims"](_claim_arguments(passage_ref))
        )
    )
    assert blocked_proposal["status"] == "pending_passage_approval"
    assert blocked_proposal["proposals"] == []
    assert blocked_proposal["blocking_code"] == "PASSAGE_APPROVAL_REQUIRED"

    # Local review confirmation alone must not mutate authority; the formal
    # MCP call consumes it in PassageCatalog's governed target transaction.
    passage_review = _approve_locally(runtime, harness, passage_approval_id)
    assert "Acceptance is not agreement." in passage_review
    assert PassageCatalog(
        harness.connection,
        content_store=harness.store,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
    ).get(passage_ref.object_id, passage_ref.version).review_status == "draft"

    passage_approved = _result(
        asyncio.run(
            registry["approve_passage"](
                {"approval_request_id": passage_approval_id}
            )
        )
    )
    assert passage_approved["status"] == "passage_approved"
    assert passage_approved["mutation_applied"] is True
    assert VersionRef.model_validate(passage_approved["passage_ref"]) == passage_ref

    proposed = _result(
        asyncio.run(
            registry["propose_claims"](_claim_arguments(passage_ref))
        )
    )
    proposals = proposed["proposals"]
    assert isinstance(proposals, list) and len(proposals) == 1
    proposal = proposals[0]
    assert isinstance(proposal, dict)
    proposal_id = proposal["proposal_id"]
    assert isinstance(proposal_id, str)
    claim_preview = _result(
        asyncio.run(
            registry["preview_claim_review"]({"proposal_id": proposal_id})
        )
    )
    assert claim_preview["status"] == "pending_local_review"
    claim_approval_id = claim_preview["approval_request_id"]
    assert isinstance(claim_approval_id, str)
    claim_review = _approve_locally(runtime, harness, claim_approval_id)
    assert "Acceptance and agreement are distinct." in claim_review
    # The proposal and its exact approval binding are control-plane state, not
    # process-local MCP state.  A confirmed review must remain executable after
    # the server lifespan that created it has exited.
    claim_execution_runtime = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"c" * 32,
    )
    replayed_claims = claim_execution_runtime.propose_claims(
        ProposeClaimsInput.model_validate(_claim_arguments(passage_ref))
    )
    replayed_claim_values = replayed_claims["proposals"]
    assert isinstance(replayed_claim_values, list)
    assert replayed_claim_values[0]["proposal_id"] == proposal_id
    # Simulate a crash after P1 has durably bound the one-shot receipt to an
    # operation ID but before the target transaction starts.  Retry must reuse
    # that exact ID rather than attempting to bind a new operation.
    prebound_operation_id = harness.ids.object_id("claim_approval_operation")
    harness.approvals.issue_for_execution(
        claim_approval_id,
        harness.approvals.get(claim_approval_id).descriptor,
        operation_id=prebound_operation_id,
    )
    approved = claim_execution_runtime.invoke(
        "approve_claim",
        ApproveClaimInput(approval_request_id=claim_approval_id),
        binding=None,
    )
    assert isinstance(approved, dict)
    assert approved["status"] == "claim_approved"
    assert approved["mutation_applied"] is True
    proposal_operation = harness.connection.execute(
        """
        SELECT state, execution_operation_id, execution_sha256
          FROM knowledge_proposal_operations
         WHERE proposal_id = ?
        """,
        (proposal_id,),
    ).fetchone()
    assert proposal_operation is not None
    assert proposal_operation[0] == "APPLIED"
    assert proposal_operation[1] == prebound_operation_id
    assert isinstance(proposal_operation[2], str)
    assert len(proposal_operation[2]) == 64
    claim_ref = VersionRef.model_validate(approved["claim_ref"])

    # An unknown proposal remains a precise non-success, never a fake draft.
    missing_wiki_id = harness.ids.object_id("wiki_proposal")
    missing_preview = _result(
        asyncio.run(
            registry["preview_wiki_update"](
                {"wiki_draft_id": missing_wiki_id}
            )
        )
    )
    assert missing_preview == {
        "status": "wiki_draft_not_found",
        "wiki_draft_id": missing_wiki_id,
        "blocking_code": "WIKI_PROPOSAL_NOT_FOUND",
    }

    wiki_draft = WikiRevisionDraft(
        wiki_id=harness.ids.object_id("wiki"),
        slug="acceptance-and-agreement",
        title="Acceptance and agreement",
        base_revision=0,
        diff_kind="add",
        sections=(
            WikiSection(
                key="distinction",
                heading="Core distinction",
                body="Acceptance does not itself assert agreement.",
                claim_refs=(claim_ref,),
                passage_refs=(passage_ref,),
                stance="support",
            ),
        ),
        theory_revision_refs=(),
        review_due_at=None,
    )
    wiki_proposed = _result(
        asyncio.run(
            registry["propose_wiki_update"](
                {"draft": wiki_draft.model_dump(mode="json")}
            )
        )
    )
    assert wiki_proposed["status"] == "wiki_update_proposed"
    wiki_proposal_id = wiki_proposed["wiki_draft_id"]
    assert isinstance(wiki_proposal_id, str)
    wiki_preview = _result(
        asyncio.run(
            registry["preview_wiki_update"](
                {"wiki_draft_id": wiki_proposal_id}
            )
        )
    )
    wiki_approval_id = wiki_preview["approval_request_id"]
    assert isinstance(wiki_approval_id, str)
    wiki_review = _approve_locally(runtime, harness, wiki_approval_id)
    assert "Acceptance does not itself assert agreement." in wiki_review
    wiki_execution_runtime = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"w" * 32,
    )
    replayed_wiki = wiki_execution_runtime.propose_wiki_update(
        ProposeWikiUpdateInput(draft=wiki_draft)
    )
    assert replayed_wiki["wiki_draft_id"] == wiki_proposal_id
    wiki_publish = wiki_execution_runtime.invoke(
        "publish_wiki",
        PublishWikiInput(approval_request_id=wiki_approval_id),
        binding=None,
    )
    assert isinstance(wiki_publish, dict)
    assert wiki_publish["status"] == (
        "prepared_pending_artifact_publication"
    )
    assert wiki_publish["authority_active"] is False
    assert wiki_publish["blocking_code"] == (
        "WIKI_DERIVED_ARTIFACT_PUBLICATION_UNAVAILABLE"
    )
    assert wiki_publish["blocking_stage"] == (
        "derived_artifact_build_and_publication"
    )

    # A fresh MCP lifespan recovers already-consumed formal results from the
    # governed catalog rather than replaying one-shot approvals or claiming an
    # in-memory proposal still exists.
    restarted = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"r" * 32,
    )
    recovered_claim = restarted.invoke(
        "approve_claim",
        ApproveClaimInput(approval_request_id=claim_approval_id),
        binding=None,
    )
    assert isinstance(recovered_claim, dict)
    assert recovered_claim["status"] == "claim_approved"
    recovered_passage = restarted.invoke(
        "approve_passage",
        ApprovePassageInput(approval_request_id=passage_approval_id),
        binding=None,
    )
    assert isinstance(recovered_passage, dict)
    assert recovered_passage["status"] == "passage_approved"
    recovered_wiki = restarted.invoke(
        "publish_wiki",
        PublishWikiInput(approval_request_id=wiki_approval_id),
        binding=None,
    )
    assert isinstance(recovered_wiki, dict)
    assert recovered_wiki["status"] == (
        "prepared_pending_artifact_publication"
    )
    assert recovered_wiki["authority_active"] is False
    assert recovered_wiki["blocking_stage"] == (
        "derived_artifact_build_and_publication"
    )

    lint = _result(asyncio.run(registry["knowledge_lint"]({})))
    assert lint["status"] == "complete"
    rendered = json.dumps(
        {
            "listed": listed,
            "registered": registered,
            "extracted": extracted,
            "claim_preview": claim_preview,
            "approved": approved,
            "wiki_publish": wiki_publish,
            "lint": lint,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    assert str(harness.root) not in rendered
    assert "client_" not in rendered
    harness.close()


def test_confirmed_theory_proposal_replays_and_executes_after_mcp_restart(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    config = AppConfig.from_values(repo, harness.root)
    runtime = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"t" * 32,
    )
    scope_policy_ref = _approved_scope_policy(harness)
    source_path = runtime.inbox_root / "consultant-theory" / "framework.md"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "# Counselor framework\n\nClarify the timeline before interpreting patterns.\n",
        encoding="utf-8",
    )
    listed = runtime.list_source_inbox(ListSourceInboxInput())
    items = listed["items"]
    assert isinstance(items, list) and len(items) == 1
    item = items[0]
    assert isinstance(item, dict)
    source_handle = item["source_handle"]
    assert isinstance(source_handle, str)
    registered = runtime.register_source_draft(
        RegisterSourceDraftInput.model_validate(
            {
                "source_handle": source_handle,
                "metadata": {
                    "license": "user_authorized",
                    "domain": "emotional_consultation",
                    "language": "en",
                    "sensitivity": "internal",
                    "source_grade": "C1",
                    "document_type": "md",
                    "author": "primary_counselor",
                },
            }
        )
    )
    source_ref = VersionRef.model_validate(registered["source_ref"])
    extracted = runtime.extract_passages(
        ExtractPassagesInput(
            source_ref=source_ref,
            extractor_version=DocumentExtractor.VERSION,
        )
    )
    passages = extracted["passages"]
    assert isinstance(passages, list) and passages
    approved_passage_ref: VersionRef | None = None
    for passage in passages:
        assert isinstance(passage, dict)
        request_id = passage["approval_request_id"]
        assert isinstance(request_id, str)
        _approve_locally(runtime, harness, request_id)
        approved_passage = runtime.approve_passage(
            ApprovePassageInput(approval_request_id=request_id)
        )
        approved_passage_ref = VersionRef.model_validate(
            approved_passage["passage_ref"]
        )
    assert approved_passage_ref is not None

    theory_draft = TheoryRevisionDraft(
        theory_id=harness.ids.object_id("theory"),
        source_ref=source_ref,
        document_sha256=source_ref.content_sha256,
        author="primary_counselor",
        declared_version="1.0",
        effective_from=harness.clock.now(),
        effective_to=None,
        scope=TheoryScope(
            domains=frozenset({"emotional_consultation"}),
            populations=frozenset({"adult"}),
            contexts=frozenset({"relationship"}),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset({"medical_diagnosis"}),
        ),
        core_claims=("Clarify facts before interpreting relational patterns.",),
        methods=("timeline_clarification",),
        contraindications=("medical_diagnosis",),
        counterexamples=("insufficient_evidence",),
        passage_refs=(approved_passage_ref,),
        citation_refs=(source_ref,),
        empirical_support="unassessed",
        scope_policy_ref=scope_policy_ref,
    )
    proposed = runtime.propose_theory_revision(
        ProposeTheoryRevisionInput(draft=theory_draft)
    )
    proposal_id = proposed["theory_proposal_id"]
    approval_request_id = proposed["approval_request_id"]
    assert isinstance(proposal_id, str)
    assert isinstance(approval_request_id, str)
    _approve_locally(runtime, harness, approval_request_id)

    restarted = build_global_knowledge_runtime(
        config=config,
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
        handle_key=b"u" * 32,
    )
    replayed = restarted.propose_theory_revision(
        ProposeTheoryRevisionInput(draft=theory_draft)
    )
    assert replayed["theory_proposal_id"] == proposal_id
    assert replayed["approval_request_id"] == approval_request_id
    result = restarted.invoke(
        "approve_theory_revision",
        ApproveTheoryRevisionInput(approval_request_id=approval_request_id),
        binding=None,
    )
    assert isinstance(result, dict)
    assert result["status"] == "prepared_pending_combined_publication"
    assert result["mutation_applied"] is True
    assert result["authority_active"] is False
    harness.close()
