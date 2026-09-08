from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import numpy as np
import pytest
from numpy.typing import NDArray

from consultation_kb.graph.graphify_adapter import GraphifyProjectionAdapter
from consultation_kb.core.config import AppConfig
from consultation_kb.knowledge.passages import PassageCatalog
from consultation_kb.knowledge.wiki_renderer import REQUIRED_SECTION_KEYS
from consultation_kb.models.common import VersionRef
from consultation_kb.models.wiki import WikiRevisionDraft, WikiSection
from consultation_kb.mcp.knowledge_runtime import GlobalKnowledgeToolRuntime
from consultation_kb.mcp.schemas import PublishWikiInput
from consultation_kb.publication.global_knowledge import (
    GlobalKnowledgePublicationPlanner,
    GlobalPublicationBuilders,
    GlobalPublicationPlanningError,
)
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
)
from consultation_kb.retrieval.embeddings import DeterministicFakeEmbedder
from consultation_kb.retrieval.lexical_builder import LexicalIndexBuilder
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexBuilder
from consultation_kb.retrieval.wiki_index import WikiIndexRetriever
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_governed_knowledge,
    prepare_successor_knowledge,
)
from tests.consultation_kb.retrieval_support import model_descriptor


def _builders(harness: GlobalKnowledgeHarness) -> GlobalPublicationBuilders:
    descriptor = model_descriptor()
    vocabulary: dict[str, NDArray[np.float32]] = {}
    for row in harness.connection.execute(
        "SELECT retrieval_content_ref FROM passages ORDER BY passage_id, version"
    ):
        reference = str(row[0])
        assert reference.startswith("sha256:")
        text = harness.store.read_hash_verified(
            reference.removeprefix("sha256:")
        ).decode("utf-8", errors="strict")
        vector = np.zeros(descriptor.dimension, dtype=np.float32)
        vector[0] = 1.0
        vocabulary[text] = vector
    return GlobalPublicationBuilders(
        embedder=DeterministicFakeEmbedder(descriptor, vocabulary),
        model_descriptor=descriptor,
        lexical=LexicalIndexBuilder(),
        wiki=WikiNavigationIndexBuilder(),
        graphify=GraphifyProjectionAdapter(seed=42),
    )


def _planner(
    tmp_path: Path,
    harness: GlobalKnowledgeHarness,
    knowledge: PreparedKnowledge,
    *,
    failure_hook: Callable[[str], None] | None = None,
) -> GlobalKnowledgePublicationPlanner:
    return GlobalKnowledgePublicationPlanner(
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        execution_guard=harness.guard,
        claim_service=knowledge.claim_service,
        passage_reader=PassageCatalog(
            harness.connection,
            content_store=harness.store,
            approval_executor=harness.executor,
            id_factory=harness.ids,
            clock=harness.clock,
        ),
        theory_service=knowledge.theory_service,
        wiki_service=knowledge.wiki_service,
        builders=_builders(harness),
        build_root=(tmp_path / "production-derived-builds").resolve(),
        id_factory=harness.ids,
        clock=harness.clock,
        lint_error_count=lambda: 0,
        failure_hook=failure_hook,
    )


def test_planner_activates_real_five_root_closure(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        planner = _planner(tmp_path, harness, knowledge)

        plan = planner.plan_wiki(
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )

        assert plan.target_runtime_epoch == 1
        assert set(plan.artifact_kinds) == {
            "c1_revision",
            "claims",
            "graph",
            "knowledge_registry",
            "lexical",
            "vector",
            "wiki_index",
            "wiki_page",
        }
        assert all(
            "client_" not in repr(artifact)
            for artifact in plan.artifacts
        )

        approval_request_id = harness.confirm(plan.descriptor)
        operation = planner.execute(
            plan,
            approval_request_id=approval_request_id,
        )

        assert operation.state == "ACTIVE"
        assert operation.runtime_epoch == 1
        assert planner.execute(
            plan,
            approval_request_id=approval_request_id,
        ) == operation
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None
        assert active.active_runtime_epoch == 1
        assert {binding.identity.artifact_key for binding in active.bindings()} == {
            "wiki_index",
            "knowledge_registry",
            "lexical",
            "vector",
            "graph",
        }
        assert knowledge.wiki_service.get(
            knowledge.wiki.wiki_id,
            knowledge.wiki.revision,
        ).status == "active"
        assert knowledge.theory_service.get(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        ).status == "active"
    finally:
        harness.close()


def test_activation_failure_never_switches_epoch(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        first_planner = _planner(tmp_path, harness, first)
        first_plan = first_planner.plan_wiki(
            wiki_id=first.wiki.wiki_id,
            wiki_revision=first.wiki.revision,
        )
        first_operation = first_planner.execute(
            first_plan,
            approval_request_id=harness.confirm(first_plan.descriptor),
        )
        assert first_operation.runtime_epoch == 1
        successor = prepare_successor_knowledge(harness, first)

        def fail_before_authority_rows(phase: str) -> None:
            if phase == "before_authority_rows":
                raise RuntimeError("injected publication failure")

        planner = _planner(
            tmp_path,
            harness,
            successor,
            failure_hook=fail_before_authority_rows,
        )
        plan = planner.plan_wiki(
            wiki_id=successor.wiki.wiki_id,
            wiki_revision=successor.wiki.revision,
        )
        assert plan.target_runtime_epoch == 2

        with pytest.raises(RuntimeError, match="injected publication failure"):
            planner.execute(
                plan,
                approval_request_id=harness.confirm(plan.descriptor),
            )

        assert harness.connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == [(1, "ACTIVE")]
        assert harness.connection.execute(
            "SELECT COUNT(DISTINCT epoch) FROM active_artifacts"
        ).fetchone() == (1,)
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None and active.active_runtime_epoch == 1
        assert successor.wiki_service.get(
            first.wiki.wiki_id,
            first.wiki.revision,
        ).status == "active"
        assert successor.wiki_service.get(
            successor.wiki.wiki_id,
            successor.wiki.revision,
        ).status == "prepared"
        assert successor.theory_service.get(
            first.theory.theory_id,
            first.theory.revision,
        ).status == "active"
        assert successor.theory_service.get(
            successor.theory.theory_id,
            successor.theory.revision,
        ).status == "prepared"
    finally:
        harness.close()


def test_second_distinct_wiki_epoch_keeps_first_wiki_retrievable(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        first_planner = _planner(tmp_path, harness, first)
        first_plan = first_planner.plan_wiki(
            wiki_id=first.wiki.wiki_id,
            wiki_revision=first.wiki.revision,
        )
        first_planner.execute(
            first_plan,
            approval_request_id=harness.confirm(first_plan.descriptor),
        )

        claim_draft = first.claim_drafts[0].model_copy(
            update={"text": "第二个独立 Wiki 的专属可检索主张。"}
        )
        claim_proposal = first.claim_service.propose(claim_draft)
        claim_preview = first.claim_service.preview(claim_proposal.proposal_id)
        second_claim = first.claim_service.commit(
            claim_proposal.proposal_id,
            descriptor=claim_preview.descriptor,
            approval_request_id=harness.confirm(claim_preview.descriptor),
        )
        second_claim_ref = VersionRef(
            object_id=second_claim.claim_id,
            version=second_claim.version,
            content_sha256=second_claim.text_sha256,
        )
        theory_ref = first.theory_service.version_ref(
            first.theory.theory_id,
            first.theory.revision,
        )
        passage_refs = tuple(
            dict.fromkeys(
                reference
                for section in first.wiki.sections
                for reference in section.passage_refs
            )
        )
        second_draft = WikiRevisionDraft(
            wiki_id=harness.ids.object_id("wiki"),
            slug="second-independent-wiki",
            title="第二个独立 Wiki",
            base_revision=0,
            diff_kind="add",
            sections=tuple(
                WikiSection(
                    key=key,
                    heading=f"第二页 {key}",
                    body=f"第二页专属内容 {key}",
                    claim_refs=(second_claim_ref, *first.theory.claim_refs),
                    passage_refs=passage_refs,
                    stance=(
                        "oppose"
                        if key == "opposition"
                        else "support" if key == "support" else "context"
                    ),
                )
                for key in sorted(REQUIRED_SECTION_KEYS)
            ),
            theory_revision_refs=(theory_ref,),
            relationships=(),
            review_due_at=None,
            unresolved_questions=(),
        )
        second_proposal = first.wiki_service.propose_diff(second_draft)
        second_preview = first.wiki_service.preview(second_proposal.proposal_id)
        second_wiki = first.wiki_service.approve(
            second_proposal.proposal_id,
            actor="knowledge_reviewer",
            approval_request_id=harness.confirm(second_preview),
        )
        second_planner = _planner(tmp_path, harness, first)
        second_plan = second_planner.plan_wiki(
            wiki_id=second_wiki.wiki_id,
            wiki_revision=second_wiki.revision,
        )
        second_operation = second_planner.execute(
            second_plan,
            approval_request_id=harness.confirm(second_plan.descriptor),
        )

        assert second_operation.runtime_epoch == 2
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None and active.active_runtime_epoch == 2
        indexed_claim_ids = {
            row.authority.reference.object_id
            for row in WikiIndexRetriever(active.wiki_index).payload.rows
        }
        first_claim_ids = {
            reference.object_id
            for section in first.wiki.sections
            for reference in section.claim_refs
        }
        second_claim_ids = {
            reference.object_id
            for section in second_wiki.sections
            for reference in section.claim_refs
        }
        assert first_claim_ids <= indexed_claim_ids
        assert second_claim_ids <= indexed_claim_ids
        assert first.wiki_service.get(
            first.wiki.wiki_id,
            first.wiki.revision,
        ).status == "active"
        assert first.wiki_service.get(
            second_wiki.wiki_id,
            second_wiki.revision,
        ).status == "active"
    finally:
        harness.close()


def test_missing_model_fails_with_fixed_code(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        with pytest.raises(
            GlobalPublicationPlanningError,
            match="KNOWLEDGE_VECTOR_MODEL_REQUIRED",
        ) as error:
            GlobalKnowledgePublicationPlanner(
                connection=harness.connection,
                content_store=harness.store,
                approval_service=harness.approvals,
                execution_guard=harness.guard,
                claim_service=knowledge.claim_service,
                passage_reader=PassageCatalog(
                    harness.connection,
                    content_store=harness.store,
                    approval_executor=harness.executor,
                    id_factory=harness.ids,
                    clock=harness.clock,
                ),
                theory_service=knowledge.theory_service,
                wiki_service=knowledge.wiki_service,
                builders=None,
                build_root=(tmp_path / "missing-model").resolve(),
                id_factory=harness.ids,
                clock=harness.clock,
                lint_error_count=lambda: 0,
            )
        assert error.value.code == "KNOWLEDGE_VECTOR_MODEL_REQUIRED"
    finally:
        harness.close()


def test_runtime_planner_seam_executes_confirmed_exact_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        planner = _planner(tmp_path, harness, knowledge)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        runtime = GlobalKnowledgeToolRuntime(
            config=AppConfig.from_values(repo, harness.root),
            connection=harness.connection,
            content_store=harness.store,
            approval_service=harness.approvals,
            approval_executor=harness.executor,
            claim_service=knowledge.claim_service,
            wiki_service=knowledge.wiki_service,
            theory_service=knowledge.theory_service,
            claim_derivation_rule_ref=knowledge.claim_drafts[0].provenance.derivation_rule_ref,
            id_factory=harness.ids,
            clock=harness.clock,
            handle_key=b"r" * 32,
            publication_planner=planner,
        )

        pending = runtime.prepare_wiki_publication(
            knowledge.wiki,
            source_approval_request_id=knowledge.wiki.approval_request_id or "",
        )
        assert pending["status"] == (
            "prepared_pending_artifact_publication_approval"
        )
        publication_approval_id = pending["publication_approval_request_id"]
        assert isinstance(publication_approval_id, str)
        publication_operation_id = pending["publication_operation_id"]
        assert isinstance(publication_operation_id, str)
        approval_request = harness.approvals.get(publication_approval_id)
        durable_review = harness.store.read_hash_verified(
            approval_request.diff_object_ref.content_sha256
        )
        assert b'"publication_plan":' in durable_review
        assert publication_operation_id.encode("ascii") in durable_review
        assert b'"path":' not in durable_review
        assert b'"scope_binding":' not in durable_review
        challenge = harness.approvals.challenge_for_review(
            publication_approval_id
        )
        harness.approvals.confirm(harness.signer.confirm(challenge))

        restarted_planner = _planner(tmp_path, harness, knowledge)

        def unexpected_replan(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("restart must recover the approved exact plan")

        monkeypatch.setattr(
            restarted_planner,
            "plan_wiki",
            unexpected_replan,
        )
        restarted = GlobalKnowledgeToolRuntime(
            config=AppConfig.from_values(repo, harness.root),
            connection=harness.connection,
            content_store=harness.store,
            approval_service=harness.approvals,
            approval_executor=harness.executor,
            claim_service=knowledge.claim_service,
            wiki_service=knowledge.wiki_service,
            theory_service=knowledge.theory_service,
            claim_derivation_rule_ref=knowledge.claim_drafts[0].provenance.derivation_rule_ref,
            id_factory=harness.ids,
            clock=harness.clock,
            handle_key=b"s" * 32,
            publication_planner=restarted_planner,
        )

        active = restarted.publish_wiki(
            PublishWikiInput(approval_request_id=publication_approval_id)
        )

        assert active["status"] == "wiki_active"
        assert active["authority_active"] is True
        assert active["runtime_epoch"] == 1
        assert active["publication_operation_id"] == publication_operation_id
        assert ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set() is not None
    finally:
        harness.close()


def test_planner_module_has_no_test_helper_dependency() -> None:
    module = Path(
        "consultation_kb/publication/global_knowledge.py"
    ).read_text(encoding="utf-8")
    assert "tests.consultation_kb" not in module
    assert "DeterministicFakeEmbedder" not in module


def test_plan_does_not_create_runtime_epoch(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        planner = _planner(tmp_path, harness, knowledge)
        planner.plan_wiki(
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        rows = harness.connection.execute(
            "SELECT epoch, state FROM runtime_epochs"
        ).fetchall()
        assert rows == []
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM publication_operations"
        ).fetchone() == (0,)
    finally:
        harness.close()
