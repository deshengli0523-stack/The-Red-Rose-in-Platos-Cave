from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from consultation_kb.graph.serialization import (
    CanonicalGraphParseError,
    canonical_graph_bytes,
    global_graph_artifact_from_canonical_bytes,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import RetrievalScope
from consultation_kb.models.wiki import (
    WikiGraphRelationDeclaration,
    WikiRevisionDraft,
)
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
)
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
)
from consultation_kb.retrieval.global_graph import (
    GlobalGraphRetriever,
    GraphNodeQuery,
)
from consultation_kb.retrieval.global_graph_runtime import (
    GlobalGraphRuntime,
    GlobalGraphRuntimeError,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)


pytestmark = pytest.mark.integration


class _NoopNodeResolver:
    def resolve(
        self,
        query: str,
        scope: RetrievalScope,
        *,
        limit: int,
    ) -> tuple[GraphNodeQuery, ...]:
        del query, scope, limit
        return ()


def _add_multi_support_graph_relation(
    harness: GlobalKnowledgeHarness,
    knowledge: PreparedKnowledge,
) -> PreparedKnowledge:
    claim = knowledge.claims[1]
    relation = WikiGraphRelationDeclaration(
        source_ref=VersionRef(
            object_id=harness.ids.object_id("concept"),
            version=1,
            content_sha256="c" * 64,
        ),
        target_ref=VersionRef(
            object_id=harness.ids.object_id("practice"),
            version=1,
            content_sha256="d" * 64,
        ),
        claim_ref=VersionRef(
            object_id=claim.claim_id,
            version=claim.version,
            content_sha256=claim.text_sha256,
        ),
        relation="DISTINCT_FROM",
        scope=("relationship",),
        review_status="approved",
        effective_from=harness.clock.now(),
        confidence_override=0.7,
    )
    current = knowledge.wiki
    proposal = knowledge.wiki_service.propose_diff(
        WikiRevisionDraft(
            wiki_id=current.wiki_id,
            slug=current.slug,
            title=current.title,
            base_revision=current.revision,
            diff_kind="correct",
            sections=current.sections,
            theory_revision_refs=current.theory_revision_refs,
            relationships=current.relationships,
            graph_relations=(*current.graph_relations, relation),
            review_due_at=current.review_due_at,
            unresolved_questions=current.unresolved_questions,
        )
    )
    prepared = knowledge.wiki_service.approve(
        proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(
            knowledge.wiki_service.preview(proposal.proposal_id)
        ),
    )
    return replace(knowledge, wiki=prepared)


def _add_c1_graph_relation(
    harness: GlobalKnowledgeHarness,
    knowledge: PreparedKnowledge,
) -> PreparedKnowledge:
    relation = WikiGraphRelationDeclaration(
        source_ref=VersionRef(
            object_id=harness.ids.object_id("concept"),
            version=1,
            content_sha256="e" * 64,
        ),
        target_ref=VersionRef(
            object_id=harness.ids.object_id("practice"),
            version=1,
            content_sha256="f" * 64,
        ),
        claim_ref=knowledge.theory.claim_refs[0],
        relation="RELATED_TO",
        scope=("relationship",),
        review_status="approved",
        effective_from=harness.clock.now(),
        confidence_override=0.9,
    )
    current = knowledge.wiki
    proposal = knowledge.wiki_service.propose_diff(
        WikiRevisionDraft(
            wiki_id=current.wiki_id,
            slug=current.slug,
            title=current.title,
            base_revision=current.revision,
            diff_kind="correct",
            sections=current.sections,
            theory_revision_refs=current.theory_revision_refs,
            relationships=current.relationships,
            graph_relations=(*current.graph_relations, relation),
            review_due_at=current.review_due_at,
            unresolved_questions=current.unresolved_questions,
        )
    )
    prepared = knowledge.wiki_service.approve(
        proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(
            knowledge.wiki_service.preview(proposal.proposal_id)
        ),
    )
    return replace(knowledge, wiki=prepared)


def _publish_graph(tmp_path: Path, *, multi_support: bool) -> tuple[Path, Path]:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            second_claim_multi_support=multi_support,
            include_graph_relation=True,
        )
        if multi_support:
            knowledge = _add_multi_support_graph_relation(harness, knowledge)
        publication = prepare_global_publication(harness, knowledge)
        operation = publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        assert operation.state == "ACTIVE"
        return harness.root / "global.sqlite3", harness.root / "global-content"
    finally:
        harness.close()


def test_runtime_cold_restart_restores_exact_multi_passage_catalog(
    tmp_path: Path,
) -> None:
    database_path, content_root = _publish_graph(tmp_path, multi_support=True)

    connection = connect_database(database_path, mode="reader")
    try:
        active = ActiveRetrievalArtifactDiscovery(
            connection,
            ContentStore(content_root),
        ).discover_current_set()
        assert active is not None

        runtime = GlobalGraphRuntime.from_artifact_binding(
            active.graph,
            global_connection=connection,
        )
        snapshot = runtime.candidate_catalog.snapshot(
            graph_root_ref=active.graph.identity.root_ref,
            graph_version=runtime.authority_catalog.graph_version,
            runtime_epoch=active.active_runtime_epoch,
        )

        assert runtime.artifact.graph.number_of_edges() == 2
        assert len(snapshot.entries) == 3
        passage_counts: dict[str, int] = {}
        for entry in snapshot.entries:
            claim_id = entry.candidate.reference.object_id
            passage_counts[claim_id] = passage_counts.get(claim_id, 0) + 1
        assert sorted(passage_counts.values()) == [1, 2]
        assert all(
            entry.candidate.channel == "global_graph"
            and entry.candidate.filter_binding is None
            for entry in snapshot.entries
        )

        # A new retriever can be assembled using only the restarted runtime.
        GlobalGraphRetriever(
            runtime.artifact,
            artifact_binding=active.graph,
            edge_authority_resolver=runtime.edge_authority_resolver,
            node_resolver=_NoopNodeResolver(),
            candidate_catalog=runtime.candidate_catalog,
        )

        # Even a fully re-hashed payload cannot smuggle a non-production type.
        raw_graph = json.loads(active.graph.path_for("global_graph").read_bytes())
        raw_graph["edges"][0]["attributes"]["privacy_scope"] = "forged"
        forged = canonical_graph_bytes(raw_graph)
        with pytest.raises(CanonicalGraphParseError):
            global_graph_artifact_from_canonical_bytes(
                forged,
                expected_sha256=hashlib.sha256(forged).hexdigest(),
            )
    finally:
        connection.close()


def test_runtime_restart_rejects_governed_candidate_drift(tmp_path: Path) -> None:
    database_path, content_root = _publish_graph(tmp_path, multi_support=False)
    connection = connect_database(database_path, mode="writer")
    try:
        active = ActiveRetrievalArtifactDiscovery(
            connection,
            ContentStore(content_root),
        ).discover_current_set()
        assert active is not None
        builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
            active.graph.path_for("graph_builder_input").read_bytes(),
            strict=True,
        )
        record = builder_input.retrieval_input_descriptor.assigned_records("graph")[0]
        changed = connection.execute(
            "UPDATE claims SET allowed_uses_json = ? "
            "WHERE claim_id = ? AND version = ?",
            (
                '["consultation","tampered"]',
                record.candidate_ref.object_id,
                record.candidate_ref.version,
            ),
        ).rowcount
        assert changed == 1

        with pytest.raises(
            GlobalGraphRuntimeError,
            match="GLOBAL_GRAPH_RUNTIME_CANDIDATE_AUTHORITY_MISMATCH",
        ):
            GlobalGraphRuntime.from_artifact_binding(
                active.graph,
                global_connection=connection,
            )
    finally:
        connection.close()


def test_runtime_restart_rejects_binding_from_a_different_authority_database(
    tmp_path: Path,
) -> None:
    first_database, first_content = _publish_graph(
        tmp_path / "first",
        multi_support=False,
    )
    second_database, _ = _publish_graph(
        tmp_path / "second",
        multi_support=False,
    )
    first_connection = connect_database(first_database, mode="reader")
    second_connection = connect_database(second_database, mode="reader")
    try:
        active = ActiveRetrievalArtifactDiscovery(
            first_connection,
            ContentStore(first_content),
        ).discover_current_set()
        assert active is not None

        with pytest.raises(GlobalGraphRuntimeError):
            GlobalGraphRuntime.from_artifact_binding(
                active.graph,
                global_connection=second_connection,
            )
    finally:
        second_connection.close()
        first_connection.close()


def test_runtime_restart_accepts_activated_c1_graph_claim(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        knowledge = _add_c1_graph_relation(harness, knowledge)
        publication = prepare_global_publication(harness, knowledge)
        operation = publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        assert operation.state == "ACTIVE"
        database_path = harness.root / "global.sqlite3"
        content_root = harness.root / "global-content"
    finally:
        harness.close()

    connection = connect_database(database_path, mode="reader")
    try:
        active = ActiveRetrievalArtifactDiscovery(
            connection,
            ContentStore(content_root),
        ).discover_current_set()
        assert active is not None
        runtime = GlobalGraphRuntime.from_artifact_binding(
            active.graph,
            global_connection=connection,
        )
        snapshot = runtime.candidate_catalog.snapshot(
            graph_root_ref=active.graph.identity.root_ref,
            graph_version=runtime.authority_catalog.graph_version,
            runtime_epoch=active.active_runtime_epoch,
        )
        assert any(
            entry.candidate.metadata.source_grade == "C1"
            for entry in snapshot.entries
        )
    finally:
        connection.close()
