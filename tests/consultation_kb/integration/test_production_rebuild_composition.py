from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Literal

import numpy as np
import pytest

from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationRepository,
)
from consultation_kb.archive.private_record import PrivateArchiveDraftBuilder
from consultation_kb.core.clock import FixedClock
from consultation_kb.generation.c1_provider import DeterministicGenerationC1Provider
from consultation_kb.models.archive import PrivateArchiveAnalysis
from consultation_kb.lifecycle.production_rebuild import (
    CLIENT_POLICY_SHA256,
    CONFIG_FILENAME,
    ProductionRebuildConfig,
    resolve_client_rebuild,
    resolve_global_rebuild,
)
from consultation_kb.lifecycle.rebuild import RebuildCoordinatorError, RebuildRequest
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)
from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    ModelDescriptor,
)
from consultation_kb.retrieval.global_graph import (
    GlobalGraphRetriever,
    GraphNodeQuery,
)
from consultation_kb.retrieval.global_graph_runtime import GlobalGraphRuntime
from consultation_kb.retrieval.lexical import LexicalRetriever
from consultation_kb.retrieval.vector import ExactVectorRetriever
from consultation_kb.retrieval.wiki_index import WikiIndexRetriever
from consultation_kb.retrieval.client_history import (
    ClientHistoryQuery,
    ScopedClientHistoryService,
    client_history_derivation_rule_ref,
)
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
    ActiveRetrievalArtifactSet,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.wiki import WikiRevisionDraft
from consultation_kb.publication.global_knowledge import (
    GlobalKnowledgePublicationPlanner,
)
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    IntegrityStore,
)
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.storage.connection import connect_database
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.integration.test_client_publication_atomicity import (
    _executor as _client_executor,
    _plan as _client_plan,
    _ticket as _client_ticket,
)
from tests.consultation_kb.integration.test_case_index_publication_authority import (
    NOW as CASE_NOW,
    _fixture as _case_fixture,
    _publish_case_index,
    _seed_verified_shared_case,
)
from tests.consultation_kb.integration.test_production_global_publication_planner import (
    _planner as _global_publication_planner,
)
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)
from tests.consultation_kb.retrieval_support import model_descriptor
from tests.consultation_kb.retrieval_support import NOW as RETRIEVAL_NOW
from tests.consultation_kb.unit.test_generation_c1_provider import (
    _Authority as _C1Authority,
    _input as _c1_input,
    _plan as _c1_plan,
)
from tests.consultation_kb.private_archive_approval_support import (
    commit_private_archive_with_guard,
)
from tests.consultation_kb.integration.test_rebuild_all import (
    SCOPE_HASH,
    _connection,
    _ids,
    _start_approved,
)


class _GraphEndpoints:
    def __init__(self, runtime: GlobalGraphRuntime) -> None:
        edge = next(iter(runtime.artifact.graph.edges), None)
        assert edge is not None
        self._query = GraphNodeQuery(
            source_node_id=str(edge[0]),
            target_node_id=str(edge[1]),
        )

    def resolve(
        self,
        query: str,
        scope: RetrievalScope,
        *,
        limit: int,
    ) -> tuple[GraphNodeQuery, ...]:
        del query, scope
        return (self._query,)[:limit]


def _run_next_in_subprocess(
    *,
    database_scope: Literal["global", "client"],
    database: Path,
    root: Path,
    scope_sha256: str,
) -> dict[str, object]:
    script = """
import json
import sys
from pathlib import Path
from consultation_kb.lifecycle.production_rebuild import resolve_client_rebuild, resolve_global_rebuild
from consultation_kb.storage.connection import connect_database

scope, database, root, scope_sha256 = sys.argv[1:]
connection = connect_database(Path(database), "writer")
try:
    if scope == "global":
        coordinator = resolve_global_rebuild(connection, Path(root), scope_sha256)
    else:
        coordinator = resolve_client_rebuild(connection, Path(root), scope_sha256)
    completed = coordinator.run_next()
    if completed is None:
        raise RuntimeError("REBUILD_SUBPROCESS_JOB_MISSING")
    print(json.dumps({
        "job_id": completed.job_id,
        "state": completed.state,
        "last_error_code": completed.last_error_code,
        "output_manifest_set_sha256": completed.output_manifest_set_sha256,
    }, sort_keys=True, separators=(",", ":")))
finally:
    connection.close()
"""
    result = subprocess.run(
        (
            sys.executable,
            "-c",
            script,
            database_scope,
            str(database),
            str(root),
            scope_sha256,
        ),
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr
    return json.loads(result.stdout.strip())


def _assert_job_crossed_full_state_machine(
    connection: sqlite3.Connection,
    *,
    database_scope: Literal["global", "client"],
    job_id: str,
) -> None:
    repository = RebuildJobRepository(
        connection,
        database_scope=database_scope,
    )
    assert tuple(entry.state for entry in repository.journal(job_id)) == (
        "queued",
        "running",
        "verifying",
        "activating",
        "succeeded",
    )


def _publish_real_private_archive(
    connection: sqlite3.Connection,
    root: Path,
) -> bytes:
    clock = FixedClock(RETRIEVAL_NOW)
    ids = _ids(88_000)
    repository = SessionRepository(
        connection,
        content_store=ContentStore(root / "cas"),
        clock=clock,
        id_factory=ids,
    )
    session_id = ids.uuid7()
    repository.create_session(
        session_id=session_id,
        client_id="client_" + "a" * 12,
        client_scope_hash=SCOPE_HASH,
        snapshot_version=1,
        snapshot_canonical_sha256="9" * 64,
        snapshot_bytes=b'{"schema_version":"test_client_snapshot.v1"}',
    )
    turn_id = ids.uuid7()
    run_id = ids.uuid7()
    TurnService(repository).append(session_id, turn_id, "approved archive input")
    TurnService(repository).begin_generation(session_id, turn_id, run_id=run_id)
    candidates = CandidateSetService(repository).store_and_await(
        session_id,
        turn_id,
        ("approved counselor reply", "unselected model scratch canary"),
        run_id=run_id,
        idempotency_key="production-rebuild-archive-candidates",
    )
    ActualReplyService(repository).record_adopted(
        session_id,
        turn_id,
        candidates.candidates[0].candidate_id,
        sent_at=clock.now(),
        idempotency_key="production-rebuild-archive-actual",
    )
    ArchiveBundleService(repository).propose(session_id)
    draft = PrivateArchiveDraftBuilder(repository).build(
        session_id,
        analysis=PrivateArchiveAnalysis(
            counselor_reflection=("approved exact archive reflection",),
        ),
    )
    _decision, publication, replayed = commit_private_archive_with_guard(
        repository,
        draft,
    )
    assert publication == replayed
    return draft.canonical_text.encode("utf-8")


def _active_manifest(
    connection: sqlite3.Connection,
    *,
    artifact_key: str,
) -> ArtifactManifest:
    row = connection.execute(
        "SELECT active.manifest_id FROM active_artifacts AS active "
        "JOIN runtime_epochs AS runtime ON runtime.epoch = active.epoch "
        "WHERE runtime.state = 'ACTIVE' AND active.artifact_key = ?",
        (artifact_key,),
    ).fetchone()
    assert row is not None
    return ManifestRepository(connection).get(str(row[0]))


def _assert_real_client_consumers(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    expected_private_archive: bytes,
) -> None:
    service = ScopedClientHistoryService(
        connection,
        current_client_id="client_" + "a" * 12,
        derivation_rule_ref=client_history_derivation_rule_ref(),
    )
    result = service.query(
        ClientHistoryQuery(
            request_id=_ids(91_000).uuid7(),
            session_handle="production-rebuild-client-consumers",
            query_category="continuity",
        )
    )
    by_type = {candidate.object_type: candidate for candidate in result.candidates}
    assert {"fact_snapshot", "profile_json", "client_graph"} <= set(by_type)
    for object_type in ("fact_snapshot", "profile_json", "client_graph"):
        payload = store.read_hash_verified(
            by_type[object_type].content_ref.content_sha256
        )
        assert json.loads(payload)

    profile = _active_manifest(connection, artifact_key="client_profile")
    markdown = next(
        member for member in profile.members if member.object_type == "profile_markdown"
    )
    assert store.read_hash_verified(markdown.object_sha256).decode("utf-8").strip()

    archive = _active_manifest(connection, artifact_key="private_archive")
    assert archive.artifact_kind == "private_archive"
    assert tuple(member.object_type for member in archive.members) == (
        "private_archive_draft",
    )
    rebuilt = store.read_hash_verified(archive.members[0].object_sha256)
    assert rebuilt == expected_private_archive
    assert b"unselected model scratch canary" not in rebuilt


def _assert_real_global_consumers(
    connection: sqlite3.Connection,
    active: ActiveRetrievalArtifactSet,
    *,
    descriptor: ModelDescriptor,
    vocabulary: dict[str, tuple[float, ...]],
) -> None:
    queries = tuple(vocabulary)
    embedder = DeterministicFakeEmbedder(
        descriptor,
        {
            text: np.asarray(vector, dtype=np.float32)
            for text, vector in vocabulary.items()
        },
    )
    wiki = WikiIndexRetriever(active.wiki_index)
    lexical = LexicalRetriever.from_artifact_binding(active.lexical)
    vector = ExactVectorRetriever.from_artifact_binding(
        active.vector,
        embedder=embedder,
    )
    graph_runtime = GlobalGraphRuntime.from_artifact_binding(
        active.graph,
        global_connection=connection,
    )
    graph = GlobalGraphRetriever(
        graph_runtime.artifact,
        artifact_binding=active.graph,
        edge_authority_resolver=graph_runtime.edge_authority_resolver,
        node_resolver=_GraphEndpoints(graph_runtime),
        candidate_catalog=graph_runtime.candidate_catalog,
    )
    snapshot_at = max(RETRIEVAL_NOW, graph_runtime.artifact.effective_at)
    allowed_ref_ids = {
        reference.object_id
        for record in graph_runtime.builder_input.retrieval_input_descriptor.records
        for reference in (record.candidate_ref, record.content_ref)
    }
    allowed_ref_ids.update(
        value.relation_ref.object_id
        for value in graph_runtime.authority_catalog.records
    )
    allowed_ref_ids.update(
        value.authority_ref.object_id
        for value in graph_runtime.authority_catalog.records
    )
    for *_edge, attributes in graph_runtime.artifact.graph.edges(data=True):
        for name in ("claim_ref", "theory_ref", "wiki_ref"):
            reference = attributes.get(name)
            if isinstance(reference, VersionRef):
                allowed_ref_ids.add(reference.object_id)
        passages = attributes.get("passage_refs", ())
        if isinstance(passages, tuple):
            allowed_ref_ids.update(
                reference.object_id
                for reference in passages
                if isinstance(reference, VersionRef)
            )
    allowed_ref_ids.add(
        next(
            value.object_id
            for value in active.graph.verify_current().members
            if value.role == "graph_build_manifest"
        )
    )
    snapshot = AuthoritativeFilterSnapshot(
        run_id=_ids(92_000).uuid7(),
        global_runtime_epoch=active.active_runtime_epoch,
        client_runtime_epoch=0,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(allowed_ref_ids),
        policy_ref=(
            graph_runtime.builder_input.retrieval_input_descriptor.route_policy_ref
        ),
        created_at=snapshot_at,
    )
    scope = RetrievalScope(
        current_client_id="client_" + "z" * 12,
        allowed_uses=frozenset({"answer_support", "consultation"}),
        maximum_sensitivity=3,
        effective_at=snapshot_at,
        known_at=snapshot_at,
    )
    wiki_queries = tuple(
        token
        for row in wiki.payload.rows
        for token in row.word_tokens
    )
    assert any(
        wiki.search(query, scope, snapshot, limit=20)
        for query in (*wiki_queries, *queries)
    )
    assert any(
        lexical.search(query, scope, snapshot, limit=20) for query in queries
    )
    assert any(
        vector.search(query, scope, snapshot, limit=20) for query in queries
    )
    assert any(
        graph.search(query, scope, snapshot, limit=20) for query in queries
    )


def _assert_active_integrity(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    scope: Literal["global", "client_private"],
    client_id: str | None = None,
) -> tuple[int, int]:
    row = connection.execute(
        "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchone()
    assert row is not None
    epoch = int(row[0])
    repository = ManifestRepository(connection)
    manifests = tuple(
        repository.get(str(value[1]))
        for value in connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        )
    )
    assert manifests
    source_versions = {manifest.source_version for manifest in manifests}
    assert len(source_versions) == 1
    source_version = next(iter(source_versions))
    ActiveIntegrityGate(
        IntegrityStore(
            scope=scope,
            connection=connection,
            content_store=store,
            client_id=client_id,
        )
    ).verify(
        epoch=epoch,
        artifacts=tuple(
            ActiveArtifact(
                artifact_key=manifest.artifact_key,
                manifest_ref=VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                ),
            )
            for manifest in manifests
        ),
        source_version=source_version,
        authority_version=source_version,
        tombstone_epoch=0,
    )
    return epoch, source_version


def _global_rebuild_vocabulary(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    extra_texts: tuple[str, ...] = (),
) -> dict[str, tuple[float, ...]]:
    values: dict[str, tuple[float, ...]] = {}
    for (reference,) in connection.execute(
        "SELECT retrieval_content_ref FROM passages ORDER BY passage_id, version"
    ):
        text = store.read_hash_verified(
            str(reference).removeprefix("sha256:")
        ).decode("utf-8", errors="strict")
        values[text] = (1.0, 0.0)
    for text in extra_texts:
        values[text] = (1.0, 0.0)
    return values


def _prepare_wiki_without_theory(
    harness,  # type: ignore[no-untyped-def]
    knowledge,  # type: ignore[no-untyped-def]
):  # type: ignore[no-untyped-def]
    claim_refs = tuple(
        VersionRef(
            object_id=claim.claim_id,
            version=claim.version,
            content_sha256=claim.text_sha256,
        )
        for claim in knowledge.claims
    )
    draft = WikiRevisionDraft(
        wiki_id=harness.ids.object_id("wiki"),
        slug="no-governed-c1",
        title="无受治理 C1 的知识页",
        base_revision=0,
        diff_kind="add",
        sections=tuple(
            section.model_copy(update={"claim_refs": claim_refs})
            for section in knowledge.wiki.sections
        ),
        theory_revision_refs=(),
        relationships=knowledge.wiki.relationships,
        graph_relations=(),
        review_due_at=None,
        unresolved_questions=("当前没有受治理的 C1 理论版本",),
    )
    proposal = knowledge.wiki_service.propose_diff(draft)
    descriptor = knowledge.wiki_service.preview(proposal.proposal_id)
    return knowledge.wiki_service.approve(
        proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(descriptor),
    )


def test_client_production_rebuild_rejects_empty_authority_without_activation(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    connection = _connection(root, "client")
    config = ProductionRebuildConfig.create_client(scope_sha256=SCOPE_HASH)
    (root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
    coordinator = resolve_client_rebuild(connection, root, SCOPE_HASH)
    try:
        plan = coordinator.plan(
            RebuildRequest(
                database_scope="client",
                scope_sha256=SCOPE_HASH,
                purpose="all",
                policy_sha256=CLIENT_POLICY_SHA256,
                model_descriptor_sha256=None,
            )
        )
        queued = _start_approved(
            connection,
            coordinator,
            plan,
            idempotency_key="production-client-empty-authority",
        )

        completed = coordinator.run_next()

        assert completed is not None
        assert completed.job_id == queued.job_id
        assert (completed.state, completed.last_error_code) == (
            "failed",
            "REBUILD_CLIENT_AUTHORITY_EMPTY",
        )
        assert connection.execute("SELECT * FROM active_artifacts").fetchall() == []
        assert connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall() == []
    finally:
        connection.close()


def test_client_production_rebuild_replays_real_fact_authority_and_is_stable(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    harness = build_approval_harness(root, target_scope_hash=SCOPE_HASH)
    try:
        publication = _client_plan(harness)
        proof = _client_executor(harness, root).execute(
            publication,
            _client_ticket(harness, publication),
        )
        harness.service.acknowledge(proof)
        approved_private_archive = _publish_real_private_archive(
            harness.target_connection,
            root,
        )
        # Model the REBUILD-ALL loss boundary: durable authority remains, while
        # the active derived closure has been physically removed.
        harness.target_connection.execute("DELETE FROM active_artifacts")
        harness.target_connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
        )
        config = ProductionRebuildConfig.create_client(scope_sha256=SCOPE_HASH)
        (root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
        coordinator = resolve_client_rebuild(
            harness.target_connection,
            root,
            SCOPE_HASH,
        )
        request = RebuildRequest(
            database_scope="client",
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=CLIENT_POLICY_SHA256,
            model_descriptor_sha256=None,
        )
        first = _start_approved(
            harness.target_connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-client-real-authority-one",
        )

        harness.target_connection.close()
        subprocess_result = _run_next_in_subprocess(
            database_scope="client",
            database=root / "client.sqlite3",
            root=root,
            scope_sha256=SCOPE_HASH,
        )
        assert subprocess_result["job_id"] == first.job_id
        assert subprocess_result["state"] == "succeeded"
        assert subprocess_result["last_error_code"] is None
        assert subprocess_result["output_manifest_set_sha256"] is not None
        harness.target_connection = connect_database(
            root / "client.sqlite3",
            "writer",
        )
        coordinator = resolve_client_rebuild(
            harness.target_connection,
            root,
            SCOPE_HASH,
        )
        first_completed = RebuildJobRepository(
            harness.target_connection,
            database_scope="client",
        ).get(first.job_id)

        assert first_completed.job_id == first.job_id
        assert (first_completed.state, first_completed.last_error_code) == (
            "succeeded",
            None,
        )
        _assert_job_crossed_full_state_machine(
            harness.target_connection,
            database_scope="client",
            job_id=first.job_id,
        )
        second = _start_approved(
            harness.target_connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-client-real-authority-two",
        )

        second_completed = coordinator.run_next()

        assert second_completed is not None
        assert second_completed.job_id == second.job_id
        assert (second_completed.state, second_completed.last_error_code) == (
            "succeeded",
            None,
        )
        assert second_completed.equivalence_report_sha256 is not None
        store = ContentStore(root / "cas")
        report = json.loads(
            store.read_hash_verified(
                second_completed.equivalence_report_sha256
            )
        )
        assert all(item["equivalent"] for item in report["items"])
        service = ScopedClientHistoryService(
            harness.target_connection,
            current_client_id="client_" + "a" * 12,
            derivation_rule_ref=client_history_derivation_rule_ref(),
        )
        result = service.query(
            ClientHistoryQuery(
                request_id=_ids(91_000).uuid7(),
                session_handle="production-rebuild-real-fact",
                query_category="continuity",
            )
        )
        fact = next(
            candidate
            for candidate in result.candidates
            if candidate.object_type == "fact_snapshot"
        )
        assert publication.events[0].event_id.encode("utf-8") in (
            store.read_hash_verified(fact.reference.content_sha256)
        )
        assert harness.target_connection.execute(
            "SELECT DISTINCT manifest.source_version "
            "FROM active_artifacts AS active "
            "JOIN artifact_manifests AS manifest "
            "ON manifest.manifest_id = active.manifest_id"
        ).fetchall() == [("1",)]
        assert harness.target_connection.execute(
            "SELECT authority_base_version FROM publication_operations "
            "WHERE purpose = 'rebuild' AND state = 'ACTIVE'"
        ).fetchone() == (1,)
        assert _assert_active_integrity(
            harness.target_connection,
            store,
            scope="client_private",
            client_id="client_" + "a" * 12,
        ) == (3, 1)
        _assert_real_client_consumers(
            harness.target_connection,
            store,
            expected_private_archive=approved_private_archive,
        )
    finally:
        harness.close()


def test_global_production_rebuild_compiles_real_eight_root_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        authority_version = int(
            harness.connection.execute(
                "SELECT COALESCE(MAX(applied_commit_version), 0) + 1 "
                "FROM approval_executions"
            ).fetchone()[0]
        )
        publication = prepare_global_publication(
            harness,
            knowledge,
            authority_base_version=authority_version,
        )
        published = publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        assert published.runtime_epoch == 1
        published_catalog_version = int(
            harness.connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()[0]
        )
        # Lose exactly the P4 roots while retaining the same-epoch governed
        # claims/C1/Wiki authority that real readers require and rebuild must
        # carry forward atomically.
        harness.connection.execute(
            "DELETE FROM active_artifacts WHERE artifact_key IN "
            "('wiki_index','knowledge_registry','graph','lexical','vector')"
        )
        descriptor = model_descriptor()
        vocabulary: dict[str, tuple[float, ...]] = {}
        for (reference,) in harness.connection.execute(
            "SELECT retrieval_content_ref FROM passages "
            "ORDER BY passage_id, version"
        ):
            text = harness.store.read_hash_verified(
                str(reference).removeprefix("sha256:")
            ).decode("utf-8", errors="strict")
            vocabulary[text] = (1.0, 0.0)
        config = ProductionRebuildConfig.create_global(
            scope_sha256="a" * 64,
            model_descriptor=descriptor,
            embedder_kind="deterministic_test",
            deterministic_vocabulary=vocabulary,
            test_mode=True,
            target_wiki_id=knowledge.wiki.wiki_id,
            cas_directory="global-content",
            graphify_production=False,
        )
        (harness.root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
        coordinator = resolve_global_rebuild(
            harness.connection,
            harness.root.resolve(),
            "a" * 64,
        )
        request = RebuildRequest(
            database_scope="global",
            scope_sha256="a" * 64,
            purpose="all",
            policy_sha256=config.policy_sha256,
            model_descriptor_sha256=descriptor.id,
        )
        queued = _start_approved(
            harness.connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-global-real-authority",
        )

        harness.connection.close()
        subprocess_result = _run_next_in_subprocess(
            database_scope="global",
            database=harness.root / "global.sqlite3",
            root=harness.root.resolve(),
            scope_sha256="a" * 64,
        )
        assert subprocess_result["job_id"] == queued.job_id
        assert subprocess_result["state"] == "succeeded"
        assert subprocess_result["last_error_code"] is None
        assert subprocess_result["output_manifest_set_sha256"] is not None
        harness.connection = connect_database(
            harness.root / "global.sqlite3",
            "writer",
        )
        coordinator = resolve_global_rebuild(
            harness.connection,
            harness.root.resolve(),
            "a" * 64,
        )
        completed = RebuildJobRepository(
            harness.connection,
            database_scope="global",
        ).get(queued.job_id)

        assert completed.job_id == queued.job_id
        assert (completed.state, completed.last_error_code) == (
            "succeeded",
            None,
        )
        _assert_job_crossed_full_state_machine(
            harness.connection,
            database_scope="global",
            job_id=queued.job_id,
        )
        second = _start_approved(
            harness.connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-global-real-authority-two",
        )

        second_completed = coordinator.run_next()

        assert second_completed is not None
        assert second_completed.job_id == second.job_id
        assert (second_completed.state, second_completed.last_error_code) == (
            "succeeded",
            None,
        )
        assert second_completed.equivalence_report_sha256 is not None
        report = json.loads(
            harness.store.read_hash_verified(
                second_completed.equivalence_report_sha256
            )
        )
        assert all(item["equivalent"] for item in report["items"])
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None
        assert active.active_runtime_epoch == 3
        assert {binding.identity.artifact_key for binding in active.bindings()} == {
            "wiki_index",
            "knowledge_registry",
            "graph",
            "lexical",
            "vector",
        }
        _assert_real_global_consumers(
            harness.connection,
            active,
            descriptor=descriptor,
            vocabulary=vocabulary,
        )
        assert _assert_active_integrity(
            harness.connection,
            harness.store,
            scope="global",
        ) == (3, published_catalog_version)
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM active_artifacts WHERE epoch = 3"
        ).fetchone() == (8,)

        original_build = GlobalKnowledgePublicationPlanner._build_artifacts

        def omit_governed_c1(self, state):  # type: ignore[no-untyped-def]
            return tuple(
                draft
                for draft in original_build(self, state)
                if draft.artifact_key != "c1_revision"
            )

        monkeypatch.setattr(
            GlobalKnowledgePublicationPlanner,
            "_build_artifacts",
            omit_governed_c1,
        )
        incomplete = _start_approved(
            harness.connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-global-governed-c1-omitted",
        )
        rejected = coordinator.run_next()
        assert rejected is not None and rejected.job_id == incomplete.job_id
        assert (rejected.state, rejected.last_error_code) == (
            "failed",
            "REBUILD_GLOBAL_CLOSURE_INCOMPLETE",
        )
    finally:
        harness.close()


def test_global_production_rebuild_publishes_canonical_c1_absence(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        wiki = _prepare_wiki_without_theory(harness, knowledge)
        planner = _global_publication_planner(tmp_path, harness, knowledge)
        publication_plan = planner.plan_wiki(
            wiki_id=wiki.wiki_id,
            wiki_revision=wiki.revision,
        )
        assert "c1_revision" not in publication_plan.artifact_kinds
        harness.guard._commit_version_allocator = (  # noqa: SLF001
            lambda _connection: publication_plan.authority_base_version
        )
        planner.execute(
            publication_plan,
            approval_request_id=harness.confirm(publication_plan.descriptor),
        )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM theory_revisions WHERE status = 'ACTIVE'"
        ).fetchone() == (0,)

        descriptor = model_descriptor()
        vocabulary = _global_rebuild_vocabulary(
            harness.connection,
            harness.store,
        )
        config = ProductionRebuildConfig.create_global(
            scope_sha256="a" * 64,
            model_descriptor=descriptor,
            embedder_kind="deterministic_test",
            deterministic_vocabulary=vocabulary,
            test_mode=True,
            target_wiki_id=wiki.wiki_id,
            cas_directory="global-content",
            graphify_production=False,
        )
        (harness.root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
        coordinator = resolve_global_rebuild(
            harness.connection,
            harness.root.resolve(),
            "a" * 64,
        )
        request = RebuildRequest(
            database_scope="global",
            scope_sha256="a" * 64,
            purpose="all",
            policy_sha256=config.policy_sha256,
            model_descriptor_sha256=descriptor.id,
        )
        queued = _start_approved(
            harness.connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="production-global-no-c1",
        )

        completed = coordinator.run_next()

        assert completed is not None and completed.job_id == queued.job_id
        assert (completed.state, completed.last_error_code) == ("succeeded", None)
        assert harness.connection.execute(
            "SELECT manifest.artifact_kind, member.object_type "
            "FROM runtime_epochs AS epoch "
            "JOIN active_artifacts AS active ON active.epoch = epoch.epoch "
            "JOIN artifact_manifests AS manifest "
            "  ON manifest.manifest_id = active.manifest_id "
            "JOIN artifact_members AS member "
            "  ON member.manifest_id = manifest.manifest_id "
            "WHERE epoch.state = 'ACTIVE' "
            "AND active.artifact_key = 'c1_revision'"
        ).fetchall() == [("c1_absence", "c1_absence")]
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None
        authority = _C1Authority(
            harness=harness,
            knowledge=knowledge,
            active=active,
        )
        query_plan = _c1_plan(authority)
        result = DeterministicGenerationC1Provider(
            clock=harness.clock
        ).resolve(
            query_plan,
            _c1_input(query_plan),
            global_connection=harness.connection,
            global_content_store=harness.store,
            active_artifacts=active,
        )
        assert result.decision.status == "unavailable"
        assert result.decision.revision is None
        assert result.decision.matched_rule_ids == ()
        assert result.decision.conflict_evidence_ids == ()
    finally:
        harness.close()


def test_global_rebuild_plan_binds_exact_pending_case_index_identity_set(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first, _ = _case_fixture(counter_start=170_000)
        _publish_case_index(
            harness,
            _seed_verified_shared_case(harness, first),
        )
        repository = CaseIndexPublicationRepository(
            harness.connection,
            harness.store,
            clock=FixedClock(CASE_NOW),
        )
        first_snapshot = repository.pending_rebuild_snapshot()
        assert len(first_snapshot.identities) == 1
        descriptor = model_descriptor()
        case_texts = tuple(
            artifact.rendered_text
            for bundle in repository.replay_approved()
            for artifact in bundle.artifacts
        )
        config = ProductionRebuildConfig.create_global(
            scope_sha256="a" * 64,
            model_descriptor=descriptor,
            embedder_kind="deterministic_test",
            deterministic_vocabulary={
                text: (1.0, 0.0) for text in case_texts
            },
            test_mode=True,
            cas_directory="global-content",
            graphify_production=False,
        )
        (harness.root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
        coordinator = resolve_global_rebuild(
            harness.connection,
            harness.root.resolve(),
            "a" * 64,
        )
        request = RebuildRequest(
            database_scope="global",
            scope_sha256="a" * 64,
            purpose="all",
            policy_sha256=config.policy_sha256,
            model_descriptor_sha256=descriptor.id,
        )
        plan = coordinator.plan(request)
        assert plan.case_index_intent_set_sha256 == first_snapshot.identity_sha256

        second, _ = _case_fixture(counter_start=180_000)
        _publish_case_index(
            harness,
            _seed_verified_shared_case(harness, second),
        )
        second_snapshot = repository.pending_rebuild_snapshot()
        assert len(second_snapshot.identities) == 2
        assert second_snapshot.identity_sha256 != plan.case_index_intent_set_sha256
        with pytest.raises(
            RebuildCoordinatorError,
            match="REBUILD_CASE_INDEX_INTENT_SET_CHANGED",
        ):
            coordinator.start(plan, idempotency_key="stale-case-index-plan")
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM rebuild_jobs"
        ).fetchone() == (0,)
    finally:
        harness.close()
