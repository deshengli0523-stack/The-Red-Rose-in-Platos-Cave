from __future__ import annotations

import hashlib
import importlib
import sqlite3
from pathlib import Path

import numpy as np
import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.lifecycle.publish import (
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.graph.artifact_contracts import (
    GraphBuildManifestPayload,
    GraphEdgeAuthorityCatalogPayload,
    build_expected_graph_edge_mapping,
)
from consultation_kb.graph.graphify_adapter import GraphifyProjectionAdapter
from consultation_kb.graph.serialization import canonical_graph_bytes, graph_payload
from consultation_kb.knowledge.wiki import wiki_revision_body_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.wiki import WikiRevision, WikiRevisionDraft, WikiSection
from consultation_kb.operations.doctor_probes import RetrievalArtifactDiagnosticProbe
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.contracts import canonical_json_bytes
from consultation_kb.retrieval.embeddings import DeterministicFakeEmbedder
from consultation_kb.retrieval.evidence_pack import RootManifestSet
from consultation_kb.retrieval.lexical import LexicalIndexError, LexicalRetriever
from consultation_kb.retrieval.lexical_builder import LexicalDocument, LexicalIndexBuilder
from consultation_kb.retrieval.vector import ExactVectorRetriever
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorDocument,
)
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexBuilder
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.retrieval_support import (
    candidate,
    model_descriptor,
    object_id,
    NOW,
    scope,
    snapshot,
)
from tests.consultation_kb.risk_support import insert_approved_risk_policy_epoch
from tests.consultation_kb.unit.test_graph_artifact_contracts import (
    _closure as graph_closure,
    _projection_bytes,
)


pytestmark = pytest.mark.integration


def _modules():
    try:
        publication = importlib.import_module(
            "consultation_kb.retrieval.artifact_publication"
        )
        discovery = importlib.import_module(
            "consultation_kb.retrieval.artifact_discovery"
        )
    except ModuleNotFoundError:
        pytest.fail("retrieval artifact discovery is not implemented", pytrace=False)
    return publication, discovery


def _ids(module, kind: str, start: int):
    return module.ArtifactPublicationIds(
        manifest_id=object_id("manifest", start),
        member_object_ids={
            role: object_id(role, start + index + 1)
            for index, role in enumerate(derived_artifact_role_layout(kind))
        },
    )


def _synthetic_wiki_revision(graph_candidates) -> WikiRevision:
    claim_refs = tuple(
        sorted(
            {candidate.reference for candidate in graph_candidates},
            key=lambda value: (
                value.object_id,
                value.version,
                value.content_sha256,
            ),
        )
    )
    passage_refs = tuple(
        sorted(
            {candidate.content_ref for candidate in graph_candidates},
            key=lambda value: (
                value.object_id,
                value.version,
                value.content_sha256,
            ),
        )
    )
    draft = WikiRevisionDraft(
        wiki_id=object_id("wiki", 1800),
        slug="synthetic-active-artifact-navigation",
        title="Synthetic active artifact navigation",
        base_revision=0,
        diff_kind="add",
        sections=(
            WikiSection(
                key="active_artifact_navigation",
                heading="Active artifact navigation",
                body="Navigation metadata only; exact Passage bodies remain authoritative.",
                claim_refs=claim_refs,
                passage_refs=passage_refs,
                stance="context",
            ),
        ),
        theory_revision_refs=(),
        review_due_at=None,
    )
    return WikiRevision(
        wiki_id=draft.wiki_id,
        revision=1,
        slug=draft.slug,
        title=draft.title,
        base_revision=draft.base_revision,
        diff_kind=draft.diff_kind,
        sections=draft.sections,
        theory_revision_refs=draft.theory_revision_refs,
        relationships=draft.relationships,
        graph_relations=draft.graph_relations,
        review_due_at=draft.review_due_at,
        unresolved_questions=draft.unresolved_questions,
        body_sha256=wiki_revision_body_sha256(draft),
        diff_sha256=hashlib.sha256(
            canonical_json_bytes(draft.model_dump(mode="json"))
        ).hexdigest(),
        status="prepared",
        approval_request_id=object_id("approval_request", 1801),
        created_at=NOW,
    )


def test_risk_only_active_epoch_is_clean_empty_for_retrieval(
    tmp_path: Path,
) -> None:
    _publication, discovery_module = _modules()
    repo_root = Path(__file__).resolve().parents[3]
    vault_root = tmp_path / "vault"
    global_root = vault_root / "global"
    global_root.mkdir(parents=True)
    connection = connect_database(global_root / "catalog.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        loaded = PolicyLoader.from_config(
            AppConfig.from_values(repo_root, vault_root)
        ).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            connection,
            loaded,
            epoch=1,
            suffix=917_000,
        )

        discovery = discovery_module.ActiveRetrievalArtifactDiscovery(
            connection,
            ContentStore(global_root),
        )
        assert discovery.discover_current_set() is None
    finally:
        connection.close()


def _builder_inputs(
    lexical_candidate,
    graph_candidates,
    route_policy_ref,
    wiki_revision: WikiRevision,
):
    descriptor = RetrievalInputDescriptor.from_assignments(
        tuple(
            [
            RetrievalInputAssignment.from_candidate(
                lexical_candidate,
                target_channels=frozenset({"lexical", "vector"}),
            )
            ]
            + [
                assignment
                for graph_candidate in graph_candidates
                for assignment in (
                    RetrievalInputAssignment.from_candidate(
                        graph_candidate,
                        target_channels=frozenset({"graph"}),
                    ),
                    RetrievalInputAssignment.from_candidate(
                        graph_candidate.model_copy(update={"channel": "wiki"}),
                        target_channels=frozenset({"wiki_index"}),
                    ),
                )
            ]
        ),
        route_policy_ref=route_policy_ref,
    )
    authority = {
        "authorization_epoch": 0,
        "catalog_version": 4,
        "claims": tuple(
            {
                "object_id": reference.object_id,
                "version": reference.version,
                "object_sha256": reference.content_sha256,
            }
            for reference in sorted(
                {
                    lexical_candidate.reference,
                    *(candidate.reference for candidate in graph_candidates),
                },
                key=lambda value: (
                    value.object_id,
                    value.version,
                    value.content_sha256,
                ),
            )
        ),
        "expected_current_epoch": None,
        "maximum_runtime_epoch": 0,
        "publication_authority_version": 5,
        "target_runtime_epoch": 1,
        "theory": None,
        "tombstone_epoch": 0,
        "wiki": {
            "object_id": wiki_revision.wiki_id,
            "version": wiki_revision.revision,
            "object_sha256": wiki_revision.body_sha256,
        },
    }
    digest = hashlib.sha256(canonical_json_bytes(authority)).hexdigest()

    def value(kind: str) -> DerivedArtifactBuilderInputV2:
        return DerivedArtifactBuilderInputV2(
            artifact_kind=kind,
            authority_closure_sha256=digest,
            authority_snapshot=authority,
            retrieval_input_descriptor=descriptor,
            target_runtime_epoch=1,
        )

    return value


def _projection_draft(
    factory,
    *,
    kind: str,
    builder_input: DerivedArtifactBuilderInputV2,
    ids,
    build_root: Path,
    route_policy_payload: bytes,
    wiki_revision: WikiRevision | None = None,
    wiki_candidates=(),
):
    if kind == "wiki_index":
        if wiki_revision is None:
            raise AssertionError("wiki revision is required")
        descriptor_records = {
            (record.candidate_ref, record.content_ref): record
            for record in builder_input.retrieval_input_descriptor.assigned_records(
                "wiki_index"
            )
        }
        assignments = tuple(
            RetrievalInputAssignment.from_candidate(
                candidate.model_copy(update={"channel": "wiki"}),
                target_channels=descriptor_records[
                    (candidate.reference, candidate.content_ref)
                ].target_channels,
            )
            for candidate in wiki_candidates
        )
        artifacts = WikiNavigationIndexBuilder().build(
            assignments,
            wiki_revision,
            builder_input=builder_input,
        )
        data_payloads = {
            "wiki_index": artifacts.index_bytes,
        }
        manifest = artifacts.build_manifest
    else:
        data_payloads = {
            "retrieval_route_policy": route_policy_payload,
            "knowledge_registry": canonical_json_bytes(
                KnowledgeRegistryPayloadV1.from_descriptor(
                    builder_input.retrieval_input_descriptor
                ).model_dump(mode="json")
            ),
        }
        manifest = GenericDerivedBuildManifestV2.create(
            artifact_kind=kind,
            builder_input=builder_input,
            member_content_sha256={
                role: hashlib.sha256(payload).hexdigest()
                for role, payload in data_payloads.items()
            },
        )
    payloads = {
        f"{kind}_build_manifest": canonical_json_bytes(
            manifest.model_dump(mode="json")
        ),
        **data_payloads,
    }
    paths = {}
    for role, payload in payloads.items():
        path = build_root / kind / f"{role}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        paths[role] = path
    return factory.fixed_layout(
        artifact_kind=kind,
        builder_input=builder_input,
        member_paths=paths,
        member_media_types={role: "application/json" for role in paths},
        ids=ids,
        source_lineage=(),
    )


def _graph_draft(
    factory,
    *,
    builder_input: DerivedArtifactBuilderInputV2,
    ids,
    build_root: Path,
    artifact,
    graph_candidates,
    authority_records,
):
    graph_bytes = canonical_graph_bytes(graph_payload(artifact))
    projection_bytes = _projection_bytes(artifact)
    projection_nodes = sorted(
        str(node)
        for node in GraphifyProjectionAdapter(seed=42).project(artifact).nodes
    )
    annotations_bytes = canonical_json_bytes({"0": projection_nodes})
    graph_ref = VersionRef(
        object_id=ids.member_object_ids["global_graph"],
        version=5,
        content_sha256=hashlib.sha256(graph_bytes).hexdigest(),
    )
    mapping = build_expected_graph_edge_mapping(
        artifact,
        builder_input=builder_input,
        candidates=graph_candidates,
        authority_records=authority_records,
    )
    catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=graph_ref,
        target_runtime_epoch=1,
        builder_input_sha256=builder_input.canonical_sha256,
        retrieval_input_descriptor_sha256=(
            builder_input.retrieval_input_descriptor.descriptor_sha256
        ),
        assigned_input_set_sha256=(
            builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                "graph"
            )
        ),
        edge_mapping=mapping,
        records=authority_records,
    )
    catalog_bytes = canonical_json_bytes(catalog.model_dump(mode="json"))
    builder_bytes = canonical_json_bytes(builder_input.model_dump(mode="json"))

    def member_ref(role: str, payload: bytes) -> VersionRef:
        return VersionRef(
            object_id=ids.member_object_ids[role],
            version=5,
            content_sha256=hashlib.sha256(payload).hexdigest(),
        )

    manifest = GraphBuildManifestPayload.create(
        builder_input_ref=member_ref("graph_builder_input", builder_bytes),
        graph_ref=graph_ref,
        edge_authority_catalog_ref=member_ref(
            "graph_edge_authority_catalog", catalog_bytes
        ),
        graphify_projection_ref=member_ref(
            "graphify_projection", projection_bytes
        ),
        graph_community_annotations_ref=member_ref(
            "graph_community_annotations", annotations_bytes
        ),
        target_runtime_epoch=1,
        source_catalog_version=5,
        builder_input_sha256=builder_input.canonical_sha256,
        edge_authority_catalog_sha256=catalog.catalog_sha256,
        retrieval_input_descriptor_sha256=(
            builder_input.retrieval_input_descriptor.descriptor_sha256
        ),
        assigned_input_set_sha256=(
            builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                "graph"
            )
        ),
        expected_row_mapping_sha256=(
            builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                "graph"
            )
        ),
        edge_mapping_sha256=mapping.mapping_sha256,
        node_count=artifact.graph.number_of_nodes(),
        edge_count=artifact.graph.number_of_edges(),
        candidate_count=len(graph_candidates),
    )
    payloads = {
        "graph_build_manifest": canonical_json_bytes(
            manifest.model_dump(mode="json")
        ),
        "global_graph": graph_bytes,
        "graph_edge_authority_catalog": catalog_bytes,
        "graphify_projection": projection_bytes,
        "graph_community_annotations": annotations_bytes,
    }
    paths = {}
    for role, payload in payloads.items():
        path = build_root / "graph" / f"{role}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        paths[role] = path
    return factory.fixed_layout(
        artifact_kind="graph",
        builder_input=builder_input,
        member_paths=paths,
        member_media_types={role: "application/json" for role in paths},
        ids=ids,
        source_lineage=(),
    )


def test_real_active_cas_discovery_binds_retrievers_and_detects_empty_drift(
    tmp_path: Path,
) -> None:
    publication_module, discovery_module = _modules()
    lexical_candidate = candidate(
        130,
        text="active exact text",
        channel="lexical",
    )
    vector_candidate = lexical_candidate.model_copy(update={"channel": "vector"})
    graph_artifact, _old_input, graph_candidates, old_catalog, _old_manifest = (
        graph_closure(runtime_epoch=1)
    )
    wiki_revision = _synthetic_wiki_revision(graph_candidates)
    registry_ids = _ids(publication_module, "knowledge_registry", 1700)
    route_policy_payload = canonical_json_bytes(
        {"contract": "retrieval_route_policy_v1"}
    )
    route_policy_ref = VersionRef(
        object_id=registry_ids.member_object_ids["retrieval_route_policy"],
        version=5,
        content_sha256=hashlib.sha256(route_policy_payload).hexdigest(),
    )
    builder_input = _builder_inputs(
        lexical_candidate,
        graph_candidates,
        route_policy_ref,
        wiki_revision,
    )
    lexical_input = builder_input("lexical")
    vector_input = builder_input("vector")
    build_root = tmp_path / "build"
    lexical_path = build_root / "lexical.sqlite3"
    lexical_manifest = LexicalIndexBuilder().build(
        (LexicalDocument(candidate=lexical_candidate, text="active exact text"),),
        lexical_path,
        builder_input=lexical_input,
    )
    embedder = DeterministicFakeEmbedder(
        model_descriptor(query_prompt="", document_prompt=""),
        {
            "active exact text": np.asarray([1.0, 0.0], dtype=np.float32),
            "query": np.asarray([1.0, 0.0], dtype=np.float32),
        },
    )
    vector_path = build_root / "vector"
    vector_manifest = ExactVectorIndexBuilder(embedder).build(
        (VectorDocument(candidate=vector_candidate, text="active exact text"),),
        vector_path,
        builder_input=vector_input,
    )
    factory = publication_module.RetrievalArtifactDraftFactory(build_root)
    lexical = factory.lexical(
        builder_input=lexical_input,
        build_manifest=lexical_manifest,
        index_path=lexical_path,
        ids=_ids(publication_module, "lexical", 1300),
        source_lineage=(),
    )
    vector = factory.vector(
        builder_input=vector_input,
        build_manifest=vector_manifest,
        vector_directory=vector_path,
        ids=_ids(publication_module, "vector", 1400),
        source_lineage=(),
    )
    graph = _graph_draft(
        factory,
        builder_input=builder_input("graph"),
        ids=_ids(publication_module, "graph", 1500),
        build_root=build_root,
        artifact=graph_artifact,
        graph_candidates=graph_candidates,
        authority_records=old_catalog.records,
    )
    wiki = _projection_draft(
        factory,
        kind="wiki_index",
        builder_input=builder_input("wiki_index"),
        ids=_ids(publication_module, "wiki_index", 1600),
        build_root=build_root,
        route_policy_payload=route_policy_payload,
        wiki_revision=wiki_revision,
        wiki_candidates=graph_candidates,
    )
    registry = _projection_draft(
        factory,
        kind="knowledge_registry",
        builder_input=builder_input("knowledge_registry"),
        ids=registry_ids,
        build_root=build_root,
        route_policy_payload=route_policy_payload,
    )

    approval_root = tmp_path / "approval"
    approval_root.mkdir()
    harness = build_approval_harness(approval_root)
    vault_root = tmp_path / "vault"
    cas_root = vault_root / "global"
    cas_root.mkdir(parents=True)
    store = ContentStore(cas_root)
    coordinator = PublishCoordinator(
        harness.target_connection,
        store,
        VisibilityGuard(
            TombstoneRepository(
                harness.target_connection,
                clock=FixedClock(harness.clock.now()),
            )
        ),
        clock=FixedClock(harness.clock.now()),
    )
    artifacts = (wiki, registry, lexical, vector, graph)
    staged = coordinator.stage_artifacts(purpose="rebuild", artifacts=artifacts)
    closure = publication_closure_sha256(
        purpose="rebuild",
        authority_base_version=5,
        expected_current_epoch=None,
        artifacts=artifacts,
    )
    descriptor = DraftDescriptor(
        purpose="rebuild",
        target_id="global-retrieval",
        base_version=4,
        draft_sha256=closure,
    )
    request = harness.service.request(
        descriptor,
        diff_object_ref=harness.diff_object_ref(),
    )
    harness.service.confirm(
        harness.signer.confirm(harness.service.challenge_for_review(request.request_id))
    )
    operation_id = harness.operation_id()
    ticket = harness.service.issue_for_execution(
        request.request_id,
        descriptor,
        operation_id=operation_id,
    )
    proof = harness.guard.apply_in_transaction(
        ticket,
        descriptor,
        lambda _connection: coordinator.prepare(
            operation_id=operation_id,
            purpose="rebuild",
            authority_base_version=5,
            approval_request_id=request.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            expected_current_epoch=None,
            artifacts=staged,
        ),
    )
    harness.service.acknowledge(proof)
    coordinator.verify(operation_id)
    active = coordinator.activate(operation_id)
    assert active.runtime_epoch == 1
    manifests = ManifestRepository(harness.target_connection)

    def root(kind: str) -> VersionRef:
        manifest = manifests.get_active(kind, epoch=1)
        return VersionRef(
            object_id=manifest.manifest_id,
            version=manifest.source_version,
            content_sha256=manifest.manifest_sha256,
        )

    roots = RootManifestSet(
        catalog_version=5,
        wiki_manifest_ref=root("wiki_index"),
        lexical_manifest_ref=root("lexical"),
        vector_manifest_ref=root("vector"),
        graph_manifest_ref=root("graph"),
    )
    authority_snapshot = AuthoritativeFilterSnapshot(
        run_id=harness.ids.uuid7(),
        global_runtime_epoch=1,
        client_runtime_epoch=0,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset({lexical_candidate.reference.object_id}),
        policy_ref=VersionRef(
            object_id=harness.ids.object_id("authority_policy"),
            version=1,
            content_sha256="a" * 64,
        ),
        created_at=harness.clock.now(),
    )
    discovery = discovery_module.ActiveRetrievalArtifactDiscovery(
        harness.target_connection,
        store,
    )
    discovered = discovery.discover_indexes(authority_snapshot, roots)

    # The Doctor composition root must rediscover this exact closure from the
    # fixed global DB/CAS paths; it cannot be handed the build paths above.
    with sqlite3.connect(cas_root / "catalog.sqlite3") as doctor_database:
        harness.target_connection.backup(doctor_database)
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / ".git").mkdir()
    doctor_check = RetrievalArtifactDiagnosticProbe().run(
        AppConfig.from_values(repo_root, vault_root)
    )
    assert doctor_check.status == "pass"
    assert doctor_check.code == "retrieval_artifacts_verified"
    assert doctor_check.observed_count == 5

    assert discovered.lexical.identity.root_ref == roots.lexical_manifest_ref
    assert discovered.vector.identity.root_ref == roots.vector_manifest_ref
    assert discovered.knowledge_registry.identity.root_ref == root(
        "knowledge_registry"
    )
    assert discovered.lexical.path_for("lexical_index") != lexical_path
    assert discovered.vector.path_for("vector_shard") != vector_path / "vectors.npy"
    lexical_retriever = LexicalRetriever.from_artifact_binding(discovered.lexical)
    vector_retriever = ExactVectorRetriever.from_artifact_binding(
        discovered.vector,
        embedder=embedder,
    )
    publication_module.require_retriever_artifact_binding(
        lexical_retriever,
        discovered.lexical,
    )

    class BoundRoute:
        def __init__(self, binding) -> None:
            self.artifact_binding = binding

        def search(self, query, route_scope, route_snapshot, *, limit):
            del query, route_scope, route_snapshot, limit
            return ()

    class BoundCaseRoute:
        def __init__(self, lexical_binding, vector_binding) -> None:
            self.artifact_bindings = {
                "lexical": lexical_binding,
                "vector": vector_binding,
            }

        def search(self, query, route_scope, route_snapshot, *, limit):
            del query, route_scope, route_snapshot, limit
            return ()

    gate = discovery_module.ActiveRetrievalArtifactGate(discovery)
    routes = {
        "wiki": BoundRoute(discovered.wiki_index),
        "lexical": lexical_retriever,
        "vector": vector_retriever,
        "global_graph": BoundRoute(discovered.graph),
        "case": BoundCaseRoute(discovered.lexical, discovered.vector),
    }
    gate.verify(
        authority_snapshot,
        roots,
        routes,
        ("case", "global_graph", "lexical", "vector", "wiki"),
    )
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        gate.verify(
            authority_snapshot,
            roots,
            {**routes, "wiki": BoundRoute(discovered.graph)},
            ("wiki",),
        )
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        gate.verify(
            authority_snapshot,
            roots,
            {
                **routes,
                "case": BoundCaseRoute(discovered.lexical, discovered.graph),
            },
            ("case",),
        )
    assert lexical_retriever.search(
        "active",
        scope(),
        authority_snapshot,
        limit=1,
    )
    assert vector_retriever.search(
        "query",
        scope(),
        authority_snapshot,
        limit=1,
    )
    assert lexical_candidate.metadata.manifest_ref != roots.lexical_manifest_ref

    mixed_descriptor = RetrievalInputDescriptor.from_assignments(
        (
            RetrievalInputAssignment.from_candidate(
                lexical_candidate,
                target_channels=frozenset({"lexical", "vector"}),
            ),
        ),
        route_policy_ref=route_policy_ref,
    )
    mixed_wiki_input = builder_input("wiki_index").model_copy(
        update={"retrieval_input_descriptor": mixed_descriptor}
    )

    def discovered_artifact(binding, input_value):
        payloads = {
            member.role: binding.path_for(member.role).read_bytes()
            for member in binding.identity.members
        }
        return discovery_module._DiscoveredArtifact(
            binding=binding,
            builder_input=input_value,
            payloads=payloads,
        )

    mixed = {
        "wiki_index": discovered_artifact(
            discovered.wiki_index, mixed_wiki_input
        ),
        "knowledge_registry": discovered_artifact(
            discovered.knowledge_registry, builder_input("knowledge_registry")
        ),
        "lexical": discovered_artifact(
            discovered.lexical, builder_input("lexical")
        ),
        "vector": discovered_artifact(discovered.vector, builder_input("vector")),
        "graph": discovered_artifact(discovered.graph, builder_input("graph")),
    }
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        discovery_module.ActiveRetrievalArtifactDiscovery._validate_shared_builder_inputs(
            mixed
        )

    harness.target_connection.execute(
        "UPDATE publication_operations SET authority_base_version = 6 "
        "WHERE operation_id = ?",
        (operation_id,),
    )
    harness.target_connection.commit()
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        discovery.discover_current_set()
    harness.target_connection.execute(
        "UPDATE publication_operations SET authority_base_version = 5 "
        "WHERE operation_id = ?",
        (operation_id,),
    )
    harness.target_connection.commit()
    assert discovery.discover_current_set() is not None

    unrelated = tmp_path / "unrelated.sqlite3"
    LexicalIndexBuilder().build(
        (LexicalDocument(candidate=lexical_candidate, text="active exact text"),),
        unrelated,
        builder_input=lexical_input,
    )
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        publication_module.require_retriever_artifact_binding(
            LexicalRetriever._from_unbound_path_for_test(unrelated),
            discovered.lexical,
        )

    harness.target_connection.execute(
        "DELETE FROM active_artifacts "
        "WHERE epoch = 1 AND artifact_key = 'knowledge_registry'"
    )
    harness.target_connection.commit()
    with pytest.raises(RuntimeError, match="ARTIFACT_VERSION_MISMATCH"):
        discovery.discover_current_set()

    discovered.lexical.path_for("lexical_index").write_bytes(b"drift")
    with pytest.raises(LexicalIndexError, match="ARTIFACT_VERSION_MISMATCH"):
        lexical_retriever.search("active", scope(), snapshot(), limit=1)
    harness.close()
