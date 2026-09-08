from __future__ import annotations

import json
from pathlib import Path

import pytest

from consultation_kb.knowledge.publication import KnowledgePublicationError
from consultation_kb.graph.artifact_contracts import GraphEdgeAuthorityCatalogPayload
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import RetrievalScope
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
)
from consultation_kb.retrieval.authority_snapshot import (
    AuthoritativeSnapshotRepository,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
    prepare_successor_knowledge,
)


_DERIVED_KINDS = frozenset(
    {"wiki_index", "knowledge_registry", "graph", "lexical", "vector"}
)


def _builder_inputs(
    harness: GlobalKnowledgeHarness,
    operation_id: str,
) -> dict[str, DerivedArtifactBuilderInputV2]:
    rows = harness.connection.execute(
        """
        SELECT manifests.artifact_kind,
               members.object_sha256,
               members.size_bytes,
               members.media_type
          FROM artifact_manifests AS manifests
          JOIN artifact_members AS members
            ON members.manifest_id = manifests.manifest_id
         WHERE manifests.operation_id = ?
           AND members.object_type = manifests.artifact_kind || '_builder_input'
         ORDER BY manifests.artifact_kind
        """,
        (operation_id,),
    ).fetchall()
    assert {str(row[0]) for row in rows} == _DERIVED_KINDS
    assert len(rows) == len(_DERIVED_KINDS)

    result: dict[str, DerivedArtifactBuilderInputV2] = {}
    for row in rows:
        payload = harness.store.read_verified(
            harness.store.reference(
                content_sha256=str(row[1]),
                size_bytes=int(row[2]),
                media_type=str(row[3]),
            )
        )
        builder = DerivedArtifactBuilderInputV2.model_validate_json(
            payload,
            strict=True,
        )
        result[str(row[0])] = builder
    return result


def test_five_builders_share_exact_claim_support_descriptor(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            second_claim_multi_support=True,
        )
        publication = prepare_global_publication(harness, knowledge)
        builders = _builder_inputs(harness, publication.operation_id)

        descriptors = [
            builder.retrieval_input_descriptor for builder in builders.values()
        ]
        assert all(descriptor == descriptors[0] for descriptor in descriptors[1:])
        descriptor = descriptors[0]

        support_pairs = {
            (str(row[0]), int(row[1]), str(row[2]), int(row[3]))
            for row in harness.connection.execute(
                """
                SELECT claim_id, claim_version, passage_id, passage_version
                  FROM claim_evidence
                 WHERE relation = 'SUPPORTS'
                """
            )
        }
        descriptor_pairs = {
            (
                record.candidate_ref.object_id,
                record.candidate_ref.version,
                record.content_ref.object_id,
                record.content_ref.version,
            )
            for record in descriptor.records
        }
        assert descriptor_pairs == support_pairs

        second_claim_records = tuple(
            record
            for record in descriptor.records
            if record.candidate_ref.object_id == knowledge.claims[1].claim_id
        )
        assert len(second_claim_records) == 2
        assert len({record.content_ref for record in second_claim_records}) == 2

        wiki_claims = {
            (str(row[0]), int(row[1]))
            for row in harness.connection.execute(
                """
                SELECT claim_id, claim_version
                  FROM wiki_revision_claims
                 WHERE wiki_id = ? AND wiki_revision = ?
                """,
                (knowledge.wiki.wiki_id, knowledge.wiki.revision),
            )
        }
        for record in descriptor.records:
            expected_targets = {"lexical", "vector"}
            if (
                record.candidate_ref.object_id,
                record.candidate_ref.version,
            ) in wiki_claims:
                expected_targets.add("wiki_index")
            assert record.target_channels == expected_targets
            assert "graph" not in record.target_channels

        claims_manifest = harness.connection.execute(
            """
            SELECT manifest_id, source_version, manifest_sha256
              FROM artifact_manifests
             WHERE operation_id = ? AND artifact_kind = 'claims'
            """,
            (publication.operation_id,),
        ).fetchone()
        assert claims_manifest is not None
        expected_manifest_ref = VersionRef(
            object_id=str(claims_manifest[0]),
            version=int(claims_manifest[1]),
            content_sha256=str(claims_manifest[2]),
        )
        assert all(
            record.authority_manifest_ref == expected_manifest_ref
            for record in descriptor.records
        )

        snapshots = [builder.authority_snapshot for builder in builders.values()]
        assert all(snapshot == snapshots[0] for snapshot in snapshots[1:])
        assert snapshots[0].expected_current_epoch is None
        assert snapshots[0].maximum_runtime_epoch == 0
        assert snapshots[0].target_runtime_epoch == 1
    finally:
        harness.close()


def test_no_active_epoch_still_targets_maximum_plus_one(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(harness)
        first_publication = prepare_global_publication(harness, first)
        first_publication.service.publish_theory_and_wiki(
            first_publication.operation_id,
            theory_id=first.theory.theory_id,
            theory_revision=first.theory.revision,
            wiki_id=first.wiki.wiki_id,
            wiki_revision=first.wiki.revision,
        )
        harness.connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE epoch = 1"
        )
        assert harness.connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone() is None

        second = prepare_successor_knowledge(harness, first)
        second_publication = prepare_global_publication(
            harness,
            second,
            authority_base_version=2,
            expected_current_epoch=None,
        )
        snapshots = {
            builder.authority_snapshot
            for builder in _builder_inputs(
                harness,
                second_publication.operation_id,
            ).values()
        }
        assert len(snapshots) == 1
        snapshot = snapshots.pop()
        assert snapshot.expected_current_epoch is None
        assert snapshot.maximum_runtime_epoch == 1
        assert snapshot.target_runtime_epoch == 2
    finally:
        harness.close()


def test_publication_rejects_lexical_index_missing_second_support_passage(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            second_claim_multi_support=True,
        )
        publication = prepare_global_publication(
            harness,
            knowledge,
            drop_lexical_support_row=True,
        )

        with pytest.raises(KnowledgePublicationError) as exc_info:
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert exc_info.value.code == "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
        assert harness.connection.execute(
            "SELECT epoch FROM runtime_epochs"
        ).fetchall() == []
    finally:
        harness.close()


def test_nonempty_graph_publication_routes_only_declared_claim_supports(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        assert len(knowledge.wiki.graph_relations) == 1
        declaration = knowledge.wiki.graph_relations[0]
        publication = prepare_global_publication(harness, knowledge)
        graph_builder = _builder_inputs(
            harness,
            publication.operation_id,
        )["graph"]

        graph_records = graph_builder.retrieval_input_descriptor.assigned_records(
            "graph"
        )
        support_refs = {
            (str(row[0]), int(row[1]), str(row[2]), int(row[3]))
            for row in harness.connection.execute(
                """
                SELECT claim_id, claim_version, passage_id, passage_version
                  FROM claim_evidence
                 WHERE claim_id = ? AND claim_version = ?
                   AND relation = 'SUPPORTS'
                """,
                (declaration.claim_ref.object_id, declaration.claim_ref.version),
            )
        }
        assert {
            (
                record.candidate_ref.object_id,
                record.candidate_ref.version,
                record.content_ref.object_id,
                record.content_ref.version,
            )
            for record in graph_records
        } == support_refs
        assert all(
            record.candidate_ref == declaration.claim_ref
            and record.target_channels == {"graph", "lexical", "vector", "wiki_index"}
            for record in graph_records
        )

        active = publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        assert active.runtime_epoch == 1
        graph_payload = harness.store.read_hash_verified(
            str(
                harness.connection.execute(
                    """
                    SELECT members.object_sha256
                      FROM artifact_manifests AS manifests
                      JOIN artifact_members AS members
                        ON members.manifest_id = manifests.manifest_id
                     WHERE manifests.operation_id = ?
                       AND manifests.artifact_kind = 'graph'
                       AND members.object_type = 'global_graph'
                    """,
                    (publication.operation_id,),
                ).fetchone()[0]
            )
        )
        assert b'"edges":[{' in graph_payload
        assert b'"nodes":[{' in graph_payload
    finally:
        harness.close()


def test_self_consistent_graph_cannot_impersonate_wiki_relation_scope(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        publication = prepare_global_publication(
            harness,
            knowledge,
            forge_graph_relation_scope=True,
        )

        with pytest.raises(KnowledgePublicationError) as exc_info:
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert exc_info.value.code == "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
        assert harness.connection.execute(
            "SELECT epoch FROM runtime_epochs"
        ).fetchall() == []
    finally:
        harness.close()


def test_active_graph_nested_authority_is_visible_without_expanding_to_nodes(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        publication = prepare_global_publication(harness, knowledge)
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        graph_members = {
            str(row[0]): str(row[1])
            for row in harness.connection.execute(
                """
                SELECT members.object_type, members.object_sha256
                  FROM artifact_manifests AS manifests
                  JOIN artifact_members AS members
                    ON members.manifest_id = manifests.manifest_id
                 WHERE manifests.operation_id = ?
                   AND manifests.artifact_kind = 'graph'
                """,
                (publication.operation_id,),
            )
        }
        graph_payload = json.loads(
            harness.store.read_hash_verified(graph_members["global_graph"])
        )
        catalog = GraphEdgeAuthorityCatalogPayload.model_validate_json(
            harness.store.read_hash_verified(
                graph_members["graph_edge_authority_catalog"]
            ),
            strict=True,
        )
        relation_ids = {
            str(edge["attributes"]["relation_ref"]["object_id"])
            for edge in graph_payload["edges"]
        }
        passage_ids = {
            str(reference["object_id"])
            for edge in graph_payload["edges"]
            for reference in edge["attributes"]["passage_refs"]
        }
        authority_ids = {record.authority_ref.object_id for record in catalog.records}
        node_ids = {str(node["node_id"]) for node in graph_payload["nodes"]}
        unrouted_passage_ids = {
            str(row[0])
            for row in harness.connection.execute("SELECT passage_id FROM passages")
        } - passage_ids
        assert unrouted_passage_ids

        client_path = tmp_path / "client.sqlite3"
        client_connection = connect_database(client_path, mode="writer")
        try:
            MigrationRunner.for_scope(client_connection, "client").apply()
        finally:
            client_connection.close()
        policy_ref = VersionRef(
            object_id=harness.ids.object_id("authority_policy"),
            version=1,
            content_sha256="c" * 64,
        )
        with AuthoritativeSnapshotRepository.open(
            harness.root / "global.sqlite3",
            client_path,
            policy_ref_provider=lambda: policy_ref,
            clock=harness.clock,
            id_factory=harness.ids,
            global_content_store=harness.store,
        ) as repository:
            now = harness.clock.now()
            snapshot = repository.freeze(
                RetrievalScope(
                    current_client_id="client_" + "a" * 12,
                    allowed_uses=frozenset({"consultation"}),
                    maximum_sensitivity=1,
                    effective_at=now,
                    known_at=now,
                )
            )

        assert relation_ids | passage_ids | authority_ids <= snapshot.allowed_ref_ids
        assert node_ids.isdisjoint(snapshot.allowed_ref_ids)
        assert unrouted_passage_ids.isdisjoint(snapshot.allowed_ref_ids)
        assert harness.ids.object_id("graph_edge") not in snapshot.allowed_ref_ids
    finally:
        harness.close()


def test_publication_rejects_valid_wiki_object_ref_with_stale_body_hash(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)

        def replace_wiki_object_ref(phase: str) -> None:
            if phase != "closure_verified":
                return
            row = harness.connection.execute(
                "SELECT body_object_ref, body_object_size_bytes, "
                "body_object_media_type FROM wiki_revisions "
                "WHERE wiki_id = ? AND revision = ?",
                (knowledge.wiki.wiki_id, knowledge.wiki.revision),
            ).fetchone()
            assert row is not None
            original = harness.store.read_verified(
                harness.store.reference(
                    content_sha256=str(row[0])[7:],
                    size_bytes=int(row[1]),
                    media_type=str(row[2]),
                )
            )
            body = json.loads(original)
            replacement_title = f"{body['title']} replacement"
            body["title"] = replacement_title
            replacement = json.dumps(
                body,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            reference = harness.store.finalize(
                harness.store.stage_bytes(
                    replacement,
                    purpose="wiki_body_negative_test",
                    manifest_id=knowledge.wiki.wiki_id,
                    media_type="application/json",
                )
            )
            harness.connection.execute(
                "UPDATE wiki_revisions SET title = ?, body_object_ref = ?, "
                "body_object_size_bytes = ?, body_object_media_type = ? "
                "WHERE wiki_id = ? AND revision = ?",
                (
                    replacement_title,
                    f"sha256:{reference.content_sha256}",
                    reference.size_bytes,
                    reference.media_type,
                    knowledge.wiki.wiki_id,
                    knowledge.wiki.revision,
                ),
            )

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=replace_wiki_object_ref,
        )
        with pytest.raises(KnowledgePublicationError) as exc_info:
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert exc_info.value.code == "KNOWLEDGE_WIKI_BODY_HASH_MISMATCH"
        assert harness.connection.execute(
            "SELECT epoch FROM runtime_epochs"
        ).fetchall() == []
    finally:
        harness.close()


def test_publication_rejects_stale_theory_redundant_revision_hash(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)

        def replace_theory_revision_hash(phase: str) -> None:
            if phase == "closure_verified":
                harness.connection.execute(
                    "UPDATE theory_revisions SET revision_sha256 = ? "
                    "WHERE theory_id = ? AND revision = ?",
                    (
                        "f" * 64,
                        knowledge.theory.theory_id,
                        knowledge.theory.revision,
                    ),
                )

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=replace_theory_revision_hash,
        )
        with pytest.raises(KnowledgePublicationError) as exc_info:
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert exc_info.value.code == "KNOWLEDGE_THEORY_REVISION_HASH_MISMATCH"
        assert harness.connection.execute(
            "SELECT epoch FROM runtime_epochs"
        ).fetchall() == []
    finally:
        harness.close()
