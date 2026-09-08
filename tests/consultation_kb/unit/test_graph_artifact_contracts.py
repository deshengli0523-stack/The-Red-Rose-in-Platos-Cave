from __future__ import annotations

import hashlib

import networkx as nx
import pytest

from consultation_kb.graph.artifact_contracts import (
    GraphBuildClosureError,
    GraphBuildManifestPayload,
    GraphEdgeAuthorityCatalogPayload,
    GraphEdgeMapping,
    GraphRelationAuthorityLink,
    build_expected_graph_edge_mapping,
    verify_graph_build_closure,
    verify_graph_member_payloads,
)
from consultation_kb.graph.graphify_adapter import GraphifyProjectionAdapter
from consultation_kb.graph.serialization import (
    canonical_graph_bytes,
    graph_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.retrieval.artifact_contracts import ArtifactMemberIdentity
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.retrieval.contracts import canonical_json_bytes
from tests.consultation_kb.graph_support import global_graph_artifact, ref
from tests.consultation_kb.retrieval_support import (
    candidate,
    derived_builder_input,
)
from tests.consultation_kb.unit.test_graph_edge_authority import (
    _artifact,
    _edge,
    _record,
)


def _version_ref(kind: str, digit: str, *, version: int, sha256: str) -> VersionRef:
    return ref(kind, digit).model_copy(
        update={"version": version, "content_sha256": sha256}
    )


def _graph_candidate(
    *,
    claim_ref: VersionRef,
    passage_ref: VersionRef,
    source_ref: VersionRef,
    index: int,
) -> CandidateRef:
    raw = candidate(
        index,
        channel="global_graph",
        object_type="claim",
        allowed_uses=frozenset({"consultation"}),
    )
    return raw.model_copy(
        update={
            "reference": claim_ref,
            "content_ref": passage_ref,
            "provenance": raw.provenance.model_copy(
                update={
                    "source_ids": frozenset({source_ref.object_id}),
                    "passage_ids": frozenset({passage_ref.object_id}),
                }
            ),
            "location": raw.location.model_copy(
                update={"anchor_refs": (passage_ref,)}
            ),
        }
    )


def _closure(
    *,
    passage_count: int = 1,
    relation_count: int = 1,
    runtime_epoch: int = 7,
):
    primary_ref = ref("graph_edge", "1")
    primary = _edge(primary_ref)
    passage_refs = [primary["passage_refs"][0]]  # type: ignore[index]
    for digit in range(2, passage_count + 1):
        passage_refs.append(ref("passage", str(digit + 6)))
    primary["passage_refs"] = tuple(passage_refs)

    second_ref = None
    second = None
    if relation_count == 2:
        second_ref = ref("graph_edge", "8")
        second = _edge(second_ref)
        second.update(
            {
                "claim_ref": primary["claim_ref"],
                "passage_refs": primary["passage_refs"],
                "source_refs": primary["source_refs"],
            }
        )
    artifact = _artifact(primary_ref, primary, second_ref, second)
    if runtime_epoch != artifact.source_runtime_epoch:
        artifact = global_graph_artifact(
            artifact.graph.copy(),
            catalog_version=artifact.source_catalog_version,
            runtime_epoch=runtime_epoch,
            effective_at=artifact.effective_at,
        )
    attributes = next(iter(artifact.graph.edges(data=True)))[2]
    candidates = tuple(
        _graph_candidate(
            claim_ref=attributes["claim_ref"],
            passage_ref=passage_ref,
            source_ref=attributes["source_refs"][0],
            index=700 + index,
        )
        for index, passage_ref in enumerate(attributes["passage_refs"])
    )
    builder = derived_builder_input(
        "graph",
        *candidates,
        source_catalog_version=artifact.source_catalog_version,
        target_runtime_epoch=artifact.source_runtime_epoch,
    )
    records = [
        _record(
            primary_ref,
            provenance_scope="global_source",
            independent_source_count=1,
            runtime_epoch=runtime_epoch,
        )
    ]
    if second_ref is not None:
        records.append(
            _record(
                second_ref,
                provenance_scope="global_source",
                independent_source_count=1,
                runtime_epoch=runtime_epoch,
            )
        )
    graph_ref = _version_ref(
        "global_graph",
        "a",
        version=artifact.source_catalog_version,
        sha256=artifact.canonical_sha256,
    )
    mapping = build_expected_graph_edge_mapping(
        artifact,
        builder_input=builder,
        candidates=candidates,
        authority_records=tuple(records),
    )
    catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=graph_ref,
        target_runtime_epoch=artifact.source_runtime_epoch,
        builder_input_sha256=builder.canonical_sha256,
        retrieval_input_descriptor_sha256=(
            builder.retrieval_input_descriptor.descriptor_sha256
        ),
        assigned_input_set_sha256=(
            builder.retrieval_input_descriptor.assigned_input_set_sha256(
                "graph"
            )
        ),
        edge_mapping=mapping,
        records=tuple(records),
    )
    manifest = _manifest(
        artifact=artifact,
        builder=builder,
        candidates=candidates,
        graph_ref=graph_ref,
        catalog=catalog,
    )
    return artifact, builder, candidates, catalog, manifest


def _manifest(*, artifact, builder, candidates, graph_ref, catalog):  # type: ignore[no-untyped-def]
    version = artifact.source_catalog_version
    builder_bytes = canonical_json_bytes(builder.model_dump(mode="json"))
    catalog_bytes = canonical_json_bytes(catalog.model_dump(mode="json"))
    return GraphBuildManifestPayload.create(
        builder_input_ref=_version_ref(
            "graph_builder_input",
            "b",
            version=version,
            sha256=hashlib.sha256(builder_bytes).hexdigest(),
        ),
        graph_ref=graph_ref,
        edge_authority_catalog_ref=_version_ref(
            "graph_edge_authority_catalog",
            "c",
            version=version,
            sha256=hashlib.sha256(catalog_bytes).hexdigest(),
        ),
        graphify_projection_ref=_version_ref(
            "graphify_projection",
            "d",
            version=version,
            sha256="d" * 64,
        ),
        graph_community_annotations_ref=_version_ref(
            "graph_community_annotations",
            "e",
            version=version,
            sha256="e" * 64,
        ),
        target_runtime_epoch=artifact.source_runtime_epoch,
        source_catalog_version=artifact.source_catalog_version,
        builder_input_sha256=builder.canonical_sha256,
        edge_authority_catalog_sha256=catalog.catalog_sha256,
        retrieval_input_descriptor_sha256=(
            builder.retrieval_input_descriptor.descriptor_sha256
        ),
        assigned_input_set_sha256=(
            builder.retrieval_input_descriptor.assigned_input_set_sha256(
                "graph"
            )
        ),
        expected_row_mapping_sha256=(
            builder.retrieval_input_descriptor.expected_row_mapping_sha256(
                "graph"
            )
        ),
        edge_mapping_sha256=catalog.edge_mapping.mapping_sha256,
        node_count=artifact.graph.number_of_nodes(),
        edge_count=artifact.graph.number_of_edges(),
        candidate_count=len(candidates),
    )


def _repack_with_mapping(closure, mapping: GraphEdgeMapping):  # type: ignore[no-untyped-def]
    artifact, builder, candidates, catalog, manifest = closure
    changed_catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=catalog.graph_version,
        target_runtime_epoch=catalog.target_runtime_epoch,
        builder_input_sha256=catalog.builder_input_sha256,
        retrieval_input_descriptor_sha256=(
            catalog.retrieval_input_descriptor_sha256
        ),
        assigned_input_set_sha256=catalog.assigned_input_set_sha256,
        edge_mapping=mapping,
        records=catalog.records,
    )
    changed_manifest = _manifest(
        artifact=artifact,
        builder=builder,
        candidates=candidates,
        graph_ref=manifest.graph_ref,
        catalog=changed_catalog,
    )
    return artifact, builder, candidates, changed_catalog, changed_manifest


def _projection_bytes(artifact) -> bytes:  # type: ignore[no-untyped-def]
    projection = GraphifyProjectionAdapter(seed=42).project(artifact)
    payload = {
        "edges": [
            {
                "source": str(source),
                "target": str(target),
                "attributes": dict(sorted(attributes.items())),
            }
            for source, target, attributes in sorted(
                projection.edges(data=True),
                key=lambda item: (str(item[0]), str(item[1])),
            )
        ],
        "nodes": sorted(str(node) for node in projection.nodes),
        "schema_version": "consultation_graphify_projection.v1",
    }
    return canonical_json_bytes(payload)


def _replace_manifest(
    manifest: GraphBuildManifestPayload,
    **updates: object,
) -> GraphBuildManifestPayload:
    values = manifest.model_dump(mode="python", exclude={"manifest_sha256"})
    values.update(updates)
    return GraphBuildManifestPayload.create(**values)


def _member_closure(closure):  # type: ignore[no-untyped-def]
    artifact, builder, _candidates, catalog, manifest = closure
    builder_bytes = canonical_json_bytes(builder.model_dump(mode="json"))
    graph_bytes = canonical_graph_bytes(graph_payload(artifact))
    catalog_bytes = canonical_json_bytes(catalog.model_dump(mode="json"))
    projection_bytes = _projection_bytes(artifact)
    projection_nodes = sorted(
        str(node)
        for node in GraphifyProjectionAdapter(seed=42).project(artifact).nodes
    )
    annotations_bytes = canonical_json_bytes(
        {} if not projection_nodes else {"0": projection_nodes}
    )
    manifest = _replace_manifest(
        manifest,
        graphify_projection_ref=manifest.graphify_projection_ref.model_copy(
            update={
                "content_sha256": hashlib.sha256(projection_bytes).hexdigest()
            }
        ),
        graph_community_annotations_ref=(
            manifest.graph_community_annotations_ref.model_copy(
                update={
                    "content_sha256": hashlib.sha256(
                        annotations_bytes
                    ).hexdigest()
                }
            )
        ),
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
    payloads = {
        "graph_builder_input": builder_bytes,
        "graph_build_manifest": manifest_bytes,
        "global_graph": graph_bytes,
        "graph_edge_authority_catalog": catalog_bytes,
        "graphify_projection": projection_bytes,
        "graph_community_annotations": annotations_bytes,
    }
    object_ids = {
        "graph_builder_input": manifest.builder_input_ref.object_id,
        "graph_build_manifest": ref("graph_build_manifest", "f").object_id,
        "global_graph": manifest.graph_ref.object_id,
        "graph_edge_authority_catalog": (
            manifest.edge_authority_catalog_ref.object_id
        ),
        "graphify_projection": manifest.graphify_projection_ref.object_id,
        "graph_community_annotations": (
            manifest.graph_community_annotations_ref.object_id
        ),
    }
    members = tuple(
        ArtifactMemberIdentity(
            role=role,
            object_id=object_ids[role],
            content_sha256=hashlib.sha256(payloads[role]).hexdigest(),
            media_type="application/json",
            size_bytes=len(payloads[role]),
        )
        for role in (
            "graph_builder_input",
            "graph_build_manifest",
            "global_graph",
            "graph_edge_authority_catalog",
            "graphify_projection",
            "graph_community_annotations",
        )
    )
    return payloads, members, manifest


def test_graph_build_closure_binds_every_exact_pair_and_authority() -> None:
    artifact, builder, candidates, catalog, manifest = _closure(
        passage_count=2,
        relation_count=2,
    )

    mapping = verify_graph_build_closure(
        artifact,
        builder_input=builder,
        candidates=candidates,
        authority_catalog=catalog,
        build_manifest=manifest,
    )

    assert len(mapping.rows) == 2
    assert all(len(row.relation_links) == 2 for row in mapping.rows)
    assert manifest.edge_mapping_sha256 == catalog.edge_mapping.mapping_sha256


def test_legitimate_empty_graph_closes_all_zero_sided_contracts() -> None:
    artifact = global_graph_artifact(
        nx.MultiDiGraph(),
        catalog_version=5,
        runtime_epoch=1,
    )
    unrelated = candidate(999, channel="lexical")
    builder = derived_builder_input(
        "lexical",
        unrelated,
        source_catalog_version=artifact.source_catalog_version,
        target_runtime_epoch=artifact.source_runtime_epoch,
    ).model_copy(update={"artifact_kind": "graph"})
    mapping = build_expected_graph_edge_mapping(
        artifact,
        builder_input=builder,
        candidates=(),
        authority_records=(),
    )
    graph_ref = _version_ref(
        "global_graph",
        "0",
        version=artifact.source_catalog_version,
        sha256=artifact.canonical_sha256,
    )
    catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=graph_ref,
        target_runtime_epoch=artifact.source_runtime_epoch,
        builder_input_sha256=builder.canonical_sha256,
        retrieval_input_descriptor_sha256=(
            builder.retrieval_input_descriptor.descriptor_sha256
        ),
        assigned_input_set_sha256=(
            builder.retrieval_input_descriptor.assigned_input_set_sha256(
                "graph"
            )
        ),
        edge_mapping=mapping,
        records=(),
    )
    manifest = _manifest(
        artifact=artifact,
        builder=builder,
        candidates=(),
        graph_ref=graph_ref,
        catalog=catalog,
    )

    assert verify_graph_build_closure(
        artifact,
        builder_input=builder,
        candidates=(),
        authority_catalog=catalog,
        build_manifest=manifest,
    ).rows == ()
    payloads, members, _bound_manifest = _member_closure(
        (artifact, builder, (), catalog, manifest)
    )
    assert verify_graph_member_payloads(payloads, members=members).rows == ()


def test_six_cas_members_verify_without_external_candidate_objects() -> None:
    closure = _closure(passage_count=2, relation_count=2)
    payloads, members, _manifest_value = _member_closure(closure)

    mapping = verify_graph_member_payloads(payloads, members=members)

    assert mapping == closure[3].edge_mapping


def test_rehashed_projection_substitution_fails_member_semantics() -> None:
    closure = _closure()
    payloads, members, manifest = _member_closure(closure)
    forged_projection = canonical_json_bytes(
        {
            "edges": [],
            "nodes": [],
            "schema_version": "consultation_graphify_projection.v1",
        }
    )
    manifest = _replace_manifest(
        manifest,
        graphify_projection_ref=manifest.graphify_projection_ref.model_copy(
            update={
                "content_sha256": hashlib.sha256(
                    forged_projection
                ).hexdigest()
            }
        ),
    )
    payloads["graphify_projection"] = forged_projection
    payloads["graph_build_manifest"] = canonical_json_bytes(
        manifest.model_dump(mode="json")
    )
    identities = {member.role: member for member in members}
    changed_members = tuple(
        identities[role].model_copy(
            update={
                "content_sha256": hashlib.sha256(payloads[role]).hexdigest(),
                "size_bytes": len(payloads[role]),
            }
        )
        for role in payloads
    )

    with pytest.raises(
        GraphBuildClosureError,
        match="GRAPH_BUILD_PROJECTION_INVALID",
    ):
        verify_graph_member_payloads(payloads, members=changed_members)


def test_rehashed_catalog_cannot_omit_one_claim_passage_pair() -> None:
    closure = _closure(passage_count=2)
    original_mapping = closure[3].edge_mapping
    changed_mapping = GraphEdgeMapping.create(original_mapping.rows[:1])
    artifact, builder, candidates, catalog, manifest = _repack_with_mapping(
        closure,
        changed_mapping,
    )

    with pytest.raises(
        GraphBuildClosureError,
        match="GRAPH_BUILD_CLOSURE_MISMATCH",
    ):
        verify_graph_build_closure(
            artifact,
            builder_input=builder,
            candidates=candidates,
            authority_catalog=catalog,
            build_manifest=manifest,
        )


def test_rehashed_catalog_cannot_substitute_an_unrelated_relation() -> None:
    closure = _closure()
    row = closure[3].edge_mapping.rows[0]
    link = row.relation_links[0]
    forged_link = GraphRelationAuthorityLink(
        relation_ref=ref("graph_edge", "f"),
        authority_ref=link.authority_ref,
    )
    changed_mapping = GraphEdgeMapping.create(
        (row.model_copy(update={"relation_links": (forged_link,)}),)
    )
    artifact, builder, candidates, catalog, manifest = _repack_with_mapping(
        closure,
        changed_mapping,
    )

    with pytest.raises(
        GraphBuildClosureError,
        match="GRAPH_BUILD_CLOSURE_MISMATCH",
    ):
        verify_graph_build_closure(
            artifact,
            builder_input=builder,
            candidates=candidates,
            authority_catalog=catalog,
            build_manifest=manifest,
        )


def test_authority_catalog_cannot_reference_build_manifest_backwards() -> None:
    catalog = _closure()[3]
    payload = catalog.model_dump(mode="json")
    payload["build_manifest_ref"] = ref("graph_build_manifest", "f").model_dump(
        mode="json"
    )

    with pytest.raises(ValueError, match="extra_forbidden"):
        GraphEdgeAuthorityCatalogPayload.model_validate(payload)


def test_rehashed_catalog_cannot_omit_an_artifact_edge_authority() -> None:
    artifact, builder, candidates, catalog, manifest = _closure(
        relation_count=2
    )
    changed_catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=catalog.graph_version,
        target_runtime_epoch=catalog.target_runtime_epoch,
        builder_input_sha256=catalog.builder_input_sha256,
        retrieval_input_descriptor_sha256=(
            catalog.retrieval_input_descriptor_sha256
        ),
        assigned_input_set_sha256=catalog.assigned_input_set_sha256,
        edge_mapping=catalog.edge_mapping,
        records=catalog.records[:1],
    )
    changed_manifest = _manifest(
        artifact=artifact,
        builder=builder,
        candidates=candidates,
        graph_ref=manifest.graph_ref,
        catalog=changed_catalog,
    )

    with pytest.raises(
        GraphBuildClosureError,
        match="GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH",
    ):
        verify_graph_build_closure(
            artifact,
            builder_input=builder,
            candidates=candidates,
            authority_catalog=changed_catalog,
            build_manifest=changed_manifest,
        )
