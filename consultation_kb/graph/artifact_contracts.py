"""Acyclic, semantically verified publication closure for global graphs.

The protected edge-authority catalog embeds the exact Claim+Passage to graph
relation mapping.  The public build manifest points to that catalog; the
catalog deliberately has no build-manifest field, so their content hashes
cannot form a cycle.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Literal

from pydantic import field_validator, model_validator

from consultation_kb.graph.authority_filter import GraphEdgeAuthorityRecord
from consultation_kb.graph.global_builder import (
    GlobalGraphArtifact,
    ref_key,
    verify_global_graph_artifact,
)
from consultation_kb.graph.serialization import canonical_graph_bytes
from consultation_kb.models.common import (
    NonNegativeInt,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.retrieval.artifact_contracts import (
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    RetrievalInputRecord,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.contracts import CandidateRef, canonical_json_bytes


PairKey = tuple[str, int, str, str, int, str]


class GraphBuildClosureError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _kind(reference: VersionRef) -> str:
    return reference.object_id.rsplit("_", maxsplit=1)[0]


def _pair_key(candidate_ref: VersionRef, content_ref: VersionRef) -> PairKey:
    return (*ref_key(candidate_ref), *ref_key(content_ref))


def _json_ready(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_ready(item) for item in value]
    if isinstance(value, set | frozenset):
        normalized = [_json_ready(item) for item in value]
        return sorted(normalized, key=canonical_json_bytes)
    return value


def _sha256(payload: object, *, domain: bytes) -> str:
    return hashlib.sha256(
        domain + canonical_json_bytes(_json_ready(payload))
    ).hexdigest()


class GraphRelationAuthorityLink(StrictModel):
    relation_ref: VersionRef
    authority_ref: VersionRef

    @model_validator(mode="after")
    def _exact_kinds(self) -> "GraphRelationAuthorityLink":
        if (
            _kind(self.relation_ref) != "graph_edge"
            or _kind(self.authority_ref) != "graph_edge_authority"
        ):
            raise ValueError("GRAPH_EDGE_MAPPING_LINK_INVALID")
        return self


class GraphCandidateEdgeMappingRow(StrictModel):
    """One retrieval row, uniquely identified by exact Claim+Passage refs."""

    candidate_ref: VersionRef
    content_ref: VersionRef
    authority_manifest_ref: VersionRef
    candidate_authority_sha256: Sha256Hex
    relation_links: tuple[GraphRelationAuthorityLink, ...]

    @model_validator(mode="after")
    def _canonical_row(self) -> "GraphCandidateEdgeMappingRow":
        keys = tuple(ref_key(value.relation_ref) for value in self.relation_links)
        if (
            _kind(self.candidate_ref) != "claim"
            or _kind(self.content_ref) != "passage"
            or not self.relation_links
            or keys != tuple(sorted(set(keys)))
            or len({value.authority_ref for value in self.relation_links})
            != len(self.relation_links)
        ):
            raise ValueError("GRAPH_EDGE_MAPPING_ROW_INVALID")
        return self


class GraphEdgeMapping(StrictModel):
    contract: Literal["graph_edge_mapping_v1"] = "graph_edge_mapping_v1"
    rows: tuple[GraphCandidateEdgeMappingRow, ...]
    mapping_sha256: Sha256Hex

    @field_validator("rows")
    @classmethod
    def _canonical_rows(
        cls,
        value: tuple[GraphCandidateEdgeMappingRow, ...],
    ) -> tuple[GraphCandidateEdgeMappingRow, ...]:
        keys = tuple(
            _pair_key(row.candidate_ref, row.content_ref) for row in value
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("GRAPH_EDGE_MAPPING_ROWS_INVALID")
        return value

    @model_validator(mode="after")
    def _verify_hash(self) -> "GraphEdgeMapping":
        expected = self._hash_rows(self.rows)
        if self.mapping_sha256 != expected:
            raise ValueError("GRAPH_EDGE_MAPPING_HASH_MISMATCH")
        return self

    @classmethod
    def _hash_rows(
        cls,
        rows: tuple[GraphCandidateEdgeMappingRow, ...],
    ) -> str:
        return _sha256(
            {
                "contract": "graph_edge_mapping_v1",
                "rows": [row.model_dump(mode="json") for row in rows],
            },
            domain=b"consultation-kb-graph-edge-mapping-v1\0",
        )

    @classmethod
    def create(
        cls,
        rows: Iterable[GraphCandidateEdgeMappingRow],
    ) -> "GraphEdgeMapping":
        canonical = tuple(
            sorted(
                (
                    GraphCandidateEdgeMappingRow.model_validate(value)
                    for value in rows
                ),
                key=lambda row: _pair_key(row.candidate_ref, row.content_ref),
            )
        )
        return cls(rows=canonical, mapping_sha256=cls._hash_rows(canonical))


def _authority_record_payload(
    record: GraphEdgeAuthorityRecord,
) -> dict[str, object]:
    return {
        "authority_ref": record.authority_ref.model_dump(mode="json"),
        "contributor_client_ids": sorted(record.contributor_client_ids),
        "excluded_client_ids": sorted(record.excluded_client_ids),
        "independent_source_count": record.independent_source_count,
        "leave_one_out_grants": [
            value.model_dump(mode="json") for value in record.leave_one_out_grants
        ],
        "leave_one_out_parent_ref": (
            None
            if record.leave_one_out_parent_ref is None
            else record.leave_one_out_parent_ref.model_dump(mode="json")
        ),
        "minimum_leave_one_out_sources": record.minimum_leave_one_out_sources,
        "provenance_scope": record.provenance_scope,
        "relation_ref": record.relation_ref.model_dump(mode="json"),
        "runtime_epoch": record.runtime_epoch,
    }


class GraphEdgeAuthorityCatalogPayload(StrictModel):
    """Protected member.  It never references the public build manifest."""

    contract: Literal["graph_edge_authority_catalog_v1"] = (
        "graph_edge_authority_catalog_v1"
    )
    graph_version: VersionRef
    target_runtime_epoch: PositiveInt
    builder_input_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    edge_mapping: GraphEdgeMapping
    records: tuple[GraphEdgeAuthorityRecord, ...]
    catalog_sha256: Sha256Hex

    @field_validator("records")
    @classmethod
    def _canonical_records(
        cls,
        value: tuple[GraphEdgeAuthorityRecord, ...],
    ) -> tuple[GraphEdgeAuthorityRecord, ...]:
        keys = tuple(ref_key(record.relation_ref) for record in value)
        authorities = tuple(record.authority_ref for record in value)
        if (
            keys != tuple(sorted(set(keys)))
            or len(authorities) != len(set(authorities))
        ):
            raise ValueError("GRAPH_EDGE_AUTHORITY_CATALOG_RECORDS_INVALID")
        return value

    @model_validator(mode="after")
    def _verify_catalog(self) -> "GraphEdgeAuthorityCatalogPayload":
        if (
            _kind(self.graph_version) != "global_graph"
            or any(
                record.runtime_epoch != self.target_runtime_epoch
                for record in self.records
            )
        ):
            raise ValueError("GRAPH_EDGE_AUTHORITY_CATALOG_INVALID")
        expected = self._hash_values(
            graph_version=self.graph_version,
            target_runtime_epoch=self.target_runtime_epoch,
            builder_input_sha256=self.builder_input_sha256,
            retrieval_input_descriptor_sha256=(
                self.retrieval_input_descriptor_sha256
            ),
            assigned_input_set_sha256=self.assigned_input_set_sha256,
            edge_mapping=self.edge_mapping,
            records=self.records,
        )
        if self.catalog_sha256 != expected:
            raise ValueError("GRAPH_EDGE_AUTHORITY_CATALOG_HASH_MISMATCH")
        return self

    @classmethod
    def _hash_values(
        cls,
        *,
        graph_version: VersionRef,
        target_runtime_epoch: int,
        builder_input_sha256: str,
        retrieval_input_descriptor_sha256: str,
        assigned_input_set_sha256: str,
        edge_mapping: GraphEdgeMapping,
        records: tuple[GraphEdgeAuthorityRecord, ...],
    ) -> str:
        return _sha256(
            {
                "assigned_input_set_sha256": assigned_input_set_sha256,
                "builder_input_sha256": builder_input_sha256,
                "contract": "graph_edge_authority_catalog_v1",
                "edge_mapping": edge_mapping.model_dump(mode="json"),
                "graph_version": graph_version.model_dump(mode="json"),
                "records": [
                    _authority_record_payload(record) for record in records
                ],
                "retrieval_input_descriptor_sha256": (
                    retrieval_input_descriptor_sha256
                ),
                "target_runtime_epoch": target_runtime_epoch,
            },
            domain=b"consultation-kb-graph-edge-authority-catalog-v1\0",
        )

    @classmethod
    def create(
        cls,
        *,
        graph_version: VersionRef,
        target_runtime_epoch: int,
        builder_input_sha256: str,
        retrieval_input_descriptor_sha256: str,
        assigned_input_set_sha256: str,
        edge_mapping: GraphEdgeMapping,
        records: Iterable[GraphEdgeAuthorityRecord],
    ) -> "GraphEdgeAuthorityCatalogPayload":
        exact_graph = VersionRef.model_validate(graph_version)
        exact_mapping = GraphEdgeMapping.model_validate(edge_mapping)
        exact_records = tuple(
            sorted(
                (
                    GraphEdgeAuthorityRecord.model_validate(value)
                    for value in records
                ),
                key=lambda record: ref_key(record.relation_ref),
            )
        )
        digest = cls._hash_values(
            graph_version=exact_graph,
            target_runtime_epoch=target_runtime_epoch,
            builder_input_sha256=builder_input_sha256,
            retrieval_input_descriptor_sha256=(
                retrieval_input_descriptor_sha256
            ),
            assigned_input_set_sha256=assigned_input_set_sha256,
            edge_mapping=exact_mapping,
            records=exact_records,
        )
        return cls(
            graph_version=exact_graph,
            target_runtime_epoch=target_runtime_epoch,
            builder_input_sha256=builder_input_sha256,
            retrieval_input_descriptor_sha256=(
                retrieval_input_descriptor_sha256
            ),
            assigned_input_set_sha256=assigned_input_set_sha256,
            edge_mapping=exact_mapping,
            records=exact_records,
            catalog_sha256=digest,
        )


class GraphBuildManifestPayload(StrictModel):
    """Public, acyclic manifest pointing one-way to protected authority."""

    contract: Literal["graph_build_manifest_v1"] = "graph_build_manifest_v1"
    builder_input_ref: VersionRef
    graph_ref: VersionRef
    edge_authority_catalog_ref: VersionRef
    graphify_projection_ref: VersionRef
    graph_community_annotations_ref: VersionRef
    target_runtime_epoch: PositiveInt
    source_catalog_version: PositiveInt
    builder_input_sha256: Sha256Hex
    edge_authority_catalog_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    expected_row_mapping_sha256: Sha256Hex
    edge_mapping_sha256: Sha256Hex
    node_count: NonNegativeInt
    edge_count: NonNegativeInt
    candidate_count: NonNegativeInt
    manifest_sha256: Sha256Hex

    @model_validator(mode="after")
    def _verify_manifest(self) -> "GraphBuildManifestPayload":
        refs = (
            self.builder_input_ref,
            self.graph_ref,
            self.edge_authority_catalog_ref,
            self.graphify_projection_ref,
            self.graph_community_annotations_ref,
        )
        if (
            tuple(_kind(value) for value in refs)
            != (
                "graph_builder_input",
                "global_graph",
                "graph_edge_authority_catalog",
                "graphify_projection",
                "graph_community_annotations",
            )
            or len(set(refs)) != len(refs)
        ):
            raise ValueError("GRAPH_BUILD_MANIFEST_REFS_INVALID")
        expected = self._hash_payload(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        )
        if self.manifest_sha256 != expected:
            raise ValueError("GRAPH_BUILD_MANIFEST_HASH_MISMATCH")
        return self

    @staticmethod
    def _hash_payload(payload: object) -> str:
        return _sha256(
            payload,
            domain=b"consultation-kb-graph-build-manifest-v1\0",
        )

    @classmethod
    def create(cls, **values: object) -> "GraphBuildManifestPayload":
        payload = {"contract": "graph_build_manifest_v1", **values}
        return cls(
            **values,  # type: ignore[arg-type]
            manifest_sha256=cls._hash_payload(payload),
        )


def _validate_edge_authority_record(
    record: GraphEdgeAuthorityRecord,
    attributes: Mapping[str, object],
) -> None:
    raw_relation_ref = attributes.get("relation_ref")
    try:
        relation_ref = (
            raw_relation_ref
            if isinstance(raw_relation_ref, VersionRef)
            else VersionRef.model_validate(raw_relation_ref)
        )
    except (TypeError, ValueError):
        raise GraphBuildClosureError(
            "GRAPH_BUILD_EDGE_AUTHORITY_MISMATCH"
        ) from None
    if (
        relation_ref != record.relation_ref
        or attributes.get("provenance_scope") != record.provenance_scope
        or attributes.get("independent_source_count")
        != record.independent_source_count
        or attributes.get("case_contributor_count")
        != len(record.contributor_client_ids)
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_EDGE_AUTHORITY_MISMATCH")


def build_expected_graph_edge_mapping(
    artifact: GlobalGraphArtifact,
    *,
    builder_input: DerivedArtifactBuilderInputV2,
    candidates: tuple[CandidateRef, ...],
    authority_records: tuple[GraphEdgeAuthorityRecord, ...],
) -> GraphEdgeMapping:
    """Reconstruct the mapping from governed inputs, never from caller hashes."""

    verify_global_graph_artifact(artifact)
    if builder_input.artifact_kind != "graph":
        raise GraphBuildClosureError("GRAPH_BUILD_INPUT_KIND_MISMATCH")
    descriptor = builder_input.retrieval_input_descriptor
    try:
        descriptor.verify_candidates("graph", candidates)
    except (TypeError, ValueError) as exc:
        raise GraphBuildClosureError("GRAPH_BUILD_INPUT_SET_MISMATCH") from exc

    records_by_pair: dict[PairKey, RetrievalInputRecord] = {
        _pair_key(record.candidate_ref, record.content_ref): record
        for record in descriptor.assigned_records("graph")
    }
    candidates_by_pair: dict[PairKey, CandidateRef] = {
        _pair_key(value.reference, value.content_ref): value
        for value in candidates
    }
    if len(candidates_by_pair) != len(candidates):
        raise GraphBuildClosureError("GRAPH_BUILD_INPUT_SET_MISMATCH")

    authority_by_relation: dict[
        tuple[str, int, str], GraphEdgeAuthorityRecord
    ] = {}
    for raw_record in authority_records:
        record = GraphEdgeAuthorityRecord.model_validate(raw_record)
        key = ref_key(record.relation_ref)
        if key in authority_by_relation:
            raise GraphBuildClosureError(
                "GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH"
            )
        authority_by_relation[key] = record

    links_by_pair: dict[PairKey, list[GraphRelationAuthorityLink]] = {}
    artifact_relations: set[tuple[str, int, str]] = set()
    for *_edge, attributes in artifact.graph.edges(data=True):
        relation_ref = attributes.get("relation_ref")
        claim_ref = attributes.get("claim_ref")
        passage_refs = attributes.get("passage_refs")
        if (
            not isinstance(relation_ref, VersionRef)
            or not isinstance(claim_ref, VersionRef)
            or not isinstance(passage_refs, tuple)
            or not passage_refs
            or any(not isinstance(value, VersionRef) for value in passage_refs)
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_INVALID")
        relation_key = ref_key(relation_ref)
        if relation_key in artifact_relations:
            raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_INVALID")
        artifact_relations.add(relation_key)
        authority_record = authority_by_relation.get(relation_key)
        if authority_record is None:
            raise GraphBuildClosureError(
                "GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH"
            )
        _validate_edge_authority_record(authority_record, attributes)
        for passage_ref in passage_refs:
            pair = _pair_key(claim_ref, passage_ref)
            links_by_pair.setdefault(pair, []).append(
                GraphRelationAuthorityLink(
                    relation_ref=relation_ref,
                    authority_ref=authority_record.authority_ref,
                )
            )

    if set(authority_by_relation) != artifact_relations:
        raise GraphBuildClosureError("GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH")
    if (
        set(candidates_by_pair) != set(links_by_pair)
        or set(records_by_pair) != set(links_by_pair)
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_SET_MISMATCH")

    rows: list[GraphCandidateEdgeMappingRow] = []
    for pair, raw_links in links_by_pair.items():
        candidate = candidates_by_pair[pair]
        input_record = records_by_pair[pair]
        links = tuple(
            sorted(raw_links, key=lambda value: ref_key(value.relation_ref))
        )
        if (
            candidate.object_type != "claim"
            or _kind(candidate.reference) != "claim"
            or _kind(candidate.content_ref) != "passage"
            or candidate.content_ref.object_id
            not in candidate.provenance.passage_ids
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_INVALID")
        rows.append(
            GraphCandidateEdgeMappingRow(
                candidate_ref=candidate.reference,
                content_ref=candidate.content_ref,
                authority_manifest_ref=input_record.authority_manifest_ref,
                candidate_authority_sha256=(
                    input_record.candidate_authority_sha256
                ),
                relation_links=links,
            )
        )
    return GraphEdgeMapping.create(rows)


def _mapping_from_graph_member_payload(
    graph_payload: Mapping[str, object],
    *,
    builder_input: DerivedArtifactBuilderInputV2,
    authority_catalog: GraphEdgeAuthorityCatalogPayload,
) -> GraphEdgeMapping:
    descriptor = builder_input.retrieval_input_descriptor
    records_by_pair = {
        _pair_key(record.candidate_ref, record.content_ref): record
        for record in descriptor.assigned_records("graph")
    }
    authority_by_relation = {
        ref_key(record.relation_ref): record
        for record in authority_catalog.records
    }
    if len(authority_by_relation) != len(authority_catalog.records):
        raise GraphBuildClosureError(
            "GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH"
        )
    raw_edges = graph_payload.get("edges")
    raw_nodes = graph_payload.get("nodes")
    if not isinstance(raw_edges, list) or not isinstance(raw_nodes, list):
        raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
    node_ids: set[str] = set()
    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict) or set(raw_node) != {
            "attributes",
            "node_id",
        }:
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        node_id = raw_node.get("node_id")
        attributes = raw_node.get("attributes")
        if (
            not isinstance(node_id, str)
            or not node_id
            or node_id in node_ids
            or not isinstance(attributes, dict)
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        node_ids.add(node_id)

    links_by_pair: dict[PairKey, list[GraphRelationAuthorityLink]] = {}
    artifact_relations: set[tuple[str, int, str]] = set()
    edge_ids: set[str] = set()
    for raw_edge in raw_edges:
        if not isinstance(raw_edge, dict) or set(raw_edge) != {
            "attributes",
            "edge_id",
            "source",
            "target",
        }:
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        edge_id = raw_edge.get("edge_id")
        source = raw_edge.get("source")
        target = raw_edge.get("target")
        attributes = raw_edge.get("attributes")
        if (
            not isinstance(edge_id, str)
            or not edge_id
            or edge_id in edge_ids
            or not isinstance(source, str)
            or not isinstance(target, str)
            or source not in node_ids
            or target not in node_ids
            or source == target
            or not isinstance(attributes, dict)
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        edge_ids.add(edge_id)
        try:
            relation_ref = VersionRef.model_validate(attributes["relation_ref"])
            claim_ref = VersionRef.model_validate(attributes["claim_ref"])
            passage_refs = tuple(
                VersionRef.model_validate(value)
                for value in attributes["passage_refs"]
            )
        except (KeyError, TypeError, ValueError):
            raise GraphBuildClosureError(
                "GRAPH_BUILD_EDGE_MAPPING_INVALID"
            ) from None
        relation_key = ref_key(relation_ref)
        if (
            relation_ref.object_id != edge_id
            or relation_key in artifact_relations
            or not passage_refs
            or len(set(passage_refs)) != len(passage_refs)
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_INVALID")
        artifact_relations.add(relation_key)
        authority = authority_by_relation.get(relation_key)
        if authority is None:
            raise GraphBuildClosureError(
                "GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH"
            )
        _validate_edge_authority_record(authority, attributes)
        for passage_ref in passage_refs:
            links_by_pair.setdefault(
                _pair_key(claim_ref, passage_ref), []
            ).append(
                GraphRelationAuthorityLink(
                    relation_ref=relation_ref,
                    authority_ref=authority.authority_ref,
                )
            )
    if set(authority_by_relation) != artifact_relations:
        raise GraphBuildClosureError("GRAPH_BUILD_EDGE_AUTHORITY_SET_MISMATCH")
    if set(records_by_pair) != set(links_by_pair):
        raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_SET_MISMATCH")

    rows: list[GraphCandidateEdgeMappingRow] = []
    for pair, links in links_by_pair.items():
        record = records_by_pair[pair]
        if (
            record.object_type != "claim"
            or _kind(record.candidate_ref) != "claim"
            or _kind(record.content_ref) != "passage"
            or record.content_ref not in record.anchor_refs
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_EDGE_MAPPING_INVALID")
        rows.append(
            GraphCandidateEdgeMappingRow(
                candidate_ref=record.candidate_ref,
                content_ref=record.content_ref,
                authority_manifest_ref=record.authority_manifest_ref,
                candidate_authority_sha256=record.candidate_authority_sha256,
                relation_links=tuple(
                    sorted(links, key=lambda value: ref_key(value.relation_ref))
                ),
            )
        )
    return GraphEdgeMapping.create(rows)


def _expected_projection_payload(
    graph_payload: Mapping[str, object],
) -> dict[str, object]:
    raw_edges = graph_payload.get("edges")
    if not isinstance(raw_edges, list):
        raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for raw_edge in raw_edges:
        if not isinstance(raw_edge, dict):
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        attributes = raw_edge.get("attributes")
        source = raw_edge.get("source")
        target = raw_edge.get("target")
        if not isinstance(attributes, dict):
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        if attributes.get("provenance_scope") != "global_source":
            continue
        if not isinstance(source, str) or not isinstance(target, str):
            raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
        endpoints: tuple[str, str] = (
            (source, target) if source <= target else (target, source)
        )
        grouped.setdefault(endpoints, []).append(attributes)

    edges: list[dict[str, object]] = []
    projection_nodes: set[str] = set()
    for (source, target), attributes_list in sorted(grouped.items()):
        complement = 1.0
        sources: set[str] = set()
        relation_counts: dict[str, int] = {}
        for attributes in attributes_list:
            confidence = attributes.get("confidence")
            relation = attributes.get("relation")
            raw_sources = attributes.get(
                "independent_source_ids", attributes.get("source_refs")
            )
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, int | float)
                or not 0 <= float(confidence) <= 1
                or not isinstance(relation, str)
                or not relation
                or not isinstance(raw_sources, list | tuple)
            ):
                raise GraphBuildClosureError("GRAPH_BUILD_PROJECTION_INVALID")
            complement *= 1.0 - float(confidence)
            relation_counts[relation] = relation_counts.get(relation, 0) + 1
            for raw_source in raw_sources:
                if isinstance(raw_source, dict):
                    try:
                        sources.add(
                            VersionRef.model_validate(raw_source).object_id
                        )
                    except ValueError:
                        raise GraphBuildClosureError(
                            "GRAPH_BUILD_PROJECTION_INVALID"
                        ) from None
                elif isinstance(raw_source, str) and raw_source:
                    sources.add(raw_source.split("@", maxsplit=1)[0])
                else:
                    raise GraphBuildClosureError(
                        "GRAPH_BUILD_PROJECTION_INVALID"
                    )
        aggregate = round(1.0 - complement, 12)
        projection_nodes.update((source, target))
        edges.append(
            {
                "attributes": {
                    "aggregate_confidence": aggregate,
                    "edge_count": len(attributes_list),
                    "relation_counts": dict(sorted(relation_counts.items())),
                    "source_count": len(sources),
                    "weight": aggregate,
                },
                "source": source,
                "target": target,
            }
        )
    return {
        "edges": edges,
        "nodes": sorted(projection_nodes),
        "schema_version": "consultation_graphify_projection.v1",
    }


def _validate_communities_payload(
    value: object,
    *,
    projection_nodes: set[str],
) -> None:
    if not isinstance(value, dict):
        raise GraphBuildClosureError("GRAPH_BUILD_COMMUNITIES_INVALID")
    expected_keys = [str(index) for index in range(len(value))]
    if list(value) != expected_keys:
        raise GraphBuildClosureError("GRAPH_BUILD_COMMUNITIES_INVALID")
    members: list[str] = []
    for raw_members in value.values():
        if (
            not isinstance(raw_members, list)
            or not raw_members
            or any(not isinstance(member, str) or not member for member in raw_members)
            or raw_members != sorted(set(raw_members))
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_COMMUNITIES_INVALID")
        members.extend(raw_members)
    if len(members) != len(set(members)) or set(members) != projection_nodes:
        raise GraphBuildClosureError("GRAPH_BUILD_COMMUNITIES_INVALID")


def verify_graph_member_payloads(
    member_payloads: Mapping[str, bytes],
    *,
    members: tuple[ArtifactMemberIdentity, ...],
) -> GraphEdgeMapping:
    """Verify all six discovered graph members without external candidates."""

    roles = derived_artifact_role_layout("graph")
    if (
        type(member_payloads) is not dict
        or tuple(member.role for member in members) != roles
        or set(member_payloads) != set(roles)
        or any(member.media_type != "application/json" for member in members)
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_LAYOUT_INVALID")
    identities = {member.role: member for member in members}
    for role in roles:
        payload = member_payloads[role]
        identity = identities[role]
        if (
            type(payload) is not bytes
            or len(payload) != identity.size_bytes
            or hashlib.sha256(payload).hexdigest() != identity.content_sha256
        ):
            raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_BYTES_INVALID")
    try:
        builder = DerivedArtifactBuilderInputV2.model_validate_json(
            member_payloads["graph_builder_input"], strict=True
        )
        manifest = GraphBuildManifestPayload.model_validate_json(
            member_payloads["graph_build_manifest"], strict=True
        )
        catalog = GraphEdgeAuthorityCatalogPayload.model_validate_json(
            member_payloads["graph_edge_authority_catalog"], strict=True
        )
        graph_payload = json.loads(member_payloads["global_graph"])
        projection_payload = json.loads(member_payloads["graphify_projection"])
        communities_payload = json.loads(
            member_payloads["graph_community_annotations"]
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_PAYLOAD_INVALID") from None
    if (
        builder.artifact_kind != "graph"
        or member_payloads["graph_builder_input"]
        != canonical_json_bytes(builder.model_dump(mode="json"))
        or member_payloads["graph_build_manifest"]
        != canonical_json_bytes(manifest.model_dump(mode="json"))
        or member_payloads["graph_edge_authority_catalog"]
        != canonical_json_bytes(catalog.model_dump(mode="json"))
        or not isinstance(graph_payload, dict)
        or member_payloads["global_graph"] != canonical_graph_bytes(graph_payload)
        or member_payloads["graphify_projection"]
        != canonical_json_bytes(projection_payload)
        or member_payloads["graph_community_annotations"]
        != canonical_json_bytes(communities_payload)
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_CANONICALITY_INVALID")

    source_version = builder.source_catalog_version

    def exact_member_ref(role: str) -> VersionRef:
        identity = identities[role]
        return VersionRef(
            object_id=identity.object_id,
            version=source_version,
            content_sha256=identity.content_sha256,
        )

    if (
        manifest.builder_input_ref != exact_member_ref("graph_builder_input")
        or manifest.graph_ref != exact_member_ref("global_graph")
        or manifest.edge_authority_catalog_ref
        != exact_member_ref("graph_edge_authority_catalog")
        or manifest.graphify_projection_ref
        != exact_member_ref("graphify_projection")
        or manifest.graph_community_annotations_ref
        != exact_member_ref("graph_community_annotations")
        or manifest.builder_input_sha256 != builder.canonical_sha256
        or manifest.edge_authority_catalog_sha256 != catalog.catalog_sha256
        or catalog.graph_version != manifest.graph_ref
        or catalog.builder_input_sha256 != builder.canonical_sha256
        or catalog.target_runtime_epoch != builder.target_runtime_epoch
        or catalog.retrieval_input_descriptor_sha256
        != builder.retrieval_input_descriptor.descriptor_sha256
        or catalog.assigned_input_set_sha256
        != builder.retrieval_input_descriptor.assigned_input_set_sha256("graph")
        or manifest.target_runtime_epoch != builder.target_runtime_epoch
        or manifest.source_catalog_version != source_version
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_BINDING_MISMATCH")
    if (
        graph_payload.get("schema_version") != "consultation_global_graph.v1"
        or graph_payload.get("source_catalog_version") != source_version
        or graph_payload.get("source_runtime_epoch") != builder.target_runtime_epoch
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_GRAPH_PAYLOAD_INVALID")
    mapping = _mapping_from_graph_member_payload(
        graph_payload,
        builder_input=builder,
        authority_catalog=catalog,
    )
    expected_projection = _expected_projection_payload(graph_payload)
    if projection_payload != expected_projection:
        raise GraphBuildClosureError("GRAPH_BUILD_PROJECTION_INVALID")
    projection_nodes = expected_projection["nodes"]
    if not isinstance(projection_nodes, list):
        raise GraphBuildClosureError("GRAPH_BUILD_PROJECTION_INVALID")
    _validate_communities_payload(
        communities_payload,
        projection_nodes=set(projection_nodes),
    )
    raw_nodes = graph_payload.get("nodes")
    raw_edges = graph_payload.get("edges")
    candidate_count = len(
        builder.retrieval_input_descriptor.assigned_records("graph")
    )
    if (
        mapping != catalog.edge_mapping
        or manifest.retrieval_input_descriptor_sha256
        != builder.retrieval_input_descriptor.descriptor_sha256
        or manifest.assigned_input_set_sha256
        != builder.retrieval_input_descriptor.assigned_input_set_sha256("graph")
        or manifest.expected_row_mapping_sha256
        != builder.retrieval_input_descriptor.expected_row_mapping_sha256(
            "graph"
        )
        or manifest.edge_mapping_sha256 != mapping.mapping_sha256
        or not isinstance(raw_nodes, list)
        or not isinstance(raw_edges, list)
        or manifest.node_count != len(raw_nodes)
        or manifest.edge_count != len(raw_edges)
        or manifest.candidate_count != candidate_count
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_MEMBER_BINDING_MISMATCH")
    return mapping


def verify_graph_build_closure(
    artifact: GlobalGraphArtifact,
    *,
    builder_input: DerivedArtifactBuilderInputV2,
    candidates: tuple[CandidateRef, ...],
    authority_catalog: GraphEdgeAuthorityCatalogPayload,
    build_manifest: GraphBuildManifestPayload,
) -> GraphEdgeMapping:
    """Verify semantic equality even if every attacker-controlled hash closes."""

    verify_global_graph_artifact(artifact)
    builder = DerivedArtifactBuilderInputV2.model_validate(builder_input)
    catalog = GraphEdgeAuthorityCatalogPayload.model_validate(authority_catalog)
    manifest = GraphBuildManifestPayload.model_validate(build_manifest)
    if (
        builder.artifact_kind != "graph"
        or builder.source_catalog_version != artifact.source_catalog_version
        or builder.target_runtime_epoch != artifact.source_runtime_epoch
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_INPUT_VERSION_MISMATCH")
    graph_version = VersionRef(
        object_id=manifest.graph_ref.object_id,
        version=artifact.source_catalog_version,
        content_sha256=artifact.canonical_sha256,
    )
    expected_mapping = build_expected_graph_edge_mapping(
        artifact,
        builder_input=builder,
        candidates=candidates,
        authority_records=catalog.records,
    )
    descriptor = builder.retrieval_input_descriptor
    assigned_input_set_sha256 = descriptor.assigned_input_set_sha256("graph")
    canonical_builder_bytes = canonical_json_bytes(builder.model_dump(mode="json"))
    canonical_catalog_bytes = canonical_json_bytes(catalog.model_dump(mode="json"))
    if (
        manifest.graph_ref != graph_version
        or catalog.graph_version != graph_version
        or catalog.target_runtime_epoch != artifact.source_runtime_epoch
        or catalog.builder_input_sha256 != builder.canonical_sha256
        or catalog.retrieval_input_descriptor_sha256
        != descriptor.descriptor_sha256
        or catalog.assigned_input_set_sha256 != assigned_input_set_sha256
        or catalog.edge_mapping != expected_mapping
        or manifest.builder_input_sha256 != builder.canonical_sha256
        or manifest.edge_authority_catalog_sha256 != catalog.catalog_sha256
        or manifest.builder_input_ref.content_sha256
        != hashlib.sha256(canonical_builder_bytes).hexdigest()
        or manifest.builder_input_ref.version != artifact.source_catalog_version
        or manifest.edge_authority_catalog_ref.content_sha256
        != hashlib.sha256(canonical_catalog_bytes).hexdigest()
        or manifest.edge_authority_catalog_ref.version
        != artifact.source_catalog_version
        or manifest.target_runtime_epoch != artifact.source_runtime_epoch
        or manifest.source_catalog_version != artifact.source_catalog_version
        or manifest.retrieval_input_descriptor_sha256
        != descriptor.descriptor_sha256
        or manifest.assigned_input_set_sha256 != assigned_input_set_sha256
        or manifest.expected_row_mapping_sha256
        != descriptor.expected_row_mapping_sha256("graph")
        or manifest.edge_mapping_sha256 != expected_mapping.mapping_sha256
        or manifest.node_count != artifact.graph.number_of_nodes()
        or manifest.edge_count != artifact.graph.number_of_edges()
        or manifest.candidate_count != len(candidates)
    ):
        raise GraphBuildClosureError("GRAPH_BUILD_CLOSURE_MISMATCH")
    for reference in (
        manifest.graphify_projection_ref,
        manifest.graph_community_annotations_ref,
    ):
        if reference.version != artifact.source_catalog_version:
            raise GraphBuildClosureError("GRAPH_BUILD_CLOSURE_MISMATCH")
    return expected_mapping


__all__ = [
    "GraphBuildClosureError",
    "GraphBuildManifestPayload",
    "GraphCandidateEdgeMappingRow",
    "GraphEdgeAuthorityCatalogPayload",
    "GraphEdgeMapping",
    "GraphRelationAuthorityLink",
    "build_expected_graph_edge_mapping",
    "verify_graph_build_closure",
    "verify_graph_member_payloads",
]
