"""Narrow adapter: Graphify is used only for community discovery."""

from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

import networkx as nx

from graphify.cluster import ClusterResult, cluster_with_metadata

from consultation_kb.graph.global_builder import (
    GlobalGraphArtifact,
    verify_global_graph_artifact,
)
from consultation_kb.graph.serialization import graph_payload_from_parts, graph_sha256
from consultation_kb.models.common import VersionRef


PROJECTION_SCHEMA_VERSION = "consultation_graphify_projection.v1"


class GraphifyProjectionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GraphifyBackendError(GraphifyProjectionError):
    pass


@dataclass(frozen=True, slots=True)
class ClusterRuntimeMetadata:
    backend: Literal["leiden", "louvain", "trivial"]
    seed: int
    degraded: bool
    reproducible: bool


@dataclass(frozen=True, slots=True)
class ProjectionClusterResult:
    projection: nx.Graph[str]
    communities: dict[int, tuple[str, ...]]
    metadata: ClusterRuntimeMetadata


@dataclass(frozen=True, slots=True)
class GlobalGraphManifest:
    schema_version: str
    source_catalog_version: int
    source_runtime_epoch: int
    graphify_version: str
    cluster_module_sha256: str
    networkx_version: str
    graspologic_version: str
    backend: str
    seed: int
    degraded: bool
    reproducible: bool
    graphify_parameters: tuple[tuple[str, object], ...]
    projection_schema_version: str
    canonical_graph_sha256: str
    projection_sha256: str
    communities_sha256: str
    manifest_sha256: str


def _stable_source_identity(value: object) -> str:
    if isinstance(value, VersionRef):
        return value.object_id
    rendered = str(value)
    return rendered.split("@", maxsplit=1)[0]


def _canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class GraphifyProjectionAdapter:
    """Project parallel governed evidence to a simple undirected graph."""

    def __init__(self, *, seed: int = 42, production: bool = False) -> None:
        if type(seed) is not int or not 0 <= seed <= (2**63 - 1):
            raise ValueError("seed must be an integer between 0 and 2**63-1")
        self.seed = seed
        self.production = production

    def project(self, artifact: GlobalGraphArtifact) -> nx.Graph[str]:
        verify_global_graph_artifact(artifact)
        canonical = artifact.graph
        projection: nx.Graph[str] = nx.Graph()

        grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
        for source, target, key, attributes in sorted(
            canonical.edges(keys=True, data=True),
            key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
        ):
            if attributes.get("provenance_scope") != "global_source":
                continue
            source_id, target_id = sorted((str(source), str(target)))
            grouped.setdefault((source_id, target_id), []).append(dict(attributes))

        for (source, target), edges in sorted(grouped.items()):
            confidences: list[float] = []
            sources: set[str] = set()
            relation_counts: dict[str, int] = {}
            for attributes in edges:
                raw_confidence = attributes.get("confidence")
                if (
                    isinstance(raw_confidence, bool)
                    or not isinstance(raw_confidence, int | float)
                    or not 0 <= float(raw_confidence) <= 1
                ):
                    raise GraphifyProjectionError("GRAPH_PROJECTION_CONFIDENCE_INVALID")
                confidences.append(float(raw_confidence))
                raw_sources = attributes.get(
                    "independent_source_ids", attributes.get("source_refs", ())
                )
                if not isinstance(raw_sources, tuple | list | set | frozenset):
                    raise GraphifyProjectionError("GRAPH_PROJECTION_SOURCES_INVALID")
                sources.update(_stable_source_identity(value) for value in raw_sources)
                relation = attributes.get("relation")
                if not isinstance(relation, str) or not relation:
                    raise GraphifyProjectionError("GRAPH_PROJECTION_RELATION_INVALID")
                relation_counts[relation] = relation_counts.get(relation, 0) + 1
            complement = 1.0
            for confidence in confidences:
                complement *= 1.0 - confidence
            aggregate_confidence = round(1.0 - complement, 12)
            projection.add_edge(
                source,
                target,
                aggregate_confidence=aggregate_confidence,
                edge_count=len(edges),
                relation_counts=dict(sorted(relation_counts.items())),
                source_count=len(sources),
                weight=aggregate_confidence,
            )
        return projection

    def cluster(self, artifact: GlobalGraphArtifact) -> ProjectionClusterResult:
        verify_global_graph_artifact(artifact)
        projection = self.project(artifact)
        runtime: ClusterResult = cluster_with_metadata(projection, seed=self.seed)
        if runtime.seed != self.seed or not runtime.reproducible:
            raise GraphifyBackendError("GRAPHIFY_CLUSTER_NOT_REPRODUCIBLE")
        if set(runtime.communities) != set(range(len(runtime.communities))):
            # Upstream IDs are not an authority.  Noncanonical IDs are accepted
            # and deterministically renumbered below, but values must close.
            pass
        members = [tuple(sorted(nodes)) for nodes in runtime.communities.values()]
        if {node for community in members for node in community} != set(
            projection.nodes
        ) or sum(len(community) for community in members) != len(projection.nodes):
            raise GraphifyBackendError("GRAPHIFY_CLUSTER_PARTITION_INVALID")
        members.sort(key=lambda nodes: (-len(nodes), nodes))
        communities = {index: nodes for index, nodes in enumerate(members)}

        if self.production and sys.version_info < (3, 13):
            if runtime.backend != "leiden" or runtime.degraded:
                raise GraphifyBackendError("GRAPHIFY_PRODUCTION_BACKEND_INVALID")
        metadata = ClusterRuntimeMetadata(
            backend=runtime.backend,
            seed=runtime.seed,
            degraded=runtime.degraded,
            reproducible=runtime.reproducible,
        )
        return ProjectionClusterResult(projection, communities, metadata)


def _package_version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _projection_payload(graph: nx.Graph[str]) -> dict[str, object]:
    return {
        "edges": [
            {
                "source": str(source),
                "target": str(target),
                "attributes": dict(sorted(attributes.items())),
            }
            for source, target, attributes in sorted(
                graph.edges(data=True), key=lambda item: (str(item[0]), str(item[1]))
            )
        ],
        "nodes": sorted(str(node) for node in graph.nodes),
        "schema_version": PROJECTION_SCHEMA_VERSION,
    }


def build_graph_manifest(
    *,
    artifact: GlobalGraphArtifact,
    cluster_result: ProjectionClusterResult,
    seed: int,
) -> GlobalGraphManifest:
    verify_global_graph_artifact(artifact)
    canonical_graph = artifact.graph
    projection = cluster_result.projection
    communities = cluster_result.communities
    metadata = cluster_result.metadata
    source_catalog_version = artifact.source_catalog_version
    runtime_epoch = artifact.source_runtime_epoch
    if metadata.seed != seed:
        raise GraphifyProjectionError("GRAPH_MANIFEST_SEED_MISMATCH")
    graph_catalog_version = canonical_graph.graph.get("source_catalog_version")
    graph_runtime_epoch = canonical_graph.graph.get("source_runtime_epoch")
    effective_at = canonical_graph.graph.get("effective_at")
    builder_policy_version = canonical_graph.graph.get("builder_policy_version")
    if (
        graph_catalog_version != source_catalog_version
        or graph_runtime_epoch != runtime_epoch
        or not isinstance(effective_at, datetime)
        or not isinstance(builder_policy_version, str)
        or not builder_policy_version
    ):
        raise GraphifyProjectionError("GRAPH_MANIFEST_AUTHORITY_MISMATCH")
    expected_projection = GraphifyProjectionAdapter(seed=seed).project(artifact)
    if _projection_payload(expected_projection) != _projection_payload(projection):
        raise GraphifyProjectionError("GRAPH_MANIFEST_PROJECTION_MISMATCH")
    community_members = [node for values in communities.values() for node in values]
    if len(community_members) != len(set(community_members)) or set(
        community_members
    ) != set(projection.nodes):
        raise GraphifyProjectionError("GRAPH_MANIFEST_COMMUNITIES_INVALID")
    # Projection, partition and runtime metadata are one seeded result.  A
    # second deterministic execution prevents callers from mixing components
    # from different runs while still presenting a valid covering partition.
    expected_cluster = GraphifyProjectionAdapter(seed=seed).cluster(artifact)
    if (
        expected_cluster.communities != communities
        or expected_cluster.metadata != metadata
    ):
        raise GraphifyProjectionError("GRAPH_MANIFEST_CLUSTER_BINDING_MISMATCH")
    source_file = inspect.getsourcefile(cluster_with_metadata)
    if source_file is None:
        raise GraphifyProjectionError("GRAPHIFY_CLUSTER_SOURCE_UNAVAILABLE")
    cluster_module_sha256 = hashlib.sha256(Path(source_file).read_bytes()).hexdigest()
    parameters: tuple[tuple[str, object], ...] = (
        ("community_seed", seed),
        ("confidence_aggregation", "noisy_or"),
        ("community_order", "size_desc_nodes_asc"),
    )
    values: dict[str, object] = {
        "schema_version": "consultation_global_graph_manifest.v1",
        "source_catalog_version": source_catalog_version,
        "source_runtime_epoch": runtime_epoch,
        "graphify_version": _package_version("graphifyy"),
        "cluster_module_sha256": cluster_module_sha256,
        "networkx_version": nx.__version__,
        "graspologic_version": _package_version("graspologic"),
        "backend": metadata.backend,
        "seed": seed,
        "degraded": metadata.degraded,
        "reproducible": metadata.reproducible,
        "graphify_parameters": parameters,
        "projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "canonical_graph_sha256": graph_sha256(
            graph_payload_from_parts(
                canonical_graph,
                source_catalog_version=source_catalog_version,
                source_runtime_epoch=runtime_epoch,
                effective_at=effective_at,
                builder_policy_version=builder_policy_version,
            )
        ),
        "projection_sha256": _canonical_json_sha256(_projection_payload(projection)),
        "communities_sha256": _canonical_json_sha256(
            {str(key): list(value) for key, value in sorted(communities.items())}
        ),
    }
    manifest_sha256 = _canonical_json_sha256(values)
    return GlobalGraphManifest(
        **values,  # type: ignore[arg-type]
        manifest_sha256=manifest_sha256,
    )


__all__ = [
    "ClusterRuntimeMetadata",
    "GlobalGraphManifest",
    "GraphifyBackendError",
    "GraphifyProjectionAdapter",
    "GraphifyProjectionError",
    "PROJECTION_SCHEMA_VERSION",
    "ProjectionClusterResult",
    "build_graph_manifest",
]
