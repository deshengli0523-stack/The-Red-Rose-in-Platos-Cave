"""Deterministic community detection with honest backend metadata."""

from __future__ import annotations

import contextlib
import inspect
import io
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, cast

import networkx as nx


ClusterBackend = Literal["leiden", "louvain", "trivial"]
if TYPE_CHECKING:
    StringGraph: TypeAlias = nx.Graph[
        str,
        dict[str, Any],
        dict[str, Any],
    ]
else:
    StringGraph = nx.Graph
Partitioner = Callable[[StringGraph], dict[str, int]]


class CommunitySeedUnsupported(RuntimeError):
    """The selected backend cannot prove deterministic seed support."""

    def __init__(self) -> None:
        super().__init__("COMMUNITY_SEED_UNSUPPORTED")


class CommunityPartitionInvalid(RuntimeError):
    """A backend returned an incomplete or malformed partition."""

    def __init__(self) -> None:
        super().__init__("COMMUNITY_PARTITION_INVALID")


@dataclass(frozen=True, slots=True)
class ClusterMetadata:
    backend: ClusterBackend
    seed: int
    degraded: bool
    reproducible: bool


@dataclass(frozen=True, slots=True)
class ClusterResult:
    communities: dict[int, list[str]]
    backend: ClusterBackend
    seed: int
    degraded: bool
    reproducible: bool


def _suppress_output() -> contextlib.AbstractContextManager[io.StringIO]:
    """Suppress progress output emitted by community-detection libraries."""

    return contextlib.redirect_stdout(io.StringIO())


def _load_leiden() -> Callable[..., dict[str, int]] | None:
    try:
        from graspologic.partition import leiden
    except ImportError:
        return None
    return cast(Callable[..., dict[str, int]], leiden)


def _validated_seed(seed: int) -> int:
    if type(seed) is not int or not 0 <= seed <= (2**63 - 1):
        raise ValueError("seed must be an integer between 0 and 2**63-1")
    return seed


def _validate_partition(G: StringGraph, result: object) -> dict[str, int]:
    if not isinstance(result, dict) or set(result) != set(G.nodes):
        raise CommunityPartitionInvalid
    if any(type(community_id) is not int for community_id in result.values()):
        raise CommunityPartitionInvalid
    return cast(dict[str, int], result)


def _resolve_partitioner(*, seed: int) -> tuple[Partitioner, ClusterMetadata]:
    """Select one seeded backend and return its actual runtime metadata."""

    seed_value = _validated_seed(seed)
    leiden = _load_leiden()
    if leiden is not None:
        parameters = inspect.signature(leiden).parameters
        seed_parameter = next(
            (name for name in ("random_seed", "seed") if name in parameters),
            None,
        )
        if seed_parameter is None:
            raise CommunitySeedUnsupported

        def run_leiden(G: StringGraph) -> dict[str, int]:
            # graspologic can emit ANSI/progress output that corrupts the
            # Windows PowerShell scroll buffer. Keep the library call silent.
            old_stderr = sys.stderr
            try:
                sys.stderr = io.StringIO()
                with _suppress_output():
                    result = leiden(G, **{seed_parameter: seed_value})
            finally:
                sys.stderr = old_stderr
            return _validate_partition(G, result)

        return run_leiden, ClusterMetadata(
            backend="leiden",
            seed=seed_value,
            degraded=False,
            reproducible=True,
        )

    louvain = nx.community.louvain_communities
    parameters = inspect.signature(louvain).parameters
    if "seed" not in parameters:
        raise CommunitySeedUnsupported

    def run_louvain(G: StringGraph) -> dict[str, int]:
        if "max_level" in parameters:
            communities = louvain(
                G,
                seed=seed_value,
                threshold=1e-4,
                max_level=10,
            )
        else:
            communities = louvain(G, seed=seed_value, threshold=1e-4)
        result = {
            node: community_id
            for community_id, nodes in enumerate(communities)
            for node in nodes
        }
        return _validate_partition(G, result)

    return run_louvain, ClusterMetadata(
        backend="louvain",
        seed=seed_value,
        degraded=True,
        reproducible=True,
    )


def _partition(G: StringGraph, *, seed: int = 42) -> dict[str, int]:
    """Compatibility wrapper returning only the seeded node partition."""

    partitioner, _metadata = _resolve_partitioner(seed=seed)
    return partitioner(G)


_MAX_COMMUNITY_FRACTION = 0.25
_MIN_SPLIT_SIZE = 10


def cluster(G: StringGraph, *, seed: int = 42) -> dict[int, list[str]]:
    """Return communities only, preserving the original public API shape."""

    return cluster_with_metadata(G, seed=seed).communities


def cluster_with_metadata(
    G: StringGraph,
    *,
    seed: int = 42,
) -> ClusterResult:
    """Run seeded Leiden or seeded Louvain and report the backend actually used.

    Community IDs are stable: largest communities come first, with a canonical
    node-ID tie breaker. Directed graphs are converted to undirected graphs.
    Oversized communities are split with the same resolved backend and seed.
    """

    seed_value = _validated_seed(seed)
    if G.number_of_nodes() == 0:
        return ClusterResult({}, "trivial", seed_value, False, True)
    if G.is_directed():
        G = G.to_undirected()
    if G.number_of_edges() == 0:
        return ClusterResult(
            {index: [node] for index, node in enumerate(sorted(G.nodes))},
            "trivial",
            seed_value,
            False,
            True,
        )

    partitioner, metadata = _resolve_partitioner(seed=seed_value)

    # Leiden warns and drops isolates, so partition only connected nodes and
    # add each isolate back as its own community.
    isolates = [node for node in G.nodes() if G.degree(node) == 0]
    connected_nodes = [node for node in G.nodes() if G.degree(node) > 0]
    connected = G.subgraph(connected_nodes)

    raw: dict[int, list[str]] = {}
    if connected.number_of_nodes() > 0:
        for node, community_id in partitioner(connected).items():
            raw.setdefault(community_id, []).append(node)

    next_community_id = max(raw, default=-1) + 1
    for node in sorted(isolates):
        raw[next_community_id] = [node]
        next_community_id += 1

    max_size = max(
        _MIN_SPLIT_SIZE,
        int(G.number_of_nodes() * _MAX_COMMUNITY_FRACTION),
    )
    final_communities: list[list[str]] = []
    for nodes in raw.values():
        if len(nodes) > max_size:
            final_communities.extend(
                _split_community(G, nodes, partitioner=partitioner)
            )
        else:
            final_communities.append(nodes)

    final_communities.sort(
        key=lambda nodes: (-len(nodes), tuple(sorted(nodes)))
    )
    return ClusterResult(
        {
            community_id: sorted(nodes)
            for community_id, nodes in enumerate(final_communities)
        },
        metadata.backend,
        metadata.seed,
        metadata.degraded,
        metadata.reproducible,
    )


def _split_community(
    G: StringGraph,
    nodes: list[str],
    *,
    partitioner: Partitioner,
) -> list[list[str]]:
    """Split one oversized community with the already-resolved backend."""

    subgraph = G.subgraph(nodes)
    if subgraph.number_of_edges() == 0:
        return [[node] for node in sorted(nodes)]
    sub_communities: dict[int, list[str]] = {}
    for node, community_id in partitioner(subgraph).items():
        sub_communities.setdefault(community_id, []).append(node)
    if len(sub_communities) <= 1:
        return [sorted(nodes)]
    return [sorted(value) for value in sub_communities.values()]


def cohesion_score(G: StringGraph, community_nodes: list[str]) -> float:
    """Ratio of actual intra-community edges to maximum possible."""

    node_count = len(community_nodes)
    if node_count <= 1:
        return 1.0
    subgraph = G.subgraph(community_nodes)
    actual = subgraph.number_of_edges()
    possible = node_count * (node_count - 1) / 2
    return round(actual / possible, 2) if possible > 0 else 0.0


def score_all(
    G: StringGraph,
    communities: dict[int, list[str]],
) -> dict[int, float]:
    return {
        community_id: cohesion_score(G, nodes)
        for community_id, nodes in communities.items()
    }


__all__ = [
    "ClusterMetadata",
    "ClusterResult",
    "CommunityPartitionInvalid",
    "CommunitySeedUnsupported",
    "cluster",
    "cluster_with_metadata",
    "cohesion_score",
    "score_all",
]
