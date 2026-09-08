from __future__ import annotations

import networkx as nx
import pytest

import graphify.cluster as cluster_module
from graphify.cluster import (
    CommunitySeedUnsupported,
    cluster,
    cluster_with_metadata,
)


def test_cluster_same_seed_is_stable_and_legacy_call_remains_compatible() -> None:
    graph = nx.karate_club_graph()
    graph = nx.relabel_nodes(graph, {node: str(node) for node in graph.nodes})

    assert cluster(graph, seed=73) == cluster(graph, seed=73)
    assert isinstance(cluster(graph), dict)


def test_cluster_result_passes_seed_to_leiden_and_reports_backend(monkeypatch) -> None:
    calls: list[int | None] = []

    def fake_leiden(graph, *, random_seed=None):
        calls.append(random_seed)
        if int(random_seed or 0) % 2:
            return {
                node: index // 2
                for index, node in enumerate(sorted(graph.nodes))
            }
        return {
            node: index % 2
            for index, node in enumerate(sorted(graph.nodes))
        }

    monkeypatch.setattr(cluster_module, "_load_leiden", lambda: fake_leiden)
    graph = nx.path_graph(["a", "b", "c", "d"])

    first = cluster_with_metadata(graph, seed=11)
    second = cluster_with_metadata(graph, seed=12)

    assert calls == [11, 12]
    assert first.communities != second.communities
    assert first.backend == "leiden"
    assert first.seed == 11
    assert first.degraded is False
    assert first.reproducible is True
    assert second.backend == "leiden"


def test_cluster_result_reports_seeded_louvain_fallback(monkeypatch) -> None:
    calls: list[int | None] = []

    def fake_louvain(graph, *, seed=None, threshold=0.0001, max_level=None):
        del threshold, max_level
        calls.append(seed)
        return [{node} for node in sorted(graph.nodes)]

    monkeypatch.setattr(cluster_module, "_load_leiden", lambda: None)
    monkeypatch.setattr(nx.community, "louvain_communities", fake_louvain)

    result = cluster_with_metadata(nx.path_graph(["a", "b", "c"]), seed=91)

    assert calls == [91]
    assert result.communities == {0: ["a"], 1: ["b"], 2: ["c"]}
    assert result.backend == "louvain"
    assert result.seed == 91
    assert result.degraded is True
    assert result.reproducible is True


def test_cluster_fails_if_installed_backend_has_no_formal_seed_parameter(
    monkeypatch,
) -> None:
    def unseeded_leiden(graph):
        return {node: 0 for node in graph.nodes}

    monkeypatch.setattr(cluster_module, "_load_leiden", lambda: unseeded_leiden)

    with pytest.raises(CommunitySeedUnsupported, match="COMMUNITY_SEED_UNSUPPORTED"):
        cluster(nx.path_graph(["a", "b"]), seed=7)
