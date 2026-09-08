"""Canonical serialization for the client-private derived MultiDiGraph."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

import networkx as nx


GRAPH_SCHEMA_VERSION = "client_temporal_graph.v1"


def _json_value(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in sorted(value.items())}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"graph attribute type is not serializable: {type(value).__name__}")


def graph_payload(
    graph: nx.MultiDiGraph[str, dict[str, object], dict[str, object]],
    *,
    publication_operation_id: str,
    source_client_commit_version: int,
    runtime_epoch: int,
    effective_at: datetime,
    known_at: datetime,
    builder_policy_version: str,
) -> dict[str, Any]:
    nodes = [
        {"node_id": str(node), "attributes": _json_value(dict(attributes))}
        for node, attributes in sorted(
            graph.nodes.items(), key=lambda item: str(item[0])
        )
    ]
    edges = [
        {
            "source": str(source),
            "target": str(target),
            "edge_id": str(key),
            "attributes": _json_value(dict(attributes)),
        }
        for source, target, key, attributes in sorted(
            graph.edges(keys=True, data=True),
            key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
        )
    ]
    return {
        "builder_policy_version": builder_policy_version,
        "edges": edges,
        "nodes": nodes,
        "publication_operation_id": publication_operation_id,
        "query": {
            "effective_at": _json_value(effective_at),
            "known_at": _json_value(known_at),
        },
        "runtime_epoch": runtime_epoch,
        "schema_version": GRAPH_SCHEMA_VERSION,
        "source_client_commit_version": source_client_commit_version,
    }


def canonical_graph_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def graph_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_graph_bytes(payload)).hexdigest()


def load_graph(
    data: bytes,
) -> tuple[
    nx.MultiDiGraph[str, dict[str, object], dict[str, object]],
    dict[str, Any],
]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("CLIENT_GRAPH_INVALID") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != GRAPH_SCHEMA_VERSION:
        raise ValueError("CLIENT_GRAPH_VERSION_UNSUPPORTED")
    graph: nx.MultiDiGraph[
        str, dict[str, object], dict[str, object]
    ] = nx.MultiDiGraph()
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("CLIENT_GRAPH_INVALID")
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("node_id"), str):
            raise ValueError("CLIENT_GRAPH_INVALID")
        attributes = node.get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("CLIENT_GRAPH_INVALID")
        graph.add_node(node["node_id"], **attributes)
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("CLIENT_GRAPH_INVALID")
        source = edge.get("source")
        target = edge.get("target")
        edge_id = edge.get("edge_id")
        attributes = edge.get("attributes")
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or not isinstance(edge_id, str)
        ):
            raise ValueError("CLIENT_GRAPH_INVALID")
        if not isinstance(attributes, dict) or attributes.get("edge_id") != edge_id:
            raise ValueError("CLIENT_GRAPH_INVALID")
        graph.add_edge(source, target, key=edge_id, **attributes)
    return graph, payload


__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "canonical_graph_bytes",
    "graph_payload",
    "graph_sha256",
    "load_graph",
]
