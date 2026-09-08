"""Canonical serialization for the consultation-owned global graph."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import networkx as nx
from pydantic import BaseModel

from consultation_kb.models.common import VersionRef
from consultation_kb.models.graph import PUBLIC_GRAPH_NODE_KINDS
from consultation_kb.models.knowledge import ClaimApplicability
from consultation_kb.retrieval.contracts import canonical_json_bytes

if TYPE_CHECKING:
    from consultation_kb.graph.global_builder import GlobalGraphArtifact


GRAPH_SCHEMA_VERSION = "consultation_global_graph.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT_ID = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SAFE_POLICY_KEY = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_TOP_LEVEL_KEYS = {
    "builder_policy_version",
    "effective_at",
    "edges",
    "nodes",
    "schema_version",
    "source_catalog_version",
    "source_runtime_epoch",
}
_NODE_ATTRIBUTE_KEYS = {"node_type", "reference", "version"}
_EDGE_ATTRIBUTE_KEYS = {
    "allowed_uses",
    "applicability",
    "authorized",
    "case_contributor_count",
    "claim_ref",
    "cognitive_type",
    "confidence",
    "edge_id",
    "effective_from",
    "effective_to",
    "empirical_support",
    "framework_eligibility",
    "independent_source_count",
    "independent_source_ids",
    "passage_refs",
    "passage_review_status",
    "privacy_scope",
    "provenance_ref",
    "provenance_scope",
    "relation",
    "relation_ref",
    "relation_scope",
    "review_due_at",
    "review_status",
    "source_grade",
    "source_refs",
    "statement_text_sha256",
    "theory_ref",
    "theory_status",
    "tombstoned",
    "truth_type",
    "wiki_ref",
}
_RELATIONS = {
    "SUPPORTS",
    "CONTRADICTS",
    "ANALOGOUS_TO",
    "DISTINCT_FROM",
    "APPLIES_TO",
    "NOT_APPLICABLE_TO",
    "RELATED_TO",
}
_COGNITIVE_TYPES = {
    "explicit",
    "paraphrase",
    "counselor_judgment",
    "model_inference",
    "cross_theory_analogy",
}
_SOURCE_GRADES = {
    *(f"T{value}" for value in range(1, 5)),
    *(f"C{value}" for value in range(1, 7)),
    *(f"K{value}" for value in range(1, 5)),
    *(f"L{value}" for value in range(1, 5)),
}
_EMPIRICAL_SUPPORT = {
    "unassessed",
    "case_supported",
    "observation_supported",
    "empirically_supported",
    "guideline_consistent",
    "conflicting",
}
_FRAMEWORK_ELIGIBILITY = {"eligible", "ineligible", "conditional"}
_TRUTH_TYPES = {
    "theory_framework",
    "source_text",
    "official_fact",
    "analogy",
    "interpretation",
}


def _json_value(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, tuple | list | set | frozenset):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"global graph attribute is not serializable: {type(value).__name__}")


def graph_structure_payload(
    graph: nx.MultiDiGraph[str, dict[str, object], dict[str, object]],
) -> dict[str, object]:
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
    return {"edges": edges, "nodes": nodes}


def graph_payload_from_parts(
    graph: nx.MultiDiGraph[str, dict[str, object], dict[str, object]],
    *,
    source_catalog_version: int,
    source_runtime_epoch: int,
    effective_at: datetime,
    builder_policy_version: str,
) -> dict[str, Any]:
    structure = graph_structure_payload(graph)
    return {
        "builder_policy_version": builder_policy_version,
        "effective_at": _json_value(effective_at),
        "edges": structure["edges"],
        "nodes": structure["nodes"],
        "schema_version": GRAPH_SCHEMA_VERSION,
        "source_catalog_version": source_catalog_version,
        "source_runtime_epoch": source_runtime_epoch,
    }


def graph_payload(artifact: GlobalGraphArtifact) -> dict[str, Any]:
    return graph_payload_from_parts(
        artifact.graph,
        source_catalog_version=artifact.source_catalog_version,
        source_runtime_epoch=artifact.source_runtime_epoch,
        effective_at=artifact.effective_at,
        builder_policy_version=artifact.builder_policy_version,
    )


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


class CanonicalGraphParseError(RuntimeError):
    def __init__(self, code: str = "GLOBAL_GRAPH_CANONICAL_PAYLOAD_INVALID") -> None:
        self.code = code
        super().__init__(code)


def _parse_ref(value: object, *, kind: str | None = None) -> VersionRef:
    if not isinstance(value, dict):
        raise CanonicalGraphParseError
    try:
        reference = VersionRef.model_validate_json(
            canonical_json_bytes(value), strict=True
        )
    except ValueError:
        raise CanonicalGraphParseError from None
    if kind is not None and reference.object_id[:-37] != kind:
        raise CanonicalGraphParseError
    return reference


def _parse_datetime(value: object, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise CanonicalGraphParseError
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CanonicalGraphParseError from None
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
        != value
    ):
        raise CanonicalGraphParseError
    return parsed


def _canonical_strings(value: object, *, required: bool) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (required and not value)
        or any(type(item) is not str or not item for item in value)
        or value != sorted(set(value))
    ):
        raise CanonicalGraphParseError
    return tuple(value)


def _canonical_refs(
    value: object,
    *,
    kind: str,
) -> tuple[VersionRef, ...]:
    if not isinstance(value, list) or not value:
        raise CanonicalGraphParseError
    refs = tuple(_parse_ref(item, kind=kind) for item in value)
    keys = tuple(
        (item.object_id, item.version, item.content_sha256) for item in refs
    )
    if keys != tuple(sorted(set(keys))):
        raise CanonicalGraphParseError
    return refs


def _parse_node(
    raw: object,
) -> tuple[str, dict[str, object]]:
    if not isinstance(raw, dict) or set(raw) != {"attributes", "node_id"}:
        raise CanonicalGraphParseError
    node_id = raw.get("node_id")
    attributes = raw.get("attributes")
    if (
        type(node_id) is not str
        or not node_id
        or not isinstance(attributes, dict)
        or set(attributes) != _NODE_ATTRIBUTE_KEYS
    ):
        raise CanonicalGraphParseError
    reference = _parse_ref(attributes["reference"])
    node_type = attributes["node_type"]
    version = attributes["version"]
    if (
        reference.object_id != node_id
        or type(node_type) is not str
        or node_type not in PUBLIC_GRAPH_NODE_KINDS
        or reference.object_id[:-37] != node_type
        or type(version) is not int
        or version != reference.version
    ):
        raise CanonicalGraphParseError
    return node_id, {
        "reference": reference,
        "node_type": node_type,
        "version": version,
    }


def _parse_edge(
    raw: object,
    *,
    node_ids: frozenset[str],
) -> tuple[str, str, str, dict[str, object]]:
    if not isinstance(raw, dict) or set(raw) != {
        "attributes",
        "edge_id",
        "source",
        "target",
    }:
        raise CanonicalGraphParseError
    source = raw.get("source")
    target = raw.get("target")
    edge_id = raw.get("edge_id")
    attributes = raw.get("attributes")
    if (
        type(source) is not str
        or type(target) is not str
        or type(edge_id) is not str
        or source not in node_ids
        or target not in node_ids
        or source == target
        or not isinstance(attributes, dict)
        or set(attributes) != _EDGE_ATTRIBUTE_KEYS
    ):
        raise CanonicalGraphParseError

    relation_ref = _parse_ref(attributes["relation_ref"], kind="graph_edge")
    wiki_ref = _parse_ref(attributes["wiki_ref"], kind="wiki")
    claim_ref = _parse_ref(attributes["claim_ref"], kind="claim")
    passage_refs = _canonical_refs(attributes["passage_refs"], kind="passage")
    source_refs = _canonical_refs(attributes["source_refs"], kind="source")
    provenance_ref = _parse_ref(attributes["provenance_ref"])
    raw_theory_ref = attributes["theory_ref"]
    theory_ref = (
        None
        if raw_theory_ref is None
        else _parse_ref(raw_theory_ref, kind="theory")
    )
    relation_scope = _canonical_strings(
        attributes["relation_scope"], required=True
    )
    allowed_uses = _canonical_strings(attributes["allowed_uses"], required=True)
    independent_source_ids = _canonical_strings(
        attributes["independent_source_ids"], required=True
    )
    effective_from = _parse_datetime(attributes["effective_from"], optional=True)
    effective_to = _parse_datetime(attributes["effective_to"], optional=True)
    review_due_at = _parse_datetime(attributes["review_due_at"], optional=True)
    try:
        applicability = ClaimApplicability.model_validate_json(
            canonical_json_bytes(attributes["applicability"]), strict=True
        )
    except ValueError:
        raise CanonicalGraphParseError from None
    if applicability.model_dump(mode="json") != attributes["applicability"]:
        raise CanonicalGraphParseError

    confidence = attributes["confidence"]
    independent_source_count = attributes["independent_source_count"]
    case_contributor_count = attributes["case_contributor_count"]
    source_grade = attributes["source_grade"]
    cognitive_type = attributes["cognitive_type"]
    empirical_support = attributes["empirical_support"]
    framework_eligibility = attributes["framework_eligibility"]
    privacy_scope = attributes["privacy_scope"]
    provenance_scope = attributes["provenance_scope"]
    theory_status = attributes["theory_status"]
    truth_type = attributes["truth_type"]
    expected_truth_type = (
        "theory_framework"
        if source_grade == "C1"
        else "source_text"
        if source_grade == "T1"
        else "official_fact"
        if source_grade == "L1"
        else "analogy"
        if cognitive_type == "cross_theory_analogy"
        else "interpretation"
    )
    expected_provenance_scope = {
        "global": "global_source",
        "case": "case_derived",
        "mixed": "mixed",
    }.get(privacy_scope)
    if (
        relation_ref.object_id != edge_id
        or attributes["edge_id"] != edge_id
        or attributes["relation"] not in _RELATIONS
        or type(confidence) not in {int, float}
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
        or type(independent_source_count) is not int
        or independent_source_count != len(independent_source_ids)
        or type(case_contributor_count) is not int
        or case_contributor_count < 0
        or type(cognitive_type) is not str
        or cognitive_type not in _COGNITIVE_TYPES
        or type(source_grade) is not str
        or source_grade not in _SOURCE_GRADES
        or type(empirical_support) is not str
        or empirical_support not in _EMPIRICAL_SUPPORT
        or type(framework_eligibility) is not str
        or framework_eligibility not in _FRAMEWORK_ELIGIBILITY
        or type(truth_type) is not str
        or truth_type not in _TRUTH_TYPES
        or truth_type != expected_truth_type
        or attributes["review_status"] != "approved"
        or attributes["passage_review_status"] != "approved"
        or attributes["authorized"] is not True
        or attributes["tombstoned"] is not False
        or "consultation" not in allowed_uses
        or expected_provenance_scope is None
        or provenance_scope != expected_provenance_scope
        or (provenance_scope == "global_source" and case_contributor_count != 0)
        or (provenance_scope != "global_source" and case_contributor_count == 0)
        or any(
            len(value) > 64 or _SAFE_POLICY_KEY.fullmatch(value) is None
            for value in relation_scope
        )
        or any(
            _OBJECT_ID.fullmatch(value) is None
            or value[:-37] not in {"source", "case"}
            for value in independent_source_ids
        )
        or (source_grade == "C1") != (theory_ref is not None)
        or (source_grade == "C1" and theory_status != "active")
        or (source_grade != "C1" and theory_status is not None)
        or attributes["statement_text_sha256"] != claim_ref.content_sha256
        or not isinstance(attributes["statement_text_sha256"], str)
        or _SHA256.fullmatch(attributes["statement_text_sha256"]) is None
        or (effective_from is not None and effective_to is not None and effective_to <= effective_from)
    ):
        raise CanonicalGraphParseError
    return source, target, edge_id, {
        **attributes,
        "allowed_uses": allowed_uses,
        "applicability": applicability.model_dump(mode="json"),
        "claim_ref": claim_ref,
        "confidence": float(confidence),
        "effective_from": effective_from,
        "effective_to": effective_to,
        "independent_source_ids": independent_source_ids,
        "passage_refs": passage_refs,
        "provenance_ref": provenance_ref,
        "relation_ref": relation_ref,
        "relation_scope": relation_scope,
        "review_due_at": review_due_at,
        "source_refs": source_refs,
        "theory_ref": theory_ref,
        "wiki_ref": wiki_ref,
    }


def global_graph_artifact_from_canonical_bytes(
    payload_bytes: bytes,
    *,
    expected_sha256: str,
) -> GlobalGraphArtifact:
    """Strictly restore the exact immutable graph represented by one CAS member."""

    if type(payload_bytes) is not bytes or _SHA256.fullmatch(expected_sha256) is None:
        raise CanonicalGraphParseError
    try:
        payload = json.loads(payload_bytes)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise CanonicalGraphParseError from None
    if (
        not isinstance(payload, dict)
        or set(payload) != _TOP_LEVEL_KEYS
        or payload_bytes != canonical_graph_bytes(payload)
        or hashlib.sha256(payload_bytes).hexdigest() != expected_sha256
        or payload["schema_version"] != GRAPH_SCHEMA_VERSION
        or payload["builder_policy_version"] != "consultation-global-graph.v1"
        or type(payload["source_catalog_version"]) is not int
        or payload["source_catalog_version"] <= 0
        or type(payload["source_runtime_epoch"]) is not int
        or payload["source_runtime_epoch"] <= 0
        or not isinstance(payload["nodes"], list)
        or not isinstance(payload["edges"], list)
    ):
        raise CanonicalGraphParseError
    effective_at = _parse_datetime(payload["effective_at"])
    assert effective_at is not None
    nodes = tuple(_parse_node(value) for value in payload["nodes"])
    if tuple(node for node, _attributes in nodes) != tuple(
        sorted({node for node, _attributes in nodes})
    ):
        raise CanonicalGraphParseError
    node_ids = frozenset(node for node, _attributes in nodes)
    edges = tuple(
        _parse_edge(value, node_ids=node_ids) for value in payload["edges"]
    )
    edge_order = tuple((source, target, edge_id) for source, target, edge_id, _ in edges)
    if edge_order != tuple(sorted(set(edge_order))):
        raise CanonicalGraphParseError

    graph: nx.MultiDiGraph[
        str, dict[str, object], dict[str, object]
    ] = nx.MultiDiGraph()
    graph.graph.update(
        {
            "builder_policy_version": payload["builder_policy_version"],
            "effective_at": effective_at,
            "source_catalog_version": payload["source_catalog_version"],
            "source_runtime_epoch": payload["source_runtime_epoch"],
        }
    )
    for node_id, attributes in nodes:
        graph.add_node(node_id, **attributes)
    for source, target, edge_id, attributes in edges:
        graph.add_edge(source, target, key=edge_id, **attributes)

    from consultation_kb.graph.global_builder import (
        GlobalGraphArtifact,
        graph_dependencies_from_graph,
    )

    return GlobalGraphArtifact(
        graph=graph,
        source_catalog_version=payload["source_catalog_version"],
        source_runtime_epoch=payload["source_runtime_epoch"],
        effective_at=effective_at,
        builder_policy_version=payload["builder_policy_version"],
        canonical_sha256=expected_sha256,
        dependencies=graph_dependencies_from_graph(graph),
    )


__all__ = [
    "CanonicalGraphParseError",
    "GRAPH_SCHEMA_VERSION",
    "canonical_graph_bytes",
    "graph_payload",
    "graph_payload_from_parts",
    "graph_sha256",
    "graph_structure_payload",
    "global_graph_artifact_from_canonical_bytes",
]
