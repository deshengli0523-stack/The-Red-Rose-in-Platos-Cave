"""Build the canonical global MultiDiGraph from governed P3 records.

The graph is deliberately a derived view.  Exact P3 ``VersionRef`` objects
remain attached to every node and edge so no graph result can become evidence
without resolving its approved Claim and Passage closure.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeAlias

import networkx as nx
from pydantic import field_serializer, model_validator

from consultation_kb.models.cases import assert_shared_text_safe
from consultation_kb.models.common import (
    FiniteFloat,
    NonNegativeInt,
    SafePolicyKey,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.knowledge import (
    ClaimRecord,
    PassageRecord,
    ReviewStatus,
    claim_is_current,
)
from consultation_kb.models.graph import GraphRelationKind, PUBLIC_GRAPH_NODE_KINDS
from consultation_kb.models.theory import TheoryRevision
from consultation_kb.models.wiki import WikiRevision
from consultation_kb.knowledge.wiki import wiki_revision_body_sha256


GLOBAL_GRAPH_NODE_KINDS = PUBLIC_GRAPH_NODE_KINDS
RefKey: TypeAlias = tuple[str, int, str]
if TYPE_CHECKING:
    CanonicalGraph: TypeAlias = nx.MultiDiGraph[
        str, dict[str, object], dict[str, object]
    ]
else:
    CanonicalGraph = nx.MultiDiGraph


def ref_key(reference: VersionRef) -> RefKey:
    return (
        reference.object_id,
        reference.version,
        reference.content_sha256,
    )


def _object_kind(reference: VersionRef) -> str:
    return reference.object_id.rsplit("_", maxsplit=1)[0]


def theory_revision_sha256(record: TheoryRevision) -> str:
    """Match the canonical public ``TheoryRevisionService.version_ref`` hash."""

    payload = record.model_dump(mode="json")
    payload.pop("status", None)
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def claim_relation_sha256(
    *,
    wiki_ref: VersionRef,
    source_ref: VersionRef,
    target_ref: VersionRef,
    claim_ref: VersionRef,
    relation: GraphRelationKind,
    scope: tuple[str, ...],
    review_status: ReviewStatus,
    effective_from: datetime | None,
    effective_to: datetime | None,
    confidence_override: float | None,
) -> str:
    """Hash every reviewed relation field under one exact Wiki revision."""

    payload = {
        "claim_ref": claim_ref.model_dump(mode="json"),
        "confidence_override": confidence_override,
        "effective_from": (
            None if effective_from is None else effective_from.isoformat()
        ),
        "effective_to": None if effective_to is None else effective_to.isoformat(),
        "relation": relation,
        "review_status": review_status,
        "scope": list(scope),
        "source_ref": source_ref.model_dump(mode="json"),
        "target_ref": target_ref.model_dump(mode="json"),
        "wiki_ref": wiki_ref.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class GlobalGraphBuildError(RuntimeError):
    """A governed authority snapshot cannot safely produce a graph."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GovernedClaim(StrictModel):
    """An exact Claim reference already verified by the P3 Claim service."""

    reference: VersionRef
    record: ClaimRecord

    @model_validator(mode="after")
    def _exact_identity(self) -> "GovernedClaim":
        if (
            self.reference.object_id != self.record.claim_id
            or self.reference.version != self.record.version
            or self.reference.content_sha256 != self.record.text_sha256
        ):
            raise ValueError("governed Claim reference is not exact")
        return self


class GovernedPassage(StrictModel):
    """An exact Passage reference already verified by the P3 Passage catalog."""

    reference: VersionRef
    record: PassageRecord

    @model_validator(mode="after")
    def _exact_identity(self) -> "GovernedPassage":
        if (
            self.reference.object_id != self.record.passage_id
            or self.reference.version != self.record.version
            or self.reference.content_sha256 != self.record.normalized_text_sha256
        ):
            raise ValueError("governed Passage reference is not exact")
        return self


class GovernedTheory(StrictModel):
    """An exact C1 revision returned by the P3 Theory service."""

    reference: VersionRef
    record: TheoryRevision

    @model_validator(mode="after")
    def _exact_identity(self) -> "GovernedTheory":
        if (
            self.reference.object_id != self.record.theory_id
            or self.reference.version != self.record.revision
            or self.reference.content_sha256 != theory_revision_sha256(self.record)
        ):
            raise ValueError(
                "governed Theory reference must match its canonical revision hash"
            )
        return self


class GovernedWiki(StrictModel):
    """An exact active Wiki revision that governs graph relationships."""

    reference: VersionRef
    record: WikiRevision

    @model_validator(mode="after")
    def _exact_identity(self) -> "GovernedWiki":
        if (
            self.reference.object_id != self.record.wiki_id
            or self.reference.version != self.record.revision
            or self.record.status != "active"
            or self.reference.content_sha256 != wiki_revision_body_sha256(self.record)
            or self.record.body_sha256 != wiki_revision_body_sha256(self.record)
        ):
            raise ValueError("governed Wiki reference is not exact")
        return self


class ClaimRelation(StrictModel):
    """A reviewed semantic relation whose evidence is one exact Claim."""

    relation_ref: VersionRef
    wiki_ref: VersionRef
    source_ref: VersionRef
    target_ref: VersionRef
    claim_ref: VersionRef
    relation: GraphRelationKind
    scope: tuple[SafePolicyKey, ...]
    review_status: ReviewStatus
    effective_from: UtcDateTime | None
    effective_to: UtcDateTime | None
    confidence_override: FiniteFloat | None = None

    @model_validator(mode="after")
    def _valid_relation(self) -> "ClaimRelation":
        if _object_kind(self.relation_ref) != "graph_edge":
            raise ValueError("global relation reference type is not public-safe")
        if self.source_ref == self.target_ref:
            raise ValueError("global relation cannot be a self loop")
        if any(
            _object_kind(reference) not in GLOBAL_GRAPH_NODE_KINDS
            for reference in (self.source_ref, self.target_ref)
        ):
            raise ValueError("global relation node type is not public-safe")
        if not self.scope or self.scope != tuple(sorted(set(self.scope))):
            raise ValueError("global relation scope must be canonical")
        if self.effective_from is not None and self.effective_to is not None:
            if self.effective_to <= self.effective_from:
                raise ValueError("relation effective interval must be increasing")
        if self.confidence_override is not None and not 0 <= self.confidence_override <= 1:
            raise ValueError("relation confidence must be within zero and one")
        expected_sha256 = claim_relation_sha256(
            wiki_ref=self.wiki_ref,
            source_ref=self.source_ref,
            target_ref=self.target_ref,
            claim_ref=self.claim_ref,
            relation=self.relation,
            scope=tuple(self.scope),
            review_status=self.review_status,
            effective_from=self.effective_from,
            effective_to=self.effective_to,
            confidence_override=(
                None
                if self.confidence_override is None
                else float(self.confidence_override)
            ),
        )
        if self.relation_ref.content_sha256 != expected_sha256:
            raise ValueError("global relation reference hash is not canonical")
        return self


class GraphAuthoritySnapshot(StrictModel):
    """Frozen ID/hash/status-only authority plus already-governed records."""

    catalog_version: NonNegativeInt
    runtime_epoch: NonNegativeInt
    effective_at: UtcDateTime
    claims: tuple[GovernedClaim, ...]
    passages: tuple[GovernedPassage, ...]
    theories: tuple[GovernedTheory, ...]
    wikis: tuple[GovernedWiki, ...]
    relations: tuple[ClaimRelation, ...]
    tombstoned_refs: frozenset[RefKey] = frozenset()

    @model_validator(mode="after")
    def _unique_exact_authority(self) -> "GraphAuthoritySnapshot":
        for label, values in (
            ("Claim", self.claims),
            ("Passage", self.passages),
            ("Theory", self.theories),
            ("Wiki", self.wikis),
        ):
            stable_ids = [value.reference.object_id for value in values]
            if len(stable_ids) != len(set(stable_ids)):
                raise ValueError(f"stable {label} ID has multiple versions")
        relation_ids = [value.relation_ref.object_id for value in self.relations]
        if len(relation_ids) != len(set(relation_ids)):
            raise ValueError("stable relation ID has multiple versions")
        node_versions: dict[str, RefKey] = {}
        for relation in self.relations:
            for reference in (relation.source_ref, relation.target_ref):
                key = ref_key(reference)
                previous = node_versions.setdefault(reference.object_id, key)
                if previous != key:
                    raise ValueError("stable graph node ID has multiple versions")
        return self

    @field_serializer("tombstoned_refs")
    def _serialize_tombstones(self, value: frozenset[RefKey]) -> list[list[object]]:
        return [list(item) for item in sorted(value)]


class GraphAuthority(Protocol):
    def snapshot(self, catalog_version: int) -> GraphAuthoritySnapshot: ...


class StaticGraphAuthority:
    """Small immutable adapter useful for build orchestration and tests."""

    def __init__(self, value: GraphAuthoritySnapshot) -> None:
        self._value = value

    def snapshot(self, catalog_version: int) -> GraphAuthoritySnapshot:
        if catalog_version != self._value.catalog_version:
            raise GlobalGraphBuildError("GRAPH_CATALOG_VERSION_MISMATCH")
        return self._value


@dataclass(frozen=True, slots=True)
class GraphDependency:
    upstream_type: Literal["source", "passage", "claim", "theory", "wiki"]
    upstream_ref: VersionRef
    dependency_kind: Literal["content", "metadata", "authority", "provenance"]


class ArtifactDependencyRegistrar(Protocol):
    def register_dependency(
        self,
        *,
        upstream_type: str,
        upstream_ref: VersionRef,
        downstream_artifact_ref: VersionRef,
        dependency_kind: Literal[
            "content", "metadata", "authority", "provenance"
        ],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class GlobalGraphArtifact:
    graph: CanonicalGraph
    source_catalog_version: int
    source_runtime_epoch: int
    effective_at: datetime
    builder_policy_version: str
    canonical_sha256: str
    dependencies: tuple[GraphDependency, ...]

    def __post_init__(self) -> None:
        verify_global_graph_artifact(self)
        seal_canonical_graph(self.graph)
        verify_global_graph_artifact(self)


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, tuple | list):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_deep_freeze(item) for item in value)
    return value


def seal_canonical_graph(graph: CanonicalGraph) -> None:
    """Freeze structure and every public metadata/attribute mapping in place."""

    nx.freeze(graph)
    raw_graph: Any = graph
    for node, attributes in list(raw_graph.nodes(data=True)):
        raw_graph._node[node] = _deep_freeze(dict(attributes))
    for source, target, key, attributes in list(
        raw_graph.edges(keys=True, data=True)
    ):
        frozen = _deep_freeze(dict(attributes))
        raw_graph._succ[source][target][key] = frozen
        raw_graph._pred[target][source][key] = frozen
    raw_graph.graph = _deep_freeze(dict(raw_graph.graph))


def verify_global_graph_artifact(artifact: GlobalGraphArtifact) -> None:
    """Recompute the artifact closure before any graph consumer may use it."""

    metadata = artifact.graph.graph
    if (
        metadata.get("source_catalog_version") != artifact.source_catalog_version
        or metadata.get("source_runtime_epoch") != artifact.source_runtime_epoch
        or metadata.get("effective_at") != artifact.effective_at
        or metadata.get("builder_policy_version") != artifact.builder_policy_version
    ):
        raise GlobalGraphBuildError("GRAPH_ARTIFACT_METADATA_MISMATCH")
    from consultation_kb.graph.serialization import graph_payload, graph_sha256

    if graph_sha256(graph_payload(artifact)) != artifact.canonical_sha256:
        raise GlobalGraphBuildError("GRAPH_ARTIFACT_HASH_MISMATCH")
    if artifact.dependencies != graph_dependencies_from_graph(artifact.graph):
        raise GlobalGraphBuildError("GRAPH_ARTIFACT_DEPENDENCY_MISMATCH")


def graph_dependencies_from_graph(
    graph: CanonicalGraph,
) -> tuple[GraphDependency, ...]:
    """Reconstruct the only valid dependency closure from canonical edges."""

    dependency_map: dict[tuple[str, RefKey], GraphDependency] = {}
    for _source, _target, key, attributes in graph.edges(
        keys=True, data=True
    ):
        relation_ref = attributes.get("relation_ref")
        claim_ref = attributes.get("claim_ref")
        wiki_ref = attributes.get("wiki_ref")
        passage_refs = attributes.get("passage_refs")
        source_refs = attributes.get("source_refs")
        theory_ref = attributes.get("theory_ref")
        if (
            not isinstance(relation_ref, VersionRef)
            or relation_ref.object_id != str(key)
            or _object_kind(relation_ref) != "graph_edge"
            or not isinstance(claim_ref, VersionRef)
            or not isinstance(wiki_ref, VersionRef)
            or not isinstance(passage_refs, tuple)
            or not passage_refs
            or any(not isinstance(value, VersionRef) for value in passage_refs)
            or not isinstance(source_refs, tuple)
            or not source_refs
            or any(not isinstance(value, VersionRef) for value in source_refs)
            or (theory_ref is not None and not isinstance(theory_ref, VersionRef))
        ):
            raise GlobalGraphBuildError("GRAPH_ARTIFACT_EDGE_CLOSURE_INVALID")
        for source_ref in source_refs:
            dependency_map[("source", ref_key(source_ref))] = GraphDependency(
                upstream_type="source",
                upstream_ref=source_ref,
                dependency_kind="metadata",
            )
        for passage_ref in passage_refs:
            dependency_map[("passage", ref_key(passage_ref))] = GraphDependency(
                upstream_type="passage",
                upstream_ref=passage_ref,
                dependency_kind="provenance",
            )
        dependency_map[("claim", ref_key(claim_ref))] = GraphDependency(
            upstream_type="claim",
            upstream_ref=claim_ref,
            dependency_kind="authority",
        )
        dependency_map[("wiki", ref_key(wiki_ref))] = GraphDependency(
            upstream_type="wiki",
            upstream_ref=wiki_ref,
            dependency_kind="authority",
        )
        if isinstance(theory_ref, VersionRef):
            dependency_map[("theory", ref_key(theory_ref))] = GraphDependency(
                upstream_type="theory",
                upstream_ref=theory_ref,
                dependency_kind="authority",
            )
    return tuple(
        value
        for _key, value in sorted(
            dependency_map.items(),
            key=lambda item: (item[0][0], item[0][1]),
        )
    )


def register_graph_dependencies(
    artifact: GlobalGraphArtifact,
    downstream_artifact_ref: VersionRef,
    registrar: ArtifactDependencyRegistrar,
) -> None:
    """Bind every exact upstream to the persisted graph artifact version."""

    verify_global_graph_artifact(artifact)
    downstream = VersionRef.model_validate(downstream_artifact_ref)
    if downstream.content_sha256 != artifact.canonical_sha256:
        raise GlobalGraphBuildError("GRAPH_ARTIFACT_REFERENCE_HASH_MISMATCH")
    for dependency in artifact.dependencies:
        registrar.register_dependency(
            upstream_type=dependency.upstream_type,
            upstream_ref=dependency.upstream_ref,
            downstream_artifact_ref=downstream,
            dependency_kind=dependency.dependency_kind,
        )


def _current_interval(
    *,
    effective_at: datetime,
    starts: tuple[datetime | None, ...],
    ends: tuple[datetime | None, ...],
) -> bool:
    return all(value is None or value <= effective_at for value in starts) and all(
        value is None or effective_at < value for value in ends
    )


def _confidence(claim: ClaimRecord, relation: ClaimRelation) -> float:
    if relation.confidence_override is not None:
        return float(relation.confidence_override)
    if claim.model_confidence is not None:
        return float(claim.model_confidence)
    return 1.0 if claim.cognitive_type == "explicit" else 0.75


def _truth_type(claim: ClaimRecord) -> str:
    if claim.source_grade == "C1":
        return "theory_framework"
    if claim.source_grade == "T1":
        return "source_text"
    if claim.source_grade == "L1":
        return "official_fact"
    if claim.cognitive_type == "cross_theory_analogy":
        return "analogy"
    return "interpretation"


def _assert_case_claim_graph_safe(
    claim: ClaimRecord,
    passages: tuple[GovernedPassage, ...],
) -> None:
    """Verify case lineage and text before it can become a graph edge."""

    provenance = claim.provenance
    if provenance.provenance_scope not in {"case_derived", "mixed"}:
        return
    if any(
        client_id in claim.text for client_id in provenance.case_contributor_client_ids
    ):
        raise GlobalGraphBuildError("GRAPH_CASE_TEXT_CONTAINS_CLIENT_ID")
    try:
        assert_shared_text_safe(claim.text)
    except ValueError:
        raise GlobalGraphBuildError("GRAPH_CASE_TEXT_UNSAFE") from None

    passage_provenance = tuple(value.record.provenance for value in passages)
    case_ids = frozenset(
        case_id for value in passage_provenance for case_id in value.case_ids
    )
    contributor_ids = frozenset(
        client_id
        for value in passage_provenance
        for client_id in value.case_contributor_client_ids
    )
    source_ids = frozenset(
        source_id for value in passage_provenance for source_id in value.source_ids
    )
    if (
        case_ids != provenance.case_ids
        or contributor_ids != provenance.case_contributor_client_ids
        or source_ids != provenance.source_ids
    ):
        raise GlobalGraphBuildError("GRAPH_CASE_PROVENANCE_CLOSURE_INVALID")


class GlobalGraphBuilder:
    """Create a canonical evidence-preserving graph from one authority epoch."""

    POLICY_VERSION = "consultation-global-graph.v1"

    def __init__(
        self,
        authority: GraphAuthority,
        *,
        required_use: str = "consultation",
    ) -> None:
        if not required_use:
            raise ValueError("required_use must be nonempty")
        self._authority = authority
        self._required_use = required_use

    def build(
        self,
        catalog_version: int,
        *,
        target_runtime_epoch: int,
    ) -> GlobalGraphArtifact:
        if type(catalog_version) is not int or catalog_version < 0:
            raise ValueError("catalog_version must be a non-negative exact integer")
        if type(target_runtime_epoch) is not int or target_runtime_epoch <= 0:
            raise ValueError("target_runtime_epoch must be a positive exact integer")
        snapshot = self._authority.snapshot(catalog_version)
        if snapshot.catalog_version != catalog_version:
            raise GlobalGraphBuildError("GRAPH_CATALOG_VERSION_MISMATCH")
        if snapshot.runtime_epoch != target_runtime_epoch:
            raise GlobalGraphBuildError("GRAPH_TARGET_RUNTIME_EPOCH_MISMATCH")

        claims = {ref_key(value.reference): value for value in snapshot.claims}
        passages = {ref_key(value.reference): value for value in snapshot.passages}
        theories = {ref_key(value.reference): value for value in snapshot.theories}
        wikis = {ref_key(value.reference): value for value in snapshot.wikis}
        graph: CanonicalGraph = nx.MultiDiGraph()
        graph.graph.update(
            {
                "builder_policy_version": self.POLICY_VERSION,
                "effective_at": snapshot.effective_at,
                "source_catalog_version": snapshot.catalog_version,
                "source_runtime_epoch": target_runtime_epoch,
            }
        )
        dependency_map: dict[
            tuple[str, RefKey], GraphDependency
        ] = {}

        for relation in sorted(
            snapshot.relations,
            key=lambda item: ref_key(item.relation_ref),
        ):
            claim_authority = claims.get(ref_key(relation.claim_ref))
            if claim_authority is None:
                raise GlobalGraphBuildError("GRAPH_AUTHORITY_CLOSURE_INVALID")
            claim = claim_authority.record
            wiki_authority = wikis.get(ref_key(relation.wiki_ref))
            if wiki_authority is None:
                raise GlobalGraphBuildError("GRAPH_WIKI_AUTHORITY_CLOSURE_INVALID")
            wiki = wiki_authority.record
            passage_authorities: list[GovernedPassage] = []
            for passage_ref in claim.passage_refs:
                passage = passages.get(ref_key(passage_ref))
                if passage is None:
                    raise GlobalGraphBuildError("GRAPH_AUTHORITY_CLOSURE_INVALID")
                passage_authorities.append(passage)

            governed_refs = (
                relation.relation_ref,
                relation.source_ref,
                relation.target_ref,
                relation.claim_ref,
                relation.wiki_ref,
                *claim.passage_refs,
            )
            if any(ref_key(value) in snapshot.tombstoned_refs for value in governed_refs):
                continue
            if relation.review_status != "approved" or claim.review_status != "approved":
                continue
            if wiki.status != "active":
                continue
            if (
                wiki.created_at > snapshot.effective_at
                or (
                    wiki.review_due_at is not None
                    and wiki.review_due_at <= snapshot.effective_at
                )
            ):
                continue
            if any(value.record.review_status != "approved" for value in passage_authorities):
                continue
            _assert_case_claim_graph_safe(claim, tuple(passage_authorities))
            if self._required_use not in claim.allowed_uses:
                continue
            if not claim_is_current(claim, at=snapshot.effective_at):
                continue
            if not _current_interval(
                effective_at=snapshot.effective_at,
                starts=(relation.effective_from,),
                ends=(relation.effective_to,),
            ):
                continue

            theory_ref = claim.theory_revision_ref
            theory_status: str | None = None
            if claim.source_grade == "C1":
                if theory_ref is None:
                    raise GlobalGraphBuildError("GRAPH_C1_AUTHORITY_INVALID")
                theory_authority = theories.get(ref_key(theory_ref))
                if theory_authority is None:
                    raise GlobalGraphBuildError("GRAPH_AUTHORITY_CLOSURE_INVALID")
                governed_refs = (*governed_refs, theory_ref)
                if ref_key(theory_ref) in snapshot.tombstoned_refs:
                    continue
                theory = theory_authority.record
                theory_status = theory.status
                if theory.status != "active":
                    continue
                if not _current_interval(
                    effective_at=snapshot.effective_at,
                    starts=(theory.effective_from,),
                    ends=(theory.effective_to,),
                ):
                    continue
                if relation.claim_ref not in theory.claim_refs or not set(
                    claim.passage_refs
                ) <= set(theory.passage_refs):
                    raise GlobalGraphBuildError("GRAPH_C1_AUTHORITY_INVALID")

            source_refs = tuple(
                sorted(
                    {value.record.source_ref for value in passage_authorities},
                    key=ref_key,
                )
            )
            stable_passage_source_ids = {
                value.record.source_ref.object_id for value in passage_authorities
            }
            if (
                claim.provenance.provenance_scope == "global_source"
                and stable_passage_source_ids != set(claim.provenance.source_ids)
            ):
                raise GlobalGraphBuildError("GRAPH_PROVENANCE_CLOSURE_INVALID")
            independent_source_ids = tuple(
                sorted(
                    set(claim.provenance.source_ids)
                    | set(claim.provenance.case_ids)
                )
            )
            if not independent_source_ids:
                raise GlobalGraphBuildError("GRAPH_PROVENANCE_CLOSURE_INVALID")
            if claim.privacy_scope == "private":
                continue
            wiki_sections = tuple(
                section
                for section in wiki.sections
                if relation.claim_ref in section.claim_refs
            )
            if not wiki_sections or not set(claim.passage_refs) <= {
                passage_ref
                for section in wiki_sections
                for passage_ref in section.passage_refs
            }:
                raise GlobalGraphBuildError("GRAPH_RELATION_WIKI_BINDING_INVALID")
            wiki_relationships = tuple(
                value
                for value in wiki.graph_relations
                if (
                    value.source_ref == relation.source_ref
                    and value.target_ref == relation.target_ref
                    and value.claim_ref == relation.claim_ref
                    and value.relation == relation.relation
                    and tuple(value.scope) == tuple(relation.scope)
                    and value.review_status == relation.review_status
                    and value.effective_from == relation.effective_from
                    and value.effective_to == relation.effective_to
                    and value.confidence_override == relation.confidence_override
                )
            )
            if len(wiki_relationships) != 1:
                raise GlobalGraphBuildError("GRAPH_RELATION_WIKI_BINDING_INVALID")
            for source_ref in source_refs:
                dependency_map[("source", ref_key(source_ref))] = GraphDependency(
                    upstream_type="source",
                    upstream_ref=source_ref,
                    dependency_kind="metadata",
                )
            for passage_ref in claim.passage_refs:
                dependency_map[("passage", ref_key(passage_ref))] = GraphDependency(
                    upstream_type="passage",
                    upstream_ref=passage_ref,
                    dependency_kind="provenance",
                )
            dependency_map[("claim", ref_key(relation.claim_ref))] = GraphDependency(
                upstream_type="claim",
                upstream_ref=relation.claim_ref,
                dependency_kind="authority",
            )
            if theory_ref is not None:
                dependency_map[("theory", ref_key(theory_ref))] = GraphDependency(
                    upstream_type="theory",
                    upstream_ref=theory_ref,
                    dependency_kind="authority",
                )
            dependency_map[("wiki", ref_key(relation.wiki_ref))] = GraphDependency(
                upstream_type="wiki",
                upstream_ref=relation.wiki_ref,
                dependency_kind="authority",
            )
            for node_ref in (relation.source_ref, relation.target_ref):
                graph.add_node(
                    node_ref.object_id,
                    reference=node_ref,
                    node_type=node_ref.object_id.rsplit("_", maxsplit=1)[0],
                    version=node_ref.version,
                )
            effective_starts = tuple(
                value
                for value in (claim.effective_from, relation.effective_from)
                if value is not None
            )
            effective_ends = tuple(
                value
                for value in (claim.effective_to, relation.effective_to)
                if value is not None
            )
            graph.add_edge(
                relation.source_ref.object_id,
                relation.target_ref.object_id,
                key=relation.relation_ref.object_id,
                edge_id=relation.relation_ref.object_id,
                relation_ref=relation.relation_ref,
                wiki_ref=relation.wiki_ref,
                claim_ref=relation.claim_ref,
                passage_refs=tuple(sorted(claim.passage_refs, key=ref_key)),
                source_refs=source_refs,
                relation=relation.relation,
                relation_scope=tuple(relation.scope),
                confidence=_confidence(claim, relation),
                cognitive_type=claim.cognitive_type,
                source_grade=claim.source_grade,
                empirical_support=claim.empirical_support,
                framework_eligibility=claim.framework_eligibility,
                review_status="approved",
                passage_review_status="approved",
                effective_from=max(effective_starts) if effective_starts else None,
                effective_to=min(effective_ends) if effective_ends else None,
                review_due_at=claim.review_due_at,
                applicability=claim.applicability.model_dump(mode="json"),
                allowed_uses=tuple(sorted(claim.allowed_uses)),
                privacy_scope=claim.privacy_scope,
                provenance_scope=claim.provenance.provenance_scope,
                provenance_ref=claim.provenance.derivation_rule_ref,
                independent_source_ids=independent_source_ids,
                independent_source_count=len(independent_source_ids),
                case_contributor_count=len(
                    claim.provenance.case_contributor_client_ids
                ),
                theory_ref=theory_ref,
                theory_status=theory_status,
                truth_type=_truth_type(claim),
                statement_text_sha256=claim.text_sha256,
                authorized=True,
                tombstoned=False,
            )

        from consultation_kb.graph.serialization import (
            graph_payload_from_parts,
            graph_sha256,
        )

        payload = graph_payload_from_parts(
            graph,
            source_catalog_version=snapshot.catalog_version,
            source_runtime_epoch=target_runtime_epoch,
            effective_at=snapshot.effective_at,
            builder_policy_version=self.POLICY_VERSION,
        )
        return GlobalGraphArtifact(
            graph=graph,
            source_catalog_version=snapshot.catalog_version,
            source_runtime_epoch=target_runtime_epoch,
            effective_at=snapshot.effective_at,
            builder_policy_version=self.POLICY_VERSION,
            canonical_sha256=graph_sha256(payload),
            dependencies=tuple(
                value
                for _key, value in sorted(
                    dependency_map.items(),
                    key=lambda item: (item[0][0], item[0][1]),
                )
            ),
        )


__all__ = [
    "CanonicalGraph",
    "ClaimRelation",
    "GLOBAL_GRAPH_NODE_KINDS",
    "ArtifactDependencyRegistrar",
    "GraphDependency",
    "GlobalGraphArtifact",
    "GlobalGraphBuildError",
    "GlobalGraphBuilder",
    "graph_dependencies_from_graph",
    "seal_canonical_graph",
    "verify_global_graph_artifact",
    "GraphAuthority",
    "GraphAuthoritySnapshot",
    "GovernedClaim",
    "GovernedPassage",
    "GovernedTheory",
    "GovernedWiki",
    "RefKey",
    "StaticGraphAuthority",
    "ref_key",
    "register_graph_dependencies",
    "theory_revision_sha256",
    "claim_relation_sha256",
]
