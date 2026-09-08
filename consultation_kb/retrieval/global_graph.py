"""Body-free production retrieval over one exact governed global graph root."""

from __future__ import annotations

from typing import Protocol

from pydantic import field_validator, model_validator

from consultation_kb.graph.artifact_contracts import (
    GraphBuildManifestPayload,
    GraphEdgeAuthorityCatalogPayload,
    verify_graph_build_closure,
    verify_graph_member_payloads,
)
from consultation_kb.graph.authority_filter import GraphEdgeAuthorityResolver
from consultation_kb.graph.global_builder import (
    GlobalGraphArtifact,
    ref_key,
    verify_global_graph_artifact,
)
from consultation_kb.graph.path_cost import PathCostContext
from consultation_kb.graph.weighted_path import EvidencePathStep, WeightedPathQuery
from consultation_kb.models.common import (
    FiniteFloat,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)

from .artifact_contracts import (
    ArtifactBinding,
    ArtifactBindingIdentity,
    DerivedArtifactBuilderInputV2,
    RetrievalInputAssignment,
    derived_artifact_role_layout,
)
from .contracts import CandidateRef, ScoreComponent


class GlobalGraphRetrieverError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GraphNodeQuery(StrictModel):
    source_node_id: NonEmptyStr
    target_node_id: NonEmptyStr
    score: FiniteFloat = 1.0

    @model_validator(mode="after")
    def _not_self(self) -> "GraphNodeQuery":
        if self.source_node_id == self.target_node_id:
            raise ValueError("graph query endpoints must differ")
        return self


class GraphQueryNodeResolver(Protocol):
    def resolve(
        self,
        query: str,
        scope: RetrievalScope,
        *,
        limit: int,
    ) -> tuple[GraphNodeQuery, ...]: ...


class GraphRouteCandidate(StrictModel):
    relation_refs: tuple[VersionRef, ...]
    candidate: CandidateRef

    @model_validator(mode="after")
    def _body_free_graph_candidate(self) -> "GraphRouteCandidate":
        if (
            not self.relation_refs
            or self.relation_refs
            != tuple(sorted(set(self.relation_refs), key=ref_key))
            or any(
                value.object_id.rsplit("_", maxsplit=1)[0] != "graph_edge"
                for value in self.relation_refs
            )
            or self.candidate.object_type != "claim"
            or self.candidate.reference.object_id.rsplit("_", maxsplit=1)[0]
            != "claim"
            or self.candidate.content_ref.object_id.rsplit("_", maxsplit=1)[0]
            != "passage"
            or self.candidate.channel != "global_graph"
            or self.candidate.filter_binding is not None
        ):
            raise ValueError("graph route candidate is invalid")
        return self


class GraphCandidateCatalogSnapshot(StrictModel):
    build_manifest_ref: VersionRef
    graph_root_ref: VersionRef
    graph_version: VersionRef
    runtime_epoch: NonNegativeInt
    entries: tuple[GraphRouteCandidate, ...]

    @field_validator("entries")
    @classmethod
    def _canonical_entries(
        cls, values: tuple[GraphRouteCandidate, ...]
    ) -> tuple[GraphRouteCandidate, ...]:
        # A retrieval row is an exact Claim+Passage pair.  A Claim may have
        # several governed supporting Passages and none may be collapsed by a
        # relation-keyed dictionary.
        keys = tuple(
            (
                *ref_key(value.candidate.reference),
                *ref_key(value.candidate.content_ref),
            )
            for value in values
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("graph candidate catalog must be exact and canonical")
        return values


class GraphCandidateCatalog(Protocol):
    """Freeze one body-free route catalog in one exact derived root."""

    def snapshot(
        self,
        *,
        graph_root_ref: VersionRef,
        graph_version: VersionRef,
        runtime_epoch: int,
    ) -> GraphCandidateCatalogSnapshot: ...


class StaticGraphCandidateCatalog:
    def __init__(self, snapshot: GraphCandidateCatalogSnapshot) -> None:
        self._snapshot = GraphCandidateCatalogSnapshot.model_validate(snapshot)

    def snapshot(
        self,
        *,
        graph_root_ref: VersionRef,
        graph_version: VersionRef,
        runtime_epoch: int,
    ) -> GraphCandidateCatalogSnapshot:
        if (
            self._snapshot.graph_root_ref != graph_root_ref
            or self._snapshot.graph_version != graph_version
            or self._snapshot.runtime_epoch != runtime_epoch
        ):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_ROOT_MISMATCH")
        return self._snapshot


class GlobalGraphRetriever:
    """Implement ``Retriever`` without opening any Claim or Passage body."""

    def __init__(
        self,
        artifact: GlobalGraphArtifact,
        *,
        artifact_binding: ArtifactBinding,
        edge_authority_resolver: GraphEdgeAuthorityResolver,
        node_resolver: GraphQueryNodeResolver,
        candidate_catalog: GraphCandidateCatalog,
        required_use: str = "consultation",
        max_node_pairs: PositiveInt = 8,
        max_hops: PositiveInt = 4,
        max_expansions: PositiveInt = 10_000,
    ) -> None:
        verify_global_graph_artifact(artifact)
        if type(artifact_binding) is not ArtifactBinding:
            raise TypeError("GLOBAL_GRAPH_ARTIFACT_BINDING_REQUIRED")
        try:
            identity = artifact_binding.verify_current()
        except Exception:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_STALE"
            ) from None
        if (
            identity.artifact_key != "graph"
            or identity.target_runtime_epoch != identity.active_runtime_epoch
            or identity.active_runtime_epoch != artifact.source_runtime_epoch
            or identity.source_catalog_version != artifact.source_catalog_version
            or tuple(member.role for member in identity.members)
            != derived_artifact_role_layout("graph")
        ):
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_INVALID"
            )
        members = {member.role: member for member in identity.members}
        graph_member = members["global_graph"]
        exact_root = identity.root_ref
        exact_version = VersionRef(
            object_id=graph_member.object_id,
            version=identity.source_catalog_version,
            content_sha256=graph_member.content_sha256,
        )
        if (
            exact_version.object_id.rsplit("_", maxsplit=1)[0]
            != "global_graph"
            or exact_version.content_sha256 != artifact.canonical_sha256
            or exact_version.version != artifact.source_catalog_version
            or exact_root == exact_version
            or exact_root.version != artifact.source_catalog_version
        ):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_ROOT_MISMATCH")
        try:
            payloads = {
                role: artifact_binding.path_for(role).read_bytes()
                for role in derived_artifact_role_layout("graph")
            }
            protected_mapping = verify_graph_member_payloads(
                payloads,
                members=identity.members,
            )
            builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
                payloads["graph_builder_input"], strict=True
            )
            build_manifest = GraphBuildManifestPayload.model_validate_json(
                payloads["graph_build_manifest"], strict=True
            )
            authority_catalog = (
                GraphEdgeAuthorityCatalogPayload.model_validate_json(
                    payloads["graph_edge_authority_catalog"], strict=True
                )
            )
            after_load = artifact_binding.verify_current()
        except Exception:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_INVALID"
            ) from None
        if after_load != identity:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_STALE"
            )
        if not callable(getattr(node_resolver, "resolve", None)):
            raise TypeError("GLOBAL_GRAPH_NODE_RESOLVER_REQUIRED")
        if not callable(getattr(candidate_catalog, "snapshot", None)):
            raise TypeError("GLOBAL_GRAPH_CANDIDATE_CATALOG_REQUIRED")
        if not required_use:
            raise ValueError("GLOBAL_GRAPH_REQUIRED_USE_INVALID")
        if (
            type(max_node_pairs) is not int
            or not 1 <= max_node_pairs <= 100
            or type(max_hops) is not int
            or not 1 <= max_hops <= 12
            or type(max_expansions) is not int
            or not 1 <= max_expansions <= 100_000
        ):
            raise ValueError("GLOBAL_GRAPH_QUERY_BUDGET_INVALID")
        self._artifact = artifact
        self._artifact_binding = artifact_binding
        self._binding_identity = identity
        self._root = exact_root
        self._version = exact_version
        build_manifest_member = members["graph_build_manifest"]
        self._build_manifest_ref = VersionRef(
            object_id=build_manifest_member.object_id,
            version=identity.source_catalog_version,
            content_sha256=build_manifest_member.content_sha256,
        )
        self._builder_input = builder_input
        self._build_manifest = build_manifest
        self._protected_catalog = authority_catalog
        self._protected_mapping = protected_mapping
        self._edge_authority = edge_authority_resolver
        self._nodes = node_resolver
        self._candidates = candidate_catalog
        self._required_use = required_use
        self._max_node_pairs = int(max_node_pairs)
        self._max_hops = int(max_hops)
        self._max_expansions = int(max_expansions)
        self._paths = WeightedPathQuery(
            artifact,
            graph_version=exact_version,
            edge_authority_resolver=edge_authority_resolver,
        )

    @property
    def artifact_binding(self) -> ArtifactBinding:
        return self._artifact_binding

    def _verify_artifact_binding(self) -> ArtifactBindingIdentity:
        try:
            identity = self._artifact_binding.verify_current()
        except Exception:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_STALE"
            ) from None
        if identity != self._binding_identity:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ARTIFACT_BINDING_STALE"
            )
        return identity

    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        before: ArtifactBindingIdentity | None = None
        try:
            before = self._verify_artifact_binding()
            return self._search(
                query,
                scope,
                authority_snapshot,
                limit=limit,
            )
        finally:
            after = self._verify_artifact_binding()
            if before is not None and after != before:
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ARTIFACT_BINDING_STALE"
                )

    def _search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        if type(query) is not str or not query.strip():
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_QUERY_INVALID")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("GLOBAL_GRAPH_LIMIT_INVALID")
        exact_scope = RetrievalScope.model_validate(scope)
        exact_snapshot = AuthoritativeFilterSnapshot.model_validate(
            authority_snapshot
        )
        binding = self._edge_authority.resolve(
            self._artifact,
            scope=exact_scope,
            authority_snapshot=exact_snapshot,
            required_use=self._required_use,
            graph_root_ref=self._root,
            graph_version=self._version,
        )
        route_catalog = self._candidates.snapshot(
            graph_root_ref=self._root,
            graph_version=self._version,
            runtime_epoch=self._artifact.source_runtime_epoch,
        )
        if (
            route_catalog.build_manifest_ref != self._build_manifest_ref
            or route_catalog.build_manifest_ref.object_id
            not in exact_snapshot.allowed_ref_ids
            or route_catalog.graph_root_ref != self._root
            or route_catalog.graph_version != self._version
            or route_catalog.runtime_epoch != self._artifact.source_runtime_epoch
        ):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_CATALOG_STALE")
        candidates_by_relation = self._validated_candidates_by_relation(
            route_catalog
        )
        candidates = tuple(entry.candidate for entry in route_catalog.entries)
        try:
            expected_mapping = verify_graph_build_closure(
                self._artifact,
                builder_input=self._builder_input,
                candidates=candidates,
                authority_catalog=self._protected_catalog,
                build_manifest=self._build_manifest,
            )
        except Exception:
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
            ) from None
        if expected_mapping != self._protected_mapping:
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_CATALOG_INVALID")

        raw_pairs = self._nodes.resolve(
            query,
            exact_scope,
            limit=self._max_node_pairs,
        )
        if type(raw_pairs) is not tuple:
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_NODE_RESOLUTION_INVALID")
        pairs = tuple(GraphNodeQuery.model_validate(value) for value in raw_pairs)
        if len(pairs) > self._max_node_pairs or len(pairs) != len(set(pairs)):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_NODE_RESOLUTION_INVALID")

        ranked: dict[
            tuple[str, int, str, str, int, str], tuple[CandidateRef, float]
        ] = {}
        for pair in pairs:
            paths = self._paths.search(
                pair.source_node_id,
                pair.target_node_id,
                context=PathCostContext(
                    effective_at=exact_scope.effective_at,
                    required_use=self._required_use,
                ),
                authority_snapshot=exact_snapshot,
                scope=exact_scope,
                edge_authority_binding=binding,
                max_hops=self._max_hops,
                top_k=min(20, limit),
                max_expansions=self._max_expansions,
                max_candidates=max(100, limit),
            )
            for path in paths:
                for step in path.steps:
                    route_candidates = candidates_by_relation.get(
                        ref_key(step.relation_ref)
                    )
                    if route_candidates is None:
                        raise GlobalGraphRetrieverError(
                            "GLOBAL_GRAPH_ROUTE_CANDIDATE_MISSING"
                        )
                    for candidate in route_candidates:
                        self._validate_candidate(candidate, step, route_catalog)
                        score = round(
                            float(pair.score) / (1.0 + float(path.total_cost)),
                            12,
                        )
                        key = (
                            *ref_key(candidate.reference),
                            *ref_key(candidate.content_ref),
                        )
                        previous = ranked.get(key)
                        if previous is None or score > previous[1]:
                            ranked[key] = (candidate, score)

        ordered = sorted(
            ranked.values(),
            key=lambda item: (
                -item[1],
                ref_key(item[0].reference),
                ref_key(item[0].content_ref),
            ),
        )[:limit]
        return tuple(
            candidate.model_copy(
                update={
                    "score": score,
                    "score_components": (
                        ScoreComponent(
                            channel="global_graph_path",
                            rank=rank,
                            score=score,
                        ),
                    ),
                }
            )
            for rank, (candidate, score) in enumerate(ordered, start=1)
        )

    def _validated_candidates_by_relation(
        self,
        catalog: GraphCandidateCatalogSnapshot,
    ) -> dict[tuple[str, int, str], tuple[CandidateRef, ...]]:
        edge_attributes: dict[tuple[str, int, str], dict[str, object]] = {}
        for *_edge, attributes in self._artifact.graph.edges(data=True):
            relation_ref = attributes.get("relation_ref")
            if not isinstance(relation_ref, VersionRef):
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                )
            key = ref_key(relation_ref)
            if key in edge_attributes:
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                )
            edge_attributes[key] = attributes

        grouped: dict[tuple[str, int, str], list[CandidateRef]] = {}
        protected_rows = {
            (
                *ref_key(row.candidate_ref),
                *ref_key(row.content_ref),
            ): row
            for row in self._protected_mapping.rows
        }
        for entry in catalog.entries:
            pair_key = (
                *ref_key(entry.candidate.reference),
                *ref_key(entry.candidate.content_ref),
            )
            protected_row = protected_rows.get(pair_key)
            try:
                input_record = RetrievalInputAssignment.from_candidate(
                    entry.candidate,
                    target_channels=frozenset({"graph"}),
                ).to_record()
            except (TypeError, ValueError):
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                ) from None
            if (
                protected_row is None
                or tuple(
                    link.relation_ref
                    for link in protected_row.relation_links
                )
                != entry.relation_refs
                or protected_row.authority_manifest_ref
                != entry.candidate.metadata.manifest_ref
                or protected_row.candidate_authority_sha256
                != input_record.candidate_authority_sha256
            ):
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                )
            for relation_ref in entry.relation_refs:
                key = ref_key(relation_ref)
                edge_data = edge_attributes.get(key)
                if edge_data is None:
                    raise GlobalGraphRetrieverError(
                        "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                    )
                self._validate_candidate_against_edge(
                    entry.candidate,
                    edge_data,
                    catalog,
                )
                grouped.setdefault(key, []).append(entry.candidate)

        if set(grouped) != set(edge_attributes):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_CATALOG_INVALID")
        if len(catalog.entries) != len(protected_rows):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_CATALOG_INVALID")
        for key, attributes in edge_attributes.items():
            claim_ref = attributes.get("claim_ref")
            passage_refs = attributes.get("passage_refs")
            if not isinstance(claim_ref, VersionRef) or not isinstance(
                passage_refs, tuple
            ):
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                )
            expected = {
                (*ref_key(claim_ref), *ref_key(passage_ref))
                for passage_ref in passage_refs
                if isinstance(passage_ref, VersionRef)
            }
            actual = {
                (*ref_key(value.reference), *ref_key(value.content_ref))
                for value in grouped[key]
            }
            if len(expected) != len(passage_refs) or actual != expected:
                raise GlobalGraphRetrieverError(
                    "GLOBAL_GRAPH_ROUTE_CATALOG_INVALID"
                )
        return {key: tuple(values) for key, values in grouped.items()}

    def _validate_candidate_against_edge(
        self,
        candidate: CandidateRef,
        attributes: dict[str, object],
        catalog: GraphCandidateCatalogSnapshot,
    ) -> None:
        claim_ref = attributes.get("claim_ref")
        passage_refs = attributes.get("passage_refs")
        source_refs = attributes.get("source_refs")
        if (
            not isinstance(claim_ref, VersionRef)
            or not isinstance(passage_refs, tuple)
            or not isinstance(source_refs, tuple)
            or any(not isinstance(value, VersionRef) for value in passage_refs)
            or any(not isinstance(value, VersionRef) for value in source_refs)
            or candidate.filter_binding is not None
            or candidate.object_type != "claim"
            or candidate.channel != "global_graph"
            or candidate.reference != claim_ref
            or candidate.content_ref not in passage_refs
            or candidate.metadata.manifest_ref == catalog.graph_root_ref
            or self._required_use not in candidate.metadata.allowed_uses
            or candidate.content_ref.object_id
            not in candidate.provenance.passage_ids
            or not candidate.provenance.passage_ids
            <= frozenset(value.object_id for value in passage_refs)
            or not candidate.provenance.source_ids
            or not candidate.provenance.source_ids
            <= frozenset(value.object_id for value in source_refs)
            or candidate.content_ref not in candidate.location.anchor_refs
        ):
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ROUTE_CANDIDATE_INVALID"
            )

    def _validate_candidate(
        self,
        candidate: CandidateRef,
        step: EvidencePathStep,
        catalog: GraphCandidateCatalogSnapshot,
    ) -> None:
        if (
            candidate.filter_binding is not None
            or candidate.channel != "global_graph"
            or candidate.reference != step.claim_ref
            or candidate.content_ref not in step.passage_refs
            or candidate.metadata.manifest_ref == catalog.graph_root_ref
            or self._required_use not in candidate.metadata.allowed_uses
            or candidate.content_ref.object_id
            not in candidate.provenance.passage_ids
            or not candidate.provenance.passage_ids
            <= frozenset(value.object_id for value in step.passage_refs)
            or candidate.content_ref not in candidate.location.anchor_refs
        ):
            raise GlobalGraphRetrieverError(
                "GLOBAL_GRAPH_ROUTE_CANDIDATE_INVALID"
            )


__all__ = [
    "GlobalGraphRetriever",
    "GlobalGraphRetrieverError",
    "GraphCandidateCatalog",
    "GraphCandidateCatalogSnapshot",
    "GraphNodeQuery",
    "GraphQueryNodeResolver",
    "GraphRouteCandidate",
    "StaticGraphCandidateCatalog",
]
