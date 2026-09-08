from __future__ import annotations

from dataclasses import replace

import networkx as nx
import pytest
from pydantic import ValidationError

from consultation_kb.graph.authority_filter import (
    FrozenGraphEdgeAuthorityCatalog,
    GraphAuthoritySnapshotError,
    GraphEdgeAuthorityRecord,
    GraphEdgeAuthorityResolver,
    GraphLeaveOneOutGrant,
    StaticGraphEdgeAuthorityCatalog,
    graph_edge_authority_sha256,
)
from consultation_kb.graph.path_cost import PathCostContext
from consultation_kb.graph.weighted_path import (
    GlobalGraphPathError,
    WeightedPathQuery,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import RetrievalScope
from tests.consultation_kb.graph_support import (
    CLIENT_A,
    CLIENT_B,
    NOW,
    global_graph_artifact,
    graph_authority_snapshot,
    ref,
)


CLIENT_C = "client_" + "c" * 12


def _authority_id(relation_ref: VersionRef) -> str:
    return f"graph_edge_authority_{relation_ref.object_id[-36:]}"


def _edge(
    relation_ref: VersionRef,
    *,
    relation: str = "SUPPORTS",
    relation_scope: tuple[str, ...] = ("consultation",),
    provenance_scope: str = "global_source",
    contributor_count: int = 0,
    independent_source_count: int = 1,
) -> dict[str, object]:
    return {
        "edge_id": relation_ref.object_id,
        "relation_ref": relation_ref,
        "wiki_ref": ref("wiki", "1"),
        "claim_ref": ref("claim", "2"),
        "passage_refs": (ref("passage", "3"),),
        "source_refs": (ref("source", "4"),),
        "relation": relation,
        "relation_scope": relation_scope,
        "confidence": 0.95,
        "cognitive_type": "explicit",
        "source_grade": "C2",
        "review_status": "approved",
        "passage_review_status": "approved",
        "effective_from": NOW,
        "effective_to": None,
        "review_due_at": None,
        "allowed_uses": ("consultation",),
        "privacy_scope": "global",
        "provenance_scope": provenance_scope,
        "case_contributor_count": contributor_count,
        "independent_source_count": independent_source_count,
        "independent_source_ids": tuple(
            ref("source", str(index + 5)).object_id
            for index in range(independent_source_count)
        ),
        "theory_ref": None,
        "theory_status": None,
        "truth_type": "interpretation",
        "statement_text_sha256": "a" * 64,
        "authorized": True,
        "tombstoned": False,
    }


def _artifact(
    primary_ref: VersionRef,
    primary_attributes: dict[str, object],
    replacement_ref: VersionRef | None = None,
    replacement_attributes: dict[str, object] | None = None,
    *,
    replacement_endpoints: tuple[str, str] = ("source", "target"),
):
    graph = nx.MultiDiGraph()
    nodes = {
        "source": ref("concept", "5"),
        "target": ref("concept", "6"),
        "other_source": ref("concept", "7"),
        "other_target": ref("concept", "8"),
    }
    for node, reference in nodes.items():
        graph.add_node(node, reference=reference)
    graph.add_edge(
        "source",
        "target",
        key=primary_ref.object_id,
        **primary_attributes,
    )
    if replacement_ref is not None and replacement_attributes is not None:
        graph.add_edge(
            replacement_endpoints[0],
            replacement_endpoints[1],
            key=replacement_ref.object_id,
            **replacement_attributes,
        )
    return global_graph_artifact(graph)


def _record(
    relation_ref: VersionRef,
    *,
    provenance_scope: str,
    independent_source_count: int,
    contributors: frozenset[str] = frozenset(),
    grants: tuple[GraphLeaveOneOutGrant, ...] = (),
    parent: VersionRef | None = None,
    excluded: frozenset[str] = frozenset(),
    minimum: int = 1,
    runtime_epoch: int = 7,
) -> GraphEdgeAuthorityRecord:
    authority_ref = VersionRef(
        object_id=_authority_id(relation_ref),
        version=relation_ref.version,
        content_sha256="0" * 64,
    )
    digest = graph_edge_authority_sha256(
        relation_ref=relation_ref,
        runtime_epoch=runtime_epoch,
        provenance_scope=provenance_scope,  # type: ignore[arg-type]
        independent_source_count=independent_source_count,
        minimum_leave_one_out_sources=minimum,
        contributor_client_ids=contributors,
        leave_one_out_grants=grants,
        leave_one_out_parent_ref=parent,
        excluded_client_ids=excluded,
    )
    return GraphEdgeAuthorityRecord.model_validate(
        {
            "authority_ref": authority_ref.model_copy(
                update={"content_sha256": digest}
            ),
            "relation_ref": relation_ref,
            "runtime_epoch": runtime_epoch,
            "provenance_scope": provenance_scope,
            "independent_source_count": independent_source_count,
            "minimum_leave_one_out_sources": minimum,
            "contributor_client_ids": contributors,
            "leave_one_out_grants": grants,
            "leave_one_out_parent_ref": parent,
            "excluded_client_ids": excluded,
        }
    )


def _resolve(artifact, records, *, client_id=CLIENT_A, snapshot=None, catalog=None):  # type: ignore[no-untyped-def]
    exact_snapshot = snapshot or graph_authority_snapshot(artifact)
    exact_catalog = catalog or StaticGraphEdgeAuthorityCatalog(
        tuple(records), runtime_epoch=artifact.source_runtime_epoch
    )
    resolver = GraphEdgeAuthorityResolver(exact_catalog)
    scope = RetrievalScope(
        current_client_id=client_id,
        allowed_uses=frozenset({"consultation"}),
        maximum_sensitivity=0,
        effective_at=exact_snapshot.created_at,
        known_at=exact_snapshot.created_at,
    )
    graph_version = ref("global_graph", "9").model_copy(
        update={
            "version": artifact.source_catalog_version,
            "content_sha256": artifact.canonical_sha256,
        }
    )
    graph_root = ref("artifact_manifest", "a").model_copy(
        update={"version": artifact.source_catalog_version}
    )
    binding = resolver.resolve(
        artifact,
        scope=scope,
        authority_snapshot=exact_snapshot,
        required_use="consultation",
        graph_root_ref=graph_root,
        graph_version=graph_version,
    )
    return resolver, scope, binding, exact_snapshot, graph_version


def _valid_loo_bundle(*, minimum: int = 1, replacement_sources: int = 1):
    primary_ref = ref("graph_edge", "b")
    replacement_ref = ref("graph_edge", "c")
    artifact = _artifact(
        primary_ref,
        _edge(
            primary_ref,
            provenance_scope="mixed",
            contributor_count=2,
            independent_source_count=2,
        ),
        replacement_ref,
        _edge(
            replacement_ref,
            provenance_scope="mixed",
            contributor_count=1,
            independent_source_count=replacement_sources,
        ),
    )
    grant = GraphLeaveOneOutGrant(
        excluded_client_id=CLIENT_A,
        replacement_relation_ref=replacement_ref,
    )
    records = (
        _record(
            primary_ref,
            provenance_scope="mixed",
            independent_source_count=2,
            contributors=frozenset({CLIENT_A, CLIENT_B}),
            grants=(grant,),
            minimum=minimum,
        ),
        _record(
            replacement_ref,
            provenance_scope="mixed",
            independent_source_count=replacement_sources,
            contributors=frozenset({CLIENT_B}),
            parent=primary_ref,
            excluded=frozenset({CLIENT_A}),
        ),
    )
    return artifact, primary_ref, replacement_ref, records


def test_self_case_is_replaced_before_path_topology_and_other_client_can_use_primary() -> None:
    artifact, primary_ref, replacement_ref, records = _valid_loo_bundle()
    resolver, scope, binding, snapshot, graph_version = _resolve(
        artifact, records, client_id=CLIENT_A
    )
    assert binding.allowed_relation_refs == (replacement_ref,)
    assert CLIENT_A not in repr(binding)
    paths = WeightedPathQuery(
        artifact,
        graph_version=graph_version,
        edge_authority_resolver=resolver,
    ).search(
        "source",
        "target",
        context=PathCostContext(
            effective_at=NOW,
            required_use="consultation",
        ),
        authority_snapshot=snapshot,
        scope=scope,
        edge_authority_binding=binding,
        max_hops=1,
        top_k=2,
    )
    assert tuple(path.edge_refs for path in paths) == ((replacement_ref,),)

    _resolver, _scope, other_binding, _snapshot, _version = _resolve(
        artifact, records, client_id=CLIENT_C
    )
    assert other_binding.allowed_relation_refs == (primary_ref,)


def test_self_case_without_approved_loo_is_denied() -> None:
    relation_ref = ref("graph_edge", "d")
    artifact = _artifact(
        relation_ref,
        _edge(
            relation_ref,
            provenance_scope="case_derived",
            contributor_count=1,
        ),
    )
    record = _record(
        relation_ref,
        provenance_scope="case_derived",
        independent_source_count=1,
        contributors=frozenset({CLIENT_A}),
    )
    _resolver, _scope, binding, _snapshot, _version = _resolve(
        artifact, (record,)
    )
    assert binding.allowed_relation_refs == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_epoch", 8),
        ("independent_source_count", 3),
        ("minimum_leave_one_out_sources", 2),
        ("contributor_client_ids", frozenset({CLIENT_A, CLIENT_C})),
    ],
)
def test_authority_ref_hash_rejects_metadata_substitution(
    field: str, value: object
) -> None:
    _artifact_value, _primary, _replacement, records = _valid_loo_bundle()
    with pytest.raises(ValidationError, match="hash is not canonical"):
        records[0].model_copy(update={field: value})


def test_authority_ref_hash_rejects_grant_parent_and_excluded_substitution() -> None:
    _artifact_value, primary, replacement, records = _valid_loo_bundle()
    alternate = ref("graph_edge", "e")
    with pytest.raises(ValidationError):
        records[0].model_copy(
            update={
                "leave_one_out_grants": (
                    GraphLeaveOneOutGrant(
                        excluded_client_id=CLIENT_A,
                        replacement_relation_ref=alternate,
                    ),
                )
            }
        )
    with pytest.raises(ValidationError):
        records[1].model_copy(update={"leave_one_out_parent_ref": alternate})
    with pytest.raises(ValidationError):
        records[1].model_copy(
            update={"excluded_client_ids": frozenset({CLIENT_C})}
        )
    assert records[1].leave_one_out_parent_ref == primary
    assert records[1].relation_ref == replacement


@pytest.mark.parametrize("excluded", ["relation", "authority"])
def test_relation_and_authority_must_both_be_live_in_same_snapshot(
    excluded: str,
) -> None:
    relation_ref = ref("graph_edge", "f")
    artifact = _artifact(relation_ref, _edge(relation_ref))
    record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
    )
    excluded_id = (
        relation_ref.object_id
        if excluded == "relation"
        else record.authority_ref.object_id
    )
    snapshot = graph_authority_snapshot(
        artifact,
        excluded_ref_ids=frozenset({excluded_id}),
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID",
    ):
        _resolve(artifact, (record,), snapshot=snapshot)


def test_dormant_bad_grant_fails_for_unrelated_client() -> None:
    primary_ref = ref("graph_edge", "1")
    missing_ref = ref("graph_edge", "2")
    artifact = _artifact(
        primary_ref,
        _edge(
            primary_ref,
            provenance_scope="case_derived",
            contributor_count=1,
        ),
    )
    record = _record(
        primary_ref,
        provenance_scope="case_derived",
        independent_source_count=1,
        contributors=frozenset({CLIENT_A}),
        grants=(
            GraphLeaveOneOutGrant(
                excluded_client_id=CLIENT_A,
                replacement_relation_ref=missing_ref,
            ),
        ),
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID",
    ):
        _resolve(artifact, (record,), client_id=CLIENT_C)


def test_loo_replacement_below_minimum_independent_sources_fails() -> None:
    artifact, _primary, _replacement, records = _valid_loo_bundle(
        minimum=2,
        replacement_sources=1,
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID",
    ):
        _resolve(artifact, records)


@pytest.mark.parametrize("mutation", ["endpoints", "relation", "scope", "use"])
def test_loo_replacement_cannot_change_topology_or_capability(
    mutation: str,
) -> None:
    primary_ref = ref("graph_edge", "3")
    replacement_ref = ref("graph_edge", "4")
    replacement_attributes = _edge(
        replacement_ref,
        provenance_scope="mixed",
        contributor_count=1,
    )
    endpoints = ("source", "target")
    if mutation == "endpoints":
        endpoints = ("other_source", "other_target")
    elif mutation == "relation":
        replacement_attributes["relation"] = "CONTRADICTS"
    elif mutation == "scope":
        replacement_attributes["relation_scope"] = ("planning",)
    else:
        replacement_attributes["allowed_uses"] = ("consultation", "planning")
    artifact = _artifact(
        primary_ref,
        _edge(
            primary_ref,
            provenance_scope="mixed",
            contributor_count=2,
            independent_source_count=2,
        ),
        replacement_ref,
        replacement_attributes,
        replacement_endpoints=endpoints,
    )
    grant = GraphLeaveOneOutGrant(
        excluded_client_id=CLIENT_A,
        replacement_relation_ref=replacement_ref,
    )
    records = (
        _record(
            primary_ref,
            provenance_scope="mixed",
            independent_source_count=2,
            contributors=frozenset({CLIENT_A, CLIENT_B}),
            grants=(grant,),
        ),
        _record(
            replacement_ref,
            provenance_scope="mixed",
            independent_source_count=1,
            contributors=frozenset({CLIENT_B}),
            parent=primary_ref,
            excluded=frozenset({CLIENT_A}),
        ),
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID",
    ):
        _resolve(artifact, records)


def test_client_private_authority_record_is_rejected() -> None:
    relation_ref = ref("graph_edge", "5")
    authority_ref = VersionRef(
        object_id=_authority_id(relation_ref),
        version=1,
        content_sha256="0" * 64,
    )
    with pytest.raises(ValidationError, match="client-private"):
        GraphEdgeAuthorityRecord.model_validate(
            {
                "authority_ref": authority_ref,
                "relation_ref": relation_ref,
                "runtime_epoch": 7,
                "provenance_scope": "client_private",
                "independent_source_count": 1,
            }
        )


def test_missing_forged_and_stale_capabilities_fail_closed() -> None:
    relation_ref = ref("graph_edge", "6")
    artifact = _artifact(relation_ref, _edge(relation_ref))
    record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
    )
    resolver, scope, binding, snapshot, graph_version = _resolve(
        artifact, (record,)
    )
    query = WeightedPathQuery(
        artifact,
        graph_version=graph_version,
        edge_authority_resolver=resolver,
    )
    with pytest.raises(
        GlobalGraphPathError,
        match="GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_REQUIRED",
    ):
        query.search(
            "source",
            "target",
            context=PathCostContext(
                effective_at=NOW,
                required_use="consultation",
            ),
            authority_snapshot=snapshot,
        )
    forged = replace(binding, allowed_relation_refs=())
    with pytest.raises(GraphAuthoritySnapshotError, match="BINDING_INVALID"):
        resolver.assert_binding_current(
            forged,
            artifact,
            scope=scope,
            authority_snapshot=snapshot,
            required_use="consultation",
            graph_root_ref=forged.graph_root_ref,
            graph_version=graph_version,
        )
    newer = snapshot.model_copy(
        update={"global_runtime_epoch": snapshot.global_runtime_epoch + 1}
    )
    with pytest.raises(GraphAuthoritySnapshotError, match="SNAPSHOT_STALE"):
        resolver.assert_binding_current(
            binding,
            artifact,
            scope=scope,
            authority_snapshot=newer,
            required_use="consultation",
            graph_root_ref=binding.graph_root_ref,
            graph_version=graph_version,
        )


def test_same_graph_hash_under_different_route_root_cannot_reuse_binding() -> None:
    relation_ref = ref("graph_edge", "7")
    artifact = _artifact(relation_ref, _edge(relation_ref))
    record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
    )
    resolver, scope, first, snapshot, graph_version = _resolve(
        artifact, (record,)
    )
    second_root = ref("artifact_manifest", "8").model_copy(
        update={"version": artifact.source_catalog_version}
    )
    second = resolver.resolve(
        artifact,
        scope=scope,
        authority_snapshot=snapshot,
        required_use="consultation",
        graph_root_ref=second_root,
        graph_version=graph_version,
    )
    assert first.artifact_sha256 == second.artifact_sha256
    assert first.graph_root_ref != second.graph_root_ref
    assert first.decision_sha256 != second.decision_sha256
    with pytest.raises(GraphAuthoritySnapshotError, match="BINDING_INVALID"):
        resolver.assert_binding_current(
            first,
            artifact,
            scope=scope,
            authority_snapshot=snapshot,
            required_use="consultation",
            graph_root_ref=first.graph_root_ref,
            graph_version=graph_version,
        )


def test_catalog_is_frozen_once_and_never_reads_bodies() -> None:
    relation_ref = ref("graph_edge", "9")
    artifact = _artifact(relation_ref, _edge(relation_ref))
    record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
    )

    class CountingCatalog:
        def __init__(self) -> None:
            self.snapshot_reads = 0
            self.body_reads = 0

        def snapshot(self, runtime_epoch: int) -> FrozenGraphEdgeAuthorityCatalog:
            self.snapshot_reads += 1
            return FrozenGraphEdgeAuthorityCatalog(runtime_epoch, (record,))

    catalog = CountingCatalog()
    _resolve(artifact, (record,), catalog=catalog)
    assert catalog.snapshot_reads == 1
    assert catalog.body_reads == 0


def test_duplicate_exact_relation_in_artifact_is_rejected_before_mapping() -> None:
    relation_ref = ref("graph_edge", "a")
    graph = nx.MultiDiGraph()
    for node, digit in (
        ("source", "1"),
        ("target", "2"),
        ("other_source", "3"),
        ("other_target", "4"),
    ):
        graph.add_node(node, reference=ref("concept", digit))
    graph.add_edge(
        "source",
        "target",
        key=relation_ref.object_id,
        **_edge(relation_ref),
    )
    graph.add_edge(
        "other_source",
        "other_target",
        key=relation_ref.object_id,
        **_edge(relation_ref),
    )
    artifact = global_graph_artifact(graph)
    record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID",
    ):
        _resolve(artifact, (record,))


def test_catalog_epoch_cannot_be_replayed_into_another_graph_epoch() -> None:
    relation_ref = ref("graph_edge", "b")
    artifact = _artifact(relation_ref, _edge(relation_ref))
    stale_record = _record(
        relation_ref,
        provenance_scope="global_source",
        independent_source_count=1,
        runtime_epoch=8,
    )
    stale_catalog = StaticGraphEdgeAuthorityCatalog(
        (stale_record,),
        runtime_epoch=8,
    )
    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_EDGE_AUTHORITY_EPOCH_MISMATCH",
    ):
        _resolve(artifact, (stale_record,), catalog=stale_catalog)
