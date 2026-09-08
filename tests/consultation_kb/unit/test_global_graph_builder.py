from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from consultation_kb.graph.global_builder import (
    ClaimRelation,
    GlobalGraphBuildError,
    GlobalGraphBuilder,
    GraphAuthoritySnapshot,
    GovernedClaim,
    GovernedPassage,
    GovernedTheory,
    GovernedWiki,
    StaticGraphAuthority,
    ref_key,
    register_graph_dependencies,
    theory_revision_sha256,
)
from consultation_kb.graph.serialization import canonical_graph_bytes, graph_payload
from consultation_kb.knowledge.wiki import wiki_revision_body_sha256
from tests.consultation_kb.graph_support import (
    NOW,
    approved_passage,
    governed_claim,
    governed_wikis_for_relations,
    graph_relation,
    ref,
    theory,
)


def _relation(  # type: ignore[no-untyped-def]
    source_ref, target_ref, claim_ref, relation: str, digit: str, claim_record=None
):
    return graph_relation(
        source_ref=source_ref,
        target_ref=target_ref,
        claim_ref=claim_ref,
        relation=relation,
        digit=digit,
        claim_record=claim_record,
    )


def test_builder_preserves_parallel_evidence_edges_and_filters_ineligible_authority() -> None:
    source_node = ref("concept", "1")
    target_node = ref("concept", "2")
    claims: list[GovernedClaim] = []
    passages: list[GovernedPassage] = []
    relations: list[ClaimRelation] = []

    for index, relation in enumerate(
        ("SUPPORTS", "CONTRADICTS", "ANALOGOUS_TO"), start=3
    ):
        passage_ref, passage = approved_passage(digit=str(index))
        claim_ref, claim = governed_claim(
            passage_ref=passage_ref,
            passage=passage,
            text=f"claim-{relation}",
            relation_kind=(
                "cross_theory_analogy" if relation == "ANALOGOUS_TO" else "explicit"
            ),
        )
        passages.append(GovernedPassage(reference=passage_ref, record=passage))
        claims.append(GovernedClaim(reference=claim_ref, record=claim))
        relations.append(
            _relation(
                source_node,
                target_node,
                claim_ref,
                relation,
                str(index),
                claim,
            )
        )

    draft_passage_ref, draft_passage = approved_passage(digit="6")
    draft_claim_ref, draft_claim = governed_claim(
        passage_ref=draft_passage_ref,
        passage=draft_passage,
        text="draft",
        review_status="reviewed",
    )
    passages.append(GovernedPassage(reference=draft_passage_ref, record=draft_passage))
    claims.append(GovernedClaim(reference=draft_claim_ref, record=draft_claim))
    relations.append(
        _relation(
            source_node,
            target_node,
            draft_claim_ref,
            "SUPPORTS",
            "6",
            draft_claim,
        )
    )

    expired_passage_ref, expired_passage = approved_passage(digit="7")
    expired_claim_ref, expired_claim = governed_claim(
        passage_ref=expired_passage_ref,
        passage=expired_passage,
        text="expired",
        effective_to=NOW + timedelta(seconds=1),
    )
    passages.append(GovernedPassage(reference=expired_passage_ref, record=expired_passage))
    claims.append(GovernedClaim(reference=expired_claim_ref, record=expired_claim))
    relations.append(
        _relation(
            source_node,
            target_node,
            expired_claim_ref,
            "SUPPORTS",
            "7",
            expired_claim,
        )
    )

    c1_passage_ref, c1_passage = approved_passage(digit="8")
    provisional_theory_ref = ref("theory", "8")
    c1_claim_ref, c1_claim = governed_claim(
        passage_ref=c1_passage_ref,
        passage=c1_passage,
        text="revoked-c1",
        grade="C1",
        theory_ref=provisional_theory_ref,
    )
    theory_record = theory(
        theory_ref=provisional_theory_ref,
        claim_ref=c1_claim_ref,
        passage_ref=c1_passage_ref,
        status="revoked",
    )
    theory_ref = provisional_theory_ref.model_copy(
        update={"content_sha256": theory_revision_sha256(theory_record)}
    )
    c1_claim = c1_claim.model_copy(update={"theory_revision_ref": theory_ref})
    passages.append(GovernedPassage(reference=c1_passage_ref, record=c1_passage))
    claims.append(GovernedClaim(reference=c1_claim_ref, record=c1_claim))
    relations.append(
        _relation(
            source_node,
            target_node,
            c1_claim_ref,
            "SUPPORTS",
            "8",
            c1_claim,
        )
    )
    revoked_theory = GovernedTheory(reference=theory_ref, record=theory_record)

    tombstoned = _relation(
        source_node,
        target_node,
        claims[0].reference,
        "SUPPORTS",
        "9",
        claims[0].record,
    )
    relations.append(tombstoned)
    snapshot = GraphAuthoritySnapshot(
        catalog_version=11,
        runtime_epoch=4,
        effective_at=NOW + timedelta(seconds=2),
        claims=tuple(claims),
        passages=tuple(passages),
        theories=(revoked_theory,),
        wikis=governed_wikis_for_relations(tuple(relations), tuple(claims)),
        relations=tuple(relations),
        tombstoned_refs=frozenset({ref_key(tombstoned.relation_ref)}),
    )

    artifact = GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
        11, target_runtime_epoch=4
    )

    assert artifact.graph.number_of_edges(source_node.object_id, target_node.object_id) == 3
    assert {
        attributes["relation"]
        for *_edge, attributes in artifact.graph.edges(keys=True, data=True)
    } == {"SUPPORTS", "CONTRADICTS", "ANALOGOUS_TO"}
    assert set(artifact.graph[source_node.object_id][target_node.object_id]) == {
        relation.relation_ref.object_id for relation in relations[:3]
    }
    assert all(attributes["passage_refs"] for *_edge, attributes in artifact.graph.edges(data=True))
    assert artifact.canonical_sha256 == artifact.canonical_sha256.lower()
    with pytest.raises(TypeError):
        artifact.graph[source_node.object_id][target_node.object_id][
            relations[0].relation_ref.object_id
        ]["confidence"] = 0.0
    with pytest.raises(Exception):
        artifact.graph.add_edge(source_node.object_id, "injected")


@pytest.mark.parametrize("private_kind", ["client", "session", "turn", "profile"])
def test_global_relation_rejects_client_private_node_kinds(private_kind: str) -> None:
    with pytest.raises(ValidationError, match="node type is not public-safe"):
        _relation(
            ref(private_kind, "1"),
            ref("concept", "2"),
            ref("claim", "3"),
            "SUPPORTS",
            "4",
        )


def test_global_relation_rejects_client_private_edge_kind() -> None:
    valid = _relation(
        ref("concept", "2"),
        ref("concept", "3"),
        ref("claim", "4"),
        "SUPPORTS",
        "4",
    )
    with pytest.raises(ValidationError, match="reference type is not public-safe"):
        ClaimRelation.model_validate(
            {
                **valid.model_dump(mode="python"),
                "relation_ref": valid.relation_ref.model_copy(
                    update={"object_id": ref("client", "1").object_id}
                ),
            }
        )


def test_claim_relation_rejects_noncanonical_payload_hash() -> None:
    valid = _relation(
        ref("concept", "5"),
        ref("concept", "6"),
        ref("claim", "7"),
        "SUPPORTS",
        "8",
    )
    with pytest.raises(ValidationError, match="reference hash is not canonical"):
        ClaimRelation.model_validate(
            {
                **valid.model_dump(mode="python"),
                "relation_ref": valid.relation_ref.model_copy(
                    update={"content_sha256": "0" * 64}
                ),
            }
        )


def test_missing_exact_passage_closure_fails_closed() -> None:
    passage_ref, passage = approved_passage(digit="a")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="claim",
    )
    relation = _relation(
        ref("concept", "b"),
        ref("concept", "c"),
        claim_ref,
        "SUPPORTS",
        "d",
        claim,
    )
    snapshot = GraphAuthoritySnapshot(
        catalog_version=1,
        runtime_epoch=1,
        effective_at=NOW,
        claims=(GovernedClaim(reference=claim_ref, record=claim),),
        passages=(),
        theories=(),
        wikis=governed_wikis_for_relations(
            (relation,),
            (GovernedClaim(reference=claim_ref, record=claim),),
        ),
        relations=(relation,),
    )

    with pytest.raises(GlobalGraphBuildError, match="GRAPH_AUTHORITY_CLOSURE_INVALID"):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            1, target_runtime_epoch=1
        )


def test_snapshot_rejects_multiple_versions_of_one_stable_relation_id() -> None:
    passage_ref, passage = approved_passage(digit="1")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="claim",
    )
    relation = _relation(
        ref("concept", "2"),
        ref("concept", "3"),
        claim_ref,
        "SUPPORTS",
        "4",
        claim,
    )
    newer_relation = relation.model_copy(
        update={
                "relation_ref": relation.relation_ref.model_copy(
                    update={"version": 2}
                )
        }
    )

    with pytest.raises(ValidationError, match="stable relation ID has multiple versions"):
        GraphAuthoritySnapshot(
            catalog_version=1,
            runtime_epoch=1,
            effective_at=NOW,
            claims=(GovernedClaim(reference=claim_ref, record=claim),),
            passages=(GovernedPassage(reference=passage_ref, record=passage),),
            theories=(),
            wikis=governed_wikis_for_relations(
                (relation,),
                (GovernedClaim(reference=claim_ref, record=claim),),
            ),
            relations=(relation, newer_relation),
        )


def test_governed_c1_reference_hash_must_equal_canonical_revision_hash() -> None:
    passage_ref, passage = approved_passage(digit="6")
    provisional_theory_ref = ref("theory", "7")
    claim_ref, _claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="c1",
        grade="C1",
        theory_ref=provisional_theory_ref,
    )
    record = theory(
        theory_ref=provisional_theory_ref,
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        status="active",
    )
    exact_ref = provisional_theory_ref.model_copy(
        update={"content_sha256": theory_revision_sha256(record)}
    )
    GovernedTheory(reference=exact_ref, record=record)

    with pytest.raises(ValidationError, match="canonical revision hash"):
        GovernedTheory(reference=provisional_theory_ref, record=record)


def test_global_graph_serialization_is_canonical_across_insertion_order() -> None:
    passage_ref, passage = approved_passage(digit="e")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="stable",
    )
    relation = _relation(
        ref("concept", "f"),
        ref("concept", "a"),
        claim_ref,
        "SUPPORTS",
        "b",
        claim,
    )
    snapshot = GraphAuthoritySnapshot(
        catalog_version=2,
        runtime_epoch=3,
        effective_at=NOW,
        claims=(GovernedClaim(reference=claim_ref, record=claim),),
        passages=(GovernedPassage(reference=passage_ref, record=passage),),
        theories=(),
        wikis=governed_wikis_for_relations(
            (relation,),
            (GovernedClaim(reference=claim_ref, record=claim),),
        ),
        relations=(relation,),
    )
    artifact = GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
        2, target_runtime_epoch=3
    )
    first = canonical_graph_bytes(graph_payload(artifact))
    second = canonical_graph_bytes(graph_payload(artifact))
    assert first == second


def test_two_versions_of_one_source_remain_exact_but_count_as_one_independent_source() -> None:
    first_ref, first_passage = approved_passage(digit="c")
    second_ref, second_passage = approved_passage(digit="d")
    same_source_v2 = first_passage.source_ref.model_copy(
        update={"version": 2, "content_sha256": "e" * 64}
    )
    second_passage = second_passage.model_copy(
        update={
            "source_ref": same_source_v2,
            "raw_content_ref": f"sha256:{same_source_v2.content_sha256}",
            "provenance": second_passage.provenance.model_copy(
                update={"source_ids": frozenset({same_source_v2.object_id})}
            ),
        }
    )
    claim_ref, claim = governed_claim(
        passage_ref=first_ref,
        passage=first_passage,
        text="same stable source",
    )
    claim = claim.model_copy(
        update={
            "passage_refs": (first_ref, second_ref),
            "provenance": claim.provenance.model_copy(
                update={
                    "passage_ids": frozenset(
                        {first_ref.object_id, second_ref.object_id}
                    )
                }
            ),
        }
    )
    relation = _relation(
        ref("concept", "f"),
        ref("concept", "1"),
        claim_ref,
        "SUPPORTS",
        "2",
        claim,
    )
    artifact = GlobalGraphBuilder(
        StaticGraphAuthority(
            GraphAuthoritySnapshot(
                catalog_version=3,
                runtime_epoch=1,
                effective_at=NOW,
                claims=(GovernedClaim(reference=claim_ref, record=claim),),
                passages=(
                    GovernedPassage(reference=first_ref, record=first_passage),
                    GovernedPassage(reference=second_ref, record=second_passage),
                ),
                theories=(),
                wikis=governed_wikis_for_relations(
                    (relation,),
                    (GovernedClaim(reference=claim_ref, record=claim),),
                ),
                relations=(relation,),
            )
        )
    ).build(3, target_runtime_epoch=1)
    attributes = next(iter(artifact.graph.edges(data=True)))[2]
    assert len(attributes["source_refs"]) == 2
    assert attributes["independent_source_count"] == 1


def test_graph_artifact_registers_exact_source_passage_and_claim_dependencies() -> None:
    passage_ref, passage = approved_passage(digit="3")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="dependency closure",
    )
    relation = _relation(
        ref("concept", "4"),
        ref("concept", "5"),
        claim_ref,
        "SUPPORTS",
        "6",
        claim,
    )
    artifact = GlobalGraphBuilder(
        StaticGraphAuthority(
            GraphAuthoritySnapshot(
                catalog_version=9,
                runtime_epoch=2,
                effective_at=NOW,
                claims=(GovernedClaim(reference=claim_ref, record=claim),),
                passages=(GovernedPassage(reference=passage_ref, record=passage),),
                theories=(),
                wikis=governed_wikis_for_relations(
                    (relation,),
                    (GovernedClaim(reference=claim_ref, record=claim),),
                ),
                relations=(relation,),
            )
        )
    ).build(9, target_runtime_epoch=2)

    class Recorder:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def register_dependency(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    recorder = Recorder()
    downstream = ref("graph_artifact", "7").model_copy(
        update={"content_sha256": artifact.canonical_sha256}
    )
    register_graph_dependencies(artifact, downstream, recorder)

    assert {call["upstream_type"] for call in recorder.calls} == {
        "source",
        "passage",
        "claim",
        "wiki",
    }
    assert all(call["downstream_artifact_ref"] == downstream for call in recorder.calls)
    assert {
        call["upstream_ref"] for call in recorder.calls
    } == {passage.source_ref, passage_ref, claim_ref, relation.wiki_ref}

    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_ARTIFACT_DEPENDENCY_MISMATCH",
    ):
        replace(artifact, dependencies=())


def test_missing_exact_wiki_closure_fails_closed() -> None:
    passage_ref, passage = approved_passage(digit="9")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="wiki closure",
    )
    relation = _relation(
        ref("concept", "a"),
        ref("concept", "b"),
        claim_ref,
        "SUPPORTS",
        "c",
        claim,
    )
    snapshot = GraphAuthoritySnapshot(
        catalog_version=10,
        runtime_epoch=1,
        effective_at=NOW,
        claims=(GovernedClaim(reference=claim_ref, record=claim),),
        passages=(GovernedPassage(reference=passage_ref, record=passage),),
        theories=(),
        wikis=(),
        relations=(relation,),
    )

    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_WIKI_AUTHORITY_CLOSURE_INVALID",
    ):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            10, target_runtime_epoch=1
        )


def test_wiki_metadata_revision_changes_relation_and_dependency_closure() -> None:
    passage_ref, passage = approved_passage(digit="d")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="wiki metadata revision",
    )
    governed_claim_value = GovernedClaim(reference=claim_ref, record=claim)
    source_node = ref("concept", "e")
    target_node = ref("concept", "f")
    first = _relation(
        source_node, target_node, claim_ref, "SUPPORTS", "1", claim
    )
    wiki_v2 = first.wiki_ref.model_copy(update={"version": 2})
    second_new_id = graph_relation(
        source_ref=source_node,
        target_ref=target_node,
        claim_ref=claim_ref,
        relation="SUPPORTS",
        digit="2",
        wiki_ref=wiki_v2,
        claim_record=claim,
    )
    second = ClaimRelation.model_validate(
        {
            **second_new_id.model_dump(mode="python"),
            "relation_ref": second_new_id.relation_ref.model_copy(
                update={
                    "object_id": first.relation_ref.object_id,
                    "version": 2,
                }
            ),
        }
    )

    def build(relation: ClaimRelation, runtime_epoch: int):
        claims = (governed_claim_value,)
        return GlobalGraphBuilder(
            StaticGraphAuthority(
                GraphAuthoritySnapshot(
                    catalog_version=10 + runtime_epoch,
                    runtime_epoch=runtime_epoch,
                    effective_at=NOW,
                    claims=claims,
                    passages=(
                        GovernedPassage(reference=passage_ref, record=passage),
                    ),
                    theories=(),
                    wikis=governed_wikis_for_relations((relation,), claims),
                    relations=(relation,),
                )
            )
        ).build(10 + runtime_epoch, target_runtime_epoch=runtime_epoch)

    first_artifact = build(first, 1)
    second_artifact = build(second, 2)
    first_wiki = next(
        value
        for value in first_artifact.dependencies
        if value.upstream_type == "wiki"
    )
    second_wiki = next(
        value
        for value in second_artifact.dependencies
        if value.upstream_type == "wiki"
    )
    assert first_wiki.upstream_ref.version == 1
    assert second_wiki.upstream_ref.version == 2
    assert first_artifact.canonical_sha256 != second_artifact.canonical_sha256


@pytest.mark.parametrize(
    "mutation",
    ["source", "target", "kind", "time", "confidence"],
)
def test_wiki_declaration_rejects_canonical_but_undeclared_relation_mutation(
    mutation: str,
) -> None:
    passage_ref, passage = approved_passage(digit="2")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="declared relation",
    )
    governed_claim_value = GovernedClaim(reference=claim_ref, record=claim)
    source = ref("concept", "3")
    target = ref("concept", "4")
    declared = _relation(
        source, target, claim_ref, "SUPPORTS", "5", claim
    )
    changes: dict[str, object] = {}
    if mutation == "source":
        changes["source_ref"] = ref("concept", "6")
    elif mutation == "target":
        changes["target_ref"] = ref("concept", "7")
    elif mutation == "kind":
        changes["relation"] = "CONTRADICTS"
    elif mutation == "time":
        changes["effective_to"] = NOW + timedelta(days=1)
    else:
        changes["confidence_override"] = 0.5
    forged = graph_relation(
        source_ref=changes.get("source_ref", source),  # type: ignore[arg-type]
        target_ref=changes.get("target_ref", target),  # type: ignore[arg-type]
        claim_ref=claim_ref,
        relation=str(changes.get("relation", "SUPPORTS")),
        digit="8",
        wiki_ref=declared.wiki_ref,
        effective_to=changes.get("effective_to"),  # type: ignore[arg-type]
        confidence_override=changes.get("confidence_override"),  # type: ignore[arg-type]
    )
    snapshot = GraphAuthoritySnapshot(
        catalog_version=20,
        runtime_epoch=1,
        effective_at=NOW,
        claims=(governed_claim_value,),
        passages=(GovernedPassage(reference=passage_ref, record=passage),),
        theories=(),
        wikis=governed_wikis_for_relations(
            (declared,), (governed_claim_value,)
        ),
        relations=(forged,),
    )

    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_RELATION_WIKI_BINDING_INVALID",
    ):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            20, target_runtime_epoch=1
        )


def test_governed_wiki_recomputes_body_hash_instead_of_trusting_record_and_ref() -> None:
    passage_ref, passage = approved_passage(digit="a")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="canonical Wiki hash",
    )
    governed_claim_value = GovernedClaim(reference=claim_ref, record=claim)
    relation = _relation(
        ref("concept", "b"),
        ref("concept", "c"),
        claim_ref,
        "SUPPORTS",
        "d",
        claim,
    )
    exact = governed_wikis_for_relations((relation,), (governed_claim_value,))[0]
    forged_digest = "f" * 64
    forged_record = exact.record.model_copy(
        update={
            "title": "forged relation authority",
            "body_sha256": forged_digest,
        }
    )
    forged_ref = exact.reference.model_copy(
        update={"content_sha256": forged_digest}
    )

    with pytest.raises(ValidationError, match="governed Wiki reference is not exact"):
        GovernedWiki(reference=forged_ref, record=forged_record)


def test_old_wiki_without_graph_declaration_cannot_authorize_relation() -> None:
    passage_ref, passage = approved_passage(digit="1")
    claim_ref, claim = governed_claim(
        passage_ref=passage_ref,
        passage=passage,
        text="legacy Wiki body",
    )
    governed_claim_value = GovernedClaim(reference=claim_ref, record=claim)
    declared = _relation(
        ref("concept", "2"),
        ref("concept", "3"),
        claim_ref,
        "SUPPORTS",
        "4",
        claim,
    )
    current_wiki = governed_wikis_for_relations(
        (declared,), (governed_claim_value,)
    )[0]
    legacy_record = current_wiki.record.model_copy(update={"graph_relations": ()})
    legacy_digest = wiki_revision_body_sha256(legacy_record)
    legacy_record = legacy_record.model_copy(update={"body_sha256": legacy_digest})
    legacy_ref = current_wiki.reference.model_copy(
        update={"content_sha256": legacy_digest}
    )
    legacy_relation = graph_relation(
        source_ref=declared.source_ref,
        target_ref=declared.target_ref,
        claim_ref=claim_ref,
        relation=declared.relation,
        digit="5",
        wiki_ref=legacy_ref,
    )
    snapshot = GraphAuthoritySnapshot(
        catalog_version=21,
        runtime_epoch=1,
        effective_at=NOW,
        claims=(governed_claim_value,),
        passages=(GovernedPassage(reference=passage_ref, record=passage),),
        theories=(),
        wikis=(GovernedWiki(reference=legacy_ref, record=legacy_record),),
        relations=(legacy_relation,),
    )

    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_RELATION_WIKI_BINDING_INVALID",
    ):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            21, target_runtime_epoch=1
        )


@pytest.mark.parametrize("wrong_target", [1, 3])
def test_builder_rejects_old_or_future_target_runtime_epoch(
    wrong_target: int,
) -> None:
    snapshot = GraphAuthoritySnapshot(
        catalog_version=22,
        runtime_epoch=2,
        effective_at=NOW,
        claims=(),
        passages=(),
        theories=(),
        wikis=(),
        relations=(),
    )
    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_TARGET_RUNTIME_EPOCH_MISMATCH",
    ):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            22,
            target_runtime_epoch=wrong_target,
        )

    artifact = GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
        22,
        target_runtime_epoch=2,
    )
    assert artifact.source_runtime_epoch == 2
    assert artifact.graph.graph["source_runtime_epoch"] == 2
