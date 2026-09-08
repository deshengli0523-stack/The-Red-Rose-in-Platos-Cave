from __future__ import annotations

import json
from pathlib import Path

import pytest

from consultation_kb.retrieval.artifact_contracts import (
    RetrievalInputDescriptor,
)
from consultation_kb.retrieval.contracts import canonical_json_bytes
from consultation_kb.retrieval.wiki_builder import (
    WikiIndexBuildError,
    WikiNavigationIndexBuilder,
    WikiNavigationIndexPayloadV2,
    WikiNavigationIndexRowV2,
)
from consultation_kb.retrieval.wiki_index import (
    WikiIndexError,
    WikiIndexRetriever,
)
from tests.consultation_kb.retrieval_support import reference, scope, snapshot
from tests.consultation_kb.wiki_index_support import (
    bound_wiki_index,
    build_fixture,
    wiki_fixture,
)


def _payload_with_recomputed_closure(
    payload: dict[str, object],
) -> WikiNavigationIndexPayloadV2:
    values = {
        key: value
        for key, value in payload.items()
        if key != "index_closure_sha256"
    }
    payload["index_closure_sha256"] = (
        WikiNavigationIndexPayloadV2.calculate_closure(values)
    )
    return WikiNavigationIndexPayloadV2.model_validate_json(
        canonical_json_bytes(payload), strict=True
    )


def test_builder_emits_only_navigation_tokens_and_preserves_claim_passage_pairs() -> None:
    source = wiki_fixture()
    built = build_fixture(source)
    rows = built.payload.rows

    assert len(rows) == 3
    first_claim = source.candidates[0].reference
    first_claim_rows = tuple(
        row for row in rows if row.authority.reference == first_claim
    )
    assert len(first_claim_rows) == 2
    assert {row.authority.content_ref for row in first_claim_rows} == {
        source.candidates[0].content_ref,
        source.candidates[1].content_ref,
    }
    assert all(row.section_keys == ("relationship_repair",) for row in first_claim_rows)
    assert all(row.candidate().channel == "wiki" for row in rows)
    assert all(row.candidate().reference.object_id[:-37] == "claim" for row in rows)
    assert all(row.candidate().content_ref.object_id[:-37] == "passage" for row in rows)

    serialized = built.index_bytes.decode("utf-8")
    assert "来访者在关系破裂后先辨认重复出现的依恋循环" not in serialized
    assert '"body"' not in serialized
    assert "client_" + "a1b2c3d4e5f6" not in serialized
    assert "word_tokens" in serialized
    assert "character_2grams" in serialized
    assert "character_3grams" in serialized
    assert built.build_manifest.member_content_sha256 == {
        "wiki_index": __import__("hashlib").sha256(built.index_bytes).hexdigest()
    }


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "forged"])
def test_builder_rejects_any_assignment_omission_extra_or_forgery(
    mutation: str,
) -> None:
    source = wiki_fixture()
    assignments = source.assignments
    if mutation == "missing":
        attacked = assignments[:-1]
    elif mutation == "duplicate":
        attacked = (*assignments, assignments[0])
    else:
        authority = assignments[0].authority.model_copy(
            update={
                "metadata": assignments[0].authority.metadata.model_copy(
                    update={"manifest_ref": reference("artifact_manifest", 999)}
                )
            }
        )
        attacked = (
            assignments[0].model_copy(update={"authority": authority}),
            *assignments[1:],
        )

    with pytest.raises(WikiIndexBuildError) as error:
        WikiNavigationIndexBuilder().build(
            attacked,
            source.revision,
            builder_input=source.builder_input,
        )
    assert error.value.code == "WIKI_INDEX_INPUT_SET_MISMATCH"


def test_payload_detects_token_hash_row_and_descriptor_attacks() -> None:
    source = wiki_fixture()
    built = build_fixture(source)
    original = json.loads(built.index_bytes)

    token_tamper = json.loads(built.index_bytes)
    token_tamper["rows"][0]["word_tokens"].append("tampered")
    token_tamper["rows"][0]["word_tokens"].sort()
    with pytest.raises(ValueError, match="WIKI_INDEX_ROW_CLOSURE_MISMATCH"):
        WikiNavigationIndexPayloadV2.model_validate_json(
            canonical_json_bytes(token_tamper), strict=True
        )

    missing = json.loads(built.index_bytes)
    missing["rows"] = missing["rows"][:-1]
    missing_payload = _payload_with_recomputed_closure(missing)
    with pytest.raises(ValueError, match="WIKI_INDEX_DESCRIPTOR_MISMATCH"):
        missing_payload.verify_descriptor(
            source.builder_input.retrieval_input_descriptor
        )

    duplicate = json.loads(built.index_bytes)
    duplicate["rows"].append(duplicate["rows"][0])
    with pytest.raises(ValueError, match="WIKI_INDEX_ROWS_INVALID"):
        _payload_with_recomputed_closure(duplicate)

    fork = RetrievalInputDescriptor.from_assignments(
        source.assignments,
        route_policy_ref=reference("retrieval_route_policy", 888, version=7),
    )
    with pytest.raises(ValueError, match="WIKI_INDEX_DESCRIPTOR_MISMATCH"):
        built.payload.verify_descriptor(fork)

    fully_rehashed = original
    row = fully_rehashed["rows"][0]
    row["word_tokens"] = sorted({*row["word_tokens"], "forgedtoken"})
    authority = source.assignments[0].authority.__class__.model_validate_json(
        canonical_json_bytes(row["authority"]), strict=True
    )
    row["row_closure_sha256"] = WikiNavigationIndexRowV2.calculate_closure(
        row_id=row["row_id"],
        authority=authority,
        section_keys=tuple(row["section_keys"]),
        word_tokens=tuple(row["word_tokens"]),
        character_2grams=tuple(row["character_2grams"]),
        character_3grams=tuple(row["character_3grams"]),
        alphanumeric_tokens=tuple(row["alphanumeric_tokens"]),
        navigation_source_sha256=row["navigation_source_sha256"],
    )
    forged_payload = _payload_with_recomputed_closure(fully_rehashed)
    forged_payload.verify_builder_input(source.builder_input)
    with pytest.raises(ValueError, match="WIKI_INDEX_SOURCE_MISMATCH"):
        forged_payload.verify_source(source.builder_input, source.revision)


def test_retriever_prefilters_before_scoring_and_keeps_legal_lower_score(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    legal = source.candidates[2]
    scored_claim_ids: list[str] = []
    original_score = bound.retriever._score_row

    def tracking_score(*args: object) -> float:
        row = args[0]
        assert isinstance(row, WikiNavigationIndexRowV2)
        scored_claim_ids.append(row.authority.reference.object_id)
        return original_score(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(bound.retriever, "_score_row", tracking_score)
    result = bound.retriever.search(
        "依恋关系修复",
        scope(use="consultation"),
        snapshot(legal),
        limit=1,
    )

    assert tuple(item.reference for item in result) == (legal.reference,)
    assert tuple(item.content_ref for item in result) == (legal.content_ref,)
    assert scored_claim_ids == [legal.reference.object_id]
    assert result[0].channel == "wiki"
    assert result[0].filter_binding is None


def test_retriever_is_deterministic_and_returns_all_passages_for_one_claim(
    tmp_path: Path,
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    authority = snapshot(*source.candidates)
    retrieval_scope = scope(use="consultation")

    first = bound.retriever.search(
        "依恋循环的新行动",
        retrieval_scope,
        authority,
        limit=10,
    )
    second = bound.retriever.search(
        "依恋循环的新行动",
        retrieval_scope,
        authority,
        limit=10,
    )

    assert first == second
    expected_claim = source.candidates[0].reference
    assert tuple(item.reference for item in first) == (
        expected_claim,
        expected_claim,
    )
    assert {item.content_ref for item in first} == {
        source.candidates[0].content_ref,
        source.candidates[1].content_ref,
    }
    assert all(not hasattr(item, "text") for item in first)


@pytest.mark.parametrize("mode", ["zero", "invalid", "exception"])
def test_search_revalidates_binding_on_zero_invalid_and_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    before = bound.state.calls
    if mode == "zero":
        assert bound.retriever.search(
            "完全不存在的导航词",
            scope(use="consultation"),
            snapshot(*source.candidates),
            limit=2,
        ) == ()
    elif mode == "invalid":
        with pytest.raises(WikiIndexError, match="WIKI_INDEX_QUERY_INVALID"):
            bound.retriever.search(
                "",
                scope(use="consultation"),
                snapshot(*source.candidates),
                limit=2,
            )
    else:
        def fail_score(*_args: object) -> float:
            raise RuntimeError("boom")

        monkeypatch.setattr(bound.retriever, "_score_row", fail_score)
        with pytest.raises(WikiIndexError, match="WIKI_INDEX_QUERY_FAILED"):
            bound.retriever.search(
                "关系修复",
                scope(use="consultation"),
                snapshot(*source.candidates),
                limit=2,
            )
    # ArtifactBinding.verify_current invokes its live verifier before and after
    # CAS verification, once at search entry and once in the unconditional exit.
    assert bound.state.calls - before == 4


def test_retriever_rejects_stale_binding_cas_drift_and_raw_path(
    tmp_path: Path,
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    bound.state.stale = True
    with pytest.raises(WikiIndexError, match="WIKI_INDEX_ARTIFACT_BINDING_STALE"):
        bound.retriever.search(
            "关系修复",
            scope(use="consultation"),
            snapshot(*source.candidates),
            limit=1,
        )

    fresh = bound_wiki_index(tmp_path / "cas-fresh", value=source)
    fresh.binding.path_for("wiki_index").write_bytes(b"{}")
    with pytest.raises(WikiIndexError, match="WIKI_INDEX_ARTIFACT_BINDING_STALE"):
        fresh.retriever.search(
            "关系修复",
            scope(use="consultation"),
            snapshot(*source.candidates),
            limit=1,
        )

    with pytest.raises(TypeError, match="WIKI_INDEX_ARTIFACT_BINDING_REQUIRED"):
        WikiIndexRetriever(tmp_path / "attacker-index.json")  # type: ignore[arg-type]


def test_binding_drift_during_query_fails_at_postcheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    original_score = bound.retriever._score_row

    def drift_after_score(*args: object) -> float:
        score_value = original_score(*args)  # type: ignore[arg-type]
        bound.state.stale = True
        return score_value

    monkeypatch.setattr(bound.retriever, "_score_row", drift_after_score)
    with pytest.raises(WikiIndexError, match="WIKI_INDEX_ARTIFACT_BINDING_STALE"):
        bound.retriever.search(
            "关系修复",
            scope(use="consultation"),
            snapshot(*source.candidates),
            limit=1,
        )
