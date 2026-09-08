from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.retrieval.lexical import LexicalIndexError, LexicalRetriever
from consultation_kb.retrieval.lexical_builder import (
    LexicalBuildError,
    LexicalDocument,
    LexicalIndexBuilder,
)
from consultation_kb.retrieval.normalization import (
    ApprovedAliasDictionary,
    ChineseTokenizer,
)
from tests.consultation_kb.retrieval_support import (
    candidate,
    derived_builder_input,
    reference,
    scope,
    snapshot,
)


def _build_index(path: Path) -> tuple[object, object]:
    high_text = "至善 至善 至善，大学之道在明明德。"
    low_text = "至善也是一种伦理目标。"
    high = candidate(1, text=high_text)
    low = candidate(2, text=low_text)
    manifest = LexicalIndexBuilder().build(
        (
            LexicalDocument(candidate=high, text=high_text),
            LexicalDocument(candidate=low, text=low_text),
        ),
        path,
        builder_input=derived_builder_input(
            "lexical",
            high,
            low,
            source_catalog_version=7,
        ),
    )
    assert manifest.row_count == 2
    return high, low


def test_schema_and_body_reference_are_immutable_source_truth(tmp_path: Path) -> None:
    index = tmp_path / "lexical.sqlite3"
    high, _low = _build_index(index)

    connection = sqlite3.connect(index)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
            )
        }
        stored_json = str(
            connection.execute(
                "SELECT candidate_json FROM lexical_documents WHERE evidence_id = ?",
                (high.reference.object_id,),
            ).fetchone()[0]
        )
    finally:
        connection.close()

    assert {
        "lexical_documents",
        "lexical_provenance",
        "lexical_word_fts",
        "lexical_char_fts",
    } <= tables
    assert high.content_ref.content_sha256 in stored_json
    assert high.content_ref.content_sha256 == hashlib.sha256(
        "至善 至善 至善，大学之道在明明德。".encode("utf-8")
    ).hexdigest()
    with pytest.raises(
        LexicalBuildError,
        match="LEXICAL_IMMUTABLE_TARGET_EXISTS",
    ):
        _build_index(index)


def test_live_allowed_join_happens_before_rank_and_limit(tmp_path: Path) -> None:
    index = tmp_path / "lexical.sqlite3"
    high, low = _build_index(index)
    retriever = LexicalRetriever._from_unbound_path_for_test(index)

    result = retriever.search("至善", scope(), snapshot(low), limit=1)

    assert [item.reference.object_id for item in result] == [low.reference.object_id]
    assert high.reference.object_id not in {
        item.reference.object_id for item in result
    }
    assert retriever.search("至善", scope(), snapshot(), limit=1) == ()


def test_index_records_body_content_ref_not_evidence_object_hash(tmp_path: Path) -> None:
    text = "主张正文"
    value = candidate(7, text=text)
    value = value.model_copy(
        update={"reference": reference("claim", 707), "object_type": "claim"}
    )
    index = tmp_path / "body-ref.sqlite3"
    LexicalIndexBuilder().build(
        (LexicalDocument(candidate=value, text=text),),
        index,
        builder_input=derived_builder_input(
            "lexical",
            value,
            source_catalog_version=1,
        ),
    )
    connection = sqlite3.connect(index)
    try:
        stored = str(
            connection.execute(
                "SELECT content_sha256 FROM lexical_documents"
            ).fetchone()[0]
        )
    finally:
        connection.close()

    assert stored == value.content_ref.content_sha256
    assert stored != value.reference.content_sha256


def test_one_claim_version_can_index_and_return_multiple_passages(
    tmp_path: Path,
) -> None:
    first = candidate(40, text="shared first passage", channel="lexical")
    second = candidate(41, text="shared second passage", channel="lexical").model_copy(
        update={"reference": first.reference}
    )
    index = tmp_path / "multi-passage.sqlite3"
    LexicalIndexBuilder().build(
        (
            LexicalDocument(candidate=first, text="shared first passage"),
            LexicalDocument(candidate=second, text="shared second passage"),
        ),
        index,
        builder_input=derived_builder_input(
            "lexical",
            first,
            second,
            source_catalog_version=2,
        ),
    )

    result = LexicalRetriever._from_unbound_path_for_test(index).search(
        "shared",
        scope(),
        snapshot(first),
        limit=2,
    )
    assert {item.content_ref for item in result} == {
        first.content_ref,
        second.content_ref,
    }


def test_index_rejects_tokenizer_descriptor_drift(tmp_path: Path) -> None:
    index = tmp_path / "lexical.sqlite3"
    high, low = _build_index(index)
    drifted = ChineseTokenizer(ApprovedAliasDictionary({"至善": ("最高善",)}))

    with pytest.raises(LexicalIndexError, match="LEXICAL_TOKENIZER_MISMATCH"):
        LexicalRetriever._from_unbound_path_for_test(
            index, tokenizer=drifted
        ).search(
            "至善",
            scope(),
            snapshot(high, low),
            limit=2,
        )
