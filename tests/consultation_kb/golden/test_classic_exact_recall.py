from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.models.evidence import EvidenceLocator
from consultation_kb.retrieval.lexical import LexicalRetriever
from consultation_kb.retrieval.lexical_builder import LexicalDocument, LexicalIndexBuilder
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


pytestmark = pytest.mark.golden


def _located(index: int, text: str):
    value = candidate(index, text=text)
    return value.model_copy(
        update={
            "location": EvidenceLocator(
                locator_kind="source_line_span",
                anchor_refs=(value.reference,),
                display_locator=f"lines:{index}-{index}",
                locator_policy_ref=reference("locator_policy", index + 700),
            )
        }
    )


def test_classic_terms_sentences_names_and_punctuation_recall_exact_location(
    tmp_path: Path,
) -> None:
    records = (
        (_located(1, "仁义礼智，非由外铄我也。"), "仁义礼智，非由外铄我也。"),
        (_located(2, "王阳明论知行合一，主张事上磨炼。"), "王阳明论知行合一，主张事上磨炼。"),
        (_located(3, "格物致知，诚意正心，而后修身。"), "格物致知，诚意正心，而后修身。"),
        (_located(4, "大学之道，在明明德，在亲民，在止于至善。"), "大学之道，在明明德，在亲民，在止于至善。"),
    )
    index = tmp_path / "classic.sqlite3"
    tokenizer = ChineseTokenizer(
        ApprovedAliasDictionary({"王守仁": ("王阳明",)})
    )
    LexicalIndexBuilder(tokenizer).build(
        tuple(LexicalDocument(candidate=item, text=text) for item, text in records),
        index,
        builder_input=derived_builder_input(
            "lexical",
            *(item for item, _text in records),
            source_catalog_version=1,
        ),
    )
    retriever = LexicalRetriever._from_unbound_path_for_test(
        index, tokenizer=tokenizer
    )
    authority = snapshot(*(item for item, _text in records))

    expectations = {
        "仁义": (records[0][0].reference.object_id, "lines:1-1"),
        "王守仁": (records[1][0].reference.object_id, "lines:2-2"),
        "格物致知": (records[2][0].reference.object_id, "lines:3-3"),
        "大学之道，在明明德。": (records[3][0].reference.object_id, "lines:4-4"),
        "知行合一！": (records[1][0].reference.object_id, "lines:2-2"),
    }
    for query, expected in expectations.items():
        result = retriever.search(query, scope(), authority, limit=1)
        assert result
        assert (result[0].reference.object_id, result[0].location.display_locator) == (
            expected
        )
