from __future__ import annotations

from pathlib import Path

import pytest

from tests.consultation_kb.retrieval_support import scope, snapshot
from tests.consultation_kb.wiki_index_support import (
    bound_wiki_index,
    wiki_fixture,
)


pytestmark = pytest.mark.golden


@pytest.mark.parametrize(
    ("query", "candidate_indexes"),
    [
        ("辨认反复出现的依恋循环并验证新行动", (0, 1)),
        ("APPLIES_TO relationship", (0, 1)),
        ("生涯转换小步实验", (2,)),
    ],
)
def test_wiki_navigation_recall_returns_only_exact_passage_backed_claims(
    tmp_path: Path,
    query: str,
    candidate_indexes: tuple[int, ...],
) -> None:
    source = wiki_fixture()
    bound = bound_wiki_index(tmp_path / "cas", value=source)
    candidates = tuple(source.candidates[index] for index in candidate_indexes)

    result = bound.retriever.search(
        query,
        scope(use="consultation"),
        snapshot(*source.candidates),
        limit=10,
    )

    assert {(item.reference, item.content_ref) for item in result} == {
        (candidate.reference, candidate.content_ref) for candidate in candidates
    }
    assert all(item.channel == "wiki" for item in result)
    assert all(not hasattr(item, "text") for item in result)
