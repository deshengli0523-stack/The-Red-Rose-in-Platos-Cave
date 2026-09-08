from __future__ import annotations

import pytest

from consultation_kb.retrieval.fts_query import FtsQueryBuilder, FtsQueryError


def test_builder_owns_boolean_grammar_and_quotes_every_token() -> None:
    builder = FtsQueryBuilder()

    assert builder.build((("a", "b"), ("c",))) == '("a" OR "b") AND "c"'
    assert builder.build_any(("OR", "NOT", "NEAR", "*", ":", "(x)", 'a"b')) == (
        '("OR" OR "NOT" OR "NEAR" OR "*" OR ":" OR "(x)" OR "a""b")'
    )


@pytest.mark.parametrize(
    "groups",
    [
        (),
        ((),),
        (("",),),
        (("   ",),),
        (("\x00",),),
        (("a\nb",),),
        (("x" * 129,),),
    ],
)
def test_builder_fails_closed_for_invalid_tokens(
    groups: tuple[tuple[str, ...], ...],
) -> None:
    with pytest.raises(FtsQueryError, match="FTS_QUERY_INVALID"):
        FtsQueryBuilder().build(groups)


def test_builder_rejects_more_than_the_fixed_token_budget() -> None:
    with pytest.raises(FtsQueryError, match="FTS_QUERY_INVALID"):
        FtsQueryBuilder(max_tokens=2).build_any(("a", "b", "c"))


def test_builder_rejects_string_as_a_sequence_of_groups_or_tokens() -> None:
    with pytest.raises(FtsQueryError, match="FTS_QUERY_INVALID"):
        FtsQueryBuilder().build("abc")
    with pytest.raises(FtsQueryError, match="FTS_QUERY_INVALID"):
        FtsQueryBuilder().build(("abc",))
