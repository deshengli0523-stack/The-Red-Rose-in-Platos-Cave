from __future__ import annotations

from consultation_kb.retrieval.budget import BudgetItem, ContextBudget


def _item(
    evidence_id: str,
    tokens: int,
    roles: frozenset[str],
    source: str,
    value: float,
    *,
    sources: tuple[str, ...] | None = None,
) -> BudgetItem:
    return BudgetItem(
        evidence_id=evidence_id,
        body=f"complete-{evidence_id}".encode(),
        token_count=tokens,
        roles=roles,
        source_keys=sources or (source,),
        marginal_value=value,
    )


def test_budget_reserves_facts_c1_support_contradiction_quote_and_source_diversity() -> None:
    items = (
        _item("fact", 4, frozenset({"current_fact"}), "client", 1.0),
        _item("c1-scope", 4, frozenset({"c1_scope"}), "c1", 0.9),
        _item("support", 4, frozenset({"support"}), "source-a", 0.8),
        _item("contradiction", 4, frozenset({"contradiction"}), "source-b", 0.7),
        _item("quote", 4, frozenset({"exact_quote"}), "source-c", 0.6),
        _item("duplicate", 4, frozenset({"context"}), "source-a", 10.0),
        _item("diverse", 4, frozenset({"context"}), "source-d", 0.5),
    )
    selection = ContextBudget(
        max_tokens=24,
        minimum_supporting=1,
        minimum_contradictions=1,
        minimum_exact_quotes=1,
    ).select(items)

    selected = {item.evidence_id for item in selection.selected}
    assert {"fact", "c1-scope", "support", "contradiction", "quote"} <= selected
    assert selection.used_tokens <= 24
    assert len(
        {
            source
            for item in selection.selected
            for source in item.source_keys
        }
    ) >= 5
    assert selection.omitted_count == 1
    assert sum(selection.omitted_counts.values()) == selection.omitted_count


def test_budget_never_truncates_a_passage_and_explains_oversize_omission() -> None:
    exact = _item("exact", 5, frozenset({"exact_quote"}), "source-a", 1.0)
    oversize = _item("oversize", 11, frozenset({"support"}), "source-b", 2.0)
    selection = ContextBudget(max_tokens=5).select((oversize, exact))

    assert selection.selected == (exact,)
    assert selection.selected[0].body == exact.body
    assert selection.omitted[0].evidence_id == "oversize"
    assert selection.omitted[0].reason == "item_exceeds_total_budget"
    assert selection.omitted_counts == {"item_exceeds_total_budget": 1}


def test_multi_role_preselection_does_not_double_count_retention_floor() -> None:
    first = _item(
        "first", 3, frozenset({"current_fact", "support"}), "source-a", 1.0
    )
    second = _item("second", 3, frozenset({"support"}), "source-a", 0.9)
    distractor = _item("distractor", 3, frozenset({"context"}), "source-b", 9.0)
    selection = ContextBudget(
        max_tokens=6,
        minimum_supporting=2,
        minimum_contradictions=0,
        minimum_exact_quotes=0,
    ).select((first, second, distractor))
    assert {item.evidence_id for item in selection.selected} == {"first", "second"}


def test_source_diversity_round_takes_only_one_item_per_new_source() -> None:
    initial = _item("initial", 2, frozenset({"support"}), "source-a", 1.0)
    duplicate_high = _item("b-high", 2, frozenset({"context"}), "source-b", 9.0)
    duplicate_low = _item("b-low", 2, frozenset({"context"}), "source-b", 8.0)
    diverse = _item("c", 2, frozenset({"context"}), "source-c", 0.5)
    selection = ContextBudget(
        max_tokens=6,
        minimum_supporting=1,
        minimum_contradictions=0,
        minimum_exact_quotes=0,
    ).select((initial, duplicate_high, duplicate_low, diverse))

    assert {item.evidence_id for item in selection.selected} == {
        "initial",
        "b-high",
        "c",
    }


def test_source_set_overlap_counts_only_new_independent_sources() -> None:
    overlap = _item(
        "ab",
        2,
        frozenset({"context"}),
        "unused",
        1.0,
        sources=("source-a", "source-b"),
    )
    duplicate = _item("a", 2, frozenset({"context"}), "source-a", 9.0)
    independent = _item("c", 2, frozenset({"context"}), "source-c", 0.5)

    selection = ContextBudget(
        max_tokens=4,
        minimum_supporting=0,
        minimum_contradictions=0,
        minimum_exact_quotes=0,
    ).select((overlap, duplicate, independent))

    assert {item.evidence_id for item in selection.selected} == {"ab", "c"}


def test_source_diversity_prefers_new_source_coverage_per_token() -> None:
    large = _item(
        "large-ab",
        10,
        frozenset({"context"}),
        "unused",
        10.0,
        sources=("source-a", "source-b"),
    )
    small = tuple(
        _item(
            f"small-{source}",
            3,
            frozenset({"context"}),
            f"source-{source}",
            0.1,
        )
        for source in ("c", "d", "e")
    )
    selection = ContextBudget(
        max_tokens=10,
        minimum_supporting=0,
        minimum_contradictions=0,
        minimum_exact_quotes=0,
    ).select((large, *small))

    assert {item.evidence_id for item in selection.selected} == {
        "small-c",
        "small-d",
        "small-e",
    }
