"""Whole-Passage context budgeting with deterministic evidence reservations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Mapping, TypeAlias

from consultation_kb.retrieval.contracts import ResolvedEvidence
from consultation_kb.retrieval.fusion import FusedCandidate


BudgetRole: TypeAlias = Literal[
    "current_fact",
    "c1_scope",
    "c1_limit",
    "support",
    "contradiction",
    "alternative",
    "exact_quote",
    "context",
]
_ALLOWED_ROLES = frozenset(
    {
        "current_fact",
        "c1_scope",
        "c1_limit",
        "support",
        "contradiction",
        "alternative",
        "exact_quote",
        "context",
    }
)


@dataclass(frozen=True, slots=True)
class BudgetItem:
    evidence_id: str
    body: bytes
    token_count: int
    roles: frozenset[str]
    source_keys: tuple[str, ...]
    marginal_value: float
    fused: FusedCandidate | None = None
    resolved: tuple[ResolvedEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.body or not self.source_keys:
            raise ValueError("budget item identity, body and source are required")
        if any(
            not isinstance(value, str) or not value
            for value in self.source_keys
        ):
            raise ValueError("budget source keys must be nonempty strings")
        if len(self.source_keys) != len(set(self.source_keys)) or (
            self.source_keys != tuple(sorted(self.source_keys))
        ):
            raise ValueError("budget source keys must be unique and canonical")
        if type(self.token_count) is not int or self.token_count <= 0:
            raise ValueError("budget token count must be a positive exact integer")
        if not self.roles or not self.roles <= _ALLOWED_ROLES:
            raise ValueError("budget roles are invalid")
        if not math.isfinite(self.marginal_value) or self.marginal_value < 0:
            raise ValueError("budget marginal value must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class OmittedBudgetItem:
    evidence_id: str
    token_count: int
    reason: str


@dataclass(frozen=True, slots=True)
class BudgetSelection:
    selected: tuple[BudgetItem, ...]
    used_tokens: int
    max_tokens: int
    omitted: tuple[OmittedBudgetItem, ...]
    omitted_count: int
    omitted_counts: Mapping[str, int]


class ContextBudget:
    """Select complete evidence bodies; never slice a Passage to fit."""

    def __init__(
        self,
        *,
        max_tokens: int,
        minimum_supporting: int = 1,
        minimum_contradictions: int = 1,
        minimum_alternatives: int = 0,
        minimum_exact_quotes: int = 1,
    ) -> None:
        if type(max_tokens) is not int or max_tokens <= 0:
            raise ValueError("max_tokens must be a positive exact integer")
        floors = (
            minimum_supporting,
            minimum_contradictions,
            minimum_alternatives,
            minimum_exact_quotes,
        )
        if any(type(value) is not int or value < 0 for value in floors):
            raise ValueError("budget floors must be non-negative exact integers")
        self._max_tokens = max_tokens
        self._minimum_supporting = minimum_supporting
        self._minimum_contradictions = minimum_contradictions
        self._minimum_alternatives = minimum_alternatives
        self._minimum_exact_quotes = minimum_exact_quotes

    def select(self, items: tuple[BudgetItem, ...]) -> BudgetSelection:
        identifiers = [item.evidence_id for item in items]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("budget evidence IDs must be unique")
        candidates = [item for item in items if item.token_count <= self._max_tokens]
        selected: list[BudgetItem] = []
        selected_ids: set[str] = set()
        used_tokens = 0

        def rank(values: list[BudgetItem]) -> list[BudgetItem]:
            return sorted(
                values,
                key=lambda item: (
                    -(item.marginal_value / item.token_count),
                    -item.marginal_value,
                    item.evidence_id,
                ),
            )

        def add(value: BudgetItem) -> bool:
            nonlocal used_tokens
            if value.evidence_id in selected_ids:
                return False
            if used_tokens + value.token_count > self._max_tokens:
                return False
            selected.append(value)
            selected_ids.add(value.evidence_id)
            used_tokens += value.token_count
            return True

        # Current facts and governed C1 scope/limits are the fixed first tier.
        for roles in (
            frozenset({"current_fact"}),
            frozenset({"c1_scope", "c1_limit"}),
        ):
            for item in rank(
                [value for value in candidates if value.roles & roles]
            ):
                add(item)

        def reserve(role: str, count: int) -> None:
            already = sum(role in value.roles for value in selected)
            for item in rank(
                [value for value in candidates if role in value.roles]
            ):
                if already >= count:
                    break
                if item.evidence_id in selected_ids:
                    continue
                if add(item):
                    already += 1

        reserve("support", self._minimum_supporting)
        reserve("contradiction", self._minimum_contradictions)
        reserve("alternative", self._minimum_alternatives)
        reserve("exact_quote", self._minimum_exact_quotes)

        # Prefer one item from each unseen source before spending the remainder
        # on repeated-source material, even if the latter has a larger raw score.
        seen_sources = {
            source_key
            for item in selected
            for source_key in item.source_keys
        }
        while True:
            unseen = [
                value
                for value in candidates
                if value.evidence_id not in selected_ids
                and set(value.source_keys) - seen_sources
            ]
            if not unseen:
                break
            unseen.sort(
                key=lambda item: (
                    -(
                        len(set(item.source_keys) - seen_sources)
                        / item.token_count
                    ),
                    -len(set(item.source_keys) - seen_sources),
                    -(item.marginal_value / item.token_count),
                    -item.marginal_value,
                    item.evidence_id,
                )
            )
            if not add(unseen[0]):
                # This candidate cannot fit; remove it from diversity
                # consideration without hiding other smaller new-source items.
                candidates.remove(unseen[0])
                continue
            seen_sources.update(unseen[0].source_keys)

        for item in rank(
            [item for item in candidates if item.evidence_id not in selected_ids]
        ):
            add(item)

        omitted: list[OmittedBudgetItem] = []
        counts: dict[str, int] = {}
        for item in items:
            if item.evidence_id in selected_ids:
                continue
            reason = (
                "item_exceeds_total_budget"
                if item.token_count > self._max_tokens
                else "insufficient_remaining_budget"
            )
            omitted.append(
                OmittedBudgetItem(
                    evidence_id=item.evidence_id,
                    token_count=item.token_count,
                    reason=reason,
                )
            )
            counts[reason] = counts.get(reason, 0) + 1
        return BudgetSelection(
            selected=tuple(selected),
            used_tokens=used_tokens,
            max_tokens=self._max_tokens,
            omitted=tuple(omitted),
            omitted_count=len(omitted),
            omitted_counts=MappingProxyType(dict(sorted(counts.items()))),
        )


__all__ = [
    "BudgetItem",
    "BudgetRole",
    "BudgetSelection",
    "ContextBudget",
    "OmittedBudgetItem",
]
