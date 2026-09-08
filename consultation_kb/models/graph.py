"""Shared canonical contracts for governed public graph declarations."""

from __future__ import annotations

from typing import Literal, TypeAlias


GraphRelationKind: TypeAlias = Literal[
    "SUPPORTS",
    "CONTRADICTS",
    "ANALOGOUS_TO",
    "DISTINCT_FROM",
    "APPLIES_TO",
    "NOT_APPLICABLE_TO",
    "RELATED_TO",
]

# This is the single public node-kind allowlist used both when a Wiki revision
# declares a relationship and when the canonical global graph is built.
PUBLIC_GRAPH_NODE_KINDS = frozenset(
    {
        "archetype",
        "author",
        "concept",
        "construct",
        "domain",
        "entity",
        "method",
        "practice",
        "principle",
        "theory",
        "topic",
        "tradition",
        "work",
    }
)


__all__ = ["GraphRelationKind", "PUBLIC_GRAPH_NODE_KINDS"]
