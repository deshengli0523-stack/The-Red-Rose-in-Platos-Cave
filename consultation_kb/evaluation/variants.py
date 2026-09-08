"""Frozen five-baseline and three-ablation evaluation variants.

The variants deliberately describe only knowledge-layer differences.  Model,
prompt, schema, reply-contract, retry-budget, and runtime controls belong to
the paired fairness contract in :mod:`consultation_kb.evaluation.runner` and
must remain identical across variants.
"""

from __future__ import annotations

from typing import Final, Literal, TypeAlias

from pydantic import field_validator, model_validator
from typing_extensions import Self

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import StrictModel
from consultation_kb.models.evidence import EvidenceChannel


SystemVariantName: TypeAlias = Literal[
    "general_model_only",
    "hybrid_rag_only",
    "wiki_hybrid_rag",
    "full_without_c1_priority",
    "full_system",
    "full_without_graphify_navigation",
    "full_without_cases",
    "full_without_reranker",
]
VariantFamily: TypeAlias = Literal["baseline", "ablation"]
C1Mode: TypeAlias = Literal["disabled", "ordinary", "priority"]


ALL_EVIDENCE_CHANNELS: Final[tuple[EvidenceChannel, ...]] = (
    "profile",
    "client_history",
    "wiki",
    "lexical",
    "vector",
    "global_graph",
    "case",
)


class VariantFeatures(StrictModel):
    """Knowledge features varied by the experiment.

    ``client_snapshot`` is not a flag: the exact immutable input snapshot is
    fixed for every paired run, including ``general_model_only``.  The
    ``profile`` and ``client_history`` routes below mean active retrieval over
    the private temporal knowledge layer, not the already-frozen input.
    """

    routes: tuple[EvidenceChannel, ...]
    c1_mode: C1Mode
    graphify_navigation: bool
    cases: bool
    reranker: bool
    multi_stage_critique: Literal[True] = True

    @field_validator("routes")
    @classmethod
    def _canonical_routes(
        cls,
        value: tuple[EvidenceChannel, ...],
    ) -> tuple[EvidenceChannel, ...]:
        if len(value) != len(set(value)):
            raise ValueError("variant routes must be unique")
        ordered = tuple(channel for channel in ALL_EVIDENCE_CHANNELS if channel in value)
        if value != ordered:
            raise ValueError("variant routes must use canonical channel order")
        return value

    @model_validator(mode="after")
    def _feature_closure(self) -> Self:
        routes = set(self.routes)
        graph_routes = {"client_history", "global_graph"}
        if self.graphify_navigation != bool(routes & graph_routes):
            raise ValueError("Graphify navigation flag and graph routes disagree")
        if self.cases != ("case" in routes):
            raise ValueError("case flag and case route disagree")
        if self.reranker and not ({"lexical", "vector"} & routes):
            raise ValueError("reranker requires a lexical or vector route")
        if "wiki" in routes and not {"lexical", "vector"} <= routes:
            raise ValueError("Wiki hybrid retrieval requires lexical and vector routes")
        return self

    @property
    def prohibited_routes(self) -> tuple[EvidenceChannel, ...]:
        allowed = set(self.routes)
        return tuple(channel for channel in ALL_EVIDENCE_CHANNELS if channel not in allowed)


class SystemVariant(StrictModel):
    """One exact baseline/ablation configuration."""

    schema_version: Literal["system_variant.v1"] = "system_variant.v1"
    name: SystemVariantName
    family: VariantFamily
    features: VariantFeatures

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


_FULL_ROUTES: Final[tuple[EvidenceChannel, ...]] = ALL_EVIDENCE_CHANNELS

GENERAL_MODEL_ONLY: Final = SystemVariant(
    name="general_model_only",
    family="baseline",
    features=VariantFeatures(
        routes=(),
        c1_mode="disabled",
        graphify_navigation=False,
        cases=False,
        reranker=False,
    ),
)

HYBRID_RAG_ONLY: Final = SystemVariant(
    name="hybrid_rag_only",
    family="baseline",
    features=VariantFeatures(
        routes=("lexical", "vector"),
        c1_mode="disabled",
        graphify_navigation=False,
        cases=False,
        reranker=True,
    ),
)

WIKI_HYBRID_RAG: Final = SystemVariant(
    name="wiki_hybrid_rag",
    family="baseline",
    features=VariantFeatures(
        routes=("wiki", "lexical", "vector"),
        c1_mode="disabled",
        graphify_navigation=False,
        cases=False,
        reranker=True,
    ),
)

FULL_WITHOUT_C1_PRIORITY: Final = SystemVariant(
    name="full_without_c1_priority",
    family="baseline",
    features=VariantFeatures(
        routes=_FULL_ROUTES,
        c1_mode="ordinary",
        graphify_navigation=True,
        cases=True,
        reranker=True,
    ),
)

FULL_SYSTEM: Final = SystemVariant(
    name="full_system",
    family="baseline",
    features=VariantFeatures(
        routes=_FULL_ROUTES,
        c1_mode="priority",
        graphify_navigation=True,
        cases=True,
        reranker=True,
    ),
)

FULL_WITHOUT_GRAPHIFY_NAVIGATION: Final = SystemVariant(
    name="full_without_graphify_navigation",
    family="ablation",
    features=VariantFeatures(
        routes=("profile", "wiki", "lexical", "vector", "case"),
        c1_mode="priority",
        graphify_navigation=False,
        cases=True,
        reranker=True,
    ),
)

FULL_WITHOUT_CASES: Final = SystemVariant(
    name="full_without_cases",
    family="ablation",
    features=VariantFeatures(
        routes=(
            "profile",
            "client_history",
            "wiki",
            "lexical",
            "vector",
            "global_graph",
        ),
        c1_mode="priority",
        graphify_navigation=True,
        cases=False,
        reranker=True,
    ),
)

FULL_WITHOUT_RERANKER: Final = SystemVariant(
    name="full_without_reranker",
    family="ablation",
    features=VariantFeatures(
        routes=_FULL_ROUTES,
        c1_mode="priority",
        graphify_navigation=True,
        cases=True,
        reranker=False,
    ),
)


BASELINE_VARIANTS: Final[tuple[SystemVariant, ...]] = (
    GENERAL_MODEL_ONLY,
    HYBRID_RAG_ONLY,
    WIKI_HYBRID_RAG,
    FULL_WITHOUT_C1_PRIORITY,
    FULL_SYSTEM,
)
ABLATION_VARIANTS: Final[tuple[SystemVariant, ...]] = (
    FULL_WITHOUT_GRAPHIFY_NAVIGATION,
    FULL_WITHOUT_CASES,
    FULL_WITHOUT_RERANKER,
)
ALL_SYSTEM_VARIANTS: Final[tuple[SystemVariant, ...]] = (
    *BASELINE_VARIANTS,
    *ABLATION_VARIANTS,
)
SYSTEM_VARIANTS_BY_NAME: Final[dict[SystemVariantName, SystemVariant]] = {
    variant.name: variant for variant in ALL_SYSTEM_VARIANTS
}


def system_variant(name: SystemVariantName) -> SystemVariant:
    """Return the immutable registered configuration for ``name``."""

    return SYSTEM_VARIANTS_BY_NAME[name]


__all__ = [
    "ABLATION_VARIANTS",
    "ALL_EVIDENCE_CHANNELS",
    "ALL_SYSTEM_VARIANTS",
    "BASELINE_VARIANTS",
    "C1Mode",
    "FULL_SYSTEM",
    "FULL_WITHOUT_C1_PRIORITY",
    "FULL_WITHOUT_CASES",
    "FULL_WITHOUT_GRAPHIFY_NAVIGATION",
    "FULL_WITHOUT_RERANKER",
    "GENERAL_MODEL_ONLY",
    "HYBRID_RAG_ONLY",
    "SYSTEM_VARIANTS_BY_NAME",
    "SystemVariant",
    "SystemVariantName",
    "VariantFamily",
    "VariantFeatures",
    "WIKI_HYBRID_RAG",
    "system_variant",
]
