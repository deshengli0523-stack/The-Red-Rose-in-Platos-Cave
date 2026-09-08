"""Consultation-owned hybrid retrieval primitives."""

from typing import TYPE_CHECKING

from .authority_snapshot import AuthoritativeSnapshotRepository
from .contracts import CandidateRef, FilterDecision, ResolvedEvidence
from .filters import CandidateFilter
from .lexical import LexicalRetriever
from .loo_authority import SqliteLeaveOneOutAuthorityVerifier
from .resolver import EvidenceResolver
from .vector import ExactVectorRetriever

if TYPE_CHECKING:
    from .global_graph import GlobalGraphRetriever


def __getattr__(name: str) -> object:
    if name == "GlobalGraphRetriever":
        from .global_graph import GlobalGraphRetriever

        return GlobalGraphRetriever
    raise AttributeError(name)

__all__ = [
    "AuthoritativeSnapshotRepository",
    "CandidateFilter",
    "CandidateRef",
    "EvidenceResolver",
    "ExactVectorRetriever",
    "FilterDecision",
    "GlobalGraphRetriever",
    "LexicalRetriever",
    "ResolvedEvidence",
    "SqliteLeaveOneOutAuthorityVerifier",
]
