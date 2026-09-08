"""Auditable LLM Wiki revision contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from .common import (
    FiniteFloat,
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from .graph import GraphRelationKind, PUBLIC_GRAPH_NODE_KINDS


WikiDiffKind = Literal[
    "add", "correct", "parallel_disagreement", "supersede", "expire"
]
WikiStatus = Literal["draft", "prepared", "active", "superseded", "revoked"]
WikiStance = Literal["support", "oppose", "context"]
WikiRelationshipKind = Literal[
    "ANALOGOUS_TO", "DISTINCT_FROM", "APPLIES_TO", "NOT_APPLICABLE_TO"
]


class WikiRelationship(StrictModel):
    target_id: ObjectId
    relationship: WikiRelationshipKind
    scope: tuple[SafePolicyKey, ...]
    source_refs: tuple[VersionRef, ...]
    reviewed: bool

    @model_validator(mode="after")
    def _validate_governed_relationship(self) -> "WikiRelationship":
        if not self.scope or not self.source_refs or not self.reviewed:
            raise ValueError("Wiki relationship requires scope, source and review")
        return self


class WikiGraphRelationDeclaration(StrictModel):
    source_ref: VersionRef
    target_ref: VersionRef
    claim_ref: VersionRef
    relation: GraphRelationKind
    scope: tuple[SafePolicyKey, ...]
    review_status: Literal["approved"]
    effective_from: UtcDateTime | None = None
    effective_to: UtcDateTime | None = None
    confidence_override: FiniteFloat | None = None

    @model_validator(mode="after")
    def _validate_declaration(self) -> "WikiGraphRelationDeclaration":
        if self.source_ref == self.target_ref:
            raise ValueError("Wiki graph relation cannot be a self loop")
        for reference in (self.source_ref, self.target_ref):
            kind = reference.object_id.rsplit("_", maxsplit=1)[0]
            if kind not in PUBLIC_GRAPH_NODE_KINDS:
                raise ValueError("Wiki graph relation node type is not public-safe")
        if self.claim_ref.object_id.rsplit("_", maxsplit=1)[0] != "claim":
            raise ValueError("Wiki graph relation must reference a Claim")
        if not self.scope or self.scope != tuple(sorted(set(self.scope))):
            raise ValueError("Wiki graph relation scope must be canonical")
        if (
            self.effective_from is not None
            and self.effective_to is not None
            and self.effective_to <= self.effective_from
        ):
            raise ValueError("Wiki graph relation effective interval is inverted")
        if self.confidence_override is not None and not (
            0 <= self.confidence_override <= 1
        ):
            raise ValueError("Wiki graph relation confidence is invalid")
        return self


class WikiSection(StrictModel):
    key: SafePolicyKey
    heading: NonEmptyStr
    body: NonEmptyStr
    claim_refs: tuple[VersionRef, ...]
    passage_refs: tuple[VersionRef, ...]
    stance: WikiStance = "context"


class WikiRevisionDraft(StrictModel):
    wiki_id: ObjectId
    slug: NonEmptyStr
    title: NonEmptyStr
    base_revision: int
    diff_kind: WikiDiffKind
    sections: tuple[WikiSection, ...]
    theory_revision_refs: tuple[VersionRef, ...]
    relationships: tuple[WikiRelationship, ...] = ()
    graph_relations: tuple[WikiGraphRelationDeclaration, ...] = ()
    review_due_at: UtcDateTime | None
    unresolved_questions: tuple[NonEmptyStr, ...] = ()

    @model_validator(mode="after")
    def _validate_draft(self) -> "WikiRevisionDraft":
        if type(self.base_revision) is not int or self.base_revision < 0:
            raise ValueError("Wiki base revision must be a non-negative integer")
        if not self.sections:
            raise ValueError("Wiki revision requires sections")
        section_keys = [section.key for section in self.sections]
        if len(section_keys) != len(set(section_keys)):
            raise ValueError("Wiki section keys must be unique")
        for section in self.sections:
            for reference in section.claim_refs:
                if (
                    reference.object_id == self.wiki_id
                    or reference.object_id.rsplit("_", maxsplit=1)[0] != "claim"
                ):
                    raise ValueError("Wiki cannot use itself as evidence")
            for reference in section.passage_refs:
                if reference.object_id.rsplit("_", maxsplit=1)[0] != "passage":
                    raise ValueError("Wiki evidence must reference a Passage")
        section_claims = {
            reference
            for section in self.sections
            for reference in section.claim_refs
        }
        relation_keys = [
            (
                relation.source_ref,
                relation.target_ref,
                relation.claim_ref,
                relation.relation,
                relation.scope,
                relation.review_status,
                relation.effective_from,
                relation.effective_to,
                relation.confidence_override,
            )
            for relation in self.graph_relations
        ]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("Wiki graph relation declarations must be unique")
        if any(
            relation.claim_ref not in section_claims
            for relation in self.graph_relations
        ):
            raise ValueError("Wiki graph relation Claim must appear in a section")
        if self.base_revision == 0 and self.diff_kind != "add":
            raise ValueError("new Wiki pages require an add diff")
        if self.base_revision > 0 and self.diff_kind == "add":
            raise ValueError("existing Wiki pages require a structured non-add diff")
        return self


class WikiRevision(StrictModel):
    wiki_id: ObjectId
    revision: PositiveInt
    slug: NonEmptyStr
    title: NonEmptyStr
    base_revision: int
    diff_kind: WikiDiffKind
    sections: tuple[WikiSection, ...]
    theory_revision_refs: tuple[VersionRef, ...]
    relationships: tuple[WikiRelationship, ...]
    graph_relations: tuple[WikiGraphRelationDeclaration, ...] = ()
    review_due_at: UtcDateTime | None
    unresolved_questions: tuple[NonEmptyStr, ...]
    body_sha256: Sha256Hex
    diff_sha256: Sha256Hex
    status: WikiStatus
    approval_request_id: ObjectId | None
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_status(self) -> "WikiRevision":
        if self.status != "draft" and self.approval_request_id is None:
            raise ValueError("prepared Wiki revision requires approval")
        if not self.sections:
            raise ValueError("Wiki revision requires sections")
        section_keys = [section.key for section in self.sections]
        if len(section_keys) != len(set(section_keys)):
            raise ValueError("Wiki section keys must be unique")
        for section in self.sections:
            if any(
                reference.object_id.rsplit("_", maxsplit=1)[0] != "claim"
                for reference in section.claim_refs
            ):
                raise ValueError("Wiki evidence Claim kind is invalid")
            if any(
                reference.object_id.rsplit("_", maxsplit=1)[0] != "passage"
                for reference in section.passage_refs
            ):
                raise ValueError("Wiki evidence must reference a Passage")
        section_claims = {
            reference
            for section in self.sections
            for reference in section.claim_refs
        }
        relation_keys = [
            (
                relation.source_ref,
                relation.target_ref,
                relation.claim_ref,
                relation.relation,
                relation.scope,
                relation.review_status,
                relation.effective_from,
                relation.effective_to,
                relation.confidence_override,
            )
            for relation in self.graph_relations
        ]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("Wiki graph relation declarations must be unique")
        if any(
            relation.claim_ref not in section_claims
            for relation in self.graph_relations
        ):
            raise ValueError("Wiki graph relation Claim must appear in a section")
        return self


__all__ = [
    "WikiDiffKind",
    "WikiRelationship",
    "WikiRelationshipKind",
    "WikiGraphRelationDeclaration",
    "GraphRelationKind",
    "WikiRevision",
    "WikiRevisionDraft",
    "WikiSection",
    "WikiStance",
    "WikiStatus",
]
