"""Deterministic, body-free Wiki navigation index construction.

Wiki prose is useful for navigation, but it is not evidence.  This module
therefore stores only deterministic tokens derived from the exact governed
Wiki revision.  Every retrievable row remains one exact approved
Claim/SUPPORTS-Passage authority input reconstructed by P3.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import field_validator, model_validator

from consultation_kb.knowledge.wiki import (
    wiki_revision_body_payload,
    wiki_revision_body_sha256,
)
from consultation_kb.models.common import (
    NonEmptyStr,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.wiki import WikiRevision

from .artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    GenericDerivedBuildManifestV2,
    RetrievalAuthorityInput,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
    retrieval_row_id,
)
from .contracts import CandidateRef, ScoreComponent, canonical_json_bytes
from .normalization import (
    ChineseTokenizer,
    NORMALIZATION_VERSION,
    NormalizationError,
)


_CLIENT_ID = re.compile(r"client_[a-z0-9]{12}", re.IGNORECASE)
_HAN_TOKEN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+\Z")


class WikiIndexBuildError(RuntimeError):
    def __init__(self, code: str = "WIKI_INDEX_BUILD_INVALID") -> None:
        self.code = code
        super().__init__(code)


def _sha256(value: object, *, domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _pair_key(
    authority: RetrievalAuthorityInput,
) -> tuple[str, int, str, str, int, str]:
    return (*_ref_key(authority.reference), *_ref_key(authority.content_ref))


def _authority_candidate(
    authority: RetrievalAuthorityInput,
    *,
    score: float = 0.0,
    score_components: tuple[ScoreComponent, ...] = (),
) -> CandidateRef:
    """Reconstruct the sole body-free Candidate representation for a Wiki row."""

    exact = RetrievalAuthorityInput.model_validate(authority)
    return CandidateRef(
        reference=exact.reference,
        content_ref=exact.content_ref,
        object_type=exact.object_type,
        channel="wiki",
        metadata=exact.metadata,
        provenance=exact.provenance,
        location=exact.location,
        freshness=exact.freshness,
        score=score,
        score_components=score_components,
    )


class WikiNavigationTokenizerDescriptor(StrictModel):
    contract: Literal["wiki_navigation_tokenizer_v1"] = (
        "wiki_navigation_tokenizer_v1"
    )
    normalization_version: NonEmptyStr = NORMALIZATION_VERSION
    jieba_version: NonEmptyStr
    approved_alias_dictionary_sha256: Sha256Hex
    ngram_min: Literal[2] = 2
    ngram_max: Literal[3] = 3

    @property
    def canonical_sha256(self) -> str:
        return _sha256(
            self.model_dump(mode="json"),
            domain=b"consultation-kb-wiki-navigation-tokenizer-v1\0",
        )


class WikiNavigationIndexRowV2(StrictModel):
    """One exact Claim/Passage authority row with navigation-only tokens."""

    row_id: Sha256Hex
    authority: RetrievalAuthorityInput
    section_keys: tuple[SafePolicyKey, ...]
    word_tokens: tuple[NonEmptyStr, ...]
    character_2grams: tuple[NonEmptyStr, ...]
    character_3grams: tuple[NonEmptyStr, ...]
    alphanumeric_tokens: tuple[NonEmptyStr, ...]
    navigation_source_sha256: Sha256Hex
    row_closure_sha256: Sha256Hex

    @field_validator("section_keys")
    @classmethod
    def _canonical_sections(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("WIKI_INDEX_SECTION_KEYS_INVALID")
        return value

    @field_validator(
        "word_tokens",
        "character_2grams",
        "character_3grams",
        "alphanumeric_tokens",
    )
    @classmethod
    def _canonical_tokens(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("WIKI_INDEX_TOKENS_INVALID")
        return value

    @model_validator(mode="after")
    def _verify_row(self) -> "WikiNavigationIndexRowV2":
        authority = self.authority
        provenance = authority.provenance
        if (
            authority.reference.object_id[:-37] != "claim"
            or authority.content_ref.object_id[:-37] != "passage"
            or authority.object_type != "claim"
            or authority.metadata.review_status != "approved"
            or "consultation" not in authority.metadata.allowed_uses
            or authority.metadata.leave_one_out is not None
            or provenance.provenance_scope != "global_source"
            or provenance.client_ids
            or provenance.case_ids
            or provenance.case_contributor_client_ids
            or provenance.private_owner_client_id is not None
            or authority.content_ref.object_id not in provenance.passage_ids
            or authority.content_ref not in authority.location.anchor_refs
            or not (
                self.word_tokens
                or self.character_2grams
                or self.character_3grams
                or self.alphanumeric_tokens
            )
        ):
            raise ValueError("WIKI_INDEX_AUTHORITY_INVALID")
        if any(
            _HAN_TOKEN.fullmatch(token) is None or len(token) != width
            for width, tokens in (
                (2, self.character_2grams),
                (3, self.character_3grams),
            )
            for token in tokens
        ):
            raise ValueError("WIKI_INDEX_NGRAMS_INVALID")
        candidate = _authority_candidate(authority)
        if self.row_id != retrieval_row_id(candidate):
            raise ValueError("WIKI_INDEX_ROW_ID_MISMATCH")
        expected = self.calculate_closure(
            row_id=self.row_id,
            authority=authority,
            section_keys=self.section_keys,
            word_tokens=self.word_tokens,
            character_2grams=self.character_2grams,
            character_3grams=self.character_3grams,
            alphanumeric_tokens=self.alphanumeric_tokens,
            navigation_source_sha256=self.navigation_source_sha256,
        )
        if self.row_closure_sha256 != expected:
            raise ValueError("WIKI_INDEX_ROW_CLOSURE_MISMATCH")
        return self

    @staticmethod
    def calculate_closure(
        *,
        row_id: str,
        authority: RetrievalAuthorityInput,
        section_keys: tuple[str, ...],
        word_tokens: tuple[str, ...],
        character_2grams: tuple[str, ...],
        character_3grams: tuple[str, ...],
        alphanumeric_tokens: tuple[str, ...],
        navigation_source_sha256: str,
    ) -> str:
        return _sha256(
            {
                "alphanumeric_tokens": alphanumeric_tokens,
                "authority": authority.model_dump(mode="json"),
                "character_2grams": character_2grams,
                "character_3grams": character_3grams,
                "navigation_source_sha256": navigation_source_sha256,
                "row_id": row_id,
                "section_keys": section_keys,
                "word_tokens": word_tokens,
            },
            domain=b"consultation-kb-wiki-navigation-row-v2\0",
        )

    @classmethod
    def create(
        cls,
        *,
        authority: RetrievalAuthorityInput,
        section_keys: tuple[str, ...],
        word_tokens: tuple[str, ...],
        character_2grams: tuple[str, ...],
        character_3grams: tuple[str, ...],
        alphanumeric_tokens: tuple[str, ...],
        navigation_source_sha256: str,
    ) -> "WikiNavigationIndexRowV2":
        candidate = _authority_candidate(authority)
        row_id = retrieval_row_id(candidate)
        values = {
            "row_id": row_id,
            "authority": authority,
            "section_keys": section_keys,
            "word_tokens": word_tokens,
            "character_2grams": character_2grams,
            "character_3grams": character_3grams,
            "alphanumeric_tokens": alphanumeric_tokens,
            "navigation_source_sha256": navigation_source_sha256,
        }
        return cls(
            **values,  # type: ignore[arg-type]
            row_closure_sha256=cls.calculate_closure(**values),  # type: ignore[arg-type]
        )

    def candidate(
        self,
        *,
        score: float = 0.0,
        score_components: tuple[ScoreComponent, ...] = (),
    ) -> CandidateRef:
        return _authority_candidate(
            self.authority,
            score=score,
            score_components=score_components,
        )


class WikiNavigationIndexPayloadV2(StrictModel):
    """Canonical CAS payload for body-free Wiki navigation retrieval."""

    contract: Literal["wiki_navigation_index_v2"] = "wiki_navigation_index_v2"
    builder_input_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    expected_row_mapping_sha256: Sha256Hex
    source_catalog_version: PositiveInt
    target_runtime_epoch: PositiveInt
    wiki_ref: VersionRef
    governed_wiki_refs: tuple[VersionRef, ...] = ()
    tokenizer_descriptor: WikiNavigationTokenizerDescriptor
    rows: tuple[WikiNavigationIndexRowV2, ...]
    index_closure_sha256: Sha256Hex

    @field_validator("rows")
    @classmethod
    def _canonical_rows(
        cls,
        value: tuple[WikiNavigationIndexRowV2, ...],
    ) -> tuple[WikiNavigationIndexRowV2, ...]:
        keys = tuple(_pair_key(row.authority) for row in value)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("WIKI_INDEX_ROWS_INVALID")
        return value

    @field_validator("governed_wiki_refs")
    @classmethod
    def _canonical_wiki_refs(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        keys = tuple(_ref_key(reference) for reference in value)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("WIKI_INDEX_WIKI_REFS_INVALID")
        return value

    @model_validator(mode="after")
    def _verify_index_closure(self) -> "WikiNavigationIndexPayloadV2":
        if (
            self.wiki_ref.object_id[:-37] != "wiki"
            or self.wiki_ref not in self.governed_wiki_refs
            or any(
                reference.object_id[:-37] != "wiki"
                for reference in self.governed_wiki_refs
            )
        ):
            raise ValueError("WIKI_INDEX_WIKI_REF_INVALID")
        expected = self.calculate_closure(
            self.model_dump(mode="json", exclude={"index_closure_sha256"})
        )
        if self.index_closure_sha256 != expected:
            raise ValueError("WIKI_INDEX_CLOSURE_MISMATCH")
        return self

    @staticmethod
    def calculate_closure(payload: object) -> str:
        return _sha256(
            payload,
            domain=b"consultation-kb-wiki-navigation-index-v2\0",
        )

    @classmethod
    def create(
        cls,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
        wiki_ref: VersionRef,
        governed_wiki_refs: tuple[VersionRef, ...] | None = None,
        tokenizer_descriptor: WikiNavigationTokenizerDescriptor,
        rows: tuple[WikiNavigationIndexRowV2, ...],
    ) -> "WikiNavigationIndexPayloadV2":
        descriptor = builder_input.retrieval_input_descriptor
        wiki_refs = tuple(
            sorted(
                governed_wiki_refs or (wiki_ref,),
                key=_ref_key,
            )
        )
        values: dict[str, object] = {
            "contract": "wiki_navigation_index_v2",
            "builder_input_sha256": builder_input.canonical_sha256,
            "retrieval_input_descriptor_sha256": descriptor.descriptor_sha256,
            "assigned_input_set_sha256": descriptor.assigned_input_set_sha256(
                "wiki_index"
            ),
            "expected_row_mapping_sha256": descriptor.expected_row_mapping_sha256(
                "wiki_index"
            ),
            "source_catalog_version": builder_input.source_catalog_version,
            "target_runtime_epoch": builder_input.target_runtime_epoch,
            "wiki_ref": wiki_ref,
            "governed_wiki_refs": wiki_refs,
            "tokenizer_descriptor": tokenizer_descriptor,
            "rows": rows,
        }
        closure_payload = {
            **values,
            "wiki_ref": wiki_ref.model_dump(mode="json"),
            "governed_wiki_refs": [
                reference.model_dump(mode="json") for reference in wiki_refs
            ],
            "tokenizer_descriptor": tokenizer_descriptor.model_dump(mode="json"),
            "rows": [row.model_dump(mode="json") for row in rows],
        }
        return cls(
            **values,  # type: ignore[arg-type]
            index_closure_sha256=cls.calculate_closure(closure_payload),
        )

    def verify_descriptor(self, descriptor: RetrievalInputDescriptor) -> None:
        exact = RetrievalInputDescriptor.model_validate(descriptor)
        records = exact.assigned_records("wiki_index")
        if (
            self.retrieval_input_descriptor_sha256 != exact.descriptor_sha256
            or self.assigned_input_set_sha256
            != exact.assigned_input_set_sha256("wiki_index")
            or self.expected_row_mapping_sha256
            != exact.expected_row_mapping_sha256("wiki_index")
            or len(self.rows) != len(records)
        ):
            raise ValueError("WIKI_INDEX_DESCRIPTOR_MISMATCH")
        for row, record in zip(self.rows, records, strict=True):
            try:
                assignment = RetrievalInputAssignment(
                    authority=row.authority,
                    target_channels=record.target_channels,
                )
            except ValueError:
                raise ValueError("WIKI_INDEX_DESCRIPTOR_MISMATCH") from None
            if assignment.to_record() != record:
                raise ValueError("WIKI_INDEX_DESCRIPTOR_MISMATCH")

    def verify_builder_input(
        self,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> None:
        exact = DerivedArtifactBuilderInputV2.model_validate(builder_input)
        wiki = exact.authority_snapshot.wiki
        if (
            exact.artifact_kind != "wiki_index"
            or self.builder_input_sha256 != exact.canonical_sha256
            or self.source_catalog_version != exact.source_catalog_version
            or self.target_runtime_epoch != exact.target_runtime_epoch
            or wiki is None
            or _ref_key(self.wiki_ref)
            != (wiki.object_id, wiki.version, wiki.object_sha256)
        ):
            raise ValueError("WIKI_INDEX_BUILDER_INPUT_MISMATCH")
        self.verify_descriptor(exact.retrieval_input_descriptor)

    def verify_source(
        self,
        builder_input: DerivedArtifactBuilderInputV2,
        wiki_revision: WikiRevision,
        *,
        tokenizer: ChineseTokenizer | None = None,
    ) -> None:
        """Rebuild tokens from the exact Wiki authority to defeat a forged builder."""

        self.verify_builder_input(builder_input)
        records = builder_input.retrieval_input_descriptor.assigned_records(
            "wiki_index"
        )
        assignments = tuple(
            RetrievalInputAssignment(
                authority=row.authority,
                target_channels=record.target_channels,
            )
            for row, record in zip(self.rows, records, strict=True)
        )
        expected = WikiNavigationIndexBuilder(tokenizer).build(
            assignments,
            wiki_revision,
            builder_input=builder_input,
        ).payload
        if self != expected:
            raise ValueError("WIKI_INDEX_SOURCE_MISMATCH")

    def verify_sources(
        self,
        builder_input: DerivedArtifactBuilderInputV2,
        wiki_revisions: tuple[WikiRevision, ...],
        *,
        tokenizer: ChineseTokenizer | None = None,
    ) -> None:
        self.verify_builder_input(builder_input)
        records = builder_input.retrieval_input_descriptor.assigned_records(
            "wiki_index"
        )
        assignments = tuple(
            RetrievalInputAssignment(
                authority=row.authority,
                target_channels=record.target_channels,
            )
            for row, record in zip(self.rows, records, strict=True)
        )
        expected = WikiNavigationIndexBuilder(tokenizer).build_many(
            assignments,
            wiki_revisions,
            target_wiki_ref=self.wiki_ref,
            builder_input=builder_input,
        ).payload
        if self != expected:
            raise ValueError("WIKI_INDEX_SOURCE_MISMATCH")


@dataclass(frozen=True, slots=True)
class WikiIndexBuildArtifacts:
    payload: WikiNavigationIndexPayloadV2
    build_manifest: GenericDerivedBuildManifestV2

    @property
    def index_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload.model_dump(mode="json"))

    @property
    def build_manifest_bytes(self) -> bytes:
        return canonical_json_bytes(self.build_manifest.model_dump(mode="json"))


class WikiNavigationIndexBuilder:
    """Compile one exact P3 authority assignment set and Wiki revision."""

    def __init__(self, tokenizer: ChineseTokenizer | None = None) -> None:
        self._tokenizer = tokenizer if tokenizer is not None else ChineseTokenizer()

    @property
    def tokenizer_descriptor(self) -> WikiNavigationTokenizerDescriptor:
        return WikiNavigationTokenizerDescriptor(
            jieba_version=self._tokenizer.jieba_version,
            approved_alias_dictionary_sha256=self._tokenizer.aliases.sha256,
        )

    def build(
        self,
        assignments: tuple[RetrievalInputAssignment, ...],
        wiki_revision: WikiRevision,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> WikiIndexBuildArtifacts:
        wiki_ref = VersionRef(
                object_id=wiki_revision.wiki_id,
                version=wiki_revision.revision,
                content_sha256=wiki_revision.body_sha256,
            )
        return self.build_many(
            assignments,
            (wiki_revision,),
            target_wiki_ref=wiki_ref,
            builder_input=builder_input,
        )

    def build_many(
        self,
        assignments: tuple[RetrievalInputAssignment, ...],
        wiki_revisions: tuple[WikiRevision, ...],
        *,
        target_wiki_ref: VersionRef,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> WikiIndexBuildArtifacts:
        try:
            ordered, wikis = self._validate_many_inputs(
                assignments,
                wiki_revisions,
                target_wiki_ref=target_wiki_ref,
                builder_input=builder_input,
            )
            rows = tuple(
                self._row_many(assignment.authority, wikis)
                for assignment in ordered
            )
            payload = WikiNavigationIndexPayloadV2.create(
                builder_input=builder_input,
                wiki_ref=target_wiki_ref,
                governed_wiki_refs=tuple(
                    VersionRef(
                        object_id=value.wiki_id,
                        version=value.revision,
                        content_sha256=value.body_sha256,
                    )
                    for value in wikis
                ),
                tokenizer_descriptor=self.tokenizer_descriptor,
                rows=rows,
            )
            payload.verify_builder_input(builder_input)
            index_bytes = canonical_json_bytes(payload.model_dump(mode="json"))
            manifest = GenericDerivedBuildManifestV2.create(
                artifact_kind="wiki_index",
                builder_input=builder_input,
                member_content_sha256={
                    "wiki_index": hashlib.sha256(index_bytes).hexdigest()
                },
            )
            return WikiIndexBuildArtifacts(
                payload=payload,
                build_manifest=manifest,
            )
        except WikiIndexBuildError:
            raise
        except (NormalizationError, TypeError, ValueError):
            raise WikiIndexBuildError() from None

    @classmethod
    def _validate_many_inputs(
        cls,
        assignments: tuple[RetrievalInputAssignment, ...],
        wiki_revisions: tuple[WikiRevision, ...],
        *,
        target_wiki_ref: VersionRef,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> tuple[tuple[RetrievalInputAssignment, ...], tuple[WikiRevision, ...]]:
        if (
            type(wiki_revisions) is not tuple
            or not wiki_revisions
            or any(type(value) is not WikiRevision for value in wiki_revisions)
        ):
            raise WikiIndexBuildError()
        wikis = tuple(
            sorted(
                wiki_revisions,
                key=lambda value: (
                    value.wiki_id,
                    value.revision,
                    value.body_sha256,
                ),
            )
        )
        if len({value.wiki_id for value in wikis}) != len(wikis):
            raise WikiIndexBuildError("WIKI_INDEX_WIKI_AUTHORITY_MISMATCH")
        target = next(
            (
                value
                for value in wikis
                if (
                    value.wiki_id,
                    value.revision,
                    value.body_sha256,
                )
                == _ref_key(target_wiki_ref)
            ),
            None,
        )
        if target is None:
            raise WikiIndexBuildError("WIKI_INDEX_WIKI_AUTHORITY_MISMATCH")
        ordered = cls._validate_inputs(
            assignments,
            target,
            builder_input=builder_input,
            governed_wikis=wikis,
        )
        return ordered, wikis

    @staticmethod
    def _validate_inputs(
        assignments: tuple[RetrievalInputAssignment, ...],
        wiki_revision: WikiRevision,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
        governed_wikis: tuple[WikiRevision, ...] | None = None,
    ) -> tuple[RetrievalInputAssignment, ...]:
        if (
            type(builder_input) is not DerivedArtifactBuilderInputV2
            or builder_input.artifact_kind != "wiki_index"
            or type(wiki_revision) is not WikiRevision
            or wiki_revision.status != "prepared"
            or wiki_revision.approval_request_id is None
            or type(assignments) is not tuple
            or any(
                type(assignment) is not RetrievalInputAssignment
                for assignment in assignments
            )
        ):
            raise WikiIndexBuildError()
        if wiki_revision_body_sha256(wiki_revision) != wiki_revision.body_sha256:
            raise WikiIndexBuildError("WIKI_INDEX_WIKI_BODY_MISMATCH")
        wiki_authority = builder_input.authority_snapshot.wiki
        if wiki_authority is None or (
            wiki_revision.wiki_id,
            wiki_revision.revision,
            wiki_revision.body_sha256,
        ) != (
            wiki_authority.object_id,
            wiki_authority.version,
            wiki_authority.object_sha256,
        ):
            raise WikiIndexBuildError("WIKI_INDEX_WIKI_AUTHORITY_MISMATCH")

        descriptor = builder_input.retrieval_input_descriptor
        expected = descriptor.assigned_records("wiki_index")
        ordered = tuple(sorted(assignments, key=lambda value: _pair_key(value.authority)))
        actual = tuple(assignment.to_record() for assignment in ordered)
        if actual != expected:
            raise WikiIndexBuildError("WIKI_INDEX_INPUT_SET_MISMATCH")

        wikis = governed_wikis or (wiki_revision,)
        if any(
            value.status not in {"prepared", "active"}
            or wiki_revision_body_sha256(value) != value.body_sha256
            for value in wikis
        ):
            raise WikiIndexBuildError("WIKI_INDEX_WIKI_BODY_MISMATCH")
        wiki_claims = {
            _ref_key(reference)
            for value in wikis
            for section in value.sections
            for reference in section.claim_refs
        }
        assigned_claims = {
            _ref_key(assignment.authority.reference) for assignment in ordered
        }
        if assigned_claims != wiki_claims:
            raise WikiIndexBuildError("WIKI_INDEX_CLAIM_SET_MISMATCH")
        snapshot_claims = {
            (claim.object_id, claim.version, claim.object_sha256)
            for claim in builder_input.authority_snapshot.claims
        }
        if not assigned_claims <= snapshot_claims:
            raise WikiIndexBuildError("WIKI_INDEX_CLAIM_AUTHORITY_MISMATCH")

        for value in wikis:
            source_payload = wiki_revision_body_payload(value)
            if _CLIENT_ID.search(
                canonical_json_bytes(source_payload).decode("utf-8")
            ) is not None:
                raise WikiIndexBuildError("WIKI_INDEX_CLIENT_DATA_FORBIDDEN")
        # Row validation enforces global provenance, approval, SUPPORTS Passage
        # anchoring, consultation use, and absence of client/case authority.
        for assignment in ordered:
            authority = assignment.authority
            sections = tuple(
                section
                for value in wikis
                for section in value.sections
                if authority.reference in section.claim_refs
            )
            if not sections:
                raise WikiIndexBuildError("WIKI_INDEX_SECTION_BINDING_MISSING")
            WikiNavigationIndexRowV2.create(
                authority=authority,
                section_keys=tuple(sorted({section.key for section in sections})),
                word_tokens=("authority",),
                character_2grams=(),
                character_3grams=(),
                alphanumeric_tokens=(),
                navigation_source_sha256="0" * 64,
            )
        return ordered

    def _row(
        self,
        authority: RetrievalAuthorityInput,
        wiki_revision: WikiRevision,
    ) -> WikiNavigationIndexRowV2:
        sections = tuple(
            section
            for section in wiki_revision.sections
            if authority.reference in section.claim_refs
        )
        graph_relations = tuple(
            relation
            for relation in wiki_revision.graph_relations
            if relation.claim_ref == authority.reference
        )
        navigation_source = {
            "graph_relations": [
                relation.model_dump(mode="json") for relation in graph_relations
            ],
            "relationships": [
                relationship.model_dump(mode="json")
                for relationship in wiki_revision.relationships
            ],
            "sections": [section.model_dump(mode="json") for section in sections],
            "slug": wiki_revision.slug,
            "theory_revision_refs": [
                reference.model_dump(mode="json")
                for reference in wiki_revision.theory_revision_refs
            ],
            "title": wiki_revision.title,
            "unresolved_questions": wiki_revision.unresolved_questions,
            "wiki_body_sha256": wiki_revision.body_sha256,
        }
        source_sha256 = _sha256(
            navigation_source,
            domain=b"consultation-kb-wiki-navigation-source-v1\0",
        )
        text_parts: list[str] = [wiki_revision.slug, wiki_revision.title]
        for section in sections:
            text_parts.extend(
                (section.key, section.heading, section.body, section.stance)
            )
        for relationship in wiki_revision.relationships:
            text_parts.extend(
                (
                    relationship.target_id[:-37],
                    relationship.relationship,
                    *relationship.scope,
                )
            )
        for relation in graph_relations:
            text_parts.extend(
                (
                    relation.source_ref.object_id[:-37],
                    relation.target_ref.object_id[:-37],
                    relation.relation,
                    *relation.scope,
                )
            )
        text_parts.extend(wiki_revision.unresolved_questions)
        text_parts.extend(
            reference.object_id[:-37]
            for reference in wiki_revision.theory_revision_refs
        )
        navigation_text = "\n".join(text_parts)
        word_tokens = self._tokenizer.word_tokens(navigation_text)
        character_tokens = self._tokenizer.character_tokens(navigation_text)
        character_2grams = tuple(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is not None and len(token) == 2
        )
        character_3grams = tuple(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is not None and len(token) == 3
        )
        alphanumeric_tokens = tuple(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is None
        )
        if len(character_tokens) != (
            len(character_2grams)
            + len(character_3grams)
            + len(alphanumeric_tokens)
        ):
            raise WikiIndexBuildError("WIKI_INDEX_TOKENIZATION_INVALID")
        return WikiNavigationIndexRowV2.create(
            authority=authority,
            section_keys=tuple(sorted(section.key for section in sections)),
            word_tokens=word_tokens,
            character_2grams=character_2grams,
            character_3grams=character_3grams,
            alphanumeric_tokens=alphanumeric_tokens,
            navigation_source_sha256=source_sha256,
        )

    def _row_many(
        self,
        authority: RetrievalAuthorityInput,
        wiki_revisions: tuple[WikiRevision, ...],
    ) -> WikiNavigationIndexRowV2:
        if len(wiki_revisions) == 1:
            return self._row(authority, wiki_revisions[0])
        relevant = tuple(
            wiki
            for wiki in wiki_revisions
            if any(
                authority.reference in section.claim_refs
                for section in wiki.sections
            )
        )
        if not relevant:
            raise WikiIndexBuildError("WIKI_INDEX_SECTION_BINDING_MISSING")
        rows = tuple(self._row(authority, wiki) for wiki in relevant)
        navigation_source = {
            "wiki_rows": [
                {
                    "wiki_ref": {
                        "object_id": wiki.wiki_id,
                        "version": wiki.revision,
                        "content_sha256": wiki.body_sha256,
                    },
                    "navigation_source_sha256": row.navigation_source_sha256,
                }
                for wiki, row in zip(relevant, rows, strict=True)
            ]
        }
        return WikiNavigationIndexRowV2.create(
            authority=authority,
            section_keys=tuple(
                sorted(
                    {
                        section.key
                        for wiki in relevant
                        for section in wiki.sections
                        if authority.reference in section.claim_refs
                    }
                )
            ),
            word_tokens=tuple(
                sorted({token for row in rows for token in row.word_tokens})
            ),
            character_2grams=tuple(
                sorted({token for row in rows for token in row.character_2grams})
            ),
            character_3grams=tuple(
                sorted({token for row in rows for token in row.character_3grams})
            ),
            alphanumeric_tokens=tuple(
                sorted({token for row in rows for token in row.alphanumeric_tokens})
            ),
            navigation_source_sha256=_sha256(
                navigation_source,
                domain=b"consultation-kb-wiki-navigation-source-set-v1\0",
            ),
        )


__all__ = [
    "WikiIndexBuildArtifacts",
    "WikiIndexBuildError",
    "WikiNavigationIndexBuilder",
    "WikiNavigationIndexPayloadV2",
    "WikiNavigationIndexRowV2",
    "WikiNavigationTokenizerDescriptor",
]
