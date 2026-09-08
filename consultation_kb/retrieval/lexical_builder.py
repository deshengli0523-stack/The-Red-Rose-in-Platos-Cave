"""Immutable lexical artifact builder."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from pathlib import Path

from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    Sha256Hex,
    StrictModel,
)

from .artifact_contracts import DerivedArtifactBuilderInputV2, retrieval_row_id
from .contracts import CandidateRef, canonical_json_bytes
from .filters import assert_case_index_text_safe
from .lexical_schema import SCHEMA_VERSION, create
from .normalization import ChineseTokenizer, NORMALIZATION_VERSION


class LexicalBuildError(RuntimeError):
    def __init__(self, code: str = "LEXICAL_BUILD_INVALID") -> None:
        super().__init__(code)


class LexicalDocument(StrictModel):
    candidate: CandidateRef
    text: NonEmptyStr

    @model_validator(mode="after")
    def _case_text_boundary(self) -> "LexicalDocument":
        assert_case_index_text_safe(self.candidate, self.text)
        return self


class TokenizerDescriptor(StrictModel):
    schema_version: str = SCHEMA_VERSION
    normalization_version: str = NORMALIZATION_VERSION
    jieba_version: NonEmptyStr
    approved_dictionary_sha256: Sha256Hex
    ngram_min: PositiveInt = 2
    ngram_max: PositiveInt = 3

    @field_validator("ngram_max")
    @classmethod
    def _ngram_range(cls, value: int) -> int:
        if value != 3:
            raise ValueError("lexical ngram range is frozen at 2-3")
        return value

    @property
    def id(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json"))
        ).hexdigest()


class LexicalBuildManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    tokenizer_descriptor: TokenizerDescriptor
    tokenizer_descriptor_id: Sha256Hex
    builder_input_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    source_catalog_version: NonNegativeInt
    target_runtime_epoch: PositiveInt
    row_content_hashes: tuple[Sha256Hex, ...]
    row_mapping_sha256: Sha256Hex
    index_sha256: Sha256Hex
    row_count: NonNegativeInt

    @field_validator("row_content_hashes")
    @classmethod
    def _canonical_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("lexical row hashes must be unique")
        return tuple(sorted(value))


class LexicalIndexBuilder:
    def __init__(self, tokenizer: ChineseTokenizer | None = None) -> None:
        self._tokenizer = tokenizer if tokenizer is not None else ChineseTokenizer()

    @property
    def descriptor(self) -> TokenizerDescriptor:
        return TokenizerDescriptor(
            jieba_version=self._tokenizer.jieba_version,
            approved_dictionary_sha256=self._tokenizer.aliases.sha256,
        )

    def build(
        self,
        documents: tuple[LexicalDocument, ...],
        output_path: Path,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> LexicalBuildManifest:
        if type(documents) is not tuple or not documents:
            raise LexicalBuildError("LEXICAL_DOCUMENTS_REQUIRED")
        if not isinstance(output_path, Path) or output_path.suffix.lower() not in {
            ".sqlite",
            ".sqlite3",
            ".db",
        }:
            raise LexicalBuildError
        if (
            type(builder_input) is not DerivedArtifactBuilderInputV2
            or builder_input.artifact_kind != "lexical"
        ):
            raise LexicalBuildError
        source_catalog_version = builder_input.source_catalog_version
        ordered_documents = tuple(
            sorted(
                documents,
                key=lambda item: (
                    item.candidate.reference.object_id,
                    item.candidate.reference.version,
                    item.candidate.reference.content_sha256,
                    item.candidate.content_ref.object_id,
                    item.candidate.content_ref.version,
                    item.candidate.content_ref.content_sha256,
                ),
            )
        )
        try:
            builder_input.retrieval_input_descriptor.verify_candidates(
                "lexical",
                tuple(document.candidate for document in ordered_documents),
            )
        except (TypeError, ValueError):
            raise LexicalBuildError("LEXICAL_INPUT_SET_MISMATCH") from None
        target = output_path.resolve(strict=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise LexicalBuildError("LEXICAL_IMMUTABLE_TARGET_EXISTS")
        temporary = target.with_name(f".{target.name}.{secrets.token_hex(12)}.stage")
        row_hashes: list[str] = []
        descriptor = self.descriptor
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(temporary, isolation_level=None)
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            create(connection)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO lexical_metadata(key, value_json) VALUES (?, ?)",
                (
                    "builder",
                    json.dumps(
                        {
                            "assigned_input_set_sha256": builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                                "lexical"
                            ),
                            "builder_input_sha256": builder_input.canonical_sha256,
                            "retrieval_input_descriptor_sha256": builder_input.retrieval_input_descriptor.descriptor_sha256,
                            "row_mapping_sha256": builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                                "lexical"
                            ),
                            "schema_version": SCHEMA_VERSION,
                            "source_catalog_version": source_catalog_version,
                            "target_runtime_epoch": builder_input.target_runtime_epoch,
                            "tokenizer_descriptor": descriptor.model_dump(mode="json"),
                            "tokenizer_descriptor_id": descriptor.id,
                        },
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            seen: set[str] = set()
            for document in ordered_documents:
                candidate = document.candidate
                row_id = retrieval_row_id(candidate)
                encoded_text = document.text.encode("utf-8")
                if (
                    candidate.filter_binding is not None
                    or candidate.metadata.review_status != "approved"
                    or row_id in seen
                    or hashlib.sha256(encoded_text).hexdigest()
                    != candidate.content_ref.content_sha256
                    or len(encoded_text) != candidate.metadata.size_bytes
                ):
                    raise LexicalBuildError
                seen.add(row_id)
                word_tokens = self._tokenizer.word_tokens(document.text)
                char_tokens = self._tokenizer.character_tokens(document.text)
                if not word_tokens and not char_tokens:
                    raise LexicalBuildError
                candidate_json = candidate.model_dump_json()
                row_sha256 = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "candidate": candidate.model_dump(mode="json"),
                            "char_tokens": char_tokens,
                            "word_tokens": word_tokens,
                        }
                    )
                ).hexdigest()
                provenance_sha256 = hashlib.sha256(
                    canonical_json_bytes(candidate.provenance.model_dump(mode="json"))
                ).hexdigest()
                connection.execute(
                    "INSERT INTO lexical_documents("
                    "row_id, evidence_id, evidence_version, evidence_sha256, "
                    "content_object_id, content_version, content_sha256, "
                    "candidate_json, row_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row_id,
                        candidate.reference.object_id,
                        candidate.reference.version,
                        candidate.reference.content_sha256,
                        candidate.content_ref.object_id,
                        candidate.content_ref.version,
                        candidate.content_ref.content_sha256,
                        candidate_json,
                        row_sha256,
                    ),
                )
                connection.execute(
                    "INSERT INTO lexical_provenance(row_id, provenance_sha256) "
                    "VALUES (?, ?)",
                    (row_id, provenance_sha256),
                )
                connection.execute(
                    "INSERT INTO lexical_word_fts(row_id, evidence_id, tokens) "
                    "VALUES (?, ?, ?)",
                    (row_id, candidate.reference.object_id, " ".join(word_tokens)),
                )
                connection.execute(
                    "INSERT INTO lexical_char_fts(row_id, evidence_id, tokens) "
                    "VALUES (?, ?, ?)",
                    (row_id, candidate.reference.object_id, " ".join(char_tokens)),
                )
                row_hashes.append(row_sha256)
            connection.execute("COMMIT")
            connection.execute("PRAGMA optimize")
            connection.close()
            connection = None
            # Hard-link publication is atomic and fails if the immutable target
            # appeared concurrently. Removing the staging name leaves one link.
            os.link(temporary, target)
            temporary.unlink()
            index_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            return LexicalBuildManifest(
                tokenizer_descriptor=descriptor,
                tokenizer_descriptor_id=descriptor.id,
                builder_input_sha256=builder_input.canonical_sha256,
                retrieval_input_descriptor_sha256=(
                    builder_input.retrieval_input_descriptor.descriptor_sha256
                ),
                assigned_input_set_sha256=(
                    builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                        "lexical"
                    )
                ),
                source_catalog_version=source_catalog_version,
                target_runtime_epoch=builder_input.target_runtime_epoch,
                row_content_hashes=tuple(row_hashes),
                row_mapping_sha256=(
                    builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                        "lexical"
                    )
                ),
                index_sha256=index_sha256,
                row_count=len(row_hashes),
            )
        except LexicalBuildError:
            raise
        except Exception as exc:
            raise LexicalBuildError from exc
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
            temporary.unlink(missing_ok=True)


__all__ = [
    "LexicalBuildError",
    "LexicalBuildManifest",
    "LexicalDocument",
    "LexicalIndexBuilder",
    "TokenizerDescriptor",
]
