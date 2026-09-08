"""Live-authority-prefiltered SQLite FTS5 retrieval."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)

from .artifact_contracts import ArtifactBinding, retrieval_row_id
from .contracts import CandidateRef, ScoreComponent
from .fts_query import FtsQueryBuilder, FtsQueryError
from .lexical_builder import TokenizerDescriptor
from .normalization import ChineseTokenizer, NormalizationError


class LexicalIndexError(RuntimeError):
    def __init__(self, code: str = "LEXICAL_INDEX_INVALID") -> None:
        super().__init__(code)


class LexicalRetriever:
    def __init__(
        self,
        artifact_binding: ArtifactBinding,
        *,
        tokenizer: ChineseTokenizer | None = None,
        query_builder: FtsQueryBuilder | None = None,
    ) -> None:
        if type(artifact_binding) is not ArtifactBinding:
            raise TypeError("LEXICAL_ARTIFACT_BINDING_REQUIRED")
        if artifact_binding.identity.artifact_key != "lexical":
            raise LexicalIndexError("ARTIFACT_VERSION_MISMATCH")
        self._initialize(
            artifact_binding.path_for("lexical_index"),
            artifact_binding=artifact_binding,
            tokenizer=tokenizer,
            query_builder=query_builder,
        )
        self._verify_artifact_binding()

    def _initialize(
        self,
        index_path: Path,
        *,
        artifact_binding: ArtifactBinding | None,
        tokenizer: ChineseTokenizer | None,
        query_builder: FtsQueryBuilder | None,
    ) -> None:
        if not isinstance(index_path, Path):
            raise TypeError("LEXICAL_INDEX_PATH_REQUIRED")
        self._path = index_path.resolve(strict=True)
        self._artifact_binding = artifact_binding
        self._tokenizer = tokenizer if tokenizer is not None else ChineseTokenizer()
        self._query_builder = query_builder if query_builder is not None else FtsQueryBuilder()
        self._descriptor = TokenizerDescriptor(
            jieba_version=self._tokenizer.jieba_version,
            approved_dictionary_sha256=self._tokenizer.aliases.sha256,
        )

    @classmethod
    def from_artifact_binding(
        cls,
        artifact_binding: ArtifactBinding,
        *,
        tokenizer: ChineseTokenizer | None = None,
        query_builder: FtsQueryBuilder | None = None,
    ) -> "LexicalRetriever":
        return cls(
            artifact_binding,
            tokenizer=tokenizer,
            query_builder=query_builder,
        )

    @classmethod
    def _from_unbound_path_for_test(
        cls,
        index_path: Path,
        *,
        tokenizer: ChineseTokenizer | None = None,
        query_builder: FtsQueryBuilder | None = None,
    ) -> "LexicalRetriever":
        instance = cls.__new__(cls)
        instance._initialize(
            index_path,
            artifact_binding=None,
            tokenizer=tokenizer,
            query_builder=query_builder,
        )
        return instance

    @property
    def artifact_binding(self) -> ArtifactBinding | None:
        return self._artifact_binding

    def _verify_artifact_binding(self) -> None:
        if self._artifact_binding is None:
            return
        try:
            self._artifact_binding.verify_current()
        except Exception:
            raise LexicalIndexError("ARTIFACT_VERSION_MISMATCH") from None

    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        del scope
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("LEXICAL_LIMIT_INVALID")
        self._verify_artifact_binding()
        try:
            return self._search(query, authority_snapshot, limit=limit)
        finally:
            self._verify_artifact_binding()

    def _search(
        self,
        query: str,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        try:
            word_tokens = self._tokenizer.word_tokens(query)
            char_tokens = self._tokenizer.character_tokens(query)
            if not word_tokens and not char_tokens:
                raise FtsQueryError
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
            try:
                connection.execute("PRAGMA query_only = OFF")
                connection.execute("PRAGMA temp_store = MEMORY")
                connection.execute(
                    "CREATE TEMP TABLE allowed_refs("
                    "evidence_id TEXT PRIMARY KEY) WITHOUT ROWID"
                )
                connection.executemany(
                    "INSERT INTO allowed_refs(evidence_id) VALUES (?)",
                    ((identifier,) for identifier in authority_snapshot.allowed_ref_ids),
                )
                self._verify_descriptor(connection)
                ranked: dict[str, tuple[CandidateRef, list[ScoreComponent]]] = {}
                if word_tokens:
                    self._merge_channel(
                        ranked,
                        self._search_channel(
                            connection,
                            table="lexical_word_fts",
                            fts_query=self._query_builder.build_any(word_tokens),
                            limit=limit,
                        ),
                        channel="lexical_word",
                    )
                if char_tokens:
                    self._merge_channel(
                        ranked,
                        self._search_channel(
                            connection,
                            table="lexical_char_fts",
                            fts_query=self._query_builder.build_any(char_tokens),
                            limit=limit,
                        ),
                        channel="lexical_char",
                    )
            finally:
                connection.close()
        except (FtsQueryError, NormalizationError):
            raise LexicalIndexError("LEXICAL_QUERY_INVALID") from None
        except LexicalIndexError:
            raise
        except (sqlite3.Error, ValidationError, TypeError, ValueError):
            raise LexicalIndexError from None

        candidates = tuple(
            candidate.model_copy(
                update={
                    "score": sum(component.score for component in components),
                    "score_components": tuple(components),
                }
            )
            for candidate, components in ranked.values()
        )
        return tuple(
            sorted(
                candidates,
                key=lambda item: (-item.score, retrieval_row_id(item)),
            )[:limit]
        )

    def _verify_descriptor(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT value_json FROM lexical_metadata WHERE key = 'builder'"
        ).fetchone()
        if row is None:
            raise LexicalIndexError
        try:
            metadata = json.loads(str(row[0]))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise LexicalIndexError from None
        if metadata.get("tokenizer_descriptor_id") != self._descriptor.id:
            raise LexicalIndexError("LEXICAL_TOKENIZER_MISMATCH")

    @staticmethod
    def _search_channel(
        connection: sqlite3.Connection,
        *,
        table: str,
        fts_query: str,
        limit: int,
    ) -> tuple[tuple[CandidateRef, int], ...]:
        if table not in {"lexical_word_fts", "lexical_char_fts"}:
            raise LexicalIndexError
        rows = connection.execute(
            f"SELECT document.row_id, document.evidence_id, "
            "document.evidence_version, document.evidence_sha256, "
            "document.content_object_id, document.content_version, "
            "document.content_sha256, document.candidate_json "
            f"FROM {table} "
            "JOIN temp.allowed_refs AS allowed "
            f"  ON allowed.evidence_id = {table}.evidence_id "
            "JOIN lexical_documents AS document "
            f"  ON document.row_id = {table}.row_id "
            f"WHERE {table} MATCH ? "
            f"ORDER BY bm25({table}) ASC, document.row_id ASC LIMIT ?",
            (fts_query, limit),
        ).fetchall()
        result: list[tuple[CandidateRef, int]] = []
        for rank, row in enumerate(rows, start=1):
            candidate = CandidateRef.model_validate_json(str(row[7]), strict=True)
            if (
                retrieval_row_id(candidate) != str(row[0])
                or candidate.reference.object_id != str(row[1])
                or candidate.reference.version != int(row[2])
                or candidate.reference.content_sha256 != str(row[3])
                or candidate.content_ref.object_id != str(row[4])
                or candidate.content_ref.version != int(row[5])
                or candidate.content_ref.content_sha256 != str(row[6])
                or candidate.filter_binding is not None
            ):
                raise LexicalIndexError("LEXICAL_ROW_IDENTITY_MISMATCH")
            result.append((candidate, rank))
        return tuple(result)

    @staticmethod
    def _merge_channel(
        ranked: dict[str, tuple[CandidateRef, list[ScoreComponent]]],
        values: tuple[tuple[CandidateRef, int], ...],
        *,
        channel: str,
    ) -> None:
        for candidate, rank in values:
            identifier = retrieval_row_id(candidate)
            component = ScoreComponent(
                channel=channel,
                rank=rank,
                score=1.0 / (60.0 + rank),
            )
            existing = ranked.get(identifier)
            if existing is None:
                ranked[identifier] = candidate, [component]
            else:
                prior, components = existing
                if prior != candidate:
                    raise LexicalIndexError("LEXICAL_DUPLICATE_IDENTITY")
                components.append(component)


__all__ = ["LexicalIndexError", "LexicalRetriever"]
