"""Artifact-bound retrieval over the body-free Wiki navigation index."""

from __future__ import annotations

import hashlib
import re

from pydantic import ValidationError

from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)

from .artifact_contracts import (
    ArtifactBinding,
    ArtifactBindingIdentity,
    DerivedArtifactBuilderInputV2,
    GenericDerivedBuildManifestV2,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
)
from .contracts import CandidateRef, ScoreComponent, canonical_json_bytes
from .normalization import ChineseTokenizer, NormalizationError
from .wiki_builder import (
    WikiNavigationIndexPayloadV2,
    WikiNavigationIndexRowV2,
    WikiNavigationTokenizerDescriptor,
)


_HAN_TOKEN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+\Z")


class WikiIndexError(RuntimeError):
    def __init__(self, code: str = "WIKI_INDEX_INVALID") -> None:
        self.code = code
        super().__init__(code)


class WikiIndexRetriever:
    """Rank navigation tokens and return exact Claim/Passage authority rows."""

    def __init__(
        self,
        artifact_binding: ArtifactBinding,
        *,
        tokenizer: ChineseTokenizer | None = None,
    ) -> None:
        if type(artifact_binding) is not ArtifactBinding:
            raise TypeError("WIKI_INDEX_ARTIFACT_BINDING_REQUIRED")
        self._artifact_binding = artifact_binding
        self._tokenizer = tokenizer if tokenizer is not None else ChineseTokenizer()
        before = self._verify_artifact_binding()
        try:
            if (
                before.artifact_key != "wiki_index"
                or before.target_runtime_epoch != before.active_runtime_epoch
                or tuple(member.role for member in before.members)
                != derived_artifact_role_layout("wiki_index")
                or tuple(member.media_type for member in before.members)
                != derived_artifact_media_type_layout("wiki_index")
            ):
                raise WikiIndexError("WIKI_INDEX_ARTIFACT_INVALID")
            payloads = {
                role: artifact_binding.path_for(role).read_bytes()
                for role in derived_artifact_role_layout("wiki_index")
            }
            builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
                payloads["wiki_index_builder_input"], strict=True
            )
            build_manifest = GenericDerivedBuildManifestV2.model_validate_json(
                payloads["wiki_index_build_manifest"], strict=True
            )
            payload = WikiNavigationIndexPayloadV2.model_validate_json(
                payloads["wiki_index"], strict=True
            )
            if (
                payloads["wiki_index_builder_input"]
                != canonical_json_bytes(builder_input.model_dump(mode="json"))
                or payloads["wiki_index_build_manifest"]
                != canonical_json_bytes(build_manifest.model_dump(mode="json"))
                or payloads["wiki_index"]
                != canonical_json_bytes(payload.model_dump(mode="json"))
                or builder_input.artifact_kind != "wiki_index"
                or builder_input.source_catalog_version
                != before.source_catalog_version
                or builder_input.target_runtime_epoch != before.target_runtime_epoch
            ):
                raise WikiIndexError("WIKI_INDEX_ARTIFACT_INVALID")
            build_manifest.verify_builder_input(builder_input)
            index_digest = hashlib.sha256(payloads["wiki_index"]).hexdigest()
            if build_manifest.member_content_sha256 != {
                "wiki_index": index_digest
            }:
                raise WikiIndexError("WIKI_INDEX_ARTIFACT_INVALID")
            payload.verify_builder_input(builder_input)
            expected_tokenizer = WikiNavigationTokenizerDescriptor(
                jieba_version=self._tokenizer.jieba_version,
                approved_alias_dictionary_sha256=self._tokenizer.aliases.sha256,
            )
            if payload.tokenizer_descriptor != expected_tokenizer:
                raise WikiIndexError("WIKI_INDEX_TOKENIZER_MISMATCH")
            if any(
                row.authority.metadata.manifest_ref == before.root_ref
                for row in payload.rows
            ):
                raise WikiIndexError("WIKI_INDEX_AUTHORITY_ROOT_INVALID")
            after = self._verify_artifact_binding()
            if after != before:
                raise WikiIndexError("WIKI_INDEX_ARTIFACT_BINDING_STALE")
        except WikiIndexError:
            raise
        except (OSError, TypeError, ValueError, ValidationError):
            raise WikiIndexError("WIKI_INDEX_ARTIFACT_INVALID") from None
        self._builder_input = builder_input
        self._build_manifest = build_manifest
        self._payload = payload
        self._rows = payload.rows

    @property
    def artifact_binding(self) -> ArtifactBinding:
        return self._artifact_binding

    @property
    def payload(self) -> WikiNavigationIndexPayloadV2:
        return self._payload

    def _verify_artifact_binding(self) -> ArtifactBindingIdentity:
        try:
            return self._artifact_binding.verify_current()
        except Exception:
            raise WikiIndexError("WIKI_INDEX_ARTIFACT_BINDING_STALE") from None

    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        """Prefilter by live authority before any scoring or top-k truncation."""

        self._verify_artifact_binding()
        try:
            if type(scope) is not RetrievalScope:
                raise TypeError("WIKI_INDEX_SCOPE_REQUIRED")
            if type(authority_snapshot) is not AuthoritativeFilterSnapshot:
                raise TypeError("WIKI_INDEX_AUTHORITY_SNAPSHOT_REQUIRED")
            if type(limit) is not int or not 1 <= limit <= 1000:
                raise ValueError("WIKI_INDEX_LIMIT_INVALID")
            try:
                return self._search(
                    query,
                    authority_snapshot,
                    limit=limit,
                )
            except NormalizationError:
                raise WikiIndexError("WIKI_INDEX_QUERY_INVALID") from None
            except WikiIndexError:
                raise
            except Exception:
                raise WikiIndexError("WIKI_INDEX_QUERY_FAILED") from None
        finally:
            # This is deliberately unconditional: invalid queries, zero hits,
            # and scoring exceptions all revalidate the active root and CAS.
            self._verify_artifact_binding()

    def _search(
        self,
        query: str,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        query_tokens = self._query_tokens(query)
        allowed_rows = tuple(
            row
            for row in self._rows
            if row.authority.reference.object_id
            in authority_snapshot.allowed_ref_ids
        )
        ranked = tuple(
            (row, score)
            for row in allowed_rows
            if (score := self._score_row(row, query_tokens)) > 0.0
        )
        if not ranked:
            return ()
        # Sparse character overlap (for example a stop-word or the generic
        # page title) must not turn every Claim on a Wiki page into a hit.
        # Relative pruning keeps section-specific matches while still allowing
        # a page-level title/relation query to return all genuinely tied rows.
        best_score = max(score for _row, score in ranked)
        minimum_score = max(2.0, round(best_score * 0.6, 12))
        ordered = sorted(
            (
                (row, score)
                for row, score in ranked
                if score >= minimum_score
            ),
            key=lambda item: (-item[1], item[0].row_id),
        )[:limit]
        return tuple(
            row.candidate(
                score=score,
                score_components=(
                    ScoreComponent(
                        channel="wiki_navigation",
                        rank=rank,
                        score=score,
                    ),
                ),
            )
            for rank, (row, score) in enumerate(ordered, start=1)
        )

    def _query_tokens(
        self,
        query: str,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
        word_tokens = frozenset(self._tokenizer.word_tokens(query))
        character_tokens = self._tokenizer.character_tokens(query)
        character_2grams = frozenset(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is not None and len(token) == 2
        )
        character_3grams = frozenset(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is not None and len(token) == 3
        )
        alphanumeric_tokens = frozenset(
            token
            for token in character_tokens
            if _HAN_TOKEN.fullmatch(token) is None
        )
        if not (
            word_tokens
            or character_2grams
            or character_3grams
            or alphanumeric_tokens
        ):
            raise NormalizationError
        return (
            word_tokens,
            character_2grams,
            character_3grams,
            alphanumeric_tokens,
        )

    @staticmethod
    def _score_row(
        row: WikiNavigationIndexRowV2,
        query_tokens: tuple[
            frozenset[str],
            frozenset[str],
            frozenset[str],
            frozenset[str],
        ],
    ) -> float:
        row_tokens = (
            frozenset(row.word_tokens),
            frozenset(row.character_2grams),
            frozenset(row.character_3grams),
            frozenset(row.alphanumeric_tokens),
        )
        weights = (4.0, 1.0, 2.0, 2.0)
        score = sum(
            weight * len(query_values & row_values) / len(query_values)
            for weight, query_values, row_values in zip(
                weights,
                query_tokens,
                row_tokens,
                strict=True,
            )
            if query_values
        )
        return round(score, 12)


__all__ = ["WikiIndexError", "WikiIndexRetriever"]
