"""Domain-aware Passage segmentation without evidence-boundary merging."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Literal, cast

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EvidenceLocator, Provenance
from consultation_kb.models.knowledge import DocumentType, PassageRecord, ReviewStatus
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.core.ids import IdFactory
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.storage.connection import transaction

from ._canonical import canonical_sha256
from .approval import GovernedWriteExecutor
from .anchors import deterministic_object_id
from .extractors import ExtractedBlock


_SENTENCE_BOUNDARY = re.compile(r"(?<=[。！？；.!?;])")


def normalize_retrieval_text(value: str) -> str:
    return " ".join(value.split())


def _ref(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class PassageGovernanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PassageCatalog:
    """Persist segmented drafts and approve them through the P1 write guard."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        approval_executor: GovernedWriteExecutor,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("passage catalog requires sqlite3.Connection")
        self._connection = connection
        self._store = content_store
        self._executor = approval_executor
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()

    def persist_drafts(
        self, records: tuple[PassageRecord, ...] | list[PassageRecord]
    ) -> tuple[PassageRecord, ...]:
        values = tuple(PassageRecord.model_validate(item) for item in records)
        if not values:
            raise PassageGovernanceError("PASSAGE_DRAFT_REQUIRED")
        if any(item.review_status != "draft" for item in values):
            raise PassageGovernanceError("PASSAGE_DRAFT_STATUS_REQUIRED")
        keys = {(item.passage_id, item.version) for item in values}
        if len(keys) != len(values):
            raise PassageGovernanceError("PASSAGE_DRAFT_DUPLICATE")
        for item in values:
            self._verify_authority(item)
        try:
            with transaction(self._connection):
                for item in values:
                    self._verify_authority(item)
                    self._connection.execute(
                        """
                        INSERT INTO passages(
                            passage_id, version, source_id, source_version,
                            document_type, structural_path, locator_json,
                            normalized_text_sha256, raw_content_ref,
                            retrieval_content_ref, context_before_ref,
                            context_after_ref, extractor_version, privacy_scope,
                            provenance_json, review_status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                  'DRAFT', ?)
                        """,
                        (
                            item.passage_id,
                            item.version,
                            item.source_ref.object_id,
                            item.source_ref.version,
                            item.document_type,
                            item.structural_path,
                            item.locator.model_dump_json(),
                            item.normalized_text_sha256,
                            item.raw_content_ref,
                            item.retrieval_content_ref,
                            item.context_before_ref,
                            item.context_after_ref,
                            item.extractor_version,
                            item.privacy_scope.upper(),
                            item.provenance.model_dump_json(),
                            _utc(item.created_at),
                        ),
                    )
                self._connection.execute(
                    "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
                )
        except sqlite3.IntegrityError as exc:
            raise PassageGovernanceError("PASSAGE_DRAFT_CONFLICT") from exc
        return tuple(self.get(item.passage_id, item.version) for item in values)

    def preview_approval(self, passage_id: str, version: int) -> DraftDescriptor:
        current = self.get(passage_id, version)
        if current.review_status not in {"draft", "reviewed"}:
            raise PassageGovernanceError("PASSAGE_NOT_REVIEWABLE")
        return DraftDescriptor(
            purpose="passage_approve",
            target_id=current.passage_id,
            base_version=current.version,
            draft_sha256=canonical_sha256(current.model_dump(mode="json")),
        )

    def approve(
        self,
        passage_id: str,
        version: int,
        *,
        approval_request_id: str,
    ) -> PassageRecord:
        descriptor = self.preview_approval(passage_id, version)

        def apply(connection: sqlite3.Connection) -> None:
            if connection is not self._connection:
                raise PassageGovernanceError("PASSAGE_TARGET_CONNECTION_MISMATCH")
            current = self.get(passage_id, version)
            self._verify_authority(current)
            if canonical_sha256(current.model_dump(mode="json")) != descriptor.draft_sha256:
                raise PassageGovernanceError("PASSAGE_APPROVAL_DESCRIPTOR_STALE")
            changed = connection.execute(
                """
                UPDATE passages SET review_status = 'APPROVED'
                 WHERE passage_id = ? AND version = ?
                   AND review_status IN ('DRAFT', 'REVIEWED')
                """,
                (passage_id, version),
            ).rowcount
            if changed != 1:
                raise PassageGovernanceError("PASSAGE_APPROVAL_CONFLICT")
            source_status = connection.execute(
                """
                SELECT status FROM source_versions
                 WHERE source_id = ? AND version = ?
                """,
                (current.source_ref.object_id, current.source_ref.version),
            ).fetchone()
            if source_status == ("DRAFT",):
                connection.execute(
                    """
                    UPDATE source_versions SET status = 'REVIEWED'
                     WHERE source_id = ? AND version = ? AND status = 'DRAFT'
                    """,
                    (current.source_ref.object_id, current.source_ref.version),
                )
            connection.execute(
                """
                INSERT INTO review_decisions(
                    decision_id, object_type, object_id, object_version,
                    decision, diff_sha256, approver_role,
                    approval_request_id, decided_at
                ) VALUES (?, 'passage', ?, ?, 'APPROVE', ?,
                          'knowledge_reviewer', ?, ?)
                """,
                (
                    self._ids.object_id("review_decision"),
                    passage_id,
                    version,
                    descriptor.draft_sha256,
                    approval_request_id,
                    _utc(self._clock.now()),
                ),
            )
            connection.execute(
                "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
            )

        self._executor.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind="passage_approval_operation",
            apply=apply,
        )
        return self.get(passage_id, version)

    def get(self, passage_id: str, version: int) -> PassageRecord:
        row = self._connection.execute(
            """
            SELECT source_id, source_version, document_type, structural_path,
                   locator_json, normalized_text_sha256, raw_content_ref,
                   retrieval_content_ref, context_before_ref, context_after_ref,
                   extractor_version, privacy_scope, provenance_json,
                   review_status, created_at
              FROM passages WHERE passage_id = ? AND version = ?
            """,
            (passage_id, version),
        ).fetchone()
        if row is None:
            raise PassageGovernanceError("PASSAGE_NOT_FOUND")
        source_row = self._connection.execute(
            """
            SELECT content_sha256 FROM source_versions
             WHERE source_id = ? AND version = ?
            """,
            (row[0], row[1]),
        ).fetchone()
        if source_row is None:
            raise PassageGovernanceError("PASSAGE_SOURCE_NOT_FOUND")
        try:
            value = PassageRecord(
                passage_id=passage_id,
                version=version,
                source_ref=VersionRef(
                    object_id=str(row[0]),
                    version=int(row[1]),
                    content_sha256=str(source_row[0]),
                ),
                document_type=cast(DocumentType, str(row[2])),
                structural_path=str(row[3]),
                locator=EvidenceLocator.model_validate_json(str(row[4])),
                normalized_text_sha256=str(row[5]),
                raw_content_ref=str(row[6]),
                retrieval_content_ref=str(row[7]),
                context_before_ref=None if row[8] is None else str(row[8]),
                context_after_ref=None if row[9] is None else str(row[9]),
                extractor_version=str(row[10]),
                privacy_scope=cast(
                    Literal["global", "private", "case"], str(row[11]).lower()
                ),
                provenance=Provenance.model_validate_json(str(row[12])),
                review_status=cast(ReviewStatus, str(row[13]).lower()),
                created_at=_parse_utc(row[14]),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PassageGovernanceError("PASSAGE_CATALOG_CORRUPT") from exc
        self._verify_authority(value)
        return value

    def _verify_authority(self, value: PassageRecord) -> None:
        source = self._connection.execute(
            """
            SELECT content_sha256, content_object_ref, document_type, status
              FROM source_versions AS v
              JOIN sources AS s ON s.source_id = v.source_id
             WHERE v.source_id = ? AND v.version = ?
            """,
            (value.source_ref.object_id, value.source_ref.version),
        ).fetchone()
        if (
            source is None
            or str(source[0]) != value.source_ref.content_sha256
            or str(source[1]) != value.raw_content_ref
            or str(source[2]) != value.document_type
            or str(source[3]) in {"REJECTED", "REVOKED"}
        ):
            raise PassageGovernanceError("PASSAGE_SOURCE_AUTHORITY_INVALID")
        raw_digest = _content_digest(value.raw_content_ref)
        retrieval_digest = _content_digest(value.retrieval_content_ref)
        if raw_digest != value.source_ref.content_sha256:
            raise PassageGovernanceError("PASSAGE_RAW_CONTENT_REF_INVALID")
        self._store.read_hash_verified(raw_digest)
        retrieval = self._store.read_hash_verified(retrieval_digest)
        if (
            retrieval_digest != value.normalized_text_sha256
            or hashlib.sha256(retrieval).hexdigest() != value.normalized_text_sha256
        ):
            raise PassageGovernanceError("PASSAGE_RETRIEVAL_CONTENT_INVALID")
        for reference in (value.context_before_ref, value.context_after_ref):
            if reference is not None:
                self._store.read_hash_verified(_content_digest(reference))


class PassageSegmenter:
    def __init__(
        self,
        *,
        logical_source_id: str,
        source_ref: VersionRef,
        max_characters: int = 2400,
        content_store: ContentStore | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if type(max_characters) is not int or max_characters < 128:
            raise ValueError("passage maximum must be at least 128 characters")
        if source_ref.object_id != logical_source_id:
            raise ValueError("source reference must identify the logical source")
        self._source_id = logical_source_id
        self._source_ref = source_ref
        self._max_characters = max_characters
        self._content_store = content_store
        self._ids = id_factory or IdFactory()

    def _materialize(self, text: str) -> str:
        if self._content_store is None:
            return _ref(text)
        staged = self._content_store.stage_bytes(
            text.encode("utf-8"),
            purpose="passage_materialize",
            manifest_id=self._ids.object_id("passage_materialization"),
            media_type="text/plain",
        )
        reference = self._content_store.finalize(staged)
        return f"sha256:{reference.content_sha256}"

    def _split_block(self, block: ExtractedBlock) -> tuple[tuple[str, str], ...]:
        normalized = normalize_retrieval_text(block.text)
        if len(normalized) <= self._max_characters:
            return ((block.structural_path, normalized),)
        sentences = [item.strip() for item in _SENTENCE_BOUNDARY.split(normalized) if item.strip()]
        chunks: list[str] = []
        current = ""
        for sentence in sentences:
            if current and len(current) + len(sentence) > self._max_characters:
                chunks.append(current)
                current = sentence
            else:
                current += sentence
        if current:
            chunks.append(current)
        if not chunks:
            chunks = [
                normalized[index : index + self._max_characters]
                for index in range(0, len(normalized), self._max_characters)
            ]
        return tuple(
            (f"{block.structural_path}/chunk-{index}", text)
            for index, text in enumerate(chunks, 1)
        )

    def segment(
        self,
        document_type: DocumentType,
        blocks: tuple[ExtractedBlock, ...] | list[ExtractedBlock],
        *,
        privacy_scope: Literal["global", "private", "case"] = "global",
        provenance: Provenance | None = None,
        review_status: ReviewStatus = "draft",
        created_at: datetime | None = None,
    ) -> tuple[PassageRecord, ...]:
        values = tuple(blocks)
        if not values or any(block.document_type != document_type for block in values):
            raise ValueError("Passage segmentation requires same-type extracted blocks")
        now = created_at or datetime.now(timezone.utc)
        records: list[PassageRecord] = []
        for block_index, block in enumerate(values):
            before = values[block_index - 1].text if block_index else None
            after = values[block_index + 1].text if block_index + 1 < len(values) else None
            for structural_path, text in self._split_block(block):
                passage_id = deterministic_object_id(
                    "passage", self._source_id, document_type, structural_path
                )
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                if provenance is None:
                    if privacy_scope != "global":
                        raise ValueError(
                            "non-global Passage segmentation requires provenance"
                        )
                    passage_provenance = Provenance(
                        source_ids=frozenset({self._source_ref.object_id}),
                        passage_ids=frozenset({passage_id}),
                        provenance_scope="global_source",
                        derivation_rule_ref=block.locator.locator_policy_ref,
                    )
                else:
                    passage_provenance = Provenance.model_validate(provenance).model_copy(
                        update={
                            "passage_ids": provenance.passage_ids
                            | frozenset({passage_id})
                        }
                    )
                records.append(
                    PassageRecord(
                        passage_id=passage_id,
                        version=self._source_ref.version,
                        source_ref=self._source_ref,
                        document_type=document_type,
                        structural_path=structural_path,
                        locator=block.locator,
                        normalized_text_sha256=digest,
                        raw_content_ref=f"sha256:{self._source_ref.content_sha256}",
                        retrieval_content_ref=self._materialize(text),
                        context_before_ref=(
                            None if before is None else self._materialize(before)
                        ),
                        context_after_ref=(
                            None if after is None else self._materialize(after)
                        ),
                        extractor_version=block.extractor_version,
                        privacy_scope=privacy_scope,
                        provenance=passage_provenance,
                        review_status=review_status,
                        created_at=now,
                    )
                )
        return tuple(records)


def _content_digest(value: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise PassageGovernanceError("PASSAGE_CONTENT_REF_INVALID")
    digest = value[len(prefix) :]
    if any(character not in "0123456789abcdef" for character in digest):
        raise PassageGovernanceError("PASSAGE_CONTENT_REF_INVALID")
    return digest


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise PassageGovernanceError("PASSAGE_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PassageGovernanceError("PASSAGE_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PassageGovernanceError("PASSAGE_TIMESTAMP_INVALID")
    return parsed


__all__ = [
    "PassageCatalog",
    "PassageGovernanceError",
    "PassageSegmenter",
    "normalize_retrieval_text",
]
