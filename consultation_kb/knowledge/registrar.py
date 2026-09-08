"""Immutable registration of user-supplied local knowledge sources."""

from __future__ import annotations

import json
import hashlib
import mimetypes
import os
import sqlite3
from contextlib import AbstractContextManager, nullcontext
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import cast

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.knowledge import ReviewStatus, SourceMetadata, SourceRecord
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.connection import transaction
from consultation_kb.vault.content_store import ContentStore


class SourceRegistrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _media_type(path: Path) -> str:
    value, _ = mimetypes.guess_type(path.name)
    return value or "application/octet-stream"


class SourceRegistrar:
    """Register source bytes before any model extraction or claim creation."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        sources_root: Path,
        content_store: ContentStore,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("source registrar requires sqlite3.Connection")
        if type(sources_root) is not Path:
            sources_root = Path(sources_root)
        try:
            absolute = Path(os.path.abspath(sources_root))
        except (OSError, ValueError) as exc:
            raise SourceRegistrationError("SOURCE_ROOT_INVALID") from exc
        if not absolute.is_absolute():
            raise SourceRegistrationError("SOURCE_ROOT_INVALID")
        self._connection = connection
        self._sources_root = absolute
        self._store = content_store
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()

    def _write_context(self) -> AbstractContextManager[sqlite3.Connection]:
        if self._connection.in_transaction:
            return nullcontext(self._connection)
        return transaction(self._connection)

    def _relative(self, source_path: Path) -> Path:
        if type(source_path) is not Path:
            source_path = Path(source_path)
        try:
            absolute = Path(os.path.abspath(source_path))
            relative = absolute.relative_to(self._sources_root)
        except (OSError, ValueError):
            raise SourceRegistrationError("SOURCE_OUTSIDE_ROOT") from None
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise SourceRegistrationError("SOURCE_OUTSIDE_ROOT")
        return relative

    def _read_verified(self, relative: Path) -> bytes:
        try:
            with PathGuard(self._sources_root).open_scoped(relative, mode="rb") as stream:
                return stream.read()
        except (OSError, ScopePathDenied):
            raise SourceRegistrationError("SOURCE_PATH_REJECTED") from None

    def _record_from_row(self, row: tuple[object, ...]) -> SourceRecord:
        try:
            metadata = SourceMetadata.model_validate_json(str(row[6]))
            imported = str(row[8]).replace("Z", "+00:00")
            return SourceRecord(
                source_id=str(row[0]),
                version=int(str(row[1])),
                logical_path=str(row[2]),
                content_sha256=str(row[3]),
                content_object_ref=str(row[4]),
                size_bytes=int(str(row[5])),
                metadata=metadata,
                status=cast(ReviewStatus, str(row[7]).lower()),
                imported_at=datetime.fromisoformat(imported),
            )
        except Exception as exc:
            raise SourceRegistrationError("SOURCE_CATALOG_CORRUPT") from exc

    def get(self, source_id: str, version: int) -> SourceRecord:
        row = self._connection.execute(
            """
            SELECT v.source_id, v.version, s.logical_path, v.content_sha256,
                   v.content_object_ref, v.size_bytes, v.metadata_json,
                   v.status, v.imported_at
              FROM source_versions AS v
              JOIN sources AS s ON s.source_id = v.source_id
             WHERE v.source_id = ? AND v.version = ?
            """,
            (source_id, version),
        ).fetchone()
        if row is None:
            raise SourceRegistrationError("SOURCE_VERSION_NOT_FOUND")
        return self._record_from_row(tuple(row))

    def register_local_file(
        self,
        source_path: Path,
        metadata: SourceMetadata,
    ) -> SourceRecord:
        validated = SourceMetadata.model_validate(metadata)
        relative = self._relative(source_path)
        if validated.source_grade == "C1" and (
            not relative.parts or relative.parts[0].lower() != "consultant-theory"
        ):
            raise SourceRegistrationError("C1_SOURCE_DIRECTORY_REQUIRED")
        if relative.suffix.lower().lstrip(".") != validated.document_type:
            raise SourceRegistrationError("SOURCE_DOCUMENT_TYPE_MISMATCH")
        payload = self._read_verified(relative)
        logical_path = PurePosixPath(*relative.parts).as_posix()
        logical_path_key = logical_path.casefold()
        metadata_json = json.dumps(
            validated.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        metadata_sha256 = hashlib.sha256(metadata_json.encode("ascii")).hexdigest()

        existing_source = self._connection.execute(
            "SELECT source_id, current_version FROM sources WHERE logical_path_key = ?",
            (logical_path_key,),
        ).fetchone()
        if existing_source is not None:
            source_id = str(existing_source[0])
            current_version = int(existing_source[1])
            current = self.get(source_id, current_version)
            digest = hashlib.sha256(payload).hexdigest()
            current_metadata_sha256 = hashlib.sha256(
                json.dumps(
                    current.metadata.model_dump(mode="json"),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            ).hexdigest()
            if (
                current.content_sha256 == digest
                and current_metadata_sha256 == metadata_sha256
            ):
                return current
            version = current_version + 1
        else:
            source_id = self._ids.object_id("source")
            version = 1

        manifest_id = self._ids.object_id("source_import")
        staged = self._store.stage_bytes(
            payload,
            purpose="source_import",
            manifest_id=manifest_id,
            media_type=_media_type(relative),
        )
        reference = self._store.finalize(staged)
        imported_at = self._clock.now()
        content_ref = f"sha256:{reference.content_sha256}"
        try:
            with self._write_context():
                if existing_source is None:
                    self._connection.execute(
                        """
                        INSERT INTO sources(
                            source_id, logical_path, document_type,
                            logical_path_key, current_version, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            source_id,
                            logical_path,
                            validated.document_type,
                            logical_path_key,
                            version,
                            _utc_text(imported_at),
                        ),
                    )
                else:
                    changed = self._connection.execute(
                        """
                        UPDATE sources SET current_version = ?
                         WHERE source_id = ? AND current_version = ?
                        """,
                        (version, source_id, version - 1),
                    ).rowcount
                    if changed != 1:
                        raise SourceRegistrationError("SOURCE_VERSION_CONFLICT")
                self._connection.execute(
                    """
                    INSERT INTO source_versions(
                        source_id, version, content_sha256, content_object_ref,
                        size_bytes, license, domain, language, sensitivity,
                        source_grade, status, imported_at, metadata_json,
                        metadata_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'DRAFT', ?, ?, ?)
                    """,
                    (
                        source_id,
                        version,
                        reference.content_sha256,
                        content_ref,
                        reference.size_bytes,
                        validated.license,
                        validated.domain,
                        validated.language,
                        validated.sensitivity,
                        validated.source_grade,
                        _utc_text(imported_at),
                        metadata_json,
                        metadata_sha256,
                    ),
                )
                state_row = self._connection.execute(
                    "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
                ).fetchone()
                if state_row is None:
                    raise SourceRegistrationError("KNOWLEDGE_CATALOG_STATE_INVALID")
                next_catalog_version = int(state_row[0]) + 1
                self._connection.execute(
                    """
                    UPDATE knowledge_catalog_state
                       SET catalog_version = ?,
                           authorization_epoch = authorization_epoch + ?
                     WHERE singleton = 1
                    """,
                    (next_catalog_version, 0 if existing_source is None else 1),
                )
                if existing_source is not None:
                    self._connection.execute(
                        """
                        UPDATE artifact_versions SET state = 'STALE'
                         WHERE state IN ('CURRENT', 'REBUILD_QUEUED')
                        """
                    )
                    self._connection.execute(
                        """
                        INSERT INTO rebuild_queue(
                            queue_id, upstream_type, upstream_id,
                            catalog_version, required_outputs_json, reason,
                            state, created_at
                        ) VALUES (?, 'source', ?, ?,
                                  '["bm25","graph","vector","wiki"]',
                                  'source_content_or_metadata_changed',
                                  'PENDING', ?)
                        """,
                        (
                            self._ids.object_id("rebuild_request"),
                            source_id,
                            next_catalog_version,
                            _utc_text(imported_at),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise SourceRegistrationError("SOURCE_VERSION_CONFLICT") from exc
        return self.get(source_id, version)


__all__ = ["SourceRegistrar", "SourceRegistrationError"]
