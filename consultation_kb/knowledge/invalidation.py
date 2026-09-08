"""Metadata-aware artifact invalidation and rebuild queueing."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Literal

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.lint import RebuildRequest
from consultation_kb.storage.connection import transaction


_ALL_OUTPUTS: frozenset[Literal["wiki", "graph", "bm25", "vector"]] = frozenset(
    {"wiki", "graph", "bm25", "vector"}
)


class ArtifactInvalidationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArtifactInvalidator:
    _UPSTREAM_HASH_QUERIES = {
        "source": "SELECT content_sha256 FROM source_versions WHERE source_id = ? AND version = ?",
        "passage": "SELECT normalized_text_sha256 FROM passages WHERE passage_id = ? AND version = ?",
        "claim": "SELECT claim_sha256 FROM claims WHERE claim_id = ? AND version = ?",
        "theory": "SELECT revision_sha256 FROM theory_revisions WHERE theory_id = ? AND revision = ?",
        "wiki": "SELECT body_sha256 FROM wiki_revisions WHERE wiki_id = ? AND revision = ?",
        "artifact": "SELECT metadata_sha256 FROM artifact_versions WHERE artifact_id = ? AND version = ?",
    }

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._connection = connection
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()

    def register_dependency(
        self,
        *,
        upstream_type: str,
        upstream_ref: VersionRef,
        downstream_artifact_ref: VersionRef,
        dependency_kind: Literal["content", "metadata", "authority", "provenance"],
    ) -> None:
        upstream = VersionRef.model_validate(upstream_ref)
        downstream = VersionRef.model_validate(downstream_artifact_ref)
        query = self._UPSTREAM_HASH_QUERIES.get(upstream_type)
        if query is None:
            raise ArtifactInvalidationError("DEPENDENCY_UPSTREAM_TYPE_INVALID")
        upstream_row = self._connection.execute(
            query, (upstream.object_id, upstream.version)
        ).fetchone()
        if upstream_row is None:
            raise ArtifactInvalidationError("DEPENDENCY_UPSTREAM_VERSION_NOT_FOUND")
        if str(upstream_row[0]) != upstream.content_sha256:
            raise ArtifactInvalidationError("DEPENDENCY_UPSTREAM_HASH_MISMATCH")
        downstream_row = self._connection.execute(
            """
            SELECT metadata_sha256 FROM artifact_versions
             WHERE artifact_id = ? AND version = ?
            """,
            (downstream.object_id, downstream.version),
        ).fetchone()
        if downstream_row is None:
            raise ArtifactInvalidationError("DEPENDENCY_ARTIFACT_VERSION_NOT_FOUND")
        if str(downstream_row[0]) != downstream.content_sha256:
            raise ArtifactInvalidationError("DEPENDENCY_ARTIFACT_HASH_MISMATCH")
        try:
            with transaction(self._connection):
                current_upstream = self._connection.execute(
                    query, (upstream.object_id, upstream.version)
                ).fetchone()
                current_downstream = self._connection.execute(
                    """
                    SELECT metadata_sha256 FROM artifact_versions
                     WHERE artifact_id = ? AND version = ?
                    """,
                    (downstream.object_id, downstream.version),
                ).fetchone()
                if current_upstream != (upstream.content_sha256,):
                    raise ArtifactInvalidationError(
                        "DEPENDENCY_UPSTREAM_CHANGED_DURING_WRITE"
                    )
                if current_downstream != (downstream.content_sha256,):
                    raise ArtifactInvalidationError(
                        "DEPENDENCY_ARTIFACT_CHANGED_DURING_WRITE"
                    )
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO artifact_dependencies(
                        upstream_type, upstream_id, upstream_version,
                        downstream_artifact_id, downstream_artifact_version,
                        dependency_kind
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        upstream_type,
                        upstream.object_id,
                        upstream.version,
                        downstream.object_id,
                        downstream.version,
                        dependency_kind,
                    ),
                )
                stored = self._connection.execute(
                    """
                    SELECT dependency_kind FROM artifact_dependencies
                     WHERE upstream_type = ? AND upstream_id = ?
                       AND upstream_version = ?
                       AND downstream_artifact_id = ?
                       AND downstream_artifact_version = ?
                    """,
                    (
                        upstream_type,
                        upstream.object_id,
                        upstream.version,
                        downstream.object_id,
                        downstream.version,
                    ),
                ).fetchone()
                if stored != (dependency_kind,):
                    raise ArtifactInvalidationError("DEPENDENCY_KIND_CONFLICT")
        except sqlite3.IntegrityError as exc:
            raise ArtifactInvalidationError("DEPENDENCY_CONFLICT") from exc

    def mark_stale(
        self,
        *,
        upstream_type: str,
        upstream_id: str,
        catalog_version: int,
        reason: str,
        authority_tightening: bool = False,
        tombstone: bool = False,
    ) -> RebuildRequest:
        if type(catalog_version) is not int or catalog_version < 0:
            raise ArtifactInvalidationError("CATALOG_VERSION_INVALID")
        existing: tuple[object, ...] | None = None
        queue_id = self._ids.object_id("rebuild_request")
        now = self._clock.now()
        try:
            with transaction(self._connection):
                existing_row = self._connection.execute(
                    """
                    SELECT queue_id, required_outputs_json, reason, created_at
                      FROM rebuild_queue
                     WHERE upstream_type = ? AND upstream_id = ?
                       AND catalog_version = ?
                    """,
                    (upstream_type, upstream_id, catalog_version),
                ).fetchone()
                if existing_row is not None:
                    existing = tuple(existing_row)
                    queue_id = str(existing[0])
                if existing is None:
                    affected = self._descendants(upstream_type, upstream_id)
                    for artifact_id, artifact_version in affected:
                        self._connection.execute(
                            """
                            UPDATE artifact_versions SET state = 'STALE'
                             WHERE artifact_id = ? AND version = ? AND state = 'CURRENT'
                            """,
                            (artifact_id, artifact_version),
                        )
                    self._connection.execute(
                        """
                        INSERT INTO rebuild_queue(
                            queue_id, upstream_type, upstream_id, catalog_version,
                            required_outputs_json, reason, state, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)
                        """,
                        (
                            queue_id,
                            upstream_type,
                            upstream_id,
                            catalog_version,
                            json.dumps(sorted(_ALL_OUTPUTS), separators=(",", ":")),
                            reason,
                            _utc(now),
                        ),
                    )
                for requested, event_kind, column in (
                    (authority_tightening, "AUTHORIZATION", "authorization_epoch"),
                    (tombstone, "TOMBSTONE", "tombstone_epoch"),
                ):
                    if not requested:
                        continue
                    inserted = self._connection.execute(
                        """
                        INSERT OR IGNORE INTO security_invalidation_events(
                            upstream_type, upstream_id, catalog_version,
                            event_kind, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            upstream_type,
                            upstream_id,
                            catalog_version,
                            event_kind,
                            _utc(now),
                        ),
                    ).rowcount
                    if inserted == 1:
                        self._connection.execute(
                            f"UPDATE knowledge_catalog_state SET {column} = {column} + 1 WHERE singleton = 1"
                        )
        except sqlite3.IntegrityError as exc:
            raise ArtifactInvalidationError("REBUILD_QUEUE_CONFLICT") from exc
        if existing is not None:
            return RebuildRequest(
                queue_id=str(existing[0]),
                upstream_type=upstream_type,
                upstream_id=upstream_id,
                catalog_version=catalog_version,
                required_outputs=frozenset(json.loads(str(existing[1]))),
                reason=str(existing[2]),
                created_at=datetime.fromisoformat(
                    str(existing[3]).replace("Z", "+00:00")
                ),
            )
        return RebuildRequest(
            queue_id=queue_id,
            upstream_type=upstream_type,
            upstream_id=upstream_id,
            catalog_version=catalog_version,
            required_outputs=_ALL_OUTPUTS,
            reason=reason,
            created_at=now,
        )

    def _descendants(self, upstream_type: str, upstream_id: str) -> set[tuple[str, int]]:
        queue: list[tuple[str, str, int | None]] = [(upstream_type, upstream_id, None)]
        seen_upstreams: set[tuple[str, str, int | None]] = set()
        affected: set[tuple[str, int]] = set()
        while queue:
            current = queue.pop(0)
            if current in seen_upstreams:
                continue
            seen_upstreams.add(current)
            if current[2] is None:
                rows = self._connection.execute(
                    """
                    SELECT downstream_artifact_id, downstream_artifact_version
                      FROM artifact_dependencies
                     WHERE upstream_type = ? AND upstream_id = ?
                    """,
                    current[:2],
                ).fetchall()
            else:
                rows = self._connection.execute(
                    """
                    SELECT downstream_artifact_id, downstream_artifact_version
                      FROM artifact_dependencies
                     WHERE upstream_type = ? AND upstream_id = ?
                       AND upstream_version = ?
                    """,
                    current,
                ).fetchall()
            for row in rows:
                artifact = str(row[0]), int(row[1])
                if artifact not in affected:
                    affected.add(artifact)
                    queue.append(("artifact", artifact[0], artifact[1]))
        return affected


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = ["ArtifactInvalidationError", "ArtifactInvalidator"]
