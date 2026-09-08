"""Scoped resolution and reference accounting for physical cleanup.

The lifecycle queue is intentionally body-free.  This adapter resolves its
hash-only authority against a single already-open v1-v6 SQLite scope.  It never
returns a body; temporary residue needles are retained only in process memory
for the atomic SQLite rebuild scan.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Literal

from consultation_kb.lifecycle.cleanup_authority import CleanupIntentAuthority
from consultation_kb.storage.deletion_inventory import session_authority_sha256
from consultation_kb.storage.tombstones import target_hash


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RESIDUE_NEEDLE_BYTES = 32 * 1024 * 1024


class CleanupInventoryError(RuntimeError):
    """Fixed-code, body-free resolver failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class PhysicalCleanupInventory:
    """In-memory cleanup inventory; repr never exposes scoped residue bytes."""

    content_sha256s: tuple[str, ...]
    forbidden_needles: tuple[bytes, ...]
    fts_tables: tuple[str, ...]
    sqlite_cleanup_required: bool

    def __repr__(self) -> str:
        return "<PhysicalCleanupInventory redacted>"


@dataclass(frozen=True, slots=True)
class CasDeletionGate:
    content_sha256: str
    active_reference_count: int
    pending_backup_count: int
    retention_authorized: bool
    rollback_authorized: bool

    @property
    def allowed(self) -> bool:
        return (
            self.active_reference_count == 0
            and self.pending_backup_count == 0
            and self.retention_authorized
            and self.rollback_authorized
        )


@dataclass(frozen=True, slots=True)
class _ObjectBinding:
    table: str
    object_type: str
    id_column: str
    version_column: str | None
    identity_sha256_column: str | None
    payload_columns: tuple[str, ...]
    parent_session_column: str | None = None


_GLOBAL_BINDINGS: tuple[_ObjectBinding, ...] = (
    _ObjectBinding(
        "source_versions",
        "source",
        "source_id",
        "version",
        "content_sha256",
        ("content_sha256", "content_object_ref"),
    ),
    _ObjectBinding(
        "passages",
        "passage",
        "passage_id",
        "version",
        "normalized_text_sha256",
        (
            "raw_content_ref",
            "retrieval_content_ref",
            "context_before_ref",
            "context_after_ref",
        ),
    ),
    _ObjectBinding(
        "claims",
        "claim",
        "claim_id",
        "version",
        "claim_sha256",
        ("claim_sha256", "claim_object_ref"),
    ),
    _ObjectBinding(
        "theory_revisions",
        "theory",
        "theory_id",
        "revision",
        "revision_sha256",
        ("revision_sha256", "revision_object_ref"),
    ),
    _ObjectBinding(
        "wiki_revisions",
        "wiki",
        "wiki_id",
        "revision",
        "body_sha256",
        (
            "body_sha256",
            "body_object_ref",
            "diff_sha256",
            "diff_object_ref",
        ),
    ),
    _ObjectBinding(
        "case_versions",
        "case",
        "case_id",
        "version",
        "global_content_sha256",
        ("global_content_sha256", "global_content_ref"),
    ),
    _ObjectBinding(
        "case_patterns",
        "case_pattern",
        "pattern_id",
        "version",
        "global_content_sha256",
        ("global_content_sha256", "global_content_ref"),
    ),
    _ObjectBinding(
        "scope_policy_versions",
        "scope_policy",
        "policy_id",
        "version",
        "semantic_sha256",
        ("cas_object_sha256", "cas_object_ref"),
    ),
)


_CLIENT_BINDINGS: tuple[_ObjectBinding, ...] = (
    _ObjectBinding(
        "sessions",
        "session",
        "session_id",
        None,
        None,
        ("client_snapshot_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "turns",
        "turn",
        "turn_id",
        "ordinal",
        "client_message_sha256",
        ("client_message_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "session_fact_events",
        "session_fact_event",
        "session_event_id",
        None,
        "content_sha256",
        ("content_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "candidate_replies",
        "candidate_reply",
        "candidate_id",
        "ordinal",
        "candidate_sha256",
        ("candidate_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "actual_replies",
        "actual_reply",
        "actual_reply_id",
        None,
        "reply_sha256",
        ("reply_sha256", "diff_sha256"),
        "session_id",
    ),
    _ObjectBinding(
        "generation_evidence_objects",
        "generation_evidence",
        "object_id",
        None,
        "content_sha256",
        ("content_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "generation_evidence_packs",
        "generation_evidence_pack",
        "evidence_pack_id",
        None,
        "pack_sha256",
        ("pack_sha256", "context_sha256"),
        "session_id",
    ),
    _ObjectBinding(
        "generation_stage_artifacts",
        "generation_stage_artifact",
        "stage_artifact_id",
        None,
        "artifact_sha256",
        ("artifact_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "generation_stage_revisions",
        "generation_stage_revision",
        "stage_revision_id",
        "revision",
        "artifact_sha256",
        ("artifact_sha256", "revision_reason_sha256"),
        "session_id",
    ),
    _ObjectBinding(
        "risk_observations",
        "risk_observation",
        "observation_id",
        None,
        "observation_sha256",
        ("observation_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "archive_bundles",
        "actual_transcript",
        "actual_transcript_object_id",
        "actual_transcript_version",
        "actual_transcript_sha256",
        ("actual_transcript_sha256",),
        "session_id",
    ),
    _ObjectBinding(
        "private_archive_revisions",
        "private_archive",
        "revision_id",
        "revision",
        "draft_sha256",
        ("draft_sha256", "actual_transcript_sha256"),
    ),
    _ObjectBinding(
        "profile_diff_drafts",
        "profile_diff",
        "draft_id",
        "revision",
        "draft_sha256",
        ("draft_sha256",),
    ),
    _ObjectBinding(
        "shared_case_candidates",
        "shared_case_candidate",
        "candidate_id",
        "version",
        "candidate_sha256",
        ("candidate_sha256",),
    ),
    _ObjectBinding(
        "outbox_events",
        "case_publish_outbox",
        "event_id",
        None,
        "payload_sha256",
        ("payload_sha256",),
    ),
    _ObjectBinding(
        "review_diff_objects",
        "review_diff",
        "object_id",
        "version",
        "content_sha256",
        ("content_sha256",),
    ),
)


class SqlitePhysicalCleanupInventory:
    """Resolve CAS objects and SQLite residue from an exact lifecycle intent."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        authority_scope: Literal["global", "client"],
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("PHYSICAL_INVENTORY_SQLITE_REQUIRED")
        if authority_scope not in {"global", "client"}:
            raise ValueError("PHYSICAL_INVENTORY_SCOPE_INVALID")
        self._connection = connection
        self._scope = authority_scope
        self._bindings = (
            _GLOBAL_BINDINGS if authority_scope == "global" else _CLIENT_BINDINGS
        )

    def resolve(
        self,
        authority: CleanupIntentAuthority,
    ) -> PhysicalCleanupInventory:
        if authority.authority_scope != self._scope:
            raise CleanupInventoryError("PHYSICAL_INVENTORY_SCOPE_MISMATCH")
        digests: set[str] = {authority.target_content_sha256}
        for binding in self._bindings:
            if binding.object_type != authority.object_type:
                continue
            for row in self._binding_rows(binding):
                if not self._row_matches_authority(binding, row, authority):
                    continue
                for value in row[4:]:
                    digest = _digest_from_value(value)
                    if digest is not None:
                        digests.add(digest)
        digests.update(self._artifact_member_digests(authority))
        digests.update(self._case_provenance_digests(authority))

        needles: tuple[bytes, ...] = ()
        sqlite_cleanup_required = False
        if self._scope == "client" and authority.object_type == "session":
            session_id = self._resolve_session_id(authority)
            digests.update(self._session_digests(session_id))
            needles = self._session_inline_needles(session_id)
            sqlite_cleanup_required = bool(needles)
        return PhysicalCleanupInventory(
            content_sha256s=tuple(sorted(digests)),
            forbidden_needles=needles,
            fts_tables=self._fts_tables(),
            sqlite_cleanup_required=sqlite_cleanup_required,
        )

    def cas_gate(
        self,
        authority: CleanupIntentAuthority,
        content_sha256: str,
    ) -> CasDeletionGate:
        if _SHA256_RE.fullmatch(content_sha256) is None:
            raise CleanupInventoryError("PHYSICAL_INVENTORY_HASH_INVALID")
        active = self._active_artifact_member_references(content_sha256)
        active += self._direct_references(content_sha256)
        # A tombstoned source can still be required to reproduce the last
        # active epoch until every deletion-bound rebuild has replaced that
        # closure.  Treat the durable rebuild queue as a rollback reference;
        # physical reclamation must not race ahead merely because a derived
        # artifact embeds a transformed value instead of the source digest.
        pending_rebuilds = int(
            self._connection.execute(
                "SELECT count(*) FROM deletion_queue_intents "
                "WHERE request_id = ? AND action_type = 'rebuild' "
                "AND state != 'SUCCEEDED'",
                (authority.request_id,),
            ).fetchone()[0]
        )
        active += pending_rebuilds
        pending_backup = 0
        if self._table_exists("backup_destruction_objects"):
            pending_backup = int(
                self._connection.execute(
                    """
                    SELECT count(*)
                      FROM backup_destruction_objects AS o
                      JOIN backup_destruction_queue AS q
                        ON q.backup_id = o.backup_id
                     WHERE o.object_sha256 = ? AND q.state != 'succeeded'
                    """,
                    (content_sha256,),
                ).fetchone()[0]
            )
        retention_authorized = self._root_tombstone_exists(authority)
        return CasDeletionGate(
            content_sha256=content_sha256,
            active_reference_count=active,
            pending_backup_count=pending_backup,
            retention_authorized=retention_authorized,
            rollback_authorized=active == 0,
        )

    def delete_authorized_inline_rows(
        self,
        connection: sqlite3.Connection,
        authority: CleanupIntentAuthority,
    ) -> int:
        """Delete only inline session bodies; immutable hashes/audits remain."""

        if self._scope != "client" or authority.object_type != "session":
            return 0
        session_id = self._resolve_session_id(authority, connection=connection)
        deleted = 0
        for table in (
            "turn_risk_evaluation_observations",
            "internal_risk_observations",
            "session_fact_events",
        ):
            if not _table_exists(connection, table):
                continue
            deleted += connection.execute(
                f'DELETE FROM "{table}" WHERE session_id = ?',
                (session_id,),
            ).rowcount
        return deleted

    def _binding_rows(self, binding: _ObjectBinding) -> list[tuple[object, ...]]:
        if not self._table_exists(binding.table):
            return []
        version = (
            "NULL" if binding.version_column is None else f'"{binding.version_column}"'
        )
        identity = (
            "NULL"
            if binding.identity_sha256_column is None
            else f'"{binding.identity_sha256_column}"'
        )
        parent = (
            "NULL"
            if binding.parent_session_column is None
            else f'"{binding.parent_session_column}"'
        )
        payloads = ", ".join(f'"{column}"' for column in binding.payload_columns)
        return self._connection.execute(
            f'SELECT "{binding.id_column}", {version}, {identity}, {parent}, '
            f'{payloads} FROM "{binding.table}"'
        ).fetchall()

    @staticmethod
    def _row_matches_authority(
        binding: _ObjectBinding,
        row: tuple[object, ...],
        authority: CleanupIntentAuthority,
    ) -> bool:
        object_id = str(row[0])
        if target_hash(binding.object_type, object_id) != authority.target_id_hash:
            return False
        if (
            binding.version_column is not None
            and int(str(row[1])) != authority.target_version
        ):
            return False
        identity = row[2]
        if identity is not None and str(identity) != authority.target_content_sha256:
            raise CleanupInventoryError("PHYSICAL_INVENTORY_IDENTITY_MISMATCH")
        return True

    def _artifact_member_digests(
        self,
        authority: CleanupIntentAuthority,
    ) -> set[str]:
        if not self._table_exists("artifact_members"):
            return set()
        manifests: set[str] = set()
        if authority.object_type == "artifact_manifest":
            for manifest_id, manifest_sha256, source_version in self._connection.execute(
                "SELECT manifest_id, manifest_sha256, source_version "
                "FROM artifact_manifests"
            ).fetchall():
                if (
                    target_hash("artifact_manifest", str(manifest_id))
                    == authority.target_id_hash
                    and int(source_version) == authority.target_version
                    and str(manifest_sha256) == authority.target_content_sha256
                ):
                    manifests.add(str(manifest_id))
        if authority.object_type == "artifact_version" and self._table_exists(
            "artifact_versions"
        ):
            for artifact_id, version, metadata_sha256, manifest_id in (
                self._connection.execute(
                    "SELECT artifact_id, version, metadata_sha256, manifest_id "
                    "FROM artifact_versions"
                ).fetchall()
            ):
                if (
                    target_hash("artifact_version", str(artifact_id))
                    == authority.target_id_hash
                    and int(version) == authority.target_version
                    and str(metadata_sha256) == authority.target_content_sha256
                ):
                    manifests.add(str(manifest_id))
        for manifest_id, object_type, object_id, object_sha256, source_version in (
            self._connection.execute(
                "SELECT manifest_id, object_type, object_id, object_sha256, "
                "source_version FROM artifact_members"
            ).fetchall()
        ):
            if (
                str(object_type) == authority.object_type
                and target_hash(authority.object_type, str(object_id))
                == authority.target_id_hash
                and int(source_version) == authority.target_version
                and str(object_sha256) == authority.target_content_sha256
            ):
                manifests.add(str(manifest_id))
        if not manifests:
            return set()
        placeholders = ",".join("?" for _ in manifests)
        return {
            str(row[0])
            for row in self._connection.execute(
                "SELECT object_sha256 FROM artifact_members "
                f"WHERE manifest_id IN ({placeholders})",
                tuple(sorted(manifests)),
            ).fetchall()
            if _SHA256_RE.fullmatch(str(row[0])) is not None
        }

    def _case_provenance_digests(
        self,
        authority: CleanupIntentAuthority,
    ) -> set[str]:
        if self._scope != "global" or not self._table_exists("case_provenance"):
            return set()
        values: set[str] = set()
        for kind, object_id, version, digest in self._connection.execute(
            "SELECT artifact_kind, artifact_object_id, artifact_version, "
            "artifact_sha256 FROM case_provenance"
        ).fetchall():
            if (
                str(kind) == authority.object_type
                and target_hash(authority.object_type, str(object_id))
                == authority.target_id_hash
                and int(version) == authority.target_version
                and str(digest) == authority.target_content_sha256
            ):
                values.add(str(digest))
        return values

    def _resolve_session_id(
        self,
        authority: CleanupIntentAuthority,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        active = self._connection if connection is None else connection
        rows = active.execute(
            """
            SELECT session_id, client_id, client_scope_hash,
                   client_snapshot_version, client_snapshot_canonical_sha256,
                   started_at, last_closed_turn_ordinal
              FROM sessions
            """
        ).fetchall()
        matches: list[str] = []
        for row in rows:
            session_id = str(row[0])
            if target_hash("session", session_id) != authority.target_id_hash:
                continue
            expected = session_authority_sha256(
                session_id=session_id,
                client_id=str(row[1]),
                client_scope_hash=str(row[2]),
                client_snapshot_version=int(row[3]),
                client_snapshot_canonical_sha256=(
                    None if row[4] is None else str(row[4])
                ),
                started_at=str(row[5]),
            )
            if (
                int(row[6]) == authority.target_version
                and expected == authority.target_content_sha256
            ):
                matches.append(session_id)
        if len(matches) != 1:
            raise CleanupInventoryError("PHYSICAL_SESSION_AUTHORITY_INVALID")
        return matches[0]

    def _session_digests(self, session_id: str) -> set[str]:
        digests: set[str] = set()
        for binding in _CLIENT_BINDINGS:
            if binding.parent_session_column is None:
                continue
            for row in self._binding_rows(binding):
                if row[3] != session_id:
                    continue
                for value in row[4:]:
                    digest = _digest_from_value(value)
                    if digest is not None:
                        digests.add(digest)
        if self._table_exists("archive_bundles"):
            bundle_ids = tuple(
                str(row[0])
                for row in self._connection.execute(
                    "SELECT bundle_id FROM archive_bundles WHERE session_id = ?",
                    (session_id,),
                ).fetchall()
            )
            if bundle_ids:
                placeholders = ",".join("?" for _ in bundle_ids)
                for table, columns in (
                    (
                        "private_archive_revisions",
                        ("draft_sha256", "actual_transcript_sha256"),
                    ),
                    ("profile_diff_drafts", ("draft_sha256",)),
                    ("shared_case_candidates", ("candidate_sha256",)),
                    ("outbox_events", ("payload_sha256",)),
                ):
                    if not self._table_exists(table):
                        continue
                    selected = ", ".join(f'"{value}"' for value in columns)
                    for row in self._connection.execute(
                        f'SELECT {selected} FROM "{table}" '
                        f"WHERE bundle_id IN ({placeholders})",
                        bundle_ids,
                    ).fetchall():
                        for value in row:
                            digest = _digest_from_value(value)
                            if digest is not None:
                                digests.add(digest)
        return digests

    def _session_inline_needles(self, session_id: str) -> tuple[bytes, ...]:
        values: set[bytes] = set()
        specs = (
            ("session_fact_events", "event_json"),
            ("internal_risk_observations", "immutable_record_json"),
            ("turn_risk_evaluation_observations", "record_snapshot_json"),
        )
        total = 0
        for table, column in specs:
            if not self._table_exists(table):
                continue
            for (value,) in self._connection.execute(
                f'SELECT "{column}" FROM "{table}" WHERE session_id = ?',
                (session_id,),
            ).fetchall():
                encoded = (
                    bytes(value)
                    if isinstance(value, (bytes, bytearray, memoryview))
                    else str(value).encode("utf-8")
                )
                if not encoded:
                    continue
                total += len(encoded)
                if total > _MAX_RESIDUE_NEEDLE_BYTES:
                    raise CleanupInventoryError("PHYSICAL_RESIDUE_SCAN_TOO_LARGE")
                values.add(encoded)
        return tuple(sorted(values))

    def _direct_references(self, digest: str) -> int:
        count = 0
        for binding in self._bindings:
            for row in self._binding_rows(binding):
                if not any(_digest_from_value(value) == digest for value in row[4:]):
                    continue
                object_id = str(row[0])
                if self._is_tombstoned(binding.object_type, object_id):
                    continue
                parent_session = None if row[3] is None else str(row[3])
                if parent_session is not None and self._is_tombstoned(
                    "session", parent_session
                ):
                    continue
                count += 1
        return count

    def _active_artifact_member_references(self, digest: str) -> int:
        if not all(
            self._table_exists(table)
            for table in ("artifact_members", "active_artifacts", "runtime_epochs")
        ):
            return 0
        row = self._connection.execute(
            """
            SELECT count(*)
              FROM artifact_members AS m
              JOIN active_artifacts AS a ON a.manifest_id = m.manifest_id
              JOIN runtime_epochs AS e ON e.epoch = a.epoch
             WHERE m.object_sha256 = ? AND e.state = 'ACTIVE'
            """,
            (digest,),
        ).fetchone()
        return 0 if row is None else int(row[0])

    def _root_tombstone_exists(self, authority: CleanupIntentAuthority) -> bool:
        row = self._connection.execute(
            """
            SELECT 1 FROM tombstones
             WHERE target_type = ? AND target_id_hash = ?
               AND source_lineage_hash = ? LIMIT 1
            """,
            (
                authority.root_object_type,
                authority.root_target_id_hash,
                authority.root_lineage_hash,
            ),
        ).fetchone()
        return row is not None

    def _is_tombstoned(self, object_type: str, object_id: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM tombstones WHERE target_type = ? "
                "AND target_id_hash = ? LIMIT 1",
                (object_type, target_hash(object_type, object_id)),
            ).fetchone()
            is not None
        )

    def _fts_tables(self) -> tuple[str, ...]:
        rows = self._connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' "
            "AND lower(sql) LIKE '%using fts5%' ORDER BY name"
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def _table_exists(self, table: str) -> bool:
        return _table_exists(self._connection, table)


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is not None
    )


def _digest_from_value(value: object) -> str | None:
    if type(value) is not str:
        return None
    candidate = value[7:] if value.startswith("sha256:") else value
    return candidate if _SHA256_RE.fullmatch(candidate) is not None else None


__all__ = [
    "CasDeletionGate",
    "CleanupInventoryError",
    "PhysicalCleanupInventory",
    "SqlitePhysicalCleanupInventory",
]
