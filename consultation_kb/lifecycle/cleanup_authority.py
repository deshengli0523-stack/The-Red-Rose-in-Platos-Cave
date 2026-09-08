"""Body-free authority verification for lifecycle cleanup workers.

Cleanup workers deliberately receive only an intent identifier.  They must
re-attest the complete deletion approval closure from the already-scoped
SQLite database before resolving a path or touching a content object.
"""

from __future__ import annotations

import hmac
import sqlite3
from dataclasses import dataclass
from typing import Literal, cast

from consultation_kb.models.deletion import (
    DeletionActionType,
    deletion_intent_authority_sha256,
)


CleanupAuthorityScope = Literal["global", "client"]


class CleanupAuthorityError(RuntimeError):
    """Fixed-code failure raised before any destructive operation."""

    def __init__(self, code: str = "CLEANUP_AUTHORITY_INVALID") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class CleanupIntentAuthority:
    """Exact, body-free authority reconstructed from the v6 lifecycle rows."""

    intent_id: str
    request_id: str
    action_id: str
    action_type: DeletionActionType
    object_type: str
    target_id_hash: str
    target_version: int
    target_content_sha256: str
    authority_scope: CleanupAuthorityScope
    state: str
    attempt_count: int
    deletion_plan_sha256: str
    root_object_type: str
    root_target_id_hash: str
    root_lineage_hash: str
    action_descriptor_sha256: str
    tombstone_epoch: int
    committed_deletion_version: int
    target_scope_hash: str

    def __repr__(self) -> str:
        return "<CleanupIntentAuthority redacted>"


class CleanupAuthorityResolver:
    """Verify one durable intent against approval, request and tombstone state."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        authority_scope: CleanupAuthorityScope,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("CLEANUP_AUTHORITY_SQLITE_REQUIRED")
        if authority_scope not in {"global", "client"}:
            raise ValueError("CLEANUP_AUTHORITY_SCOPE_INVALID")
        self._connection = connection
        self._scope = authority_scope

    def resolve(
        self,
        intent_id: str,
        *,
        expected_action_type: DeletionActionType | None = None,
    ) -> CleanupIntentAuthority:
        if type(intent_id) is not str or not intent_id:
            raise CleanupAuthorityError
        rows = self._connection.execute(
            """
            SELECT i.intent_id, i.request_id, i.action_id, i.action_type,
                   i.object_type, i.target_id_hash, i.target_version,
                   i.target_content_sha256, i.authority_scope, i.state,
                   i.attempt_count,
                   p.deletion_plan_sha256, p.root_object_type,
                   p.root_target_id_hash, p.root_lineage_hash,
                   p.action_descriptor_sha256,
                   r.plan_sha256, r.target_scope_hash,
                   r.tombstone_epoch, r.committed_deletion_version,
                   r.operation_id, r.approval_request_id,
                   r.approval_descriptor_sha256,
                   r.approval_target_scope_hash, r.state,
                   e.request_id, e.descriptor_sha256, e.draft_sha256,
                   e.target_scope_hash, e.state, e.applied_commit_version,
                   r.base_deletion_version, e.descriptor_base_version
              FROM deletion_queue_intents AS i
              JOIN deletion_intent_authority_proofs AS p
                ON p.intent_id = i.intent_id
               AND p.request_id = i.request_id
               AND p.action_id = i.action_id
              JOIN deletion_requests AS r ON r.request_id = i.request_id
              JOIN approval_executions AS e ON e.operation_id = r.operation_id
             WHERE i.intent_id = ?
            """,
            (intent_id,),
        ).fetchall()
        if len(rows) != 1:
            raise CleanupAuthorityError
        row = rows[0]
        try:
            action_type = cast(DeletionActionType, str(row[3]))
            authority_scope = cast(CleanupAuthorityScope, str(row[8]))
            authority = CleanupIntentAuthority(
                intent_id=str(row[0]),
                request_id=str(row[1]),
                action_id=str(row[2]),
                action_type=action_type,
                object_type=str(row[4]),
                target_id_hash=str(row[5]),
                target_version=int(row[6]),
                target_content_sha256=str(row[7]),
                authority_scope=authority_scope,
                state=str(row[9]),
                attempt_count=int(row[10]),
                deletion_plan_sha256=str(row[11]),
                root_object_type=str(row[12]),
                root_target_id_hash=str(row[13]),
                root_lineage_hash=str(row[14]),
                action_descriptor_sha256=str(row[15]),
                target_scope_hash=str(row[17]),
                tombstone_epoch=int(row[18]),
                committed_deletion_version=int(row[19]),
            )
        except (TypeError, ValueError):
            raise CleanupAuthorityError from None
        expected_descriptor = deletion_intent_authority_sha256(
            intent_id=authority.intent_id,
            request_id=authority.request_id,
            action_id=authority.action_id,
            action_type=authority.action_type,
            object_type=authority.object_type,
            target_id_hash=authority.target_id_hash,
            target_version=authority.target_version,
            target_content_sha256=authority.target_content_sha256,
            authority_scope=authority.authority_scope,
            deletion_plan_sha256=authority.deletion_plan_sha256,
            root_object_type=authority.root_object_type,
            root_target_id_hash=authority.root_target_id_hash,
            root_lineage_hash=authority.root_lineage_hash,
        )
        exact_values = (
            authority.authority_scope == self._scope,
            expected_action_type is None
            or authority.action_type == expected_action_type,
            authority.action_type
            in {"physical_delete", "rebuild", "backup_expiry"},
            hmac.compare_digest(str(row[16]), authority.deletion_plan_sha256),
            hmac.compare_digest(
                expected_descriptor, authority.action_descriptor_sha256
            ),
            hmac.compare_digest(str(row[17]), str(row[23])),
            str(row[24])
            in {"TOMBSTONED", "PHYSICAL_CLEANUP_COMPLETE"},
            hmac.compare_digest(str(row[21]), str(row[25])),
            hmac.compare_digest(str(row[22]), str(row[26])),
            hmac.compare_digest(authority.deletion_plan_sha256, str(row[27])),
            hmac.compare_digest(str(row[17]), str(row[28])),
            str(row[29]) == "APPLIED",
            int(row[30]) > 0,
            int(row[31]) == int(row[32]),
        )
        if not all(exact_values):
            raise CleanupAuthorityError
        self._require_authority_epoch(authority)
        self._require_root_tombstone(authority)
        if authority.action_type == "physical_delete":
            self._require_target_tombstone(authority)
        return authority

    def _require_authority_epoch(self, authority: CleanupIntentAuthority) -> None:
        row = self._connection.execute(
            """
            SELECT deletion_version, tombstone_epoch
              FROM deletion_authority_state WHERE singleton = 1
            """
        ).fetchone()
        if (
            row is None
            or int(row[0]) < authority.committed_deletion_version
            or int(row[1]) < authority.tombstone_epoch
        ):
            raise CleanupAuthorityError

    def _require_root_tombstone(self, authority: CleanupIntentAuthority) -> None:
        row = self._connection.execute(
            """
            SELECT count(*) FROM tombstones
             WHERE target_type = ? AND target_id_hash = ?
               AND source_lineage_hash = ?
            """,
            (
                authority.root_object_type,
                authority.root_target_id_hash,
                authority.root_lineage_hash,
            ),
        ).fetchone()
        if row is None or int(row[0]) != 1:
            raise CleanupAuthorityError

    def _require_target_tombstone(self, authority: CleanupIntentAuthority) -> None:
        row = self._connection.execute(
            """
            SELECT count(*) FROM tombstones
             WHERE target_type = ? AND target_id_hash = ?
               AND source_lineage_hash = ?
            """,
            (
                authority.object_type,
                authority.target_id_hash,
                authority.root_lineage_hash,
            ),
        ).fetchone()
        if row is None or int(row[0]) != 1:
            raise CleanupAuthorityError


__all__ = [
    "CleanupAuthorityError",
    "CleanupAuthorityResolver",
    "CleanupAuthorityScope",
    "CleanupIntentAuthority",
]
