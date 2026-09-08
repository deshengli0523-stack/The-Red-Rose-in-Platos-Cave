"""CAS-backed, approval-governed authority for C1 scope policies."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime

from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.knowledge.approval import GovernedWriteExecutor
from consultation_kb.models.common import ObjectId, VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyRecord,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.vault.content_store import ContentStore, ContentStoreError


_OBJECT_ID = TypeAdapter(ObjectId)
_MEDIA_TYPE = "application/json"


class ScopePolicyError(RuntimeError):
    """Fixed-code, content-free scope-policy authority failure."""

    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ScopePolicyError("SCOPE_POLICY_AUTHORITY_ROW_INVALID")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ScopePolicyError("SCOPE_POLICY_AUTHORITY_ROW_INVALID") from None


class ScopePolicyRepository:
    """Persist and resolve exact approved scope-policy versions.

    Policy bodies never enter SQLite.  Every read reconstructs the CAS
    reference from hash-only metadata, re-hashes the bytes, validates the
    canonical strict document, and checks its semantic ``VersionRef``.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        approval_executor: GovernedWriteExecutor | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("scope policy repository requires sqlite3.Connection")
        if not isinstance(content_store, ContentStore):
            raise TypeError("scope policy repository requires ContentStore")
        self._connection = connection
        self._store = content_store
        self._approval_executor = approval_executor
        self._clock = clock or SystemClock()

    @staticmethod
    def semantic_ref(document: ScopePolicyDocument) -> VersionRef:
        validated = ScopePolicyDocument.model_validate(document)
        payload = canonical_json_bytes(validated.model_dump(mode="json"))
        return VersionRef(
            object_id=validated.policy_id,
            version=validated.version,
            content_sha256=hashlib.sha256(payload).hexdigest(),
        )

    def prepare(
        self,
        document: ScopePolicyDocument,
        *,
        effective_from: datetime,
        effective_to: datetime | None = None,
        supersedes_ref: VersionRef | None = None,
    ) -> ScopePolicyRecord:
        validated = ScopePolicyDocument.model_validate(document)
        semantic_ref = self.semantic_ref(validated)
        predecessor = (
            None
            if supersedes_ref is None
            else VersionRef.model_validate(supersedes_ref)
        )
        if (validated.version == 1) != (predecessor is None):
            raise ScopePolicyError("SCOPE_POLICY_VERSION_CONFLICT")
        if predecessor is not None and (
            predecessor.object_id != validated.policy_id
            or predecessor.version != validated.version - 1
        ):
            raise ScopePolicyError("SCOPE_POLICY_VERSION_CONFLICT")
        now = self._clock.now()
        payload = canonical_json_bytes(validated.model_dump(mode="json"))
        provisional = ScopePolicyRecord(
            semantic_ref=semantic_ref,
            cas_object_ref=f"sha256:{semantic_ref.content_sha256}",
            cas_object_sha256=semantic_ref.content_sha256,
            cas_object_size_bytes=len(payload),
            status="PREPARED",
            effective_from=effective_from,
            effective_to=effective_to,
            supersedes_ref=predecessor,
            created_at=now,
            updated_at=now,
        )
        try:
            content_ref = self._store.finalize(
                self._store.stage_bytes(
                    payload,
                    purpose="scope_policy",
                    manifest_id=validated.policy_id,
                    media_type=_MEDIA_TYPE,
                )
            )
        except (ContentStoreError, OSError):
            raise ScopePolicyError("SCOPE_POLICY_CONTENT_INVALID") from None
        if (
            content_ref.content_sha256 != provisional.cas_object_sha256
            or content_ref.size_bytes != provisional.cas_object_size_bytes
            or content_ref.media_type != provisional.cas_object_media_type
        ):
            raise ScopePolicyError("SCOPE_POLICY_CONTENT_INVALID")

        with transaction(self._connection):
            row = self._connection.execute(
                """
                SELECT semantic_sha256, effective_from, effective_to,
                       supersedes_policy_id, supersedes_version,
                       supersedes_sha256
                  FROM scope_policy_versions
                 WHERE policy_id = ? AND version = ?
                """,
                (validated.policy_id, validated.version),
            ).fetchone()
            if row is not None:
                expected_predecessor = (
                    (None, None, None)
                    if predecessor is None
                    else (
                        predecessor.object_id,
                        predecessor.version,
                        predecessor.content_sha256,
                    )
                )
                if (
                    str(row[0]) != semantic_ref.content_sha256
                    or str(row[1]) != _utc(effective_from)
                    or (None if row[2] is None else str(row[2])) != _utc(effective_to)
                    or tuple(row[3:6]) != expected_predecessor
                ):
                    raise ScopePolicyError("SCOPE_POLICY_VERSION_CONFLICT")
            else:
                maximum = self._connection.execute(
                    """
                    SELECT version, semantic_sha256, status
                      FROM scope_policy_versions
                     WHERE policy_id = ? ORDER BY version DESC LIMIT 1
                    """,
                    (validated.policy_id,),
                ).fetchone()
                if validated.version == 1:
                    if maximum is not None or predecessor is not None:
                        raise ScopePolicyError("SCOPE_POLICY_VERSION_CONFLICT")
                else:
                    if (
                        maximum is None
                        or int(maximum[0]) != validated.version - 1
                        or predecessor is None
                        or predecessor.object_id != validated.policy_id
                        or predecessor.version != int(maximum[0])
                        or predecessor.content_sha256 != str(maximum[1])
                        or str(maximum[2]) not in {"APPROVED", "REVOKED"}
                    ):
                        raise ScopePolicyError("SCOPE_POLICY_VERSION_CONFLICT")
                    self._load_pair(predecessor)
                self._connection.execute(
                    """
                    INSERT INTO scope_policy_versions(
                        policy_id, version, semantic_sha256, cas_object_ref,
                        cas_object_sha256, cas_object_size_bytes,
                        cas_object_media_type, status, approval_request_id,
                        approved_at, revocation_approval_request_id, revoked_at,
                        effective_from, effective_to, supersedes_policy_id,
                        supersedes_version, supersedes_sha256, created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', NULL, NULL,
                              NULL, NULL, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        validated.policy_id,
                        validated.version,
                        semantic_ref.content_sha256,
                        f"sha256:{content_ref.content_sha256}",
                        content_ref.content_sha256,
                        content_ref.size_bytes,
                        content_ref.media_type,
                        _utc(effective_from),
                        _utc(effective_to),
                        None if predecessor is None else predecessor.object_id,
                        None if predecessor is None else predecessor.version,
                        None if predecessor is None else predecessor.content_sha256,
                        _utc(now),
                        _utc(now),
                    ),
                )
        return self.get_record(semantic_ref)

    def preview_approval(self, reference: VersionRef) -> DraftDescriptor:
        record = self.get_record(reference)
        if record.status != "PREPARED":
            raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
        return DraftDescriptor(
            purpose="theory_approve",
            target_id=record.semantic_ref.object_id,
            base_version=record.semantic_ref.version - 1,
            draft_sha256=canonical_sha256(
                {
                    "action": "approve_scope_policy",
                    "record": record.model_dump(mode="json"),
                }
            ),
        )

    def approve(
        self,
        reference: VersionRef,
        *,
        approval_request_id: str,
    ) -> ScopePolicyRecord:
        exact = VersionRef.model_validate(reference)
        request_id = self._approval_id(approval_request_id)
        descriptor = self.preview_approval(exact)
        executor = self._require_executor()
        approved_at = self._clock.now()

        def apply(connection: sqlite3.Connection) -> None:
            if connection is not self._connection:
                raise ScopePolicyError("SCOPE_POLICY_TRANSACTION_SCOPE_MISMATCH")
            current, _document = self._load_pair(exact)
            if current.status != "PREPARED":
                raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
            if self.preview_approval(exact) != descriptor:
                raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT")
            if current.supersedes_ref is not None:
                predecessor, _ = self._load_pair(current.supersedes_ref)
                if predecessor.status == "APPROVED":
                    changed = connection.execute(
                        """
                        UPDATE scope_policy_versions
                           SET status = 'SUPERSEDED', updated_at = ?
                         WHERE policy_id = ? AND version = ?
                           AND semantic_sha256 = ? AND status = 'APPROVED'
                        """,
                        (
                            _utc(approved_at),
                            predecessor.semantic_ref.object_id,
                            predecessor.semantic_ref.version,
                            predecessor.semantic_ref.content_sha256,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
                elif predecessor.status != "REVOKED":
                    raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
            try:
                connection.execute(
                    """
                    INSERT INTO scope_policy_approval_bindings(
                        approval_request_id, policy_id, version, action, bound_at
                    ) VALUES (?, ?, ?, 'APPROVE', ?)
                    """,
                    (
                        request_id,
                        exact.object_id,
                        exact.version,
                        _utc(approved_at),
                    ),
                )
                changed = connection.execute(
                    """
                    UPDATE scope_policy_versions
                       SET status = 'APPROVED', approval_request_id = ?,
                           approved_at = ?, updated_at = ?
                     WHERE policy_id = ? AND version = ?
                       AND semantic_sha256 = ? AND status = 'PREPARED'
                       AND approval_request_id IS NULL AND approved_at IS NULL
                    """,
                    (
                        request_id,
                        _utc(approved_at),
                        _utc(approved_at),
                        exact.object_id,
                        exact.version,
                        exact.content_sha256,
                    ),
                ).rowcount
            except sqlite3.IntegrityError:
                raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT") from None
            if changed != 1:
                raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")

        executor.execute(
            approval_request_id=request_id,
            descriptor=descriptor,
            operation_kind="scope_policy_approval_operation",
            apply=apply,
        )
        result = self.get_record(exact)
        if result.status != "APPROVED" or result.approval_request_id != request_id:
            raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT")
        return result

    def preview_revoke(self, reference: VersionRef) -> DraftDescriptor:
        record = self.get_record(reference)
        if record.status != "APPROVED":
            raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
        return DraftDescriptor(
            purpose="theory_revoke",
            target_id=record.semantic_ref.object_id,
            base_version=record.semantic_ref.version,
            draft_sha256=canonical_sha256(
                {
                    "action": "revoke_scope_policy",
                    "record": record.model_dump(mode="json"),
                }
            ),
        )

    def revoke(
        self,
        reference: VersionRef,
        *,
        approval_request_id: str,
    ) -> ScopePolicyRecord:
        exact = VersionRef.model_validate(reference)
        request_id = self._approval_id(approval_request_id)
        descriptor = self.preview_revoke(exact)
        executor = self._require_executor()
        revoked_at = self._clock.now()

        def apply(connection: sqlite3.Connection) -> None:
            if connection is not self._connection:
                raise ScopePolicyError("SCOPE_POLICY_TRANSACTION_SCOPE_MISMATCH")
            current, _document = self._load_pair(exact)
            if current.status != "APPROVED":
                raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")
            if self.preview_revoke(exact) != descriptor:
                raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT")
            try:
                connection.execute(
                    """
                    INSERT INTO scope_policy_approval_bindings(
                        approval_request_id, policy_id, version, action, bound_at
                    ) VALUES (?, ?, ?, 'REVOKE', ?)
                    """,
                    (
                        request_id,
                        exact.object_id,
                        exact.version,
                        _utc(revoked_at),
                    ),
                )
                changed = connection.execute(
                    """
                    UPDATE scope_policy_versions
                       SET status = 'REVOKED',
                           revocation_approval_request_id = ?, revoked_at = ?,
                           updated_at = ?
                     WHERE policy_id = ? AND version = ?
                       AND semantic_sha256 = ? AND status = 'APPROVED'
                       AND revocation_approval_request_id IS NULL
                       AND revoked_at IS NULL
                    """,
                    (
                        request_id,
                        _utc(revoked_at),
                        _utc(revoked_at),
                        exact.object_id,
                        exact.version,
                        exact.content_sha256,
                    ),
                ).rowcount
            except sqlite3.IntegrityError:
                raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT") from None
            if changed != 1:
                raise ScopePolicyError("SCOPE_POLICY_STATE_TRANSITION_INVALID")

        executor.execute(
            approval_request_id=request_id,
            descriptor=descriptor,
            operation_kind="scope_policy_revocation_operation",
            apply=apply,
        )
        result = self.get_record(exact)
        if (
            result.status != "REVOKED"
            or result.revocation_approval_request_id != request_id
        ):
            raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT")
        return result

    def get_record(self, reference: VersionRef) -> ScopePolicyRecord:
        record, _document = self._read_pair(VersionRef.model_validate(reference))
        return record

    def load_document(self, reference: VersionRef) -> ScopePolicyDocument:
        _record, document = self._read_pair(VersionRef.model_validate(reference))
        return document

    def resolve_approved(
        self,
        reference: VersionRef,
        *,
        at: datetime | None = None,
    ) -> ScopePolicyDocument:
        record, document = self._read_pair(VersionRef.model_validate(reference))
        effective = self._clock.now() if at is None else at
        if record.status != "APPROVED":
            raise ScopePolicyError("SCOPE_POLICY_NOT_APPROVED")
        if effective < record.effective_from or (
            record.effective_to is not None and effective >= record.effective_to
        ):
            raise ScopePolicyError("SCOPE_POLICY_NOT_EFFECTIVE")
        return document

    def resolve_current(
        self,
        policy_id: str,
        *,
        at: datetime | None = None,
    ) -> tuple[ScopePolicyRecord, ScopePolicyDocument]:
        with transaction(self._connection, immediate=False):
            rows = self._connection.execute(
                """
                SELECT version, semantic_sha256
                  FROM scope_policy_versions
                 WHERE policy_id = ? AND status = 'APPROVED'
                """,
                (policy_id,),
            ).fetchall()
            if len(rows) != 1:
                raise ScopePolicyError("SCOPE_POLICY_NOT_APPROVED")
            reference = VersionRef(
                object_id=policy_id,
                version=int(rows[0][0]),
                content_sha256=str(rows[0][1]),
            )
            record, document = self._load_pair(reference)
            effective = self._clock.now() if at is None else at
            if effective < record.effective_from or (
                record.effective_to is not None and effective >= record.effective_to
            ):
                raise ScopePolicyError("SCOPE_POLICY_NOT_EFFECTIVE")
            return record, document

    def _read_pair(
        self,
        reference: VersionRef,
    ) -> tuple[ScopePolicyRecord, ScopePolicyDocument]:
        if self._connection.in_transaction:
            return self._load_pair(reference)
        with transaction(self._connection, immediate=False):
            return self._load_pair(reference)

    def _load_pair(
        self,
        reference: VersionRef,
    ) -> tuple[ScopePolicyRecord, ScopePolicyDocument]:
        row = self._connection.execute(
            """
            SELECT semantic_sha256, cas_object_ref, cas_object_sha256,
                   cas_object_size_bytes, cas_object_media_type, status,
                   approval_request_id, approved_at,
                   revocation_approval_request_id, revoked_at,
                   effective_from, effective_to, supersedes_policy_id,
                   supersedes_version, supersedes_sha256, created_at, updated_at
              FROM scope_policy_versions
             WHERE policy_id = ? AND version = ?
            """,
            (reference.object_id, reference.version),
        ).fetchone()
        if row is None:
            raise ScopePolicyError("SCOPE_POLICY_NOT_FOUND")
        if str(row[0]) != reference.content_sha256:
            raise ScopePolicyError("SCOPE_POLICY_HASH_MISMATCH")
        predecessor_values = tuple(row[12:15])
        if predecessor_values == (None, None, None):
            predecessor = None
        elif all(item is not None for item in predecessor_values):
            try:
                predecessor = VersionRef(
                    object_id=str(row[12]),
                    version=int(row[13]),
                    content_sha256=str(row[14]),
                )
            except (TypeError, ValueError, ValidationError):
                raise ScopePolicyError("SCOPE_POLICY_AUTHORITY_ROW_INVALID") from None
        else:
            raise ScopePolicyError("SCOPE_POLICY_AUTHORITY_ROW_INVALID")
        try:
            record = ScopePolicyRecord.model_validate(
                {
                    "semantic_ref": reference,
                    "cas_object_ref": str(row[1]),
                    "cas_object_sha256": str(row[2]),
                    "cas_object_size_bytes": int(row[3]),
                    "cas_object_media_type": str(row[4]),
                    "status": str(row[5]),
                    "approval_request_id": (None if row[6] is None else str(row[6])),
                    "approved_at": (None if row[7] is None else _parse_utc(row[7])),
                    "revocation_approval_request_id": (
                        None if row[8] is None else str(row[8])
                    ),
                    "revoked_at": (None if row[9] is None else _parse_utc(row[9])),
                    "effective_from": _parse_utc(row[10]),
                    "effective_to": (None if row[11] is None else _parse_utc(row[11])),
                    "supersedes_ref": predecessor,
                    "created_at": _parse_utc(row[15]),
                    "updated_at": _parse_utc(row[16]),
                }
            )
        except ScopePolicyError:
            raise
        except (TypeError, ValueError, ValidationError):
            raise ScopePolicyError("SCOPE_POLICY_AUTHORITY_ROW_INVALID") from None
        self._validate_approval_bindings(record)
        try:
            cas_reference = self._store.reference(
                content_sha256=record.cas_object_sha256,
                size_bytes=record.cas_object_size_bytes,
                media_type=record.cas_object_media_type,
            )
            payload = self._store.read_verified(cas_reference)
            document = ScopePolicyDocument.model_validate_json(payload)
        except (ContentStoreError, OSError, ValidationError, ValueError, TypeError):
            raise ScopePolicyError("SCOPE_POLICY_CONTENT_INVALID") from None
        canonical = canonical_json_bytes(document.model_dump(mode="json"))
        if canonical != payload:
            raise ScopePolicyError("SCOPE_POLICY_CONTENT_INVALID")
        exact_ref = self.semantic_ref(document)
        if exact_ref != reference:
            raise ScopePolicyError("SCOPE_POLICY_HASH_MISMATCH")
        return record, document

    def _validate_approval_bindings(self, record: ScopePolicyRecord) -> None:
        rows = self._connection.execute(
            """
            SELECT approval_request_id, action, bound_at
              FROM scope_policy_approval_bindings
             WHERE policy_id = ? AND version = ? ORDER BY action
            """,
            (record.semantic_ref.object_id, record.semantic_ref.version),
        ).fetchall()
        expected: list[tuple[str, str, str]] = []
        if record.approval_request_id is not None and record.approved_at is not None:
            expected.append(
                (
                    record.approval_request_id,
                    "APPROVE",
                    _utc(record.approved_at) or "",
                )
            )
        if (
            record.revocation_approval_request_id is not None
            and record.revoked_at is not None
        ):
            expected.append(
                (
                    record.revocation_approval_request_id,
                    "REVOKE",
                    _utc(record.revoked_at) or "",
                )
            )
        actual = [(str(row[0]), str(row[1]), str(row[2])) for row in rows]
        if actual != sorted(expected, key=lambda item: item[1]):
            raise ScopePolicyError("SCOPE_POLICY_APPROVAL_CONFLICT")

    def _require_executor(self) -> GovernedWriteExecutor:
        if self._approval_executor is None:
            raise ScopePolicyError("SCOPE_POLICY_APPROVAL_REQUIRED")
        return self._approval_executor

    @staticmethod
    def _approval_id(value: str) -> str:
        try:
            return _OBJECT_ID.validate_python(value)
        except ValidationError:
            raise ScopePolicyError("SCOPE_POLICY_APPROVAL_INVALID") from None


__all__ = ["ScopePolicyError", "ScopePolicyRepository"]
