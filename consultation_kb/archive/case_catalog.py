"""Read-only global case catalog gated by the current ACTIVE manifest."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from pydantic import field_validator, model_validator

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.cases import CaseSectionKind, assert_shared_text_safe
from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
)
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.vault.content_store import ContentStore


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("stored case timestamp must be text")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class CaseCatalogError(RuntimeError):
    def __init__(self, code: str = "CASE_CATALOG_INVALID") -> None:
        self.code = code
        super().__init__(code)


class ActiveCaseRecord(StrictModel):
    case_ref: VersionRef
    manifest_id: ObjectId
    provenance_ref: VersionRef
    authorization_ref: VersionRef
    allowed_uses: frozenset[SafePolicyKey]
    source_grade: NonEmptyStr
    content_media_type: NonEmptyStr
    content_size_bytes: int
    activated_at: UtcDateTime

    @field_validator("content_size_bytes")
    @classmethod
    def _positive_size(cls, value: int) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError("active case content size must be positive")
        return value

    @model_validator(mode="after")
    def _catalog_shape(self) -> "ActiveCaseRecord":
        if not self.allowed_uses or self.content_media_type != "application/json":
            raise ValueError("active case governance metadata is incomplete")
        return self


class GlobalCaseBodySection(StrictModel):
    section_kind: CaseSectionKind
    text: NonEmptyStr
    text_sha256: Sha256Hex

    @model_validator(mode="after")
    def _safe_text(self) -> "GlobalCaseBodySection":
        if text_sha256(self.text) != self.text_sha256:
            raise ValueError("global case section hash mismatch")
        assert_shared_text_safe(self.text)
        return self


class GlobalCaseBody(StrictModel):
    schema_version: str
    sections: tuple[GlobalCaseBodySection, ...]

    @model_validator(mode="after")
    def _body_shape(self) -> "GlobalCaseBody":
        if self.schema_version != "global_case_body.v1" or not self.sections:
            raise ValueError("global case body is incomplete")
        return self


class CaseCatalog:
    """Query only an already-open global connection and its global CAS."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        *,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("CaseCatalog requires a global SQLite connection")
        if not isinstance(content_store, ContentStore):
            raise TypeError("CaseCatalog requires a global ContentStore")
        self._connection = connection
        self._content_store = content_store
        self._clock = clock if clock is not None else SystemClock()

    def active_cases(
        self,
        *,
        purpose: str | None = None,
    ) -> tuple[ActiveCaseRecord, ...]:
        if purpose is not None and (
            type(purpose) is not str or not purpose.strip()
        ):
            raise ValueError("case catalog purpose must be nonblank")
        now_text = _utc_text(self._clock.now())
        rows = self._connection.execute(
            """
            SELECT c.case_id, cv.version, cv.global_content_sha256,
                   cv.manifest_id, cv.allowed_uses_json, cv.source_grade,
                   cv.global_content_media_type, cv.global_content_size_bytes,
                   cv.activated_at, cp.provenance_id, cp.provenance_version,
                   cp.provenance_sha256, ca.authorization_id,
                   ca.authorization_version, ca.authorization_sha256
              FROM cases AS c
              JOIN case_versions AS cv
                ON cv.case_id = c.case_id AND cv.version = c.current_version
              JOIN artifact_manifests AS am
                ON am.manifest_id = cv.manifest_id
              JOIN publication_operations AS operation
                ON operation.operation_id = am.operation_id
              JOIN case_provenance AS cp
                ON cp.provenance_id = cv.provenance_id
               AND cp.provenance_version = cv.provenance_version
              JOIN case_authorizations AS ca
                ON ca.case_id = cv.case_id AND ca.case_version = cv.version
              JOIN case_review_decisions AS review
                ON review.case_id = cv.case_id AND review.case_version = cv.version
              JOIN artifact_members AS member
                ON member.manifest_id = am.manifest_id
               AND member.object_type = 'case'
               AND member.object_id = cv.case_id
               AND member.object_sha256 = cv.global_content_sha256
             WHERE c.state = 'ACTIVE'
               AND cv.state = 'ACTIVE'
               AND am.state = 'VERIFIED'
               AND am.verified = 1
               AND am.artifact_kind = 'shared_case'
               AND am.source_version = CAST(cv.version AS TEXT)
               AND operation.purpose = 'case_publish'
               AND operation.state = 'VERIFIED'
               AND operation.runtime_epoch IS NULL
               AND operation.activated_at IS NULL
               AND operation.authority_base_version = cv.version
               AND review.decision = 'approved'
               AND review.release_decision_sha256 = cv.release_decision_sha256
               AND review.allowed_uses_json = cv.allowed_uses_json
               AND ca.allowed_uses_json = cv.allowed_uses_json
               AND cp.artifact_object_id = cv.case_id
               AND cp.artifact_version = cv.version
               AND cp.artifact_sha256 = cv.global_content_sha256
               AND cp.artifact_kind = 'case'
               AND cp.allowed_uses_json = cv.allowed_uses_json
               AND member.source_version = am.source_version
               AND member.media_type = cv.global_content_media_type
               AND member.size_bytes = cv.global_content_size_bytes
               AND ca.reuse_authorized = 1
               AND ca.valid_from <= ?
               AND (ca.expires_at IS NULL OR ca.expires_at > ?)
               AND (ca.revoked_at IS NULL OR ca.revoked_at > ?)
             ORDER BY c.case_id
            """,
            (now_text, now_text, now_text),
        ).fetchall()
        records = tuple(
            record
            for record in (self._from_row(row) for row in rows)
            if self._ledger_is_verified(record)
            and not self._is_tombstoned(record)
        )
        if purpose is None:
            return records
        return tuple(item for item in records if purpose in item.allowed_uses)

    list_active = active_cases

    def get_active(
        self,
        case_id: str,
        *,
        purpose: str,
    ) -> ActiveCaseRecord | None:
        return next(
            (
                item
                for item in self.active_cases(purpose=purpose)
                if item.case_ref.object_id == case_id
            ),
            None,
        )

    def read_body(self, record: ActiveCaseRecord) -> GlobalCaseBody:
        exact = ActiveCaseRecord.model_validate(record)
        self._require_live(exact)
        reference = self._content_store.reference(
            content_sha256=exact.case_ref.content_sha256,
            media_type=exact.content_media_type,
            size_bytes=exact.content_size_bytes,
        )
        payload = self._content_store.read_verified(reference)
        self._require_live(exact)
        try:
            return GlobalCaseBody.model_validate_json(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise CaseCatalogError("CASE_CATALOG_BODY_INVALID") from None

    def _require_live(self, expected: ActiveCaseRecord) -> None:
        current = self.get_active(
            expected.case_ref.object_id,
            purpose=next(iter(sorted(expected.allowed_uses))),
        )
        if current != expected:
            raise CaseCatalogError("CASE_CATALOG_RECORD_NOT_ACTIVE")

    def _is_tombstoned(self, record: ActiveCaseRecord) -> bool:
        tombstones = TombstoneRepository(self._connection)
        identities = (
            ObjectIdentity("case", record.case_ref.object_id),
            ObjectIdentity(
                "case_version",
                f"{record.case_ref.object_id}:{record.case_ref.version}",
            ),
            ObjectIdentity("manifest", record.manifest_id),
            ObjectIdentity(
                "case_authorization",
                record.authorization_ref.object_id,
            ),
        )
        return any(tombstones.has_lineage(identity) for identity in identities)

    def _ledger_is_verified(self, record: ActiveCaseRecord) -> bool:
        try:
            manifest = ManifestRepository(self._connection).get(record.manifest_id)
        except Exception:
            return False
        if (
            manifest.state != "VERIFIED"
            or not manifest.verified
            or manifest.artifact_kind != "shared_case"
            or manifest.source_version != record.case_ref.version
            or len(manifest.members) != 1
        ):
            return False
        member = manifest.members[0]
        if (
            member.object_type != "case"
            or member.object_id != record.case_ref.object_id
            or member.object_sha256 != record.case_ref.content_sha256
            or member.media_type != record.content_media_type
            or member.size_bytes != record.content_size_bytes
        ):
            return False
        operation = self._connection.execute(
            "SELECT purpose, authority_base_version, state, "
            "required_manifests_json, required_manifest_count, "
            "verified_manifest_count, expected_current_epoch, runtime_epoch, "
            "activated_at FROM publication_operations WHERE operation_id = ?",
            (manifest.operation_id,),
        ).fetchone()
        if operation is None:
            return False
        try:
            required = json.loads(str(operation[3]))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if (
            tuple(operation[:3])
            != ("case_publish", record.case_ref.version, "VERIFIED")
            or required != [manifest.manifest_id]
            or int(str(operation[4])) != 1
            or int(str(operation[5])) != 1
            or operation[7] is not None
            or operation[8] is not None
        ):
            return False
        closure = publication_closure_sha256(
            purpose="case_publish",
            authority_base_version=record.case_ref.version,
            expected_current_epoch=(
                None if operation[6] is None else int(str(operation[6]))
            ),
            artifacts=(manifest,),
        )
        attestation = self._connection.execute(
            "SELECT approval_draft_sha256, closure_sha256 "
            "FROM publication_closure_attestations WHERE operation_id = ?",
            (manifest.operation_id,),
        ).fetchall()
        if (
            len(attestation) != 1
            or type(attestation[0][0]) is not str
            or len(str(attestation[0][0])) != 64
            or str(attestation[0][1]) != closure
        ):
            return False
        active = self._connection.execute(
            "SELECT 1 FROM active_artifacts WHERE manifest_id = ? LIMIT 1",
            (manifest.manifest_id,),
        ).fetchone()
        return active is None

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> ActiveCaseRecord:
        if len(row) != 15:
            raise CaseCatalogError("CASE_CATALOG_ROW_INVALID")
        try:
            allowed = json.loads(str(row[4]))
            if (
                type(allowed) is not list
                or any(type(value) is not str for value in allowed)
                or allowed != sorted(set(allowed))
            ):
                raise ValueError
            return ActiveCaseRecord.model_validate(
                {
                    "case_ref": {
                        "object_id": row[0],
                        "version": row[1],
                        "content_sha256": row[2],
                    },
                    "manifest_id": row[3],
                    "allowed_uses": frozenset(allowed),
                    "source_grade": row[5],
                    "content_media_type": row[6],
                    "content_size_bytes": row[7],
                    "activated_at": _parse_utc(row[8]),
                    "provenance_ref": {
                        "object_id": row[9],
                        "version": row[10],
                        "content_sha256": row[11],
                    },
                    "authorization_ref": {
                        "object_id": row[12],
                        "version": row[13],
                        "content_sha256": row[14],
                    },
                }
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            raise CaseCatalogError("CASE_CATALOG_ROW_INVALID") from None


__all__ = [
    "ActiveCaseRecord",
    "CaseCatalog",
    "CaseCatalogError",
    "GlobalCaseBody",
    "GlobalCaseBodySection",
]
