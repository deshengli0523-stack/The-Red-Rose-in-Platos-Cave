"""Persist one immutable actual transcript with three independent archive purposes."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import cast

from consultation_kb.archive.private_record import ActualTranscriptReader
from consultation_kb.models.archive import (
    ARCHIVE_PURPOSE_ORDER,
    ArchiveBundle,
    ArchivePurpose,
    ArchivePurposeState,
    ArchivePurposeStatus,
    legal_archive_purpose,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.session.repository import PreviousTurnNotClosed, SessionRepository
from consultation_kb.storage.connection import transaction


class ArchiveBundleError(RuntimeError):
    """Fixed-code archive proposal or lifecycle failure."""


_TRANSITIONS: dict[str, frozenset[str]] = {
    "DRAFT": frozenset({"PREPARED", "REJECTED", "NO_CHANGE", "PRIVATE_ONLY"}),
    "PREPARED": frozenset({"ACTIVE", "REJECTED", "PRIVATE_ONLY"}),
    "ACTIVE": frozenset(),
    "REJECTED": frozenset(),
    "NO_CHANGE": frozenset(),
    "PRIVATE_ONLY": frozenset(),
}


def _utc_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ArchiveBundleError("ARCHIVE_BUNDLE_INTEGRITY_ERROR")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArchiveBundleError("ARCHIVE_BUNDLE_INTEGRITY_ERROR") from exc


class ArchiveBundleService:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def propose(self, session_id: str) -> ArchiveBundle:
        existing = self._row_for_session(session_id)
        if existing is not None:
            return self._from_row(existing)
        self._repository.get_session(session_id)
        if not self._repository.list_turns(session_id):
            raise ArchiveBundleError("ARCHIVE_EMPTY_SESSION")
        try:
            self._repository.close_session(session_id)
        except PreviousTurnNotClosed as exc:
            raise ArchiveBundleError("ARCHIVE_OPEN_TURN") from exc

        transcript = ActualTranscriptReader(self._repository).snapshot(session_id)
        bundle_id = self._repository.id_factory.object_id("archive_bundle")
        now = self._repository.clock.now()
        try:
            with transaction(self._repository.connection):
                self._repository.connection.execute(
                    """
                    INSERT INTO archive_bundles(
                        bundle_id, session_id, actual_transcript_object_id,
                        actual_transcript_version, actual_transcript_sha256,
                        actual_transcript_media_type,
                        actual_transcript_size_bytes, incomplete_evidence,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, 'application/json', ?, ?, ?)
                    """,
                    (
                        bundle_id,
                        session_id,
                        transcript.actual_transcript_ref.object_id,
                        transcript.actual_transcript_ref.version,
                        transcript.actual_transcript_ref.content_sha256,
                        len(transcript.canonical_text.encode("utf-8")),
                        int(transcript.incomplete_evidence),
                        _utc_text(now),
                    ),
                )
                for purpose in ARCHIVE_PURPOSE_ORDER:
                    self._repository.connection.execute(
                        """
                        INSERT INTO archive_purpose_states(
                            bundle_id, purpose, state, manifest_id,
                            review_decision_id, updated_at
                        ) VALUES (?, ?, 'DRAFT', NULL, NULL, ?)
                        """,
                        (bundle_id, purpose, _utc_text(now)),
                    )
                self._repository.connection.execute(
                    """
                    UPDATE sessions
                       SET archive_state = ?, updated_at = ?
                     WHERE session_id = ? AND state = 'CLOSED'
                    """,
                    (
                        "INCOMPLETE" if transcript.incomplete_evidence else "DRAFT",
                        _utc_text(now),
                        session_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            existing = self._row_for_session(session_id)
            if existing is None:
                raise ArchiveBundleError("ARCHIVE_BUNDLE_WRITE_CONFLICT") from exc
            return self._from_row(existing)
        return self.get(bundle_id)

    def get(self, bundle_id: str) -> ArchiveBundle:
        row = self._row(bundle_id)
        if row is None:
            raise ArchiveBundleError("ARCHIVE_BUNDLE_NOT_FOUND")
        return self._from_row(row)

    def transition(
        self,
        bundle_id: str,
        *,
        purpose: ArchivePurpose | str,
        state: ArchivePurposeState,
        review_decision_id: str | None = None,
        manifest_id: str | None = None,
    ) -> ArchiveBundle:
        selected_purpose = legal_archive_purpose(purpose)
        target = ArchivePurposeStatus(
            purpose=selected_purpose,
            state=state,
            manifest_id=manifest_id,
            review_decision_id=review_decision_id,
        )
        bundle = self.get(bundle_id)
        current = bundle.state_for(selected_purpose)
        if current == target:
            return bundle
        if target.state not in _TRANSITIONS[current.state]:
            raise ArchiveBundleError("ARCHIVE_PURPOSE_TRANSITION_INVALID")

        if target.review_decision_id is not None:
            decision = self._repository.connection.execute(
                """
                SELECT session_id FROM review_decisions WHERE decision_id = ?
                """,
                (target.review_decision_id,),
            ).fetchone()
            if decision is None:
                raise ArchiveBundleError("ARCHIVE_REVIEW_DECISION_NOT_FOUND")
            if decision[0] != bundle.session_id:
                raise ArchiveBundleError("ARCHIVE_REVIEW_DECISION_SCOPE_MISMATCH")
        if target.manifest_id is not None:
            manifest = self._repository.connection.execute(
                "SELECT state FROM artifact_manifests WHERE manifest_id = ?",
                (target.manifest_id,),
            ).fetchone()
            if manifest is None:
                raise ArchiveBundleError("ARCHIVE_MANIFEST_NOT_FOUND")
            if manifest[0] not in {"VERIFIED", "ACTIVE"}:
                raise ArchiveBundleError("ARCHIVE_MANIFEST_NOT_READY")

        now = self._repository.clock.now()
        try:
            with transaction(self._repository.connection):
                changed = self._repository.connection.execute(
                    """
                    UPDATE archive_purpose_states
                       SET state = ?, manifest_id = ?, review_decision_id = ?,
                           updated_at = ?
                     WHERE bundle_id = ? AND purpose = ? AND state = ?
                    """,
                    (
                        target.state,
                        target.manifest_id,
                        target.review_decision_id,
                        _utc_text(now),
                        bundle_id,
                        selected_purpose,
                        current.state,
                    ),
                ).rowcount
                if changed != 1:
                    raise ArchiveBundleError("ARCHIVE_PURPOSE_STATE_CONFLICT")
        except sqlite3.IntegrityError as exc:
            raise ArchiveBundleError("ARCHIVE_PURPOSE_STATE_CONFLICT") from exc
        return self.get(bundle_id)

    def _row_for_session(self, session_id: str) -> tuple[object, ...] | None:
        row = self._repository.connection.execute(
            """
            SELECT bundle_id, session_id, actual_transcript_object_id,
                   actual_transcript_version, actual_transcript_sha256,
                   incomplete_evidence, created_at
              FROM archive_bundles WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        return cast(tuple[object, ...] | None, row)

    def _row(self, bundle_id: str) -> tuple[object, ...] | None:
        row = self._repository.connection.execute(
            """
            SELECT bundle_id, session_id, actual_transcript_object_id,
                   actual_transcript_version, actual_transcript_sha256,
                   incomplete_evidence, created_at
              FROM archive_bundles WHERE bundle_id = ?
            """,
            (bundle_id,),
        ).fetchone()
        return cast(tuple[object, ...] | None, row)

    def _from_row(self, row: tuple[object, ...]) -> ArchiveBundle:
        if (
            len(row) != 7
            or type(row[0]) is not str
            or type(row[1]) is not str
            or type(row[2]) is not str
            or type(row[3]) is not int
            or type(row[4]) is not str
            or type(row[5]) is not int
        ):
            raise ArchiveBundleError("ARCHIVE_BUNDLE_INTEGRITY_ERROR")
        bundle_id = row[0]
        session_id = row[1]
        transcript_object_id = row[2]
        transcript_version = row[3]
        transcript_sha256 = row[4]
        incomplete_evidence = row[5]
        states = self._repository.connection.execute(
            """
            SELECT purpose, state, manifest_id, review_decision_id
              FROM archive_purpose_states
             WHERE bundle_id = ?
             ORDER BY CASE purpose
                WHEN 'private_archive' THEN 1
                WHEN 'profile_diff' THEN 2
                WHEN 'shared_case' THEN 3
             END
            """,
            (bundle_id,),
        ).fetchall()
        try:
            return ArchiveBundle(
                bundle_id=bundle_id,
                session_id=session_id,
                actual_transcript_ref=VersionRef(
                    object_id=transcript_object_id,
                    version=transcript_version,
                    content_sha256=transcript_sha256,
                ),
                incomplete_evidence=bool(incomplete_evidence),
                purpose_states=tuple(
                    ArchivePurposeStatus(
                        purpose=item[0],
                        state=item[1],
                        manifest_id=item[2],
                        review_decision_id=item[3],
                    )
                    for item in states
                ),
                created_at=_parse_utc(row[6]),
            )
        except (TypeError, ValueError) as exc:
            raise ArchiveBundleError("ARCHIVE_BUNDLE_INTEGRITY_ERROR") from exc


__all__ = ["ArchiveBundleError", "ArchiveBundleService"]
