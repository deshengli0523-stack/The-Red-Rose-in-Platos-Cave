"""Counselor review and client-local publication for private archive analysis."""

from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
from contextlib import nullcontext
from collections.abc import Sequence
from datetime import datetime
from typing import Literal, cast

from pydantic import ValidationError

from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    descriptor_sha256,
)
from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.private_record import _canonical_bytes
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.archive import (
    ArchiveBundle,
    PrivateArchiveAnalysis,
    PrivateArchiveDraft,
    PrivateArchivePublication,
    PrivateArchiveReviewAction,
    PrivateArchiveReviewDecision,
    PrivateArchiveReviewPreview,
    private_archive_draft_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.session import StoredContentRef
from consultation_kb.session.repository import SessionRepository
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import ManifestMember, ManifestRepository
from consultation_kb.vault.content_store import ContentStoreError


class PrivateArchiveReviewError(RuntimeError):
    """Fixed-code private archive review or publication failure."""


def _utc_text(value: object) -> str:
    if not hasattr(value, "isoformat"):
        raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_TIME_INVALID")
    return cast(str, value.isoformat()).replace("+00:00", "Z")


class PrivateArchiveReviewService:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def preview(self, draft: PrivateArchiveDraft) -> PrivateArchiveReviewPreview:
        selected = PrivateArchiveDraft.model_validate(draft)
        self._assert_stored_draft(selected)
        bundle = self._bundle_for_session(selected.actual_transcript.session_id)
        self._assert_actual_source(bundle, selected)
        active = self.active(bundle.session_id)
        before = "" if active is None else active.canonical_text
        diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                selected.canonical_text.splitlines(keepends=True),
                fromfile="active_private_archive",
                tofile="review_draft",
            )
        )
        if not diff:
            diff = "NO_CONTENT_CHANGE\n"
        stored_diff = self._repository._store_content(
            diff.encode("utf-8"),
            kind="private_archive_diff",
            media_type="text/x-diff",
        )
        base_version = self._active_revision(bundle.bundle_id)
        descriptor = DraftDescriptor(
            purpose="private_archive_publish",
            target_id=selected.draft_ref.object_id,
            client_id=self._repository.get_session(bundle.session_id).client_id,
            base_version=base_version,
            draft_sha256=selected.draft_ref.content_sha256,
            session_id=bundle.session_id,
        )
        return PrivateArchiveReviewPreview(
            actual_transcript=selected.actual_transcript,
            analysis=selected.analysis,
            diff_ref=VersionRef(
                object_id=stored_diff.object_id,
                version=1,
                content_sha256=stored_diff.content_sha256,
            ),
            descriptor=descriptor,
        )

    def prepare_modified(
        self,
        draft: PrivateArchiveDraft,
        analysis: PrivateArchiveAnalysis,
    ) -> PrivateArchiveDraft:
        """Persist a counselor-edited draft before requesting formal approval."""

        original = PrivateArchiveDraft.model_validate(draft)
        self._assert_stored_draft(original)
        return self._replace_analysis(original, analysis)

    def approve_modified(
        self,
        draft: PrivateArchiveDraft,
        *,
        approval_ticket: ApprovalExecutionTicket,
        modified_draft: PrivateArchiveDraft | None = None,
    ) -> PrivateArchiveReviewDecision:
        original = PrivateArchiveDraft.model_validate(draft)
        try:
            exact_ticket = ApprovalExecutionTicket.model_validate(approval_ticket)
        except (TypeError, ValueError, ValidationError):
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_APPROVAL_TICKET_INVALID"
            ) from None
        if modified_draft is not None:
            selected = PrivateArchiveDraft.model_validate(modified_draft)
            if (
                selected.actual_transcript.canonical_text
                != original.actual_transcript.canonical_text
            ):
                raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_ACTUAL_CHANGED")
        else:
            selected = original
        return self._record_decision(
            selected,
            action="APPROVE_MODIFIED",
            reviewer_id=exact_ticket.receipt.provider_id,
            approval_ticket=exact_ticket,
        )

    def reject(
        self,
        draft: PrivateArchiveDraft,
        *,
        reviewer_id: str,
    ) -> PrivateArchiveReviewDecision:
        return self._record_decision(
            PrivateArchiveDraft.model_validate(draft),
            action="REJECT",
            reviewer_id=reviewer_id,
        )

    def commit(
        self,
        decision: PrivateArchiveReviewDecision,
        *,
        approval_ticket: ApprovalExecutionTicket,
    ) -> PrivateArchivePublication:
        selected = PrivateArchiveReviewDecision.model_validate(decision)
        if selected.action != "APPROVE_MODIFIED":
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_NOT_APPROVED")
        self._assert_approval_execution(
            approval_ticket,
            selected.descriptor,
            expected_state="CLAIMED",
        )
        if not self._repository.connection.in_transaction:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_TRANSACTION_REQUIRED")
        self._assert_stored_draft(selected.draft)
        bundle = ArchiveBundleService(self._repository).get(selected.bundle_id)
        self._assert_actual_source(bundle, selected.draft)
        session = self._repository.get_session(bundle.session_id)
        if selected.descriptor.client_id != session.client_id:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_APPROVAL_BINDING_MISMATCH")
        row = self._repository.connection.execute(
            """
            SELECT revision.revision_id, revision.revision,
                   revision.draft_object_id, revision.draft_sha256,
                   revision.draft_media_type, revision.draft_size_bytes,
                   revision.state, revision.manifest_id
              FROM private_archive_revisions AS revision
              JOIN review_decisions AS decision
                ON decision.decision_id = revision.review_decision_id
               AND decision.session_id = ?
               AND decision.object_id = revision.draft_object_id
               AND decision.decision = 'EDITED'
             WHERE revision.bundle_id = ? AND revision.review_decision_id = ?
            """,
            (bundle.session_id, selected.bundle_id, selected.decision_id),
        ).fetchone()
        if row is None or row[2] != selected.draft.draft_ref.object_id or row[3] != (
            selected.draft.draft_ref.content_sha256
        ):
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_APPROVAL_BINDING_MISMATCH")
        expected_base_version = (
            int(row[1]) - 1
            if row[6] == "ACTIVE"
            else self._active_revision(bundle.bundle_id)
        )
        if selected.descriptor.base_version != expected_base_version:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_APPROVAL_BINDING_MISMATCH")
        if row[6] == "ACTIVE":
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_APPROVAL_ALREADY_APPLIED")
        if row[6] != "PREPARED":
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVISION_NOT_PREPARED")

        revision = int(row[1])
        operation_id = self._repository.id_factory.object_id("publication_operation")
        manifest_id = self._repository.id_factory.object_id("artifact_manifest")
        now = self._repository.clock.now()
        now_text = _utc_text(now)
        member = ManifestMember(
            ordinal=0,
            object_type="private_archive_draft",
            object_id=selected.draft.draft_ref.object_id,
            object_sha256=selected.draft.draft_ref.content_sha256,
            source_version=revision,
            media_type="application/json",
            size_bytes=len(selected.draft.canonical_text.encode("utf-8")),
            source_lineage_hashes=(bundle.actual_transcript_ref.content_sha256,),
        )
        try:
            with nullcontext(self._repository.connection):
                self._repository.connection.execute(
                    """
                    INSERT INTO publication_operations(
                        operation_id, purpose, authority_base_version,
                        approval_request_id, descriptor_sha256, state,
                        required_manifests_json, required_manifest_count,
                        verified_manifest_count, expected_current_epoch,
                        runtime_epoch, created_at, activated_at
                    ) VALUES (?, 'private_archive_publish', ?, ?, ?, 'PREPARED',
                              ?, 1, 0, NULL, NULL, ?, NULL)
                    """,
                    (
                        operation_id,
                        selected.descriptor.base_version + 1,
                        approval_ticket.request_id,
                        descriptor_sha256(selected.descriptor),
                        json.dumps([manifest_id], separators=(",", ":")),
                        now_text,
                    ),
                )
                manifests = ManifestRepository(self._repository.connection)
                manifests.insert_prepared(
                    manifest_id=manifest_id,
                    operation_id=operation_id,
                    artifact_key="private_archive",
                    artifact_kind="private_archive",
                    source_version=revision,
                    members=(member,),
                    created_at=now_text,
                )
                manifests.mark_verified(
                    manifest_id,
                    expected_source_version=revision,
                    verified_at=now_text,
                )
                closure_sha256 = publication_closure_sha256(
                    purpose="private_archive_publish",
                    authority_base_version=revision,
                    expected_current_epoch=None,
                    artifacts=(manifests.get(manifest_id),),
                )
                self._repository.connection.execute(
                    """
                    INSERT INTO publication_closure_attestations(
                        operation_id, approval_draft_sha256,
                        closure_sha256, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        operation_id,
                        approval_ticket.descriptor.draft_sha256,
                        closure_sha256,
                        now_text,
                    ),
                )
                self._repository.connection.execute(
                    """
                    UPDATE publication_operations
                       SET state = 'ACTIVE', verified_manifest_count = 1,
                           activated_at = ?
                     WHERE operation_id = ? AND state = 'PREPARED'
                    """,
                    (now_text, operation_id),
                )
                self._repository.connection.execute(
                    """
                    UPDATE artifact_manifests
                       SET state = 'ACTIVE'
                     WHERE manifest_id = ? AND state = 'VERIFIED' AND verified = 1
                    """,
                    (manifest_id,),
                )
                changed_revision = self._repository.connection.execute(
                    """
                    UPDATE private_archive_revisions
                       SET state = 'ACTIVE', manifest_id = ?
                     WHERE revision_id = ? AND state = 'PREPARED'
                    """,
                    (manifest_id, row[0]),
                ).rowcount
                changed_purpose = self._repository.connection.execute(
                    """
                    UPDATE archive_purpose_states
                       SET state = 'ACTIVE', manifest_id = ?, updated_at = ?
                     WHERE bundle_id = ? AND purpose = 'private_archive'
                       AND state = 'PREPARED' AND review_decision_id = ?
                    """,
                    (manifest_id, now_text, selected.bundle_id, selected.decision_id),
                ).rowcount
                if changed_revision != 1 or changed_purpose != 1:
                    raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_COMMIT_CONFLICT")
        except sqlite3.IntegrityError as exc:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_COMMIT_CONFLICT") from exc
        committed = self._repository.connection.execute(
            """
            SELECT revision_id, revision, draft_object_id, draft_sha256,
                   draft_media_type, draft_size_bytes, state, manifest_id
              FROM private_archive_revisions WHERE revision_id = ?
            """,
            (row[0],),
        ).fetchone()
        if committed is None:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVISION_INTEGRITY_ERROR")
        return self._publication(
            selected.bundle_id,
            selected.draft,
            committed,
            manifest_id,
        )

    def recover_committed(
        self,
        draft: PrivateArchiveDraft,
        *,
        approval_ticket: ApprovalExecutionTicket,
    ) -> PrivateArchivePublication:
        """Recover an exact publication after its guarded transaction committed."""

        selected = PrivateArchiveDraft.model_validate(draft)
        exact_ticket = ApprovalExecutionTicket.model_validate(approval_ticket)
        self._assert_approval_execution(
            exact_ticket,
            exact_ticket.descriptor,
            expected_state="APPLIED",
        )
        bundle = self._bundle_for_session(selected.actual_transcript.session_id)
        self._assert_actual_source(bundle, selected)
        session = self._repository.get_session(bundle.session_id)
        descriptor = exact_ticket.descriptor
        if (
            descriptor.purpose != "private_archive_publish"
            or descriptor.target_id != selected.draft_ref.object_id
            or descriptor.draft_sha256 != selected.draft_ref.content_sha256
            or descriptor.client_id != session.client_id
            or descriptor.session_id != bundle.session_id
        ):
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_APPROVAL_BINDING_MISMATCH"
            )
        row = self._repository.connection.execute(
            """
            SELECT revision.revision_id, revision.revision,
                   revision.draft_object_id, revision.draft_sha256,
                   revision.draft_media_type, revision.draft_size_bytes,
                   revision.state, revision.manifest_id,
                   operation.operation_id
              FROM private_archive_revisions AS revision
              JOIN publication_operations AS operation
                ON operation.purpose = 'private_archive_publish'
               AND operation.approval_request_id = ?
               AND operation.descriptor_sha256 = ?
               AND operation.state = 'ACTIVE'
              JOIN artifact_manifests AS manifest
                ON manifest.operation_id = operation.operation_id
               AND manifest.manifest_id = revision.manifest_id
               AND manifest.state = 'ACTIVE' AND manifest.verified = 1
             WHERE revision.bundle_id = ?
               AND revision.draft_object_id = ?
               AND revision.draft_sha256 = ?
               AND revision.state = 'ACTIVE'
            """,
            (
                exact_ticket.request_id,
                exact_ticket.descriptor_sha256,
                bundle.bundle_id,
                selected.draft_ref.object_id,
                selected.draft_ref.content_sha256,
            ),
        ).fetchone()
        if (
            row is None
            or type(row[1]) is not int
            or row[1] - 1 != descriptor.base_version
            or type(row[7]) is not str
            or type(row[8]) is not str
        ):
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_COMMIT_RECOVERY_FAILED")
        manifest = ManifestRepository(self._repository.connection).get(row[7])
        closure_sha256 = publication_closure_sha256(
            purpose="private_archive_publish",
            authority_base_version=row[1],
            expected_current_epoch=None,
            artifacts=(manifest,),
        )
        attestation = self._repository.connection.execute(
            "SELECT approval_draft_sha256, closure_sha256 "
            "FROM publication_closure_attestations WHERE operation_id = ?",
            (row[8],),
        ).fetchone()
        if attestation != (descriptor.draft_sha256, closure_sha256):
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_COMMIT_RECOVERY_FAILED")
        return self._publication(bundle.bundle_id, selected, row[:8], row[7])

    def active(self, session_id: str) -> PrivateArchiveDraft | None:
        row = self._repository.connection.execute(
            """
            SELECT revision.draft_object_id, revision.draft_sha256,
                   revision.draft_media_type, revision.draft_size_bytes
              FROM archive_bundles AS bundle
              JOIN archive_purpose_states AS purpose
                ON purpose.bundle_id = bundle.bundle_id
               AND purpose.purpose = 'private_archive'
               AND purpose.state = 'ACTIVE'
              JOIN private_archive_revisions AS revision
                ON revision.bundle_id = bundle.bundle_id
               AND revision.state = 'ACTIVE'
               AND revision.manifest_id = purpose.manifest_id
             WHERE bundle.session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        reference = StoredContentRef(
            object_id=row[0],
            content_sha256=row[1],
            media_type=row[2],
            size_bytes=row[3],
        )
        try:
            payload = json.loads(self._repository.read_content(reference).decode("utf-8"))
            if type(payload) is not dict or set(payload) != {
                "actual",
                "analysis",
                "created_at",
            }:
                raise ValueError
            return PrivateArchiveDraft.model_validate_json(
                json.dumps(
                    {
                    "draft_ref": {
                        "object_id": row[0],
                        "version": 1,
                        "content_sha256": row[1],
                    },
                    "actual_transcript": payload["actual"],
                    "analysis": payload["analysis"],
                    "created_at": payload["created_at"],
                    },
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVISION_INTEGRITY_ERROR") from exc

    def _replace_analysis(
        self,
        draft: PrivateArchiveDraft,
        analysis: PrivateArchiveAnalysis,
    ) -> PrivateArchiveDraft:
        selected_analysis = PrivateArchiveAnalysis.model_validate(analysis)
        created_at = self._repository.clock.now()
        body = _canonical_bytes(
            private_archive_draft_payload(
                actual_transcript=draft.actual_transcript,
                analysis=selected_analysis,
                created_at=created_at,
            )
        )
        stored = self._repository.store_json(body, kind="private_archive_draft")
        return PrivateArchiveDraft(
            draft_ref=VersionRef(
                object_id=stored.object_id,
                version=1,
                content_sha256=stored.content_sha256,
            ),
            actual_transcript=draft.actual_transcript,
            analysis=selected_analysis,
            created_at=created_at,
        )

    def _record_decision(
        self,
        draft: PrivateArchiveDraft,
        *,
        action: PrivateArchiveReviewAction,
        reviewer_id: str,
        approval_ticket: ApprovalExecutionTicket | None = None,
    ) -> PrivateArchiveReviewDecision:
        if type(reviewer_id) is not str or not reviewer_id.strip():
            raise ValueError("reviewer_id must be nonblank")
        preview = self.preview(draft)
        if action == "APPROVE_MODIFIED":
            if approval_ticket is None:
                raise PrivateArchiveReviewError(
                    "PRIVATE_ARCHIVE_APPROVAL_GUARD_REQUIRED"
                )
            self._assert_approval_execution(
                approval_ticket,
                preview.descriptor,
                expected_state="CLAIMED",
            )
            if not self._repository.connection.in_transaction:
                raise PrivateArchiveReviewError(
                    "PRIVATE_ARCHIVE_TRANSACTION_REQUIRED"
                )
        bundle = self._bundle_for_session(draft.actual_transcript.session_id)
        current = bundle.state_for("private_archive")
        if current.state != "DRAFT":
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVIEW_STATE_CONFLICT")
        decision_id = self._repository.id_factory.object_id("review_decision")
        reviewer_hash = hashlib.sha256(reviewer_id.encode("utf-8")).hexdigest()
        now = self._repository.clock.now()
        next_revision = int(
            self._repository.connection.execute(
                """
                SELECT COALESCE(MAX(revision), 0) + 1
                  FROM private_archive_revisions WHERE bundle_id = ?
                """,
                (bundle.bundle_id,),
            ).fetchone()[0]
        )
        revision_id = self._repository.id_factory.object_id("private_archive_revision")
        stored_decision = "EDITED" if action == "APPROVE_MODIFIED" else "REJECTED"
        revision_state = "PREPARED" if action == "APPROVE_MODIFIED" else "REJECTED"
        purpose_state = "PREPARED" if action == "APPROVE_MODIFIED" else "REJECTED"
        try:
            boundary = (
                nullcontext(self._repository.connection)
                if approval_ticket is not None
                else transaction(self._repository.connection)
            )
            with boundary:
                self._repository.connection.execute(
                    """
                    INSERT INTO review_decisions(
                        decision_id, session_id, object_id, decision,
                        reviewer_id_hash, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision_id,
                        bundle.session_id,
                        draft.draft_ref.object_id,
                        stored_decision,
                        reviewer_hash,
                        _utc_text(now),
                    ),
                )
                self._repository.connection.execute(
                    """
                    INSERT INTO private_archive_revisions(
                        revision_id, bundle_id, revision, draft_object_id,
                        draft_sha256, draft_media_type, draft_size_bytes,
                        actual_transcript_object_id, actual_transcript_sha256,
                        review_decision_id, manifest_id, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'application/json', ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        revision_id,
                        bundle.bundle_id,
                        next_revision,
                        draft.draft_ref.object_id,
                        draft.draft_ref.content_sha256,
                        len(draft.canonical_text.encode("utf-8")),
                        bundle.actual_transcript_ref.object_id,
                        bundle.actual_transcript_ref.content_sha256,
                        decision_id,
                        revision_state,
                        _utc_text(now),
                    ),
                )
                changed = self._repository.connection.execute(
                    """
                    UPDATE archive_purpose_states
                       SET state = ?, review_decision_id = ?, updated_at = ?
                     WHERE bundle_id = ? AND purpose = 'private_archive'
                       AND state = 'DRAFT'
                    """,
                    (
                        purpose_state,
                        decision_id,
                        _utc_text(now),
                        bundle.bundle_id,
                    ),
                ).rowcount
                if changed != 1:
                    raise PrivateArchiveReviewError(
                        "PRIVATE_ARCHIVE_REVIEW_STATE_CONFLICT"
                    )
        except sqlite3.IntegrityError as exc:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVIEW_WRITE_CONFLICT") from exc
        return PrivateArchiveReviewDecision(
            decision_id=decision_id,
            bundle_id=bundle.bundle_id,
            draft=draft,
            action=action,
            descriptor=preview.descriptor,
            diff_ref=preview.diff_ref,
            reviewer_id_hash=reviewer_hash,
            reviewed_at=now,
        )

    def _bundle_for_session(self, session_id: str) -> ArchiveBundle:
        row = self._repository.connection.execute(
            "SELECT bundle_id FROM archive_bundles WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_BUNDLE_NOT_FOUND")
        return ArchiveBundleService(self._repository).get(row[0])

    @staticmethod
    def _assert_actual_source(bundle: ArchiveBundle, draft: PrivateArchiveDraft) -> None:
        if (
            bundle.session_id != draft.actual_transcript.session_id
            or bundle.actual_transcript_ref
            != draft.actual_transcript.actual_transcript_ref
            or bundle.incomplete_evidence != draft.incomplete_evidence
        ):
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_ACTUAL_SOURCE_MISMATCH")

    def _assert_stored_draft(self, draft: PrivateArchiveDraft) -> None:
        body = draft.canonical_text.encode("utf-8", errors="strict")
        reference = StoredContentRef(
            object_id=draft.draft_ref.object_id,
            content_sha256=draft.draft_ref.content_sha256,
            media_type="application/json",
            size_bytes=len(body),
        )
        try:
            if self._repository.read_content(reference) != body:
                raise PrivateArchiveReviewError(
                    "PRIVATE_ARCHIVE_DRAFT_CONTENT_MISSING"
                )
        except ContentStoreError as exc:
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_DRAFT_CONTENT_MISSING"
            ) from exc

    def _active_revision(self, bundle_id: str) -> int:
        return int(
            self._repository.connection.execute(
                """
                SELECT COALESCE(MAX(revision), 0)
                  FROM private_archive_revisions
                 WHERE bundle_id = ? AND state = 'ACTIVE'
                """,
                (bundle_id,),
            ).fetchone()[0]
        )

    def _assert_approval_execution(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        expected_state: Literal["CLAIMED", "APPLIED"],
    ) -> ApprovalExecutionTicket:
        try:
            exact = ApprovalExecutionTicket.model_validate(ticket)
        except (TypeError, ValueError, ValidationError):
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_APPROVAL_TICKET_INVALID"
            ) from None
        if exact.descriptor != descriptor:
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_APPROVAL_BINDING_MISMATCH"
            )
        nonce_sha256 = hashlib.sha256(
            exact.receipt.nonce.encode("ascii", errors="strict")
        ).hexdigest()
        row = self._repository.connection.execute(
            """
            SELECT request_id, descriptor_sha256, draft_sha256,
                   descriptor_base_version, target_scope_hash, nonce_sha256,
                   state, applied_commit_version, applied_at
              FROM approval_executions WHERE operation_id = ?
            """,
            (exact.operation_id,),
        ).fetchone()
        expected_tail: tuple[object, object]
        if expected_state == "CLAIMED":
            expected_tail = (None, None)
        else:
            if row is None or type(row[7]) is not int or type(row[8]) is not str:
                raise PrivateArchiveReviewError(
                    "PRIVATE_ARCHIVE_APPROVAL_EXECUTION_INVALID"
                )
            expected_tail = (row[7], row[8])
        if row != (
            exact.request_id,
            exact.descriptor_sha256,
            descriptor.draft_sha256,
            descriptor.base_version,
            exact.target_scope_hash,
            nonce_sha256,
            expected_state,
            *expected_tail,
        ):
            raise PrivateArchiveReviewError(
                "PRIVATE_ARCHIVE_APPROVAL_EXECUTION_INVALID"
            )
        return exact

    def _publication(
        self,
        bundle_id: str,
        draft: PrivateArchiveDraft,
        revision_row: Sequence[object],
        manifest_id: str,
    ) -> PrivateArchivePublication:
        if (
            len(revision_row) != 8
            or type(revision_row[0]) is not str
            or type(revision_row[1]) is not int
            or type(revision_row[3]) is not str
        ):
            raise PrivateArchiveReviewError("PRIVATE_ARCHIVE_REVISION_INTEGRITY_ERROR")
        revision_id = revision_row[0]
        revision = revision_row[1]
        draft_sha256 = revision_row[3]
        manifest = ManifestRepository(self._repository.connection).get(manifest_id)
        purpose = ArchiveBundleService(self._repository).get(bundle_id).state_for(
            "private_archive"
        )
        return PrivateArchivePublication(
            revision_ref=VersionRef(
                object_id=revision_id,
                version=revision,
                content_sha256=draft_sha256,
            ),
            manifest_ref=VersionRef(
                object_id=manifest.manifest_id,
                version=manifest.source_version,
                content_sha256=manifest.manifest_sha256,
            ),
            purpose_state=purpose,
            draft=draft,
            published_at=datetime.fromisoformat(
                manifest.created_at.replace("Z", "+00:00")
            ),
        )


__all__ = ["PrivateArchiveReviewError", "PrivateArchiveReviewService"]
