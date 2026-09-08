from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.private_record import (
    PrivateArchiveDraftBuilder,
    _canonical_bytes,
)
from consultation_kb.archive.private_review import (
    PrivateArchiveReviewError,
    PrivateArchiveReviewService,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.models.archive import (
    PrivateArchiveAnalysis,
    PrivateArchiveDraft,
    private_archive_draft_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.storage.manifests import ManifestRepository
from tests.consultation_kb.private_archive_approval_support import (
    commit_private_archive_with_guard,
)

from .test_private_archive import _awaiting_actual, _repository


def _closed_bundle(tmp_path: Path, *, suffix: int):  # type: ignore[no-untyped-def]
    connection, repository, session_id = _repository(tmp_path, suffix=suffix)
    turn_id, selected_id, _, _ = _awaiting_actual(
        repository,
        session_id,
        suffix=suffix,
    )
    actual = ActualReplyService(repository).record_adopted(
        session_id,
        turn_id,
        selected_id,
        sent_at=repository.clock.now(),
        idempotency_key=f"actual-review-{suffix}",
    )
    bundle = ArchiveBundleService(repository).propose(session_id)
    return connection, repository, session_id, actual, bundle


def test_review_preview_separates_actual_from_model_and_counselor_analysis(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, _, _ = _closed_bundle(tmp_path, suffix=6)
    try:
        analysis = PrivateArchiveAnalysis(
            key_events=("来访者描述了关系冲突",),
            actual_interventions=("咨询师进行了目标澄清",),
            client_responses=("来访者确认下一步目标",),
            model_analysis=("模型提出依恋模式假设",),
            counselor_reflection=("咨询师认为需要继续验证该假设",),
        )
        draft = PrivateArchiveDraftBuilder(repository).build(
            session_id,
            analysis=analysis,
        )

        preview = PrivateArchiveReviewService(repository).preview(draft)

        assert preview.section_boundary == (
            "actual_transcript",
            "model_analysis",
            "counselor_reflection",
        )
        assert preview.actual_transcript == draft.actual_transcript
        assert preview.analysis.model_analysis == ("模型提出依恋模式假设",)
        assert preview.analysis.counselor_reflection == (
            "咨询师认为需要继续验证该假设",
        )
        assert preview.descriptor.purpose == "private_archive_publish"
        assert preview.descriptor.client_id == repository.get_session(session_id).client_id
        assert preview.descriptor.draft_sha256 == draft.draft_ref.content_sha256
    finally:
        connection.close()


def test_reject_keeps_actual_transcript_and_hides_analysis(tmp_path: Path) -> None:
    connection, repository, session_id, actual, bundle = _closed_bundle(
        tmp_path,
        suffix=7,
    )
    try:
        draft = PrivateArchiveDraftBuilder(repository).build(
            session_id,
            analysis=PrivateArchiveAnalysis(model_analysis=("未批准的模型分析",)),
        )
        service = PrivateArchiveReviewService(repository)
        decision = service.reject(draft, reviewer_id="primary-counselor")

        assert decision.action == "REJECT"
        assert ArchiveBundleService(repository).get(bundle.bundle_id).state_for(
            "private_archive"
        ).state == "REJECTED"
        assert service.active(session_id) is None
        assert repository.list_actual_replies(session_id) == (actual,)
        assert repository.read_content(actual.content).decode("utf-8") == "最终采用的回复"
        assert connection.execute(
            "SELECT count(*) FROM archive_bundles WHERE bundle_id = ?",
            (bundle.bundle_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_approve_modified_then_commit_publishes_only_exact_approved_draft(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, actual, bundle = _closed_bundle(
        tmp_path,
        suffix=8,
    )
    try:
        original = PrivateArchiveDraftBuilder(repository).build(
            session_id,
            analysis=PrivateArchiveAnalysis(model_analysis=("需要被咨询师修改的分析",)),
        )
        approved_analysis = PrivateArchiveAnalysis(
            emotion_change_refs=(original.turns[0].client_message_ref,),
            goal_change_refs=(original.turns[0].actual_reply_ref,),
            key_events=("关系冲突得到澄清",),
            actual_interventions=("咨询师实际进行了目标澄清",),
            client_responses=("来访者确认了下一步目标",),
            model_analysis=("经修改并批准的模型分析",),
            counselor_reflection=("咨询师保留不同解释并计划复核",),
        )
        service = PrivateArchiveReviewService(repository)
        approved_draft = service.prepare_modified(
            original,
            approved_analysis,
        )
        approved, publication, replayed = commit_private_archive_with_guard(
            repository,
            approved_draft,
        )
        repository.clock = FixedClock(repository.clock.now() + timedelta(hours=1))
        active = service.active(session_id)

        assert approved.action == "APPROVE_MODIFIED"
        assert publication.purpose_state.state == "ACTIVE"
        assert replayed == publication
        assert publication.purpose_state.review_decision_id == approved.decision_id
        assert active is not None
        assert active.draft_ref.content_sha256 == approved.draft.draft_ref.content_sha256
        assert active.analysis.model_analysis == ("经修改并批准的模型分析",)
        assert "需要被咨询师修改的分析" not in active.canonical_text
        assert repository.list_actual_replies(session_id) == (actual,)
        assert active.actual_transcript.canonical_text == original.actual_transcript.canonical_text
        assert ManifestRepository(connection).get(publication.manifest_ref.object_id).state == (
            "ACTIVE"
        )
        assert ArchiveBundleService(repository).get(bundle.bundle_id).state_for(
            "profile_diff"
        ).state == "DRAFT"
        assert ArchiveBundleService(repository).get(bundle.bundle_id).state_for(
            "shared_case"
        ).state == "DRAFT"
    finally:
        connection.close()


def test_direct_private_archive_approval_without_guard_is_rejected(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, _, bundle = _closed_bundle(
        tmp_path,
        suffix=14,
    )
    try:
        draft = PrivateArchiveDraftBuilder(repository).build(session_id)
        service = PrivateArchiveReviewService(repository)

        with pytest.raises(TypeError):
            service.approve_modified(draft)  # type: ignore[call-arg]

        assert connection.execute(
            "SELECT count(*) FROM approval_executions"
        ).fetchone() == (0,)
        assert ArchiveBundleService(repository).get(bundle.bundle_id).state_for(
            "private_archive"
        ).state == "DRAFT"
    finally:
        connection.close()


def test_review_rejects_same_transcript_hash_under_different_object_identity(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, _, _ = _closed_bundle(tmp_path, suffix=11)
    try:
        original = PrivateArchiveDraftBuilder(repository).build(session_id)
        forged_transcript = original.actual_transcript.model_copy(
            update={
                "actual_transcript_ref": original.actual_transcript.actual_transcript_ref.model_copy(
                    update={
                        "object_id": repository.id_factory.object_id(
                            "actual_transcript"
                        )
                    }
                )
            }
        )
        body = _canonical_bytes(
            private_archive_draft_payload(
                actual_transcript=forged_transcript,
                analysis=original.analysis,
                created_at=original.created_at,
            )
        )
        stored = repository.store_json(body, kind="private_archive_draft")
        forged = PrivateArchiveDraft(
            draft_ref=VersionRef(
                object_id=stored.object_id,
                version=1,
                content_sha256=stored.content_sha256,
            ),
            actual_transcript=forged_transcript,
            analysis=original.analysis,
            created_at=original.created_at,
        )

        with pytest.raises(
            PrivateArchiveReviewError,
            match="PRIVATE_ARCHIVE_ACTUAL_SOURCE_MISMATCH",
        ):
            PrivateArchiveReviewService(repository).preview(forged)
    finally:
        connection.close()


def test_review_rejects_valid_draft_contract_without_cas_content(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, _, _ = _closed_bundle(tmp_path, suffix=13)
    try:
        original = PrivateArchiveDraftBuilder(repository).build(session_id)
        analysis = PrivateArchiveAnalysis(model_analysis=("not stored in CAS",))
        body = _canonical_bytes(
            private_archive_draft_payload(
                actual_transcript=original.actual_transcript,
                analysis=analysis,
                created_at=original.created_at,
            )
        )
        unstored = PrivateArchiveDraft(
            draft_ref=VersionRef(
                object_id=repository.id_factory.object_id("private_archive_draft"),
                version=1,
                content_sha256=hashlib.sha256(body).hexdigest(),
            ),
            actual_transcript=original.actual_transcript,
            analysis=analysis,
            created_at=original.created_at,
        )

        with pytest.raises(
            PrivateArchiveReviewError,
            match="PRIVATE_ARCHIVE_DRAFT_CONTENT_MISSING",
        ):
            PrivateArchiveReviewService(repository).preview(unstored)
    finally:
        connection.close()
