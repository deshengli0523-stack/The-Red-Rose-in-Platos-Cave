from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.archive.bundles import ArchiveBundleError, ArchiveBundleService
from consultation_kb.models.archive import ArchivePurposeStatus
from consultation_kb.session.actual_replies import ActualReplyService

from .test_private_archive import _awaiting_actual, _repository


def test_archive_purposes_have_independent_legal_states(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=4)
    turn_id, selected_id, _, _ = _awaiting_actual(repository, session_id, suffix=4)
    try:
        ActualReplyService(repository).record_adopted(
            session_id,
            turn_id,
            selected_id,
            sent_at=repository.clock.now(),
            idempotency_key="actual-4",
        )
        service = ArchiveBundleService(repository)
        bundle = service.propose(session_id)

        assert tuple(item.purpose for item in bundle.purpose_states) == (
            "private_archive",
            "profile_diff",
            "shared_case",
        )
        assert {item.state for item in bundle.purpose_states} == {"DRAFT"}

        decision_id = repository.id_factory.object_id("review_decision")
        connection.execute(
            """
            INSERT INTO review_decisions(
                decision_id, session_id, object_id, decision,
                reviewer_id_hash, decided_at
            ) VALUES (?, ?, ?, 'REJECTED', ?, ?)
            """,
            (
                decision_id,
                session_id,
                bundle.bundle_id,
                "c" * 64,
                repository.clock.now().isoformat().replace("+00:00", "Z"),
            ),
        )
        changed = service.transition(
            bundle.bundle_id,
            purpose="shared_case",
            state="PRIVATE_ONLY",
            review_decision_id=decision_id,
        )

        assert changed.state_for("shared_case").state == "PRIVATE_ONLY"
        assert changed.state_for("private_archive").state == "DRAFT"
        assert changed.state_for("profile_diff").state == "DRAFT"
        assert all(item.purpose != "actual_transcript" for item in changed.purpose_states)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("purpose", "state"),
    (
        ("private_archive", "NO_CHANGE"),
        ("private_archive", "PRIVATE_ONLY"),
        ("profile_diff", "PRIVATE_ONLY"),
        ("shared_case", "NO_CHANGE"),
    ),
)
def test_purpose_models_reject_states_outside_their_subset(
    purpose: str,
    state: str,
) -> None:
    with pytest.raises(ValueError, match="purpose state is not legal"):
        ArchivePurposeStatus(
            purpose=purpose,
            state=state,
            manifest_id=None,
            review_decision_id="review_decision_018f0000-0000-7103-8000-000000000001",
        )


def test_bundle_state_transition_rejects_unrelated_review_reference(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=5)
    turn_id, _, _, _ = _awaiting_actual(repository, session_id, suffix=5)
    try:
        ActualReplyService(repository).record_external_unknown(
            session_id,
            turn_id,
            confirmed_at=repository.clock.now(),
            idempotency_key="unknown-5",
        )
        service = ArchiveBundleService(repository)
        bundle = service.propose(session_id)

        with pytest.raises(ArchiveBundleError, match="ARCHIVE_REVIEW_DECISION_NOT_FOUND"):
            service.transition(
                bundle.bundle_id,
                purpose="profile_diff",
                state="NO_CHANGE",
                review_decision_id=repository.id_factory.object_id("review_decision"),
            )
    finally:
        connection.close()


def test_profile_drafts_and_shared_candidates_are_append_only(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=12)
    turn_id, selected_id, _, _ = _awaiting_actual(repository, session_id, suffix=12)
    try:
        ActualReplyService(repository).record_adopted(
            session_id,
            turn_id,
            selected_id,
            sent_at=repository.clock.now(),
            idempotency_key="actual-12",
        )
        bundle = ArchiveBundleService(repository).propose(session_id)
        now = repository.clock.now().isoformat().replace("+00:00", "Z")
        connection.execute(
            """
            INSERT INTO profile_diff_drafts(
                draft_id, bundle_id, revision, base_profile_version,
                base_profile_sha256, draft_object_id, draft_sha256,
                draft_media_type, draft_size_bytes, created_at
            ) VALUES (?, ?, 1, 0, ?, ?, ?, 'application/json', 2, ?)
            """,
            (
                repository.id_factory.object_id("profile_diff_draft"),
                bundle.bundle_id,
                "a" * 64,
                repository.id_factory.object_id("profile_diff_draft"),
                "b" * 64,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO shared_case_candidates(
                candidate_id, bundle_id, version, candidate_object_id,
                candidate_sha256, candidate_media_type, candidate_size_bytes,
                source_record_sha256, incomplete_evidence, created_at
            ) VALUES (?, ?, 1, ?, ?, 'application/json', 2, ?, 0, ?)
            """,
            (
                repository.id_factory.object_id("shared_case_candidate"),
                bundle.bundle_id,
                repository.id_factory.object_id("shared_case_candidate"),
                "c" * 64,
                "d" * 64,
                now,
            ),
        )

        for table in ("profile_diff_drafts", "shared_case_candidates"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(f"UPDATE {table} SET created_at = created_at")
            with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
                connection.execute(f"DELETE FROM {table}")
    finally:
        connection.close()
