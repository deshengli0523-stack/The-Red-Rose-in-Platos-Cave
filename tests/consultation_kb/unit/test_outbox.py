from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.approvals.models import descriptor_sha256
from consultation_kb.archive.publication_proof import (
    CasePublicationProof,
    CasePublicationProofPayload,
    LocalHmacCasePublicationProofSigner,
    LocalHmacCasePublicationProofVerifier,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.session import StoredContentRef
from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.recovery import RecoveryCoordinator
from consultation_kb.lifecycle.sqlite_recovery import SqliteRecoveryBackend
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxConflict,
    OutboxError,
    OutboxRepository,
    SourceCaseApproval,
    case_publish_payload_bytes,
    case_publish_payload_sha256,
)
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000801"


def _oid(kind: str, suffix: int) -> str:
    return f"{kind}_018f0000-0000-7000-8000-{suffix:012x}"


def _ref(kind: str, suffix: int, digest: str) -> VersionRef:
    return VersionRef(
        object_id=_oid(kind, suffix),
        version=1,
        content_sha256=digest,
    )


def _source_database(path: Path) -> sqlite3.Connection:
    connection = connect_database(path, "writer")
    MigrationRunner.for_scope(connection, "client").apply()
    return connection


def _publication_proof(
    event_id: str,
    payload: CasePublishOutboxPayload,
) -> CasePublicationProof:
    return LocalHmacCasePublicationProofSigner(
        secret=b"c" * 32,
        attestor_id="case-publication-test",
    ).sign(
        CasePublicationProofPayload(
            source_event_id=event_id,
            approval_operation_id=payload.approval_operation_id,
            approval_request_id=payload.approval_request_id,
            approval_descriptor_sha256=payload.approval_descriptor_sha256,
            approval_draft_sha256=payload.approval_draft_sha256,
            approval_descriptor_base_version=payload.candidate_ref.version,
            approval_applied_commit_version=1,
            approval_target_scope_hash=payload.approval_target_scope_hash,
            global_publication_operation_id=_oid("global_case_publish", 41),
            publication_closure_sha256="a" * 64,
            case_ref=_ref("case", 42, "b" * 64),
            manifest_id=_oid("artifact_manifest", 43),
            provenance_ref=_ref("case_provenance", 44, "c" * 64),
            published_global_version=1,
            authority_epoch=1,
        )
    )


def test_global_loo_schema_binds_regeneration_and_approval_proofs(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(case_leave_one_out_variants)"
            ).fetchall()
        }
        assert {
            "approval_descriptor_sha256",
            "regeneration_request_sha256",
            "regeneration_proof_id",
            "regeneration_proof_version",
            "regeneration_proof_sha256",
        }.issubset(columns)
        proof_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(case_regeneration_proofs)"
            ).fetchall()
        }
        assert {
            "proof_sha256",
            "request_sha256",
            "parent_ref_json",
            "input_case_refs_json",
            "input_independent_source_refs_json",
        }.issubset(proof_columns)
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).fetchall()
        }
        assert {
            "case_patterns_update_guard",
            "case_patterns_no_delete",
            "case_leave_one_out_variants_update_guard",
            "case_leave_one_out_variants_no_delete",
            "case_regeneration_proofs_no_update",
            "case_regeneration_proofs_no_delete",
        }.issubset(triggers)
    finally:
        connection.close()


def _fixture(
    connection: sqlite3.Connection,
    *,
    seed_authority: bool = True,
) -> tuple[
    str,
    CasePublishOutboxPayload,
    StoredContentRef,
    SourceCaseApproval,
]:
    bundle_id = _oid("archive_bundle", 2)
    candidate_ref = _ref("shared_case_candidate", 3, "b" * 64)
    decision_id = _oid("case_source_review", 4)
    operation_id = _oid("case_publish_operation", 40)
    draft_sha256 = "8" * 64
    scope_hash = "3" * 64
    descriptor = DraftDescriptor(
        purpose="case_publish",
        target_id=candidate_ref.object_id,
        client_id="client_" + "aaaaaaaaaaaa",
        base_version=candidate_ref.version,
        draft_sha256=draft_sha256,
        session_id=SESSION_ID,
    )
    descriptor_hash = descriptor_sha256(descriptor)
    payload = CasePublishOutboxPayload(
        candidate_ref=candidate_ref,
        candidate_sha256=candidate_ref.content_sha256,
        candidate_size_bytes=321,
        authorization_ref=_ref("case_authorization", 5, "c" * 64),
        review_ref=_ref("case_review", 6, "d" * 64),
        release_policy_ref=_ref("case_release_policy", 7, "e" * 64),
        release_decision_sha256="f" * 64,
        provenance_ref=_ref("candidate_provenance", 8, "1" * 64),
        purpose="answer_support",
        approval_operation_id=operation_id,
        approval_request_id=decision_id,
        approval_descriptor_sha256=descriptor_hash,
        approval_draft_sha256=draft_sha256,
        approval_target_scope_hash=scope_hash,
        source_review_decision_id=decision_id,
        idempotency_key="publish-case-once",
    )
    serialized = case_publish_payload_bytes(payload)
    payload_ref = StoredContentRef(
        object_id=_oid("case_outbox_payload", 9),
        content_sha256=case_publish_payload_sha256(payload),
        media_type="application/json",
        size_bytes=len(serialized),
    )
    approval = SourceCaseApproval(
        operation_id=operation_id,
        decision_id=decision_id,
        descriptor_sha256=descriptor_hash,
        draft_sha256=draft_sha256,
        target_scope_hash=scope_hash,
        session_id=SESSION_ID,
        candidate_id=candidate_ref.object_id,
        candidate_sha256=candidate_ref.content_sha256,
        reviewer_id_hash="2" * 64,
        decided_at=NOW,
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_scope_hash, state, started_at, closed_at,
            client_id, client_snapshot_version,
            client_snapshot_canonical_sha256, client_snapshot_object_id,
            client_snapshot_sha256, client_snapshot_media_type,
            client_snapshot_size_bytes, capability_epoch,
            last_closed_turn_ordinal, archive_state, updated_at
        ) VALUES (?, ?, 'CLOSED', ?, ?, ?, 0, ?, ?, ?, 'application/json',
                  2, 1, 0, 'DRAFT', ?)
        """,
        (
            SESSION_ID,
            "3" * 64,
            NOW.isoformat(),
            NOW.isoformat(),
            "client_" + "aaaaaaaaaaaa",
            "6" * 64,
            _oid("session_context", 1),
            "7" * 64,
            NOW.isoformat(),
        ),
    )
    connection.execute(
        """
        INSERT INTO archive_bundles(
            bundle_id, session_id, actual_transcript_object_id,
            actual_transcript_version, actual_transcript_sha256,
            actual_transcript_media_type, actual_transcript_size_bytes,
            incomplete_evidence, created_at
        ) VALUES (?, ?, ?, 1, ?, 'application/json', 10, 0, ?)
        """,
        (
            bundle_id,
            SESSION_ID,
            _oid("actual_transcript", 10),
            "4" * 64,
            NOW.isoformat(),
        ),
    )
    connection.execute(
        """
        INSERT INTO archive_purpose_states(
            bundle_id, purpose, state, manifest_id, review_decision_id, updated_at
        ) VALUES (?, 'shared_case', 'DRAFT', NULL, NULL, ?)
        """,
        (bundle_id, NOW.isoformat()),
    )
    connection.execute(
        """
        INSERT INTO shared_case_candidates(
            candidate_id, bundle_id, version, candidate_object_id,
            candidate_sha256, candidate_media_type, candidate_size_bytes,
            source_record_sha256, incomplete_evidence, created_at
        ) VALUES (?, ?, 1, ?, ?, 'application/json', ?, ?, 0, ?)
        """,
        (
            candidate_ref.object_id,
            bundle_id,
            candidate_ref.object_id,
            candidate_ref.content_sha256,
            payload.candidate_size_bytes,
            "5" * 64,
            NOW.isoformat(),
        ),
    )
    if seed_authority:
        decided_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        connection.execute(
            """
            INSERT INTO review_decisions(
                decision_id, session_id, object_id, decision,
                reviewer_id_hash, decided_at
            ) VALUES (?, ?, ?, 'APPROVED', ?, ?)
            """,
            (
                decision_id,
                SESSION_ID,
                candidate_ref.object_id,
                approval.reviewer_id_hash,
                decided_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                operation_id,
                decision_id,
                descriptor_hash,
                draft_sha256,
                candidate_ref.version,
                scope_hash,
                "9" * 64,
            ),
        )
        connection.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = 1, applied_at = ? WHERE operation_id = ?",
            (decided_at, operation_id),
        )
    return bundle_id, payload, payload_ref, approval


def test_exact_persisted_approval_and_body_free_outbox_are_idempotent(
    tmp_path: Path,
) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(connection)
        repository = OutboxRepository(connection)
        event_id = _oid("case_outbox_event", 11)
        record = repository.enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )
        replayed = repository.enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )

        body_free = case_publish_payload_bytes(payload).decode("ascii")
        assert record == replayed
        assert "sections" not in body_free and "case narrative" not in body_free
        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0] == 1
        assert connection.execute(
            "SELECT state FROM archive_purpose_states WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()[0] == "PREPARED"

        with pytest.raises(OutboxConflict):
            repository.enqueue(
                event_id=_oid("case_outbox_event", 12),
                bundle_id=bundle_id,
                approval=approval,
                payload=payload,
                payload_ref=payload_ref,
                created_at=NOW,
            )
    finally:
        connection.close()


def test_outbox_claim_failure_and_global_ack_are_replay_safe(tmp_path: Path) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(connection)
        repository = OutboxRepository(connection)
        event_id = _oid("case_outbox_event", 13)
        repository.enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )
        claimed = repository.claim(event_id, claimed_at=NOW + timedelta(seconds=1))
        failed = repository.mark_failed(
            event_id,
            error_code="TRANSFER_RETRY",
            failed_at=NOW + timedelta(seconds=2),
        )
        reclaimed = repository.claim(
            event_id,
            claimed_at=NOW + timedelta(seconds=3),
        )
        proof = _publication_proof(event_id, payload)
        published = repository.mark_published(
            event_id,
            global_version=1,
            published_at=NOW + timedelta(seconds=4),
            publication_proof=proof,
        )
        replayed = repository.mark_published(
            event_id,
            global_version=1,
            published_at=NOW + timedelta(seconds=5),
            publication_proof=proof,
        )

        assert claimed.attempt_count == 1
        assert failed.state == "FAILED"
        assert reclaimed.attempt_count == 2
        assert published == replayed
        with pytest.raises(OutboxConflict):
            repository.mark_published(
                event_id,
                global_version=2,
                published_at=NOW + timedelta(seconds=6),
                publication_proof=proof,
            )
    finally:
        connection.close()


def test_invalid_candidate_binding_writes_nothing(tmp_path: Path) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(
            connection,
            seed_authority=False,
        )
        poisoned = approval.model_copy(update={"candidate_sha256": "0" * 64})
        with pytest.raises(OutboxError, match="OUTBOX_APPROVAL_BINDING_MISMATCH"):
            OutboxRepository(connection).enqueue(
                event_id=_oid("case_outbox_event", 14),
                bundle_id=bundle_id,
                approval=poisoned,
                payload=payload,
                payload_ref=payload_ref,
                created_at=NOW,
            )
        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0] == 0
    finally:
        connection.close()


def test_enqueue_rejects_missing_persisted_approval_authority(tmp_path: Path) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(
            connection,
            seed_authority=False,
        )

        with pytest.raises(OutboxError, match="OUTBOX_APPROVAL_EXECUTION_REQUIRED"):
            OutboxRepository(connection).enqueue(
                event_id=_oid("case_outbox_event", 140),
                bundle_id=bundle_id,
                approval=approval,
                payload=payload,
                payload_ref=payload_ref,
                created_at=NOW,
            )

        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM archive_purpose_states WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone() == ("DRAFT",)
    finally:
        connection.close()


def test_enqueue_never_creates_review_from_caller_supplied_approval(
    tmp_path: Path,
) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(
            connection,
            seed_authority=False,
        )
        applied_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, 1, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                approval.operation_id,
                approval.decision_id,
                approval.descriptor_sha256,
                approval.draft_sha256,
                approval.target_scope_hash,
                "a" * 64,
            ),
        )
        connection.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = 1, applied_at = ? WHERE operation_id = ?",
            (applied_at, approval.operation_id),
        )

        with pytest.raises(OutboxError, match="OUTBOX_REVIEW_AUTHORITY_REQUIRED"):
            OutboxRepository(connection).enqueue(
                event_id=_oid("case_outbox_event", 141),
                bundle_id=bundle_id,
                approval=approval,
                payload=payload,
                payload_ref=payload_ref,
                created_at=NOW,
            )

        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM archive_purpose_states WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone() == ("DRAFT",)
    finally:
        connection.close()


def test_outbox_rejects_time_regression_and_direct_binding_mutation(
    tmp_path: Path,
) -> None:
    connection = _source_database(tmp_path / "source.sqlite3")
    try:
        bundle_id, payload, payload_ref, approval = _fixture(connection)
        repository = OutboxRepository(connection)
        event_id = _oid("case_outbox_event", 15)
        repository.enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )

        with pytest.raises(OutboxError, match="OUTBOX_TIME_REGRESSION"):
            repository.claim(event_id, claimed_at=NOW - timedelta(seconds=1))
        assert repository.get(event_id).state == "PENDING"

        with pytest.raises(sqlite3.IntegrityError, match="transition invalid"):
            connection.execute(
                "UPDATE outbox_events SET payload_sha256 = ? WHERE event_id = ?",
                ("0" * 64, event_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM outbox_events WHERE event_id = ?",
                (event_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE review_decisions SET decision = 'REJECTED' "
                "WHERE decision_id = ?",
                (approval.decision_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM approval_executions WHERE operation_id = ?",
                (approval.operation_id,),
            )
    finally:
        connection.close()


def test_production_recovery_acks_only_an_exact_signed_global_proof(
    tmp_path: Path,
) -> None:
    database = tmp_path / "source.sqlite3"
    cas = tmp_path / "source-cas"
    connection = _source_database(database)
    try:
        bundle_id, payload, payload_ref, approval = _fixture(connection)
        serialized = case_publish_payload_bytes(payload)
        store = ContentStore(cas)
        reference = store.finalize(
            store.stage_bytes(
                serialized,
                purpose="case_publish",
                manifest_id=payload_ref.object_id,
                media_type="application/json",
            )
        )
        assert reference.content_sha256 == payload_ref.content_sha256
        event_id = _oid("case_outbox_event", 16)
        OutboxRepository(connection).enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )
    finally:
        connection.close()

    # The scoped source recovery never opens or discovers this adjacent file.
    (tmp_path / "global.sqlite3").write_bytes(b"not sqlite")
    proof = _publication_proof(event_id, payload)
    verifier = LocalHmacCasePublicationProofVerifier(
        secret=b"c" * 32,
        attestor_id="case-publication-test",
    )
    database_ref = "d" * 64

    def backend() -> SqliteRecoveryBackend:
        return SqliteRecoveryBackend(
            database=database.resolve(),
            content_store=ContentStore(cas.resolve()),
            database_scope="client",
            database_ref_sha256=database_ref,
            clock=FixedClock(NOW),
            outbox_ack_proofs={event_id: proof},
            outbox_proof_verifier=verifier,
        )

    scan = RecoveryCoordinator(
        backend=backend(),
        clock=FixedClock(NOW),
    ).scan()
    decision = next(value for value in scan.decisions if value.manifest_id == event_id)
    assert decision.action == "ACK_SOURCE"

    first = RecoveryCoordinator(
        backend=backend(),
        clock=FixedClock(NOW),
    ).recover()
    second = RecoveryCoordinator(
        backend=backend(),
        clock=FixedClock(NOW),
    ).recover()
    assert len(first.receipts) == 1
    assert second.receipts == ()
    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state, published_global_version FROM outbox_events "
            "WHERE event_id = ?",
            (event_id,),
        ).fetchone() == ("PUBLISHED", 1)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_decision_journal"
        ).fetchone() == (1,)
    finally:
        reader.close()
