from __future__ import annotations

import itertools
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.archive.case_publisher import (
    CasePublishAuthoritySnapshot,
    CasePublishError,
    CasePublishTransfer,
    SharedCasePublisher,
    case_release_decision_sha256,
    shared_candidate_bytes,
)
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofSigner,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.session import StoredContentRef
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRecord,
    case_publish_payload_bytes,
    case_publish_payload_sha256,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
)
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore
from tests.consultation_kb.unit.test_case_release_policy import (
    NOW as CASE_NOW,
    _authorization,
    _candidate,
    _policy,
    _review,
)


class InjectedSagaFailure(RuntimeError):
    pass


def _global_database(path: Path) -> sqlite3.Connection:
    connection = connect_database(path, "writer")
    MigrationRunner.for_scope(connection, "global").apply()
    return connection


def _package(
    *,
    seed: int = 1,
    idempotency_key: str = "shared-case-publish-fixture",
    reuse_authorized: bool = True,
    authorization_expires_at: datetime | None = None,
) -> tuple[OutboxRecord, CasePublishTransfer, datetime]:
    values = itertools.count(seed)
    ids = IdFactory(
        clock=FixedClock(CASE_NOW),
        random_source=lambda: next(values),
    )
    candidate = _candidate(ids)
    authorization = _authorization(
        ids,
        reuse=reuse_authorized,
        expires_at=authorization_expires_at,
    )
    review = _review(ids, candidate)
    evaluated_at = CASE_NOW + timedelta(minutes=2)
    decision = _policy(ids).evaluate(
        candidate,
        authorization,
        review,
        purpose="answer_support",
        at=evaluated_at,
    )
    candidate_body = shared_candidate_bytes(candidate)
    approval_request_id = ids.object_id("source_case_review")
    payload = CasePublishOutboxPayload(
        candidate_ref=candidate.candidate_ref,
        candidate_sha256=candidate.candidate_sha256,
        candidate_size_bytes=len(candidate_body),
        authorization_ref=authorization.authorization_ref,
        review_ref=review.review_ref,
        release_policy_ref=decision.policy_ref,
        release_decision_sha256=case_release_decision_sha256(decision),
        provenance_ref=candidate.provenance.provenance_ref,
        purpose="answer_support",
        approval_operation_id=ids.object_id("case_publish_operation"),
        approval_request_id=approval_request_id,
        approval_descriptor_sha256="1" * 64,
        approval_draft_sha256="2" * 64,
        approval_target_scope_hash="3" * 64,
        source_review_decision_id=approval_request_id,
        idempotency_key=idempotency_key,
    )
    serialized_payload = case_publish_payload_bytes(payload)
    event = OutboxRecord(
        event_id=ids.object_id("case_outbox_event"),
        bundle_id=ids.object_id("archive_bundle"),
        idempotency_key=payload.idempotency_key,
        payload=StoredContentRef(
            object_id=ids.object_id("case_outbox_payload"),
            content_sha256=case_publish_payload_sha256(payload),
            media_type="application/json",
            size_bytes=len(serialized_payload),
        ),
        state="CLAIMED",
        attempt_count=1,
        created_at=evaluated_at,
        updated_at=evaluated_at,
    )
    transfer = CasePublishTransfer(
        outbox_payload=payload,
        candidate=candidate,
        authorization=authorization,
        review=review,
        release_decision=decision,
    )
    return event, transfer, evaluated_at


class _MutableCasePublishAuthority:
    def __init__(
        self,
        transfer: CasePublishTransfer,
        *,
        authority_epoch: int = 1,
    ) -> None:
        payload = transfer.outbox_payload
        self.snapshot = CasePublishAuthoritySnapshot(
            candidate_ref=payload.candidate_ref,
            authorization_ref=payload.authorization_ref,
            review_ref=payload.review_ref,
            release_policy_ref=payload.release_policy_ref,
            release_decision_sha256=payload.release_decision_sha256,
            provenance_ref=payload.provenance_ref,
            purpose=payload.purpose,
            approval_operation_id=payload.approval_operation_id,
            approval_request_id=payload.approval_request_id,
            approval_descriptor_sha256=payload.approval_descriptor_sha256,
            approval_draft_sha256=payload.approval_draft_sha256,
            approval_descriptor_base_version=payload.candidate_ref.version,
            approval_applied_commit_version=1,
            approval_target_scope_hash=payload.approval_target_scope_hash,
            authority_epoch=authority_epoch,
            state="active",
        )
        self.observed_at: list[datetime] = []

    def resolve_case_publish_authority(
        self,
        *,
        payload: CasePublishOutboxPayload,
        as_of: datetime,
    ) -> CasePublishAuthoritySnapshot | None:
        del payload
        self.observed_at.append(as_of)
        return self.snapshot

    def revoke(self) -> None:
        self.snapshot = self.snapshot.model_copy(
            update={
                "authority_epoch": self.snapshot.authority_epoch + 1,
                "state": "revoked",
            }
        )

    def set_epoch(self, value: int) -> None:
        self.snapshot = self.snapshot.model_copy(
            update={"authority_epoch": value}
        )


def _publisher(
    connection: sqlite3.Connection,
    root: Path,
    now: datetime,
    authority: _MutableCasePublishAuthority,
) -> SharedCasePublisher:
    values = itertools.count(100)
    clock = FixedClock(now + timedelta(seconds=1))
    return SharedCasePublisher(
        connection,
        ContentStore(root),
        authority_resolver=authority,
        publication_proof_signer=LocalHmacCasePublicationProofSigner(
            secret=b"c" * 32,
            attestor_id="case-publication-test",
        ),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )


def test_publisher_requires_body_free_live_authority_resolver(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    try:
        with pytest.raises(TypeError, match="requires an authority resolver"):
            SharedCasePublisher(
                connection,
                ContentStore(tmp_path / "global_cas"),
                authority_resolver=object(),  # type: ignore[arg-type]
                publication_proof_signer=LocalHmacCasePublicationProofSigner(
                    secret=b"c" * 32,
                    attestor_id="case-publication-test",
                ),
            )
        assert set(CasePublishAuthoritySnapshot.model_fields).isdisjoint(
            {"body", "text", "client_id", "session_id", "path", "sql"}
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "phase",
    (
        "before_copy",
        "after_copy",
        "before_catalog_prepare",
        "after_catalog_prepare",
        "before_activate",
        "after_activate",
    ),
)
def test_publish_saga_faults_replay_to_one_complete_active_case(
    tmp_path: Path,
    phase: str,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)

    def fail_at(actual: str) -> None:
        if actual == phase:
            raise InjectedSagaFailure(actual)

    try:
        with pytest.raises(InjectedSagaFailure, match=phase):
            publisher.process(event, transfer, fault_hook=fail_at)

        catalog = CaseCatalog(connection, ContentStore(store_root))
        visible_before_replay = catalog.active_cases(purpose="answer_support")
        assert len(visible_before_replay) == (1 if phase == "after_activate" else 0)

        publication = publisher.replay(event, transfer)
        replayed = publisher.replay(event, transfer)
        visible = catalog.active_cases(purpose="answer_support")

        assert publication == replayed
        assert len(visible) == 1
        assert visible[0].case_ref == publication.case_ref
        assert len(catalog.read_body(visible[0]).sections) >= 2
        assert connection.execute("SELECT count(*) FROM cases").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM case_versions").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM global_publish_sagas").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_active_catalog_is_global_only_and_source_ack_failure_cannot_rollback_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)
    try:
        publication = publisher.process(event, transfer)

        def failed_source_ack() -> None:
            raise RuntimeError("source acknowledgement unavailable")

        with pytest.raises(RuntimeError, match="acknowledgement unavailable"):
            failed_source_ack()

        def forbid_new_database(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise AssertionError("catalog attempted to open another database")

        monkeypatch.setattr(sqlite3, "connect", forbid_new_database)
        catalog = CaseCatalog(connection, ContentStore(store_root))
        visible = catalog.active_cases(purpose="answer_support")
        body = catalog.read_body(visible[0])

        assert visible[0].case_ref == publication.case_ref
        assert transfer.authorization.contributor_client_hash not in (
            str(body.model_dump(mode="json"))
        )
        assert publisher.replay(event, transfer) == publication
    finally:
        connection.close()


@pytest.mark.parametrize(
    "invalidated_by",
    (
        "source_authority",
        "case",
        "case_version",
        "manifest",
        "authorization_expiry",
        "tombstone",
    ),
)
def test_active_saga_replay_rechecks_every_exact_live_authority(
    tmp_path: Path,
    invalidated_by: str,
) -> None:
    expires_at = CASE_NOW + timedelta(minutes=3)
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, evaluated_at = _package(
        authorization_expires_at=(
            expires_at if invalidated_by == "authorization_expiry" else None
        )
    )
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, evaluated_at, authority)
    try:
        publication = publisher.process(event, transfer)
        invalidated_at = evaluated_at + timedelta(seconds=2)
        if invalidated_by == "source_authority":
            authority.revoke()
        elif invalidated_by == "case":
            connection.execute(
                "UPDATE cases SET state = 'REVOKED', updated_at = ? WHERE case_id = ?",
                (
                    invalidated_at.isoformat().replace("+00:00", "Z"),
                    publication.case_ref.object_id,
                ),
            )
        elif invalidated_by == "case_version":
            connection.execute(
                "UPDATE case_versions SET state = 'REVOKED', revoked_at = ? "
                "WHERE case_id = ? AND version = ?",
                (
                    invalidated_at.isoformat().replace("+00:00", "Z"),
                    publication.case_ref.object_id,
                    publication.case_ref.version,
                ),
            )
        elif invalidated_by == "manifest":
            connection.execute(
                "UPDATE artifact_manifests SET state = 'PREPARED', verified = 0, "
                "verified_at = NULL "
                "WHERE manifest_id = ?",
                (publication.manifest_id,),
            )
        elif invalidated_by == "authorization_expiry":
            publisher = _publisher(connection, store_root, expires_at, authority)
        else:
            TombstoneRepository(
                connection,
                clock=FixedClock(invalidated_at),
                id_factory=IdFactory(
                    FixedClock(invalidated_at),
                    iter(range(80_000, 80_100)).__next__,
                ),
            ).add(
                ObjectIdentity("case", publication.case_ref.object_id),
                reason_code="authorization_revoked",
            )

        with pytest.raises(CasePublishError, match="CASE_PUBLISH_"):
            publisher.replay(event, transfer)
    finally:
        connection.close()


def test_catalog_rejects_a_record_tombstoned_after_listing(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)
    try:
        publisher.process(event, transfer)
        catalog = CaseCatalog(connection, ContentStore(store_root))
        stale = catalog.active_cases(purpose="answer_support")[0]
        TombstoneRepository(connection).add(
            ObjectIdentity("case", stale.case_ref.object_id),
            reason_code="authorization_revoked",
        )

        assert catalog.active_cases(purpose="answer_support") == ()
        with pytest.raises(
            RuntimeError,
            match="CASE_CATALOG_RECORD_NOT_ACTIVE",
        ):
            catalog.read_body(stale)
    finally:
        connection.close()


def test_catalog_rechecks_live_authority_after_reading_case_bytes(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)
    try:
        publisher.process(event, transfer)
        stable_catalog = CaseCatalog(connection, ContentStore(store_root))
        stale = stable_catalog.active_cases(purpose="answer_support")[0]
        tombstones = TombstoneRepository(connection)

        class _RevokingStore(ContentStore):
            def __init__(self, root: Path) -> None:
                super().__init__(root)
                self._revoked = False

            def read_verified(self, reference: ContentObjectRef) -> bytes:
                payload = super().read_verified(reference)
                if not self._revoked:
                    self._revoked = True
                    tombstones.add(
                        ObjectIdentity("case", stale.case_ref.object_id),
                        reason_code="authorization_revoked",
                    )
                return payload

        racing_catalog = CaseCatalog(connection, _RevokingStore(store_root))
        with pytest.raises(
            RuntimeError,
            match="CASE_CATALOG_RECORD_NOT_ACTIVE",
        ):
            racing_catalog.read_body(stale)
    finally:
        connection.close()


def test_ineligible_transfer_can_be_copied_but_never_prepared_or_visible(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package(reuse_authorized=False)
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)
    try:
        with pytest.raises(CasePublishError, match="CASE_PUBLISH_RELEASE_INVALID"):
            publisher.process(event, transfer)
        assert CaseCatalog(connection, ContentStore(store_root)).active_cases() == ()
        assert connection.execute("SELECT state FROM global_publish_sagas").fetchone()[0] == (
            "COPIED"
        )
        assert connection.execute("SELECT count(*) FROM cases").fetchone()[0] == 0
    finally:
        connection.close()


@pytest.mark.parametrize("phase", ("after_copy", "after_catalog_prepare"))
@pytest.mark.parametrize("invalidated_by", ("expiry", "revocation"))
def test_replay_rechecks_live_authority_before_each_publication_transition(
    tmp_path: Path,
    phase: str,
    invalidated_by: str,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    expires_at = CASE_NOW + timedelta(minutes=3)
    event, transfer, evaluated_at = _package(
        authorization_expires_at=(
            expires_at if invalidated_by == "expiry" else None
        )
    )
    authority = _MutableCasePublishAuthority(transfer, authority_epoch=7)
    publisher = _publisher(
        connection,
        store_root,
        evaluated_at,
        authority,
    )

    def fail_at(actual: str) -> None:
        if actual == phase:
            raise InjectedSagaFailure(actual)

    try:
        with pytest.raises(InjectedSagaFailure, match=phase):
            publisher.process(event, transfer, fault_hook=fail_at)

        if invalidated_by == "revocation":
            authority.revoke()
            replay = publisher
        else:
            replay = _publisher(
                connection,
                store_root,
                expires_at,
                authority,
            )

        with pytest.raises(
            CasePublishError,
            match="CASE_PUBLISH_AUTHORITY_NOT_ACTIVE",
        ):
            replay.replay(event, transfer)

        saga_state, persisted_epoch = connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone()
        assert saga_state == (
            "COPIED" if phase == "after_copy" else "PREPARED"
        )
        assert persisted_epoch == (
            None if phase == "after_copy" else 7
        )
        assert CaseCatalog(
            connection,
            ContentStore(store_root),
        ).active_cases() == ()
        assert connection.execute(
            "SELECT count(*) FROM case_versions WHERE state = 'ACTIVE'"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_prepared_saga_rejects_authority_epoch_rollback_then_accepts_newer(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer, authority_epoch=9)
    publisher = _publisher(connection, store_root, now, authority)

    def stop_after_prepare(phase: str) -> None:
        if phase == "after_catalog_prepare":
            raise InjectedSagaFailure(phase)

    try:
        with pytest.raises(InjectedSagaFailure, match="after_catalog_prepare"):
            publisher.process(event, transfer, fault_hook=stop_after_prepare)
        assert connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone() == ("PREPARED", 9)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="global case publish saga transition invalid",
        ):
            connection.execute(
                "UPDATE global_publish_sagas "
                "SET state = 'ACTIVE', authority_epoch = 8, "
                "published_global_version = case_version"
            )

        authority.set_epoch(8)
        with pytest.raises(
            CasePublishError,
            match="CASE_PUBLISH_AUTHORITY_EPOCH_ROLLBACK",
        ):
            publisher.replay(event, transfer)
        assert connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone() == ("PREPARED", 9)

        authority.set_epoch(10)
        publication = publisher.replay(event, transfer)
        assert publication.state == "ACTIVE"
        assert connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone() == ("ACTIVE", 10)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "mismatch",
    ("candidate", "authorization", "review", "approval"),
)
def test_live_authority_must_match_every_exact_governed_reference(
    tmp_path: Path,
    mismatch: str,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    ids = IdFactory(FixedClock(now), iter(range(50_000, 50_100)).__next__)
    if mismatch == "approval":
        authority.snapshot = authority.snapshot.model_copy(
            update={"approval_request_id": ids.object_id("wrong_approval")}
        )
    else:
        field = {
            "candidate": "candidate_ref",
            "authorization": "authorization_ref",
            "review": "review_ref",
        }[mismatch]
        current = getattr(authority.snapshot, field)
        authority.snapshot = authority.snapshot.model_copy(
            update={
                field: current.model_copy(
                    update={"content_sha256": "f" * 64}
                )
            }
        )
    publisher = _publisher(connection, store_root, now, authority)
    try:
        with pytest.raises(
            CasePublishError,
            match="CASE_PUBLISH_AUTHORITY_MISMATCH",
        ):
            publisher.process(event, transfer)
        assert connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone() == ("COPIED", None)
        assert connection.execute("SELECT count(*) FROM cases").fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("table", "error_code"),
    (
        ("case_versions", "CASE_PUBLISH_CASE_VERSION_ACTIVATION_FAILED"),
        ("cases", "CASE_PUBLISH_CASE_ACTIVATION_FAILED"),
        ("global_publish_sagas", "CASE_PUBLISH_SAGA_ACTIVATION_FAILED"),
    ),
)
def test_activation_requires_each_business_update_to_change_exactly_one_row(
    tmp_path: Path,
    table: str,
    error_code: str,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, now = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publisher = _publisher(connection, store_root, now, authority)

    def stop_after_prepare(phase: str) -> None:
        if phase == "after_catalog_prepare":
            raise InjectedSagaFailure(phase)

    try:
        with pytest.raises(InjectedSagaFailure, match="after_catalog_prepare"):
            publisher.process(event, transfer, fault_hook=stop_after_prepare)
        connection.execute(
            f"""
            CREATE TEMP TRIGGER suppress_{table}_activation
            BEFORE UPDATE OF state ON {table}
            WHEN OLD.state = 'PREPARED' AND NEW.state = 'ACTIVE'
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

        with pytest.raises(CasePublishError, match=error_code):
            publisher.replay(event, transfer)

        assert connection.execute(
            "SELECT state, authority_epoch FROM global_publish_sagas"
        ).fetchone() == ("PREPARED", 1)
        assert connection.execute(
            "SELECT state FROM case_versions"
        ).fetchone() == ("PREPARED",)
        assert connection.execute("SELECT state FROM cases").fetchone() == (
            "PREPARED",
        )
    finally:
        connection.close()


def test_case_ledgers_leave_existing_retrieval_epoch_unchanged(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    existing_operation = "retrieval-operation"
    existing_manifests = tuple(
        f"retrieval-manifest-{kind}"
        for kind in ("wiki", "registry", "graph", "lexical", "vector")
    )
    timestamp = CASE_NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT INTO publication_operations(operation_id, purpose, "
        "authority_base_version, approval_request_id, descriptor_sha256, "
        "state, required_manifests_json, required_manifest_count, "
        "verified_manifest_count, expected_current_epoch, runtime_epoch, "
        "created_at, activated_at) VALUES (?, 'knowledge_publish', 7, ?, ?, "
        "'ACTIVE', ?, 5, 5, NULL, 7, ?, ?)",
        (
            existing_operation,
            "retrieval-approval",
            "a" * 64,
            json.dumps(list(existing_manifests), separators=(",", ":")),
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO runtime_epochs(epoch, operation_id, state, created_at, "
        "activated_at) VALUES (7, ?, 'ACTIVE', ?, ?)",
        (existing_operation, timestamp, timestamp),
    )
    for ordinal, (manifest_id, artifact_kind) in enumerate(
        zip(
            existing_manifests,
            ("wiki_index", "knowledge_registry", "graph", "lexical", "vector"),
            strict=True,
        )
    ):
        connection.execute(
            "INSERT INTO artifact_manifests(manifest_id, operation_id, "
            "artifact_key, artifact_kind, source_version, manifest_sha256, "
            "state, verified, created_at, verified_at) VALUES (?, ?, ?, ?, "
            "'7', ?, 'ACTIVE', 1, ?, ?)",
            (
                manifest_id,
                existing_operation,
                artifact_kind,
                artifact_kind,
                f"{ordinal + 1:064x}",
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO active_artifacts(epoch, artifact_key, manifest_id, "
            "activated_at) VALUES (7, ?, ?, ?)",
            (artifact_kind, manifest_id, timestamp),
        )
    epochs_before = connection.execute(
        "SELECT * FROM runtime_epochs ORDER BY epoch"
    ).fetchall()
    active_before = connection.execute(
        "SELECT * FROM active_artifacts ORDER BY artifact_key"
    ).fetchall()
    first_event, first_transfer, now = _package()
    second_event, second_transfer, _ = _package(
        seed=10_000,
        idempotency_key="shared-case-publish-second",
    )
    first_authority = _MutableCasePublishAuthority(first_transfer)
    second_authority = _MutableCasePublishAuthority(second_transfer)

    class _CombinedAuthority:
        def resolve_case_publish_authority(
            self,
            *,
            payload: CasePublishOutboxPayload,
            as_of: datetime,
        ) -> CasePublishAuthoritySnapshot | None:
            authority = (
                first_authority
                if payload.candidate_ref == first_transfer.candidate.candidate_ref
                else second_authority
            )
            return authority.resolve_case_publish_authority(
                payload=payload,
                as_of=as_of,
            )

    publisher = SharedCasePublisher(
        connection,
        ContentStore(store_root),
        authority_resolver=_CombinedAuthority(),
        publication_proof_signer=LocalHmacCasePublicationProofSigner(
            secret=b"c" * 32,
            attestor_id="case-publication-test",
        ),
        clock=FixedClock(now + timedelta(seconds=1)),
        id_factory=IdFactory(
            clock=FixedClock(now + timedelta(seconds=1)),
            random_source=iter(range(100, 200)).__next__,
        ),
    )
    try:
        first = publisher.process(first_event, first_transfer)
        second = publisher.process(second_event, second_transfer)

        assert connection.execute(
            "SELECT * FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == epochs_before
        assert connection.execute(
            "SELECT * FROM active_artifacts ORDER BY artifact_key"
        ).fetchall() == active_before
        assert connection.execute(
            "SELECT COUNT(DISTINCT manifest.operation_id), "
            "MIN(manifest.operation_id) FROM active_artifacts AS active "
            "JOIN artifact_manifests AS manifest "
            "ON manifest.manifest_id = active.manifest_id"
        ).fetchone() == (1, existing_operation)
        assert len(CaseCatalog(connection, ContentStore(store_root)).active_cases()) == 2
        manifests = ManifestRepository(connection)
        assert manifests.get(first.manifest_id).state == "VERIFIED"
        assert manifests.get(second.manifest_id).state == "VERIFIED"
        assert connection.execute(
            "SELECT COUNT(*) FROM active_artifacts WHERE manifest_id IN (?, ?)",
            (first.manifest_id, second.manifest_id),
        ).fetchone() == (0,)
    finally:
        connection.close()
