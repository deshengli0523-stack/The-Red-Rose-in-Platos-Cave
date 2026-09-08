from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofVerifier,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.lifecycle.recovery import RecoveryCoordinator
from consultation_kb.lifecycle.sqlite_recovery import (
    SqliteRecoveryBackend,
    SqliteRecoveryError,
)
from consultation_kb.models.recovery import RecoveryDecision
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner, load_migrations
from consultation_kb.storage.outbox import (
    OutboxRepository,
    case_publish_payload_bytes,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.unit.test_outbox import (
    _fixture as _outbox_fixture,
    _publication_proof,
)


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
DATABASE_REF = hashlib.sha256(b"production-recovery-database").hexdigest()
DESCRIPTOR_SHA256 = "a" * 64
SCOPE_HASH = "b" * 64
ARTIFACT_KINDS = (
    "profile",
    "graph",
    "lex",
    "vector",
    "wiki_page",
    "wiki_index",
    "knowledge_registry",
    "claims",
)


def _oid(kind: str, suffix: int) -> str:
    return f"{kind}_019f79d1-7d00-7000-8000-{suffix:012x}"


def _open_database(
    database: Path,
    *,
    scope: str,
    latest: bool = True,
) -> sqlite3.Connection:
    connection = connect_database(database, "writer")
    migrations = load_migrations(scope)  # type: ignore[arg-type]
    MigrationRunner(
        connection,
        migrations if latest else migrations[:-1],
    ).apply()
    return connection


def _coordinator(
    connection: sqlite3.Connection,
    cas: Path,
    *,
    clock: FixedClock | None = None,
) -> PublishCoordinator:
    exact_clock = clock or FixedClock(NOW)
    return PublishCoordinator(
        connection,
        ContentStore(cas),
        VisibilityGuard(TombstoneRepository(connection, clock=exact_clock)),
        clock=exact_clock,
    )


def _artifacts(
    *,
    version: int,
    suffix_base: int,
    kinds: tuple[str, ...] = ARTIFACT_KINDS,
) -> tuple[ArtifactDraft, ...]:
    values: list[ArtifactDraft] = []
    for offset, kind in enumerate(kinds):
        member_kind = f"{kind}_artifact"
        values.append(
            ArtifactDraft(
                manifest_id=_oid("manifest", suffix_base + offset),
                artifact_key=kind,
                artifact_kind=kind,
                source_version=version,
                members=(
                    ContentDraft(
                        object_type=member_kind,
                        object_id=_oid(member_kind, suffix_base + 100 + offset),
                        data=json.dumps(
                            {"kind": kind, "version": version},
                            separators=(",", ":"),
                        ).encode("ascii"),
                        source_version=version,
                        media_type="application/json",
                        source_lineage=(),
                    ),
                ),
            )
        )
    return tuple(values)


def _prepare(
    connection: sqlite3.Connection,
    cas: Path,
    *,
    operation_suffix: int,
    version: int,
    expected_epoch: int | None,
    artifacts: tuple[ArtifactDraft, ...],
    purpose: str,
) -> tuple[str, tuple[str, ...]]:
    coordinator = _coordinator(connection, cas)
    prepared = coordinator.stage_artifacts(purpose=purpose, artifacts=artifacts)
    operation_id = _oid("operation", operation_suffix)
    approval_request_id = _oid("approval_request", operation_suffix)
    closure = publication_closure_sha256(
        purpose=purpose,
        authority_base_version=version,
        expected_current_epoch=expected_epoch,
        artifacts=prepared,
    )
    connection.execute(
        "INSERT INTO approval_executions("
        "operation_id, request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, nonce_sha256, state, "
        "applied_commit_version, applied_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)",
        (
            operation_id,
            approval_request_id,
            DESCRIPTOR_SHA256,
            closure,
            version - 1,
            SCOPE_HASH,
            hashlib.sha256(operation_id.encode("ascii")).hexdigest(),
        ),
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose=purpose,
        authority_base_version=version,
        approval_request_id=approval_request_id,
        descriptor_sha256=DESCRIPTOR_SHA256,
        expected_current_epoch=expected_epoch,
        artifacts=prepared,
    )
    changed = connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = 97, applied_at = ? "
        "WHERE operation_id = ? AND state = 'CLAIMED'",
        (NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"), operation_id),
    ).rowcount
    assert changed == 1
    return operation_id, tuple(value.manifest_id for value in artifacts)


def _activate(
    connection: sqlite3.Connection,
    cas: Path,
    operation_id: str,
) -> int:
    coordinator = _coordinator(connection, cas)
    coordinator.verify(operation_id)
    operation = coordinator.activate(operation_id)
    assert operation.runtime_epoch is not None
    return operation.runtime_epoch


def _backend(
    database: Path,
    cas: Path,
    *,
    scope: str,
    now: datetime = NOW,
    staging_ttl: timedelta = timedelta(hours=24),
) -> SqliteRecoveryBackend:
    return SqliteRecoveryBackend(
        database=database.resolve(),
        content_store=ContentStore(cas.resolve()),
        database_scope=scope,  # type: ignore[arg-type]
        database_ref_sha256=DATABASE_REF,
        clock=FixedClock(now),
        staging_ttl=staging_ttl,
    )


def _subprocess_recover(
    database: Path,
    cas: Path,
    *,
    scope: str,
) -> dict[str, object]:
    script = """
import json
from datetime import datetime, timezone
from pathlib import Path
from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.recovery import RecoveryCoordinator
from consultation_kb.lifecycle.sqlite_recovery import SqliteRecoveryBackend
from consultation_kb.vault.content_store import ContentStore
backend = SqliteRecoveryBackend(
    database=Path(__import__('sys').argv[1]).resolve(),
    content_store=ContentStore(Path(__import__('sys').argv[2]).resolve()),
    database_scope=__import__('sys').argv[3],
    database_ref_sha256=__import__('sys').argv[4],
    clock=FixedClock(datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)),
)
report = RecoveryCoordinator(backend=backend, clock=backend._clock).recover()
print(report.model_dump_json())
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(database), str(cas), scope, DATABASE_REF],
        check=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[3],
    )
    return json.loads(completed.stdout)


def test_client_prepared_operation_recovers_in_a_fresh_process_and_is_idempotent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client")
    try:
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 1, client_id = ? "
            "WHERE singleton = 1",
            ("client" + "_aaaaaaaaaaaa",),
        )
        _, manifests = _prepare(
            connection,
            cas,
            operation_suffix=10,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(version=1, suffix_base=100, kinds=("profile", "graph")),
            purpose="profile_update",
        )
    finally:
        connection.close()

    # A malformed adjacent database proves the scoped adapter never enumerates it.
    (tmp_path / "unrelated-client.sqlite3").write_bytes(b"not sqlite")
    first = _subprocess_recover(database, cas, scope="client")
    second = _subprocess_recover(database, cas, scope="client")

    first_receipts = first["receipts"]
    assert isinstance(first_receipts, list) and len(first_receipts) == 2
    assert {value["disposition"] for value in first_receipts} == {"APPLIED", "REPLAYED"}
    assert second["receipts"] == []
    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state, runtime_epoch FROM publication_operations"
        ).fetchone() == ("ACTIVE", 1)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_decision_journal"
        ).fetchone() == (2,)
        assert {
            str(row[0])
            for row in reader.execute(
                "SELECT manifest_id FROM active_artifacts WHERE epoch = 1"
            ).fetchall()
        } == set(manifests)
    finally:
        reader.close()


def test_eight_root_corruption_retires_the_whole_prepared_operation_once(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client")
    try:
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 1 WHERE singleton = 1"
        )
        old_operation, _ = _prepare(
            connection,
            cas,
            operation_suffix=20,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(version=1, suffix_base=200, kinds=("profile",)),
            purpose="profile_update",
        )
        assert _activate(connection, cas, old_operation) == 1
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 2 WHERE singleton = 1"
        )
        new_operation, manifests = _prepare(
            connection,
            cas,
            operation_suffix=21,
            version=2,
            expected_epoch=1,
            artifacts=_artifacts(version=2, suffix_base=300),
            purpose="profile_update",
        )
        corrupted = ManifestRepository(connection).get(manifests[3]).members[0]
        reference = ContentStore(cas).reference(
            content_sha256=corrupted.object_sha256,
            media_type=corrupted.media_type,
            size_bytes=corrupted.size_bytes,
        )
        reference.path.write_bytes(b"corrupt")
    finally:
        connection.close()

    coordinator = RecoveryCoordinator(
        backend=_backend(database, cas, scope="client"),
        clock=FixedClock(NOW),
    )
    scan = coordinator.scan()
    prepared = [
        value for value in scan.decisions if value.manifest_id in set(manifests)
    ]
    assert len(prepared) == 8
    assert {value.action for value in prepared} == {"TOMBSTONE_PREPARED"}
    assert all("MANIFEST_HASH_INVALID" in value.reason_codes for value in prepared)

    coordinator.recover()
    coordinator.recover()
    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (new_operation,),
        ).fetchone() == ("FAILED",)
        assert reader.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone() == (1,)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_prepared_retirements "
            "WHERE operation_id = ?",
            (new_operation,),
        ).fetchone() == (8,)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_required_actions "
            "WHERE manifest_id IN ("
            + ",".join("?" for _ in manifests)
            + ") AND action_type = 'cleanup'",
            manifests,
        ).fetchone() == (8,)
    finally:
        reader.close()


def test_legacy_prepared_binding_and_stale_authority_fail_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client", latest=False)
    try:
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 1 WHERE singleton = 1"
        )
        legacy_operation, legacy_manifests = _prepare(
            connection,
            cas,
            operation_suffix=30,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(version=1, suffix_base=400, kinds=("profile",)),
            purpose="profile_update",
        )
        MigrationRunner.for_scope(connection, "client").apply()
        assert connection.execute(
            "SELECT binding_origin FROM recovery_operation_authority_bindings "
            "WHERE operation_id = ?",
            (legacy_operation,),
        ).fetchone() == ("LEGACY_UNTRUSTED",)
    finally:
        connection.close()

    legacy_scan = RecoveryCoordinator(
        backend=_backend(database, cas, scope="client"),
        clock=FixedClock(NOW),
    ).scan()
    legacy = next(
        value
        for value in legacy_scan.decisions
        if value.manifest_id == legacy_manifests[0]
    )
    assert legacy.action == "TOMBSTONE_PREPARED"
    assert "APPROVAL_INTENT_INVALID" in legacy.reason_codes

    connection = connect_database(database, "writer")
    try:
        RecoveryCoordinator(
            backend=_backend(database, cas, scope="client"),
            clock=FixedClock(NOW),
        ).recover()
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 2 WHERE singleton = 1"
        )
        _, current_manifests = _prepare(
            connection,
            cas,
            operation_suffix=31,
            version=2,
            expected_epoch=None,
            artifacts=_artifacts(version=2, suffix_base=410, kinds=("profile",)),
            purpose="profile_update",
        )
        connection.execute(
            "UPDATE client_fact_authority SET commit_version = 3 WHERE singleton = 1"
        )
        TombstoneRepository(connection, clock=FixedClock(NOW)).add(
            ObjectIdentity("unrelated", _oid("unrelated", 999)),
            reason_code="revoked",
        )
    finally:
        connection.close()
    stale_scan = RecoveryCoordinator(
        backend=_backend(database, cas, scope="client"),
        clock=FixedClock(NOW),
    ).scan()
    stale = next(
        value
        for value in stale_scan.decisions
        if value.manifest_id == current_manifests[0]
    )
    assert stale.action == "TOMBSTONE_PREPARED"
    assert {"SOURCE_VERSION_STALE", "BASE_VERSION_STALE", "TOMBSTONE_EPOCH_STALE"}.issubset(
        stale.reason_codes
    )


def test_global_permission_drift_never_opens_an_adjacent_client_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "global.sqlite3"
    cas = tmp_path / "global-cas"
    connection = _open_database(database, scope="global")
    try:
        connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1"
        )
        _, manifests = _prepare(
            connection,
            cas,
            operation_suffix=40,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(version=1, suffix_base=500, kinds=("wiki_page",)),
            purpose="wiki_publish",
        )
        connection.execute(
            "UPDATE knowledge_catalog_state "
            "SET authorization_epoch = authorization_epoch + 1 "
            "WHERE singleton = 1"
        )
    finally:
        connection.close()
    (tmp_path / "client.sqlite3").write_bytes(b"not sqlite")

    scan = RecoveryCoordinator(
        backend=_backend(database, cas, scope="global"),
        clock=FixedClock(NOW),
    ).scan()
    decision = next(
        value for value in scan.decisions if value.manifest_id == manifests[0]
    )
    assert decision.action == "TOMBSTONE_PREPARED"
    assert "PERMISSION_TIGHTENED" in decision.reason_codes


def test_draft_ttl_and_retired_retention_are_production_inventory(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client")
    store = ContentStore(cas)
    old_draft_id = _oid("manifest", 600)
    new_draft_id = _oid("manifest", 601)
    store.stage_bytes(
        b"old",
        purpose="profile_update",
        manifest_id=old_draft_id,
        media_type="application/json",
    )
    store.stage_bytes(
        b"new",
        purpose="profile_update",
        manifest_id=new_draft_id,
        media_type="application/json",
    )
    old_payload = next(
        path
        for path in (cas / ".staging" / "profile_update" / old_draft_id).rglob("*")
        if path.is_file()
    )
    old_timestamp = (NOW - timedelta(hours=2)).timestamp()
    os.utime(old_payload, (old_timestamp, old_timestamp))
    try:
        for version, operation_suffix, suffix in (
            (1, 50, 700),
            (2, 51, 710),
            (3, 52, 720),
        ):
            connection.execute(
                "UPDATE client_fact_authority SET commit_version = ? "
                "WHERE singleton = 1",
                (version,),
            )
            operation, _ = _prepare(
                connection,
                cas,
                operation_suffix=operation_suffix,
                version=version,
                expected_epoch=None if version == 1 else version - 1,
                artifacts=_artifacts(
                    version=version,
                    suffix_base=suffix,
                    kinds=("profile",),
                ),
                purpose="profile_update",
            )
            if version == 2:
                connection.execute(
                    "INSERT INTO recovery_epoch_retention_windows("
                    "epoch, rollback_expires_at, retention_required, "
                    "binding_origin, bound_at"
                    ") VALUES (1, ?, 1, 'EXPLICIT', ?)",
                    (
                        (NOW - timedelta(days=1)).isoformat(),
                        NOW.isoformat(),
                    ),
                )
            assert _activate(connection, cas, operation) == version
    finally:
        connection.close()

    backend = _backend(
        database,
        cas,
        scope="client",
        now=NOW + timedelta(days=8),
        staging_ttl=timedelta(hours=1),
    )
    scan = RecoveryCoordinator(
        backend=backend,
        clock=FixedClock(NOW + timedelta(days=8)),
    ).scan()
    decisions = {value.manifest_id: value for value in scan.decisions}
    assert decisions[old_draft_id].action == "CLEAN_STAGING"
    assert decisions[new_draft_id].action == "CLEAN_STAGING"
    retired = [value for value in scan.decisions if value.before_state == "RETIRED"]
    assert len(retired) == 2
    assert {value.action for value in retired} == {"KEEP", "QUEUE_CLEANUP"}
    retained = next(value for value in retired if value.action == "KEEP")
    assert "RETENTION_REQUIRED" in retained.reason_codes

    RecoveryCoordinator(
        backend=backend,
        clock=FixedClock(NOW + timedelta(days=8)),
    ).recover()
    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_required_actions "
            "WHERE action_type = 'cleanup'"
        ).fetchone() == (3,)
    finally:
        reader.close()


def test_shared_case_and_case_index_can_never_use_runtime_epoch_activation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "global.sqlite3"
    cas = tmp_path / "global-cas"
    connection = _open_database(database, scope="global")
    try:
        connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1"
        )
        manifests: list[tuple[str, str]] = []
        for offset, (artifact_kind, purpose) in enumerate(
            (("shared_case", "case_publish"), ("case_index", "case_index_publish"))
        ):
            _, prepared = _prepare(
                connection,
                cas,
                operation_suffix=60 + offset,
                version=1,
                expected_epoch=None,
                artifacts=_artifacts(
                    version=1,
                    suffix_base=800 + offset,
                    kinds=(artifact_kind,),
                ),
                purpose=purpose,
            )
            manifests.append((prepared[0], "case" if offset == 0 else "index"))
    finally:
        connection.close()

    backend = _backend(database, cas, scope="global")
    for offset, (manifest_id, purpose) in enumerate(manifests):
        decision = RecoveryDecision(
            decision_sha256=f"{offset + 1:x}" * 64,
            evidence_sha256=f"{offset + 3:x}" * 64,
            database_ref_sha256=DATABASE_REF,
            database_scope="global",
            purpose=purpose,  # type: ignore[arg-type]
            manifest_id=manifest_id,
            manifest_sha256=f"{offset + 5:x}" * 64,
            before_state="PREPARED",
            after_state="ACTIVE",
            action="VERIFY_AND_ACTIVATE",
            verification_result="VALID",
            reason_codes=("VALID",),
            query_allowed=True,
        )
        with backend.single_writer(
            database_ref_sha256=DATABASE_REF,
            purpose=purpose,  # type: ignore[arg-type]
        ) as writer:
            with pytest.raises(
                SqliteRecoveryError,
                match="RECOVERY_LEDGER_RUNTIME_ACTIVATION_DENIED",
            ):
                writer.apply(decision)
    reader = connect_database(database, "reader")
    try:
        assert reader.execute("SELECT COUNT(*) FROM runtime_epochs").fetchone() == (0,)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_decision_journal"
        ).fetchone() == (0,)
    finally:
        reader.close()


@pytest.mark.parametrize(
    "artifact_kind",
    ("policy_manifest",),
)
def test_normal_governed_policy_artifacts_are_valid_recovery_inventory(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    database = tmp_path / "global.sqlite3"
    cas = tmp_path / "global-cas"
    connection = _open_database(database, scope="global")
    try:
        _prepare(
            connection,
            cas,
            operation_suffix=89,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(
                version=1,
                suffix_base=890,
                kinds=(artifact_kind,),
            ),
            purpose="risk_policy_publish",
        )
    finally:
        connection.close()

    inventory = _backend(database, cas, scope="global").read_only_inventory()

    assert len(inventory) == 1
    assert inventory[0].purpose == "wiki"
    assert inventory[0].state == "PREPARED"


@pytest.mark.parametrize(
    "artifact_kind",
    ("risk_rule_policy", "risk_model_descriptor"),
)
def test_risk_artifacts_are_left_to_the_dedicated_startup_validator(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    database = tmp_path / "global.sqlite3"
    cas = tmp_path / "global-cas"
    connection = _open_database(database, scope="global")
    try:
        _prepare(
            connection,
            cas,
            operation_suffix=90,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(
                version=1,
                suffix_base=900,
                kinds=(artifact_kind,),
            ),
            purpose="risk_policy_publish",
        )
    finally:
        connection.close()

    assert _backend(database, cas, scope="global").read_only_inventory() == ()


def test_outbox_ack_requires_exact_signed_global_active_proof_and_reopens_idempotently(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client")
    try:
        bundle_id, payload, payload_ref, approval = _outbox_fixture(connection)
        body = case_publish_payload_bytes(payload)
        stored = ContentStore(cas).finalize(
            ContentStore(cas).stage_bytes(
                body,
                purpose="case_publish",
                manifest_id=payload_ref.object_id,
                media_type="application/json",
            )
        )
        assert stored.content_sha256 == payload_ref.content_sha256
        event_id = _oid("case_outbox_event", 900)
        OutboxRepository(connection).enqueue(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=NOW,
        )
        assert connection.execute(
            "SELECT binding_origin FROM recovery_outbox_authority_bindings "
            "WHERE event_id = ?",
            (event_id,),
        ).fetchone() == ("LIVE",)
    finally:
        connection.close()

    verifier = LocalHmacCasePublicationProofVerifier(
        secret=b"c" * 32,
        attestor_id="case-publication-test",
    )
    exact = _publication_proof(event_id, payload)
    invalid = exact.model_copy(update={"signature": "0" * 64})
    cross_event = _publication_proof(
        _oid("case_outbox_event", 901),
        payload,
    )

    def coordinator(*, proof: object | None) -> RecoveryCoordinator:
        proofs = {} if proof is None else {event_id: proof}
        backend = SqliteRecoveryBackend(
            database=database.resolve(),
            content_store=ContentStore(cas.resolve()),
            database_scope="client",
            database_ref_sha256=DATABASE_REF,
            clock=FixedClock(NOW),
            outbox_ack_proofs=proofs,  # type: ignore[arg-type]
            outbox_proof_verifier=verifier if proofs else None,
        )
        return RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))

    for proof in (None, invalid, cross_event):
        scan = coordinator(proof=proof).scan()
        decision = next(
            value for value in scan.decisions if value.manifest_id == event_id
        )
        assert decision.action == "KEEP"
        assert "SOURCE_ACK_UNVERIFIED" in decision.reason_codes
        assert coordinator(proof=proof).recover().receipts == ()
        reader = connect_database(database, "reader")
        try:
            assert reader.execute(
                "SELECT state, published_global_version FROM outbox_events "
                "WHERE event_id = ?",
                (event_id,),
            ).fetchone() == ("PENDING", None)
        finally:
            reader.close()

    exact_coordinator = coordinator(proof=exact)
    exact_scan = exact_coordinator.scan()
    exact_decision = next(
        value for value in exact_scan.decisions if value.manifest_id == event_id
    )
    assert exact_decision.action == "ACK_SOURCE"
    assert exact_decision.reason_codes == ("GLOBAL_ACTIVE_ACK_PENDING",)

    first = exact_coordinator.recover()
    reopened = coordinator(proof=exact).recover()
    assert len(first.receipts) == 1
    assert reopened.receipts == ()
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


def test_outbox_ack_rechecks_tombstone_authority_inside_writer_transaction(
    tmp_path: Path,
) -> None:
    database = tmp_path / "client.sqlite3"
    cas = tmp_path / "client-cas"
    connection = _open_database(database, scope="client")
    try:
        bundle_id, payload, payload_ref, approval = _outbox_fixture(connection)
        store = ContentStore(cas)
        stored = store.finalize(
            store.stage_bytes(
                case_publish_payload_bytes(payload),
                purpose="case_publish",
                manifest_id=payload_ref.object_id,
                media_type="application/json",
            )
        )
        assert stored.content_sha256 == payload_ref.content_sha256
        event_id = _oid("case_outbox_event", 902)
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

    verifier = LocalHmacCasePublicationProofVerifier(
        secret=b"c" * 32,
        attestor_id="case-publication-test",
    )
    proof = _publication_proof(event_id, payload)
    backend = SqliteRecoveryBackend(
        database=database.resolve(),
        content_store=ContentStore(cas.resolve()),
        database_scope="client",
        database_ref_sha256=DATABASE_REF,
        clock=FixedClock(NOW),
        outbox_ack_proofs={event_id: proof},
        outbox_proof_verifier=verifier,
    )
    decision = next(
        value
        for value in RecoveryCoordinator(
            backend=backend,
            clock=FixedClock(NOW),
        ).scan().decisions
        if value.manifest_id == event_id
    )
    assert decision.action == "ACK_SOURCE"

    connection = connect_database(database, "writer")
    try:
        TombstoneRepository(connection, clock=FixedClock(NOW)).add(
            ObjectIdentity("claim", _oid("claim", 903)),
            reason_code="claim_revoked",
            tombstone_id=_oid("tombstone", 904),
        )
    finally:
        connection.close()

    with backend.single_writer(
        database_ref_sha256=DATABASE_REF,
        purpose="outbox",
    ) as writer:
        with pytest.raises(
            SqliteRecoveryError,
            match="RECOVERY_OUTBOX_INVENTORY_CHANGED",
        ):
            writer.apply(decision)

    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state, published_global_version FROM outbox_events "
            "WHERE event_id = ?",
            (event_id,),
        ).fetchone() == ("PENDING", None)
        assert reader.execute(
            "SELECT COUNT(*) FROM case_publication_proofs WHERE event_id = ?",
            (event_id,),
        ).fetchone() == (0,)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_decision_journal"
        ).fetchone() == (0,)
    finally:
        reader.close()
