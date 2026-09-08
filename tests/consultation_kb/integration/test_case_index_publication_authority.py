from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationError,
    CaseIndexPublicationRepository,
    CaseIndexPublicationService,
    invalidate_pending_case_indexes_in_transaction,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.archive.case_indexing import CaseIndexArtifact, CaseIndexBundle
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.operations.doctor_probes import (
    CaseIndexInvalidationDiagnosticProbe,
    RecoveryPendingDiagnosticProbe,
    _LifecycleDatabase,
)
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.manifests import ManifestMember, ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner, load_migrations
from consultation_kb.storage.tombstones import lineage_hash
from tests.consultation_kb.integration.test_case_01_full_lineage import (
    CLIENT_A,
    NOW,
    _fixture,
)
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    build_global_knowledge_harness,
)
from tests.consultation_kb import knowledge_integration_support


class InjectedPostVerifyCrash(RuntimeError):
    pass


def _utc() -> str:
    return NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _insert_provenance(harness: GlobalKnowledgeHarness, bundle: CaseIndexBundle) -> None:
    value = bundle.artifacts[0].provenance
    harness.connection.execute(
        "INSERT INTO case_provenance(provenance_id, provenance_version, "
        "provenance_sha256, artifact_object_id, artifact_version, "
        "artifact_sha256, artifact_kind, contributor_client_hashes_json, "
        "independent_source_count, derivation_rule_id, derivation_rule_version, "
        "derivation_rule_sha256, policy_manifest_id, policy_manifest_version, "
        "policy_manifest_sha256, source_grade, provenance_scope, "
        "allowed_uses_json, effective_to, closure_json, closure_sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            value.provenance_ref.object_id,
            value.provenance_ref.version,
            value.provenance_ref.content_sha256,
            value.artifact_ref.object_id,
            value.artifact_ref.version,
            value.artifact_ref.content_sha256,
            value.artifact_kind,
            json.dumps(sorted(value.contributor_client_hashes), separators=(",", ":")),
            len(value.independent_evidence),
            value.derivation_rule_ref.object_id,
            value.derivation_rule_ref.version,
            value.derivation_rule_ref.content_sha256,
            value.policy_manifest_ref.object_id,
            value.policy_manifest_ref.version,
            value.policy_manifest_ref.content_sha256,
            value.source_grade,
            value.provenance_scope,
            json.dumps(sorted(value.allowed_uses), separators=(",", ":")),
            None,
            canonical_json_bytes(value.model_dump(mode="json")).decode("ascii"),
            value.closure_sha256,
        ),
    )


def _seed_verified_shared_case(
    harness: GlobalKnowledgeHarness,
    original: CaseIndexBundle,
) -> CaseIndexBundle:
    root = original.root_case_ref
    body = b"deidentified-global-case-body"
    assert hashlib.sha256(body).hexdigest() == root.content_sha256
    manifest_id = harness.ids.object_id("case_manifest")
    operation_id = harness.ids.object_id("case_publication_operation")
    staged = harness.store.stage_bytes(
        body,
        purpose="shared_case_publish",
        manifest_id=manifest_id,
        media_type="application/json",
    )
    content = harness.store.finalize(staged)
    timestamp = _utc()
    harness.connection.execute(
        "INSERT INTO publication_operations(operation_id, purpose, "
        "authority_base_version, approval_request_id, descriptor_sha256, "
        "state, required_manifests_json, required_manifest_count, "
        "verified_manifest_count, expected_current_epoch, runtime_epoch, "
        "created_at, activated_at) VALUES (?, 'case_publish', 1, ?, ?, "
        "'PREPARED', ?, 1, 0, NULL, NULL, ?, NULL)",
        (
            operation_id,
            harness.ids.object_id("source_approval"),
            "a" * 64,
            json.dumps([manifest_id], separators=(",", ":")),
            timestamp,
        ),
    )
    manifests = ManifestRepository(harness.connection)
    manifests.insert_prepared(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key="case_" + hashlib.sha256(root.object_id.encode("ascii")).hexdigest()[:59],
        artifact_kind="shared_case",
        source_version=1,
        members=(
            ManifestMember(
                ordinal=0,
                object_type="case",
                object_id=root.object_id,
                object_sha256=root.content_sha256,
                source_version=1,
                media_type="application/json",
                size_bytes=content.size_bytes,
                source_lineage_hashes=(lineage_hash("case", root.object_id),),
            ),
        ),
        created_at=timestamp,
    )
    manifests.mark_verified(
        manifest_id,
        expected_source_version=1,
        verified_at=timestamp,
    )
    manifest = manifests.get(manifest_id)
    closure = publication_closure_sha256(
        purpose="case_publish",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=(manifest,),
    )
    harness.connection.execute(
        "INSERT INTO publication_closure_attestations(operation_id, "
        "approval_draft_sha256, closure_sha256, created_at) VALUES (?, ?, ?, ?)",
        (operation_id, "b" * 64, closure, timestamp),
    )
    harness.connection.execute(
        "UPDATE publication_operations SET state = 'VERIFIED', "
        "verified_manifest_count = 1 WHERE operation_id = ?",
        (operation_id,),
    )
    _insert_provenance(harness, original)
    root_artifact = original.artifacts[0]
    authorization = root_artifact.provenance.case_contributions[0].authorization_ref
    review = root_artifact.review_ref
    allowed_json = json.dumps(sorted(root_artifact.allowed_uses), separators=(",", ":"))
    candidate_id = harness.ids.object_id("shared_case_candidate")
    candidate_sha = hashlib.sha256(root.object_id.encode("ascii")).hexdigest()
    harness.connection.execute(
        "INSERT INTO cases(case_id, state, current_version, created_at, updated_at) "
        "VALUES (?, 'PREPARED', NULL, ?, ?)",
        (root.object_id, timestamp, timestamp),
    )
    harness.connection.execute(
        "INSERT INTO case_versions(case_id, version, candidate_id, "
        "candidate_version, candidate_sha256, global_content_ref, "
        "global_content_sha256, global_content_media_type, "
        "global_content_size_bytes, manifest_id, release_decision_sha256, "
        "allowed_uses_json, source_grade, provenance_id, provenance_version, "
        "state, prepared_at, activated_at, revoked_at) VALUES (?, 1, ?, 1, ?, "
        "?, ?, 'application/json', ?, ?, ?, ?, 'K1', ?, 1, 'ACTIVE', ?, ?, NULL)",
        (
            root.object_id,
            candidate_id,
            candidate_sha,
            f"sha256:{root.content_sha256}",
            root.content_sha256,
            content.size_bytes,
            manifest_id,
            root_artifact.release_decision_sha256,
            allowed_json,
            root_artifact.provenance.provenance_ref.object_id,
            timestamp,
            timestamp,
        ),
    )
    contributor_hash = next(iter(root_artifact.provenance.contributor_client_hashes))
    harness.connection.execute(
        "INSERT INTO case_authorizations(case_id, case_version, authorization_id, "
        "authorization_version, authorization_sha256, contributor_client_hash, "
        "reuse_authorized, allowed_uses_json, valid_from, expires_at, revoked_at, "
        "terms_sha256) VALUES (?, 1, ?, ?, ?, ?, 1, ?, ?, NULL, NULL, ?)",
        (
            root.object_id,
            authorization.object_id,
            authorization.version,
            authorization.content_sha256,
            contributor_hash,
            allowed_json,
            timestamp,
            "d" * 64,
        ),
    )
    harness.connection.execute(
        "INSERT INTO case_review_decisions(case_id, case_version, review_id, "
        "review_version, review_sha256, candidate_sha256, decision, "
        "checked_categories_json, residual_risk, rare_combination_disposition, "
        "allowed_uses_json, reviewer_attestation_sha256, release_policy_id, "
        "release_policy_version, release_policy_sha256, release_decision_sha256, "
        "reviewed_at, evaluated_at) VALUES (?, 1, ?, ?, ?, ?, 'approved', ?, "
        "'low', 'not_present', ?, ?, ?, 1, ?, ?, ?, ?)",
        (
            root.object_id,
            review.object_id,
            review.version,
            review.content_sha256,
            candidate_sha,
            json.dumps(
                [
                    "direct_identifiers",
                    "location_occupation_family_time",
                    "no_verbatim_quotes",
                    "rare_attributes",
                    "section_boundaries",
                    "third_party_people",
                ],
                separators=(",", ":"),
            ),
            allowed_json,
            "e" * 64,
            harness.ids.object_id("case_release_policy"),
            "f" * 64,
            root_artifact.release_decision_sha256,
            timestamp,
            timestamp,
        ),
    )
    harness.connection.execute(
        "UPDATE cases SET state = 'ACTIVE', current_version = 1 WHERE case_id = ?",
        (root.object_id,),
    )
    harness.connection.execute(
        "INSERT INTO global_publish_sagas("
        "saga_id, source_event_id, idempotency_key_sha256, "
        "outbox_payload_sha256, case_id, case_version, candidate_id, "
        "candidate_version, candidate_sha256, publication_operation_id, "
        "manifest_id, provenance_id, provenance_version, "
        "global_content_sha256, global_content_media_type, "
        "global_content_size_bytes, state, authority_epoch, attempt_count, "
        "published_global_version, last_error_code, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?, 1, ?, "
        "'application/json', ?, 'ACTIVE', 0, 0, 1, NULL, ?, ?)",
        (
            harness.ids.object_id("global_case_publish_saga"),
            harness.ids.object_id("case_publish_source_event"),
            hashlib.sha256(operation_id.encode("ascii")).hexdigest(),
            hashlib.sha256(manifest_id.encode("ascii")).hexdigest(),
            root.object_id,
            candidate_id,
            candidate_sha,
            operation_id,
            manifest_id,
            root_artifact.provenance.provenance_ref.object_id,
            root.content_sha256,
            content.size_bytes,
            timestamp,
            timestamp,
        ),
    )
    source_manifest_ref = VersionRef(
        object_id=manifest.manifest_id,
        version=manifest.source_version,
        content_sha256=manifest.manifest_sha256,
    )
    artifacts: list[CaseIndexArtifact] = []
    for artifact in original.artifacts:
        candidate = artifact.candidate
        if candidate is not None:
            candidate = candidate.model_copy(
                update={
                    "metadata": candidate.metadata.model_copy(
                        update={"manifest_ref": source_manifest_ref}
                    )
                }
            )
        artifacts.append(artifact.model_copy(update={"candidate": candidate}))
    return CaseIndexBundle(root_case_ref=root, artifacts=tuple(artifacts))


def _publication_service(
    harness: GlobalKnowledgeHarness,
) -> CaseIndexPublicationService:
    return CaseIndexPublicationService(
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        execution_guard=harness.guard,
        id_factory=harness.ids,
        clock=FixedClock(NOW),
    )


def _publish_case_index(
    harness: GlobalKnowledgeHarness,
    bundle: CaseIndexBundle,
):
    service = _publication_service(harness)
    plan = service.plan(bundle)
    return service.execute(
        plan,
        approval_request_id=harness.confirm(plan.descriptor),
    )


def test_verified_case_index_recovers_post_verify_without_runtime_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    original, contributor_hash = _fixture()
    bundle = _seed_verified_shared_case(harness, original)
    service = CaseIndexPublicationService(
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        execution_guard=harness.guard,
        id_factory=harness.ids,
        clock=FixedClock(NOW),
    )
    plan = service.plan(bundle)
    request_id = harness.confirm(plan.descriptor)

    def crash(_plan: object) -> tuple[str, int]:
        raise InjectedPostVerifyCrash

    monkeypatch.setattr(service, "_ensure_rebuild_intent", crash)
    with pytest.raises(InjectedPostVerifyCrash):
        service.execute(plan, approval_request_id=request_id)

    assert harness.connection.execute(
        "SELECT state, runtime_epoch FROM publication_operations "
        "WHERE operation_id = ?",
        (plan.operation_id,),
    ).fetchone() == ("VERIFIED", None)
    assert harness.connection.execute(
        "SELECT state FROM case_patterns WHERE manifest_id = ?",
        (plan.manifest_id,),
    ).fetchone() == ("PREPARED",)
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM rebuild_queue WHERE upstream_type = 'case_index'"
    ).fetchone() == (0,)
    assert harness.connection.execute("SELECT * FROM runtime_epochs").fetchall() == []
    assert harness.connection.execute("SELECT * FROM active_artifacts").fetchall() == []
    database = _LifecycleDatabase(
        scope="global",
        database=harness.root / "global.sqlite3",
        content_root=harness.root / "global-content",
    )
    with pytest.raises(RuntimeError):
        RecoveryPendingDiagnosticProbe()._run_one(
            database,
            harness.connection,
        )

    restarted = CaseIndexPublicationService(
        connection=harness.connection,
        content_store=harness.store,
        approval_service=harness.approvals,
        execution_guard=harness.guard,
        id_factory=harness.ids,
        clock=FixedClock(NOW),
    )
    publication = restarted.recover(plan.operation_id)
    replayed = CaseIndexPublicationRepository(
        harness.connection,
        harness.store,
        clock=FixedClock(NOW),
    )
    assert restarted.recover(plan.operation_id) == publication
    assert publication.catalog_version == 1
    assert len(publication.candidates) == 5
    assert len(replayed.replay_approved()) == 1
    intents = replayed.pending_rebuild_intents(target_catalog_version=1)
    assert len(intents) == 1
    assert intents[0].manifest_ref == publication.manifest_ref
    assert intents[0].queue_id == publication.rebuild_queue_id
    assert harness.connection.execute(
        "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone() == (0,)
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM case_provenance"
    ).fetchone() == (7,)
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM rebuild_queue WHERE upstream_type = 'case_index'"
    ).fetchone() == (1,)
    assert harness.connection.execute("SELECT * FROM runtime_epochs").fetchall() == []
    assert harness.connection.execute("SELECT * FROM active_artifacts").fetchall() == []
    assert (
        RecoveryPendingDiagnosticProbe()._run_one(
            database,
            harness.connection,
        )
        == 0
    )
    for artifact in replayed.replay_manifest(publication.manifest_ref).artifacts:
        assert CLIENT_A not in artifact.rendered_text
        assert contributor_hash not in artifact.rendered_text
    harness.connection.close()


def test_same_target_batch_is_claim_stable_and_all_or_nothing(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    first, _ = _fixture(counter_start=70_000)
    second, _ = _fixture(counter_start=80_000)
    first_publication = _publish_case_index(
        harness,
        _seed_verified_shared_case(harness, first),
    )
    second_publication = _publish_case_index(
        harness,
        _seed_verified_shared_case(harness, second),
    )
    repository = CaseIndexPublicationRepository(
        harness.connection,
        harness.store,
        clock=FixedClock(NOW),
    )
    snapshot = repository.pending_rebuild_snapshot(target_catalog_version=1)
    assert len(snapshot.identities) == 2
    assert {item.manifest_ref for item in snapshot.identities} == {
        first_publication.manifest_ref,
        second_publication.manifest_ref,
    }
    harness.connection.execute(
        "UPDATE rebuild_queue SET state = 'CLAIMED' WHERE queue_id = ?",
        (first_publication.rebuild_queue_id,),
    )
    claimed = repository.pending_rebuild_snapshot(target_catalog_version=1)
    assert claimed == snapshot
    assert claimed.identity_sha256 == snapshot.identity_sha256

    first_identity = snapshot.identities[0]
    with pytest.raises(sqlite3.IntegrityError, match="pending case index rebuild"):
        with transaction(harness.connection):
            harness.connection.execute(
                "UPDATE case_patterns SET state = 'ACTIVE' "
                "WHERE pattern_id = ? AND version = ?",
                (first_identity.pattern_id, first_identity.pattern_version),
            )
            harness.connection.execute(
                "UPDATE rebuild_queue SET state = 'COMPLETED' WHERE queue_id = ?",
                (first_identity.queue_id,),
            )
            harness.connection.execute(
                "UPDATE knowledge_catalog_state SET catalog_version = 1 "
                "WHERE singleton = 1 AND catalog_version = 0"
            )
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM case_patterns GROUP BY state"
    ).fetchall() == [("PREPARED", 2)]
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM rebuild_queue "
        "WHERE upstream_type = 'case_index' GROUP BY state ORDER BY state"
    ).fetchall() == [("CLAIMED", 1), ("PENDING", 1)]

    with transaction(harness.connection):
        repository.transition_rebuild_batch(snapshot)
        changed = harness.connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1 AND catalog_version = 0"
        ).rowcount
        assert changed == 1
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM case_patterns GROUP BY state"
    ).fetchall() == [("ACTIVE", 2)]
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM rebuild_queue "
        "WHERE upstream_type = 'case_index' GROUP BY state"
    ).fetchall() == [("COMPLETED", 2)]
    harness.connection.close()


def test_recovery_pending_probe_rejects_case_index_queue_state_mismatch(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    original, _contributor_hash = _fixture()
    _publish_case_index(harness, _seed_verified_shared_case(harness, original))
    database = _LifecycleDatabase(
        scope="global",
        database=harness.root / "global.sqlite3",
        content_root=harness.root / "global-content",
    )
    probe = RecoveryPendingDiagnosticProbe()
    assert probe._run_one(database, harness.connection) == 0

    harness.connection.execute(
        "UPDATE rebuild_queue SET state = 'COMPLETED' "
        "WHERE upstream_type = 'case_index' AND state = 'PENDING'"
    )

    with pytest.raises(RuntimeError):
        probe._run_one(database, harness.connection)
    harness.connection.close()


def test_security_epoch_requires_exact_plan_bound_invalidation(tmp_path: Path) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    first, _ = _fixture(counter_start=90_000)
    _publish_case_index(harness, _seed_verified_shared_case(harness, first))
    planned = snapshot_pending_case_index_invalidations(harness.connection)
    assert len(planned.identities) == 1

    with pytest.raises(
        sqlite3.IntegrityError,
        match="pending case index security invalidation required",
    ):
        with transaction(harness.connection):
            harness.connection.execute(
                "UPDATE knowledge_catalog_state SET tombstone_epoch = 1 "
                "WHERE singleton = 1"
            )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
    ).fetchone() == (0,)
    assert harness.connection.execute(
        "SELECT state FROM case_patterns"
    ).fetchall() == [("PREPARED",)]

    second, _ = _fixture(counter_start=100_000)
    _publish_case_index(harness, _seed_verified_shared_case(harness, second))
    with pytest.raises(
        CaseIndexPublicationError,
        match="CASE_INDEX_INVALIDATION_SET_CHANGED",
    ):
        with transaction(harness.connection):
            invalidate_pending_case_indexes_in_transaction(
                harness.connection,
                expected_snapshot=planned,
                authority_request_id=harness.ids.object_id("deletion_request"),
                reason_code="deletion_authority_advanced",
                next_authorization_epoch=0,
                next_tombstone_epoch=1,
                invalidated_at=NOW,
            )
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
    ).fetchone() == (0,)
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM case_patterns GROUP BY state"
    ).fetchall() == [("PREPARED", 2)]

    exact = snapshot_pending_case_index_invalidations(harness.connection)
    request_id = harness.ids.object_id("deletion_request")
    with transaction(harness.connection):
        invalidated = invalidate_pending_case_indexes_in_transaction(
            harness.connection,
            expected_snapshot=exact,
            authority_request_id=request_id,
            reason_code="deletion_authority_advanced",
            next_authorization_epoch=0,
            next_tombstone_epoch=1,
            invalidated_at=NOW,
        )
        harness.connection.execute(
            "UPDATE knowledge_catalog_state SET tombstone_epoch = 1 "
            "WHERE singleton = 1"
        )
    assert set(invalidated) == {item.queue_id for item in exact.identities}
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM case_patterns GROUP BY state"
    ).fetchall() == [("REVOKED", 2)]
    assert harness.connection.execute(
        "SELECT state, COUNT(*) FROM rebuild_queue "
        "WHERE upstream_type = 'case_index' GROUP BY state"
    ).fetchall() == [("PENDING", 2)]
    assert harness.connection.execute(
        "SELECT authority_request_id, invalidation_set_sha256, COUNT(*) "
        "FROM case_index_rebuild_invalidations "
        "GROUP BY authority_request_id, invalidation_set_sha256"
    ).fetchall() == [(request_id, exact.identity_sha256, 2)]
    first_queue = exact.identities[0].queue_id
    with pytest.raises(sqlite3.IntegrityError, match="append only"):
        harness.connection.execute(
            "UPDATE case_index_rebuild_invalidations SET reason_code = 'tampered' "
            "WHERE queue_id = ?",
            (first_queue,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append only"):
        harness.connection.execute(
            "DELETE FROM case_index_rebuild_invalidations WHERE queue_id = ?",
            (first_queue,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append only"):
        harness.connection.execute(
            "INSERT OR REPLACE INTO case_index_rebuild_invalidations "
            "SELECT * FROM case_index_rebuild_invalidations WHERE queue_id = ?",
            (first_queue,),
        )
    with pytest.raises(
        CaseIndexPublicationError,
        match="CASE_INDEX_INVALIDATION_SET_CHANGED",
    ):
        with transaction(harness.connection):
            invalidate_pending_case_indexes_in_transaction(
                harness.connection,
                expected_snapshot=exact,
                authority_request_id=request_id,
                reason_code="deletion_authority_advanced",
                next_authorization_epoch=0,
                next_tombstone_epoch=2,
                invalidated_at=NOW,
            )
    assert snapshot_pending_case_index_invalidations(
        harness.connection
    ).identities == ()
    assert harness.connection.execute(
        "SELECT catalog_version, tombstone_epoch FROM knowledge_catalog_state "
        "WHERE singleton = 1"
    ).fetchone() == (0, 1)

    repo_root = tmp_path / "doctor-repo"
    (repo_root / ".git").mkdir(parents=True)
    vault_root = tmp_path / "doctor-vault"
    global_root = vault_root / "global"
    global_root.mkdir(parents=True)
    (vault_root / "clients").mkdir()
    with sqlite3.connect(global_root / "catalog.sqlite3") as doctor_database:
        harness.connection.backup(doctor_database)
    doctor = CaseIndexInvalidationDiagnosticProbe().run(
        AppConfig.from_values(repo_root, vault_root)
    )
    assert doctor.status == "pass"
    assert doctor.code == "case_index_invalidations_verified"
    assert doctor.observed_count == 2
    harness.connection.close()


def test_competing_catalog_writer_cannot_overtake_new_pending_case_index(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    database_row = harness.connection.execute("PRAGMA database_list").fetchone()
    assert database_row is not None
    competitor = connect_database(Path(str(database_row[2])), mode="writer")
    try:
        competitor.execute("BEGIN")
        assert competitor.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (0,)
        bundle, _ = _fixture(counter_start=110_000)
        _publish_case_index(harness, _seed_verified_shared_case(harness, bundle))

        # The old read snapshot cannot upgrade into a writer after the pending
        # ledger committed on the competing connection.
        with pytest.raises(sqlite3.OperationalError):
            competitor.execute(
                "UPDATE knowledge_catalog_state SET catalog_version = 1 "
                "WHERE singleton = 1"
            )
        competitor.execute("ROLLBACK")

        # A fresh adjacent retry sees v0007 and fails for the explicit pending
        # authority reason rather than silently advancing past target version 1.
        with pytest.raises(sqlite3.IntegrityError, match="pending case index rebuild"):
            with transaction(competitor):
                competitor.execute(
                    "UPDATE knowledge_catalog_state SET catalog_version = 1 "
                    "WHERE singleton = 1"
                )
        assert harness.connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (0,)
    finally:
        if competitor.in_transaction:
            competitor.execute("ROLLBACK")
        competitor.close()
        harness.connection.close()


def test_v0007_upgrade_preserves_and_guards_existing_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migrations = load_migrations("global")
    assert tuple(migration.version for migration in migrations[6:]) == (7, 8, 9)

    class V0006MigrationRunner:
        @staticmethod
        def for_scope(connection: sqlite3.Connection, scope: str) -> MigrationRunner:
            assert scope == "global"
            return MigrationRunner(connection, migrations[:6])

    # Construct a real v0006 database.  Rewriting only the v0007 history row
    # on a latest-schema fixture leaves v0008/v0009 behind and is not a valid prefix.
    with monkeypatch.context() as fixture_patch:
        fixture_patch.setattr(
            knowledge_integration_support,
            "MigrationRunner",
            V0006MigrationRunner,
        )
        harness = build_global_knowledge_harness(tmp_path)
    bundle, _ = _fixture(counter_start=120_000)
    publication = _publish_case_index(
        harness,
        _seed_verified_shared_case(harness, bundle),
    )

    MigrationRunner.for_scope(harness.connection, "global").apply()

    assert harness.connection.execute(
        "SELECT state FROM case_patterns WHERE manifest_id = ?",
        (publication.manifest_ref.object_id,),
    ).fetchone() == ("PREPARED",)
    assert harness.connection.execute(
        "SELECT state FROM rebuild_queue WHERE queue_id = ?",
        (publication.rebuild_queue_id,),
    ).fetchone() == ("PENDING",)
    assert harness.connection.execute(
        "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
    ).fetchone() == (0,)
    with pytest.raises(sqlite3.IntegrityError, match="pending case index rebuild"):
        harness.connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1"
        )
    harness.connection.close()
