from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.retrieval.authority_snapshot import AuthoritativeSnapshotRepository
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.retrieval.filters import AuthoritySnapshotStale, CandidateFilter
from consultation_kb.retrieval.resolver import EvidenceResolutionDenied, EvidenceResolver
from consultation_kb.storage.tombstones import target_hash
from tests.consultation_kb.retrieval_db_support import (
    activate_epoch,
    add_active_candidate,
    migrate_database,
)
from tests.consultation_kb.retrieval_support import (
    NOW,
    candidate,
    private_provenance,
    reference,
    scope,
)


def _seed_authority_databases(
    root: Path,
) -> tuple[Path, Path, CandidateRef, CandidateRef]:
    global_path = root / "global.sqlite3"
    client_path = root / "client.sqlite3"
    migrate_database(global_path, "global")
    migrate_database(client_path, "client")
    global_candidate = candidate(31, text="global", object_type="claim")
    global_candidate = global_candidate.model_copy(
        update={
            "metadata": global_candidate.metadata.model_copy(
                update={
                    "manifest_ref": global_candidate.metadata.manifest_ref.model_copy(
                        update={"version": 3}
                    ),
                    "source_lineage_hashes": ("d" * 64,),
                }
            )
        }
    )
    private_candidate = candidate(
        32,
        text="private",
        provenance=private_provenance(32),
        channel="profile",
        object_type="profile_json",
        allowed_uses=frozenset({"answer_support", "continuity"}),
    )
    private_candidate = private_candidate.model_copy(
        update={
            "metadata": private_candidate.metadata.model_copy(
                update={
                    "manifest_ref": private_candidate.metadata.manifest_ref.model_copy(
                        update={"version": 4}
                    )
                }
            )
        }
    )
    global_connection = sqlite3.connect(global_path)
    client_connection = sqlite3.connect(client_path)
    try:
        global_connection.execute("PRAGMA foreign_keys = ON")
        client_connection.execute("PRAGMA foreign_keys = ON")
        global_operation = activate_epoch(
            global_connection,
            epoch=3,
            index=3001,
            required_manifest_count=1,
        )
        global_connection.execute(
            "INSERT INTO claims("
            "claim_id, version, claim_object_ref, claim_object_size_bytes, "
            "claim_object_media_type, claim_sha256, cognitive_type, source_grade, "
            "framework_eligibility, empirical_support, model_confidence, "
            "review_status, effective_from, effective_to, review_due_at, "
            "applicability_json, privacy_scope, allowed_uses_json, "
            "provenance_json, theory_revision_id, theory_revision, "
            "theory_revision_sha256, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 'explicit', 'T1', 'ELIGIBLE', "
            "'empirically_supported', NULL, 'APPROVED', NULL, NULL, NULL, "
            "'{}', 'GLOBAL', '[\"answer_support\"]', '{}', NULL, NULL, NULL, ?)",
            (
                global_candidate.reference.object_id,
                global_candidate.reference.version,
                f"sha256:{global_candidate.reference.content_sha256}",
                global_candidate.metadata.size_bytes,
                global_candidate.metadata.media_type,
                global_candidate.reference.content_sha256,
                NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
        )
        add_active_candidate(
            global_connection,
            epoch=3,
            operation_id=global_operation,
            artifact_key="claims",
            artifact_kind="claims",
            candidate=global_candidate,
        )
        client_operation = activate_epoch(
            client_connection,
            epoch=4,
            index=3002,
            required_manifest_count=1,
        )
        add_active_candidate(
            client_connection,
            epoch=4,
            operation_id=client_operation,
            artifact_key="client_profile",
            artifact_kind="profile",
            candidate=private_candidate,
        )
        global_connection.commit()
        client_connection.commit()
    finally:
        global_connection.close()
        client_connection.close()
    return global_path, client_path, global_candidate, private_candidate


def test_freeze_joins_live_global_and_client_authority_without_bodies(
    tmp_path: Path,
) -> None:
    global_path, client_path, global_candidate, private_candidate = (
        _seed_authority_databases(tmp_path)
    )
    policy_ref = reference("authority_policy", 801)
    with AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: policy_ref,
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: 99),
    ) as repository:
        frozen = repository.freeze(scope())
        decision = CandidateFilter(repository).filter(
            scope(),
            (global_candidate, private_candidate),
            frozen,
        )

        assert frozen.global_runtime_epoch == 3
        assert frozen.client_runtime_epoch == 4
        assert frozen.allowed_ref_ids == frozenset(
            {
                global_candidate.reference.object_id,
                private_candidate.reference.object_id,
            }
        )
        assert frozen.policy_ref == policy_ref
        assert "body" not in frozen.model_dump_json()
        assert '"global"' not in frozen.model_dump_json()
        assert '"private"' not in frozen.model_dump_json()
        assert len(decision.allowed) == 2
        binding = decision.allowed[0].filter_binding
        assert binding is not None
        repository.assert_binding_current(binding)


def test_epoch_policy_or_allowed_set_change_invalidates_whole_snapshot(
    tmp_path: Path,
) -> None:
    global_path, client_path, global_candidate, _private_candidate = (
        _seed_authority_databases(tmp_path)
    )
    current_policy = [reference("authority_policy", 811)]
    with AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: current_policy[0],
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: 100),
    ) as repository:
        frozen = repository.freeze(scope())
        decision = CandidateFilter(repository).filter(
            scope(),
            (global_candidate,),
            frozen,
        )
        binding = decision.allowed[0].filter_binding
        assert binding is not None

        current_policy[0] = reference("authority_policy", 812)
        with pytest.raises(AuthoritySnapshotStale, match="AUTHORITY_SNAPSHOT_STALE"):
            repository.assert_snapshot_current(frozen)
        with pytest.raises(AuthoritySnapshotStale, match="AUTHORITY_SNAPSHOT_STALE"):
            repository.assert_binding_current(binding)
        requested: list[str] = []

        class _Reader:
            def read_verified(self, value: CandidateRef) -> bytes:
                requested.append(value.reference.object_id)
                return b"global"

        with pytest.raises(
            EvidenceResolutionDenied,
            match="EVIDENCE_RESOLUTION_DENIED",
        ):
            EvidenceResolver(repository, _Reader()).resolve_many(decision.allowed)
        assert requested == []


def test_exact_hash_and_live_tombstone_are_authoritative(tmp_path: Path) -> None:
    global_path, client_path, global_candidate, _private_candidate = (
        _seed_authority_databases(tmp_path)
    )
    with AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: reference("authority_policy", 821),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: 101),
    ) as repository:
        frozen = repository.freeze(scope())
        wrong_hash = global_candidate.model_copy(
            update={
                "reference": global_candidate.reference.model_copy(
                    update={"content_sha256": "f" * 64}
                )
            }
        )
        assert repository.candidate_status(wrong_hash, frozen) == "unauthorized"

        writer = sqlite3.connect(global_path)
        try:
            writer.execute(
                "INSERT INTO tombstones("
                "tombstone_id, target_type, target_id_hash, source_lineage_hash, "
                "reason_code, created_at"
                ") VALUES (?, ?, ?, '', ?, ?)",
                (
                    reference("tombstone", 1).object_id,
                    global_candidate.object_type,
                    target_hash(
                        global_candidate.object_type,
                        global_candidate.reference.object_id,
                    ),
                    "revoked",
                    NOW.isoformat().replace("+00:00", "Z"),
                ),
            )
            writer.commit()
        finally:
            writer.close()

        assert repository.candidate_status(global_candidate, frozen) == "tombstoned"
        refreshed = repository.freeze(scope())
        assert global_candidate.reference.object_id not in refreshed.allowed_ref_ids


def test_lineage_tombstone_is_removed_before_channel_ranking(tmp_path: Path) -> None:
    global_path, client_path, global_candidate, _private_candidate = (
        _seed_authority_databases(tmp_path)
    )
    with AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: reference("authority_policy", 831),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: 102),
    ) as repository:
        before = repository.freeze(scope())
        assert global_candidate.reference.object_id in before.allowed_ref_ids
        writer = sqlite3.connect(global_path)
        try:
            writer.execute(
                "INSERT INTO tombstones("
                "tombstone_id, target_type, target_id_hash, source_lineage_hash, "
                "reason_code, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    reference("tombstone", 2).object_id,
                    "source",
                    target_hash("source", reference("source", 999).object_id),
                    "d" * 64,
                    "lineage_revoked",
                    NOW.isoformat().replace("+00:00", "Z"),
                ),
            )
            writer.commit()
        finally:
            writer.close()

        after = repository.freeze(scope())
        assert global_candidate.reference.object_id not in after.allowed_ref_ids
        assert repository.candidate_status(global_candidate, before) == "tombstoned"
