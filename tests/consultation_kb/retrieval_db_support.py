from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Literal

from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.retrieval_support import NOW, object_id


def migrate_database(path: Path, scope: Literal["global", "client"]) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        MigrationRunner.for_scope(connection, scope).apply()
    finally:
        connection.close()


def activate_epoch(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    index: int,
    required_manifest_count: int,
) -> str:
    operation_id = object_id("publication_operation", index)
    timestamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT INTO publication_operations("
        "operation_id, purpose, authority_base_version, approval_request_id, "
        "descriptor_sha256, state, required_manifests_json, "
        "required_manifest_count, verified_manifest_count, "
        "expected_current_epoch, runtime_epoch, created_at, activated_at"
        ") VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, NULL, ?, ?, ?)",
        (
            operation_id,
            "retrieval_test",
            epoch,
            f"approval-{index}",
            f"{index + 1:064x}",
            json.dumps([f"artifact-{item}" for item in range(required_manifest_count)]),
            required_manifest_count,
            required_manifest_count,
            epoch,
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO runtime_epochs("
        "epoch, operation_id, state, created_at, activated_at"
        ") VALUES (?, ?, 'ACTIVE', ?, ?)",
        (epoch, operation_id, timestamp, timestamp),
    )
    return operation_id


def add_active_candidate(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    operation_id: str,
    artifact_key: str,
    artifact_kind: str,
    candidate: CandidateRef,
    ordinal: int = 0,
) -> None:
    timestamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    manifest = candidate.metadata.manifest_ref
    connection.execute(
        "INSERT INTO artifact_manifests("
        "manifest_id, operation_id, artifact_key, artifact_kind, "
        "source_version, manifest_sha256, state, verified, created_at, verified_at"
        ") VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?)",
        (
            manifest.object_id,
            operation_id,
            artifact_key,
            artifact_kind,
            str(manifest.version),
            manifest.content_sha256,
            timestamp,
            timestamp,
        ),
    )
    add_manifest_candidate(
        connection,
        manifest_id=manifest.object_id,
        candidate=candidate,
        ordinal=ordinal,
    )
    connection.execute(
        "INSERT INTO active_artifacts(epoch, artifact_key, manifest_id, activated_at) "
        "VALUES (?, ?, ?, ?)",
        (epoch, artifact_key, manifest.object_id, timestamp),
    )


def add_manifest_candidate(
    connection: sqlite3.Connection,
    *,
    manifest_id: str,
    candidate: CandidateRef,
    ordinal: int,
) -> None:
    manifest_row = connection.execute(
        "SELECT source_version FROM artifact_manifests WHERE manifest_id = ?",
        (manifest_id,),
    ).fetchone()
    if manifest_row is None:
        raise AssertionError("manifest must exist before adding a test member")
    connection.execute(
        "INSERT INTO artifact_members("
        "manifest_id, ordinal, object_type, object_id, object_sha256, "
        "source_version, source_lineage_json, media_type, size_bytes"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            manifest_id,
            ordinal,
            candidate.object_type,
            candidate.reference.object_id,
            candidate.reference.content_sha256,
            str(manifest_row[0]),
            json.dumps(
                list(candidate.metadata.source_lineage_hashes),
                separators=(",", ":"),
            ),
            candidate.metadata.media_type,
            candidate.metadata.size_bytes,
        ),
    )


def add_approved_global_claim_passage(
    connection: sqlite3.Connection,
    *,
    candidate: CandidateRef,
) -> None:
    """Seed the exact governed Claim -> SUPPORTS -> Passage closure used by P4."""

    if candidate.object_type != "claim":
        raise AssertionError("global governed evidence must be a Claim candidate")
    if candidate.content_ref == candidate.reference:
        raise AssertionError("Claim evidence must resolve through a distinct Passage")
    if candidate.content_ref not in candidate.location.anchor_refs:
        raise AssertionError("Passage must be an exact candidate locator anchor")
    if candidate.content_ref.object_id not in candidate.provenance.passage_ids:
        raise AssertionError("Passage must be present in candidate provenance")
    source_ids = tuple(candidate.provenance.source_ids)
    if len(source_ids) != 1:
        raise AssertionError("test Claim candidates require exactly one Source")

    source_id = source_ids[0]
    source_bytes = f"source:{source_id}".encode("utf-8")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    metadata_sha256 = hashlib.sha256(b"{}").hexdigest()
    timestamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT INTO sources(source_id, logical_path, logical_path_key, "
        "document_type, current_version, created_at) VALUES (?, ?, ?, 'text', 1, ?)",
        (source_id, f"source/{source_id}.txt", f"source/{source_id}.txt", timestamp),
    )
    connection.execute(
        "INSERT INTO source_versions("
        "source_id, version, content_sha256, content_object_ref, size_bytes, "
        "license, domain, language, sensitivity, source_grade, status, "
        "imported_at, metadata_json, metadata_sha256"
        ") VALUES (?, 1, ?, ?, ?, 'test', 'consultation', 'zh', 'public', "
        "'T1', 'APPROVED', ?, '{}', ?)",
        (
            source_id,
            source_sha256,
            f"sha256:{source_sha256}",
            len(source_bytes),
            timestamp,
            metadata_sha256,
        ),
    )
    passage = candidate.content_ref
    connection.execute(
        "INSERT INTO passages("
        "passage_id, version, source_id, source_version, document_type, "
        "structural_path, locator_json, normalized_text_sha256, raw_content_ref, "
        "retrieval_content_ref, context_before_ref, context_after_ref, "
        "extractor_version, privacy_scope, provenance_json, review_status, created_at"
        ") VALUES (?, ?, ?, 1, 'text', 'section/1', '{}', ?, ?, ?, NULL, NULL, "
        "'test-v1', 'GLOBAL', '{}', 'APPROVED', ?)",
        (
            passage.object_id,
            passage.version,
            source_id,
            passage.content_sha256,
            f"sha256:{passage.content_sha256}",
            f"sha256:{passage.content_sha256}",
            timestamp,
        ),
    )
    claim = candidate.reference
    connection.execute(
        "INSERT INTO claims("
        "claim_id, version, claim_object_ref, claim_object_size_bytes, "
        "claim_object_media_type, claim_sha256, cognitive_type, source_grade, "
        "framework_eligibility, empirical_support, model_confidence, "
        "review_status, effective_from, effective_to, review_due_at, "
        "applicability_json, privacy_scope, allowed_uses_json, provenance_json, "
        "theory_revision_id, theory_revision, theory_revision_sha256, created_at"
        ") VALUES (?, ?, ?, ?, 'application/json', ?, 'explicit', 'T1', "
        "'ELIGIBLE', 'empirically_supported', NULL, 'APPROVED', NULL, NULL, "
        "NULL, '{}', 'GLOBAL', '[\"answer_support\"]', '{}', NULL, NULL, NULL, ?)",
        (
            claim.object_id,
            claim.version,
            f"sha256:{claim.content_sha256}",
            candidate.metadata.size_bytes,
            claim.content_sha256,
            timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO claim_evidence("
        "claim_id, claim_version, passage_id, passage_version, relation, "
        "evidence_role) VALUES (?, ?, ?, ?, 'SUPPORTS', 'PRIMARY')",
        (claim.object_id, claim.version, passage.object_id, passage.version),
    )
