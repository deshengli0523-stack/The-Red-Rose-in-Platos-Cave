from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.lint import KnowledgeLinter
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _insert_claim(
    connection: sqlite3.Connection,
    *,
    claim_id: str,
    grade: str = "C2",
    empirical: str = "unassessed",
    cognitive: str = "paraphrase",
    theory_id: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO claims(
            claim_id, version, claim_object_ref,
            claim_object_size_bytes, claim_object_media_type, claim_sha256,
            cognitive_type, source_grade, framework_eligibility,
            empirical_support, model_confidence, review_status,
            effective_from, effective_to, review_due_at,
            applicability_json, privacy_scope, allowed_uses_json,
            provenance_json, theory_revision_id, theory_revision,
            theory_revision_sha256, created_at
        ) VALUES (?, 1, ?, 0, 'text/plain', ?, ?, ?, 'CONDITIONAL', ?,
                  NULL, 'APPROVED', ?, NULL, NULL, '{}', 'GLOBAL',
                  '["consultation"]', ?, ?, ?, ?, ?)
        """,
        (
            claim_id,
            "sha256:" + "1" * 64,
            "1" * 64,
            cognitive,
            grade,
            empirical,
            "2026-07-18T08:00:00.000000Z",
            json.dumps({"case_ids": []}),
            theory_id,
            1 if theory_id is not None else None,
            "7" * 64 if theory_id is not None else None,
            "2026-07-18T08:00:00.000000Z",
        ),
    )


def test_linter_reports_critical_catalog_and_manifest_failures(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    counter = iter(range(1, 1000))
    ids = IdFactory(FixedClock(NOW), lambda: next(counter))
    unsourced = ids.object_id("claim")
    invalid_c1 = ids.object_id("claim")
    absent_theory = ids.object_id("theory")
    source = ids.object_id("source")
    connection.execute(
        """
        INSERT INTO sources(
            source_id, logical_path, logical_path_key, document_type,
            current_version, created_at
        ) VALUES (?, 'consultant-theory/lint.md',
                  'consultant-theory/lint.md', 'md', 1, ?)
        """,
        (source, "2026-07-18T08:00:00.000000Z"),
    )
    connection.execute(
        """
        INSERT INTO source_versions(
            source_id, version, content_sha256, content_object_ref, size_bytes,
            license, domain, language, sensitivity, source_grade, status,
            imported_at, metadata_json, metadata_sha256
        ) VALUES (?, 1, ?, ?, 0, 'synthetic', 'lint', 'zh-CN', 'internal',
                  'C1', 'DRAFT', ?, '{}', ?)
        """,
        (
            source,
            "5" * 64,
            "sha256:" + "5" * 64,
            "2026-07-18T08:00:00.000000Z",
            "8" * 64,
        ),
    )
    connection.execute(
        """
        INSERT INTO theory_revisions(
            theory_id, revision, source_id, source_version, document_sha256,
            revision_sha256, revision_object_ref, revision_object_size_bytes,
            revision_object_media_type, author, declared_version, source_grade,
            empirical_support, status, approval_request_id, approved_at,
            effective_from, effective_to, applicability_json, core_claims_json,
            methods_json, contraindications_json, counterexamples_json,
            citations_json, scope_policy_ref_json, supersedes_revision,
            revokes_revision, created_at
        ) VALUES (?, 1, ?, 1, ?, ?, ?, 0, 'application/json', 'synthetic', '1.0',
                  'C1', 'unassessed', 'DRAFT', NULL, NULL, ?, NULL, '{}',
                  '["claim"]', '["method"]', '["contra"]', '["counter"]',
                  '[]', '{}', NULL, NULL, ?)
        """,
        (
            absent_theory,
            source,
            "5" * 64,
            "7" * 64,
            "sha256:" + "6" * 64,
            "2026-07-18T08:00:00.000000Z",
            "2026-07-18T08:00:00.000000Z",
        ),
    )
    _insert_claim(connection, claim_id=unsourced)
    _insert_claim(
        connection,
        claim_id=invalid_c1,
        grade="C1",
        empirical="highest",
        theory_id=absent_theory,
    )

    first = ids.object_id("claim")
    second = ids.object_id("claim")
    rule = VersionRef(
        object_id=ids.object_id("policy"), version=1, content_sha256="2" * 64
    )
    for source, target in ((first, second), (second, first)):
        connection.execute(
            """
            INSERT INTO provenance_edges(
                from_type, from_id, from_version, relation,
                to_type, to_id, to_version, derivation_rule_ref_json,
                source_client_ids_json, source_case_ids_json
            ) VALUES ('claim', ?, 1, 'DERIVED_FROM', 'claim', ?, 1, ?, '[]', '[]')
            """,
            (source, target, rule.model_dump_json()),
        )

    artifact = ids.object_id("artifact")
    connection.execute(
        """
        INSERT INTO artifact_versions(
            artifact_id, version, artifact_kind, source_catalog_version,
            metadata_sha256, manifest_id, state, created_at
        ) VALUES (?, 1, 'vector', 1, ?, NULL, 'CURRENT', ?)
        """,
        (artifact, "3" * 64, "2026-07-18T08:00:00.000000Z"),
    )
    connection.execute(
        "UPDATE knowledge_catalog_state SET catalog_version = 2 WHERE singleton = 1"
    )

    report = KnowledgeLinter(connection, now=NOW).run(catalog_version=2)
    rules = {item.rule for item in report.findings}
    assert {
        "unsourced_claim",
        "invalid_c1_authority",
        "c1_empirical_conflation",
        "cyclic_evidence",
        "artifact_metadata_mismatch",
    } <= rules
    assert report.has_errors
    assert all("synthetic" not in item.summary for item in report.findings)
    connection.close()


def test_linter_warns_for_orphan_wiki_and_unexplained_conflict(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    ids = IdFactory(FixedClock(NOW), lambda: 5)
    claim = ids.object_id("claim")
    _insert_claim(connection, claim_id=claim, empirical="conflicting")
    wiki = ids.object_id("wiki")
    connection.execute(
        """
        INSERT INTO wiki_revisions(
            wiki_id, revision, slug, title, body_object_ref,
            body_object_size_bytes, body_object_media_type, body_sha256,
            base_revision, diff_kind, diff_object_ref,
            diff_object_size_bytes, diff_object_media_type, diff_sha256, review_status,
            review_due_at, approval_request_id, created_at
        ) VALUES (?, 1, 'orphan', 'orphan', ?, 0, 'application/json', ?, 0,
                  'ADD', ?, 0, 'application/json', ?, 'PREPARED', NULL, ?, ?)
        """,
        (
            wiki,
            "sha256:" + "4" * 64,
            "4" * 64,
            "sha256:" + "5" * 64,
            "5" * 64,
            ids.object_id("approval_request"),
            "2026-07-18T08:00:00.000000Z",
        ),
    )
    report = KnowledgeLinter(connection, now=NOW).run(catalog_version=0)
    by_rule = {item.rule: item.severity for item in report.findings}
    assert by_rule["orphan_wiki_page"] == "warning"
    assert by_rule["unexplained_conflict"] == "warning"
    connection.close()
