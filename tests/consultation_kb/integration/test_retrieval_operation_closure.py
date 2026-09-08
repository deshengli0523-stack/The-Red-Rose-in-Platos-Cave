from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.operations.doctor_probes import RetrievalArtifactDiagnosticProbe
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
)
from consultation_kb.retrieval.evidence_pack import ArtifactVersionMismatch
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)


pytestmark = pytest.mark.integration


def _backup_database(source: sqlite3.Connection, target: Path) -> None:
    with sqlite3.connect(target) as destination:
        source.backup(destination)


def _doctor_config(tmp_path: Path, *, source_root: Path) -> tuple[AppConfig, Path]:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / ".git").mkdir()
    vault_root = tmp_path / "doctor-vault"
    global_root = vault_root / "global"
    shutil.copytree(source_root, global_root)
    return AppConfig.from_values(repo_root, vault_root), global_root / "catalog.sqlite3"


def test_active_operation_closure_tampering_invalidates_discovery_binding_and_doctor(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        discovery = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        )
        active = discovery.discover_current_set()
        assert active is not None

        operation_row = harness.connection.execute(
            "SELECT required_manifests_json, required_manifest_count, "
            "verified_manifest_count FROM publication_operations "
            "WHERE operation_id = ?",
            (publication.operation_id,),
        ).fetchone()
        assert operation_row is not None
        original_json = str(operation_row[0])
        original_required = int(operation_row[1])
        original_verified = int(operation_row[2])
        required_ids = json.loads(original_json)
        assert type(required_ids) is list
        assert len(required_ids) >= 2
        duplicate_ids = sorted([*required_ids[:-1], required_ids[-2]])
        substituted_ids = list(required_ids)
        last_id = str(substituted_ids[-1])
        substituted_ids[-1] = last_id[:-1] + (
            "0" if last_id[-1] != "0" else "1"
        )
        substituted_ids.sort()
        config, doctor_database = _doctor_config(
            tmp_path,
            source_root=harness.root / "global-content",
        )

        mutations: tuple[tuple[str, object], ...] = (
            ("required_manifests_json", f" {original_json}"),
            (
                "required_manifests_json",
                json.dumps(duplicate_ids, separators=(",", ":")),
            ),
            (
                "required_manifests_json",
                json.dumps(substituted_ids, separators=(",", ":")),
            ),
            ("required_manifest_count", original_required + 1),
            ("verified_manifest_count", original_verified - 1),
        )
        for column, value in mutations:
            harness.connection.execute(
                f"UPDATE publication_operations SET {column} = ? "
                "WHERE operation_id = ?",
                (value, publication.operation_id),
            )
            harness.connection.commit()

            with pytest.raises(
                ArtifactVersionMismatch,
                match="ARTIFACT_VERSION_MISMATCH",
            ):
                discovery.discover_current_set()
            with pytest.raises(
                ArtifactVersionMismatch,
                match="ARTIFACT_VERSION_MISMATCH",
            ):
                active.lexical.verify_current()

            _backup_database(harness.connection, doctor_database)
            doctor = RetrievalArtifactDiagnosticProbe().run(config)
            assert doctor.status == "fail"
            assert doctor.code == "retrieval_artifacts_invalid"

            harness.connection.execute(
                "UPDATE publication_operations SET "
                "required_manifests_json = ?, required_manifest_count = ?, "
                "verified_manifest_count = ? WHERE operation_id = ?",
                (
                    original_json,
                    original_required,
                    original_verified,
                    publication.operation_id,
                ),
            )
            harness.connection.commit()
            active.lexical.verify_current()
            assert discovery.discover_current_set() is not None
    finally:
        harness.close()
