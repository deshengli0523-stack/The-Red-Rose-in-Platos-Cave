from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from consultation_kb import cli
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.integration.test_case_01_full_lineage import (
    _fixture as _case_index_fixture,
)
from tests.consultation_kb.integration.test_case_index_publication_authority import (
    _seed_verified_shared_case,
)
from tests.consultation_kb.integration.test_sqlite_recovery import (
    _artifacts,
    _prepare,
)
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
)


def test_cli_scans_live_wal_and_applies_only_the_exact_global_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = (tmp_path / "vault").resolve()
    database = vault / "global" / "catalog.sqlite3"
    database.parent.mkdir(parents=True)
    connection = connect_database(database, "writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1"
        )
        _prepare(
            connection,
            database.parent,
            operation_suffix=950,
            version=1,
            expected_epoch=None,
            artifacts=_artifacts(
                version=1,
                suffix_base=950,
                kinds=("wiki_page",),
            ),
            purpose="wiki_publish",
        )
    finally:
        connection.close()
    monkeypatch.setattr(
        cli,
        "_resolved_config",
        lambda _args: SimpleNamespace(vault_root=vault),
    )

    # Live WAL/SHM files are ordinary production state, not a scan blocker.
    assert cli.main(("recovery-report", "--json")) == 0
    first_scan = json.loads(capsys.readouterr().out)
    reference = first_scan["database_ref_sha256"]
    assert first_scan["recovery"]["mutating_decision_count"] == 1
    assert first_scan["startup_health"] == "HEALTHY"

    assert cli.main(("recover", "--apply", "--json")) == 2
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "code": "LIFECYCLE_APPROVAL_REQUIRED",
    }
    assert cli.main(
        (
            "recover",
            "--apply",
            "--database-ref-sha256",
            "0" * 64,
            "--json",
        )
    ) == 2
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "code": "LIFECYCLE_SCOPE_UNAVAILABLE",
    }

    assert cli.main(
        (
            "recover",
            "--apply",
            "--database-ref-sha256",
            reference,
            "--json",
        )
    ) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["mode"] == "apply"
    assert applied["applied_count"] == 1
    assert applied["publication_operations"] == {"ACTIVE": 1}

    assert cli.main(
        (
            "recover",
            "--apply",
            "--database-ref-sha256",
            reference,
            "--json",
        )
    ) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["applied_count"] == 0


def test_cli_treats_a_stable_verified_case_ledger_as_healthy_keep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = (tmp_path / "vault").resolve()
    database = vault / "global" / "catalog.sqlite3"
    harness = build_global_knowledge_harness(
        tmp_path,
        root=database.parent,
        database_name=database.name,
    )
    # Match the production global content root used by CLI and MCP lifespan.
    harness.store = ContentStore(database.parent)
    try:
        original, _contributor = _case_index_fixture()
        _seed_verified_shared_case(harness, original)
    finally:
        harness.connection.close()
    monkeypatch.setattr(
        cli,
        "_resolved_config",
        lambda _args: SimpleNamespace(vault_root=vault),
    )

    assert cli.main(("recovery-report", "--json")) == 0
    report = json.loads(capsys.readouterr().out)
    reference = report["database_ref_sha256"]
    assert report["startup_health"] == "HEALTHY"
    assert report["query_ready"] is True
    assert report["recovery"]["mutating_decision_count"] == 0
    assert report["recovery"]["actions"] == {"KEEP": 1}
    assert report["publication_operations"] == {"VERIFIED": 1}

    assert cli.main(
        (
            "recover",
            "--apply",
            "--database-ref-sha256",
            reference,
            "--json",
        )
    ) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["applied_count"] == 0
    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state FROM publication_operations"
        ).fetchone() == ("VERIFIED",)
        assert reader.execute(
            "SELECT state FROM global_publish_sagas"
        ).fetchone() == ("ACTIVE",)
        assert reader.execute("SELECT COUNT(*) FROM runtime_epochs").fetchone() == (
            0,
        )
    finally:
        reader.close()
