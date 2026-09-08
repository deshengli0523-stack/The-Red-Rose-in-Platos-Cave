from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.lifecycle.publish import ArtifactDraft, ContentDraft
from consultation_kb.mcp import runtime as runtime_module
from consultation_kb.mcp.runtime import ProductionRuntime, RuntimeCompositionError
from consultation_kb.policy.loader import PolicyLoader, risk_rule_member_identities
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.integration.test_sqlite_recovery import (
    _activate,
    _artifacts,
    _prepare,
)
from tests.consultation_kb.unit.test_mcp_production_retrieval_integration import (
    _RetrievalSpy,
    _migrated_workspace,
)


def _fixture_object_id(kind: str, suffix: int) -> str:
    return f"{kind}_019f79d1-7d00-7000-8000-{suffix:012x}"


def _risk_policy_artifact(
    config: AppConfig,
    *,
    suffix: int,
) -> ArtifactDraft:
    loaded = PolicyLoader.from_config(config).load_all().risk_rules
    identities = risk_rule_member_identities(loaded)
    return ArtifactDraft(
        manifest_id=_fixture_object_id("risk_rule_policy_manifest", suffix),
        artifact_key="risk_rule_policy",
        artifact_kind="risk_rule_policy",
        source_version=loaded.policy_version,
        members=(
            ContentDraft(
                object_type="risk_policy",
                object_id=_fixture_object_id("risk_policy", suffix + 1),
                data=loaded.canonical_bytes,
                source_version=loaded.policy_version,
                media_type="application/vnd.consultation-kb.risk-policy+json",
                source_lineage=(),
            ),
            *(
                ContentDraft(
                    object_type="risk_rule",
                    object_id=_fixture_object_id(
                        "risk_rule",
                        suffix + 2 + identity.member_ordinal,
                    ),
                    data=identity.canonical_bytes,
                    source_version=identity.version,
                    media_type="application/vnd.consultation-kb.risk-rule+json",
                    source_lineage=(),
                )
                for identity in identities
            ),
        ),
    )


def _prepare_global_startup_operation(
    database: Path,
    content_root: Path,
    *,
    config: AppConfig,
    suffix: int,
) -> tuple[str, str, str]:
    connection = connect_database(database, "writer")
    try:
        connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = 1 "
            "WHERE singleton = 1"
        )
        operation_id, manifests = _prepare(
            connection,
            content_root,
            operation_suffix=suffix,
            version=1,
            expected_epoch=1,
            artifacts=(
                *_artifacts(
                    version=1,
                    suffix_base=suffix,
                    kinds=("wiki_page",),
                ),
                _risk_policy_artifact(config, suffix=suffix + 10_000),
            ),
            purpose="wiki_publish",
        )
        return operation_id, manifests[0], manifests[1]
    finally:
        connection.close()


def test_production_runtime_recovers_exact_prepared_global_operation_before_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, vault = _migrated_workspace(tmp_path)
    config = AppConfig.from_values(repo, vault)
    database = vault / "global" / "catalog.sqlite3"
    operation_id, _manifest_id, _risk_manifest_id = (
        _prepare_global_startup_operation(
            database,
            database.parent,
            config=config,
            suffix=970,
        )
    )
    retrieval = _RetrievalSpy()
    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        lambda **_kwargs: retrieval,
    )

    runtime = ProductionRuntime.open(config=config)
    try:
        reader = connect_database(database, "reader")
        try:
            assert reader.execute(
                "SELECT state, runtime_epoch FROM publication_operations "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone() == ("ACTIVE", 2)
            assert reader.execute(
                "SELECT COUNT(*) FROM recovery_decision_journal"
            ).fetchone() == (1,)
        finally:
            reader.close()
        assert retrieval.startup_verifications == 1
    finally:
        runtime.close()


def test_production_runtime_queues_rebuild_and_fails_before_retrieval_on_active_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, vault = _migrated_workspace(tmp_path)
    config = AppConfig.from_values(repo, vault)
    database = vault / "global" / "catalog.sqlite3"
    operation_id, manifest_id, _risk_manifest_id = (
        _prepare_global_startup_operation(
            database,
            database.parent,
            config=config,
            suffix=980,
        )
    )
    connection = connect_database(database, "writer")
    try:
        assert _activate(connection, database.parent, operation_id) == 2
        member = ManifestRepository(connection).get(manifest_id).members[0]
        reference = ContentStore(database.parent).reference(
            content_sha256=member.object_sha256,
            media_type=member.media_type,
            size_bytes=member.size_bytes,
        )
        reference.path.write_bytes(b"corrupt")
    finally:
        connection.close()
    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        lambda **_kwargs: pytest.fail("retrieval composed before recovery gate"),
    )

    with pytest.raises(
        RuntimeCompositionError,
        match="^RECOVERY_STARTUP_BLOCKED$",
    ):
        ProductionRuntime.open(config=config)

    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT state, runtime_epoch FROM publication_operations "
            "WHERE operation_id = ?",
            (operation_id,),
        ).fetchone() == ("ACTIVE", 2)
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_required_actions "
            "WHERE action_type = 'rebuild' AND state = 'PENDING'"
        ).fetchone() == (1,)
    finally:
        reader.close()


@pytest.mark.parametrize("damage", ("missing", "corrupt"))
def test_production_runtime_keeps_old_epoch_when_dedicated_risk_sibling_is_bad(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: Literal["missing", "corrupt"],
) -> None:
    repo, vault = _migrated_workspace(tmp_path)
    config = AppConfig.from_values(repo, vault)
    database = vault / "global" / "catalog.sqlite3"
    operation_id, _manifest_id, risk_manifest_id = (
        _prepare_global_startup_operation(
            database,
            database.parent,
            config=config,
            suffix=990 if damage == "missing" else 1_000,
        )
    )
    connection = connect_database(database, "writer")
    try:
        if damage == "missing":
            connection.execute(
                "DELETE FROM artifact_members WHERE manifest_id = ?",
                (risk_manifest_id,),
            )
            connection.execute(
                "DELETE FROM artifact_manifests WHERE manifest_id = ?",
                (risk_manifest_id,),
            )
        else:
            connection.execute(
                "UPDATE artifact_members SET object_sha256 = ? "
                "WHERE manifest_id = ? AND ordinal = 0",
                ("0" * 64, risk_manifest_id),
            )
    finally:
        connection.close()
    retrieval = _RetrievalSpy()
    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        (
            (lambda **_kwargs: pytest.fail("retrieval composed before recovery gate"))
            if damage == "missing"
            else (lambda **_kwargs: retrieval)
        ),
    )

    if damage == "missing":
        with pytest.raises(
            RuntimeCompositionError,
            match="^RECOVERY_APPLY_FAILED$",
        ):
            ProductionRuntime.open(config=config)
    else:
        runtime = ProductionRuntime.open(config=config)
        runtime.close()
        assert retrieval.startup_verifications == 1

    reader = connect_database(database, "reader")
    try:
        assert reader.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == [(1, "ACTIVE")]
        assert reader.execute(
            "SELECT state, runtime_epoch FROM publication_operations "
            "WHERE operation_id = ?",
            (operation_id,),
        ).fetchone() == (
            ("PREPARED", None) if damage == "missing" else ("FAILED", None)
        )
        assert reader.execute(
            "SELECT COUNT(*) FROM recovery_decision_journal"
        ).fetchone() == ((0,) if damage == "missing" else (1,))
    finally:
        reader.close()
