from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from consultation_kb.core.config import AppConfig
from consultation_kb.models.common import VersionRef
from consultation_kb.policy.loader import (
    LoadedPolicy,
    PolicyLoader,
    RiskRulesPolicy,
    risk_rule_member_identities,
)
from consultation_kb.risk.rules import (
    PersistentRiskRuleCatalogResolver,
    RiskRuleCatalog,
    RiskRulePolicyBinding,
)
from consultation_kb.risk.repository import RiskEvaluationAuthorityBinding
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.storage.migrate import MigrationRunner


UTC_TEXT = "2026-07-19T08:00:00Z"


def _object_id(kind: str, suffix: int) -> str:
    return f"{kind}_018f0000-0000-7000-8000-{suffix:012x}"


def deterministic_risk_authority(
    *,
    epoch: int = 1,
    suffix: int = 900_000,
) -> RiskEvaluationAuthorityBinding:
    return RiskEvaluationAuthorityBinding(
        global_runtime_epoch=epoch,
        risk_policy_manifest_ref=VersionRef(
            object_id=_object_id("risk_policy_manifest", suffix),
            version=1,
            content_sha256=f"{suffix % 16:x}" * 64,
        ),
        model_mode="deterministic_only",
    )


def _manifest_members(
    loaded: LoadedPolicy[RiskRulesPolicy],
    *,
    suffix: int,
) -> tuple[ManifestMember, ...]:
    identities = risk_rule_member_identities(loaded)
    return (
        ManifestMember(
            ordinal=0,
            object_type="risk_policy",
            object_id=_object_id("risk_policy", suffix),
            object_sha256=loaded.content_sha256,
            source_version=loaded.policy_version,
            media_type="application/vnd.consultation-kb.risk-policy+json",
            size_bytes=len(loaded.canonical_bytes),
            source_lineage_hashes=(),
        ),
        *(
            ManifestMember(
                ordinal=identity.member_ordinal + 1,
                object_type="risk_rule",
                object_id=_object_id(
                    "risk_rule", suffix + identity.member_ordinal + 1
                ),
                object_sha256=identity.content_sha256,
                source_version=identity.version,
                media_type="application/vnd.consultation-kb.risk-rule+json",
                size_bytes=len(identity.canonical_bytes),
                source_lineage_hashes=(),
            )
            for identity in identities
        ),
    )


def insert_approved_risk_policy_epoch(
    connection: sqlite3.Connection,
    loaded: LoadedPolicy[RiskRulesPolicy],
    *,
    epoch: int,
    suffix: int,
    retire_current: bool = False,
    approved_model_ref: VersionRef | None = None,
) -> RiskRulePolicyBinding:
    if retire_current:
        connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
        )
    operation_id = _object_id("risk_rule_publication", suffix + 100)
    approval_id = _object_id("approval_request", suffix + 200)
    manifest_id = _object_id("risk_rule_policy_manifest", suffix + 300)
    members = _manifest_members(loaded, suffix=suffix + 400)
    digest = manifest_sha256(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key="risk_rule_policy",
        artifact_kind="risk_rule_policy",
        source_version=loaded.policy_version,
        members=members,
    )
    model_manifest_id = _object_id("risk_model_manifest", suffix + 301)
    model_members = (
        ()
        if approved_model_ref is None
        else (
            ManifestMember(
                ordinal=0,
                object_type="risk_model",
                object_id=approved_model_ref.object_id,
                object_sha256=approved_model_ref.content_sha256,
                source_version=approved_model_ref.version,
                media_type=(
                    "application/vnd.consultation-kb."
                    "risk-model-descriptor+json"
                ),
                size_bytes=1,
                source_lineage_hashes=(),
            ),
        )
    )
    model_digest = (
        None
        if approved_model_ref is None
        else manifest_sha256(
            manifest_id=model_manifest_id,
            operation_id=operation_id,
            artifact_key="risk_model_descriptor",
            artifact_kind="risk_model_descriptor",
            source_version=approved_model_ref.version,
            members=model_members,
        )
    )
    descriptor_sha256 = f"{(suffix + 1) % 16:x}" * 64
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES (?, ?, ?, ?, 0, ?, ?, 'CLAIMED', NULL, NULL)
        """,
        (
            operation_id,
            approval_id,
            descriptor_sha256,
            f"{(suffix + 2) % 16:x}" * 64,
            f"{(suffix + 3) % 16:x}" * 64,
            f"{(suffix + 4) % 16:x}" * 64,
        ),
    )
    connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = ?, applied_at = ? WHERE operation_id = ?",
        (epoch, UTC_TEXT, operation_id),
    )
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version,
            approval_request_id, descriptor_sha256, state,
            required_manifests_json, required_manifest_count,
            verified_manifest_count, expected_current_epoch,
            runtime_epoch, created_at, activated_at
        ) VALUES (?, 'risk_rule_policy_publication', 1, ?, ?, 'ACTIVE',
                  ?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            operation_id,
            approval_id,
            descriptor_sha256,
            json.dumps(
                [manifest_id]
                + ([] if approved_model_ref is None else [model_manifest_id]),
                separators=(",", ":"),
            ),
            1 if approved_model_ref is None else 2,
            1 if approved_model_ref is None else 2,
            epoch,
            UTC_TEXT,
            UTC_TEXT,
        ),
    )
    connection.execute(
        """
        INSERT INTO runtime_epochs(
            epoch, operation_id, state, created_at, activated_at
        ) VALUES (?, ?, 'ACTIVE', ?, ?)
        """,
        (epoch, operation_id, UTC_TEXT, UTC_TEXT),
    )
    connection.execute(
        """
        INSERT INTO artifact_manifests(
            manifest_id, operation_id, artifact_key, artifact_kind,
            source_version, manifest_sha256, state, verified,
            created_at, verified_at
        ) VALUES (?, ?, 'risk_rule_policy', 'risk_rule_policy', ?, ?,
                  'ACTIVE', 1, ?, ?)
        """,
        (
            manifest_id,
            operation_id,
            loaded.policy_version,
            digest,
            UTC_TEXT,
            UTC_TEXT,
        ),
    )
    connection.executemany(
        """
        INSERT INTO artifact_members(
            manifest_id, ordinal, object_type, object_id, object_sha256,
            source_version, source_lineage_json, media_type, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?)
        """,
        (
            (
                manifest_id,
                member.ordinal,
                member.object_type,
                member.object_id,
                member.object_sha256,
                member.source_version,
                member.media_type,
                member.size_bytes,
            )
            for member in members
        ),
    )
    if approved_model_ref is not None:
        assert model_digest is not None
        connection.execute(
            """
            INSERT INTO artifact_manifests(
                manifest_id, operation_id, artifact_key, artifact_kind,
                source_version, manifest_sha256, state, verified,
                created_at, verified_at
            ) VALUES (?, ?, 'risk_model_descriptor', 'risk_model_descriptor',
                      ?, ?, 'ACTIVE', 1, ?, ?)
            """,
            (
                model_manifest_id,
                operation_id,
                str(approved_model_ref.version),
                model_digest,
                UTC_TEXT,
                UTC_TEXT,
            ),
        )
        model_member = next(iter(model_members))
        connection.execute(
            """
            INSERT INTO artifact_members(
                manifest_id, ordinal, object_type, object_id, object_sha256,
                source_version, source_lineage_json, media_type, size_bytes
            ) VALUES (?, 0, ?, ?, ?, ?, '[]', ?, ?)
            """,
            (
                model_manifest_id,
                model_member.object_type,
                model_member.object_id,
                model_member.object_sha256,
                str(model_member.source_version),
                model_member.media_type,
                model_member.size_bytes,
            ),
        )
    connection.execute(
        """
        INSERT INTO active_artifacts(epoch, artifact_key, manifest_id, activated_at)
        VALUES (?, 'risk_rule_policy', ?, ?)
        """,
        (epoch, manifest_id, UTC_TEXT),
    )
    if approved_model_ref is not None:
        connection.execute(
            """
            INSERT INTO active_artifacts(
                epoch, artifact_key, manifest_id, activated_at
            ) VALUES (?, 'risk_model_descriptor', ?, ?)
            """,
            (epoch, model_manifest_id, UTC_TEXT),
        )
    return RiskRulePolicyBinding(
        runtime_epoch=epoch,
        manifest_ref=VersionRef(
            object_id=manifest_id,
            version=loaded.policy_version,
            content_sha256=digest,
        ),
    )


def attach_risk_policy_to_active_epoch(
    connection: sqlite3.Connection,
    loaded: LoadedPolicy[RiskRulesPolicy],
    *,
    suffix: int,
) -> RiskRulePolicyBinding:
    """Test-only: add risk policy to an already-approved active fixture epoch."""

    row = connection.execute(
        """
        SELECT r.epoch, r.operation_id, p.required_manifests_json,
               p.required_manifest_count, p.verified_manifest_count
          FROM runtime_epochs AS r
          JOIN publication_operations AS p
            ON p.operation_id = r.operation_id
         WHERE r.state = 'ACTIVE' AND p.state = 'ACTIVE'
        """
    ).fetchone()
    if row is None:
        raise AssertionError("active publication fixture is required")
    epoch = int(row[0])
    operation_id = str(row[1])
    required = json.loads(str(row[2]))
    if (
        type(required) is not list
        or int(row[3]) != len(required)
        or int(row[4]) != len(required)
    ):
        raise AssertionError("active publication manifest closure is invalid")
    manifest_id = _object_id("risk_rule_policy_manifest", suffix + 300)
    members = _manifest_members(loaded, suffix=suffix + 400)
    digest = manifest_sha256(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key="risk_rule_policy",
        artifact_kind="risk_rule_policy",
        source_version=loaded.policy_version,
        members=members,
    )
    connection.execute(
        """
        INSERT INTO artifact_manifests(
            manifest_id, operation_id, artifact_key, artifact_kind,
            source_version, manifest_sha256, state, verified,
            created_at, verified_at
        ) VALUES (?, ?, 'risk_rule_policy', 'risk_rule_policy', ?, ?,
                  'ACTIVE', 1, ?, ?)
        """,
        (
            manifest_id,
            operation_id,
            loaded.policy_version,
            digest,
            UTC_TEXT,
            UTC_TEXT,
        ),
    )
    connection.executemany(
        """
        INSERT INTO artifact_members(
            manifest_id, ordinal, object_type, object_id, object_sha256,
            source_version, source_lineage_json, media_type, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?)
        """,
        (
            (
                manifest_id,
                member.ordinal,
                member.object_type,
                member.object_id,
                member.object_sha256,
                member.source_version,
                member.media_type,
                member.size_bytes,
            )
            for member in members
        ),
    )
    connection.execute(
        """
        INSERT INTO active_artifacts(epoch, artifact_key, manifest_id, activated_at)
        VALUES (?, 'risk_rule_policy', ?, ?)
        """,
        (epoch, manifest_id, UTC_TEXT),
    )
    required.append(manifest_id)
    connection.execute(
        """
        UPDATE publication_operations
           SET required_manifests_json = ?, required_manifest_count = ?,
               verified_manifest_count = ?
         WHERE operation_id = ? AND state = 'ACTIVE'
        """,
        (
            json.dumps(required, separators=(",", ":")),
            len(required),
            len(required),
            operation_id,
        ),
    )
    return RiskRulePolicyBinding(
        runtime_epoch=epoch,
        manifest_ref=VersionRef(
            object_id=manifest_id,
            version=loaded.policy_version,
            content_sha256=digest,
        ),
    )


def persistent_risk_authority(
    repo_root: Path,
    tmp_path: Path,
    *,
    suffix: int = 1,
) -> tuple[
    sqlite3.Connection,
    LoadedPolicy[RiskRulesPolicy],
    RiskRuleCatalog,
    PersistentRiskRuleCatalogResolver,
    RiskRulePolicyBinding,
]:
    vault = tmp_path / f"risk-vault-{suffix}"
    vault.mkdir(exist_ok=True)
    loaded = PolicyLoader.from_config(
        AppConfig.from_values(repo_root, vault)
    ).load_all().risk_rules
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    MigrationRunner.for_scope(connection, "global").apply()
    binding = insert_approved_risk_policy_epoch(
        connection,
        loaded,
        epoch=1,
        suffix=suffix,
    )
    resolver = PersistentRiskRuleCatalogResolver(
        connection,
        loaded,
        database_scope="global",
    )
    catalog = resolver.resolve(binding)
    return connection, loaded, catalog, resolver, binding


__all__ = [
    "deterministic_risk_authority",
    "attach_risk_policy_to_active_epoch",
    "insert_approved_risk_policy_epoch",
    "persistent_risk_authority",
]
