from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Literal

import numpy as np
import pytest

from consultation_kb.approvals.models import descriptor_sha256
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.lifecycle.equivalence import (
    ArtifactFingerprint,
    EquivalenceReport,
    VectorSnapshot,
    compare_artifact_sets,
    compare_vector_snapshots,
)
from consultation_kb.lifecycle.rebuild import (
    ActivationReceipt,
    AuthorityInventory,
    AuthorityRecord,
    AuthorityVersionRef,
    BuildContext,
    BuiltArtifact,
    EMPTY_CASE_INDEX_INTENT_SET_SHA256,
    RebuildCoordinator,
    RebuildCoordinatorError,
    RebuildPlan,
    RebuildRequest,
    SqliteCasRebuildArtifactStore,
    SqliteRebuildAuthoritySource,
    StageVerification,
    authority_source_snapshot_sha256,
)
from consultation_kb.lifecycle.rebuild_jobs import (
    RebuildCancellationRejected,
    RebuildJob,
    RebuildJobCreate,
    RebuildJobRepository,
)
from consultation_kb.lifecycle.rebuild_registry import (
    AUTHORITY_TABLE_ALLOWLIST,
    AuthoritySourceSpec,
    BuilderDescriptor,
    BuilderRegistry,
    DatabaseScope,
)
from consultation_kb.lifecycle.structured_artifact import (
    StructuredArtifactEnvelope,
    StructuredArtifactMember,
)
from consultation_kb.models.deletion import deletion_intent_authority_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner, load_migrations
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-19T10:00:00.000000Z"
SCOPE_HASH = "1" * 64
POLICY_HASH = "2" * 64
MODEL_HASH = "3" * 64
TOMBSTONED_CANARY = b"deleted-client-body-must-never-rebuild"
UNAPPROVED_CANARY = b"unapproved-model-draft-must-never-rebuild"
INACTIVE_CANARY = b"inactive-approved-revision-must-never-rebuild"


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _connection(tmp_path: Path, scope: DatabaseScope) -> sqlite3.Connection:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    MigrationRunner(connection, load_migrations(scope)).apply()
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rebuild_jobs'"
    ).fetchone()
    if exists is None:
        import_module(
            f"consultation_kb.storage.migrations.{scope}.v0006_lifecycle"
        ).upgrade(connection)
    return connection


def _ids(start: int = 100) -> IdFactory:
    counter = iter(range(start, start + 10000))
    return IdFactory(
        clock=FixedClock(NOW),
        random_source=lambda: next(counter),
    )


def _apply_rebuild_approval(
    connection: sqlite3.Connection,
    plan: RebuildPlan,
    *,
    content_store: ContentStore | None = None,
    lifecycle_purpose: Literal["rebuild", "rollback"] = "rebuild",
    ids: IdFactory | None = None,
) -> tuple[str, str]:
    if plan.database_scope == "client":
        factory = ids or IdFactory(clock=FixedClock(NOW))
        operation_id = factory.object_id("approval_operation")
        request_id = factory.object_id("approval_request")
        descriptor = DraftDescriptor(
            purpose="rebuild",
            target_id=f"client_rebuild:{plan.purpose}",
        client_id="client" + "_abcdefghijkl",
            session_id=factory.uuid7(),
            base_version=plan.tombstone_epoch,
            draft_sha256=plan.plan_sha256,
        )
        nonce_sha256 = canonical_sha256(
            {"operation_id": operation_id, "request_id": request_id}
        )
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                operation_id,
                request_id,
                descriptor_sha256(descriptor),
                plan.plan_sha256,
                plan.tombstone_epoch,
                plan.scope_sha256,
                nonce_sha256,
            ),
        )
        connection.execute(
            """
            UPDATE approval_executions
               SET state = 'APPLIED', applied_commit_version = ?, applied_at = ?
             WHERE operation_id = ? AND state = 'CLAIMED'
            """,
            (max(1, plan.tombstone_epoch + 17), NOW_TEXT, operation_id),
        )
        if content_store is not None:
            envelope = {
                "schema_version": "client_rebuild_plan.v1",
                "action": "start",
                "operation_id": operation_id,
                "client_id": descriptor.client_id,
                "session_id": descriptor.session_id,
                "plan": plan.model_dump(mode="json"),
                "job_id": None,
                "job_plan_sha256": None,
                "base_versions": [
                    {
                        "authority_key": "tombstone_epoch",
                        "scope_sha256": plan.scope_sha256,
                        "version": plan.tombstone_epoch,
                    }
                ],
                "plan_sha256": plan.plan_sha256,
                "descriptor": descriptor.model_dump(mode="json"),
            }
            plan_object_id = factory.object_id("lifecycle_plan")
            stored = content_store.finalize(
                content_store.stage_bytes(
                    canonical_json_bytes(envelope),
                    purpose=lifecycle_purpose,
                    manifest_id=plan_object_id,
                    media_type="application/json",
                )
            )
            connection.execute(
                """
                INSERT INTO lifecycle_plan_objects(
                    object_id, version, content_sha256, size_bytes, media_type,
                    purpose, operation_id, plan_sha256, base_version,
                    target_scope_hash, created_at
                ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_object_id,
                    stored.content_sha256,
                    stored.size_bytes,
                    stored.media_type,
                    lifecycle_purpose,
                    operation_id,
                    plan.plan_sha256,
                    plan.tombstone_epoch,
                    plan.scope_sha256,
                    NOW_TEXT,
                ),
            )
            connection.execute(
                """
                INSERT INTO lifecycle_approval_attestations(
                    operation_id, request_id, descriptor_sha256,
                    plan_object_id, plan_version, plan_content_sha256,
                    plan_size_bytes, plan_media_type, purpose,
                    base_version, target_scope_hash, attested_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    request_id,
                    descriptor_sha256(descriptor),
                    plan_object_id,
                    stored.content_sha256,
                    stored.size_bytes,
                    stored.media_type,
                    lifecycle_purpose,
                    plan.tombstone_epoch,
                    plan.scope_sha256,
                    NOW_TEXT,
                ),
            )
        return operation_id, request_id
    if content_store is not None:
        factory = ids or IdFactory(clock=FixedClock(NOW))
        operation_id = factory.object_id("approval_operation")
        request_id = factory.object_id("approval_request")
        descriptor = DraftDescriptor(
            purpose="rebuild",
            target_id=f"global_rebuild:{plan.purpose}",
            base_version=plan.tombstone_epoch,
            draft_sha256=plan.plan_sha256,
        )
        envelope = {
            "schema_version": "global_rebuild_plan.v1",
            "action": "start",
            "operation_id": operation_id,
            "plan": plan.model_dump(mode="json"),
            "job_id": None,
            "job_plan_sha256": None,
            "base_versions": [
                {
                    "authority_key": "tombstone_epoch",
                    "scope_sha256": plan.scope_sha256,
                    "version": plan.tombstone_epoch,
                }
            ],
            "plan_sha256": plan.plan_sha256,
            "descriptor": descriptor.model_dump(mode="json"),
        }
        plan_object_id = factory.object_id("lifecycle_plan")
        stored = content_store.finalize(
            content_store.stage_bytes(
                canonical_json_bytes(envelope),
                purpose="rebuild",
                manifest_id=plan_object_id,
                media_type="application/json",
            )
        )
        diff_ref = VersionRef(
            object_id=plan_object_id,
            version=1,
            content_sha256=stored.content_sha256,
        )
        nonce_sha256 = canonical_sha256(
            {"operation_id": operation_id, "request_id": request_id}
        )
        exact_descriptor_sha256 = descriptor_sha256(descriptor)
        connection.execute(
            """
            INSERT INTO approval_requests(
                request_id, descriptor_sha256, descriptor_json,
                diff_object_ref_json, purpose, target_scope_hash, session_id,
                base_version, created_at, expires_at, nonce_sha256,
                nonce_ciphertext, state
            ) VALUES (?, ?, ?, ?, 'rebuild', ?, NULL, ?, ?, ?, ?, ?, 'ISSUED')
            """,
            (
                request_id,
                exact_descriptor_sha256,
                json.dumps(
                    descriptor.model_dump(mode="json"),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    diff_ref.model_dump(mode="json"),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                plan.scope_sha256,
                plan.tombstone_epoch,
                NOW_TEXT,
                "2026-07-19T11:00:00.000000Z",
                nonce_sha256,
                b"test-rebuild-approval-nonce",
            ),
        )
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                operation_id,
                request_id,
                exact_descriptor_sha256,
                plan.plan_sha256,
                plan.tombstone_epoch,
                plan.scope_sha256,
                nonce_sha256,
            ),
        )
        connection.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = ?, applied_at = ? "
            "WHERE operation_id = ? AND state = 'CLAIMED'",
            (max(1, plan.tombstone_epoch + 17), NOW_TEXT, operation_id),
        )
        return operation_id, request_id
    return _apply_approval_for_hash(
        connection,
        plan_sha256=plan.plan_sha256,
        scope_sha256=plan.scope_sha256,
        tombstone_epoch=plan.tombstone_epoch,
        database_scope=plan.database_scope,
        purpose=plan.purpose,
        ids=ids,
    )


def _apply_approval_for_hash(
    connection: sqlite3.Connection,
    *,
    plan_sha256: str,
    scope_sha256: str,
    tombstone_epoch: int,
    database_scope: DatabaseScope = "global",
    purpose: str = "all",
    approval_purpose: Literal["rebuild", "delete"] = "rebuild",
    ids: IdFactory | None = None,
) -> tuple[str, str]:
    factory = ids or IdFactory(clock=FixedClock(NOW))
    operation_id = factory.object_id("approval_operation")
    request_id = factory.object_id("approval_request")
    descriptor = DraftDescriptor(
        purpose=approval_purpose,
        target_id=f"{database_scope}_rebuild:{purpose}",
        client_id=(
            "client" + "_abcdefghijkl" if database_scope == "client" else None
        ),
        session_id=(factory.uuid7() if database_scope == "client" else None),
        base_version=tombstone_epoch,
        draft_sha256=plan_sha256,
    )
    exact_descriptor_sha256 = descriptor_sha256(descriptor)
    diff_ref = VersionRef(
        object_id=factory.object_id("rebuild_plan"),
        version=1,
        content_sha256=plan_sha256,
    )
    nonce_sha256 = canonical_sha256(
        {"operation_id": operation_id, "request_id": request_id}
    )
    now = "2026-07-19T10:00:00.000000Z"
    connection.execute(
        """
        INSERT INTO approval_requests(
            request_id, descriptor_sha256, descriptor_json,
            diff_object_ref_json, purpose, target_scope_hash, session_id,
            base_version, created_at, expires_at, nonce_sha256,
            nonce_ciphertext, state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ISSUED')
        """,
        (
            request_id,
            exact_descriptor_sha256,
            json.dumps(
                descriptor.model_dump(mode="json"),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            json.dumps(
                diff_ref.model_dump(mode="json"),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            approval_purpose,
            scope_sha256,
            descriptor.session_id,
            tombstone_epoch,
            now,
            "2026-07-19T11:00:00.000000Z",
            nonce_sha256,
            b"test-rebuild-approval-nonce",
        ),
    )
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
        """,
        (
            operation_id,
            request_id,
            exact_descriptor_sha256,
            plan_sha256,
            tombstone_epoch,
            scope_sha256,
            nonce_sha256,
        ),
    )
    connection.execute(
        """
        UPDATE approval_executions
           SET state = 'APPLIED', applied_commit_version = ?, applied_at = ?
         WHERE operation_id = ? AND state = 'CLAIMED'
        """,
        (max(1, tombstone_epoch + 1), now, operation_id),
    )
    return operation_id, request_id


def _start_approved(
    connection: sqlite3.Connection,
    coordinator: RebuildCoordinator,
    plan: RebuildPlan,
    *,
    idempotency_key: str,
) -> RebuildJob:
    artifact_store = getattr(coordinator, "_artifact_store", None)
    content_store = getattr(artifact_store, "_content_store", None)
    operation_id, request_id = _apply_rebuild_approval(
        connection,
        plan,
        content_store=(
            content_store if isinstance(content_store, ContentStore) else None
        ),
    )
    return coordinator.start(
        plan,
        idempotency_key=idempotency_key,
        approval_operation_id=operation_id,
        approval_request_id=request_id,
    )


def _direct_rebuild_plan(
    *,
    source_intent_id: str | None = None,
    tombstone_epoch: int = 0,
) -> RebuildPlan:
    plan_payload = {
        "domain": "consultation_kb.rebuild_plan.v1",
        "database_scope": "global",
        "source_intent_id": source_intent_id,
        "scope_sha256": SCOPE_HASH,
        "purpose": "all",
        "builder_ids": ["direct_test_builder"],
        "builder_dag_sha256": POLICY_HASH,
        "input_authority_versions_sha256": MODEL_HASH,
        "case_index_intent_set_sha256": EMPTY_CASE_INDEX_INTENT_SET_SHA256,
        "tombstone_epoch": tombstone_epoch,
        "policy_sha256": POLICY_HASH,
        "model_descriptor_sha256": MODEL_HASH,
    }
    plan = RebuildPlan(
        database_scope="global",
        source_intent_id=source_intent_id,
        scope_sha256=SCOPE_HASH,
        purpose="all",
        builder_ids=("direct_test_builder",),
        builder_dag_sha256=POLICY_HASH,
        input_authority_versions_sha256=MODEL_HASH,
        case_index_intent_set_sha256=EMPTY_CASE_INDEX_INTENT_SET_SHA256,
        tombstone_epoch=tombstone_epoch,
        policy_sha256=POLICY_HASH,
        model_descriptor_sha256=MODEL_HASH,
        plan_sha256=canonical_sha256(plan_payload),
    )
    return plan


def _running_rebuild_job(
    connection: sqlite3.Connection,
    *,
    content_store: ContentStore,
    id_start: int,
    tombstone_epoch: int = 0,
    approval_purpose: Literal["rebuild", "delete"] = "rebuild",
) -> tuple[RebuildJobRepository, RebuildJob]:
    plan = _direct_rebuild_plan(tombstone_epoch=tombstone_epoch)
    operation_id, request_id = (
        _apply_rebuild_approval(
            connection,
            plan,
            content_store=content_store,
            ids=_ids(id_start),
        )
        if approval_purpose == "rebuild"
        else _apply_approval_for_hash(
            connection,
            plan_sha256=plan.plan_sha256,
            scope_sha256=SCOPE_HASH,
            tombstone_epoch=tombstone_epoch,
            approval_purpose=approval_purpose,
            ids=_ids(id_start),
        )
    )
    repository = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(id_start + 100),
    )
    repository.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=None,
            approval_operation_id=operation_id,
            approval_request_id=request_id,
            plan_sha256=plan.plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=tombstone_epoch,
        ),
        idempotency_key=f"direct-store-{id_start}",
    )
    running = repository.claim_next()
    assert running is not None and running.state == "running"
    return repository, running


@dataclass(frozen=True, slots=True)
class _DeletionAuthorityFixture:
    request_id: str
    deletion_plan_sha256: str
    root_object_type: str
    root_target_id_hash: str
    root_lineage_hash: str
    tombstone_epoch: int
    now: str


def _seed_approved_deletion_authority(
    connection: sqlite3.Connection,
    ids: IdFactory,
    *,
    approval_applied_commit_version: int = 1,
) -> _DeletionAuthorityFixture:
    approval_operation_id = ids.object_id("approval_operation")
    approval_request_id = ids.object_id("approval_request")
    deletion_request_id = ids.object_id("deletion_request")
    root_object_type = "case"
    root_object_id = ids.object_id("case")
    root_target_id_hash = target_hash(root_object_type, root_object_id)
    root_lineage_hash = lineage_hash(root_object_type, root_object_id)
    deletion_plan_sha256 = canonical_sha256(
        {"deletion": "approved", "request_id": deletion_request_id}
    )
    descriptor_sha256 = canonical_sha256(
        {"descriptor": "deletion", "request_id": deletion_request_id}
    )
    now = "2026-07-19T10:00:00.000000Z"
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES (?, ?, ?, ?, 0, ?, ?, 'CLAIMED', NULL, NULL)
        """,
        (
            approval_operation_id,
            approval_request_id,
            descriptor_sha256,
            deletion_plan_sha256,
            SCOPE_HASH,
            canonical_sha256({"approval": approval_operation_id}),
        ),
    )
    connection.execute(
        """
        UPDATE approval_executions
           SET state = 'APPLIED', applied_commit_version = ?, applied_at = ?
         WHERE operation_id = ? AND state = 'CLAIMED'
        """,
        (approval_applied_commit_version, now, approval_operation_id),
    )
    connection.execute(
        "UPDATE deletion_authority_state "
        "SET deletion_version = 1, tombstone_epoch = 1 WHERE singleton = 1"
    )
    connection.execute(
        """
        INSERT INTO deletion_requests(
            request_id, operation_id, plan_sha256, target_type,
            target_id_hash, target_scope_hash, base_deletion_version,
            committed_deletion_version, tombstone_epoch,
            approval_request_id, approval_descriptor_sha256,
            approval_target_scope_hash, state, queue_state, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, 1, ?, ?, ?,
                  'TOMBSTONED', 'PENDING', ?)
        """,
        (
            deletion_request_id,
            approval_operation_id,
            deletion_plan_sha256,
            root_object_type,
            root_target_id_hash,
            SCOPE_HASH,
            approval_request_id,
            descriptor_sha256,
            SCOPE_HASH,
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO tombstones(
            tombstone_id, target_type, target_id_hash,
            source_lineage_hash, reason_code, created_at
        ) VALUES (?, ?, ?, ?, 'client_requested_deletion', ?)
        """,
        (
            ids.object_id("tombstone"),
            root_object_type,
            root_target_id_hash,
            root_lineage_hash,
            now,
        ),
    )
    return _DeletionAuthorityFixture(
        request_id=deletion_request_id,
        deletion_plan_sha256=deletion_plan_sha256,
        root_object_type=root_object_type,
        root_target_id_hash=root_target_id_hash,
        root_lineage_hash=root_lineage_hash,
        tombstone_epoch=1,
        now=now,
    )


def _seed_deletion_rebuild_intent(
    connection: sqlite3.Connection,
    authority: _DeletionAuthorityFixture,
    ids: IdFactory,
    *,
    tag: str,
    target_version: int = 1,
    action_descriptor_override: str | None = None,
) -> str:
    intent_id = ids.object_id("deletion_queue_intent")
    action_id = ids.object_id("deletion_action")
    object_type = "case"
    target_id_hash = target_hash(object_type, f"rebuild_target_{tag}")
    target_content_sha256 = canonical_sha256(
        {"case": "content", "tag": tag, "version": target_version}
    )
    connection.execute(
        """
        INSERT INTO deletion_queue_intents(
            intent_id, request_id, action_id, action_type, object_type,
            target_id_hash, target_version, target_content_sha256,
            authority_scope, state, attempt_count, created_at
        ) VALUES (?, ?, ?, 'rebuild', ?, ?, ?, ?, 'global',
                  'PENDING', 0, ?)
        """,
        (
            intent_id,
            authority.request_id,
            action_id,
            object_type,
            target_id_hash,
            target_version,
            target_content_sha256,
            authority.now,
        ),
    )
    action_descriptor_sha256 = deletion_intent_authority_sha256(
        intent_id=intent_id,
        request_id=authority.request_id,
        action_id=action_id,
        action_type="rebuild",
        object_type=object_type,
        target_id_hash=target_id_hash,
        target_version=target_version,
        target_content_sha256=target_content_sha256,
        authority_scope="global",
        deletion_plan_sha256=authority.deletion_plan_sha256,
        root_object_type=authority.root_object_type,
        root_target_id_hash=authority.root_target_id_hash,
        root_lineage_hash=authority.root_lineage_hash,
    )
    connection.execute(
        """
        INSERT INTO deletion_intent_authority_proofs(
            intent_id, request_id, action_id, deletion_plan_sha256,
            root_object_type, root_target_id_hash, root_lineage_hash,
            action_descriptor_sha256, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            intent_id,
            authority.request_id,
            action_id,
            authority.deletion_plan_sha256,
            authority.root_object_type,
            authority.root_target_id_hash,
            authority.root_lineage_hash,
            (
                action_descriptor_sha256
                if action_descriptor_override is None
                else action_descriptor_override
            ),
            authority.now,
        ),
    )
    return intent_id


class _Authority:
    def __init__(self, registry: BuilderRegistry, scope: DatabaseScope) -> None:
        descriptors = registry.plan(database_scope=scope, purpose="all")
        sources = {
            source.key: source
            for descriptor in descriptors
            for source in descriptor.authority_sources
        }
        self.epoch = 11
        self.read_log: list[str] = []
        self.records: dict[str, tuple[AuthorityRecord, ...]] = {}
        for key, source in sorted(sources.items()):
            approved_payload = f"approved:{key}".encode("ascii")
            self.records[key] = (
                AuthorityRecord(
                    source=source,
                    object_id=f"approved_{source.table}",
                    version=1,
                    content_sha256=_sha_bytes(approved_payload),
                    payload=approved_payload,
                    approved=True,
                    tombstoned=False,
                    active=True,
                ),
                AuthorityRecord(
                    source=source,
                    object_id=f"tombstoned_{source.table}",
                    version=1,
                    content_sha256=_sha_bytes(TOMBSTONED_CANARY),
                    payload=TOMBSTONED_CANARY,
                    approved=True,
                    tombstoned=True,
                    active=True,
                ),
                AuthorityRecord(
                    source=source,
                    object_id=f"unapproved_{source.table}",
                    version=1,
                    content_sha256=_sha_bytes(UNAPPROVED_CANARY),
                    payload=UNAPPROVED_CANARY,
                    approved=False,
                    tombstoned=False,
                    active=True,
                ),
                AuthorityRecord(
                    source=source,
                    object_id=f"inactive_{source.table}",
                    version=1,
                    content_sha256=_sha_bytes(INACTIVE_CANARY),
                    payload=INACTIVE_CANARY,
                    approved=True,
                    tombstoned=False,
                    active=False,
                ),
            )
        self._inventories: dict[str, AuthorityInventory] = {}

    def inventory(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory:
        versions = tuple(
            AuthorityVersionRef(
                source=source,
                version=1,
                snapshot_sha256=authority_source_snapshot_sha256(
                    source,
                    self.records[source.key],
                ),
            )
            for source in sorted(sources, key=lambda value: value.key)
        )
        inventory = AuthorityInventory.create(
            database_scope=database_scope,
            scope_sha256=scope_sha256,
            tombstone_epoch=self.epoch,
            versions=versions,
        )
        self._inventories[inventory.input_authority_versions_sha256] = inventory
        return inventory

    def resolve_exact(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        input_authority_versions_sha256: str,
        tombstone_epoch: int,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory:
        inventory = self._inventories[input_authority_versions_sha256]
        assert inventory.database_scope == database_scope
        assert inventory.scope_sha256 == scope_sha256
        assert inventory.tombstone_epoch == tombstone_epoch
        assert tuple(source.key for source in sources) == tuple(
            version.source.key for version in inventory.versions
        )
        return inventory

    def read_exact(
        self, inventory: AuthorityInventory
    ) -> Mapping[str, Sequence[AuthorityRecord]]:
        result: dict[str, Sequence[AuthorityRecord]] = {}
        for version in inventory.versions:
            self.read_log.append(version.source.key)
            result[version.source.key] = self.records[version.source.key]
        return result

    def current_tombstone_epoch(
        self, *, database_scope: DatabaseScope, scope_sha256: str
    ) -> int:
        del database_scope, scope_sha256
        return self.epoch


class _Builder:
    def __init__(self, descriptor: BuilderDescriptor) -> None:
        self.descriptor = descriptor
        self.seen_payloads: list[bytes] = []
        self.fail = False

    def build(self, context: BuildContext) -> BuiltArtifact:
        assert context.descriptor == self.descriptor
        if self.fail:
            raise RuntimeError("synthetic builder failure")
        self.seen_payloads.extend(record.payload for record in context.authority_records)
        payload = canonical_json_bytes(
            {
                "builder_id": self.descriptor.builder_id,
                "authority_versions": [
                    value.model_dump(mode="json")
                    for value in context.authority_versions
                ],
                "authority": [
                    {
                        "source": record.source.key,
                        "object_id": record.object_id,
                        "version": record.version,
                        "content_sha256": record.content_sha256,
                    }
                    for record in context.authority_records
                ],
                "dependencies": [
                    {
                        "builder_id": artifact.builder_id,
                        "content_sha256": artifact.content_sha256,
                    }
                    for artifact in context.dependency_artifacts
                ],
                "policy_sha256": context.policy_sha256,
                "model_descriptor_sha256": context.model_descriptor_sha256,
                "tombstone_epoch": context.tombstone_epoch,
            }
        )
        return BuiltArtifact.create(
            builder_id=self.descriptor.builder_id,
            output_purpose=self.descriptor.output_purpose,
            version=1,
            payload=payload,
            semantic_fingerprint_sha256=canonical_sha256(
                {"purpose": self.descriptor.output_purpose, "payload": payload.hex()}
            ),
        )


class _ArtifactStore:
    def __init__(self) -> None:
        self.active: dict[str, BuiltArtifact] = {}
        self._comparison_baseline: dict[str, ArtifactFingerprint] = {}
        self._stages: dict[str, dict[str, BuiltArtifact]] = {}
        self._expected: dict[str, tuple[str, ...]] = {}
        self._verifications: dict[str, StageVerification] = {}
        self._activated: dict[str, str] = {}
        self.activation_count = 0
        self.on_verify: Callable[[], None] | None = None
        self.fail_after_activation_once = False

    def begin_empty_stage(
        self,
        *,
        job_id: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> str:
        del tombstone_epoch
        assert job_id not in self._stages
        self._stages[job_id] = {}
        self._expected[job_id] = tuple(output_purposes)
        return job_id

    def stage_artifact(self, *, stage_ref: str, artifact: BuiltArtifact) -> None:
        stage = self._stages[stage_ref]
        assert artifact.output_purpose not in stage
        stage[artifact.output_purpose] = artifact

    def verify_stage(
        self,
        *,
        stage_ref: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> StageVerification:
        del tombstone_epoch
        if self.on_verify is not None:
            self.on_verify()
        stage = self._stages[stage_ref]
        assert tuple(output_purposes) == self._expected[stage_ref]
        assert set(stage) == set(output_purposes)
        before = self._comparison_baseline or {
            purpose: ArtifactFingerprint(
                artifact_key=purpose,
                version=artifact.version,
                content_sha256=artifact.content_sha256,
                semantic_fingerprint_sha256=artifact.semantic_fingerprint_sha256,
            )
            for purpose, artifact in self.active.items()
        }
        after = {
            purpose: ArtifactFingerprint(
                artifact_key=purpose,
                version=artifact.version,
                content_sha256=artifact.content_sha256,
                semantic_fingerprint_sha256=artifact.semantic_fingerprint_sha256,
            )
            for purpose, artifact in stage.items()
        }
        report = compare_artifact_sets(
            tuple(before.values()), tuple(after.values())
        )
        verification = StageVerification.create(
            artifacts=tuple(stage.values()),
            equivalence_report=report,
        )
        self._verifications[stage_ref] = verification
        return verification

    def activate_atomically(
        self,
        *,
        stage_ref: str,
        output_manifest_set_sha256: str,
        tombstone_epoch: int,
    ) -> ActivationReceipt:
        verification = self._verifications[stage_ref]
        assert verification.output_manifest_set_sha256 == output_manifest_set_sha256
        already_active = self._activated.get(stage_ref)
        if already_active is not None:
            assert already_active == output_manifest_set_sha256
            return ActivationReceipt(
                output_manifest_set_sha256=output_manifest_set_sha256,
                tombstone_epoch=tombstone_epoch,
                already_active=True,
            )
        self.active = dict(self._stages[stage_ref])
        self._comparison_baseline = {
            purpose: ArtifactFingerprint(
                artifact_key=purpose,
                version=artifact.version,
                content_sha256=artifact.content_sha256,
                semantic_fingerprint_sha256=artifact.semantic_fingerprint_sha256,
            )
            for purpose, artifact in self.active.items()
        }
        self._activated[stage_ref] = output_manifest_set_sha256
        self.activation_count += 1
        if self.fail_after_activation_once:
            self.fail_after_activation_once = False
            raise RuntimeError("synthetic activation acknowledgement loss")
        return ActivationReceipt(
            output_manifest_set_sha256=output_manifest_set_sha256,
            tombstone_epoch=tombstone_epoch,
            already_active=False,
        )

    def resume_stage(self, *, job_id: str) -> str:
        return job_id

    def discard_stage(self, *, stage_ref: str) -> None:
        self._stages.pop(stage_ref, None)
        self._expected.pop(stage_ref, None)
        self._verifications.pop(stage_ref, None)

    def delete_all_derived_keep_fingerprints(self) -> None:
        self._comparison_baseline = {
            purpose: ArtifactFingerprint(
                artifact_key=purpose,
                version=artifact.version,
                content_sha256=artifact.content_sha256,
                semantic_fingerprint_sha256=artifact.semantic_fingerprint_sha256,
            )
            for purpose, artifact in self.active.items()
        }
        self.active.clear()

    def report(self, job_id: str) -> EquivalenceReport:
        return self._verifications[job_id].equivalence_report


def _runtime(
    tmp_path: Path, scope: DatabaseScope
) -> tuple[
    sqlite3.Connection,
    RebuildCoordinator,
    _Authority,
    _ArtifactStore,
    dict[str, _Builder],
]:
    registry = BuilderRegistry.default()
    connection = _connection(tmp_path, scope)
    repository = RebuildJobRepository(
        connection,
        database_scope=scope,
        clock=FixedClock(NOW),
        id_factory=_ids(),
    )
    authority = _Authority(registry, scope)
    store = _ArtifactStore()
    builders = {
        descriptor.builder_id: _Builder(descriptor)
        for descriptor in registry.plan(database_scope=scope, purpose="all")
    }
    coordinator = RebuildCoordinator(
        registry=registry,
        jobs=repository,
        authority=authority,
        artifact_store=store,
        builders=builders,
    )
    return connection, coordinator, authority, store, builders


@pytest.mark.parametrize("scope", ("global", "client"))
def test_rebuild_all_from_exact_authority_is_equivalent_and_excludes_tombstones(
    tmp_path: Path,
    scope: DatabaseScope,
) -> None:
    connection, coordinator, authority, store, builders = _runtime(tmp_path, scope)
    try:
        request = RebuildRequest(
            database_scope=scope,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH if scope == "global" else None,
        )
        plan = coordinator.plan(request)
        queued = _start_approved(
            connection, coordinator, plan, idempotency_key="initial-build"
        )
        assert queued.state == "queued"
        assert authority.read_log == []
        assert store.active == {}

        initial = coordinator.run_next()
        assert initial is not None and initial.state == "succeeded"
        baseline = {
            purpose: artifact.content_sha256
            for purpose, artifact in store.active.items()
        }
        store.delete_all_derived_keep_fingerprints()

        repeated_plan = coordinator.plan(request)
        _start_approved(
            connection,
            coordinator,
            repeated_plan,
            idempotency_key="rebuild-after-loss",
        )
        rebuilt = coordinator.run_next()

        assert rebuilt is not None and rebuilt.state == "succeeded"
        assert {
            purpose: artifact.content_sha256
            for purpose, artifact in store.active.items()
        } == baseline
        assert store.report(rebuilt.job_id).equivalent
        assert store.activation_count == 2
        assert set(authority.read_log) <= {
            f"{scope}.{table}" for table in AUTHORITY_TABLE_ALLOWLIST[scope]
        }
        seen = b"\n".join(
            payload for builder in builders.values() for payload in builder.seen_payloads
        )
        assert TOMBSTONED_CANARY not in seen
        assert UNAPPROVED_CANARY not in seen
        assert INACTIVE_CANARY not in seen
    finally:
        connection.close()


def test_failed_builder_never_replaces_the_old_active_set(tmp_path: Path) -> None:
    connection, coordinator, _, store, builders = _runtime(tmp_path, "global")
    try:
        request = RebuildRequest(
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
        )
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="baseline",
        )
        baseline_job = coordinator.run_next()
        assert baseline_job is not None and baseline_job.state == "succeeded"
        old_active = dict(store.active)
        old_activation_count = store.activation_count
        builders["vector"].fail = True
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="will-fail",
        )

        failed = coordinator.run_next()

        assert failed is not None and failed.state == "failed"
        assert failed.last_error_code == "REBUILD_BUILD_FAILED"
        assert store.active == old_active
        assert store.activation_count == old_activation_count
    finally:
        connection.close()


def test_authority_rows_must_match_the_exact_planned_snapshot(tmp_path: Path) -> None:
    connection, coordinator, authority, store, _ = _runtime(tmp_path, "global")
    try:
        request = RebuildRequest(
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
        )
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="exact-snapshot",
        )
        source_key = sorted(authority.records)[0]
        old = authority.records[source_key]
        replacement_payload = b"different-approved-authority"
        authority.records[source_key] = (
            AuthorityRecord(
                source=old[0].source,
                object_id=old[0].object_id,
                version=old[0].version + 1,
                content_sha256=_sha_bytes(replacement_payload),
                payload=replacement_payload,
                approved=True,
                tombstoned=False,
                active=True,
            ),
            *old[1:],
        )

        failed = coordinator.run_next()

        assert failed is not None and failed.state == "failed"
        assert failed.last_error_code == "REBUILD_AUTHORITY_SOURCE_HASH_MISMATCH"
        assert store.active == {}
        assert store.activation_count == 0
    finally:
        connection.close()


def test_tombstone_epoch_change_before_activation_keeps_old_active(
    tmp_path: Path,
) -> None:
    connection, coordinator, authority, store, _ = _runtime(tmp_path, "global")
    try:
        request = RebuildRequest(
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
        )
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="baseline",
        )
        baseline_job = coordinator.run_next()
        assert baseline_job is not None and baseline_job.state == "succeeded"
        old_active = dict(store.active)
        old_activation_count = store.activation_count
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="stale-epoch",
        )
        store.on_verify = lambda: setattr(authority, "epoch", authority.epoch + 1)

        failed = coordinator.run_next()

        assert failed is not None and failed.state == "failed"
        assert failed.last_error_code == "REBUILD_TOMBSTONE_EPOCH_CHANGED"
        assert store.active == old_active
        assert store.activation_count == old_activation_count
    finally:
        connection.close()


def test_process_restart_resumes_an_activated_job_without_a_second_switch(
    tmp_path: Path,
) -> None:
    connection, coordinator, authority, store, builders = _runtime(
        tmp_path, "global"
    )
    try:
        request = RebuildRequest(
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
        )
        queued = _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="lost-activation-ack",
        )
        store.fail_after_activation_once = True

        with pytest.raises(
            RuntimeError, match="synthetic activation acknowledgement loss"
        ):
            coordinator.run_next()

        restarted_jobs = RebuildJobRepository(
            connection,
            database_scope="global",
            clock=FixedClock(NOW),
            id_factory=_ids(5000),
        )
        assert restarted_jobs.get(queued.job_id).state == "activating"
        assert store.activation_count == 1
        restarted = RebuildCoordinator(
            registry=BuilderRegistry.default(),
            jobs=restarted_jobs,
            authority=authority,
            artifact_store=store,
            builders=builders,
        )

        completed = restarted.run_next()

        assert completed is not None and completed.state == "succeeded"
        assert store.activation_count == 1
        assert tuple(
            entry.state for entry in restarted_jobs.journal(queued.job_id)
        ) == (
            "queued",
            "running",
            "verifying",
            "activating",
            "succeeded",
        )
    finally:
        connection.close()


def test_vector_equivalence_uses_fixed_tolerance_and_report_copies_no_vectors() -> None:
    before = VectorSnapshot(
        artifact_key="global_vector",
        version=4,
        model_descriptor_sha256=MODEL_HASH,
        file_sha256s=("4" * 64,),
        embeddings=np.asarray([[0.25, -0.5], [0.75, 1.0]], dtype=np.float32),
        top_k_rankings=(("safe-row-a", "sensitive-canary-row"),),
    )
    within_tolerance = VectorSnapshot(
        artifact_key="global_vector",
        version=4,
        model_descriptor_sha256=MODEL_HASH,
        file_sha256s=("4" * 64,),
        embeddings=np.asarray(
            [[0.2500005, -0.5], [0.75, 1.0]], dtype=np.float32
        ),
        top_k_rankings=(("safe-row-a", "sensitive-canary-row"),),
    )

    report = compare_vector_snapshots(before, within_tolerance)

    assert report.equivalent
    assert report.items[0].numeric_atol == 1e-6
    rendered = report.model_dump_json()
    assert "sensitive-canary-row" not in rendered
    assert "0.2500005" not in rendered

    new_manifest_version = VectorSnapshot(
        artifact_key="global_vector",
        version=5,
        model_descriptor_sha256=MODEL_HASH,
        file_sha256s=("4" * 64,),
        embeddings=before.embeddings.copy(),
        top_k_rankings=before.top_k_rankings,
    )
    versioned_equivalent = compare_vector_snapshots(before, new_manifest_version)
    assert versioned_equivalent.equivalent
    assert versioned_equivalent.items[0].before_version == 4
    assert versioned_equivalent.items[0].after_version == 5
    assert versioned_equivalent.items[0].reason_codes == (
        "content_equivalent_new_version",
    )

    ranking_changed = VectorSnapshot(
        artifact_key="global_vector",
        version=4,
        model_descriptor_sha256=MODEL_HASH,
        file_sha256s=("4" * 64,),
        embeddings=within_tolerance.embeddings,
        top_k_rankings=(("safe-row-b", "safe-row-a"),),
    )
    unsafe = compare_vector_snapshots(before, ranking_changed)
    assert not unsafe.equivalent
    assert not unsafe.activation_eligible
    assert unsafe.items[0].reason_codes == ("top_k_ranking_changed",)


def test_exact_content_equivalence_is_independent_of_manifest_version() -> None:
    before = ArtifactFingerprint(
        artifact_key="profile_view",
        version=8,
        content_sha256="5" * 64,
        semantic_fingerprint_sha256="6" * 64,
    )
    new_manifest = before.model_copy(update={"version": 9})

    report = compare_artifact_sets((before,), (new_manifest,))

    assert report.equivalent
    assert report.activation_eligible
    assert report.items[0].before_version == 8
    assert report.items[0].after_version == 9
    assert report.items[0].reason_codes == ("content_equivalent_new_version",)

    unversioned_change = before.model_copy(update={"content_sha256": "7" * 64})
    unsafe = compare_artifact_sets((before,), (unversioned_change,))
    assert not unsafe.equivalent
    assert not unsafe.activation_eligible
    assert "unversioned_content_change" in unsafe.items[0].reason_codes


def _seed_approved_source_with_unreadable_draft(
    connection: sqlite3.Connection,
    content_store: ContentStore,
    ids: IdFactory,
) -> bytes:
    approved_body = b"approved-source-body-from-verified-cas"
    staged = content_store.stage_bytes(
        approved_body,
        purpose="source_import",
        manifest_id=ids.object_id("source_manifest"),
        media_type="text/plain",
    )
    approved = content_store.finalize(staged)
    connection.execute(
        """
        INSERT INTO sources(
            source_id, logical_path, logical_path_key, document_type,
            current_version, created_at
        ) VALUES ('source_approved', 'approved.txt', 'approved.txt', 'text', 1, ?)
        """,
        ("2026-07-19T10:00:00.000000Z",),
    )
    connection.executemany(
        """
        INSERT INTO source_versions(
            source_id, version, content_sha256, content_object_ref,
            size_bytes, license, domain, language, sensitivity,
            source_grade, status, imported_at, metadata_json, metadata_sha256
        ) VALUES ('source_approved', ?, ?, ?, ?, 'owned', 'consultation',
                  'zh', 'normal', 'C1', ?, ?, '{}', ?)
        """,
        (
            (
                1,
                approved.content_sha256,
                f"sha256:{approved.content_sha256}",
                approved.size_bytes,
                "APPROVED",
                "2026-07-19T10:00:00.000000Z",
                canonical_sha256({}),
            ),
            (
                2,
                "f" * 64,
                f"sha256:{'f' * 64}",
                999,
                "DRAFT",
                "2026-07-19T10:00:00.000000Z",
                canonical_sha256({"unapproved": True}),
            ),
        ),
    )
    return approved_body


def test_sqlite_cas_adapters_rebuild_real_migrated_scope_as_one_active_set(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "production-global.sqlite3"
    connection = connect_database(database_path, mode="writer")
    MigrationRunner(connection, load_migrations("global")).apply()
    content_store = ContentStore(tmp_path / "production-global-cas")
    approved_body = _seed_approved_source_with_unreadable_draft(
        connection, content_store, _ids(20_000)
    )
    registry = BuilderRegistry.default()
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(30_000),
    )
    authority = SqliteRebuildAuthoritySource(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
    )
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(40_000),
    )
    descriptors = registry.plan(database_scope="global", purpose="all")
    builders = {
        descriptor.builder_id: _Builder(descriptor) for descriptor in descriptors
    }
    coordinator = RebuildCoordinator(
        registry=registry,
        jobs=jobs,
        authority=authority,
        artifact_store=store,
        builders=builders,
    )
    try:
        plan = coordinator.plan(
            RebuildRequest(
                database_scope="global",
                scope_sha256=SCOPE_HASH,
                purpose="all",
                policy_sha256=POLICY_HASH,
                model_descriptor_sha256=MODEL_HASH,
            )
        )
        queued = _start_approved(
            connection,
            coordinator,
            plan,
            idempotency_key="real-sqlite-cas-rebuild",
        )
        assert queued.plan_sha256 == plan.plan_sha256

        completed = coordinator.run_next()

        assert completed is not None and completed.state == "succeeded"
        operation = connection.execute(
            """
            SELECT operation_id, state, runtime_epoch
              FROM publication_operations
             WHERE approval_request_id = ? AND purpose = 'rebuild'
            """,
            (queued.approval_request_id,),
        ).fetchone()
        assert operation is not None and operation[1] == "ACTIVE"
        epoch = int(operation[2])
        active = connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        ).fetchall()
        assert tuple(row[0] for row in active) == tuple(
            sorted(descriptor.output_purpose for descriptor in descriptors)
        )
        assert connection.execute(
            "SELECT count(*) FROM artifact_manifests "
            "WHERE operation_id = ? AND state = 'ACTIVE' AND verified = 1",
            (operation[0],),
        ).fetchone() == (len(descriptors),)
        assert completed.equivalence_report_sha256 is not None
        report_body = content_store.read_hash_verified(
            completed.equivalence_report_sha256
        )
        assert hashlib.sha256(report_body).hexdigest() == (
            completed.equivalence_report_sha256
        )
        seen = b"\n".join(
            payload
            for builder in builders.values()
            for payload in builder.seen_payloads
        )
        assert approved_body.hex().encode("ascii") not in seen
        assert b"approved-source-body-from-verified-cas" not in seen
        assert b"YXBwcm92ZWQtc291cmNlLWJvZHktZnJvbS12ZXJpZmllZC1jYXM=" in seen
    finally:
        connection.close()


def test_sqlite_cas_store_resumes_durable_verified_stage_after_restart(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "durable-stage-cas")
    first = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(50_000),
    )
    jobs, running = _running_rebuild_job(
        connection, content_store=content_store, id_start=51_000
    )
    artifacts = tuple(
        BuiltArtifact.create(
            builder_id=builder_id,
            output_purpose=purpose,
            version=1,
            payload=purpose.encode("ascii"),
            semantic_fingerprint_sha256=canonical_sha256({"purpose": purpose}),
        )
        for builder_id, purpose in (
            ("global_wiki_render", "wiki_render"),
            ("global_graph", "global_graph"),
        )
    )
    try:
        stage_ref = first.begin_empty_stage(
            job_id=running.job_id,
            output_purposes=tuple(value.output_purpose for value in artifacts),
            tombstone_epoch=0,
        )
        for artifact in artifacts:
            first.stage_artifact(stage_ref=stage_ref, artifact=artifact)
        jobs.mark_verifying(running.job_id)
        verification = first.verify_stage(
            stage_ref=stage_ref,
            output_purposes=tuple(value.output_purpose for value in artifacts),
            tombstone_epoch=0,
        )
        jobs.mark_activating(
            running.job_id,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            equivalence_report_sha256=(
                verification.equivalence_report.report_sha256
            ),
        )

        restarted = SqliteCasRebuildArtifactStore(
            connection,
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            content_store=content_store,
            clock=FixedClock(NOW),
            id_factory=_ids(60_000),
        )
        recovered_ref = restarted.resume_stage(job_id=running.job_id)
        receipt = restarted.activate_atomically(
            stage_ref=recovered_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=0,
        )

        assert not receipt.already_active
        assert connection.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (stage_ref,),
        ).fetchone() == ("ACTIVE",)
        assert connection.execute(
            "SELECT count(DISTINCT epoch), count(*) FROM active_artifacts"
        ).fetchone() == (1, 2)
    finally:
        connection.close()


def test_sqlite_cas_store_rejects_cross_purpose_approval_with_same_plan(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "cross-purpose-approval-cas")
    jobs, running = _running_rebuild_job(
        connection,
        content_store=content_store,
        id_start=61_000,
        approval_purpose="delete",
    )
    assert running.approval_request_id is not None
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(62_000),
    )
    try:
        with pytest.raises(
            RebuildCoordinatorError,
            match="REBUILD_ACTIVATION_AUTHORITY_INVALID",
        ):
            store.begin_empty_stage(
                job_id=running.job_id,
                output_purposes=("wiki_render",),
                tombstone_epoch=running.tombstone_epoch,
            )
        assert jobs.get(running.job_id).state == "running"
        assert connection.execute(
            "SELECT count(*) FROM rebuild_stage_bindings WHERE job_id = ?",
            (running.job_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_client_sqlite_cas_store_rejects_cross_purpose_plan_object(
    tmp_path: Path,
) -> None:
    connection, coordinator, _, _, _ = _runtime(tmp_path, "client")
    content_store = ContentStore(tmp_path / "client-cross-purpose-plan-cas")
    jobs = RebuildJobRepository(connection, database_scope="client")
    try:
        plan = coordinator.plan(
            RebuildRequest(
                database_scope="client",
                scope_sha256=SCOPE_HASH,
                purpose="all",
                policy_sha256=POLICY_HASH,
                model_descriptor_sha256=None,
            )
        )
        operation_id, request_id = _apply_rebuild_approval(
            connection,
            plan,
            content_store=content_store,
            lifecycle_purpose="rollback",
        )
        queued = coordinator.start(
            plan,
            idempotency_key="client-cross-purpose-plan-object",
            approval_operation_id=operation_id,
            approval_request_id=request_id,
        )
        running = jobs.claim_next()
        assert running is not None and running.job_id == queued.job_id
        store = SqliteCasRebuildArtifactStore(
            connection,
            database_scope="client",
            scope_sha256=SCOPE_HASH,
            content_store=content_store,
            clock=FixedClock(NOW),
            id_factory=_ids(63_000),
        )

        with pytest.raises(
            RebuildCoordinatorError,
            match="REBUILD_ACTIVATION_AUTHORITY_INVALID",
        ):
            store.begin_empty_stage(
                job_id=running.job_id,
                output_purposes=("private_archive",),
                tombstone_epoch=running.tombstone_epoch,
            )

        assert jobs.get(running.job_id).state == "running"
        assert connection.execute(
            "SELECT count(*) FROM rebuild_stage_bindings WHERE job_id = ?",
            (running.job_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_sqlite_cas_store_restarts_exact_repeated_role_structured_archive(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "structured-restart-cas")
    first = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(61_000),
    )
    jobs, running = _running_rebuild_job(
        connection, content_store=content_store, id_start=62_000
    )
    payloads = (
        canonical_json_bytes({"archive": "first", "revision": 1}),
        canonical_json_bytes({"archive": "second", "revision": 2}),
    )
    envelope = StructuredArtifactEnvelope(
        artifact_key="private_archive",
        artifact_kind="private_archive",
        source_version=1,
        semantic_basis_sha256=canonical_sha256(
            {"policy": "approved-private-archive-replay.v1"}
        ),
        members=tuple(
            StructuredArtifactMember.from_bytes(
                role="private_archive_draft",
                media_type="application/json",
                payload=payload,
                source_lineage_hashes=(f"{index}" * 64,),
            )
            for index, payload in enumerate(payloads, start=1)
        ),
    )
    artifact = BuiltArtifact.create(
        builder_id="private_archive",
        output_purpose="private_archive",
        version=1,
        payload=envelope.canonical_bytes,
        semantic_fingerprint_sha256=envelope.semantic_fingerprint_sha256,
        comparison_content_sha256=envelope.comparison_content_sha256,
    )
    try:
        stage_ref = first.begin_empty_stage(
            job_id=running.job_id,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        first.stage_artifact(stage_ref=stage_ref, artifact=artifact)
        jobs.mark_verifying(running.job_id)
        verification = first.verify_stage(
            stage_ref=stage_ref,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        jobs.mark_activating(
            running.job_id,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            equivalence_report_sha256=verification.equivalence_report.report_sha256,
        )

        restarted = SqliteCasRebuildArtifactStore(
            connection,
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            content_store=content_store,
            clock=FixedClock(NOW),
            id_factory=_ids(63_000),
        )
        recovered_ref = restarted.resume_stage(job_id=running.job_id)
        receipt = restarted.activate_atomically(
            stage_ref=recovered_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=0,
        )

        assert not receipt.already_active
        active = connection.execute(
            "SELECT manifest_id FROM active_artifacts "
            "WHERE artifact_key = 'private_archive'"
        ).fetchone()
        assert active is not None
        manifest = ManifestRepository(connection).get(str(active[0]))
        assert manifest.artifact_kind == "private_archive"
        assert tuple(member.object_type for member in manifest.members) == (
            "private_archive_draft",
            "private_archive_draft",
        )
        assert tuple(member.media_type for member in manifest.members) == (
            "application/json",
            "application/json",
        )
        assert len({member.object_id for member in manifest.members}) == 2
        assert tuple(
            content_store.read_hash_verified(member.object_sha256)
            for member in manifest.members
        ) == payloads
        comparisons = json.loads(
            connection.execute(
                "SELECT member_comparisons_json "
                "FROM rebuild_structured_artifacts WHERE manifest_id = ?",
                (manifest.manifest_id,),
            ).fetchone()[0]
        )
        assert [(item["ordinal"], item["role"]) for item in comparisons] == [
            (0, "private_archive_draft"),
            (1, "private_archive_draft"),
        ]
    finally:
        connection.close()


def test_sqlite_cas_store_acknowledges_active_stage_after_new_deletion_epoch(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "lost-ack-after-deletion-cas")
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(65_000),
    )
    jobs, running = _running_rebuild_job(
        connection, content_store=content_store, id_start=66_000
    )
    artifact = BuiltArtifact.create(
        builder_id="global_wiki_render",
        output_purpose="wiki_render",
        version=1,
        payload=b"activated-before-new-deletion",
        semantic_fingerprint_sha256=canonical_sha256({"lost_ack": True}),
    )
    try:
        stage_ref = store.begin_empty_stage(
            job_id=running.job_id,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        store.stage_artifact(stage_ref=stage_ref, artifact=artifact)
        jobs.mark_verifying(running.job_id)
        verification = store.verify_stage(
            stage_ref=stage_ref,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        jobs.mark_activating(
            running.job_id,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            equivalence_report_sha256=(
                verification.equivalence_report.report_sha256
            ),
        )
        first_receipt = store.activate_atomically(
            stage_ref=stage_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=0,
        )
        assert not first_receipt.already_active
        connection.execute(
            """
            UPDATE deletion_authority_state
               SET deletion_version = 1, tombstone_epoch = 1
             WHERE singleton = 1
            """
        )

        restarted = SqliteCasRebuildArtifactStore(
            connection,
            database_scope="global",
            scope_sha256=SCOPE_HASH,
            content_store=content_store,
            clock=FixedClock(NOW),
            id_factory=_ids(67_000),
        )
        recovered_ref = restarted.resume_stage(job_id=running.job_id)
        replay_receipt = restarted.activate_atomically(
            stage_ref=recovered_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=0,
        )

        assert replay_receipt.already_active
        assert connection.execute(
            "SELECT count(*) FROM runtime_epochs"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (stage_ref,),
        ).fetchone() == ("ACTIVE",)
    finally:
        connection.close()


def test_sqlite_cas_store_epoch_cas_prevents_every_partial_activation(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "stale-epoch-cas")
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(70_000),
    )
    artifact = BuiltArtifact.create(
        builder_id="global_wiki_render",
        output_purpose="wiki_render",
        version=1,
        payload=b"verified-but-stale",
        semantic_fingerprint_sha256=canonical_sha256({"stale": True}),
    )
    try:
        jobs, running = _running_rebuild_job(
            connection, content_store=content_store, id_start=71_000
        )
        stage_ref = store.begin_empty_stage(
            job_id=running.job_id,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        store.stage_artifact(stage_ref=stage_ref, artifact=artifact)
        jobs.mark_verifying(running.job_id)
        verification = store.verify_stage(
            stage_ref=stage_ref,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=0,
        )
        jobs.mark_activating(
            running.job_id,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            equivalence_report_sha256=(
                verification.equivalence_report.report_sha256
            ),
        )
        connection.execute(
            "UPDATE deletion_authority_state SET tombstone_epoch = 1 "
            "WHERE singleton = 1"
        )

        with pytest.raises(
            RebuildCoordinatorError, match="^REBUILD_TOMBSTONE_EPOCH_CHANGED$"
        ):
            store.activate_atomically(
                stage_ref=stage_ref,
                output_manifest_set_sha256=(
                    verification.output_manifest_set_sha256
                ),
                tombstone_epoch=0,
            )

        assert connection.execute("SELECT count(*) FROM runtime_epochs").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (stage_ref,),
        ).fetchone() == ("VERIFIED",)
    finally:
        connection.close()


def test_sqlite_cas_store_rejects_unapplied_approval_without_any_stage(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "unapplied-approval-cas")
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(80_000),
    )
    ids = _ids(81_000)
    operation_id = ids.object_id("approval_operation")
    request_id = ids.object_id("approval_request")
    plan_sha256 = canonical_sha256({"authority": "not-applied"})
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
            request_id,
            POLICY_HASH,
            plan_sha256,
            SCOPE_HASH,
            canonical_sha256({"operation_id": operation_id}),
        ),
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(82_000),
    )
    jobs.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=None,
            approval_operation_id=operation_id,
            approval_request_id=request_id,
            plan_sha256=plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=0,
        ),
        idempotency_key="unapplied-approval",
    )
    running = jobs.claim_next()
    assert running is not None
    try:
        with pytest.raises(
            RebuildCoordinatorError,
            match="^REBUILD_ACTIVATION_AUTHORITY_INVALID$",
        ):
            store.begin_empty_stage(
                job_id=running.job_id,
                output_purposes=("wiki_render",),
                tombstone_epoch=0,
            )

        assert connection.execute(
            "SELECT count(*) FROM publication_operations WHERE purpose = 'rebuild'"
        ).fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM runtime_epochs").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_sqlite_cas_store_accepts_only_exact_approved_deletion_intent_chain(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "deletion-intent-cas")
    ids = _ids(90_000)
    authority = _seed_approved_deletion_authority(connection, ids)
    intent_id = _seed_deletion_rebuild_intent(
        connection,
        authority,
        ids,
        tag="accepted",
    )
    rebuild_plan = _direct_rebuild_plan(
        source_intent_id=intent_id,
        tombstone_epoch=authority.tombstone_epoch,
    )
    rebuild_approval = _apply_rebuild_approval(
        connection,
        rebuild_plan,
        content_store=content_store,
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(91_000),
    )
    queued = jobs.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=intent_id,
            approval_operation_id=rebuild_approval[0],
            approval_request_id=rebuild_approval[1],
            plan_sha256=rebuild_plan.plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=authority.tombstone_epoch,
        ),
        idempotency_key="approved-deletion-intent",
    )
    running = jobs.claim_next()
    assert running is not None and running.job_id == queued.job_id
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(92_000),
    )
    artifact = BuiltArtifact.create(
        builder_id="global_wiki_render",
        output_purpose="wiki_render",
        version=1,
        payload=b"deletion-intent-rebuild",
        semantic_fingerprint_sha256=canonical_sha256({"deletion": "rebuild"}),
    )
    try:
        stage_ref = store.begin_empty_stage(
            job_id=queued.job_id,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=authority.tombstone_epoch,
        )
        store.stage_artifact(stage_ref=stage_ref, artifact=artifact)
        jobs.mark_verifying(queued.job_id)
        verification = store.verify_stage(
            stage_ref=stage_ref,
            output_purposes=(artifact.output_purpose,),
            tombstone_epoch=authority.tombstone_epoch,
        )
        jobs.mark_activating(
            queued.job_id,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            equivalence_report_sha256=(
                verification.equivalence_report.report_sha256
            ),
        )

        receipt = store.activate_atomically(
            stage_ref=stage_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=authority.tombstone_epoch,
        )

        assert not receipt.already_active
        assert connection.execute(
            "SELECT state, runtime_epoch FROM publication_operations "
            "WHERE operation_id = ?",
            (stage_ref,),
        ).fetchone() == ("ACTIVE", 1)
        assert connection.execute(
            "SELECT state, attempt_count, finished_at "
            "FROM deletion_queue_intents WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("SUCCEEDED", 1, NOW_TEXT)

        replay = store.activate_atomically(
            stage_ref=stage_ref,
            output_manifest_set_sha256=verification.output_manifest_set_sha256,
            tombstone_epoch=authority.tombstone_epoch,
        )
        assert replay.already_active
        assert connection.execute(
            "SELECT state, attempt_count, finished_at "
            "FROM deletion_queue_intents WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("SUCCEEDED", 1, NOW_TEXT)
    finally:
        connection.close()


def test_sqlite_cas_store_rejects_deletion_proof_not_matching_exact_target(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "mutated-deletion-intent-cas")
    ids = _ids(100_000)
    authority = _seed_approved_deletion_authority(connection, ids)
    intent_id = _seed_deletion_rebuild_intent(
        connection,
        authority,
        ids,
        tag="before-mutation",
        target_version=4,
        action_descriptor_override=canonical_sha256(
            {"tampered_target_version": 5, "tampered_content": True}
        ),
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(101_000),
    )
    rebuild_plan_sha256 = canonical_sha256({"rebuild": "mutated-intent"})
    rebuild_approval = _apply_approval_for_hash(
        connection,
        plan_sha256=rebuild_plan_sha256,
        scope_sha256=SCOPE_HASH,
        tombstone_epoch=authority.tombstone_epoch,
    )
    queued = jobs.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=intent_id,
            approval_operation_id=rebuild_approval[0],
            approval_request_id=rebuild_approval[1],
            plan_sha256=rebuild_plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=authority.tombstone_epoch,
        ),
        idempotency_key="mutated-deletion-intent",
    )
    running = jobs.claim_next()
    assert running is not None and running.job_id == queued.job_id
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(102_000),
    )
    try:
        with pytest.raises(
            RebuildCoordinatorError,
            match="^REBUILD_ACTIVATION_AUTHORITY_INVALID$",
        ):
            store.begin_empty_stage(
                job_id=queued.job_id,
                output_purposes=("wiki_render",),
                tombstone_epoch=authority.tombstone_epoch,
            )

        assert connection.execute(
            "SELECT count(*) FROM publication_operations WHERE purpose = 'rebuild'"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM rebuild_stage_bindings"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_sqlite_cas_store_accepts_independent_approval_execution_sequence(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "independent-approval-sequence-cas")
    ids = _ids(105_000)
    authority = _seed_approved_deletion_authority(
        connection,
        ids,
        approval_applied_commit_version=2,
    )
    intent_id = _seed_deletion_rebuild_intent(
        connection,
        authority,
        ids,
        tag="independent-approval-sequence",
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(106_000),
    )
    rebuild_plan = _direct_rebuild_plan(
        source_intent_id=intent_id,
        tombstone_epoch=authority.tombstone_epoch,
    )
    rebuild_approval = _apply_rebuild_approval(
        connection,
        rebuild_plan,
        content_store=content_store,
    )
    queued = jobs.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=intent_id,
            approval_operation_id=rebuild_approval[0],
            approval_request_id=rebuild_approval[1],
            plan_sha256=rebuild_plan.plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=authority.tombstone_epoch,
        ),
        idempotency_key="independent-approval-sequence",
    )
    running = jobs.claim_next()
    assert running is not None and running.job_id == queued.job_id
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(107_000),
    )
    try:
        stage_ref = store.begin_empty_stage(
            job_id=queued.job_id,
            output_purposes=("wiki_render",),
            tombstone_epoch=authority.tombstone_epoch,
        )

        assert connection.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (stage_ref,),
        ).fetchone() == ("PREPARED",)
    finally:
        connection.close()


def test_source_bound_rebuild_failure_updates_deletion_status_and_cannot_cancel(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    ids = _ids(108_000)
    authority = _seed_approved_deletion_authority(connection, ids)
    intent_id = _seed_deletion_rebuild_intent(
        connection,
        authority,
        ids,
        tag="failed-source-job",
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(109_000),
    )
    rebuild_plan_sha256 = canonical_sha256({"rebuild": "failed-source-job"})
    rebuild_approval = _apply_approval_for_hash(
        connection,
        plan_sha256=rebuild_plan_sha256,
        scope_sha256=SCOPE_HASH,
        tombstone_epoch=authority.tombstone_epoch,
    )
    queued = jobs.enqueue(
        RebuildJobCreate(
            database_scope="global",
            source_intent_id=intent_id,
            approval_operation_id=rebuild_approval[0],
            approval_request_id=rebuild_approval[1],
            plan_sha256=rebuild_plan_sha256,
            scope_sha256=SCOPE_HASH,
            purpose="all",
            builder_dag_sha256=POLICY_HASH,
            input_authority_versions_sha256=MODEL_HASH,
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
            tombstone_epoch=authority.tombstone_epoch,
        ),
        idempotency_key="failed-source-job",
    )
    try:
        running = jobs.claim_next()
        assert running is not None
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("CLAIMED",)

        failed = jobs.mark_failed(
            queued.job_id,
            error_code="REBUILD_TEST_FAILURE",
        )

        assert failed.state == "failed"
        assert connection.execute(
            "SELECT state, last_error_code FROM deletion_queue_intents "
            "WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("FAILED", "REBUILD_TEST_FAILURE")
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("TOMBSTONED", "FAILED")
        with pytest.raises(RebuildCancellationRejected):
            jobs.cancel_before_activation(queued.job_id)

        jobs.requeue_failed(queued.job_id)
        resumed = jobs.claim_next()
        assert resumed is not None and resumed.attempt_count == 2
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents "
            "WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("CLAIMED", 2)
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("TOMBSTONED", "RUNNING")
    finally:
        connection.close()


def test_two_deletion_rebuild_intents_serialize_and_recover_own_stages(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path, "global")
    content_store = ContentStore(tmp_path / "parallel-intent-stage-cas")
    ids = _ids(110_000)
    authority = _seed_approved_deletion_authority(connection, ids)
    intent_ids = tuple(
        _seed_deletion_rebuild_intent(
            connection,
            authority,
            ids,
            tag=tag,
            target_version=index,
        )
        for index, tag in enumerate(("first", "second"), start=1)
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(111_000),
    )
    plan_and_approval = tuple(
        (
            _direct_rebuild_plan(
                source_intent_id=intent_id,
                tombstone_epoch=authority.tombstone_epoch,
            ),
            intent_id,
        )
        for intent_id in intent_ids
    )
    approved_plans = tuple(
        (
            plan,
            intent_id,
            _apply_rebuild_approval(
                connection,
                plan,
                content_store=content_store,
            ),
        )
        for plan, intent_id in plan_and_approval
    )
    queued = tuple(
        jobs.enqueue(
            RebuildJobCreate(
                database_scope="global",
                source_intent_id=intent_id,
                approval_operation_id=approval[0],
                approval_request_id=approval[1],
                plan_sha256=plan.plan_sha256,
                scope_sha256=SCOPE_HASH,
                purpose="all",
                builder_dag_sha256=POLICY_HASH,
                input_authority_versions_sha256=MODEL_HASH,
                policy_sha256=POLICY_HASH,
                model_descriptor_sha256=MODEL_HASH,
                tombstone_epoch=authority.tombstone_epoch,
            ),
            idempotency_key=f"parallel-intent-{index}",
        )
        for index, (plan, intent_id, approval) in enumerate(
            approved_plans,
            start=1,
        )
    )
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(112_000),
    )
    stage_by_job: dict[str, str] = {}
    try:
        for index, expected_job in enumerate(queued, start=1):
            running = jobs.claim_next()
            assert running is not None
            assert running.job_id == expected_job.job_id
            assert jobs.claim_next() is None
            artifact = BuiltArtifact.create(
                builder_id="global_wiki_render",
                output_purpose="wiki_render",
                version=index,
                payload=f"parallel-stage-{index}".encode("ascii"),
                semantic_fingerprint_sha256=canonical_sha256(
                    {"parallel-stage": index}
                ),
            )
            stage_ref = store.begin_empty_stage(
                job_id=running.job_id,
                output_purposes=(artifact.output_purpose,),
                tombstone_epoch=authority.tombstone_epoch,
            )
            stage_by_job[running.job_id] = stage_ref
            store.stage_artifact(stage_ref=stage_ref, artifact=artifact)
            jobs.mark_verifying(running.job_id)
            verification = store.verify_stage(
                stage_ref=stage_ref,
                output_purposes=("wiki_render",),
                tombstone_epoch=authority.tombstone_epoch,
            )
            jobs.mark_activating(
                running.job_id,
                output_manifest_set_sha256=(
                    verification.output_manifest_set_sha256
                ),
                equivalence_report_sha256=(
                    verification.equivalence_report.report_sha256
                ),
            )
            activating = jobs.claim_next()
            assert activating is not None
            assert activating.job_id == running.job_id
            restarted = SqliteCasRebuildArtifactStore(
                connection,
                database_scope="global",
                scope_sha256=SCOPE_HASH,
                content_store=content_store,
                clock=FixedClock(NOW),
                id_factory=_ids(113_000 + index * 100),
            )
            assert restarted.resume_stage(job_id=running.job_id) == stage_ref
            receipt = restarted.activate_atomically(
                stage_ref=stage_ref,
                output_manifest_set_sha256=(
                    verification.output_manifest_set_sha256
                ),
                tombstone_epoch=authority.tombstone_epoch,
            )
            assert not receipt.already_active
            assert jobs.mark_succeeded(running.job_id).state == "succeeded"

        assert len(set(stage_by_job.values())) == 2
        assert connection.execute(
            """
            SELECT count(*), count(DISTINCT job_id), count(DISTINCT operation_id)
              FROM rebuild_stage_bindings
            """
        ).fetchone() == (2, 2, 2)
        assert connection.execute(
            """
            SELECT count(*) FROM publication_operations
             WHERE purpose = 'rebuild' AND state = 'ACTIVE'
            """
        ).fetchone() == (2,)
        assert connection.execute(
            """
            SELECT count(*) FROM publication_operations
             WHERE purpose = 'rebuild' AND state = 'FAILED'
            """
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents ORDER BY intent_id"
        ).fetchall() == [("SUCCEEDED",), ("SUCCEEDED",)]
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
    finally:
        connection.close()
