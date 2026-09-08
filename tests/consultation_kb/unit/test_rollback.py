from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    ApprovalRequest,
)
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.lifecycle.rebuild import (
    BuildContext,
    BuiltArtifact,
    RebuildCoordinator,
    SqliteRebuildAuthoritySource,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.lifecycle.rebuild_registry import (
    BuilderDescriptor,
    BuilderRegistry,
)
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.lifecycle.rollback import (
    ArtifactRollbackPlan,
    FactRollbackPlan,
    RollbackError,
    RollbackPlanEnvelope,
    RollbackPlanner,
    SqliteRollbackWorkflow,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.facts import FactEvent, canonical_json
from consultation_kb.storage.client_ledger import FactEventRepository
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestMember,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import lineage_hash
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
NOW_TEXT = "2026-07-22T08:00:00.000000Z"
CLIENT_ID = "client" + "_aaaaaaaaaaaa"
SCOPE_SHA256 = "a" * 64
POLICY_SHA256 = "b" * 64


@dataclass(frozen=True, slots=True)
class _NeverBuilder:
    descriptor: BuilderDescriptor

    def build(self, context: BuildContext) -> BuiltArtifact:
        del context
        raise AssertionError("queued rollback rebuild must not run synchronously")


@dataclass(slots=True)
class _ClientFixture:
    approval: ApprovalHarness
    store: ContentStore
    workflow: SqliteRollbackWorkflow
    restore: FactEvent
    current: FactEvent

    def close(self) -> None:
        self.approval.close()


def _fact(
    harness: ApprovalHarness,
    *,
    version: int,
    value: str,
    previous: FactEvent | None,
) -> FactEvent:
    event_id = harness.ids.object_id("fact_event")
    return FactEvent.model_validate(
        {
            "event_id": event_id,
            "fact_id": "relationship.current_partner",
            "client_id": CLIENT_ID,
            "event_version": version,
            "mutation_type": "ADD" if version == 1 else "CORRECT",
            "canonical_key": "relationship.current_partner",
            "subject": "visitor",
            "predicate": "current_partner",
            "object_json": canonical_json({"alias": value}),
            "cognitive_type": "external_fact",
            "source_kind": "controlled_import",
            "source_session_id": None,
            "source_turn_id": None,
            "source_ref": "controlled-import",
            "effective_from": NOW,
            "effective_to": None,
            "time_precision": "instant",
            "timezone_name": "Asia/Shanghai",
            "recorded_at": NOW,
            "approved_at": NOW,
            "reported_at": None,
            "observed_at": None,
            "transaction_id": harness.ids.object_id("transaction"),
            "commit_version": version,
            "publication_operation_id": harness.ids.object_id(
                "publication_operation"
            ),
            "visible_runtime_epoch": min(version, 2),
            "review_status": "approved",
            "validity_status": "active",
            "resolution_status": "open",
            "epistemic_status": "asserted",
            "fact_confidence": 1.0,
            "model_confidence": None,
            "reviewer_id": "primary-counselor",
            "review_reason": "verified",
            "review_source": "local-review",
            "privacy_level": "private_client",
            "allowed_purposes_json": canonical_json(
                ["consultation", "next_session_context"]
            ),
            "applicability_json": canonical_json({"status": "current"}),
            "source_anchor_json": canonical_json({"kind": "controlled"}),
            "supersedes_event_id": None,
            "previous_event_id": None if previous is None else previous.event_id,
            "replacement_event_id": None,
            "source_event_ids": (
                () if previous is None else (previous.event_id,)
            ),
            "relation_type": None,
        }
    )


def _seed_facts(harness: ApprovalHarness) -> tuple[FactEvent, FactEvent]:
    repository = FactEventRepository(harness.target_connection)
    restore = _fact(harness, version=1, value="partner-a", previous=None)
    repository.append(restore)
    current = _fact(harness, version=2, value="partner-b", previous=restore)
    repository.append(current)
    return restore, current


def _seed_runtime_only(harness: ApprovalHarness, *, epoch: int = 2) -> None:
    operation_id = harness.ids.object_id("publication_operation")
    request_id = harness.ids.object_id("approval_request")
    harness.target_connection.execute(
        "INSERT INTO publication_operations("
        "operation_id,purpose,authority_base_version,approval_request_id,"
        "descriptor_sha256,state,required_manifests_json,"
        "required_manifest_count,verified_manifest_count,expected_current_epoch,"
        "runtime_epoch,created_at,activated_at"
        ") VALUES (?, 'profile_update', 2, ?, ?, 'ACTIVE', '[]', 0, 0, "
        "NULL, ?, ?, ?)",
        (operation_id, request_id, "1" * 64, epoch, NOW_TEXT, NOW_TEXT),
    )
    harness.target_connection.execute(
        "INSERT INTO runtime_epochs(epoch,operation_id,state,created_at,activated_at) "
        "VALUES (?, ?, 'ACTIVE', ?, ?)",
        (epoch, operation_id, NOW_TEXT, NOW_TEXT),
    )


def _coordinator(
    harness: ApprovalHarness,
    store: ContentStore,
) -> RebuildCoordinator:
    registry = BuilderRegistry.default()
    builders = {
        descriptor.builder_id: _NeverBuilder(descriptor)
        for descriptor in registry.descriptors
        if descriptor.database_scope == "client"
    }
    return RebuildCoordinator(
        registry=registry,
        jobs=RebuildJobRepository(
            harness.target_connection,
            database_scope="client",
            id_factory=harness.ids,
            clock=harness.clock,
        ),
        authority=SqliteRebuildAuthoritySource(
            harness.target_connection,
            database_scope="client",
            scope_sha256=SCOPE_SHA256,
            content_store=store,
        ),
        artifact_store=object(),  # type: ignore[arg-type]
        builders=builders,
    )


def _fixture(tmp_path: Path, *, closure: bool = False) -> _ClientFixture:
    approval = build_approval_harness(tmp_path, target_scope_hash=SCOPE_SHA256)
    store = ContentStore(tmp_path / "client-vault")
    restore, current = _seed_facts(approval)
    if closure:
        _seed_closure(
            approval,
            store,
            source_version=1,
            epoch=1,
            state="RETIRED",
            fact_events=(restore,),
        )
        _seed_closure(
            approval,
            store,
            source_version=2,
            epoch=2,
            state="ACTIVE",
            fact_events=(restore, current),
        )
    else:
        _seed_runtime_only(approval)
    workflow = SqliteRollbackWorkflow(
        approval.target_connection,
        database_scope="client",
        scope_sha256=SCOPE_SHA256,
        content_store=store,
        clock=approval.clock,
        id_factory=approval.ids,
        approval_guard=approval.guard,
        rebuild_coordinator=_coordinator(approval, store),
        rebuild_policy_sha256=POLICY_SHA256,
        bound_session_id=approval.ids.uuid7(),
    )
    return _ClientFixture(approval, store, workflow, restore, current)


def _approve(
    fixture: _ClientFixture,
    *,
    descriptor,
    plan_ref,
    operation_id: str,
) -> tuple[ApprovalRequest, ApprovalExecutionTicket]:
    request = fixture.approval.service.request(
        descriptor,
        diff_object_ref=plan_ref.version_ref,
    )
    fixture.approval.service.confirm(
        fixture.approval.signer.confirm(
            fixture.approval.service.challenge_for_review(request.request_id)
        )
    )
    ticket = fixture.approval.service.issue_for_execution(
        request.request_id,
        descriptor,
        operation_id=operation_id,
    )
    return request, ticket


def _read_envelope(
    fixture: _ClientFixture,
    plan_ref,
) -> RollbackPlanEnvelope:
    payload = fixture.store.read_verified(
        fixture.store.reference(
            content_sha256=plan_ref.content_sha256,
            media_type=plan_ref.media_type,
            size_bytes=plan_ref.size_bytes,
        )
    )
    return RollbackPlanEnvelope.model_validate_json(payload, strict=True)


def test_fact_rollback_is_exact_append_only_and_replay_safe(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        preview = fixture.workflow.preview_profile_fact(
            fact_id=fixture.current.fact_id,
            current_version=2,
            restore_version=1,
            reason="visitor corrected the current relationship",
        )
        envelope = _read_envelope(fixture, preview.plan_ref)
        assert isinstance(envelope.plan, FactRollbackPlan)
        plan = envelope.plan
        assert plan.inverse_mutation.previous_value_json == fixture.current.object_json
        assert plan.inverse_mutation.new_value_json == fixture.restore.object_json
        assert plan.new_event.event_version == 3
        assert plan.rebuild_plan.purpose == "all"
        assert set(plan.rebuild_plan.builder_ids) == {
            "client_fact_snapshot",
            "client_profile",
            "client_graph",
            "private_archive",
        }

        request, ticket = _approve(
            fixture,
            descriptor=preview.descriptor,
            plan_ref=preview.plan_ref,
            operation_id=preview.proposed_operation_id,
        )
        committed = fixture.workflow.commit(
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            base_versions=preview.base_versions,
            ticket=ticket,
            approval_request=request,
        )
        replay = fixture.workflow.commit(
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            base_versions=preview.base_versions,
            ticket=ticket,
            approval_request=request,
        )

        latest = FactEventRepository(
            fixture.approval.target_connection
        ).get_latest_event(fixture.current.fact_id)
        assert latest == plan.new_event
        assert latest.object_json == fixture.restore.object_json
        assert committed.summary == replay.summary
        assert committed.summary.rebuild_job_id is not None
        job = RebuildJobRepository(
            fixture.approval.target_connection,
            database_scope="client",
        ).get(committed.summary.rebuild_job_id)
        assert job.purpose == "all"
        assert job.approval_operation_id == ticket.operation_id
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (3,)
    finally:
        fixture.close()


def test_commit_requires_the_exact_approval_diff_request(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        preview = fixture.workflow.preview_profile_fact(
            fact_id=fixture.current.fact_id,
            current_version=2,
            restore_version=1,
            reason="restore reviewed fact",
        )
        request, ticket = _approve(
            fixture,
            descriptor=preview.descriptor,
            plan_ref=preview.plan_ref,
            operation_id=preview.proposed_operation_id,
        )
        forged = request.model_copy(
            update={
                "diff_object_ref": VersionRef(
                    object_id=fixture.approval.ids.object_id("lifecycle_plan"),
                    version=1,
                    content_sha256="f" * 64,
                )
            }
        )
        with pytest.raises(
            RollbackError,
            match="ROLLBACK_APPROVAL_BINDING_MISMATCH",
        ):
            fixture.workflow.commit(
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                base_versions=preview.base_versions,
                ticket=ticket,
                approval_request=forged,
            )
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (2,)
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM rebuild_jobs"
        ).fetchone() == (0,)
    finally:
        fixture.close()


def test_authority_drift_rolls_back_claim_and_writes_nothing(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        preview = fixture.workflow.preview_profile_fact(
            fact_id=fixture.current.fact_id,
            current_version=2,
            restore_version=1,
            reason="restore reviewed fact",
        )
        request, ticket = _approve(
            fixture,
            descriptor=preview.descriptor,
            plan_ref=preview.plan_ref,
            operation_id=preview.proposed_operation_id,
        )
        fixture.approval.target_connection.execute(
            "UPDATE deletion_authority_state "
            "SET deletion_version = 1, tombstone_epoch = 1 "
            "WHERE singleton = 1"
        )
        with pytest.raises(RollbackError, match="ROLLBACK_AUTHORITY_CHANGED"):
            fixture.workflow.commit(
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                base_versions=preview.base_versions,
                ticket=ticket,
                approval_request=request,
            )
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (2,)
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM rebuild_jobs"
        ).fetchone() == (0,)
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM approval_executions"
        ).fetchone() == (0,)
    finally:
        fixture.close()


def _seed_closure(
    harness: ApprovalHarness,
    store: ContentStore,
    *,
    source_version: int,
    epoch: int,
    state: str,
    fact_events: tuple[FactEvent, ...],
) -> tuple[ArtifactManifest, ...]:
    keys = (
        "client_fact_snapshot",
        "client_graph",
        "client_profile",
        "private_archive",
    )
    operation_id = harness.ids.object_id("publication_operation")
    manifest_ids = {key: harness.ids.object_id("artifact_manifest") for key in keys}
    required = tuple(sorted(manifest_ids.values()))
    harness.target_connection.execute(
        "INSERT INTO publication_operations("
        "operation_id,purpose,authority_base_version,approval_request_id,"
        "descriptor_sha256,state,required_manifests_json,"
        "required_manifest_count,verified_manifest_count,expected_current_epoch,"
        "runtime_epoch,created_at,activated_at"
        ") VALUES (?, 'rebuild', ?, ?, ?, 'PREPARED', ?, ?, 0, ?, NULL, ?, NULL)",
        (
            operation_id,
            source_version,
            harness.ids.object_id("approval_request"),
            str(source_version) * 64,
            json.dumps(required, separators=(",", ":")),
            len(required),
            None if epoch == 1 else epoch - 1,
            NOW_TEXT,
        ),
    )
    repository = ManifestRepository(harness.target_connection)
    manifests: list[ArtifactManifest] = []
    for key in keys:
        payload = canonical_json_bytes(
            {"artifact_key": key, "source_version": source_version}
        )
        stored = store.finalize(
            store.stage_bytes(
                payload,
                purpose="rebuild_artifact",
                manifest_id=manifest_ids[key],
                media_type="application/json",
            )
        )
        lineage = (
            ()
            if key == "private_archive"
            else tuple(
                sorted(
                    lineage_hash("fact_event", event.event_id)
                    for event in fact_events
                )
            )
        )
        manifest = repository.insert_prepared(
            manifest_id=manifest_ids[key],
            operation_id=operation_id,
            artifact_key=key,
            artifact_kind=key,
            source_version=source_version,
            members=(
                ManifestMember(
                    ordinal=0,
                    object_type=f"{key}_member",
                    object_id=harness.ids.object_id(f"{key}_member"),
                    object_sha256=stored.content_sha256,
                    source_version=source_version,
                    media_type=stored.media_type,
                    size_bytes=stored.size_bytes,
                    source_lineage_hashes=lineage,
                ),
            ),
            created_at=NOW_TEXT,
        )
        repository.mark_verified(
            manifest.manifest_id,
            expected_source_version=source_version,
            verified_at=NOW_TEXT,
        )
        harness.target_connection.execute(
            "UPDATE artifact_manifests SET state = 'ACTIVE' WHERE manifest_id = ?",
            (manifest.manifest_id,),
        )
        manifests.append(repository.get(manifest.manifest_id))
    harness.target_connection.execute(
        "UPDATE publication_operations SET state = 'ACTIVE', "
        "verified_manifest_count = ?, runtime_epoch = ?, activated_at = ? "
        "WHERE operation_id = ?",
        (len(keys), epoch, NOW_TEXT, operation_id),
    )
    approval_draft_sha256 = f"{source_version + 7:x}" * 64
    closure_sha256 = publication_closure_sha256(
        purpose="rebuild",
        authority_base_version=source_version,
        expected_current_epoch=None if epoch == 1 else epoch - 1,
        artifacts=tuple(manifests),
    )
    request_id, descriptor_sha256 = harness.target_connection.execute(
        "SELECT approval_request_id, descriptor_sha256 "
        "FROM publication_operations WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    harness.target_connection.execute(
        "INSERT INTO publication_closure_attestations("
        "operation_id, approval_draft_sha256, closure_sha256, created_at) "
        "VALUES (?, ?, ?, ?)",
        (operation_id, approval_draft_sha256, closure_sha256, NOW_TEXT),
    )
    harness.target_connection.execute(
        "INSERT INTO approval_executions("
        "operation_id, request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, nonce_sha256, state, "
        "applied_commit_version, applied_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)",
        (
            operation_id,
            request_id,
            descriptor_sha256,
            approval_draft_sha256,
            source_version - 1,
            SCOPE_SHA256,
            f"{source_version + 3:x}" * 64,
        ),
    )
    harness.target_connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = ?, applied_at = ? WHERE operation_id = ?",
        (source_version, NOW_TEXT, operation_id),
    )
    harness.target_connection.execute(
        "INSERT INTO runtime_epochs(epoch,operation_id,state,created_at,activated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (epoch, operation_id, state, NOW_TEXT, NOW_TEXT),
    )
    for manifest in manifests:
        harness.target_connection.execute(
            "INSERT INTO active_artifacts(epoch,artifact_key,manifest_id,activated_at) "
            "VALUES (?, ?, ?, ?)",
            (epoch, manifest.artifact_key, manifest.manifest_id, NOW_TEXT),
        )
    return tuple(manifests)


def test_artifact_rollback_consumes_source_plan_and_queues_full_closure(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, closure=True)
    try:
        reason = "restore source authority and rebuild the whole client closure"
        source = fixture.workflow.preview_profile_fact(
            fact_id=fixture.current.fact_id,
            current_version=2,
            restore_version=1,
            reason=reason,
        )
        artifact = fixture.workflow.preview_artifact(
            artifact_key="client_profile",
            current_version=2,
            restore_version=1,
            reason=reason,
            source_plan_ref=source.plan_ref,
        )
        envelope = _read_envelope(fixture, artifact.plan_ref)
        assert isinstance(envelope.plan, ArtifactRollbackPlan)
        plan = envelope.plan
        assert tuple(root.artifact_key for root in plan.current_closure) == (
            "client_fact_snapshot",
            "client_graph",
            "client_profile",
            "private_archive",
        )
        assert plan.source_plan_ref == source.plan_ref
        assert plan.new_source_version == 3
        assert plan.full_closure_purpose == "all"

        request, ticket = _approve(
            fixture,
            descriptor=artifact.descriptor,
            plan_ref=artifact.plan_ref,
            operation_id=artifact.proposed_operation_id,
        )
        committed = fixture.workflow.commit(
            plan_ref=artifact.plan_ref,
            plan_sha256=artifact.plan_sha256,
            base_versions=artifact.base_versions,
            ticket=ticket,
            approval_request=request,
        )
        assert committed.summary.rollback_kind == "artifact"
        assert committed.summary.rebuild_job_id is not None
        assert committed.summary.requires_combined_publication is False
        assert FactEventRepository(
            fixture.approval.target_connection
        ).get_latest_event(fixture.current.fact_id).object_json == (
            fixture.restore.object_json
        )
        job = RebuildJobRepository(
            fixture.approval.target_connection,
            database_scope="client",
        ).get(committed.summary.rebuild_job_id)
        assert job.purpose == "all"
        assert job.plan_sha256 == _read_envelope(
            fixture, source.plan_ref
        ).plan.rebuild_plan.plan_sha256  # type: ignore[union-attr]
    finally:
        fixture.close()


def test_artifact_rollback_rejects_unrelated_source_plan_without_write(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, closure=True)
    try:
        reason = "unrelated private archive rewind"
        source = fixture.workflow.preview_profile_fact(
            fact_id=fixture.current.fact_id,
            current_version=2,
            restore_version=1,
            reason=reason,
        )
        before = fixture.approval.target_connection.execute(
            "SELECT count(*) FROM lifecycle_plan_objects"
        ).fetchone()
        with pytest.raises(
            RollbackError,
            match="ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH",
        ):
            fixture.workflow.preview_artifact(
                artifact_key="private_archive",
                current_version=2,
                restore_version=1,
                reason=reason,
                source_plan_ref=source.plan_ref,
            )
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM lifecycle_plan_objects"
        ).fetchone() == before
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (2,)
    finally:
        fixture.close()


def test_legacy_single_root_apis_fail_closed_and_write_nothing(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, closure=True)
    try:
        repository = ManifestRepository(fixture.approval.target_connection)
        current = repository.get_active("client_profile", epoch=2)
        restore = repository.get_active("client_profile", epoch=1)
        count = fixture.approval.target_connection.execute(
            "SELECT count(*) FROM artifact_manifests"
        ).fetchone()
        with pytest.raises(
            RollbackError,
            match="ROLLBACK_ARTIFACT_FULL_REBUILD_REQUIRED",
        ):
            RollbackPlanner().artifact(
                operation_id=fixture.approval.ids.object_id("rollback_operation"),
                new_manifest_id=fixture.approval.ids.object_id("artifact_manifest"),
                current=current,
                restore=restore,
                reason="unsafe single root",
                client_id=CLIENT_ID,
            )
        with pytest.raises(
            RollbackError,
            match="ROLLBACK_ARTIFACT_SINGLE_ROOT_FORBIDDEN",
        ):
            RollbackPlanner().insert_prepared_artifact(
                repository,
                plan=None,  # type: ignore[arg-type]
                created_at=NOW_TEXT,
            )
        assert fixture.approval.target_connection.execute(
            "SELECT count(*) FROM artifact_manifests"
        ).fetchone() == count
    finally:
        fixture.close()
