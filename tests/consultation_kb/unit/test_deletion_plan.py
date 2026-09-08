from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.approvals.models import ApprovalExecutionTicket
from consultation_kb.lifecycle.deletion_plan import DeletionPlanBuilder
from consultation_kb.lifecycle.deletion import (
    DeletionApprovalMismatch,
    DeletionPlanStale,
    DeletionService,
)
from consultation_kb.models.deletion import (
    DELETION_ACTION_TYPES,
    DeletionAuthorityScope,
    DeletionBaseVersion,
    DeletionClosureNode,
    DeletionDependency,
    DeletionInventory,
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    DeletionTarget,
    DeletionTargetType,
    target_scope_sha256,
)
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
REQUEST_ID = "deletion_request_01890f9d-5b40-7abc-8def-1234567890ab"
CLIENT_ID = "client" + "_aaaaaaaaaaaa"
SESSION_ID = "01890f9d-5b40-7abc-8def-1234567890ab"


def _ref(
    kind: str,
    ordinal: int,
    *,
    scope: DeletionAuthorityScope = "global",
) -> DeletionObjectRef:
    return DeletionObjectRef(
        object_type=kind,
        object_id=f"{kind}_01890f9d-5b40-7abc-8def-{ordinal:012d}",
        version=ordinal,
        content_sha256=f"{ordinal:x}" * 64,
        authority_scope=scope,
    )


def _preview(
    target_type: DeletionTargetType, *, reason_code: str = "approved_deletion"
) -> tuple[DeletionPlan, DeletionObjectRef]:
    scope: DeletionAuthorityScope = (
        "client" if target_type == "session" else "global"
    )
    if target_type == "client":
        target_ref = DeletionObjectRef(
            object_type="client",
            object_id=CLIENT_ID,
            version=3,
            content_sha256="3" * 64,
            authority_scope="global",
        )
    elif target_type == "session":
        target_ref = DeletionObjectRef(
            object_type="session",
            object_id=SESSION_ID,
            version=3,
            content_sha256="3" * 64,
            authority_scope="client",
        )
    else:
        target_ref = _ref(target_type, 3, scope=scope)
    target = DeletionTarget(
        target_type=target_type,
        object_ref=target_ref,
        client_id=CLIENT_ID if target_type in {"client", "session"} else None,
        session_id=SESSION_ID if target_type == "session" else None,
    )
    authorization = _ref("case_authorization", 4)
    manifest = _ref("artifact_manifest", 5)
    backup = _ref("backup_object", 6)
    hosted = _ref("managed_task_control", 7)
    audit = _ref("deletion_audit_proof", 8)
    disconnected = _ref("cache_entry", 9)
    nodes = (
        DeletionClosureNode(
            object_ref=target_ref,
            role="authority",
            actions=("tombstone_now", "physical_delete"),
            authority_effect=("revoke_case" if target_type == "case" else "none"),
        ),
        DeletionClosureNode(
            object_ref=authorization,
            role="authorization",
            actions=("tombstone_now",),
            authority_effect="revoke_authorization",
        ),
        DeletionClosureNode(
            object_ref=manifest,
            role="active_manifest",
            actions=("tombstone_now", "physical_delete", "rebuild"),
        ),
        DeletionClosureNode(
            object_ref=backup,
            role="backup",
            actions=("backup_expiry",),
        ),
        DeletionClosureNode(
            object_ref=hosted,
            role="hosted_product",
            actions=("manual_product_action",),
        ),
        DeletionClosureNode(
            object_ref=audit,
            role="audit_proof",
            actions=(),
            retention="retain_body_free_audit",
        ),
        DeletionClosureNode(
            object_ref=disconnected,
            role="cache",
            actions=("physical_delete",),
        ),
    )
    dependencies = tuple(
        DeletionDependency(
            edge_id=f"edge_{index}",
            source_ref=target_ref,
            dependent_ref=dependent,
            relation="provenance" if index == 1 else "artifact_dependency",
        )
        for index, dependent in enumerate(
            (authorization, manifest, backup, hosted, audit), start=1
        )
    )
    inventory = DeletionInventory(
        nodes=nodes,
        dependencies=dependencies,
        active_manifest_refs=(manifest,),
        base_versions=(
            DeletionBaseVersion(
                authority_key="catalog",
                scope_sha256="a" * 64,
                version=11,
            ),
            DeletionBaseVersion(
                authority_key="authorization",
                scope_sha256="b" * 64,
                version=13,
            ),
        ),
        deletion_version=0,
        tombstone_epoch=0,
        authorization_epoch=0,
    )
    request = DeletionPreviewRequest(
        request_id=REQUEST_ID,
        target=target,
        reason_code=reason_code,
        requested_at=NOW,
    )
    return DeletionPlanBuilder().preview(request, inventory), disconnected


@pytest.mark.parametrize(
    "target_type", ("client", "session", "case", "passage", "claim")
)
def test_preview_is_body_free_exact_dependency_closure_with_five_action_types(
    target_type: DeletionTargetType,
) -> None:
    plan, disconnected = _preview(target_type)

    assert {action.action_type for action in plan.actions} == set(
        DELETION_ACTION_TYPES
    )
    assert disconnected not in {node.object_ref for node in plan.closure_nodes}
    assert plan.active_manifest_refs
    assert plan.retained_audit_refs
    assert plan.descriptor.purpose == "delete"
    assert plan.descriptor.target_id == plan.target.object_ref.object_id
    assert plan.descriptor.base_version == plan.base_deletion_version
    assert plan.descriptor.draft_sha256 == plan.plan_sha256
    assert plan.target_scope_hash == target_scope_sha256(plan.target)
    assert plan.next_deletion_version == plan.base_deletion_version + 1
    assert plan.next_tombstone_epoch == plan.base_tombstone_epoch + 1
    assert plan.next_authorization_epoch == plan.base_authorization_epoch + 1
    rendered = plan.model_dump_json()
    assert "synthetic consultation body" not in rendered
    assert "disconnected" not in rendered
    assert plan.hosted_product_task_state == "unchanged_requires_product_controls"


def test_plan_hash_binds_all_base_versions_and_exact_scope() -> None:
    plan, _ = _preview("case")

    with pytest.raises(ValueError, match="DELETION_PLAN_HASH_MISMATCH"):
        plan.model_copy(
            update={
                "base_versions": (
                    *plan.base_versions[:-1],
                    plan.base_versions[-1].model_copy(update={"version": 14}),
                )
            }
        )
    with pytest.raises(ValueError, match="DELETION_TARGET_SCOPE_MISMATCH"):
        plan.model_copy(update={"target_scope_hash": "f" * 64})


def _install_deletion_foundation(
    harness: ApprovalHarness, plan: DeletionPlan
) -> None:
    changed = harness.target_connection.execute(
        "UPDATE deletion_authority_state "
        "SET deletion_version = ?, tombstone_epoch = ? WHERE singleton = 1",
        (plan.base_deletion_version, plan.base_tombstone_epoch),
    ).rowcount
    assert changed == 1
    harness.target_connection.executemany(
        "INSERT INTO deletion_base_versions VALUES (?, ?, ?)",
        [
            (item.authority_key, item.scope_sha256, item.version)
            for item in plan.base_versions
        ],
    )


def _issue(
    harness: ApprovalHarness, plan: DeletionPlan
) -> ApprovalExecutionTicket:
    request = harness.service.request(
        plan.descriptor,
        diff_object_ref=harness.diff_object_ref(),
    )
    event = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    harness.service.confirm(event)
    return harness.service.issue_for_execution(
        request.request_id,
        plan.descriptor,
        operation_id=harness.operation_id(),
    )


def test_guarded_commit_keeps_tombstones_and_pending_queue_when_wake_fails(
    tmp_path: Path,
) -> None:
    plan, _ = _preview("case")
    harness = build_approval_harness(
        tmp_path, target_scope_hash=plan.target_scope_hash
    )
    try:
        _install_deletion_foundation(harness, plan)
        ticket = _issue(harness, plan)

        def fail_wake(_request_id: str) -> None:
            raise RuntimeError("synthetic queue transport outage")

        result = DeletionService(
            harness.target_connection,
            approval_guard=harness.guard,
            clock=harness.clock,
            queue_waker=fail_wake,
        ).commit_tombstone(plan, ticket)

        tombstone_actions = [
            action for action in plan.actions if action.action_type == "tombstone_now"
        ]
        queued_actions = [
            action
            for action in plan.actions
            if action.action_type
            in {"physical_delete", "rebuild", "backup_expiry"}
        ]
        assert result.tombstone_committed
        assert result.queue_wake_state == "pending"
        assert result.deletion_version == plan.next_deletion_version
        assert result.tombstone_epoch == plan.next_tombstone_epoch
        assert result.authorization_epoch == plan.next_authorization_epoch
        assert harness.target_connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone() == (plan.next_deletion_version, plan.next_tombstone_epoch)
        assert harness.target_connection.execute(
            "SELECT count(*) FROM tombstones"
        ).fetchone() == (len(tombstone_actions),)
        assert harness.target_connection.execute(
            "SELECT effect FROM deletion_revocations ORDER BY effect"
        ).fetchall() == [("revoke_authorization",), ("revoke_case",)]
        assert harness.target_connection.execute(
            "SELECT count(*) FROM deletion_queue_intents WHERE state = 'PENDING'"
        ).fetchone() == (len(queued_actions),)
        assert harness.target_connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("TOMBSTONED", "PENDING")
        assert harness.target_connection.execute(
            "SELECT state FROM approval_executions"
        ).fetchone() == ("APPLIED",)
    finally:
        harness.close()


def test_commit_rejects_wrong_exact_plan_and_stale_base_inside_guard(
    tmp_path: Path,
) -> None:
    plan, _ = _preview("case")
    harness = build_approval_harness(
        tmp_path, target_scope_hash=plan.target_scope_hash
    )
    try:
        _install_deletion_foundation(harness, plan)
        ticket = _issue(harness, plan)
        service = DeletionService(
            harness.target_connection,
            approval_guard=harness.guard,
            clock=harness.clock,
        )

        wrong_plan, _ = _preview("case", reason_code="different_deletion_reason")
        with pytest.raises(
            DeletionApprovalMismatch, match="DELETION_APPROVAL_MISMATCH"
        ):
            service.commit_tombstone(wrong_plan, ticket)

        stale = plan.base_versions[0]
        harness.target_connection.execute(
            "UPDATE deletion_base_versions SET version = version + 1 "
            "WHERE authority_key = ? AND scope_sha256 = ?",
            (stale.authority_key, stale.scope_sha256),
        )
        with pytest.raises(DeletionPlanStale, match="DELETION_BASE_VERSION_STALE"):
            service.commit_tombstone(plan, ticket)

        assert harness.target_connection.execute(
            "SELECT count(*) FROM approval_executions"
        ).fetchone() == (0,)
        assert harness.target_connection.execute(
            "SELECT count(*) FROM deletion_requests"
        ).fetchone() == (0,)
        assert harness.target_connection.execute(
            "SELECT count(*) FROM tombstones"
        ).fetchone() == (0,)
    finally:
        harness.close()
