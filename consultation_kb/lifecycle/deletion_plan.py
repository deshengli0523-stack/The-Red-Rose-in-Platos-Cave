"""Deterministic deletion previews over explicit provenance/dependency edges."""

from __future__ import annotations

from collections import deque

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.deletion import (
    DELETION_ACTION_TYPES,
    DeletionAction,
    DeletionActionType,
    DeletionClosureNode,
    DeletionDependency,
    DeletionInventory,
    DeletionPlan,
    DeletionPreviewRequest,
    deletion_ref_key,
    target_scope_sha256,
)
from consultation_kb.models.manifests import DraftDescriptor


class DeletionPlanError(RuntimeError):
    def __init__(self, code: str = "DELETION_PLAN_INVALID") -> None:
        self.code = code
        super().__init__(code)


def _scoped_object_id(request_id: str, kind: str, ordinal: int) -> str:
    return f"{kind}_{ordinal:04d}_{request_id[-36:]}"


class DeletionPlanBuilder:
    """Compute reachability only from supplied provenance/artifact edges."""

    def preview(
        self,
        request: DeletionPreviewRequest,
        inventory: DeletionInventory,
    ) -> DeletionPlan:
        requested = DeletionPreviewRequest.model_validate(request)
        snapshot = DeletionInventory.model_validate(inventory)
        target_key = deletion_ref_key(requested.target.object_ref)
        nodes = {deletion_ref_key(node.object_ref): node for node in snapshot.nodes}
        if target_key not in nodes:
            raise DeletionPlanError("DELETION_TARGET_NOT_IN_INVENTORY")

        outgoing: dict[tuple[str, str, int, str, str], list[DeletionDependency]] = {}
        for edge in snapshot.dependencies:
            outgoing.setdefault(deletion_ref_key(edge.source_ref), []).append(edge)
        for values in outgoing.values():
            values.sort(key=lambda value: value.edge_id)

        paths: dict[tuple[str, str, int, str, str], tuple[str, ...]] = {
            target_key: ()
        }
        pending = deque((target_key,))
        while pending:
            source = pending.popleft()
            for edge in outgoing.get(source, ()):
                dependent = deletion_ref_key(edge.dependent_ref)
                if dependent in paths:
                    continue
                paths[dependent] = (*paths[source], edge.edge_id)
                pending.append(dependent)

        closure_nodes = tuple(
            sorted(
                (nodes[key] for key in paths),
                key=lambda node: deletion_ref_key(node.object_ref),
            )
        )
        closure_keys = set(paths)
        closure_edges = tuple(
            sorted(
                (
                    edge
                    for edge in snapshot.dependencies
                    if deletion_ref_key(edge.source_ref) in closure_keys
                    and deletion_ref_key(edge.dependent_ref) in closure_keys
                ),
                key=lambda edge: edge.edge_id,
            )
        )
        active_manifest_refs = tuple(
            sorted(
                (
                    ref
                    for ref in snapshot.active_manifest_refs
                    if deletion_ref_key(ref) in closure_keys
                ),
                key=deletion_ref_key,
            )
        )
        retained_audit_refs = tuple(
            node.object_ref
            for node in closure_nodes
            if node.retention == "retain_body_free_audit"
        )

        action_order = {
            name: index for index, name in enumerate(DELETION_ACTION_TYPES)
        }
        action_specs: list[
            tuple[int, DeletionClosureNode, DeletionActionType]
        ] = []
        for node in closure_nodes:
            for action_type in node.actions:
                action_specs.append((action_order[action_type], node, action_type))
        action_specs.sort(
            key=lambda item: (
                item[0],
                deletion_ref_key(item[1].object_ref),
            )
        )
        actions = tuple(
            DeletionAction(
                action_id=_scoped_object_id(
                    requested.request_id, "deletion_action", ordinal
                ),
                action_type=action_type,
                target_ref=node.object_ref,
                authority_effect=node.authority_effect,
                path_edge_ids=paths[deletion_ref_key(node.object_ref)],
                reason_code=requested.reason_code,
            )
            for ordinal, (_order, node, action_type) in enumerate(
                action_specs, start=1
            )
        )
        authorization_delta = int(
            any(action.authority_effect != "none" for action in actions)
        )
        base_versions = tuple(
            sorted(
                snapshot.base_versions,
                key=lambda item: (item.authority_key, item.scope_sha256),
            )
        )
        target_scope_hash = target_scope_sha256(requested.target)
        material: dict[str, object] = {
            "request_id": requested.request_id,
            "created_at": requested.requested_at,
            "target": requested.target,
            "reason_code": requested.reason_code,
            "target_scope_hash": target_scope_hash,
            "base_versions": base_versions,
            "base_deletion_version": snapshot.deletion_version,
            "next_deletion_version": snapshot.deletion_version + 1,
            "base_tombstone_epoch": snapshot.tombstone_epoch,
            "next_tombstone_epoch": snapshot.tombstone_epoch + 1,
            "base_authorization_epoch": snapshot.authorization_epoch,
            "next_authorization_epoch": (
                snapshot.authorization_epoch + authorization_delta
            ),
            "closure_nodes": closure_nodes,
            "closure_edges": closure_edges,
            "active_manifest_refs": active_manifest_refs,
            "pending_case_index_invalidation": (
                snapshot.pending_case_index_invalidation
            ),
            "retained_audit_refs": retained_audit_refs,
            "actions": actions,
            "local_retrieval_state_after_commit": "blocked_by_tombstone",
            "physical_cleanup_state_after_commit": "pending",
            "hosted_product_task_state": "unchanged_requires_product_controls",
        }
        unhashed = DeletionPlan.model_construct(
            request_id=requested.request_id,
            created_at=requested.requested_at,
            target=requested.target,
            reason_code=requested.reason_code,
            target_scope_hash=target_scope_hash,
            base_versions=base_versions,
            base_deletion_version=snapshot.deletion_version,
            next_deletion_version=snapshot.deletion_version + 1,
            base_tombstone_epoch=snapshot.tombstone_epoch,
            next_tombstone_epoch=snapshot.tombstone_epoch + 1,
            base_authorization_epoch=snapshot.authorization_epoch,
            next_authorization_epoch=(
                snapshot.authorization_epoch + authorization_delta
            ),
            closure_nodes=closure_nodes,
            closure_edges=closure_edges,
            active_manifest_refs=active_manifest_refs,
            pending_case_index_invalidation=(
                snapshot.pending_case_index_invalidation
            ),
            retained_audit_refs=retained_audit_refs,
            actions=actions,
            local_retrieval_state_after_commit="blocked_by_tombstone",
            physical_cleanup_state_after_commit="pending",
            hosted_product_task_state="unchanged_requires_product_controls",
            plan_sha256="0" * 64,
            descriptor=DraftDescriptor(
                purpose="delete",
                target_id=requested.target.object_ref.object_id,
                client_id=requested.target.client_id,
                session_id=requested.target.session_id,
                base_version=snapshot.deletion_version,
                draft_sha256="0" * 64,
            ),
        )
        plan_sha256 = canonical_sha256(
            unhashed.model_dump(mode="json", exclude={"descriptor", "plan_sha256"})
        )
        descriptor = DraftDescriptor(
            purpose="delete",
            target_id=requested.target.object_ref.object_id,
            client_id=requested.target.client_id,
            session_id=requested.target.session_id,
            base_version=snapshot.deletion_version,
            draft_sha256=plan_sha256,
        )
        return DeletionPlan.model_validate(
            {**material, "plan_sha256": plan_sha256, "descriptor": descriptor}
        )


__all__ = ["DeletionPlanBuilder", "DeletionPlanError"]
