"""Body-free deletion preview, approval, and queue contracts."""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import field_validator, model_validator

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.manifests import DraftDescriptor


DeletionTargetType: TypeAlias = Literal[
    "client", "session", "case", "case_authorization", "passage", "claim"
]
DeletionAuthorityScope: TypeAlias = Literal["global", "client"]
DeletionActionType: TypeAlias = Literal[
    "tombstone_now",
    "physical_delete",
    "rebuild",
    "backup_expiry",
    "manual_product_action",
]
DELETION_ACTION_TYPES: tuple[DeletionActionType, ...] = (
    "tombstone_now",
    "physical_delete",
    "rebuild",
    "backup_expiry",
    "manual_product_action",
)
DeletionAuthorityEffect: TypeAlias = Literal[
    "none", "revoke_case", "revoke_authorization"
]
DeletionRetention: TypeAlias = Literal[
    "delete_or_rebuild", "retain_body_free_audit"
]


class DeletionObjectRef(StrictModel):
    """Exact metadata reference; it deliberately has no body/content field."""

    object_type: SafePolicyKey
    object_id: NonEmptyStr
    version: NonNegativeInt
    content_sha256: Sha256Hex
    authority_scope: DeletionAuthorityScope


def deletion_ref_key(value: DeletionObjectRef) -> tuple[str, str, int, str, str]:
    exact = DeletionObjectRef.model_validate(value)
    return (
        exact.authority_scope,
        exact.object_type,
        exact.version,
        exact.object_id,
        exact.content_sha256,
    )


class DeletionTarget(StrictModel):
    target_type: DeletionTargetType
    object_ref: DeletionObjectRef
    client_id: ClientId | None = None
    session_id: Uuid7String | None = None

    @model_validator(mode="after")
    def _exact_scope(self) -> "DeletionTarget":
        if self.object_ref.object_type != self.target_type:
            raise ValueError("DELETION_TARGET_TYPE_MISMATCH")
        if self.target_type == "client":
            if (
                self.object_ref.authority_scope != "global"
                or self.client_id != self.object_ref.object_id
                or self.session_id is not None
            ):
                raise ValueError("DELETION_CLIENT_SCOPE_INVALID")
        elif self.target_type == "session":
            if (
                self.object_ref.authority_scope != "client"
                or self.client_id is None
                or self.session_id != self.object_ref.object_id
            ):
                raise ValueError("DELETION_SESSION_SCOPE_INVALID")
        elif self.client_id is not None or self.session_id is not None:
            raise ValueError("DELETION_GLOBAL_TARGET_SCOPE_INVALID")
        return self


def target_scope_sha256(value: DeletionTarget) -> str:
    exact = DeletionTarget.model_validate(value)
    return canonical_sha256(
        {
            "authority_scope": exact.object_ref.authority_scope,
            "client_id": exact.client_id,
            "object_id": exact.object_ref.object_id,
            "session_id": exact.session_id,
            "target_type": exact.target_type,
        }
    )


class DeletionClosureNode(StrictModel):
    object_ref: DeletionObjectRef
    role: SafePolicyKey
    actions: tuple[DeletionActionType, ...]
    authority_effect: DeletionAuthorityEffect = "none"
    retention: DeletionRetention = "delete_or_rebuild"

    @field_validator("actions")
    @classmethod
    def _canonical_actions(
        cls, value: tuple[DeletionActionType, ...]
    ) -> tuple[DeletionActionType, ...]:
        if len(value) != len(set(value)):
            raise ValueError("DELETION_ACTION_DUPLICATE")
        order = {name: index for index, name in enumerate(DELETION_ACTION_TYPES)}
        return tuple(sorted(value, key=order.__getitem__))

    @model_validator(mode="after")
    def _valid_disposition(self) -> "DeletionClosureNode":
        if self.retention == "retain_body_free_audit":
            if self.role != "audit_proof" or self.actions:
                raise ValueError("DELETION_AUDIT_RETENTION_INVALID")
        elif not self.actions:
            raise ValueError("DELETION_NODE_ACTION_REQUIRED")
        if self.authority_effect != "none" and "tombstone_now" not in self.actions:
            raise ValueError("DELETION_AUTHORITY_EFFECT_REQUIRES_TOMBSTONE")
        if self.role == "hosted_product" and self.actions != (
            "manual_product_action",
        ):
            raise ValueError("DELETION_HOSTED_PRODUCT_ACTION_INVALID")
        return self


class DeletionDependency(StrictModel):
    """An explicit provenance/artifact edge, never an inferred file match."""

    edge_id: NonEmptyStr
    source_ref: DeletionObjectRef
    dependent_ref: DeletionObjectRef
    relation: SafePolicyKey

    @model_validator(mode="after")
    def _not_self(self) -> "DeletionDependency":
        if deletion_ref_key(self.source_ref) == deletion_ref_key(self.dependent_ref):
            raise ValueError("DELETION_DEPENDENCY_SELF_EDGE")
        return self


class DeletionBaseVersion(StrictModel):
    authority_key: SafePolicyKey
    scope_sha256: Sha256Hex
    version: NonNegativeInt


class DeletionCaseIndexInvalidationIdentity(StrictModel):
    """One body-free pending case-index identity bound by deletion approval."""

    manifest_ref: VersionRef
    operation_id: ObjectId
    approval_descriptor_sha256: Sha256Hex
    pattern_id: ObjectId
    pattern_version: PositiveInt
    queue_id: ObjectId
    target_catalog_version: PositiveInt


class DeletionCaseIndexInvalidationSnapshot(StrictModel):
    """Exact pending set which must be invalidated before epoch advancement."""

    schema_version: Literal["case_index_rebuild_snapshot.v1"] = (
        "case_index_rebuild_snapshot.v1"
    )
    target_catalog_version: PositiveInt
    identities: tuple[DeletionCaseIndexInvalidationIdentity, ...]

    @field_validator("identities")
    @classmethod
    def _canonical_identities(
        cls,
        value: tuple[DeletionCaseIndexInvalidationIdentity, ...],
    ) -> tuple[DeletionCaseIndexInvalidationIdentity, ...]:
        keys = tuple(
            (
                item.manifest_ref.object_id,
                item.manifest_ref.version,
                item.manifest_ref.content_sha256,
                item.operation_id,
                item.approval_descriptor_sha256,
                item.pattern_id,
                item.pattern_version,
                item.queue_id,
                item.target_catalog_version,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("DELETION_CASE_INDEX_SET_NOT_CANONICAL")
        return value

    @model_validator(mode="after")
    def _one_target(self) -> "DeletionCaseIndexInvalidationSnapshot":
        if any(
            item.target_catalog_version != self.target_catalog_version
            for item in self.identities
        ):
            raise ValueError("DELETION_CASE_INDEX_SET_TARGET_MISMATCH")
        return self

    @property
    def identity_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class DeletionInventory(StrictModel):
    """Explicit snapshot supplied by provenance and manifest repositories."""

    nodes: tuple[DeletionClosureNode, ...]
    dependencies: tuple[DeletionDependency, ...]
    active_manifest_refs: tuple[DeletionObjectRef, ...]
    base_versions: tuple[DeletionBaseVersion, ...]
    deletion_version: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt = 0
    pending_case_index_invalidation: (
        DeletionCaseIndexInvalidationSnapshot | None
    ) = None

    @model_validator(mode="after")
    def _closed_inventory(self) -> "DeletionInventory":
        node_keys = [deletion_ref_key(node.object_ref) for node in self.nodes]
        if len(node_keys) != len(set(node_keys)):
            raise ValueError("DELETION_NODE_DUPLICATE")
        known = set(node_keys)
        edge_ids = [edge.edge_id for edge in self.dependencies]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("DELETION_DEPENDENCY_ID_DUPLICATE")
        if any(
            deletion_ref_key(edge.source_ref) not in known
            or deletion_ref_key(edge.dependent_ref) not in known
            for edge in self.dependencies
        ):
            raise ValueError("DELETION_DEPENDENCY_ENDPOINT_MISSING")
        manifest_keys = [deletion_ref_key(ref) for ref in self.active_manifest_refs]
        if len(manifest_keys) != len(set(manifest_keys)) or any(
            key not in known for key in manifest_keys
        ):
            raise ValueError("DELETION_ACTIVE_MANIFEST_INVALID")
        base_keys = [
            (item.authority_key, item.scope_sha256) for item in self.base_versions
        ]
        if not base_keys or len(base_keys) != len(set(base_keys)):
            raise ValueError("DELETION_BASE_VERSIONS_INVALID")
        return self


class DeletionPreviewRequest(StrictModel):
    request_id: ObjectId
    target: DeletionTarget
    reason_code: SafePolicyKey
    requested_at: UtcDateTime


class DeletionAction(StrictModel):
    action_id: ObjectId
    action_type: DeletionActionType
    target_ref: DeletionObjectRef
    authority_effect: DeletionAuthorityEffect = "none"
    path_edge_ids: tuple[NonEmptyStr, ...]
    reason_code: SafePolicyKey


class DeletionPlan(StrictModel):
    request_id: ObjectId
    created_at: UtcDateTime
    target: DeletionTarget
    reason_code: SafePolicyKey
    target_scope_hash: Sha256Hex
    base_versions: tuple[DeletionBaseVersion, ...]
    base_deletion_version: NonNegativeInt
    next_deletion_version: int
    base_tombstone_epoch: NonNegativeInt
    next_tombstone_epoch: int
    base_authorization_epoch: NonNegativeInt
    next_authorization_epoch: NonNegativeInt
    closure_nodes: tuple[DeletionClosureNode, ...]
    closure_edges: tuple[DeletionDependency, ...]
    active_manifest_refs: tuple[DeletionObjectRef, ...]
    pending_case_index_invalidation: (
        DeletionCaseIndexInvalidationSnapshot | None
    ) = None
    retained_audit_refs: tuple[DeletionObjectRef, ...]
    actions: tuple[DeletionAction, ...]
    local_retrieval_state_after_commit: Literal["blocked_by_tombstone"] = (
        "blocked_by_tombstone"
    )
    physical_cleanup_state_after_commit: Literal["pending"] = "pending"
    hosted_product_task_state: Literal[
        "unchanged_requires_product_controls"
    ] = "unchanged_requires_product_controls"
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _exact_binding(self) -> "DeletionPlan":
        if self.target_scope_hash != target_scope_sha256(self.target):
            raise ValueError("DELETION_TARGET_SCOPE_MISMATCH")
        if self.next_deletion_version != self.base_deletion_version + 1:
            raise ValueError("DELETION_VERSION_SEQUENCE_INVALID")
        if self.next_tombstone_epoch != self.base_tombstone_epoch + 1:
            raise ValueError("DELETION_TOMBSTONE_EPOCH_SEQUENCE_INVALID")
        authorization_delta = int(
            any(action.authority_effect != "none" for action in self.actions)
        )
        if (
            self.next_authorization_epoch
            != self.base_authorization_epoch + authorization_delta
        ):
            raise ValueError("DELETION_AUTHORIZATION_EPOCH_SEQUENCE_INVALID")
        expected_descriptor = DraftDescriptor(
            purpose="delete",
            target_id=self.target.object_ref.object_id,
            client_id=self.target.client_id,
            session_id=self.target.session_id,
            base_version=self.base_deletion_version,
            draft_sha256=self.plan_sha256,
        )
        if self.descriptor != expected_descriptor:
            raise ValueError("DELETION_APPROVAL_DESCRIPTOR_MISMATCH")
        if self.plan_sha256 != deletion_plan_sha256(self):
            raise ValueError("DELETION_PLAN_HASH_MISMATCH")
        return self


class DeletionCommitResult(StrictModel):
    request_id: ObjectId
    plan_sha256: Sha256Hex
    tombstone_committed: Literal[True] = True
    deletion_version: int
    tombstone_epoch: int
    authorization_epoch: NonNegativeInt
    tombstone_count: NonNegativeInt
    queue_intent_count: NonNegativeInt
    queue_wake_state: Literal["notified", "pending"]
    local_retrieval_state: Literal["blocked_by_tombstone"] = (
        "blocked_by_tombstone"
    )
    physical_cleanup_state: Literal["pending"] = "pending"
    hosted_product_task_state: Literal[
        "unchanged_requires_product_controls"
    ] = "unchanged_requires_product_controls"


def deletion_plan_payload(value: DeletionPlan) -> dict[str, object]:
    """Return exactly the body-free fields covered by counselor approval."""

    return value.model_dump(
        mode="json",
        exclude={"descriptor", "plan_sha256"},
    )


def deletion_plan_sha256(value: DeletionPlan) -> str:
    return canonical_sha256(deletion_plan_payload(value))


def deletion_intent_authority_sha256(
    *,
    intent_id: str,
    request_id: str,
    action_id: str,
    action_type: DeletionActionType,
    object_type: str,
    target_id_hash: str,
    target_version: int,
    target_content_sha256: str,
    authority_scope: DeletionAuthorityScope,
    deletion_plan_sha256: str,
    root_object_type: str,
    root_target_id_hash: str,
    root_lineage_hash: str,
) -> str:
    """Bind one durable follow-up intent to its approved deletion closure."""

    return canonical_sha256(
        {
            "domain": "consultation_kb.deletion_intent_authority.v1",
            "intent_id": intent_id,
            "request_id": request_id,
            "action_id": action_id,
            "action_type": action_type,
            "object_type": object_type,
            "target_id_hash": target_id_hash,
            "target_version": target_version,
            "target_content_sha256": target_content_sha256,
            "authority_scope": authority_scope,
            "deletion_plan_sha256": deletion_plan_sha256,
            "root_object_type": root_object_type,
            "root_target_id_hash": root_target_id_hash,
            "root_lineage_hash": root_lineage_hash,
        }
    )


__all__ = [
    "DELETION_ACTION_TYPES",
    "DeletionAction",
    "DeletionActionType",
    "DeletionAuthorityEffect",
    "DeletionAuthorityScope",
    "DeletionBaseVersion",
    "DeletionCaseIndexInvalidationIdentity",
    "DeletionCaseIndexInvalidationSnapshot",
    "DeletionClosureNode",
    "DeletionCommitResult",
    "DeletionDependency",
    "DeletionInventory",
    "DeletionObjectRef",
    "DeletionPlan",
    "DeletionPreviewRequest",
    "DeletionTarget",
    "DeletionTargetType",
    "deletion_intent_authority_sha256",
    "deletion_plan_payload",
    "deletion_plan_sha256",
    "deletion_ref_key",
    "target_scope_sha256",
]
