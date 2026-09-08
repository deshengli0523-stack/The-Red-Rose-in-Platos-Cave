"""Pure, per-purpose crash-recovery decision policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from consultation_kb.models.common import require_utc
from consultation_kb.models.recovery import (
    RECOVERY_PURPOSES,
    RecoveryAction,
    RecoveryDecision,
    RecoveryInventoryItem,
    RecoveryPurpose,
    RecoveryReason,
    RecoveryState,
    RecoveryVerificationResult,
    utc_timestamp,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def inventory_evidence_sha256(
    item: RecoveryInventoryItem,
    *,
    staging_expired: bool,
    rollback_expired: bool,
) -> str:
    """Hash only safe inventory fields and evaluated time-window predicates."""

    return _canonical_sha256(
        {
            "inventory": item.model_dump(mode="json"),
            "rollback_expired": rollback_expired,
            "staging_expired": staging_expired,
        }
    )


def _invalid_reasons(item: RecoveryInventoryItem) -> tuple[RecoveryReason, ...]:
    reasons: list[RecoveryReason] = []
    if item.tombstoned:
        reasons.append("TOMBSTONED")
    if not item.members_complete:
        reasons.append("MEMBERS_INCOMPLETE")
    if not item.manifest_hash_valid:
        reasons.append("MANIFEST_HASH_INVALID")
    if item.source_version != item.current_source_version:
        reasons.append("SOURCE_VERSION_STALE")
    if item.base_version != item.current_base_version:
        reasons.append("BASE_VERSION_STALE")
    if not item.approval_intent_valid:
        reasons.append("APPROVAL_INTENT_INVALID")
    if item.approval_epoch != item.current_approval_epoch:
        reasons.append("APPROVAL_EPOCH_STALE")
    if (
        not item.permission_allows_activation
        or item.permission_epoch != item.current_permission_epoch
    ):
        reasons.append("PERMISSION_TIGHTENED")
    if item.tombstone_epoch != item.current_tombstone_epoch:
        reasons.append("TOMBSTONE_EPOCH_STALE")
    return tuple(reasons)


def _active_invalid_reasons(
    item: RecoveryInventoryItem,
) -> tuple[RecoveryReason, ...]:
    reasons = list(_invalid_reasons(item))
    if not item.active_pointer_valid:
        reasons.append("ACTIVE_POINTER_INVALID")
    return tuple(reasons)


def _build_decision(
    item: RecoveryInventoryItem,
    *,
    action: RecoveryAction,
    after_state: RecoveryState,
    result: RecoveryVerificationResult,
    reasons: tuple[RecoveryReason, ...],
    query_allowed: bool,
    staging_expired: bool,
    rollback_expired: bool,
) -> RecoveryDecision:
    evidence_sha256 = inventory_evidence_sha256(
        item,
        staging_expired=staging_expired,
        rollback_expired=rollback_expired,
    )
    decision_sha256 = _canonical_sha256(
        {
            "action": action,
            "after_state": after_state,
            "before_state": item.state,
            "database_ref_sha256": item.database_ref_sha256,
            "evidence_sha256": evidence_sha256,
            "manifest_id": item.manifest_id,
            "manifest_sha256": item.manifest_sha256,
            "purpose": item.purpose,
            "query_allowed": query_allowed,
            "reason_codes": reasons,
            "verification_result": result,
        }
    )
    return RecoveryDecision(
        decision_sha256=decision_sha256,
        evidence_sha256=evidence_sha256,
        database_ref_sha256=item.database_ref_sha256,
        database_scope=item.database_scope,
        purpose=item.purpose,
        manifest_id=item.manifest_id,
        manifest_sha256=item.manifest_sha256,
        before_state=item.state,
        after_state=after_state,
        action=action,
        verification_result=result,
        reason_codes=reasons,
        query_allowed=query_allowed,
    )


@dataclass(frozen=True, slots=True)
class PurposeRecoveryPolicy:
    """One deterministic policy instance bound to exactly one purpose."""

    purpose: RecoveryPurpose

    def decide(
        self, item: RecoveryInventoryItem, *, observed_at: datetime
    ) -> RecoveryDecision:
        checked = RecoveryInventoryItem.model_validate(item)
        if checked.purpose != self.purpose:
            raise ValueError("RECOVERY_POLICY_PURPOSE_MISMATCH")
        now = require_utc(observed_at)
        staging_expired = bool(
            checked.staging_expires_at is not None and now >= checked.staging_expires_at
        )
        rollback_expired = bool(
            checked.rollback_expires_at is not None
            and now >= checked.rollback_expires_at
        )

        if checked.state == "DRAFT":
            if staging_expired and not checked.formal_intent_present:
                return _build_decision(
                    checked,
                    action="CLEAN_STAGING",
                    after_state="RETIRED",
                    result="EXPIRED",
                    reasons=("DRAFT_STAGING_EXPIRED",),
                    query_allowed=False,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            reason: RecoveryReason = (
                "DRAFT_FORMAL_INTENT_PRESENT"
                if checked.formal_intent_present
                else "STAGING_NOT_EXPIRED"
            )
            return _build_decision(
                checked,
                action="KEEP",
                after_state="DRAFT",
                result="INVALID" if checked.formal_intent_present else "PENDING",
                reasons=(reason,),
                query_allowed=False,
                staging_expired=staging_expired,
                rollback_expired=rollback_expired,
            )

        if checked.state == "PREPARED":
            invalid = _invalid_reasons(checked)
            if (
                checked.purpose == "outbox"
                and checked.source_ack_pending
                and checked.global_state == "ACTIVE"
                and not invalid
                and checked.members_complete
                and checked.manifest_hash_valid
                and not checked.tombstoned
                and checked.permission_allows_activation
                and checked.permission_epoch == checked.current_permission_epoch
                and checked.tombstone_epoch == checked.current_tombstone_epoch
            ):
                return _build_decision(
                    checked,
                    action="ACK_SOURCE",
                    after_state="ACTIVE",
                    result="ACK_PENDING",
                    reasons=("GLOBAL_ACTIVE_ACK_PENDING",),
                    query_allowed=True,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            if checked.purpose == "outbox" and not checked.source_ack_pending:
                return _build_decision(
                    checked,
                    action="KEEP",
                    after_state="PREPARED",
                    result="PENDING",
                    reasons=("SOURCE_ACK_UNVERIFIED",),
                    query_allowed=True,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            if checked.activation_mode == "sealed_replay":
                return _build_decision(
                    checked,
                    action="KEEP",
                    after_state="PREPARED",
                    result="PENDING" if not invalid else "INVALID",
                    reasons=("SEALED_REPLAY_REQUIRED", *invalid),
                    query_allowed=True,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            if checked.activation_mode == "full_rebuild_only":
                return _build_decision(
                    checked,
                    action="KEEP",
                    after_state="PREPARED",
                    result="PENDING" if not invalid else "INVALID",
                    reasons=("FULL_REBUILD_REQUIRED", *invalid),
                    query_allowed=True,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            if invalid:
                return _build_decision(
                    checked,
                    action="TOMBSTONE_PREPARED",
                    after_state="RETIRED",
                    result="TOMBSTONED" if checked.tombstoned else "INVALID",
                    reasons=invalid,
                    query_allowed=True,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            return _build_decision(
                checked,
                action="VERIFY_AND_ACTIVATE",
                after_state="ACTIVE",
                result="VALID",
                reasons=("VALID",),
                query_allowed=True,
                staging_expired=staging_expired,
                rollback_expired=rollback_expired,
            )

        if checked.state == "ACTIVE":
            if checked.tombstoned:
                return _build_decision(
                    checked,
                    action="KEEP",
                    after_state="ACTIVE",
                    result="TOMBSTONED",
                    reasons=("TOMBSTONED",),
                    query_allowed=False,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            invalid = _active_invalid_reasons(checked)
            if invalid:
                return _build_decision(
                    checked,
                    action="ENQUEUE_REBUILD",
                    after_state="ACTIVE",
                    result="CORRUPT",
                    reasons=invalid,
                    query_allowed=False,
                    staging_expired=staging_expired,
                    rollback_expired=rollback_expired,
                )
            return _build_decision(
                checked,
                action="KEEP",
                after_state="ACTIVE",
                result="VALID",
                reasons=("VALID",),
                query_allowed=True,
                staging_expired=staging_expired,
                rollback_expired=rollback_expired,
            )

        retained: list[RecoveryReason] = []
        if not rollback_expired:
            retained.append("ROLLBACK_WINDOW_OPEN")
        if checked.retention_required:
            retained.append("RETENTION_REQUIRED")
        if retained:
            return _build_decision(
                checked,
                action="KEEP",
                after_state="RETIRED",
                result="RETAINED",
                reasons=tuple(retained),
                query_allowed=False,
                staging_expired=staging_expired,
                rollback_expired=rollback_expired,
            )
        return _build_decision(
            checked,
            action="QUEUE_CLEANUP",
            after_state="RETIRED",
            result="EXPIRED",
            reasons=("ROLLBACK_WINDOW_EXPIRED",),
            query_allowed=False,
            staging_expired=staging_expired,
            rollback_expired=rollback_expired,
        )


class RecoveryPolicyRegistry:
    """Complete immutable purpose-to-policy registry."""

    def __init__(
        self, policies: Mapping[RecoveryPurpose, PurposeRecoveryPolicy]
    ) -> None:
        copied = dict(policies)
        if set(copied) != set(RECOVERY_PURPOSES):
            raise ValueError("RECOVERY_POLICY_REGISTRY_INCOMPLETE")
        if any(key != value.purpose for key, value in copied.items()):
            raise ValueError("RECOVERY_POLICY_REGISTRY_MISMATCH")
        self._policies: Mapping[RecoveryPurpose, PurposeRecoveryPolicy] = (
            MappingProxyType(copied)
        )

    @classmethod
    def default(cls) -> "RecoveryPolicyRegistry":
        return cls(
            {purpose: PurposeRecoveryPolicy(purpose) for purpose in RECOVERY_PURPOSES}
        )

    def decide(
        self, item: RecoveryInventoryItem, *, observed_at: datetime
    ) -> RecoveryDecision:
        checked = RecoveryInventoryItem.model_validate(item)
        return self._policies[checked.purpose].decide(checked, observed_at=observed_at)


def recovery_scan_seed(
    decisions: tuple[RecoveryDecision, ...], *, observed_at: datetime
) -> str:
    """Hash a scan without including mutable bodies or database locations."""

    return _canonical_sha256(
        {
            "decision_sha256": [value.decision_sha256 for value in decisions],
            "observed_at": utc_timestamp(require_utc(observed_at)),
        }
    )


__all__ = [
    "PurposeRecoveryPolicy",
    "RecoveryPolicyRegistry",
    "inventory_evidence_sha256",
    "recovery_scan_seed",
]
