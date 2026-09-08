"""Body-free contracts for startup inventory and deterministic recovery."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import model_validator

from consultation_kb.models.common import (
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
)


RecoveryPurpose = Literal[
    "private_record",
    "profile",
    "wiki",
    "graph",
    "lex",
    "vector",
    "case",
    "index",
    "outbox",
]
RECOVERY_PURPOSES: tuple[RecoveryPurpose, ...] = (
    "private_record",
    "profile",
    "wiki",
    "graph",
    "lex",
    "vector",
    "case",
    "index",
    "outbox",
)

RecoveryDatabaseScope = Literal["global", "client"]
RecoveryActivationMode = Literal[
    "runtime_epoch",
    "verified_ledger",
    "sealed_replay",
    "full_rebuild_only",
]
RecoveryState = Literal["DRAFT", "PREPARED", "ACTIVE", "RETIRED"]
RecoveryAction = Literal[
    "KEEP",
    "CLEAN_STAGING",
    "VERIFY_AND_ACTIVATE",
    "TOMBSTONE_PREPARED",
    "ACK_SOURCE",
    "ENQUEUE_REBUILD",
    "QUEUE_CLEANUP",
]
RecoveryVerificationResult = Literal[
    "VALID",
    "PENDING",
    "EXPIRED",
    "INVALID",
    "CORRUPT",
    "RETAINED",
    "TOMBSTONED",
    "ACK_PENDING",
]
RecoveryReason = Literal[
    "VALID",
    "STAGING_NOT_EXPIRED",
    "DRAFT_FORMAL_INTENT_PRESENT",
    "DRAFT_STAGING_EXPIRED",
    "MEMBERS_INCOMPLETE",
    "MANIFEST_HASH_INVALID",
    "SOURCE_VERSION_STALE",
    "BASE_VERSION_STALE",
    "APPROVAL_INTENT_INVALID",
    "APPROVAL_EPOCH_STALE",
    "PERMISSION_TIGHTENED",
    "TOMBSTONED",
    "TOMBSTONE_EPOCH_STALE",
    "ACTIVE_POINTER_INVALID",
    "ROLLBACK_WINDOW_OPEN",
    "ROLLBACK_WINDOW_EXPIRED",
    "RETENTION_REQUIRED",
    "GLOBAL_ACTIVE_ACK_PENDING",
    "SOURCE_ACK_UNVERIFIED",
    "SEALED_REPLAY_REQUIRED",
    "FULL_REBUILD_REQUIRED",
]
RecoveryDisposition = Literal["APPLIED", "REPLAYED"]
RecoveryStartupHealth = Literal["HEALTHY", "DEGRADED"]

MUTATING_RECOVERY_ACTIONS: frozenset[RecoveryAction] = frozenset(
    {
        "CLEAN_STAGING",
        "VERIFY_AND_ACTIVATE",
        "TOMBSTONE_PREPARED",
        "ACK_SOURCE",
        "ENQUEUE_REBUILD",
        "QUEUE_CLEANUP",
    }
)


class RecoveryInventoryItem(StrictModel):
    """One safe inventory row; it contains no body, path, or direct client ID."""

    database_ref_sha256: Sha256Hex
    database_scope: RecoveryDatabaseScope
    purpose: RecoveryPurpose
    manifest_id: ObjectId
    manifest_sha256: Sha256Hex
    state: RecoveryState
    activation_mode: RecoveryActivationMode = "runtime_epoch"

    formal_intent_present: bool
    members_complete: bool
    manifest_hash_valid: bool
    source_version: PositiveInt
    current_source_version: NonNegativeInt
    base_version: NonNegativeInt
    current_base_version: NonNegativeInt
    approval_intent_valid: bool
    approval_epoch: NonNegativeInt
    current_approval_epoch: NonNegativeInt
    permission_allows_activation: bool
    permission_epoch: NonNegativeInt
    current_permission_epoch: NonNegativeInt
    tombstoned: bool
    tombstone_epoch: NonNegativeInt
    current_tombstone_epoch: NonNegativeInt
    active_pointer_valid: bool

    staging_expires_at: UtcDateTime | None
    rollback_expires_at: UtcDateTime | None
    retention_required: bool

    source_ack_pending: bool
    global_state: RecoveryState | None

    @model_validator(mode="after")
    def _validate_state_specific_evidence(self) -> "RecoveryInventoryItem":
        if self.activation_mode == "verified_ledger" and self.state != "ACTIVE":
            raise ValueError("verified recovery ledgers must be active")
        if self.activation_mode == "sealed_replay" and self.purpose not in {
            "case",
            "outbox",
        }:
            raise ValueError("sealed replay is only valid for case workflows")
        if self.activation_mode == "full_rebuild_only" and self.purpose != "index":
            raise ValueError("full rebuild recovery is only valid for indexes")
        if self.state == "DRAFT":
            if self.staging_expires_at is None:
                raise ValueError("draft recovery inventory requires staging expiry")
        elif self.staging_expires_at is not None:
            raise ValueError("only draft inventory may carry staging expiry")

        if self.state == "RETIRED":
            if self.rollback_expires_at is None:
                raise ValueError("retired recovery inventory requires rollback expiry")
        elif self.rollback_expires_at is not None:
            raise ValueError("only retired inventory may carry rollback expiry")

        if self.state != "DRAFT" and not self.formal_intent_present:
            raise ValueError("persisted lifecycle state requires formal intent")

        if self.purpose != "outbox":
            if self.source_ack_pending or self.global_state is not None:
                raise ValueError("saga evidence is only valid for outbox recovery")
        elif self.source_ack_pending:
            if self.state != "PREPARED":
                raise ValueError("pending source acknowledgement must be prepared")
            if self.database_scope != "client":
                raise ValueError(
                    "source acknowledgement belongs to its client database"
                )
            if self.global_state != "ACTIVE":
                raise ValueError("source acknowledgement requires a global active copy")
        return self


class RecoveryDecision(StrictModel):
    """Deterministic, durable-journal-safe decision without artifact bytes."""

    decision_sha256: Sha256Hex
    evidence_sha256: Sha256Hex
    database_ref_sha256: Sha256Hex
    database_scope: RecoveryDatabaseScope
    purpose: RecoveryPurpose
    manifest_id: ObjectId
    manifest_sha256: Sha256Hex
    before_state: RecoveryState
    after_state: RecoveryState
    action: RecoveryAction
    verification_result: RecoveryVerificationResult
    reason_codes: tuple[RecoveryReason, ...]
    query_allowed: bool

    @property
    def requires_writer(self) -> bool:
        return self.action in MUTATING_RECOVERY_ACTIONS

    @property
    def rebuild_required(self) -> bool:
        return self.action == "ENQUEUE_REBUILD"

    @model_validator(mode="after")
    def _validate_transition(self) -> "RecoveryDecision":
        if not self.reason_codes or len(set(self.reason_codes)) != len(
            self.reason_codes
        ):
            raise ValueError("recovery reasons must be non-empty and unique")
        transitions: dict[RecoveryAction, tuple[RecoveryState, RecoveryState]] = {
            "CLEAN_STAGING": ("DRAFT", "RETIRED"),
            "VERIFY_AND_ACTIVATE": ("PREPARED", "ACTIVE"),
            "TOMBSTONE_PREPARED": ("PREPARED", "RETIRED"),
            "ACK_SOURCE": ("PREPARED", "ACTIVE"),
            "ENQUEUE_REBUILD": ("ACTIVE", "ACTIVE"),
            "QUEUE_CLEANUP": ("RETIRED", "RETIRED"),
        }
        expected = transitions.get(self.action)
        if expected is None:
            if self.before_state != self.after_state:
                raise ValueError("keep decision must preserve lifecycle state")
        elif (self.before_state, self.after_state) != expected:
            raise ValueError("recovery action has an invalid state transition")
        if self.rebuild_required and self.query_allowed:
            raise ValueError("corrupt active artifacts must fail closed")
        return self


class RecoveryApplyReceipt(StrictModel):
    """Result of an idempotent, atomically journaled recovery application."""

    decision_sha256: Sha256Hex
    disposition: RecoveryDisposition
    after_state: RecoveryState
    durable_result_sha256: Sha256Hex


class RebuildCommand(StrictModel):
    """Structured command descriptor, rendered only at the operator boundary."""

    database_ref_sha256: Sha256Hex
    purpose: RecoveryPurpose
    manifest_id: ObjectId

    def render(self) -> str:
        return (
            f"consultation-kb rebuild-start --purpose {self.purpose} "
            f"--database-ref-sha256 {self.database_ref_sha256}"
        )


class RecoveryScan(StrictModel):
    """Read-only startup scan result."""

    scan_sha256: Sha256Hex
    scanned_at: UtcDateTime
    inventory_count: NonNegativeInt
    decisions: tuple[RecoveryDecision, ...]
    startup_health: RecoveryStartupHealth
    query_ready: bool
    rebuild_commands: tuple[RebuildCommand, ...]

    @model_validator(mode="after")
    def _validate_health_shape(self) -> "RecoveryScan":
        if self.inventory_count != len(self.decisions):
            raise ValueError("inventory and decision cardinality must match")
        decision_ids = tuple(value.decision_sha256 for value in self.decisions)
        if len(set(decision_ids)) != len(decision_ids):
            raise ValueError("recovery scan decisions must be unique")
        rebuild_decisions = tuple(
            value for value in self.decisions if value.rebuild_required
        )
        degraded = bool(rebuild_decisions)
        if (self.startup_health == "DEGRADED") != degraded:
            raise ValueError("startup health does not match active integrity state")
        if self.query_ready == degraded:
            raise ValueError("query readiness does not match startup health")
        command_keys = {
            (value.database_ref_sha256, value.purpose, value.manifest_id)
            for value in self.rebuild_commands
        }
        decision_keys = {
            (value.database_ref_sha256, value.purpose, value.manifest_id)
            for value in rebuild_decisions
        }
        if command_keys != decision_keys or len(command_keys) != len(
            self.rebuild_commands
        ):
            raise ValueError("rebuild commands must exactly cover corrupt active items")
        return self


class RecoveryReport(StrictModel):
    """Recovery execution result tied to the exact read-only scan."""

    scan: RecoveryScan
    receipts: tuple[RecoveryApplyReceipt, ...]

    @model_validator(mode="after")
    def _validate_receipts(self) -> "RecoveryReport":
        expected = {
            decision.decision_sha256: decision
            for decision in self.scan.decisions
            if decision.requires_writer
        }
        actual = {receipt.decision_sha256: receipt for receipt in self.receipts}
        if len(actual) != len(self.receipts) or set(actual) != set(expected):
            raise ValueError("receipts must exactly cover mutating recovery decisions")
        if any(
            receipt.after_state != expected[decision_id].after_state
            for decision_id, receipt in actual.items()
        ):
            raise ValueError("recovery receipt state does not match its decision")
        return self


def utc_timestamp(value: datetime) -> str:
    """Canonical UTC timestamp used only by the safe inventory hash."""

    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "MUTATING_RECOVERY_ACTIONS",
    "RECOVERY_PURPOSES",
    "RebuildCommand",
    "RecoveryAction",
    "RecoveryActivationMode",
    "RecoveryApplyReceipt",
    "RecoveryDatabaseScope",
    "RecoveryDecision",
    "RecoveryDisposition",
    "RecoveryInventoryItem",
    "RecoveryPurpose",
    "RecoveryReason",
    "RecoveryReport",
    "RecoveryScan",
    "RecoveryStartupHealth",
    "RecoveryState",
    "RecoveryVerificationResult",
    "utc_timestamp",
]
