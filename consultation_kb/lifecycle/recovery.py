"""Read-only-first startup recovery coordinator."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Protocol

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.lifecycle.recovery_policy import (
    RecoveryPolicyRegistry,
    recovery_scan_seed,
)
from consultation_kb.models.recovery import (
    RebuildCommand,
    RecoveryApplyReceipt,
    RecoveryDecision,
    RecoveryInventoryItem,
    RecoveryPurpose,
    RecoveryReport,
    RecoveryScan,
)


class RecoveryError(RuntimeError):
    """Base class for fixed-code startup recovery failures."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RecoveryInventoryError(RecoveryError):
    def __init__(self, code: str = "RECOVERY_INVENTORY_INVALID") -> None:
        super().__init__(code)


class RecoveryExecutionError(RecoveryError):
    def __init__(self, code: str = "RECOVERY_APPLY_FAILED") -> None:
        super().__init__(code)


class RecoveryStartupBlocked(RecoveryError):
    def __init__(self) -> None:
        super().__init__("RECOVERY_STARTUP_BLOCKED")


class RecoveryWriter(Protocol):
    """Database-local writer with a durable decision-idempotency journal."""

    def apply(self, decision: RecoveryDecision) -> RecoveryApplyReceipt:
        """Atomically journal and apply, or replay, one body-free decision."""


class RecoveryBackend(Protocol):
    """Adapter boundary that keeps database discovery out of the coordinator."""

    def read_only_inventory(self) -> Sequence[RecoveryInventoryItem]:
        """Return safe inventory rows without taking a writer lock."""

    def single_writer(
        self, *, database_ref_sha256: str, purpose: RecoveryPurpose
    ) -> AbstractContextManager[RecoveryWriter]:
        """Open only the named database/purpose under its durable writer lock."""


class RecoveryCoordinator:
    """Inventory every purpose first, then recover under narrow writer locks."""

    def __init__(
        self,
        *,
        backend: RecoveryBackend,
        clock: Clock | None = None,
        policies: RecoveryPolicyRegistry | None = None,
    ) -> None:
        self._backend = backend
        self._clock = clock or SystemClock()
        self._policies = policies or RecoveryPolicyRegistry.default()
        self._lock_catalog_guard = threading.Lock()
        self._lock_catalog: dict[tuple[str, RecoveryPurpose], threading.Lock] = {}

    def _process_lock(
        self, database_ref_sha256: str, purpose: RecoveryPurpose
    ) -> threading.Lock:
        key = (database_ref_sha256, purpose)
        with self._lock_catalog_guard:
            existing = self._lock_catalog.get(key)
            if existing is None:
                existing = threading.Lock()
                self._lock_catalog[key] = existing
            return existing

    def scan(self) -> RecoveryScan:
        """Build a complete read-only startup decision inventory."""

        try:
            raw_inventory = tuple(self._backend.read_only_inventory())
            inventory = tuple(
                RecoveryInventoryItem.model_validate(item) for item in raw_inventory
            )
        except Exception as exc:
            raise RecoveryInventoryError from exc

        identity_keys = tuple(
            (item.database_ref_sha256, item.purpose, item.manifest_id)
            for item in inventory
        )
        if len(set(identity_keys)) != len(identity_keys):
            raise RecoveryInventoryError("RECOVERY_INVENTORY_DUPLICATE")

        observed_at = self._clock.now()
        ordered = tuple(
            sorted(
                inventory,
                key=lambda item: (
                    item.database_ref_sha256,
                    item.purpose,
                    item.manifest_id,
                ),
            )
        )
        try:
            decisions = tuple(
                self._policies.decide(item, observed_at=observed_at) for item in ordered
            )
        except Exception as exc:
            raise RecoveryInventoryError("RECOVERY_POLICY_REJECTED_INVENTORY") from exc

        rebuild_commands = tuple(
            RebuildCommand(
                database_ref_sha256=decision.database_ref_sha256,
                purpose=decision.purpose,
                manifest_id=decision.manifest_id,
            )
            for decision in decisions
            if decision.rebuild_required
        )
        degraded = bool(rebuild_commands)
        return RecoveryScan(
            scan_sha256=recovery_scan_seed(decisions, observed_at=observed_at),
            scanned_at=observed_at,
            inventory_count=len(inventory),
            decisions=decisions,
            startup_health="DEGRADED" if degraded else "HEALTHY",
            query_ready=not degraded,
            rebuild_commands=rebuild_commands,
        )

    def recover(self) -> RecoveryReport:
        """Scan first, then idempotently apply every required decision."""

        scan = self.scan()
        grouped: defaultdict[tuple[str, RecoveryPurpose], list[RecoveryDecision]] = (
            defaultdict(list)
        )
        for decision in scan.decisions:
            if decision.requires_writer:
                grouped[(decision.database_ref_sha256, decision.purpose)].append(
                    decision
                )

        receipts: list[RecoveryApplyReceipt] = []
        for database_ref_sha256, purpose in sorted(grouped):
            decisions = grouped[(database_ref_sha256, purpose)]
            process_lock = self._process_lock(database_ref_sha256, purpose)
            try:
                with (
                    process_lock,
                    self._backend.single_writer(
                        database_ref_sha256=database_ref_sha256,
                        purpose=purpose,
                    ) as writer,
                ):
                    for decision in decisions:
                        receipt = RecoveryApplyReceipt.model_validate(
                            writer.apply(decision)
                        )
                        if (
                            receipt.decision_sha256 != decision.decision_sha256
                            or receipt.after_state != decision.after_state
                        ):
                            raise RecoveryExecutionError("RECOVERY_RECEIPT_MISMATCH")
                        receipts.append(receipt)
            except RecoveryError:
                raise
            except Exception as exc:
                raise RecoveryExecutionError from exc
        return RecoveryReport(scan=scan, receipts=tuple(receipts))

    def require_query_ready(self, scan: RecoveryScan) -> None:
        """Fail required startup when an active artifact is not trustworthy."""

        checked = RecoveryScan.model_validate(scan)
        if not checked.query_ready:
            raise RecoveryStartupBlocked


__all__ = [
    "RecoveryBackend",
    "RecoveryCoordinator",
    "RecoveryError",
    "RecoveryExecutionError",
    "RecoveryInventoryError",
    "RecoveryStartupBlocked",
    "RecoveryWriter",
]
