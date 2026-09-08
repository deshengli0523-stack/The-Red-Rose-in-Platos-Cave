from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.recovery import (
    RecoveryBackend,
    RecoveryCoordinator,
    RecoveryExecutionError,
    RecoveryInventoryError,
    RecoveryWriter,
)
from consultation_kb.models.recovery import (
    RECOVERY_PURPOSES,
    RecoveryApplyReceipt,
    RecoveryDecision,
    RecoveryInventoryItem,
    RecoveryPurpose,
    RecoveryState,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _item(
    *,
    purpose: RecoveryPurpose = "wiki",
    state: RecoveryState = "PREPARED",
    database_ref_sha256: str | None = None,
    manifest_suffix: str = "ab",
    **overrides: object,
) -> RecoveryInventoryItem:
    values: dict[str, object] = {
        "database_ref_sha256": database_ref_sha256 or _sha(f"db-{purpose}"),
        "database_scope": "global",
        "purpose": purpose,
        "manifest_id": (
            "manifest_01890f9d-5b40-7abc-8def-1234567890" + manifest_suffix
        ),
        "manifest_sha256": _sha(f"manifest-{purpose}-{manifest_suffix}"),
        "state": state,
        "formal_intent_present": state != "DRAFT",
        "members_complete": True,
        "manifest_hash_valid": True,
        "source_version": 4,
        "current_source_version": 4,
        "base_version": 3,
        "current_base_version": 3,
        "approval_intent_valid": True,
        "approval_epoch": 5,
        "current_approval_epoch": 5,
        "permission_allows_activation": True,
        "permission_epoch": 7,
        "current_permission_epoch": 7,
        "tombstoned": False,
        "tombstone_epoch": 9,
        "current_tombstone_epoch": 9,
        "active_pointer_valid": True,
        "staging_expires_at": NOW + timedelta(minutes=5) if state == "DRAFT" else None,
        "rollback_expires_at": NOW + timedelta(days=1) if state == "RETIRED" else None,
        "retention_required": False,
        "source_ack_pending": False,
        "global_state": None,
    }
    values.update(overrides)
    return RecoveryInventoryItem.model_validate(values)


class _JournalWriter(RecoveryWriter):
    def __init__(self, backend: "_Backend") -> None:
        self._backend = backend

    def apply(self, decision: RecoveryDecision) -> RecoveryApplyReceipt:
        existing = self._backend.journal.get(decision.decision_sha256)
        if existing is not None:
            return existing.model_copy(update={"disposition": "REPLAYED"})
        self._backend.version_count += int(
            decision.action in {"VERIFY_AND_ACTIVATE", "TOMBSTONE_PREPARED"}
        )
        self._backend.event_count += int(
            decision.action
            in {
                "CLEAN_STAGING",
                "ACK_SOURCE",
                "ENQUEUE_REBUILD",
                "QUEUE_CLEANUP",
            }
        )
        receipt = RecoveryApplyReceipt(
            decision_sha256=decision.decision_sha256,
            disposition="APPLIED",
            after_state=decision.after_state,
            durable_result_sha256=_sha(f"result-{decision.decision_sha256}"),
        )
        self._backend.journal[decision.decision_sha256] = receipt
        return receipt


class _Backend(RecoveryBackend):
    def __init__(self, items: Sequence[RecoveryInventoryItem]) -> None:
        self.items = tuple(items)
        self.log: list[tuple[str, str, str]] = []
        self.journal: dict[str, RecoveryApplyReceipt] = {}
        self.version_count = 0
        self.event_count = 0
        self.opened_writers: list[tuple[str, RecoveryPurpose]] = []
        self.active_writers = 0
        self.max_active_writers = 0
        self._counter_lock = threading.Lock()

    def read_only_inventory(self) -> Sequence[RecoveryInventoryItem]:
        self.log.append(("inventory", "", ""))
        return self.items

    @contextmanager
    def single_writer(
        self, *, database_ref_sha256: str, purpose: RecoveryPurpose
    ) -> Iterator[RecoveryWriter]:
        self.log.append(("writer", database_ref_sha256, purpose))
        self.opened_writers.append((database_ref_sha256, purpose))
        with self._counter_lock:
            self.active_writers += 1
            self.max_active_writers = max(self.max_active_writers, self.active_writers)
        try:
            yield _JournalWriter(self)
        finally:
            with self._counter_lock:
                self.active_writers -= 1


@pytest.mark.parametrize("purpose", RECOVERY_PURPOSES)
def test_each_purpose_recovers_twice_without_duplicate_version_or_event(
    purpose: RecoveryPurpose,
) -> None:
    proof_evidence: dict[str, object] = {}
    if purpose == "outbox":
        proof_evidence = {
            "database_scope": "client",
            "source_ack_pending": True,
            "global_state": "ACTIVE",
        }
    backend = _Backend([_item(purpose=purpose, **proof_evidence)])
    coordinator = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))

    first = coordinator.recover()
    counts = (backend.version_count, backend.event_count, len(backend.journal))
    second = coordinator.recover()

    assert first.scan.decisions[0].decision_sha256 == (
        second.scan.decisions[0].decision_sha256
    )
    assert second.receipts[0].disposition == "REPLAYED"
    assert (backend.version_count, backend.event_count, len(backend.journal)) == counts


def test_inventory_is_complete_before_any_grouped_single_writer_is_opened() -> None:
    database_ref = _sha("same-database")
    backend = _Backend(
        [
            _item(database_ref_sha256=database_ref, manifest_suffix="ab"),
            _item(database_ref_sha256=database_ref, manifest_suffix="ac"),
            _item(
                purpose="graph",
                database_ref_sha256=database_ref,
                manifest_suffix="ad",
            ),
        ]
    )

    report = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW)).recover()

    assert backend.log[0][0] == "inventory"
    assert [entry[0] for entry in backend.log].count("inventory") == 1
    assert backend.opened_writers.count((database_ref, "wiki")) == 1
    assert backend.opened_writers.count((database_ref, "graph")) == 1
    assert len(report.receipts) == 3


def test_duplicate_inventory_identity_is_rejected_before_any_writer() -> None:
    duplicate = _item()
    backend = _Backend([duplicate, duplicate])

    with pytest.raises(
        RecoveryInventoryError,
        match="RECOVERY_INVENTORY_DUPLICATE",
    ):
        RecoveryCoordinator(backend=backend, clock=FixedClock(NOW)).recover()

    assert backend.opened_writers == []
    assert backend.journal == {}


def test_scan_is_read_only_and_keep_decisions_open_no_writer() -> None:
    backend = _Backend([_item(state="ACTIVE")])
    coordinator = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))

    scan = coordinator.scan()

    assert scan.query_ready
    assert scan.startup_health == "HEALTHY"
    assert scan.decisions[0].action == "KEEP"
    assert backend.opened_writers == []
    assert backend.journal == {}


def test_writer_receipt_must_match_the_exact_decision() -> None:
    class MismatchedWriter(RecoveryWriter):
        def apply(self, decision: RecoveryDecision) -> RecoveryApplyReceipt:
            return RecoveryApplyReceipt(
                decision_sha256=decision.decision_sha256,
                disposition="APPLIED",
                after_state=decision.before_state,
                durable_result_sha256=_sha("mismatched-receipt"),
            )

    class MismatchedBackend(_Backend):
        @contextmanager
        def single_writer(
            self, *, database_ref_sha256: str, purpose: RecoveryPurpose
        ) -> Iterator[RecoveryWriter]:
            self.opened_writers.append((database_ref_sha256, purpose))
            yield MismatchedWriter()

    backend = MismatchedBackend([_item()])

    with pytest.raises(
        RecoveryExecutionError,
        match="RECOVERY_RECEIPT_MISMATCH",
    ):
        RecoveryCoordinator(backend=backend, clock=FixedClock(NOW)).recover()

    assert backend.opened_writers == [(_sha("db-wiki"), "wiki")]


def test_outbox_ack_opens_only_its_source_database() -> None:
    source_database = _sha("source-db")
    unrelated_database = _sha("unrelated-client-db")
    backend = _Backend(
        [
            _item(
                purpose="outbox",
                database_scope="client",
                database_ref_sha256=source_database,
                source_ack_pending=True,
                global_state="ACTIVE",
            ),
            _item(
                purpose="profile",
                state="ACTIVE",
                database_scope="client",
                database_ref_sha256=unrelated_database,
                manifest_suffix="ac",
            ),
        ]
    )

    report = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW)).recover()

    assert {decision.action for decision in report.scan.decisions} == {
        "ACK_SOURCE",
        "KEEP",
    }
    assert backend.opened_writers == [(source_database, "outbox")]


def test_unproved_global_prepared_outbox_opens_no_writer() -> None:
    global_database = _sha("global-db")
    backend = _Backend(
        [
            _item(
                purpose="outbox",
                database_ref_sha256=global_database,
                global_state="PREPARED",
            )
        ]
    )

    report = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW)).recover()

    assert report.scan.decisions[0].action == "KEEP"
    assert report.scan.decisions[0].reason_codes == ("SOURCE_ACK_UNVERIFIED",)
    assert backend.opened_writers == []


def test_active_corruption_blocks_startup_and_enqueues_explicit_rebuild() -> None:
    item = _item(state="ACTIVE", manifest_hash_valid=False)
    backend = _Backend([item])
    coordinator = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))

    scan = coordinator.scan()

    assert scan.startup_health == "DEGRADED"
    assert not scan.query_ready
    assert len(scan.rebuild_commands) == 1
    assert scan.rebuild_commands[0].render() == (
        "consultation-kb rebuild-start --purpose wiki "
        f"--database-ref-sha256 {item.database_ref_sha256}"
    )
    with pytest.raises(RuntimeError, match="RECOVERY_STARTUP_BLOCKED"):
        coordinator.require_query_ready(scan)

    report = coordinator.recover()
    assert report.receipts[0].after_state == "ACTIVE"
    assert backend.event_count == 1


def test_active_tombstone_does_not_enqueue_rebuild_or_block_startup() -> None:
    backend = _Backend([_item(state="ACTIVE", tombstoned=True)])
    coordinator = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))

    scan = coordinator.scan()

    assert scan.startup_health == "HEALTHY"
    assert scan.query_ready
    assert scan.rebuild_commands == ()
    assert scan.decisions[0].action == "KEEP"
    assert not scan.decisions[0].query_allowed

    report = coordinator.recover()
    assert report.receipts == ()
    assert backend.opened_writers == []


def test_process_local_lock_serializes_same_database_and_purpose() -> None:
    backend = _Backend([_item()])
    coordinator = RecoveryCoordinator(backend=backend, clock=FixedClock(NOW))
    barrier = threading.Barrier(3)

    def run() -> None:
        barrier.wait()
        coordinator.recover()

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert backend.max_active_writers == 1
    assert backend.version_count == 1
