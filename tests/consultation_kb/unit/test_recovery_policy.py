from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from consultation_kb.lifecycle.recovery_policy import RecoveryPolicyRegistry
from consultation_kb.models.recovery import (
    RECOVERY_PURPOSES,
    RecoveryAction,
    RecoveryInventoryItem,
    RecoveryPurpose,
    RecoveryState,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
MANIFEST_ID = "manifest_01890f9d-5b40-7abc-8def-1234567890ab"


def _item(
    *,
    purpose: RecoveryPurpose = "wiki",
    state: RecoveryState = "PREPARED",
    **overrides: object,
) -> RecoveryInventoryItem:
    values: dict[str, object] = {
        "database_ref_sha256": "1" * 64,
        "database_scope": "global",
        "purpose": purpose,
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "2" * 64,
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


@pytest.mark.parametrize(
    ("item", "expected_action", "expected_after"),
    [
        (
            _item(
                state="DRAFT",
                formal_intent_present=False,
                staging_expires_at=NOW - timedelta(seconds=1),
            ),
            "CLEAN_STAGING",
            "RETIRED",
        ),
        (_item(state="PREPARED"), "VERIFY_AND_ACTIVATE", "ACTIVE"),
        (
            _item(state="PREPARED", members_complete=False),
            "TOMBSTONE_PREPARED",
            "RETIRED",
        ),
        (_item(state="ACTIVE"), "KEEP", "ACTIVE"),
        (
            _item(state="ACTIVE", manifest_hash_valid=False),
            "ENQUEUE_REBUILD",
            "ACTIVE",
        ),
        (_item(state="RETIRED"), "KEEP", "RETIRED"),
        (
            _item(
                state="RETIRED",
                rollback_expires_at=NOW - timedelta(seconds=1),
            ),
            "QUEUE_CLEANUP",
            "RETIRED",
        ),
    ],
)
def test_state_matrix(
    item: RecoveryInventoryItem,
    expected_action: RecoveryAction,
    expected_after: RecoveryState,
) -> None:
    decision = RecoveryPolicyRegistry.default().decide(item, observed_at=NOW)

    assert decision.action == expected_action
    assert decision.before_state == item.state
    assert decision.after_state == expected_after
    assert decision.manifest_id == item.manifest_id
    assert decision.manifest_sha256 == item.manifest_sha256
    assert len(decision.evidence_sha256) == 64


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"base_version": 2}, "BASE_VERSION_STALE"),
        ({"approval_intent_valid": False}, "APPROVAL_INTENT_INVALID"),
        ({"approval_epoch": 4}, "APPROVAL_EPOCH_STALE"),
        ({"permission_allows_activation": False}, "PERMISSION_TIGHTENED"),
        ({"permission_epoch": 6}, "PERMISSION_TIGHTENED"),
        ({"tombstone_epoch": 8}, "TOMBSTONE_EPOCH_STALE"),
    ],
)
def test_prepared_stale_authority_fails_closed(
    overrides: dict[str, object], reason: str
) -> None:
    item = _item().model_copy(update=overrides)
    decision = RecoveryPolicyRegistry.default().decide(item, observed_at=NOW)

    assert decision.action == "TOMBSTONE_PREPARED"
    assert decision.after_state == "RETIRED"
    assert reason in decision.reason_codes
    assert decision.query_allowed


def test_visible_tombstone_has_priority_over_other_prepared_failures() -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            tombstoned=True,
            manifest_hash_valid=False,
            approval_intent_valid=False,
            permission_allows_activation=False,
        ),
        observed_at=NOW,
    )

    assert decision.action == "TOMBSTONE_PREPARED"
    assert decision.verification_result == "TOMBSTONED"
    assert decision.reason_codes[0] == "TOMBSTONED"


def test_active_corruption_never_rolls_back_to_an_unknown_version() -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            state="ACTIVE",
            members_complete=False,
            source_version=3,
            tombstone_epoch=8,
        ),
        observed_at=NOW,
    )

    assert decision.action == "ENQUEUE_REBUILD"
    assert decision.before_state == decision.after_state == "ACTIVE"
    assert not decision.query_allowed
    assert decision.rebuild_required


def test_active_tombstone_stays_non_queryable_without_rebuild() -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            state="ACTIVE",
            tombstoned=True,
            members_complete=False,
            manifest_hash_valid=False,
        ),
        observed_at=NOW,
    )

    assert decision.action == "KEEP"
    assert decision.before_state == decision.after_state == "ACTIVE"
    assert decision.verification_result == "TOMBSTONED"
    assert decision.reason_codes == ("TOMBSTONED",)
    assert not decision.query_allowed
    assert not decision.rebuild_required


def test_outbox_global_active_with_invalid_approval_never_acks_source() -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            purpose="outbox",
            database_scope="client",
            activation_mode="sealed_replay",
            source_ack_pending=True,
            global_state="ACTIVE",
            approval_intent_valid=False,
            base_version=2,
        ),
        observed_at=NOW,
    )

    assert decision.action == "KEEP"
    assert decision.after_state == "PREPARED"
    assert "APPROVAL_INTENT_INVALID" in decision.reason_codes


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"permission_allows_activation": False}, "PERMISSION_TIGHTENED"),
        ({"permission_epoch": 6}, "PERMISSION_TIGHTENED"),
        ({"tombstone_epoch": 8}, "TOMBSTONE_EPOCH_STALE"),
    ],
)
def test_outbox_ack_never_overrides_revocation_authority(
    overrides: dict[str, object], reason: str
) -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            purpose="outbox",
            database_scope="client",
            source_ack_pending=True,
            global_state="ACTIVE",
            **overrides,
        ),
        observed_at=NOW,
    )

    assert decision.action == "TOMBSTONE_PREPARED"
    assert decision.after_state == "RETIRED"
    assert reason in decision.reason_codes


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"members_complete": False}, "MEMBERS_INCOMPLETE"),
        ({"manifest_hash_valid": False}, "MANIFEST_HASH_INVALID"),
    ],
)
def test_outbox_ack_requires_an_intact_source_event(
    overrides: dict[str, object], reason: str
) -> None:
    decision = RecoveryPolicyRegistry.default().decide(
        _item(
            purpose="outbox",
            database_scope="client",
            source_ack_pending=True,
            global_state="ACTIVE",
            approval_intent_valid=False,
            base_version=2,
            **overrides,
        ),
        observed_at=NOW,
    )

    assert decision.action == "TOMBSTONE_PREPARED"
    assert decision.after_state == "RETIRED"
    assert reason in decision.reason_codes


def test_every_purpose_has_a_deterministic_policy_and_body_free_decision() -> None:
    registry = RecoveryPolicyRegistry.default()

    for purpose in RECOVERY_PURPOSES:
        item = _item(purpose=purpose)
        first = registry.decide(item, observed_at=NOW)
        second = registry.decide(item, observed_at=NOW + timedelta(seconds=1))

        assert first.decision_sha256 == second.decision_sha256
        assert first == second
        rendered = first.model_dump_json()
        assert "client_" not in rendered
        assert "transcript" not in rendered
        assert "consultation body" not in rendered
