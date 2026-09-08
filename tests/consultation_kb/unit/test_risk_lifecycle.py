from __future__ import annotations

import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    InternalRiskObservationRepository,
    RiskLifecycleConflict,
    RiskObservationSource,
    RiskTriggerSpan,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint


NOW = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000201"
TURN_ID = "018f0000-0000-7000-8000-000000000202"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class BarrierClock:
    def __init__(self, value: datetime, parties: int = 2) -> None:
        self.value = value
        self.barrier = threading.Barrier(parties)

    def now(self) -> datetime:
        self.barrier.wait(timeout=5)
        return self.value


def _ref(kind: str, suffix: int) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )


def _record() -> InternalRiskObservationRecord:
    rule_ref = _ref("risk_rule", 1)
    trigger = "private!"
    normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
        trigger
    )
    return InternalRiskObservationRecord(
        session_id=SESSION_ID,
        observation=InternalRiskObservation(
            observation_id="risk_observation_018f0000-0000-7000-8000-000000000203",
            category="synthetic_high_observation",
            level="high",
            trigger_turn_ids=(TURN_ID,),
            rule_ref=rule_ref,
            detected_at=NOW,
            suggested_questions=("SYNTH-QUESTION-HIGH-VERIFY",),
        ),
        trigger_spans=(
            RiskTriggerSpan(
                turn_id=TURN_ID,
                content_ref=_ref("private_span", 2),
                start_offset=4,
                end_offset=12,
                span_sha256=hashlib.sha256(trigger.encode("utf-8")).hexdigest(),
                normalized_length=normalized_length,
                normalized_span_sha256=normalized_span_sha256,
            ),
        ),
        sources=(
            RiskObservationSource(
                source_kind="deterministic_rule",
                source_ref=rule_ref,
            ),
        ),
        confidence=0.91,
    )


def _repository() -> tuple[sqlite3.Connection, InternalRiskObservationRepository]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    InternalRiskObservationRepository.install_schema(connection, database_scope="client")
    return connection, InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=FixedClock(NOW),
    )


def test_trigger_span_carries_only_body_free_normalized_fingerprint_fields() -> None:
    assert {
        "normalized_length",
        "normalized_span_sha256",
    } <= set(RiskTriggerSpan.model_fields)


def test_repository_is_explicitly_client_only_and_never_stores_trigger_quote() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    with pytest.raises(ValueError, match="RISK_REPOSITORY_REQUIRES_CLIENT_DATABASE"):
        InternalRiskObservationRepository(connection, database_scope="global")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="RISK_REPOSITORY_REQUIRES_CLIENT_DATABASE"):
        InternalRiskObservationRepository.install_schema(
            connection, database_scope="global"  # type: ignore[arg-type]
        )

    InternalRiskObservationRepository.install_schema(connection, database_scope="client")
    repository = InternalRiskObservationRepository(
        connection, database_scope="client", clock=FixedClock(NOW)
    )
    repository.add(_record())
    stored = str(
        connection.execute(
            "SELECT immutable_record_json FROM internal_risk_observations"
        ).fetchone()[0]
    )
    assert "trigger quote" not in stored
    assert "private!" not in stored
    assert "span_sha256" in stored
    assert "normalized_length" in stored
    assert "normalized_span_sha256" in stored
    connection.close()


def test_high_observation_remains_visible_after_acknowledge_until_manual_close() -> None:
    connection, repository = _repository()
    try:
        created = repository.add(_record())
        assert repository.add(_record()) == created
        assert repository.list_visible(SESSION_ID) == (created,)

        acknowledged = repository.acknowledge(
            created.observation.observation_id,
            counselor_disposition="continue direct observation",
        )
        assert acknowledged.status == "acknowledged"
        assert acknowledged.acknowledged_at == NOW
        assert acknowledged.visible_to_counselor is True
        assert repository.list_visible(SESSION_ID) == (acknowledged,)

        with pytest.raises(RiskLifecycleConflict, match="RISK_ACKNOWLEDGEMENT_CONFLICT"):
            repository.acknowledge(
                created.observation.observation_id,
                rejection_reason="different decision",
            )

        closed = repository.close(
            created.observation.observation_id,
            decision="counselor_confirmed_closed",
            reason="Counselor manually reviewed the synthetic observation.",
        )
        assert closed.status == "closed"
        assert closed.visible_to_counselor is False
        assert repository.list_visible(SESSION_ID) == ()
    finally:
        connection.close()


def test_repository_retry_with_stable_id_keeps_first_detection_and_one_row() -> None:
    connection, repository = _repository()
    first = _record()
    retry = first.model_copy(
        update={
            "observation": first.observation.model_copy(
                update={"detected_at": NOW + timedelta(minutes=5)}
            )
        }
    )
    try:
        created = repository.add(first)
        replayed = repository.add(retry)
        row_count = connection.execute(
            "SELECT count(*) FROM internal_risk_observations"
        ).fetchone()
        provenance_retry = repository.add(
            retry.model_copy(update={"confidence": 0.92})
        )
        with pytest.raises(
            RiskLifecycleConflict,
            match="RISK_OBSERVATION_ID_CONFLICT",
        ):
            repository.add(
                retry.model_copy(
                    update={
                        "observation": retry.observation.model_copy(
                            update={"category": "different_semantic_identity"}
                        )
                    }
                )
            )
    finally:
        connection.close()

    assert replayed == created
    assert provenance_retry == created
    assert replayed.observation.detected_at == NOW
    assert row_count == (1,)


def test_close_requires_prior_human_acknowledgement_and_reason() -> None:
    connection, repository = _repository()
    try:
        created = repository.add(_record())
        with pytest.raises(
            RiskLifecycleConflict, match="RISK_CLOSE_REQUIRES_ACKNOWLEDGEMENT"
        ):
            repository.close(
                created.observation.observation_id,
                decision="resolved",
                reason="manual",
            )
        with pytest.raises(ValueError, match="nonblank manual reason"):
            repository.close(
                created.observation.observation_id,
                decision="resolved",
                reason=" ",
            )
        with pytest.raises(ValueError, match="requires disposition"):
            repository.acknowledge(created.observation.observation_id)
    finally:
        connection.close()


def test_clock_regression_cannot_commit_an_invalid_close_or_hide_reminder() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    InternalRiskObservationRepository.install_schema(connection, database_scope="client")
    clock = MutableClock(NOW)
    repository = InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=clock,
    )
    try:
        created = repository.add(_record())
        acknowledged = repository.acknowledge(
            created.observation.observation_id,
            counselor_disposition="continue direct observation",
        )
        clock.value = NOW - timedelta(minutes=1)
        with pytest.raises(
            RiskLifecycleConflict,
            match="RISK_CLOSE_PREDATES_ACKNOWLEDGEMENT",
        ):
            repository.close(
                created.observation.observation_id,
                decision="counselor_confirmed_closed",
                reason="This write must roll back before SQL mutation.",
            )
        assert repository.get(created.observation.observation_id) == acknowledged
        assert repository.list_visible(SESSION_ID) == (acknowledged,)
    finally:
        connection.close()


def _concurrent_repositories(
    path: Path,
    clock: BarrierClock,
) -> tuple[
    sqlite3.Connection,
    sqlite3.Connection,
    InternalRiskObservationRepository,
    InternalRiskObservationRepository,
]:
    connections = tuple(
        sqlite3.connect(
            path,
            isolation_level=None,
            timeout=5.0,
            check_same_thread=False,
        )
        for _ in range(2)
    )
    for connection in connections:
        connection.execute("PRAGMA busy_timeout = 5000")
    return (
        connections[0],
        connections[1],
        InternalRiskObservationRepository(
            connections[0], database_scope="client", clock=clock
        ),
        InternalRiskObservationRepository(
            connections[1], database_scope="client", clock=clock
        ),
    )


def test_concurrent_same_value_acknowledge_and_close_are_idempotent_cas_replays(
    tmp_path: Path,
) -> None:
    path = tmp_path / "risk-cas.sqlite3"
    setup = sqlite3.connect(path, isolation_level=None)
    InternalRiskObservationRepository.install_schema(setup, database_scope="client")
    setup_repository = InternalRiskObservationRepository(
        setup,
        database_scope="client",
        clock=FixedClock(NOW),
    )
    created = setup_repository.add(_record())
    setup.close()

    first, second, repo_a, repo_b = _concurrent_repositories(
        path,
        BarrierClock(NOW),
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = tuple(
                pool.submit(
                    repository.acknowledge,
                    created.observation.observation_id,
                    counselor_disposition="same disposition",
                )
                for repository in (repo_a, repo_b)
            )
            acknowledged = tuple(future.result(timeout=10) for future in futures)
        assert acknowledged[0] == acknowledged[1]
    finally:
        first.close()
        second.close()

    first, second, repo_a, repo_b = _concurrent_repositories(
        path,
        BarrierClock(NOW + timedelta(minutes=1)),
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = tuple(
                pool.submit(
                    repository.close,
                    created.observation.observation_id,
                    decision="counselor_confirmed_closed",
                    reason="same manual reason",
                )
                for repository in (repo_a, repo_b)
            )
            closed = tuple(future.result(timeout=10) for future in futures)
        assert closed[0] == closed[1]
        assert repo_a.list_visible(SESSION_ID) == ()
        with pytest.raises(RiskLifecycleConflict, match="RISK_CLOSE_CONFLICT"):
            repo_a.close(
                created.observation.observation_id,
                decision="counselor_confirmed_closed",
                reason="different manual reason",
            )
    finally:
        first.close()
        second.close()
