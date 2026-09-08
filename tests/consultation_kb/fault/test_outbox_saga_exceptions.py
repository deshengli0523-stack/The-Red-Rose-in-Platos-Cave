from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.integration.test_case_publish_saga import (
    InjectedSagaFailure,
    _MutableCasePublishAuthority,
    _global_database,
    _package,
    _publisher,
)


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]

_STATE_AFTER_FAULT = {
    "before_copy": "RECEIVED",
    "after_copy": "COPIED",
    "before_catalog_prepare": "COPIED",
    "after_catalog_prepare": "PREPARED",
    "before_activate": "PREPARED",
    "after_activate": "ACTIVE",
}


@pytest.mark.parametrize("phase", tuple(_STATE_AFTER_FAULT))
def test_python_exception_replay_keeps_verified_ledger_atomic_and_publishes_once(
    tmp_path: Path,
    phase: str,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global-cas"
    first_event, first_transfer, now = _package(
        seed=1,
        idempotency_key="tx-01-baseline",
    )
    second_event, second_transfer, _ = _package(
        seed=10_000,
        idempotency_key="tx-01-replayed",
    )
    first_authority = _MutableCasePublishAuthority(first_transfer)
    second_authority = _MutableCasePublishAuthority(second_transfer)

    class _CombinedAuthority:
        def resolve_case_publish_authority(self, *, payload, as_of):
            authority = (
                first_authority
                if payload.candidate_ref == first_transfer.outbox_payload.candidate_ref
                else second_authority
            )
            return authority.resolve_case_publish_authority(
                payload=payload,
                as_of=as_of,
            )

    publisher = _publisher(connection, store_root, now, _CombinedAuthority())
    catalog = CaseCatalog(connection, ContentStore(store_root))
    try:
        baseline = publisher.process(first_event, first_transfer)

        def fail_at(actual: str) -> None:
            if actual == phase:
                raise InjectedSagaFailure(actual)

        with pytest.raises(InjectedSagaFailure, match=phase):
            publisher.process(second_event, second_transfer, fault_hook=fail_at)

        saga = connection.execute(
            """
            SELECT case_id, manifest_id, state, attempt_count
              FROM global_publish_sagas
             WHERE source_event_id = ?
            """,
            (second_event.event_id,),
        ).fetchone()
        assert saga is not None
        second_case_id, second_manifest_id, state, attempts = saga
        assert state == _STATE_AFTER_FAULT[phase]
        assert attempts == 1

        visible_before = catalog.active_cases(purpose="answer_support")
        expected_visible = 2 if phase == "after_activate" else 1
        assert len(visible_before) == expected_visible
        assert baseline.case_ref in {item.case_ref for item in visible_before}

        # Shared cases are durable VERIFIED ledgers. They deliberately do not
        # create a standalone retrieval runtime epoch or active-artifact alias;
        # the next full global rebuild incorporates their approved candidates.
        assert connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == []
        assert connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts"
        ).fetchall() == []

        second_case = connection.execute(
            "SELECT state, current_version FROM cases WHERE case_id = ?",
            (second_case_id,),
        ).fetchone()
        if state in {"RECEIVED", "COPIED"}:
            assert second_case is None
        elif state == "PREPARED":
            assert second_case == ("PREPARED", None)
            assert connection.execute(
                "SELECT state FROM case_versions WHERE case_id = ?",
                (second_case_id,),
            ).fetchone() == ("PREPARED",)
        else:
            assert second_case == ("ACTIVE", 1)

        publication = publisher.replay(second_event, second_transfer)
        replayed = publisher.replay(second_event, second_transfer)
        assert replayed == publication

        visible_after = catalog.active_cases(purpose="answer_support")
        assert {item.case_ref for item in visible_after} == {
            baseline.case_ref,
            publication.case_ref,
        }
        assert len(catalog.read_body(visible_after[0]).sections) >= 2
        assert len(catalog.read_body(visible_after[1]).sections) >= 2
        assert connection.execute(
            "SELECT state, attempt_count FROM global_publish_sagas "
            "WHERE source_event_id = ?",
            (second_event.event_id,),
        ).fetchone() == ("ACTIVE", 3)
        assert connection.execute(
            "SELECT count(*) FROM global_publish_sagas"
        ).fetchone() == (2,)
        assert connection.execute("SELECT count(*) FROM cases").fetchone() == (2,)
        assert connection.execute(
            "SELECT count(*) FROM case_versions"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == []
        assert connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts"
        ).fetchall() == []
        assert connection.execute(
            "SELECT manifest_id, artifact_kind, state, verified "
            "FROM artifact_manifests WHERE manifest_id IN (?, ?) "
            "ORDER BY manifest_id",
            tuple(sorted((baseline.manifest_id, publication.manifest_id))),
        ).fetchall() == [
            (manifest_id, "shared_case", "VERIFIED", 1)
            for manifest_id in sorted(
                (baseline.manifest_id, publication.manifest_id)
            )
        ]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()
