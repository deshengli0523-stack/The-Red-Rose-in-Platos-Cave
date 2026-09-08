"""Subprocess crash worker that executes the real production write paths."""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from consultation_kb.approvals.attestation import LocalHmacTargetExecutionAttestor
from consultation_kb.archive.case_publisher import (
    CasePublishAuthoritySnapshot,
    CasePublishTransfer,
    SharedCasePublisher,
)
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofSigner,
)
from consultation_kb.client.publication import (
    ClientPublicationExecutor,
    ClientPublicationPlan,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.fault_points import (
    FaultConfigurationError,
    FaultInjector,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRecord,
    OutboxRepository,
)
from consultation_kb.vault.content_store import ContentStore


_CONFIG_NAME = "production-fault.pkl"
_CLIENT_LEGACY_PHASES = (
    "graph_finalize",
    "authoritative_event_transaction",
    "profile_finalize",
    "prepared",
    "verify",
    "epoch_switch",
)
_CASE_LEGACY_PHASES = (
    "before_copy",
    "after_copy",
    "before_catalog_prepare",
    "after_catalog_prepare",
    "before_activate",
    "after_activate",
)


def _read_config(vault: Path) -> Mapping[str, Any]:
    with (vault / _CONFIG_NAME).open("rb") as handle:
        value = pickle.load(handle)  # noqa: S301 - sealed, test-owned vault only
    if not isinstance(value, dict):
        raise RuntimeError("PRODUCTION_FAULT_CONFIG_INVALID")
    return value


def _write_control(path: Path, result: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".pending")
    with pending.open("w", encoding="ascii", newline="\n") as handle:
        json.dump(result, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(pending, path)


def _client_state(connection: sqlite3.Connection) -> dict[str, object]:
    operation_rows = connection.execute(
        "SELECT state, runtime_epoch FROM publication_operations ORDER BY operation_id"
    ).fetchall()
    return {
        "approval_rows": connection.execute(
            "SELECT count(*) FROM approval_executions"
        ).fetchone()[0],
        "approval_states": [
            str(row[0])
            for row in connection.execute(
                "SELECT state FROM approval_executions ORDER BY operation_id"
            ).fetchall()
        ],
        "fact_events": connection.execute("SELECT count(*) FROM fact_events").fetchone()[0],
        "profile_revisions": connection.execute(
            "SELECT count(*) FROM profile_revisions"
        ).fetchone()[0],
        "publication_rows": len(operation_rows),
        "publication_states": [str(row[0]) for row in operation_rows],
        "runtime_epochs": [
            [int(row[0]), str(row[1])]
            for row in connection.execute(
                "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
            ).fetchall()
        ],
        "active_artifacts": connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone()[0],
        "manifests": connection.execute(
            "SELECT count(*) FROM artifact_manifests"
        ).fetchone()[0],
    }


def _run_client(vault: Path, injector: FaultInjector) -> dict[str, object]:
    config = _read_config(vault)
    plan = config.get("plan")
    ticket = config.get("ticket")
    now = config.get("now")
    if not isinstance(plan, ClientPublicationPlan) or not isinstance(now, datetime):
        raise RuntimeError("PRODUCTION_CLIENT_CONFIG_INVALID")
    connection = connect_database(vault / "client.sqlite3", mode="writer")
    try:
        ClientPublicationExecutor(
            connection,
            scope_root=vault,
            execution_proof_signer=LocalHmacTargetExecutionAttestor(
                secret=b"t" * 32,
                attestor_id="test-target-writer",
            ),
            clock=FixedClock(now),
            fault_injector=injector.guarded_hook(
                allowed_passthrough=_CLIENT_LEGACY_PHASES
            ),
        ).execute(plan, ticket)
        return _client_state(connection)
    finally:
        connection.close()


class _SealedAuthorityResolver:
    def __init__(self, transfer: CasePublishTransfer) -> None:
        payload = transfer.outbox_payload
        self._snapshot = CasePublishAuthoritySnapshot(
            candidate_ref=payload.candidate_ref,
            authorization_ref=payload.authorization_ref,
            review_ref=payload.review_ref,
            release_policy_ref=payload.release_policy_ref,
            release_decision_sha256=payload.release_decision_sha256,
            provenance_ref=payload.provenance_ref,
            purpose=payload.purpose,
            approval_operation_id=payload.approval_operation_id,
            approval_request_id=payload.approval_request_id,
            approval_descriptor_sha256=payload.approval_descriptor_sha256,
            approval_draft_sha256=payload.approval_draft_sha256,
            approval_descriptor_base_version=payload.candidate_ref.version,
            approval_applied_commit_version=1,
            approval_target_scope_hash=payload.approval_target_scope_hash,
            authority_epoch=1,
            state="active",
        )

    def resolve_case_publish_authority(
        self,
        *,
        payload: CasePublishOutboxPayload,
        as_of: datetime,
    ) -> CasePublishAuthoritySnapshot | None:
        del payload, as_of
        return self._snapshot


def _case_state(
    source: sqlite3.Connection,
    global_connection: sqlite3.Connection,
) -> dict[str, object]:
    return {
        "source": [
            [str(row[0]), int(row[1]), None if row[2] is None else int(row[2])]
            for row in source.execute(
                "SELECT state, attempt_count, published_global_version "
                "FROM outbox_events ORDER BY event_id"
            ).fetchall()
        ],
        "sagas": [
            [str(row[0])]
            for row in global_connection.execute(
                "SELECT state FROM global_publish_sagas "
                "ORDER BY source_event_id"
            ).fetchall()
        ],
        "cases": global_connection.execute("SELECT count(*) FROM cases").fetchone()[0],
        "case_versions": global_connection.execute(
            "SELECT count(*) FROM case_versions"
        ).fetchone()[0],
        "active_case_versions": global_connection.execute(
            "SELECT count(*) FROM case_versions WHERE state = 'ACTIVE'"
        ).fetchone()[0],
        "runtime_epochs": [
            [int(row[0]), str(row[1])]
            for row in global_connection.execute(
                "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
            ).fetchall()
        ],
        "active_artifacts": global_connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone()[0],
    }


def _run_case(vault: Path, injector: FaultInjector) -> dict[str, object]:
    config = _read_config(vault)
    event = config.get("event")
    transfer = config.get("transfer")
    now = config.get("now")
    if (
        not isinstance(event, OutboxRecord)
        or not isinstance(transfer, CasePublishTransfer)
        or not isinstance(now, datetime)
    ):
        raise RuntimeError("PRODUCTION_CASE_CONFIG_INVALID")
    source = connect_database(vault / "source.sqlite3", mode="writer")
    global_connection = connect_database(vault / "global.sqlite3", mode="writer")
    try:
        outbox = OutboxRepository(source)
        current = outbox.get(event.event_id)
        if current.state == "PENDING":
            injector.hit("after_source_outbox")
            current = outbox.claim(event.event_id, claimed_at=now + timedelta(seconds=1))
        publisher_clock = FixedClock(now + timedelta(seconds=2))
        publisher = SharedCasePublisher(
            global_connection,
            ContentStore(vault / "global-cas"),
            authority_resolver=_SealedAuthorityResolver(transfer),
            publication_proof_signer=LocalHmacCasePublicationProofSigner(
                secret=b"t" * 32,
                attestor_id="test-target-writer",
            ),
            clock=publisher_clock,
            id_factory=IdFactory(
                publisher_clock,
                random_source=iter(range(100, 200)).__next__,
            ),
        )
        publication = publisher.replay(
            current,
            transfer,
            fault_hook=injector.guarded_hook(
                allowed_passthrough=_CASE_LEGACY_PHASES
            ),
        )
        injector.hit("before_source_ack")
        outbox.mark_published(
            event.event_id,
            global_version=publication.case_ref.version,
            published_at=now + timedelta(seconds=3),
            publication_proof=publication.proof,
        )
        return _case_state(source, global_connection)
    finally:
        global_connection.close()
        source.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("client", "case"), required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--test-mode", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    vault = args.vault.resolve(strict=True)
    try:
        injector = FaultInjector.from_environment(
            test_mode=bool(args.test_mode),
            vault_root=vault,
        )
    except FaultConfigurationError as exc:
        raise SystemExit(str(exc)) from exc
    result = (
        _run_client(vault, injector)
        if args.scenario == "client"
        else _run_case(vault, injector)
    )
    _write_control(args.control.resolve(), result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
