"""Scoped, append-only repository for one client's fact ledger."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping

from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import FactEvent, FactEvidence
from consultation_kb.storage.connection import transaction


class FactLedgerError(RuntimeError):
    """Base fixed-code ledger error."""


class StaleFactPreview(FactLedgerError):
    def __init__(self) -> None:
        super().__init__("STALE_FACT_PREVIEW")


class FactLedgerIntegrityError(FactLedgerError):
    def __init__(self) -> None:
        super().__init__("FACT_LEDGER_INTEGRITY_ERROR")


_EVENT_COLUMNS = (
    "event_id",
    "fact_id",
    "client_id",
    "event_version",
    "mutation_type",
    "canonical_key",
    "subject",
    "predicate",
    "object_json",
    "cognitive_type",
    "source_kind",
    "source_session_id",
    "source_turn_id",
    "source_ref",
    "effective_from",
    "effective_to",
    "time_precision",
    "timezone_name",
    "recorded_at",
    "approved_at",
    "reported_at",
    "observed_at",
    "transaction_id",
    "commit_version",
    "publication_operation_id",
    "visible_runtime_epoch",
    "review_status",
    "validity_status",
    "resolution_status",
    "epistemic_status",
    "fact_confidence",
    "model_confidence",
    "reviewer_id",
    "review_reason",
    "review_source",
    "privacy_level",
    "allowed_purposes_json",
    "applicability_json",
    "source_anchor_json",
    "supersedes_event_id",
    "previous_event_id",
    "replacement_event_id",
    "source_event_ids_json",
    "relation_type",
)
_INSERT = (
    f"INSERT INTO fact_events ({','.join(_EVENT_COLUMNS)}) "
    f"VALUES ({','.join('?' for _ in _EVENT_COLUMNS)})"
)


class FactEventRepository:
    """One-scope repository; production composition lives only in the worker."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("FactEventRepository requires sqlite3.Connection")
        self.connection = connection

    def current_commit_version(self) -> int:
        row = self.connection.execute(
            "SELECT commit_version FROM client_fact_authority WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise FactLedgerIntegrityError
        return row[0]

    def bound_client_id(self) -> str | None:
        row = self.connection.execute(
            "SELECT client_id FROM client_fact_authority WHERE singleton = 1"
        ).fetchone()
        if row is None or (row[0] is not None and type(row[0]) is not str):
            raise FactLedgerIntegrityError
        return row[0]

    def append(self, event: FactEvent) -> FactEvent:
        validated = FactEvent.model_validate(event)
        current = self.current_commit_version()
        if validated.commit_version != current + 1:
            raise StaleFactPreview
        self.append_batch(base_commit_version=current, events=(validated,))
        return validated

    def append_batch(
        self,
        *,
        base_commit_version: int,
        events: Iterable[FactEvent],
        merge_members: Mapping[str, tuple[str, ...]] | None = None,
        evidence: Mapping[str, tuple[FactEvidence, ...]] | None = None,
        dependencies: Iterable[DependencyEdge] = (),
    ) -> int:
        with transaction(self.connection):
            return self.append_batch_in_transaction(
                base_commit_version=base_commit_version,
                events=events,
                merge_members=merge_members,
                evidence=evidence,
                dependencies=dependencies,
            )

    def append_batch_in_transaction(
        self,
        *,
        base_commit_version: int,
        events: Iterable[FactEvent],
        merge_members: Mapping[str, tuple[str, ...]] | None = None,
        evidence: Mapping[str, tuple[FactEvidence, ...]] | None = None,
        dependencies: Iterable[DependencyEdge] = (),
    ) -> int:
        """Append under an enclosing approval transaction.

        Production publication calls this only from
        ``ApprovalExecutionGuard.apply_in_transaction`` so the approval claim,
        immutable facts, derived manifests, and authority CAS either all
        commit or all roll back.
        """

        if not self.connection.in_transaction:
            raise FactLedgerIntegrityError
        if type(base_commit_version) is not int or base_commit_version < 0:
            raise ValueError("base_commit_version must be a non-negative integer")
        validated = tuple(FactEvent.model_validate(event) for event in events)
        validated_dependencies = tuple(
            DependencyEdge.model_validate(edge) for edge in dependencies
        )
        if not validated:
            raise ValueError("at least one fact event is required")
        next_version = base_commit_version + 1
        if any(event.commit_version != next_version for event in validated):
            raise FactLedgerIntegrityError
        if len({event.event_id for event in validated}) != len(validated):
            raise FactLedgerIntegrityError
        if len({edge.edge_id for edge in validated_dependencies}) != len(
            validated_dependencies
        ):
            raise FactLedgerIntegrityError
        client_ids = {event.client_id for event in validated}
        if len(client_ids) != 1:
            raise FactLedgerIntegrityError
        client_id = next(iter(client_ids))
        authority = self.connection.execute(
            "SELECT commit_version, client_id FROM client_fact_authority "
            "WHERE singleton = 1"
        ).fetchone()
        if authority is None or type(authority[0]) is not int:
            raise FactLedgerIntegrityError
        if authority[0] != base_commit_version:
            raise StaleFactPreview
        if authority[1] is not None and authority[1] != client_id:
            raise FactLedgerIntegrityError

        batch_clients = {event.event_id: event.client_id for event in validated}
        referenced_event_ids = {
            reference
            for event in validated
            for reference in (
                event.previous_event_id,
                event.supersedes_event_id,
                event.replacement_event_id,
                *event.source_event_ids,
            )
            if reference is not None
        }
        referenced_event_ids.update(
            member_event_id
            for member_event_ids in (merge_members or {}).values()
            for member_event_id in member_event_ids
        )
        for reference in sorted(referenced_event_ids):
            reference_client = batch_clients.get(reference)
            if reference_client is None:
                row = self.connection.execute(
                    "SELECT client_id FROM fact_events WHERE event_id = ?",
                    (reference,),
                ).fetchone()
                if row is None:
                    raise FactLedgerIntegrityError
                reference_client = str(row[0])
            if reference_client != client_id:
                raise FactLedgerIntegrityError
        try:
            changed = self.connection.execute(
                "UPDATE client_fact_authority "
                "SET commit_version = ?, client_id = COALESCE(client_id, ?) "
                "WHERE singleton = 1 AND commit_version = ? "
                "AND (client_id IS NULL OR client_id = ?)",
                (next_version, client_id, base_commit_version, client_id),
            ).rowcount
            if changed != 1:
                raise StaleFactPreview
            for event in validated:
                record = event.to_record()
                if tuple(record) != _EVENT_COLUMNS:
                    raise FactLedgerIntegrityError
                self.connection.execute(_INSERT, tuple(record.values()))
            batch_event_ids = {event.event_id for event in validated}
            batch_fact_ids = {event.fact_id for event in validated}
            for dependency in sorted(
                validated_dependencies,
                key=lambda edge: edge.edge_id,
            ):
                if (
                    dependency.source_event_id not in batch_event_ids
                    or not batch_fact_ids.intersection(
                        {
                            dependency.dependent_fact_id,
                            dependency.prerequisite_fact_id,
                        }
                    )
                ):
                    raise FactLedgerIntegrityError
                endpoint_rows = self.connection.execute(
                    "SELECT DISTINCT fact_id FROM fact_events "
                    "WHERE client_id = ? AND fact_id IN (?, ?)",
                    (
                        client_id,
                        dependency.dependent_fact_id,
                        dependency.prerequisite_fact_id,
                    ),
                ).fetchall()
                if {str(row[0]) for row in endpoint_rows} != {
                    dependency.dependent_fact_id,
                    dependency.prerequisite_fact_id,
                }:
                    raise FactLedgerIntegrityError
                source_row = self.connection.execute(
                    "SELECT client_id FROM fact_events WHERE event_id = ?",
                    (dependency.source_event_id,),
                ).fetchone()
                if source_row != (client_id,):
                    raise FactLedgerIntegrityError
                self.connection.execute(
                    "INSERT INTO fact_dependencies("
                    "edge_id, dependent_fact_id, prerequisite_fact_id, "
                    "dependency_type, confidence, source_event_id, reviewer_id, "
                    "created_commit_version"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        dependency.edge_id,
                        dependency.dependent_fact_id,
                        dependency.prerequisite_fact_id,
                        dependency.dependency_type,
                        dependency.confidence,
                        dependency.source_event_id,
                        dependency.reviewer_id,
                        next_version,
                    ),
                )
            for projection_event_id, member_event_ids in sorted(
                (merge_members or {}).items()
            ):
                if len(member_event_ids) < 2 or len(set(member_event_ids)) != len(
                    member_event_ids
                ):
                    raise FactLedgerIntegrityError
                for ordinal, member_event_id in enumerate(member_event_ids):
                    member = self.connection.execute(
                        "SELECT source_session_id, source_turn_id, recorded_at, client_id "
                        "FROM fact_events WHERE event_id = ?",
                        (member_event_id,),
                    ).fetchone()
                    if member is None or member[3] != client_id:
                        raise FactLedgerIntegrityError
                    self.connection.execute(
                        "INSERT INTO fact_merge_members("
                        "projection_event_id, member_event_id, member_session_id, "
                        "member_turn_id, member_recorded_at, ordinal"
                        ") VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            projection_event_id,
                            member_event_id,
                            member[0],
                            member[1],
                            member[2],
                            ordinal,
                        ),
                    )
            for event_id, event_evidence in sorted((evidence or {}).items()):
                for item in sorted(event_evidence, key=lambda value: value.evidence_id):
                    validated_evidence = FactEvidence.model_validate(item)
                    self.connection.execute(
                        "INSERT INTO fact_evidence("
                        "event_id, evidence_id, source_kind, source_ref, supports, "
                        "evidence_confidence"
                        ") VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            event_id,
                            validated_evidence.evidence_id,
                            validated_evidence.source_kind,
                            validated_evidence.source_ref,
                            int(validated_evidence.supports),
                            validated_evidence.evidence_confidence,
                        ),
                    )
        except StaleFactPreview:
            raise
        except sqlite3.IntegrityError:
            raise
        return next_version

    def get_event(self, event_id: str) -> FactEvent:
        row = self.connection.execute(
            f"SELECT {','.join(_EVENT_COLUMNS)} FROM fact_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise KeyError(event_id)
        return FactEvent.from_record(dict(zip(_EVENT_COLUMNS, row, strict=True)))

    def get_latest_event(self, fact_id: str) -> FactEvent:
        row = self.connection.execute(
            f"SELECT {','.join(_EVENT_COLUMNS)} FROM fact_events "
            "WHERE fact_id = ? ORDER BY event_version DESC, event_id DESC LIMIT 1",
            (fact_id,),
        ).fetchone()
        if row is None:
            raise KeyError(fact_id)
        return FactEvent.from_record(dict(zip(_EVENT_COLUMNS, row, strict=True)))

    def list_events(
        self,
        *,
        fixed_epoch: int | None = None,
    ) -> tuple[FactEvent, ...]:
        parameters: tuple[object, ...] = ()
        predicate = ""
        if fixed_epoch is not None:
            if type(fixed_epoch) is not int or fixed_epoch < 0:
                raise ValueError("fixed_epoch must be a non-negative integer")
            predicate = " WHERE visible_runtime_epoch <= ?"
            parameters = (fixed_epoch,)
        rows = self.connection.execute(
            f"SELECT {','.join(_EVENT_COLUMNS)} FROM fact_events"
            f"{predicate} ORDER BY commit_version, event_id",
            parameters,
        ).fetchall()
        return tuple(
            FactEvent.from_record(dict(zip(_EVENT_COLUMNS, row, strict=True)))
            for row in rows
        )

    def list_merge_member_ids(self) -> frozenset[str]:
        return frozenset(
            str(row[0])
            for row in self.connection.execute(
                "SELECT member_event_id FROM fact_merge_members ORDER BY member_event_id"
            ).fetchall()
        )


__all__ = [
    "FactEventRepository",
    "FactLedgerError",
    "FactLedgerIntegrityError",
    "StaleFactPreview",
]
