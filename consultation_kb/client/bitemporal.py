"""Deterministic bitemporal queries over immutable client fact events."""

from __future__ import annotations

import hashlib
import json
from typing import TypeVar

from pydantic import Field, model_validator

from consultation_kb.models.common import StrictModel, UtcDateTime
from consultation_kb.models.facts import (
    EpistemicStatus,
    FactEvent,
    ResolutionStatus,
    ReviewStatus,
    ValidityStatus,
)
from consultation_kb.storage.client_ledger import FactEventRepository


_Status = TypeVar("_Status", bound=str)


class FactQuery(StrictModel):
    effective_at: UtcDateTime
    known_at: UtcDateTime
    fixed_epoch: int = Field(strict=True, ge=0)
    review_statuses: frozenset[ReviewStatus] | None = None
    validity_statuses: frozenset[ValidityStatus] | None = None
    resolution_statuses: frozenset[ResolutionStatus] | None = None
    epistemic_statuses: frozenset[EpistemicStatus] | None = None

    @model_validator(mode="after")
    def _nonempty_filters(self) -> "FactQuery":
        for value in (
            self.review_statuses,
            self.validity_statuses,
            self.resolution_statuses,
            self.epistemic_statuses,
        ):
            if value is not None and not value:
                raise ValueError("an explicit status filter must not be empty")
        return self


class BitemporalSnapshot(StrictModel):
    query: FactQuery
    client_commit_version: int = Field(strict=True, ge=0)
    events: tuple[FactEvent, ...]
    event_ids: tuple[str, ...]
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _integrity(self) -> "BitemporalSnapshot":
        if self.event_ids != tuple(event.event_id for event in self.events):
            raise ValueError("snapshot event IDs do not match events")
        expected = snapshot_sha256(self.query, self.client_commit_version, self.events)
        if expected != self.canonical_sha256:
            raise ValueError("snapshot hash mismatch")
        return self


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def snapshot_sha256(
    query: FactQuery,
    commit_version: int,
    events: tuple[FactEvent, ...],
) -> str:
    payload = {
        "client_commit_version": commit_version,
        "events": [event.model_dump(mode="json") for event in events],
        "query": query.model_dump(mode="json"),
        "schema_version": "client_fact_snapshot.v1",
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _matches_filter(value: _Status, accepted: frozenset[_Status] | None) -> bool:
    return accepted is None or value in accepted


def _is_time_correction(event: FactEvent, predecessor: FactEvent) -> bool:
    """Identify the only CORRECT variant that rewrites the business window.

    Mutation validation requires value corrections to change ``object_json``
    and validity corrections to change ``validity_status``.  A CORRECT event
    that preserves the value and all four independent status axes while
    changing the effective window is therefore an exact time correction.
    """

    return (
        event.mutation_type == "CORRECT"
        and event.previous_event_id == predecessor.event_id
        and event.fact_id == predecessor.fact_id
        and event.object_json == predecessor.object_json
        and event.review_status == predecessor.review_status
        and event.validity_status == predecessor.validity_status
        and event.resolution_status == predecessor.resolution_status
        and event.epistemic_status == predecessor.epistemic_status
        and (event.effective_from, event.effective_to)
        != (predecessor.effective_from, predecessor.effective_to)
    )


def _time_corrected_event_ids(events: tuple[FactEvent, ...]) -> frozenset[str]:
    """Return obsolete event windows after all currently-known corrections.

    Consecutive time corrections with the same semantic value invalidate the
    whole same-value window chain.  Traversal stops at a value correction so a
    genuinely different predecessor can still apply before the corrected
    value's start time.
    """

    by_id = {event.event_id: event for event in events}
    obsolete: set[str] = set()
    for event in events:
        current = event
        while current.previous_event_id is not None:
            predecessor = by_id.get(current.previous_event_id)
            if predecessor is None or not _is_time_correction(current, predecessor):
                break
            obsolete.add(predecessor.event_id)
            current = predecessor
    return frozenset(obsolete)


class BitemporalFactQuery:
    def __init__(self, repository: FactEventRepository) -> None:
        self._repository = repository

    def execute(self, query: FactQuery) -> tuple[FactEvent, ...]:
        validated = FactQuery.model_validate(query)
        return self.select_events(
            self._repository.list_events(fixed_epoch=validated.fixed_epoch),
            validated,
        )

    @staticmethod
    def select_events(
        events: tuple[FactEvent, ...],
        query: FactQuery,
    ) -> tuple[FactEvent, ...]:
        """Project a snapshot from an explicit immutable event closure."""

        validated = FactQuery.model_validate(query)
        validated_events = tuple(FactEvent.model_validate(event) for event in events)
        known: list[FactEvent] = []
        for event in validated_events:
            if event.visible_runtime_epoch > validated.fixed_epoch:
                continue
            if event.recorded_at > validated.known_at or event.approved_at > validated.known_at:
                continue
            known.append(event)

        known_events = tuple(known)
        obsolete_time_windows = _time_corrected_event_ids(known_events)
        eligible: list[FactEvent] = []
        for event in known_events:
            if event.event_id in obsolete_time_windows:
                continue
            if event.effective_from > validated.effective_at:
                continue
            if event.effective_to is not None and validated.effective_at >= event.effective_to:
                continue
            eligible.append(event)

        selected: dict[str, FactEvent] = {}
        for event in eligible:
            previous = selected.get(event.fact_id)
            if previous is None or (
                event.approved_at,
                event.recorded_at,
                event.event_version,
                event.event_id,
            ) > (
                previous.approved_at,
                previous.recorded_at,
                previous.event_version,
                previous.event_id,
            ):
                selected[event.fact_id] = event
        filtered = (
            event
            for event in selected.values()
            if _matches_filter(event.review_status, validated.review_statuses)
            and _matches_filter(event.validity_status, validated.validity_statuses)
            and _matches_filter(event.resolution_status, validated.resolution_statuses)
            and _matches_filter(event.epistemic_status, validated.epistemic_statuses)
        )
        return tuple(
            sorted(
                filtered,
                key=lambda event: (
                    event.subject,
                    event.predicate,
                    event.effective_from,
                    event.fact_id,
                ),
            )
        )

    @staticmethod
    def snapshot_events(
        events: tuple[FactEvent, ...],
        query: FactQuery,
        *,
        client_commit_version: int,
    ) -> BitemporalSnapshot:
        if type(client_commit_version) is not int or client_commit_version < 0:
            raise ValueError("client commit version must be non-negative")
        validated_query = FactQuery.model_validate(query)
        selected = BitemporalFactQuery.select_events(events, validated_query)
        return BitemporalSnapshot(
            query=validated_query,
            client_commit_version=client_commit_version,
            events=selected,
            event_ids=tuple(event.event_id for event in selected),
            canonical_sha256=snapshot_sha256(
                validated_query,
                client_commit_version,
                selected,
            ),
        )

    def snapshot(self, query: FactQuery) -> BitemporalSnapshot:
        events = self.execute(query)
        commit_version = max(
            (
                event.commit_version
                for event in self._repository.list_events(fixed_epoch=query.fixed_epoch)
            ),
            default=0,
        )
        return BitemporalSnapshot(
            query=query,
            client_commit_version=commit_version,
            events=events,
            event_ids=tuple(event.event_id for event in events),
            canonical_sha256=snapshot_sha256(query, commit_version, events),
        )


__all__ = [
    "BitemporalFactQuery",
    "BitemporalSnapshot",
    "FactQuery",
    "snapshot_sha256",
]
