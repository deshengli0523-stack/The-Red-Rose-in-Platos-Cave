from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.client.mutations import (
    ApprovedMutation,
    DuplicateFact,
    FactMutationService,
    MutationConflict,
)
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.client.normalization import CanonicalFactKey, normalize_role, normalize_text
from consultation_kb.models.facts import (
    AddMutation,
    ConfirmMutation,
    CorrectMutation,
    FactEvidence,
    SupersedeMutation,
)
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


UTC = timezone.utc


def test_normalization_is_nfkc_whitespace_role_and_key_deterministic() -> None:
    assert normalize_text("  Ａ\u3000Ｂ  ") == "a b"
    assert normalize_role("现 男 友") == "male_partner"
    first = CanonicalFactKey.build(
        subject=" 来访者 ",
        predicate=" current_partner ",
        value="现 男 友",
        effective_from=datetime(2026, 7, 1, tzinfo=UTC),
        effective_to=None,
        scope="long_term_profile",
    )
    second = CanonicalFactKey.build(
        subject="来访者",
        predicate="current_partner",
        value="男朋友",
        effective_from=datetime(2026, 7, 1, tzinfo=UTC),
        effective_to=None,
        scope="long_term_profile",
    )
    assert first.digest == second.digest


def test_validity_correction_is_not_a_seventh_mutation_and_cannot_change_value() -> None:
    correction = CorrectMutation(
        target_event_id="event-1",
        correction_kind="validity",
        previous_value_json='"甲"',
        reason="relationship changed",
        effective_at=datetime(2026, 7, 1, tzinfo=UTC),
        previous_validity_status="active",
        new_validity_status="invalidated",
    )
    assert correction.operation == "CORRECT"
    with pytest.raises(ValidationError, match="correction_kind"):
        CorrectMutation(
            target_event_id="event-1",
            correction_kind="validity",
            previous_value_json='"甲"',
            reason="relationship changed",
            effective_at=datetime(2026, 7, 1, tzinfo=UTC),
            previous_validity_status="active",
            new_validity_status="invalidated",
            new_value_json='"乙"',
        )


def test_add_rejects_exact_duplicate_but_surfaces_conflicting_current_partner() -> None:
    repository = _repository()
    existing = _event(canonical_key="same-key", object_json='"甲"')
    repository.append_batch(base_commit_version=0, events=(existing,))
    service = FactMutationService(repository)
    with pytest.raises(DuplicateFact, match="DUPLICATE_FACT"):
        service.preview(AddMutation(new_fact=_event(event_id="event-2", canonical_key="same-key")))

    conflicting = _event(
        event_id="event-3",
        fact_id="fact-3",
        canonical_key="different-key",
        object_json='"乙"',
    )
    preview = service.preview(AddMutation(new_fact=conflicting))
    assert [(item.event_id, item.classification) for item in preview.candidates] == [
        ("event-1", "conflict")
    ]


def test_supersede_rejects_inverted_or_self_replacement() -> None:
    with pytest.raises(ValidationError):
        SupersedeMutation(
            target_event_id="event-1",
            replacement=_event(event_id="event-1"),
            effective_at=datetime(2026, 7, 16, tzinfo=UTC),
            reason="new partner",
        )


def test_add_rejects_caller_supplied_version_links() -> None:
    with pytest.raises(ValidationError, match="fresh version"):
        AddMutation(
            new_fact=_event(
                event_version=99,
                previous_event_id="invented-previous",
            )
        )


def test_confirm_rejects_all_counterevidence() -> None:
    with pytest.raises(ValidationError, match="supporting evidence"):
        ConfirmMutation(
            target_event_id="event-1",
            evidence=(
                FactEvidence(
                    evidence_id="evidence-1",
                    source_kind="session_statement",
                    source_ref="source-1",
                    supports=False,
                    evidence_confidence=0.9,
                ),
            ),
            calibrated_confidence=0.9,
            reason="counterevidence cannot confirm a fact",
        )


def test_supersede_rejects_cross_client_replacement_before_preview() -> None:
    repository = _repository()
    repository.append_batch(base_commit_version=0, events=(_event(),))
    service = FactMutationService(repository)
    replacement = _event(
        event_id="event-other-client",
        fact_id="fact-other-client",
        client_id="client_" + "b" * 12,
        commit_version=2,
        visible_runtime_epoch=2,
    )
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        service.preview(
            SupersedeMutation(
                target_event_id="event-1",
                replacement=replacement,
                effective_at=datetime(2026, 7, 1, tzinfo=UTC),
                reason="cross-client replacement must fail closed",
            )
        )
    assert repository.current_commit_version() == 1
    assert tuple(event.event_id for event in repository.list_events()) == ("event-1",)


def test_validity_correction_rejects_stale_previous_status() -> None:
    repository = _repository()
    repository.append_batch(
        base_commit_version=0,
        events=(_event(validity_status="superseded"),),
    )
    service = FactMutationService(repository)
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        service.preview(
            CorrectMutation(
                target_event_id="event-1",
                correction_kind="validity",
                previous_value_json=_event().object_json,
                previous_validity_status="active",
                new_validity_status="invalidated",
                reason="stale status must not be accepted",
                effective_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
        )


def test_dependency_edge_is_appended_with_fact_and_is_sql_immutable() -> None:
    repository = _repository()
    prerequisite = _event(event_id="event-prerequisite", fact_id="fact-prerequisite")
    repository.append_batch(base_commit_version=0, events=(prerequisite,))
    dependent = _event(
        event_id="event-dependent",
        fact_id="fact-dependent",
        canonical_key="dependent",
        predicate="weekend_plan",
        commit_version=2,
        visible_runtime_epoch=2,
    )
    edge = DependencyEdge(
        edge_id="dependency-1",
        dependent_fact_id=dependent.fact_id,
        prerequisite_fact_id=prerequisite.fact_id,
        dependency_type="direct_deterministic",
        confidence=1.0,
        source_event_id=dependent.event_id,
        reviewer_id="counselor",
    )
    service = FactMutationService(repository)
    preview = service.preview(AddMutation(new_fact=dependent, dependency_edges=(edge,)))
    assert preview.direct_dependency_fact_ids == (dependent.fact_id,)
    service.commit(
        preview,
        ApprovedMutation(
            preview_sha256=preview.preview_sha256,
            approval_operation_id="dependency-publication",
            runtime_epoch=2,
            source="unit_test",
        ),
    )
    assert repository.connection.execute(
        "SELECT edge_id, created_commit_version FROM fact_dependencies"
    ).fetchall() == [("dependency-1", 2)]
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repository.connection.execute(
            "UPDATE fact_dependencies SET confidence = 0.5 WHERE edge_id = ?",
            (edge.edge_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repository.connection.execute(
            "DELETE FROM fact_dependencies WHERE edge_id = ?",
            (edge.edge_id,),
        )


def test_mutation_rejects_a_nonlatest_target_event() -> None:
    repository = _repository()
    original = _event(event_id="event-original", fact_id="fact-versioned")
    repository.append_batch(base_commit_version=0, events=(original,))
    latest = _event(
        event_id="event-latest",
        fact_id=original.fact_id,
        event_version=2,
        mutation_type="CONFIRM",
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id=original.event_id,
        source_event_ids=(original.event_id,),
    )
    repository.append_batch(base_commit_version=1, events=(latest,))
    replacement = _event(
        event_id="event-replacement",
        fact_id="fact-replacement",
        commit_version=3,
        visible_runtime_epoch=3,
    )
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        FactMutationService(repository).preview(
            SupersedeMutation(
                target_event_id=original.event_id,
                replacement=replacement,
                effective_at=datetime(2026, 7, 1, tzinfo=UTC),
                reason="historical targets must not be mutated",
            )
        )
