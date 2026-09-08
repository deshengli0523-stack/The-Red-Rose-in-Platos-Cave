from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.c1_projection import (
    C1ContextProjectionError,
    build_c1_applicability_input,
)
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    Subquery,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.models.profile import (
    ProfileItem,
    ProfileSection,
    ProfileSnapshot,
    profile_sha256,
)
from consultation_kb.models.session import StoredContentRef, TemporaryFactEvent
from consultation_kb.security.worker_protocol import GenerationClientBinding
from consultation_kb.session.context import (
    ClientContextSnapshot,
    client_context_sha256,
)


NOW = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)
IDS = IdFactory(FixedClock(NOW), lambda: 41)


def _annotation(field: str, state: str, values: tuple[str, ...] = ()) -> dict[str, object]:
    return {
        "c1_context": {
            "schema_version": "c1_context_projection.v1",
            "fields": [
                {
                    "context_field": field,
                    "state": state,
                    "value_keys": list(values),
                }
            ],
        }
    }


def _profile_item(
    fact_id: str,
    field: str,
    state: str,
    values: tuple[str, ...] = (),
) -> ProfileItem:
    return ProfileItem(
        fact_id=fact_id,
        event_id=f"event-{fact_id}",
        subject="client",
        predicate="governed_context",
        object_json=json.dumps(
            _annotation(field, state, values),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        cognitive_type="client_statement",
        review_status="approved",
        validity_status="active",
        resolution_status="open",
        epistemic_status="asserted",
        fact_confidence=1.0,
        effective_from=NOW,
        effective_to=None,
        recorded_at=NOW,
        approved_at=NOW,
        source_session_id=None,
        source_turn_id=None,
        source_event_ids=(f"event-{fact_id}",),
    )


def _snapshot(*items: ProfileItem) -> ClientContextSnapshot:
    sections = (
        ProfileSection(name="active_facts", items=tuple(items)),
    )
    profile_payload = {
        "schema_version": "client_profile.v1",
        "source_snapshot_sha256": "1" * 64,
        "source_client_commit_version": 3,
        "effective_at": NOW,
        "known_at": NOW,
        "fixed_epoch": 4,
        "sections": sections,
        "current_event_ids": tuple(item.event_id for item in items),
    }
    hash_payload = {
        **profile_payload,
        "effective_at": NOW.isoformat().replace("+00:00", "Z"),
        "known_at": NOW.isoformat().replace("+00:00", "Z"),
        "sections": [section.model_dump(mode="json") for section in sections],
    }
    profile = ProfileSnapshot(
        **profile_payload,
        canonical_sha256=profile_sha256(hash_payload),
    )
    payload = {
        "schema_version": "client_context.v1",
        "client_id": "client_" + "aaaaaaaaaaaa",
        "profile_revision_id": "profile-revision-3",
        "profile_version": 3,
        "profile_sha256": profile.canonical_sha256,
        "fixed_epoch": 4,
        "profile": profile,
        "recent_session_summary_refs": (),
        "unresolved_items": (),
        "goals": (),
        "preferences": (),
        "constraints": (),
        "key_facts": (),
        "review_items": (),
        "created_at": NOW,
    }
    return ClientContextSnapshot(
        **payload,
        canonical_sha256=client_context_sha256(payload),
    )


def _plan(snapshot_ref: VersionRef) -> QueryPlan:
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=IDS.uuid7(),
            run_id=IDS.uuid7(),
            parent_sha256s=("2" * 64,),
            created_at=NOW,
        ),
        intent="theory_guidance",
        client_snapshot_ref=snapshot_ref,
        global_runtime_epoch=7,
        client_runtime_epoch=8,
        tombstone_epoch=(11 << 32) | 9,
        authorization_epoch=10,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="theory",
                category="theory_method_boundary",
                question="Which governed theory boundary applies?",
                routes=("lexical",),
                required_evidence_types=("theory_applicability",),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Resolve governed applicability from structured context.",
    )


def _temporary(
    plan: QueryPlan,
    *,
    value: object,
    event_kind: str = "CORRECT",
    target_fact_id: str | None = "fact-domain",
) -> tuple[TemporaryFactEvent, VersionRef, object]:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    content = StoredContentRef(
        object_id=IDS.object_id("session_fact"),
        content_sha256=__import__("hashlib").sha256(body.encode("utf-8")).hexdigest(),
        media_type="application/json",
        size_bytes=len(body.encode("utf-8")),
    )
    event = TemporaryFactEvent(
        event_id=IDS.object_id("session_event"),
        session_id=IDS.uuid7(),
        turn_id=plan.envelope.turn_id,
        event_kind=event_kind,
        cognitive_type="client_statement",
        content=content,
        target_fact_id=target_fact_id,
        target_fact_version=1 if target_fact_id is not None else None,
        recorded_at=NOW,
    )
    return (
        event,
        VersionRef(
            object_id=content.object_id,
            version=1,
            content_sha256=content.content_sha256,
        ),
        value,
    )


def test_profile_projection_preserves_values_and_known_empty_semantics() -> None:
    snapshot_ref = VersionRef(
        object_id=IDS.object_id("client_snapshot"),
        version=1,
        content_sha256="3" * 64,
    )
    plan = _plan(snapshot_ref)
    binding = GenerationClientBinding(
        client_snapshot_ref=snapshot_ref,
        client_runtime_epoch=8,
        client_tombstone_count=9,
        temporary_fact_refs=(),
    )

    projected = build_c1_applicability_input(
        plan,
        binding,
        _snapshot(
            _profile_item("fact-domain", "domain", "values", ("emotional_consultation",)),
            _profile_item("fact-contra", "contraindications", "known_empty"),
        ),
        (),
        {},
    )

    assert projected.context_values() == {
        "contraindications": (),
        "domain": ("emotional_consultation",),
    }
    assert projected.assertions[0].source_evidence_ids == (
        snapshot_ref.object_id,
    )


def test_current_turn_correction_overrides_profile_and_binds_exact_fact_ref() -> None:
    snapshot_ref = VersionRef(
        object_id=IDS.object_id("client_snapshot"),
        version=1,
        content_sha256="4" * 64,
    )
    plan = _plan(snapshot_ref)
    event, reference, value = _temporary(
        plan,
        value=_annotation("domain", "values", ("career_consultation",)),
    )
    binding = GenerationClientBinding(
        client_snapshot_ref=snapshot_ref,
        client_runtime_epoch=8,
        client_tombstone_count=9,
        temporary_fact_refs=(reference,),
    )

    projected = build_c1_applicability_input(
        plan,
        binding,
        _snapshot(
            _profile_item("fact-domain", "domain", "values", ("emotional_consultation",)),
        ),
        (event,),
        {reference.object_id: value},
    )

    assert projected.context_values() == {"domain": ("career_consultation",)}
    assert projected.assertions[0].source_evidence_ids == (reference.object_id,)


def test_invalidating_target_without_replacement_makes_profile_field_missing() -> None:
    snapshot_ref = VersionRef(
        object_id=IDS.object_id("client_snapshot"),
        version=1,
        content_sha256="5" * 64,
    )
    plan = _plan(snapshot_ref)
    event, reference, value = _temporary(
        plan,
        value={"note": "no replacement context"},
        event_kind="POSSIBLY_INVALID",
    )
    binding = GenerationClientBinding(
        client_snapshot_ref=snapshot_ref,
        client_runtime_epoch=8,
        client_tombstone_count=9,
        temporary_fact_refs=(reference,),
    )

    projected = build_c1_applicability_input(
        plan,
        binding,
        _snapshot(
            _profile_item("fact-domain", "domain", "values", ("emotional_consultation",)),
        ),
        (event,),
        {reference.object_id: value},
    )

    assert projected.context_values() == {}


@pytest.mark.parametrize(
    "event_kind",
    ("RESOLVE", "POSSIBLY_INVALID", "CONFLICT"),
)
def test_invalidating_event_cannot_reintroduce_c1_value_from_its_body(
    event_kind: str,
) -> None:
    snapshot_ref = VersionRef(
        object_id=IDS.object_id("client_snapshot"),
        version=1,
        content_sha256="8" * 64,
    )
    plan = _plan(snapshot_ref)
    event, reference, value = _temporary(
        plan,
        value=_annotation("domain", "values", ("career_consultation",)),
        event_kind=event_kind,
    )
    binding = GenerationClientBinding(
        client_snapshot_ref=snapshot_ref,
        client_runtime_epoch=8,
        client_tombstone_count=9,
        temporary_fact_refs=(reference,),
    )

    projected = build_c1_applicability_input(
        plan,
        binding,
        _snapshot(
            _profile_item(
                "fact-domain",
                "domain",
                "values",
                ("emotional_consultation",),
            ),
        ),
        (event,),
        {reference.object_id: value},
    )

    assert projected.context_values() == {}


def test_malformed_reserved_projection_fails_closed() -> None:
    snapshot_ref = VersionRef(
        object_id=IDS.object_id("client_snapshot"),
        version=1,
        content_sha256="6" * 64,
    )
    plan = _plan(snapshot_ref)
    event, reference, value = _temporary(
        plan,
        value={"c1_context": {"fields": "not-a-list"}},
        event_kind="ADD",
        target_fact_id=None,
    )
    binding = GenerationClientBinding(
        client_snapshot_ref=snapshot_ref,
        client_runtime_epoch=8,
        client_tombstone_count=9,
        temporary_fact_refs=(reference,),
    )

    with pytest.raises(
        C1ContextProjectionError,
        match="C1_CONTEXT_PROJECTION_INVALID",
    ):
        build_c1_applicability_input(
            plan,
            binding,
            _snapshot(),
            (event,),
            {reference.object_id: value},
        )
