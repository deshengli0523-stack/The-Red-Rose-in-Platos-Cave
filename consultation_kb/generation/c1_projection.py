"""Trusted projection of client-local structured facts into C1 vocabulary keys.

This module never classifies prose.  It only accepts an explicit, strictly
typed ``c1_context`` annotation already stored inside the frozen client
snapshot or a current-turn temporary fact.  The scoped worker supplies the
verified objects and their exact content references; the public result carries
only safe policy keys and bound evidence identifiers.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Self

from pydantic import ValidationError, field_validator, model_validator

from consultation_kb.generation.c1_context import (
    C1ApplicabilityInput,
    C1ContextAssertion,
)
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.models.common import SafePolicyKey, StrictModel
from consultation_kb.models.profile import ProfileItem
from consultation_kb.models.session import TemporaryFactEvent
from consultation_kb.security.worker_protocol import GenerationClientBinding
from consultation_kb.session.context import ClientContextSnapshot


class C1ContextProjectionError(RuntimeError):
    """One fixed-code client-local projection failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class C1ProjectedField(StrictModel):
    """One explicit safe-vocabulary field state embedded in client evidence."""

    context_field: SafePolicyKey
    state: Literal["values", "known_empty", "unknown"]
    value_keys: tuple[SafePolicyKey, ...] = ()

    @field_validator("value_keys")
    @classmethod
    def _canonical_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("C1_PROJECTED_VALUES_NOT_CANONICAL")
        return value

    @model_validator(mode="after")
    def _state_shape(self) -> Self:
        if (self.state == "values") != bool(self.value_keys):
            raise ValueError("C1_PROJECTED_FIELD_STATE_INVALID")
        return self


class C1ContextProjection(StrictModel):
    """Reserved annotation payload; fields are unique and canonical."""

    schema_version: Literal["c1_context_projection.v1"] = (
        "c1_context_projection.v1"
    )
    fields: tuple[C1ProjectedField, ...]

    @field_validator("fields")
    @classmethod
    def _canonical_fields(
        cls, value: tuple[C1ProjectedField, ...]
    ) -> tuple[C1ProjectedField, ...]:
        keys = tuple(item.context_field for item in value)
        if not keys or keys != tuple(sorted(set(keys))):
            raise ValueError("C1_PROJECTED_FIELDS_NOT_CANONICAL")
        return value


@dataclass(frozen=True, slots=True)
class _FieldState:
    state: Literal["values", "known_empty", "unknown"]
    value_keys: tuple[str, ...]
    source_evidence_ids: tuple[str, ...]


def _projection_from_value(value: object) -> C1ContextProjection | None:
    if type(value) is not dict or "c1_context" not in value:
        return None
    try:
        return C1ContextProjection.model_validate_json(
            json.dumps(
                value["c1_context"],
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError):
        raise C1ContextProjectionError(
            "C1_CONTEXT_PROJECTION_INVALID"
        ) from None


def _profile_projection(item: ProfileItem) -> C1ContextProjection | None:
    try:
        value = json.loads(item.object_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return _projection_from_value(value)


def _eligible_profile_item(item: ProfileItem) -> bool:
    return (
        item.review_status == "approved"
        and item.validity_status == "active"
        and item.resolution_status != "resolved"
        and item.epistemic_status != "disputed"
        and item.cognitive_type
        in {"external_fact", "client_statement", "consultant_observation"}
    )


def _merge_profile_states(
    items: tuple[ProfileItem, ...],
    *,
    snapshot_source_id: str,
) -> tuple[dict[str, _FieldState], dict[str, tuple[str, ...]]]:
    projected_by_field: dict[str, list[C1ProjectedField]] = {}
    fields_by_fact: dict[str, set[str]] = {}
    for item in items:
        projection = _profile_projection(item)
        if projection is None:
            continue
        fields_by_fact.setdefault(item.fact_id, set()).update(
            field.context_field for field in projection.fields
        )
        if not _eligible_profile_item(item):
            continue
        for field in projection.fields:
            projected_by_field.setdefault(field.context_field, []).append(field)

    states: dict[str, _FieldState] = {}
    for context_field, projected in projected_by_field.items():
        state_kinds = {item.state for item in projected}
        if "unknown" in state_kinds:
            states[context_field] = _FieldState("unknown", (), ())
            continue
        if state_kinds == {"known_empty"}:
            states[context_field] = _FieldState(
                "known_empty", (), (snapshot_source_id,)
            )
            continue
        if state_kinds != {"values"}:
            raise C1ContextProjectionError("C1_CONTEXT_PROJECTION_CONFLICT")
        values = tuple(
            sorted({value for item in projected for value in item.value_keys})
        )
        states[context_field] = _FieldState(
            "values", values, (snapshot_source_id,)
        )
    return states, {
        fact_id: tuple(sorted(fields)) for fact_id, fields in fields_by_fact.items()
    }


def _temporary_projection(
    event: TemporaryFactEvent,
    value: object,
) -> C1ContextProjection | None:
    projection = _projection_from_value(value)
    # Resolution, uncertainty and conflict events invalidate the targeted
    # profile field; they are not positive assertions of a replacement value.
    # A reserved annotation embedded in one of these event bodies therefore
    # cannot immediately overwrite the ``unknown`` tombstone established by
    # ``target_fact_id`` below.
    if event.event_kind in {"RESOLVE", "POSSIBLY_INVALID", "CONFLICT"}:
        return None
    if projection is not None and event.cognitive_type not in {
        "external_fact",
        "client_statement",
        "consultant_observation",
    }:
        raise C1ContextProjectionError("C1_CONTEXT_PROJECTION_SOURCE_INVALID")
    return projection


def build_c1_applicability_input(
    plan: QueryPlan,
    binding: GenerationClientBinding,
    snapshot: ClientContextSnapshot,
    temporary_facts: tuple[TemporaryFactEvent, ...],
    temporary_values: Mapping[str, object],
) -> C1ApplicabilityInput:
    """Project an exact frozen snapshot/current-turn ledger into safe keys."""

    exact_plan = QueryPlan.model_validate(plan, strict=True)
    exact_binding = GenerationClientBinding.model_validate(binding, strict=True)
    exact_snapshot = ClientContextSnapshot.model_validate(snapshot, strict=True)
    if (
        exact_plan.client_snapshot_ref != exact_binding.client_snapshot_ref
        or exact_plan.client_runtime_epoch != exact_binding.client_runtime_epoch
        or (exact_plan.tombstone_epoch & (2**32 - 1))
        != exact_binding.client_tombstone_count
    ):
        raise C1ContextProjectionError("C1_CONTEXT_PROJECTION_BINDING_MISMATCH")

    profile_items = (
        ()
        if exact_snapshot.profile is None
        else tuple(
            item
            for section in exact_snapshot.profile.sections
            for item in section.items
        )
    )
    states, fields_by_fact = _merge_profile_states(
        profile_items,
        snapshot_source_id=exact_binding.client_snapshot_ref.object_id,
    )
    refs = {
        item.object_id: item for item in exact_binding.temporary_fact_refs
    }
    events = tuple(
        sorted(
            temporary_facts,
            key=lambda item: (item.recorded_at, item.event_id),
        )
    )
    event_ids = tuple(item.content.object_id for item in events)
    if len(event_ids) != len(set(event_ids)) or set(event_ids) != set(refs):
        raise C1ContextProjectionError("C1_CONTEXT_PROJECTION_FACT_SET_MISMATCH")
    if set(temporary_values) != set(refs):
        raise C1ContextProjectionError("C1_CONTEXT_PROJECTION_VALUE_SET_MISMATCH")

    for event in events:
        reference = refs[event.content.object_id]
        if (
            event.turn_id != exact_plan.envelope.turn_id
            or event.content.content_sha256 != reference.content_sha256
            or event.content.object_id != reference.object_id
        ):
            raise C1ContextProjectionError(
                "C1_CONTEXT_PROJECTION_FACT_BINDING_MISMATCH"
            )
        if event.target_fact_id is not None:
            for context_field in fields_by_fact.get(event.target_fact_id, ()):
                states[context_field] = _FieldState("unknown", (), ())
        projection = _temporary_projection(
            event,
            temporary_values[event.content.object_id],
        )
        if projection is None:
            continue
        for field in projection.fields:
            states[field.context_field] = _FieldState(
                field.state,
                field.value_keys,
                ()
                if field.state == "unknown"
                else (event.content.object_id,),
            )

    assertions = tuple(
        C1ContextAssertion(
            context_field=context_field,
            value_keys=state.value_keys,
            source_evidence_ids=state.source_evidence_ids,
        )
        for context_field, state in sorted(states.items())
        if state.state == "values"
    )
    known_empty = tuple(
        context_field
        for context_field, state in sorted(states.items())
        if state.state == "known_empty"
    )
    return C1ApplicabilityInput.bind(
        exact_plan,
        client_snapshot_ref=exact_binding.client_snapshot_ref,
        client_runtime_epoch=exact_binding.client_runtime_epoch,
        client_tombstone_count=exact_binding.client_tombstone_count,
        temporary_fact_refs=exact_binding.temporary_fact_refs,
        assertions=assertions,
        known_empty_fields=known_empty,
    )


__all__ = [
    "C1ContextProjection",
    "C1ContextProjectionError",
    "C1ProjectedField",
    "build_c1_applicability_input",
]
