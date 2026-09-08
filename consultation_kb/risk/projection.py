"""One-way allowlist projection from internal observations to natural goals."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, field_validator

from consultation_kb.models.common import SafePolicyKey, StrictModel, UtcDateTime, VersionRef
from consultation_kb.models.risk import InternalRiskObservation

from .repository import InternalRiskObservationRecord
from .resources import RegionalResourceCatalog


ClientGoal: TypeAlias = Literal[
    "maintain_conversation",
    "ask_clarifying_question",
    "check_immediate_safety",
    "invite_real_world_support",
    "offer_reviewed_resource",
]

_GOAL_ORDER: tuple[ClientGoal, ...] = (
    "maintain_conversation",
    "ask_clarifying_question",
    "check_immediate_safety",
    "invite_real_world_support",
    "offer_reviewed_resource",
)


class ClientResponseGoals(StrictModel):
    """Only stable goal keys and independently approved public text refs."""

    schema_version: Literal["1.0"] = "1.0"
    goals: Annotated[
        tuple[ClientGoal, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    reviewed_resource_text_refs: Annotated[
        tuple[VersionRef, ...], Field(json_schema_extra={"uniqueItems": True})
    ] = ()

    @field_validator("goals")
    @classmethod
    def _canonical_goals(cls, value: tuple[ClientGoal, ...]) -> tuple[ClientGoal, ...]:
        if len(value) != len(set(value)):
            raise ValueError("client response goals must be unique")
        present = set(value)
        return tuple(goal for goal in _GOAL_ORDER if goal in present)

    @field_validator("reviewed_resource_text_refs")
    @classmethod
    def _canonical_refs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        if len(value) != len(set(value)):
            raise ValueError("reviewed resource refs must be unique")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.object_id,
                    item.version,
                    item.content_sha256,
                ),
            )
        )


class RiskResponseProjector:
    """Erase categories, levels, rule text, and trigger spans by construction."""

    @staticmethod
    def to_client_goals(
        observations: tuple[
            InternalRiskObservationRecord | InternalRiskObservation, ...
        ],
        *,
        resource_catalog: RegionalResourceCatalog | None = None,
        region: SafePolicyKey | None = None,
        as_of: UtcDateTime | None = None,
    ) -> ClientResponseGoals:
        resource_arguments = (resource_catalog, region, as_of)
        if any(value is not None for value in resource_arguments) and any(
            value is None for value in resource_arguments
        ):
            raise ValueError(
                "resource projection requires catalog, region, and as_of together"
            )
        if resource_catalog is not None and type(resource_catalog) is not RegionalResourceCatalog:
            raise TypeError("RESOURCE_CATALOG_REQUIRED")

        cores: list[InternalRiskObservation] = []
        for value in observations:
            if isinstance(value, InternalRiskObservationRecord):
                if not value.visible_to_counselor:
                    continue
                cores.append(value.observation)
            else:
                cores.append(InternalRiskObservation.model_validate(value))

        goals: set[ClientGoal] = {"maintain_conversation"}
        if any(observation.level == "general" for observation in cores):
            goals.add("ask_clarifying_question")
        has_high = any(observation.level == "high" for observation in cores)
        if has_high:
            goals.update(("check_immediate_safety", "invite_real_world_support"))

        resource_refs: tuple[VersionRef, ...] = ()
        if has_high and resource_catalog is not None:
            assert region is not None and as_of is not None
            exact_resources = resource_catalog.approved_for(region, as_of=as_of)
            if exact_resources:
                goals.add("offer_reviewed_resource")
                resource_refs = tuple(
                    dict.fromkeys(value.public_text_ref for value in exact_resources)
                )

        return ClientResponseGoals(
            goals=tuple(goal for goal in _GOAL_ORDER if goal in goals),
            reviewed_resource_text_refs=resource_refs,
        )


__all__ = ["ClientGoal", "ClientResponseGoals", "RiskResponseProjector"]
