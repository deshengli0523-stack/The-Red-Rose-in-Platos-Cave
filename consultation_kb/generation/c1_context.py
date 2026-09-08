"""Body-free, evidence-bound inputs for deterministic C1 applicability.

The scoped worker may project approved safe vocabulary keys from a client
snapshot and current-turn temporary facts into this contract.  It cannot send
prose, a client identifier, or an applicability decision.  The production C1
provider independently recomputes that decision from the governed theory and
scope policy.
"""

from __future__ import annotations

import hashlib
from typing import Self

from pydantic import field_validator, model_validator

from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.models.common import (
    NonNegativeInt,
    ObjectId,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.retrieval.contracts import canonical_json_bytes


def query_plan_sha256(plan: QueryPlan) -> str:
    """Hash the exact strict QueryPlan bytes used by retrieval."""

    value = QueryPlan.model_validate(plan, strict=True)
    return hashlib.sha256(
        canonical_json_bytes(value.model_dump(mode="json"))
    ).hexdigest()


def generation_binding_sha256(
    *,
    client_snapshot_ref: VersionRef,
    client_runtime_epoch: int,
    client_tombstone_count: int,
    temporary_fact_refs: tuple[VersionRef, ...],
) -> str:
    """Hash the public projection of one exact scoped-worker binding."""

    return hashlib.sha256(
        canonical_json_bytes(
            {
                "client_runtime_epoch": client_runtime_epoch,
                "client_snapshot_ref": client_snapshot_ref.model_dump(mode="json"),
                "client_tombstone_count": client_tombstone_count,
                "temporary_fact_refs": [
                    item.model_dump(mode="json") for item in temporary_fact_refs
                ],
            }
        )
    ).hexdigest()


class C1ContextAssertion(StrictModel):
    """One safe-vocabulary assertion with exact source evidence identities."""

    context_field: SafePolicyKey
    value_keys: tuple[SafePolicyKey, ...]
    source_evidence_ids: tuple[ObjectId, ...]

    @field_validator("value_keys", "source_evidence_ids")
    @classmethod
    def _canonical_nonempty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("C1_CONTEXT_ASSERTION_NOT_CANONICAL")
        return value


class C1ApplicabilityInput(StrictModel):
    """Exact, client-ID-free applicability slice bound to one QueryPlan.

    ``known_empty_fields`` means the trusted snapshot explicitly represents a
    field as present and empty.  A field absent from both this tuple and
    ``assertions`` remains missing and must produce ``insufficient_context``
    whenever the selected theory requires it.
    """

    client_snapshot_ref: VersionRef
    client_runtime_epoch: NonNegativeInt
    client_tombstone_count: NonNegativeInt
    temporary_fact_refs: tuple[VersionRef, ...]
    query_plan_sha256: Sha256Hex
    client_binding_sha256: Sha256Hex
    assertions: tuple[C1ContextAssertion, ...]
    known_empty_fields: tuple[SafePolicyKey, ...]

    @field_validator("temporary_fact_refs")
    @classmethod
    def _canonical_refs(
        cls, value: tuple[VersionRef, ...]
    ) -> tuple[VersionRef, ...]:
        keys = tuple(
            (item.object_id, item.version, item.content_sha256) for item in value
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("C1_TEMPORARY_FACT_REFS_NOT_CANONICAL")
        return value

    @field_validator("known_empty_fields")
    @classmethod
    def _canonical_empty_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("C1_KNOWN_EMPTY_FIELDS_NOT_CANONICAL")
        return value

    @model_validator(mode="after")
    def _exact_binding(self) -> Self:
        fields = tuple(item.context_field for item in self.assertions)
        if fields != tuple(sorted(set(fields))):
            raise ValueError("C1_CONTEXT_ASSERTIONS_NOT_CANONICAL")
        if set(fields) & set(self.known_empty_fields):
            raise ValueError("C1_CONTEXT_FIELD_BOTH_ASSERTED_AND_EMPTY")
        if self.client_tombstone_count >= 2**32:
            raise ValueError("C1_CLIENT_TOMBSTONE_COUNT_INVALID")
        allowed_sources = {
            self.client_snapshot_ref.object_id,
            *(item.object_id for item in self.temporary_fact_refs),
        }
        if any(
            not set(assertion.source_evidence_ids) <= allowed_sources
            for assertion in self.assertions
        ):
            raise ValueError("C1_CONTEXT_SOURCE_EVIDENCE_UNBOUND")
        expected_binding = generation_binding_sha256(
            client_snapshot_ref=self.client_snapshot_ref,
            client_runtime_epoch=self.client_runtime_epoch,
            client_tombstone_count=self.client_tombstone_count,
            temporary_fact_refs=self.temporary_fact_refs,
        )
        if self.client_binding_sha256 != expected_binding:
            raise ValueError("C1_CLIENT_BINDING_HASH_MISMATCH")
        return self

    @property
    def canonical_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    @classmethod
    def bind(
        cls,
        plan: QueryPlan,
        *,
        client_snapshot_ref: VersionRef,
        client_runtime_epoch: int,
        client_tombstone_count: int,
        temporary_fact_refs: tuple[VersionRef, ...],
        assertions: tuple[C1ContextAssertion, ...] = (),
        known_empty_fields: tuple[SafePolicyKey, ...] = (),
    ) -> Self:
        """Create the exact slice; no default facts are inferred from prose."""

        exact_plan = QueryPlan.model_validate(plan, strict=True)
        exact_snapshot = VersionRef.model_validate(client_snapshot_ref, strict=True)
        exact_temporary = tuple(
            VersionRef.model_validate(item, strict=True) for item in temporary_fact_refs
        )
        return cls(
            client_snapshot_ref=exact_snapshot,
            client_runtime_epoch=client_runtime_epoch,
            client_tombstone_count=client_tombstone_count,
            temporary_fact_refs=exact_temporary,
            query_plan_sha256=query_plan_sha256(exact_plan),
            client_binding_sha256=generation_binding_sha256(
                client_snapshot_ref=exact_snapshot,
                client_runtime_epoch=client_runtime_epoch,
                client_tombstone_count=client_tombstone_count,
                temporary_fact_refs=exact_temporary,
            ),
            assertions=assertions,
            known_empty_fields=known_empty_fields,
        )

    def assert_plan_closure(self, plan: QueryPlan) -> None:
        value = QueryPlan.model_validate(plan, strict=True)
        if (
            self.query_plan_sha256 != query_plan_sha256(value)
            or self.client_snapshot_ref != value.client_snapshot_ref
            or self.client_runtime_epoch != value.client_runtime_epoch
            or self.client_tombstone_count != (value.tombstone_epoch & (2**32 - 1))
        ):
            raise ValueError("C1_APPLICABILITY_INPUT_PLAN_MISMATCH")

    def context_values(self) -> dict[str, object]:
        """Return only the safe keys consumed by ``ApplicabilityGate``."""

        values: dict[str, object] = {
            item.context_field: item.value_keys for item in self.assertions
        }
        values.update({field: () for field in self.known_empty_fields})
        return values


__all__ = [
    "C1ApplicabilityInput",
    "C1ContextAssertion",
    "generation_binding_sha256",
    "query_plan_sha256",
]
