"""Evidence, provenance, filtering and pack contracts."""

from __future__ import annotations

import re
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    Field,
    GetJsonSchemaHandler,
    TypeAdapter,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from .common import (
    ClientId,
    FiniteFloat,
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    SafeLocatorText,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)


SourceGrade: TypeAlias = Literal[
    "T1", "T2", "T3", "T4",
    "C1", "C2", "C3", "C4", "C5", "C6",
    "K1", "K2", "K3", "K4",
    "L1", "L2", "L3", "L4",
]
EmpiricalSupport: TypeAlias = Literal[
    "unassessed",
    "case_supported",
    "observation_supported",
    "empirically_supported",
    "guideline_consistent",
    "conflicting",
]
ProvenanceScope: TypeAlias = Literal[
    "global_source", "client_private", "case_derived", "mixed"
]
EvidenceChannel: TypeAlias = Literal[
    "profile", "client_history", "wiki", "lexical", "vector", "global_graph", "case"
]
_CHANNELS_BY_PROVENANCE_SCOPE: dict[str, frozenset[str]] = {
    "global_source": frozenset({"wiki", "lexical", "vector", "global_graph"}),
    "client_private": frozenset({"profile", "client_history"}),
    "case_derived": frozenset(
        {"case", "wiki", "lexical", "vector", "global_graph"}
    ),
    "mixed": frozenset({"case", "wiki", "lexical", "vector", "global_graph"}),
}
ClientExclusionStatus: TypeAlias = Literal[
    "not_applicable",
    "current_subject_private",
    "no_subject_contribution",
    "leave_one_subject_out_applied",
]


def _version_ref_key(value: VersionRef) -> tuple[str, int, str]:
    return value.object_id, value.version, value.content_sha256


def _unique_sorted_strings(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


def _unique_sorted_refs(
    values: tuple[VersionRef, ...],
    label: str,
) -> tuple[VersionRef, ...]:
    keys = [_version_ref_key(value) for value in values]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(sorted(values, key=_version_ref_key))


class Provenance(StrictModel):
    source_ids: frozenset[ObjectId] = frozenset()
    passage_ids: frozenset[ObjectId] = frozenset()
    case_ids: frozenset[ObjectId] = frozenset()
    client_ids: frozenset[ClientId] = frozenset()
    provenance_scope: ProvenanceScope
    private_owner_client_id: ClientId | None = None
    case_contributor_client_ids: frozenset[ClientId] = frozenset()
    derivation_rule_ref: VersionRef

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        empty = {"maxItems": 0}
        nonempty = {"minItems": 1}
        null = {"type": "null"}
        nonnull = {"not": {"type": "null"}}
        rendered["oneOf"] = [
            {
                "properties": {
                    "provenance_scope": {"const": "global_source"},
                    "source_ids": nonempty,
                    "case_ids": empty,
                    "client_ids": empty,
                    "case_contributor_client_ids": empty,
                    "private_owner_client_id": null,
                },
                "required": ["provenance_scope", "source_ids"],
            },
            {
                "properties": {
                    "provenance_scope": {"const": "client_private"},
                    "source_ids": empty,
                    "case_ids": empty,
                    "client_ids": nonempty,
                    "case_contributor_client_ids": empty,
                    "private_owner_client_id": nonnull,
                },
                "required": [
                    "provenance_scope",
                    "client_ids",
                    "private_owner_client_id",
                ],
            },
            {
                "properties": {
                    "provenance_scope": {"const": "case_derived"},
                    "source_ids": empty,
                    "case_ids": nonempty,
                    "client_ids": nonempty,
                    "case_contributor_client_ids": nonempty,
                    "private_owner_client_id": null,
                },
                "required": [
                    "provenance_scope",
                    "case_ids",
                    "client_ids",
                    "case_contributor_client_ids",
                ],
            },
            {
                "properties": {
                    "provenance_scope": {"const": "mixed"},
                    "source_ids": nonempty,
                    "case_ids": nonempty,
                    "client_ids": nonempty,
                    "case_contributor_client_ids": nonempty,
                    "private_owner_client_id": null,
                },
                "required": [
                    "provenance_scope",
                    "source_ids",
                    "case_ids",
                    "client_ids",
                    "case_contributor_client_ids",
                ],
            },
        ]
        rendered["x-runtime-only-invariants"] = [
            "client_private_client_ids_equal_owner_singleton",
            "case_or_mixed_client_ids_equal_case_contributors",
        ]
        return rendered

    @model_validator(mode="after")
    def _validate_scope_matrix(self) -> "Provenance":
        sources = bool(self.source_ids)
        cases = bool(self.case_ids)
        clients = bool(self.client_ids)
        contributors = bool(self.case_contributor_client_ids)
        owner = self.private_owner_client_id

        valid = False
        if self.provenance_scope == "global_source":
            valid = sources and not cases and not clients and not contributors and owner is None
        elif self.provenance_scope == "client_private":
            valid = (
                not sources
                and not cases
                and owner is not None
                and self.client_ids == frozenset({owner})
                and not contributors
            )
        elif self.provenance_scope == "case_derived":
            valid = (
                not sources
                and cases
                and contributors
                and self.client_ids == self.case_contributor_client_ids
                and owner is None
            )
        elif self.provenance_scope == "mixed":
            valid = (
                sources
                and cases
                and contributors
                and self.client_ids == self.case_contributor_client_ids
                and owner is None
            )
        if not valid:
            raise ValueError("provenance fields do not match the closed-world scope matrix")
        return self

    @field_serializer(
        "source_ids",
        "passage_ids",
        "case_ids",
        "client_ids",
        "case_contributor_client_ids",
    )
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class RetrievalScope(StrictModel):
    current_client_id: ClientId
    allowed_uses: frozenset[NonEmptyStr]
    maximum_sensitivity: NonNegativeInt
    effective_at: UtcDateTime
    known_at: UtcDateTime

    @field_serializer("allowed_uses")
    def _serialize_allowed_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class AuthoritativeFilterSnapshot(StrictModel):
    run_id: Uuid7String
    global_runtime_epoch: NonNegativeInt
    client_runtime_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt
    allowed_ref_ids: frozenset[ObjectId]
    policy_ref: VersionRef
    created_at: UtcDateTime

    @field_serializer("allowed_ref_ids")
    def _serialize_allowed_refs(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class AuthoritySnapshotBinding(StrictModel):
    snapshot_ref: VersionRef
    run_id: Uuid7String
    global_runtime_epoch: NonNegativeInt
    client_runtime_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt
    policy_ref: VersionRef
    created_at: UtcDateTime


class EvidenceProvenanceView(StrictModel):
    provenance_ref: VersionRef
    provenance_scope: ProvenanceScope
    derivation_rule_ref: VersionRef
    source_count: NonNegativeInt
    passage_count: NonNegativeInt
    case_count: NonNegativeInt
    case_contributor_count: NonNegativeInt
    independent_source_count: NonNegativeInt
    client_exclusion_status: ClientExclusionStatus

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        case_exclusion = {
            "enum": [
                "no_subject_contribution",
                "leave_one_subject_out_applied",
            ]
        }
        rendered["oneOf"] = [
            {
                "properties": {
                    "provenance_scope": {"const": "global_source"},
                    "source_count": {"minimum": 1},
                    "case_count": {"const": 0},
                    "case_contributor_count": {"const": 0},
                    "independent_source_count": {"minimum": 1},
                    "client_exclusion_status": {"const": "not_applicable"},
                }
            },
            {
                "properties": {
                    "provenance_scope": {"const": "client_private"},
                    "source_count": {"const": 0},
                    "case_count": {"const": 0},
                    "case_contributor_count": {"const": 0},
                    "independent_source_count": {"const": 0},
                    "client_exclusion_status": {"const": "current_subject_private"},
                }
            },
            {
                "properties": {
                    "provenance_scope": {"const": "case_derived"},
                    "source_count": {"const": 0},
                    "case_count": {"minimum": 1},
                    "case_contributor_count": {"minimum": 1},
                    "independent_source_count": {"const": 0},
                    "client_exclusion_status": case_exclusion,
                }
            },
            {
                "properties": {
                    "provenance_scope": {"const": "mixed"},
                    "source_count": {"minimum": 1},
                    "case_count": {"minimum": 1},
                    "case_contributor_count": {"minimum": 1},
                    "independent_source_count": {"minimum": 1},
                    "client_exclusion_status": case_exclusion,
                }
            },
        ]
        rendered["x-runtime-only-invariants"] = [
            "independent_source_count_lte_source_count"
        ]
        return rendered

    @model_validator(mode="after")
    def _validate_safe_matrix(self) -> "EvidenceProvenanceView":
        if self.independent_source_count > self.source_count:
            raise ValueError("independent source count must not exceed source count")

        status = self.client_exclusion_status
        valid = False
        if self.provenance_scope == "global_source":
            valid = (
                self.source_count > 0
                and self.independent_source_count > 0
                and self.case_count == 0
                and self.case_contributor_count == 0
                and status == "not_applicable"
            )
        elif self.provenance_scope == "client_private":
            valid = (
                self.source_count == 0
                and self.case_count == 0
                and self.case_contributor_count == 0
                and self.independent_source_count == 0
                and status == "current_subject_private"
            )
        elif self.provenance_scope == "case_derived":
            valid = (
                self.source_count == 0
                and self.independent_source_count == 0
                and self.case_count > 0
                and self.case_contributor_count > 0
                and status in {
                    "no_subject_contribution",
                    "leave_one_subject_out_applied",
                }
            )
        elif self.provenance_scope == "mixed":
            valid = (
                self.source_count > 0
                and self.independent_source_count > 0
                and self.case_count > 0
                and self.case_contributor_count > 0
                and status in {
                    "no_subject_contribution",
                    "leave_one_subject_out_applied",
                }
            )
        if not valid:
            raise ValueError("safe provenance fields do not match the closed-world matrix")
        return self


LocatorKind: TypeAlias = Literal[
    "source_page_span",
    "source_paragraph_span",
    "source_line_span",
    "source_table_span",
    "source_sheet_range",
    "client_fact",
    "session_turn",
    "wiki_section",
    "case_turn",
    "graph_path",
]

_POSITIVE = r"([1-9][0-9]*)"
_PAGE_RE = re.compile(rf"pages:{_POSITIVE}:{_POSITIVE}-{_POSITIVE}:{_POSITIVE}\Z")
_PARAGRAPH_RE = re.compile(rf"paragraphs:{_POSITIVE}-{_POSITIVE}\Z")
_LINE_RE = re.compile(rf"lines:{_POSITIVE}-{_POSITIVE}\Z")
_TABLE_RE = re.compile(
    rf"table:{_POSITIVE};rows:{_POSITIVE}-{_POSITIVE};columns:{_POSITIVE}-{_POSITIVE}\Z"
)
_CELL = r"([A-Z]+)([1-9][0-9]*)"
_SHEET_RE = re.compile(rf"sheet:{_POSITIVE};range:{_CELL}-{_CELL}\Z")
_FACT_RE = re.compile(r"fact:(.+)\Z")
_TURN_RE = re.compile(r"turn:(.+)\Z")
_SECTION_RE = re.compile(r"section:([a-z0-9]+(?:-[a-z0-9]+)*)\Z")
_CASE_RE = re.compile(rf"case:(.+);turn:{_POSITIVE}\Z")
_PATH_RE = re.compile(r"path:([0-9a-f]{64})\Z")
_OBJECT_ID_ADAPTER = TypeAdapter(ObjectId)
_UUID7_ADAPTER = TypeAdapter(Uuid7String)
_SHA_ADAPTER = TypeAdapter(Sha256Hex)
_UUID7_JSON_PATTERN = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_OBJECT_ID_JSON_PATTERN = (
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_" + _UUID7_JSON_PATTERN
)
_CLIENT_ID_JSON_PATTERN = r"client_[a-z0-9]{12}"
_JSON_LINE_SEPARATOR_PATTERN = r"[\r\n\u2028\u2029]"
_CASE_TURN_OVERLONG_KIND_JSON_PATTERN = (
    rf"^case:[a-z0-9_]{{65,}}_{_UUID7_JSON_PATTERN};turn:[1-9][0-9]*$"
)
_LOCATOR_JSON_RULES: dict[str, dict[str, object]] = {
    "source_page_span": {
        "pattern": (
            r"^pages:[1-9][0-9]*:[1-9][0-9]*-"
            r"[1-9][0-9]*:[1-9][0-9]*$"
        ),
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "source_paragraph_span": {
        "pattern": r"^paragraphs:[1-9][0-9]*-[1-9][0-9]*$",
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "source_line_span": {
        "pattern": r"^lines:[1-9][0-9]*-[1-9][0-9]*$",
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "source_table_span": {
        "pattern": (
            r"^table:[1-9][0-9]*;rows:[1-9][0-9]*-[1-9][0-9]*;"
            r"columns:[1-9][0-9]*-[1-9][0-9]*$"
        ),
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "source_sheet_range": {
        "pattern": (
            r"^sheet:[1-9][0-9]*;range:[A-Z]+[1-9][0-9]*-"
            r"[A-Z]+[1-9][0-9]*$"
        ),
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "client_fact": {
        "pattern": rf"^fact:{_OBJECT_ID_JSON_PATTERN}$",
        "maxLength": 106,
        "not": {
            "anyOf": [
                {"pattern": _CLIENT_ID_JSON_PATTERN},
                {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
            ]
        },
    },
    "session_turn": {
        "pattern": rf"^turn:{_UUID7_JSON_PATTERN}$",
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "wiki_section": {
        "pattern": r"^section:[a-z0-9]+(?:-[a-z0-9]+)*$",
        "maxLength": 136,
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
    "case_turn": {
        "pattern": rf"^case:{_OBJECT_ID_JSON_PATTERN};turn:[1-9][0-9]*$",
        "not": {
            "anyOf": [
                {"pattern": _CLIENT_ID_JSON_PATTERN},
                {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                {"pattern": _CASE_TURN_OVERLONG_KIND_JSON_PATTERN},
            ]
        },
    },
    "graph_path": {
        "pattern": r"^path:[0-9a-f]{64}$",
        "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
    },
}


def _column_number(value: str) -> int:
    result = 0
    for char in value:
        result = result * 26 + ord(char) - ord("A") + 1
    return result


def _validate_locator(kind: str, value: str) -> None:
    match: re.Match[str] | None
    if kind == "source_page_span":
        match = _PAGE_RE.fullmatch(value)
        if match is None:
            raise ValueError("page locator must use canonical page/block endpoints")
        start = int(match.group(1)), int(match.group(2))
        end = int(match.group(3)), int(match.group(4))
        if start > end:
            raise ValueError("page locator endpoints must be ordered")
    elif kind == "source_paragraph_span":
        match = _PARAGRAPH_RE.fullmatch(value)
        if match is None or int(match.group(1)) > int(match.group(2)):
            raise ValueError("paragraph locator must be a canonical ordered span")
    elif kind == "source_line_span":
        match = _LINE_RE.fullmatch(value)
        if match is None or int(match.group(1)) > int(match.group(2)):
            raise ValueError("line locator must be a canonical ordered span")
    elif kind == "source_table_span":
        match = _TABLE_RE.fullmatch(value)
        if match is None:
            raise ValueError("table locator must use canonical table/row/column grammar")
        if int(match.group(2)) > int(match.group(3)) or int(match.group(4)) > int(match.group(5)):
            raise ValueError("table locator rectangle must be ordered")
    elif kind == "source_sheet_range":
        match = _SHEET_RE.fullmatch(value)
        if match is None:
            raise ValueError("sheet locator must use canonical uppercase A1 grammar")
        start_column, start_row = _column_number(match.group(2)), int(match.group(3))
        end_column, end_row = _column_number(match.group(4)), int(match.group(5))
        if start_column > end_column or start_row > end_row:
            raise ValueError("sheet locator rectangle must be ordered")
    elif kind == "client_fact":
        match = _FACT_RE.fullmatch(value)
        if match is None:
            raise ValueError("fact locator must contain an object identifier")
        _OBJECT_ID_ADAPTER.validate_python(match.group(1))
    elif kind == "session_turn":
        match = _TURN_RE.fullmatch(value)
        if match is None:
            raise ValueError("turn locator must contain a UUIDv7")
        _UUID7_ADAPTER.validate_python(match.group(1))
    elif kind == "wiki_section":
        match = _SECTION_RE.fullmatch(value)
        if match is None or len(match.group(1)) > 128:
            raise ValueError("section locator must contain a canonical bounded slug")
    elif kind == "case_turn":
        match = _CASE_RE.fullmatch(value)
        if match is None:
            raise ValueError("case locator must contain an object identifier and turn")
        _OBJECT_ID_ADAPTER.validate_python(match.group(1))
    elif kind == "graph_path":
        match = _PATH_RE.fullmatch(value)
        if match is None:
            raise ValueError("graph locator must contain a lowercase SHA-256")
        _SHA_ADAPTER.validate_python(match.group(1))
    else:
        raise ValueError("unsupported locator kind")


class EvidenceLocator(StrictModel):
    locator_kind: LocatorKind
    anchor_refs: Annotated[
        tuple[VersionRef, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    display_locator: SafeLocatorText
    locator_policy_ref: VersionRef

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        rendered["allOf"] = [
            {
                "if": {
                    "properties": {"locator_kind": {"const": kind}},
                    "required": ["locator_kind"],
                },
                "then": {"properties": {"display_locator": display_schema}},
            }
            for kind, display_schema in _LOCATOR_JSON_RULES.items()
        ]
        return rendered

    @field_validator("anchor_refs")
    @classmethod
    def _validate_anchors(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        if not value:
            raise ValueError("locator requires at least one anchor")
        return _unique_sorted_refs(value, "anchor refs")

    @model_validator(mode="after")
    def _validate_display_locator(self) -> "EvidenceLocator":
        _validate_locator(self.locator_kind, self.display_locator)
        return self


class EvidenceFreshnessSnapshot(StrictModel):
    status: Literal["current", "historical", "stale", "not_time_sensitive"]
    evaluated_at: UtcDateTime
    source_observed_at: UtcDateTime | None
    last_reviewed_at: UtcDateTime | None
    review_due_at: UtcDateTime | None
    policy_ref: VersionRef

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        rendered["allOf"] = [
            {
                "if": {
                    "properties": {"status": {"const": "stale"}},
                    "required": ["status"],
                },
                "then": {
                    "properties": {"review_due_at": {"not": {"type": "null"}}}
                },
            }
        ]
        return rendered

    @model_validator(mode="after")
    def _validate_times(self) -> "EvidenceFreshnessSnapshot":
        if self.source_observed_at is not None and self.source_observed_at > self.evaluated_at:
            raise ValueError("source observation must not be later than evaluation")
        if self.last_reviewed_at is not None and self.last_reviewed_at > self.evaluated_at:
            raise ValueError("last review must not be later than evaluation")
        if self.status == "stale":
            if self.review_due_at is None or self.review_due_at > self.evaluated_at:
                raise ValueError("stale evidence requires a due time at or before evaluation")
        if self.status == "current" and (
            self.review_due_at is not None and self.review_due_at <= self.evaluated_at
        ):
            raise ValueError("current evidence requires no due time or a future due time")
        return self


class EvidenceCandidate(StrictModel):
    evidence_id: ObjectId
    text_ref: VersionRef
    location: EvidenceLocator
    freshness: EvidenceFreshnessSnapshot
    channel: EvidenceChannel
    review_status: Literal["approved"]
    source_grade: SourceGrade
    framework_priority: Literal["highest", "normal", "not_applicable"]
    empirical_support: EmpiricalSupport
    provenance: EvidenceProvenanceView
    supports_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    contradicts_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    score: FiniteFloat

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        rendered["oneOf"] = [
            {
                "properties": {
                    "channel": {"enum": sorted(channels)},
                    "provenance": {
                        "properties": {"provenance_scope": {"const": scope}},
                        "required": ["provenance_scope"],
                    },
                },
                "required": ["channel", "provenance"],
            }
            for scope, channels in _CHANNELS_BY_PROVENANCE_SCOPE.items()
        ]
        return rendered

    @field_validator("supports_evidence_ids", "contradicts_evidence_ids")
    @classmethod
    def _canonical_relationships(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "candidate relationship IDs")

    @model_validator(mode="after")
    def _validate_candidate(self) -> "EvidenceCandidate":
        supporting = set(self.supports_evidence_ids)
        contradicting = set(self.contradicts_evidence_ids)
        if self.evidence_id in supporting or self.evidence_id in contradicting:
            raise ValueError("candidate must not reference itself")
        if supporting & contradicting:
            raise ValueError("support and contradiction targets must be disjoint")

        if self.channel not in _CHANNELS_BY_PROVENANCE_SCOPE[
            self.provenance.provenance_scope
        ]:
            raise ValueError("candidate channel is incompatible with provenance scope")
        return self


class C1ApplicabilityDecision(StrictModel):
    status: Literal["applicable", "not_applicable", "insufficient_context", "unavailable"]
    revision: VersionRef | None
    scope_policy_ref: VersionRef
    matched_rule_ids: Annotated[
        tuple[SafePolicyKey, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    missing_context_fields: Annotated[
        tuple[SafePolicyKey, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    effective_status: Literal["active", "expired", "superseded", "revoked", "none"]
    empirical_support: EmpiricalSupport
    conflict_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        nonnull_revision = {"not": {"type": "null"}}
        rendered["oneOf"] = [
            {
                "properties": {
                    "status": {"enum": ["applicable", "not_applicable"]},
                    "revision": nonnull_revision,
                    "effective_status": {"const": "active"},
                    "matched_rule_ids": {"minItems": 1},
                    "missing_context_fields": {"maxItems": 0},
                }
            },
            {
                "properties": {
                    "status": {"const": "insufficient_context"},
                    "revision": nonnull_revision,
                    "effective_status": {"const": "active"},
                    "missing_context_fields": {"minItems": 1},
                }
            },
            {
                "properties": {
                    "status": {"const": "unavailable"},
                    "revision": {"type": "null"},
                    "matched_rule_ids": {"maxItems": 0},
                    "missing_context_fields": {"maxItems": 0},
                    "effective_status": {"const": "none"},
                    "empirical_support": {"const": "unassessed"},
                }
            },
            {
                "properties": {
                    "status": {"const": "unavailable"},
                    "revision": nonnull_revision,
                    "missing_context_fields": {"maxItems": 0},
                    "effective_status": {
                        "enum": ["expired", "superseded", "revoked"]
                    },
                }
            },
        ]
        return rendered

    @field_validator("matched_rule_ids", "missing_context_fields", "conflict_evidence_ids")
    @classmethod
    def _canonical_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "C1 decision values")

    @model_validator(mode="after")
    def _validate_matrix(self) -> "C1ApplicabilityDecision":
        if self.status in {"applicable", "not_applicable"}:
            valid = (
                self.revision is not None
                and self.effective_status == "active"
                and bool(self.matched_rule_ids)
                and not self.missing_context_fields
            )
        elif self.status == "insufficient_context":
            valid = (
                self.revision is not None
                and self.effective_status == "active"
                and bool(self.missing_context_fields)
            )
        elif self.effective_status == "none":
            valid = (
                self.revision is None
                and not self.matched_rule_ids
                and not self.missing_context_fields
                and self.empirical_support == "unassessed"
            )
        elif self.effective_status in {"expired", "superseded", "revoked"}:
            valid = self.revision is not None and not self.missing_context_fields
        else:
            valid = False
        if not valid:
            raise ValueError("C1 applicability fields do not match the frozen state matrix")
        return self


class EvidencePack(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: Uuid7String
    authority: AuthoritySnapshotBinding
    client_snapshot_ref: VersionRef
    temporary_fact_refs: Annotated[
        tuple[VersionRef, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    supporting: Annotated[
        tuple[EvidenceCandidate, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    contradicting: Annotated[
        tuple[EvidenceCandidate, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    unresolved_conflict_refs: Annotated[
        tuple[VersionRef, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    c1_applicability: C1ApplicabilityDecision
    exclusion_proof_ref: VersionRef
    wiki_manifest_ref: VersionRef
    lexical_manifest_ref: VersionRef
    vector_manifest_ref: VersionRef
    graph_manifest_ref: VersionRef
    reranker_descriptor_ref: VersionRef

    @field_validator("temporary_fact_refs", "unresolved_conflict_refs")
    @classmethod
    def _canonical_refs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        return _unique_sorted_refs(value, "pack version refs")

    @field_validator("supporting", "contradicting")
    @classmethod
    def _canonical_candidates(
        cls,
        value: tuple[EvidenceCandidate, ...],
    ) -> tuple[EvidenceCandidate, ...]:
        identifiers = [candidate.evidence_id for candidate in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("a pack role must not repeat an evidence identifier")
        return tuple(sorted(value, key=lambda candidate: candidate.evidence_id))

    @model_validator(mode="after")
    def _validate_pack_closure(self) -> "EvidencePack":
        if self.authority.run_id != self.run_id:
            raise ValueError("authority binding run_id must equal pack run_id")

        by_id: dict[str, EvidenceCandidate] = {}
        for candidate in self.supporting + self.contradicting:
            existing = by_id.get(candidate.evidence_id)
            if existing is not None and existing != candidate:
                raise ValueError("cross-role candidate copies must be identical")
            by_id[candidate.evidence_id] = candidate

        available = set(by_id)
        for candidate in by_id.values():
            targets = set(candidate.supports_evidence_ids) | set(
                candidate.contradicts_evidence_ids
            )
            if not targets <= available:
                raise ValueError("candidate relationships must resolve inside the pack")
        if not set(self.c1_applicability.conflict_evidence_ids) <= available:
            raise ValueError("C1 conflict evidence must resolve inside the pack")
        return self
