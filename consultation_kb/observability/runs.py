"""Version-pinned, no-body run manifests stored as append-only JSONL."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Annotated, Final, Literal, TypeAlias, cast

from pydantic import Field, StringConstraints, field_validator, model_validator

from consultation_kb.models.common import (
    NonNegativeInt,
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)

from .audit import (
    AuditErrorCode,
    ObservabilityCorruptionError,
    ObservabilityStoreError,
    _append_line,
    _canonical_json_line,
    _exclusive_store_lock,
    _load_records,
)


RunKind: TypeAlias = Literal["consultation_reply", "archive", "evaluation"]
ArchiveDecision: TypeAlias = Literal[
    "not_applicable", "pending", "approved", "rejected"
]
RunComponentName: TypeAlias = Literal[
    "approval",
    "archive",
    "case",
    "client_snapshot",
    "consultation",
    "evaluation",
    "generation",
    "global_graph",
    "lexical",
    "model",
    "model_parameters",
    "policy",
    "query_plan",
    "reply",
    "reranker",
    "retrieval",
    "risk",
    "schema",
    "storage",
    "vector",
    "wiki",
]
RunRouteName: TypeAlias = Literal[
    "profile", "client_history", "wiki", "lexical", "vector", "global_graph", "case"
]
DegradedComponent: TypeAlias = Literal[
    "approval",
    "archive",
    "case",
    "generation",
    "global_graph",
    "lexical",
    "model",
    "policy",
    "reranker",
    "retrieval",
    "risk",
    "storage",
    "vector",
    "wiki",
]
RunPhase: TypeAlias = Literal[
    "query",
    "retrieval",
    "generation_stage",
    "final_candidate",
    "actual_reply",
    "archive",
    "evaluation",
]
HostUnknownField: TypeAlias = Literal["generation_seed", "temperature"]
PythonVersion: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=32,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-z0-9.+-]*)$",
    ),
]


class GovernedObjectRef(StrictModel):
    """A governed content reference that carries identity and hash, never its body."""

    object_id: ObjectId
    content_sha256: Sha256Hex


class NamedVersionRef(StrictModel):
    """Name a version-pinned Prompt, Skill, or other repeated component."""

    name: RunComponentName
    ref: VersionRef


class RunVersionSnapshot(StrictModel):
    """P0 version closure required by design specification section 19."""

    model_descriptor_ref: VersionRef
    model_parameters_ref: VersionRef
    prompt_refs: tuple[NamedVersionRef, ...]
    skill_refs: tuple[NamedVersionRef, ...]
    client_snapshot_ref: VersionRef
    wiki_manifest_ref: VersionRef
    case_manifest_ref: VersionRef
    graph_manifest_ref: VersionRef
    lexical_manifest_ref: VersionRef
    vector_manifest_ref: VersionRef
    reranker_descriptor_ref: VersionRef

    @field_validator("prompt_refs", "skill_refs")
    @classmethod
    def _canonical_named_refs(
        cls,
        value: tuple[NamedVersionRef, ...],
    ) -> tuple[NamedVersionRef, ...]:
        names = tuple(item.name for item in value)
        if len(names) != len(set(names)):
            raise ValueError("named version references must use unique names")
        return tuple(sorted(value, key=lambda item: item.name))


class RunFilterCounts(StrictModel):
    """Complete fixed filter accounting; every removed candidate has one reason."""

    before: NonNegativeInt
    after: NonNegativeInt
    scope_denied: NonNegativeInt = 0
    authorization_denied: NonNegativeInt = 0
    validity_denied: NonNegativeInt = 0
    freshness_denied: NonNegativeInt = 0
    review_denied: NonNegativeInt = 0
    sensitivity_denied: NonNegativeInt = 0
    tombstone_denied: NonNegativeInt = 0
    deduplicated: NonNegativeInt = 0
    other_denied: NonNegativeInt = 0

    @model_validator(mode="after")
    def _validate_balance(self) -> "RunFilterCounts":
        removed = (
            self.scope_denied
            + self.authorization_denied
            + self.validity_denied
            + self.freshness_denied
            + self.review_denied
            + self.sensitivity_denied
            + self.tombstone_denied
            + self.deduplicated
            + self.other_denied
        )
        if self.after + removed != self.before:
            raise ValueError("filter counts must reconcile before to after")
        return self


class RunRouteSnapshot(StrictModel):
    """Governed query-plan and retrieval-route decisions without query text."""

    query_plan_ref: VersionRef
    route_policy_ref: VersionRef
    routes: tuple[RunRouteName, ...]
    filter_counts: RunFilterCounts

    @field_validator("routes")
    @classmethod
    def _require_unique_routes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("retrieval routes must be unique")
        return value


class RunManifestV1(StrictModel):
    """Reproducible P0 run envelope containing IDs, versions, hashes, and counts."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Uuid7String
    run_kind: RunKind
    scope_sha256: Sha256Hex
    started_at: UtcDateTime
    completed_at: UtcDateTime
    versions: RunVersionSnapshot
    routing: RunRouteSnapshot
    evidence_object_ids: tuple[ObjectId, ...]
    critique_error_codes: tuple[AuditErrorCode, ...]
    retry_count: NonNegativeInt
    degraded_components: tuple[DegradedComponent, ...]
    generation_candidate_refs: tuple[GovernedObjectRef, ...]
    actual_reply_ref: GovernedObjectRef | None
    consultant_edit_diff_ref: GovernedObjectRef | None
    archive_draft_ref: GovernedObjectRef | None
    archive_decision: ArchiveDecision
    archive_decision_ref: GovernedObjectRef | None
    result_sha256: Sha256Hex

    @field_validator("evidence_object_ids")
    @classmethod
    def _unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence object IDs must be unique")
        return value

    @field_validator("critique_error_codes")
    @classmethod
    def _canonical_error_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("critique error codes must be unique")
        return tuple(sorted(value))

    @field_validator("degraded_components")
    @classmethod
    def _canonical_degraded_components(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("degraded components must be unique")
        return tuple(sorted(value))

    @field_validator("generation_candidate_refs")
    @classmethod
    def _unique_candidate_refs(
        cls,
        value: tuple[GovernedObjectRef, ...],
    ) -> tuple[GovernedObjectRef, ...]:
        object_ids = tuple(item.object_id for item in value)
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("generation candidate object IDs must be unique")
        return value

    @model_validator(mode="after")
    def _validate_run_window_and_archive_decision(self) -> "RunManifestV1":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.consultant_edit_diff_ref is not None and self.actual_reply_ref is None:
            raise ValueError("consultant edit diff requires an actual reply ref")

        if self.run_kind == "consultation_reply":
            if not self.generation_candidate_refs or self.actual_reply_ref is None:
                raise ValueError("consultation reply run requires candidates and actual reply")
            if (
                self.archive_draft_ref is not None
                or self.archive_decision != "not_applicable"
                or self.archive_decision_ref is not None
            ):
                raise ValueError("consultation reply run must not carry archive state")
        elif self.run_kind == "archive":
            if (
                self.generation_candidate_refs
                or self.actual_reply_ref is not None
                or self.consultant_edit_diff_ref is not None
            ):
                raise ValueError("archive run must not carry reply state")
            if self.archive_draft_ref is None or self.archive_decision == "not_applicable":
                raise ValueError("archive run requires a draft and archive decision")
            if self.archive_decision in {"approved", "rejected"}:
                if self.archive_decision_ref is None:
                    raise ValueError("final archive decision requires a governed decision ref")
            elif self.archive_decision_ref is not None:
                raise ValueError("pending archive state must not carry a decision ref")
        else:
            if (
                self.generation_candidate_refs
                or self.actual_reply_ref is not None
                or self.consultant_edit_diff_ref is not None
                or self.archive_draft_ref is not None
                or self.archive_decision != "not_applicable"
                or self.archive_decision_ref is not None
            ):
                raise ValueError("evaluation run must not carry reply or archive state")

        version_refs = (
            self.versions.model_descriptor_ref,
            self.versions.model_parameters_ref,
            *(item.ref for item in self.versions.prompt_refs),
            *(item.ref for item in self.versions.skill_refs),
            self.versions.client_snapshot_ref,
            self.versions.wiki_manifest_ref,
            self.versions.case_manifest_ref,
            self.versions.graph_manifest_ref,
            self.versions.lexical_manifest_ref,
            self.versions.vector_manifest_ref,
            self.versions.reranker_descriptor_ref,
            self.routing.query_plan_ref,
            self.routing.route_policy_ref,
        )
        closure: dict[tuple[str, int], str] = {}
        for ref in version_refs:
            key = (ref.object_id, ref.version)
            existing_hash = closure.get(key)
            if existing_hash is not None and existing_hash != ref.content_sha256:
                raise ValueError("version closure contains conflicting content hashes")
            closure[key] = ref.content_sha256
        return self


def _version_key(reference: VersionRef) -> tuple[str, int, str]:
    return (reference.object_id, reference.version, reference.content_sha256)


def _canonical_version_refs(
    value: tuple[VersionRef, ...],
    *,
    field_name: str,
) -> tuple[VersionRef, ...]:
    keys = tuple(_version_key(item) for item in value)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{field_name} must contain unique exact versions")
    return tuple(sorted(value, key=_version_key))


class RunLineage(StrictModel):
    """One body-free node in the query-to-archive run tree."""

    root_run_id: Uuid7String
    parent_run_id: Uuid7String | None
    phase: RunPhase
    sequence: NonNegativeInt
    turn_ref: GovernedObjectRef


class RuntimeEnvironmentSnapshot(StrictModel):
    """Reproducible runtime identity with no executable path disclosure."""

    python_implementation: Literal["CPython"] = "CPython"
    python_version: PythonVersion
    pointer_bits: Literal[64] = 64
    base_executable_sha256: Sha256Hex
    runtime_source_tag: Literal[
        "dedicated_venv",
        "managed_install",
        "system_install",
    ]
    runtime_source_sha256: Sha256Hex
    schema_bundle_sha256: Sha256Hex
    package_set_sha256: Sha256Hex
    dependency_lock_sha256: Sha256Hex

    @classmethod
    def from_base_executable(
        cls,
        *,
        base_executable: Path,
        python_version: str,
        runtime_source_tag: Literal[
            "dedicated_venv",
            "managed_install",
            "system_install",
        ],
        runtime_source_sha256: str,
        schema_bundle_sha256: str,
        package_set_sha256: str,
        dependency_lock_sha256: str,
    ) -> "RuntimeEnvironmentSnapshot":
        """Hash an approved interpreter while refusing Codex's cache runtime."""

        if not isinstance(base_executable, Path):
            raise TypeError("base executable must be pathlib.Path")
        try:
            resolved_executable = base_executable.resolve(strict=True)
        except OSError:
            raise ValueError("base executable must be an existing regular file") from None
        normalized = os.fspath(resolved_executable).replace("\\", "/").casefold()
        if ".cache/codex-runtimes/" in f"{normalized.rstrip('/')}/":
            raise ValueError("Codex cache interpreter is forbidden for production runs")
        if not resolved_executable.is_file():
            raise ValueError("base executable must be an existing regular file")
        digest = hashlib.sha256()
        try:
            with resolved_executable.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
        except OSError:
            raise ValueError("base executable cannot be hashed") from None
        return cls(
            python_version=python_version,
            base_executable_sha256=digest.hexdigest(),
            runtime_source_tag=runtime_source_tag,
            runtime_source_sha256=runtime_source_sha256,
            schema_bundle_sha256=schema_bundle_sha256,
            package_set_sha256=package_set_sha256,
            dependency_lock_sha256=dependency_lock_sha256,
        )


class RunReproducibilitySnapshot(StrictModel):
    """Known generation controls plus explicit host-owned unknowns."""

    queue_order_seed: NonNegativeInt
    generation_seed: NonNegativeInt | None
    temperature_milli: Annotated[int, Field(strict=True, ge=0, le=5000)] | None
    host_unknown_fields: tuple[HostUnknownField, ...]

    @field_validator("host_unknown_fields")
    @classmethod
    def _canonical_unknowns(
        cls,
        value: tuple[HostUnknownField, ...],
    ) -> tuple[HostUnknownField, ...]:
        if len(value) != len(set(value)):
            raise ValueError("host unknown fields must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _known_unknown_consistency(self) -> "RunReproducibilitySnapshot":
        unknown = set(self.host_unknown_fields)
        if (self.generation_seed is None) != ("generation_seed" in unknown):
            raise ValueError("generation seed must be known or explicitly host-unknown")
        if (self.temperature_milli is None) != ("temperature" in unknown):
            raise ValueError("temperature must be known or explicitly host-unknown")
        return self


class EvidenceCandidateClosure(StrictModel):
    """Exact candidate edges; bodies and expanded provenance are never embedded."""

    candidate_ref: VersionRef
    text_ref: VersionRef
    locator_ref: VersionRef
    freshness_policy_ref: VersionRef
    provenance_ref: VersionRef
    derivation_ref: VersionRef

    def version_refs(self) -> tuple[VersionRef, ...]:
        return (
            self.candidate_ref,
            self.text_ref,
            self.locator_ref,
            self.freshness_policy_ref,
            self.provenance_ref,
            self.derivation_ref,
        )


class EvidencePackClosureV2(StrictModel):
    """Complete immutable EvidencePack closure represented only by exact refs."""

    evidence_pack_ref: VersionRef
    evidence_pack_canonical_sha256: Sha256Hex
    authority_snapshot_ref: VersionRef
    authority_policy_ref: VersionRef
    client_snapshot_ref: VersionRef
    temporary_fact_refs: tuple[VersionRef, ...]
    candidates: tuple[EvidenceCandidateClosure, ...]
    c1_revision_ref: VersionRef | None
    c1_scope_policy_ref: VersionRef
    c1_applicability_ref: VersionRef
    unresolved_conflict_refs: tuple[VersionRef, ...]
    exclusion_proof_ref: VersionRef
    wiki_manifest_ref: VersionRef
    lexical_manifest_ref: VersionRef
    vector_manifest_ref: VersionRef
    graph_manifest_ref: VersionRef
    reranker_descriptor_ref: VersionRef

    @field_validator("temporary_fact_refs", "unresolved_conflict_refs")
    @classmethod
    def _canonical_ref_groups(
        cls,
        value: tuple[VersionRef, ...],
        info: object,
    ) -> tuple[VersionRef, ...]:
        field_name = getattr(info, "field_name", "version_refs")
        return _canonical_version_refs(value, field_name=str(field_name))

    @field_validator("candidates")
    @classmethod
    def _canonical_candidates(
        cls,
        value: tuple[EvidenceCandidateClosure, ...],
    ) -> tuple[EvidenceCandidateClosure, ...]:
        identities = tuple(_version_key(item.candidate_ref) for item in value)
        if len(identities) != len(set(identities)):
            raise ValueError("evidence candidates must be unique")
        return tuple(sorted(value, key=lambda item: _version_key(item.candidate_ref)))

    @model_validator(mode="after")
    def _complete_exact_closure(self) -> "EvidencePackClosureV2":
        if self.evidence_pack_ref.content_sha256 != self.evidence_pack_canonical_sha256:
            raise ValueError("EvidencePack canonical hash must match its exact reference")
        closure: dict[tuple[str, int], str] = {}
        for reference in self.version_refs():
            key = (reference.object_id, reference.version)
            previous = closure.setdefault(key, reference.content_sha256)
            if previous != reference.content_sha256:
                raise ValueError("EvidencePack closure contains a conflicting exact version")
        return self

    def version_refs(self) -> tuple[VersionRef, ...]:
        refs = [
            self.evidence_pack_ref,
            self.authority_snapshot_ref,
            self.authority_policy_ref,
            self.client_snapshot_ref,
            *self.temporary_fact_refs,
            self.c1_scope_policy_ref,
            self.c1_applicability_ref,
            *self.unresolved_conflict_refs,
            self.exclusion_proof_ref,
            self.wiki_manifest_ref,
            self.lexical_manifest_ref,
            self.vector_manifest_ref,
            self.graph_manifest_ref,
            self.reranker_descriptor_ref,
        ]
        if self.c1_revision_ref is not None:
            refs.append(self.c1_revision_ref)
        for candidate in self.candidates:
            refs.extend(candidate.version_refs())
        return tuple(refs)


class RunManifestV2(StrictModel):
    """P9 complete, lineage-aware, no-body reproducibility manifest."""

    schema_version: Literal["2.0"] = "2.0"
    run_id: Uuid7String
    run_kind: RunKind
    scope_sha256: Sha256Hex
    started_at: UtcDateTime
    completed_at: UtcDateTime
    lineage: RunLineage
    versions: RunVersionSnapshot
    evidence: EvidencePackClosureV2
    routing: RunRouteSnapshot
    runtime: RuntimeEnvironmentSnapshot
    reproducibility: RunReproducibilitySnapshot
    critique_error_codes: tuple[AuditErrorCode, ...]
    retry_count: NonNegativeInt
    degraded_components: tuple[DegradedComponent, ...]
    generation_candidate_refs: tuple[GovernedObjectRef, ...]
    actual_reply_ref: GovernedObjectRef | None
    consultant_edit_diff_ref: GovernedObjectRef | None
    consultant_review_decision: ArchiveDecision
    consultant_review_ref: GovernedObjectRef | None
    archive_draft_ref: GovernedObjectRef | None
    archive_decision: ArchiveDecision
    archive_decision_ref: GovernedObjectRef | None
    result_sha256: Sha256Hex

    @field_validator("critique_error_codes")
    @classmethod
    def _canonical_v2_error_codes(
        cls,
        value: tuple[AuditErrorCode, ...],
    ) -> tuple[AuditErrorCode, ...]:
        if len(value) != len(set(value)):
            raise ValueError("critique error codes must be unique")
        return tuple(sorted(value))

    @field_validator("degraded_components")
    @classmethod
    def _canonical_v2_degraded_components(
        cls,
        value: tuple[DegradedComponent, ...],
    ) -> tuple[DegradedComponent, ...]:
        if len(value) != len(set(value)):
            raise ValueError("degraded components must be unique")
        return tuple(sorted(value))

    @field_validator("generation_candidate_refs")
    @classmethod
    def _canonical_v2_candidate_refs(
        cls,
        value: tuple[GovernedObjectRef, ...],
    ) -> tuple[GovernedObjectRef, ...]:
        object_ids = tuple(item.object_id for item in value)
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("generation candidate object IDs must be unique")
        return tuple(sorted(value, key=lambda item: item.object_id))

    @model_validator(mode="after")
    def _validate_complete_run(self) -> "RunManifestV2":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.lineage.parent_run_id is None:
            if (
                self.lineage.root_run_id != self.run_id
                or self.lineage.sequence != 0
                or self.lineage.phase not in {"query", "evaluation"}
            ):
                raise ValueError("root run lineage is inconsistent")
        elif (
            self.lineage.parent_run_id == self.run_id
            or self.lineage.root_run_id == self.run_id
            or self.lineage.sequence == 0
        ):
            raise ValueError("child run lineage is inconsistent")

        phase = self.lineage.phase
        if phase == "archive" and self.run_kind != "archive":
            raise ValueError("archive phase requires archive run kind")
        if phase == "evaluation" and self.run_kind != "evaluation":
            raise ValueError("evaluation phase requires evaluation run kind")
        if phase not in {"archive", "evaluation"} and self.run_kind != "consultation_reply":
            raise ValueError("consultation phase requires consultation reply run kind")

        if self.consultant_edit_diff_ref is not None and self.actual_reply_ref is None:
            raise ValueError("consultant edit diff requires an actual reply ref")
        if self.run_kind == "consultation_reply":
            if not self.generation_candidate_refs or self.actual_reply_ref is None:
                raise ValueError("consultation reply requires governed candidates and reply")
            if (
                self.consultant_review_decision not in {"approved", "rejected"}
                or self.consultant_review_ref is None
            ):
                raise ValueError("consultation reply requires a governed review decision")
            if (
                self.archive_draft_ref is not None
                or self.archive_decision != "not_applicable"
                or self.archive_decision_ref is not None
            ):
                raise ValueError("consultation reply must not carry archive state")
        elif self.run_kind == "archive":
            if (
                self.generation_candidate_refs
                or self.actual_reply_ref is not None
                or self.consultant_edit_diff_ref is not None
                or self.consultant_review_decision != "not_applicable"
                or self.consultant_review_ref is not None
            ):
                raise ValueError("archive run must not carry reply state")
            if self.archive_draft_ref is None or self.archive_decision == "not_applicable":
                raise ValueError("archive run requires draft and decision state")
            if self.archive_decision in {"approved", "rejected"}:
                if self.archive_decision_ref is None:
                    raise ValueError("final archive decision requires a governed ref")
            elif self.archive_decision_ref is not None:
                raise ValueError("pending archive decision must not carry a final ref")
        elif (
            self.generation_candidate_refs
            or self.actual_reply_ref is not None
            or self.consultant_edit_diff_ref is not None
            or self.consultant_review_decision != "not_applicable"
            or self.consultant_review_ref is not None
            or self.archive_draft_ref is not None
            or self.archive_decision != "not_applicable"
            or self.archive_decision_ref is not None
        ):
            raise ValueError("evaluation run must not carry reply or archive state")

        paired_refs = (
            (self.versions.client_snapshot_ref, self.evidence.client_snapshot_ref),
            (self.versions.wiki_manifest_ref, self.evidence.wiki_manifest_ref),
            (self.versions.lexical_manifest_ref, self.evidence.lexical_manifest_ref),
            (self.versions.vector_manifest_ref, self.evidence.vector_manifest_ref),
            (self.versions.graph_manifest_ref, self.evidence.graph_manifest_ref),
            (
                self.versions.reranker_descriptor_ref,
                self.evidence.reranker_descriptor_ref,
            ),
        )
        if any(left != right for left, right in paired_refs):
            raise ValueError("version snapshot and EvidencePack closure disagree")

        closure: dict[tuple[str, int], str] = {}
        version_refs = (
            self.versions.model_descriptor_ref,
            self.versions.model_parameters_ref,
            *(item.ref for item in self.versions.prompt_refs),
            *(item.ref for item in self.versions.skill_refs),
            *self.evidence.version_refs(),
            self.routing.query_plan_ref,
            self.routing.route_policy_ref,
        )
        for reference in version_refs:
            key = (reference.object_id, reference.version)
            previous = closure.setdefault(key, reference.content_sha256)
            if previous != reference.content_sha256:
                raise ValueError("run closure contains a conflicting exact version")
        return self


RunManifest: TypeAlias = RunManifestV1
RunManifestRecord: TypeAlias = RunManifestV1 | RunManifestV2
_RUN_MANIFEST_MODELS: Final[dict[str, type[StrictModel]]] = {
    "1.0": RunManifestV1,
    "2.0": RunManifestV2,
}


class DuplicateRunError(ObservabilityStoreError):
    """Raised when an immutable run ID is appended more than once."""


class RunLineageError(ObservabilityStoreError):
    """Raised when a V2 run would cross a turn, scope, root, or parent boundary."""


def _lineage_error(records: tuple[RunManifestRecord, ...]) -> str | None:
    seen: dict[str, RunManifestV2] = {}
    turn_bindings: dict[str, tuple[str, str, str]] = {}
    for record in records:
        if not isinstance(record, RunManifestV2):
            continue
        lineage = record.lineage
        turn = lineage.turn_ref
        binding = (turn.content_sha256, record.scope_sha256, lineage.root_run_id)
        previous_binding = turn_bindings.setdefault(turn.object_id, binding)
        if previous_binding != binding:
            return "run turn binding crosses an immutable scope or root"
        if lineage.parent_run_id is None:
            if lineage.root_run_id != record.run_id:
                return "run root lineage does not identify itself"
        else:
            parent = seen.get(lineage.parent_run_id)
            root = seen.get(lineage.root_run_id)
            if parent is None or root is None:
                return "run lineage parent or root is not already committed"
            if (
                parent.lineage.root_run_id != lineage.root_run_id
                or parent.scope_sha256 != record.scope_sha256
                or parent.lineage.turn_ref != turn
                or root.lineage.parent_run_id is not None
                or lineage.sequence <= parent.lineage.sequence
            ):
                return "run lineage parent, root, scope, turn, or sequence disagrees"
        seen[record.run_id] = record
    return None


class RunManifestStore:
    """Locked P0 append-only store with version-dispatched strict reload."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("run manifest path must be pathlib.Path")
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def append(self, manifest: RunManifestRecord) -> None:
        if isinstance(manifest, RunManifestV2):
            validated: RunManifestRecord = RunManifestV2.model_validate(manifest)
        else:
            validated = RunManifestV1.model_validate(manifest)
        with _exclusive_store_lock(self._path):
            existing = self._load_unlocked()
            if any(item.run_id == validated.run_id for item in existing):
                raise DuplicateRunError("run ID is already present")
            lineage_error = _lineage_error((*existing, validated))
            if lineage_error is not None:
                raise RunLineageError(lineage_error)
            _append_line(self._path, _canonical_json_line(validated))

    def load(self) -> tuple[RunManifestRecord, ...]:
        with _exclusive_store_lock(self._path):
            return self._load_unlocked()

    def _load_unlocked(self) -> tuple[RunManifestRecord, ...]:
        loaded = _load_records(self._path, _RUN_MANIFEST_MODELS)
        records = cast(tuple[RunManifestRecord, ...], loaded)
        run_ids = tuple(record.run_id for record in records)
        if len(run_ids) != len(set(run_ids)):
            raise ObservabilityCorruptionError(
                "run manifest stream contains a duplicate run ID"
            )
        lineage_error = _lineage_error(records)
        if lineage_error is not None:
            raise ObservabilityCorruptionError(lineage_error)
        return records
