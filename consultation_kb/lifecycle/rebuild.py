"""Asynchronous rebuild coordinator over exact authority snapshots."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, cast

from pydantic import model_validator

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.lifecycle.equivalence import (
    ArtifactFingerprint,
    EquivalenceReport,
    compare_artifact_sets,
    equivalence_report_bytes,
)
from consultation_kb.lifecycle.rebuild_jobs import (
    RebuildJob,
    RebuildJobCreate,
    RebuildJobRepository,
)
from consultation_kb.lifecycle.rebuild_registry import (
    AUTHORITY_TABLE_ALLOWLIST,
    AuthoritySourceSpec,
    BuilderDescriptor,
    BuilderRegistry,
    DatabaseScope,
)
from consultation_kb.approvals.models import descriptor_sha256
from consultation_kb.lifecycle.structured_artifact import (
    StructuredArtifactEnvelope,
    StructuredArtifactError,
    StructuredArtifactMember,
    parse_structured_artifact,
)
from consultation_kb.models.deletion import (
    DeletionActionType,
    DeletionAuthorityScope,
    deletion_intent_authority_sha256,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestMember,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore, ContentStoreError
from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.manifests import DraftDescriptor


_SAFE_KEY = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_CASE_INDEX_INTENT_SET_SHA256 = canonical_sha256(
    {
        "domain": "consultation_kb.case_index_intent_set.v1",
        "identities": [],
    }
)


def rebuild_manifest_id(
    *,
    job_id: str,
    attempt_count: int,
    output_purpose: str,
) -> str:
    """Derive a stable UUIDv7 manifest id from an approved stage output."""

    if (
        type(job_id) is not str
        or len(job_id) < 38
        or type(attempt_count) is not int
        or attempt_count <= 0
        or _SAFE_KEY.fullmatch(output_purpose) is None
    ):
        raise RebuildCoordinatorError("REBUILD_STAGE_OUTPUTS_INVALID")
    try:
        source = uuid.UUID(job_id[-36:])
    except (ValueError, AttributeError):
        raise RebuildCoordinatorError("REBUILD_STAGE_OUTPUTS_INVALID") from None
    if source.version != 7 or source.variant != uuid.RFC_4122:
        raise RebuildCoordinatorError("REBUILD_STAGE_OUTPUTS_INVALID")
    timestamp_ms = source.int >> 80
    randomness = int.from_bytes(
        hashlib.sha256(
            canonical_json_bytes(
                {
                    "domain": "consultation_kb.rebuild_manifest_id.v1",
                    "job_id": job_id,
                    "attempt_count": attempt_count,
                    "output_purpose": output_purpose,
                }
            )
        ).digest(),
        "big",
    ) % (2**74)
    rand_a = randomness >> 62
    rand_b = randomness & ((1 << 62) - 1)
    bits = (
        (timestamp_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return f"rebuild_manifest_{uuid.UUID(int=bits)}"


class RebuildCoordinatorError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuthorityVersionRef(StrictModel):
    source: AuthoritySourceSpec
    version: NonNegativeInt
    snapshot_sha256: Sha256Hex


def authority_inventory_sha256(
    *,
    database_scope: DatabaseScope,
    scope_sha256: str,
    tombstone_epoch: int,
    versions: tuple[AuthorityVersionRef, ...],
) -> str:
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_authority_inventory.v1",
            "database_scope": database_scope,
            "scope_sha256": scope_sha256,
            "tombstone_epoch": tombstone_epoch,
            "versions": [value.model_dump(mode="json") for value in versions],
        }
    )


class AuthorityInventory(StrictModel):
    """Exact, body-free authority snapshot resolvable after process restart."""

    database_scope: DatabaseScope
    scope_sha256: Sha256Hex
    tombstone_epoch: NonNegativeInt
    versions: tuple[AuthorityVersionRef, ...]
    input_authority_versions_sha256: Sha256Hex

    @classmethod
    def create(
        cls,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        tombstone_epoch: int,
        versions: tuple[AuthorityVersionRef, ...],
    ) -> "AuthorityInventory":
        ordered = tuple(sorted(versions, key=lambda value: value.source.key))
        return cls(
            database_scope=database_scope,
            scope_sha256=scope_sha256,
            tombstone_epoch=tombstone_epoch,
            versions=ordered,
            input_authority_versions_sha256=authority_inventory_sha256(
                database_scope=database_scope,
                scope_sha256=scope_sha256,
                tombstone_epoch=tombstone_epoch,
                versions=ordered,
            ),
        )

    @model_validator(mode="after")
    def _validate_inventory(self) -> "AuthorityInventory":
        keys = tuple(value.source.key for value in self.versions)
        if not keys or keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("authority versions must be non-empty, sorted, and unique")
        if any(
            value.source.database_scope != self.database_scope
            for value in self.versions
        ):
            raise ValueError("authority inventory cannot cross database scopes")
        expected = authority_inventory_sha256(
            database_scope=self.database_scope,
            scope_sha256=self.scope_sha256,
            tombstone_epoch=self.tombstone_epoch,
            versions=self.versions,
        )
        if self.input_authority_versions_sha256 != expected:
            raise ValueError("authority inventory hash mismatch")
        return self


class RebuildRequest(StrictModel):
    database_scope: DatabaseScope
    source_intent_id: NonEmptyStr | None = None
    scope_sha256: Sha256Hex
    purpose: SafePolicyKey
    policy_sha256: Sha256Hex | None
    model_descriptor_sha256: Sha256Hex | None


def _plan_sha256_payload(value: "RebuildPlan") -> dict[str, object]:
    return _plan_payload(
        database_scope=value.database_scope,
        source_intent_id=value.source_intent_id,
        scope_sha256=value.scope_sha256,
        purpose=value.purpose,
        builder_ids=value.builder_ids,
        builder_dag_sha256=value.builder_dag_sha256,
        input_authority_versions_sha256=(
            value.input_authority_versions_sha256
        ),
        case_index_intent_set_sha256=value.case_index_intent_set_sha256,
        tombstone_epoch=value.tombstone_epoch,
        policy_sha256=value.policy_sha256,
        model_descriptor_sha256=value.model_descriptor_sha256,
    )


def _plan_payload(
    *,
    database_scope: DatabaseScope,
    source_intent_id: str | None,
    scope_sha256: str,
    purpose: str,
    builder_ids: tuple[str, ...],
    builder_dag_sha256: str,
    input_authority_versions_sha256: str,
    case_index_intent_set_sha256: str,
    tombstone_epoch: int,
    policy_sha256: str | None,
    model_descriptor_sha256: str | None,
) -> dict[str, object]:
    return {
        "domain": "consultation_kb.rebuild_plan.v1",
        "database_scope": database_scope,
        "source_intent_id": source_intent_id,
        "scope_sha256": scope_sha256,
        "purpose": purpose,
        "builder_ids": list(builder_ids),
        "builder_dag_sha256": builder_dag_sha256,
        "input_authority_versions_sha256": input_authority_versions_sha256,
        "case_index_intent_set_sha256": case_index_intent_set_sha256,
        "tombstone_epoch": tombstone_epoch,
        "policy_sha256": policy_sha256,
        "model_descriptor_sha256": model_descriptor_sha256,
    }


class RebuildPlan(StrictModel):
    database_scope: DatabaseScope
    source_intent_id: NonEmptyStr | None
    scope_sha256: Sha256Hex
    purpose: SafePolicyKey
    builder_ids: tuple[SafePolicyKey, ...]
    builder_dag_sha256: Sha256Hex
    input_authority_versions_sha256: Sha256Hex
    case_index_intent_set_sha256: Sha256Hex
    tombstone_epoch: NonNegativeInt
    policy_sha256: Sha256Hex | None
    model_descriptor_sha256: Sha256Hex | None
    plan_sha256: Sha256Hex

    @model_validator(mode="after")
    def _validate_plan(self) -> "RebuildPlan":
        if not self.builder_ids or len(set(self.builder_ids)) != len(
            self.builder_ids
        ):
            raise ValueError("rebuild plan builders must be non-empty and unique")
        if self.plan_sha256 != canonical_sha256(_plan_sha256_payload(self)):
            raise ValueError("rebuild plan hash mismatch")
        return self


def rebuild_job_plan_sha256(
    job: RebuildJob,
    *,
    registry: BuilderRegistry,
    case_index_intent_set_sha256: str,
) -> str:
    """Reconstruct the approved plan hash from durable job inputs."""

    exact = RebuildJob.model_validate(job)
    if _SHA256.fullmatch(case_index_intent_set_sha256) is None:
        raise RebuildCoordinatorError("REBUILD_CASE_INDEX_INTENT_SET_INVALID")
    descriptors = registry.plan(
        database_scope=exact.database_scope,
        purpose=exact.purpose,
    )
    return canonical_sha256(
        _plan_payload(
            database_scope=exact.database_scope,
            source_intent_id=exact.source_intent_id,
            scope_sha256=exact.scope_sha256,
            purpose=exact.purpose,
            builder_ids=tuple(value.builder_id for value in descriptors),
            builder_dag_sha256=exact.builder_dag_sha256,
            input_authority_versions_sha256=(
                exact.input_authority_versions_sha256
            ),
            case_index_intent_set_sha256=case_index_intent_set_sha256,
            tombstone_epoch=exact.tombstone_epoch,
            policy_sha256=exact.policy_sha256,
            model_descriptor_sha256=exact.model_descriptor_sha256,
        )
    )


@dataclass(frozen=True)
class AuthorityRecord:
    """Transient exact authority body supplied only to a declared builder."""

    source: AuthoritySourceSpec
    object_id: str
    version: int
    content_sha256: str
    payload: bytes
    approved: bool
    tombstoned: bool
    active: bool = True

    def __post_init__(self) -> None:
        if type(self.object_id) is not str or not self.object_id:
            raise ValueError("authority object id must be non-empty")
        if type(self.version) is not int or self.version < 0:
            raise ValueError("authority object version must be non-negative")
        if type(self.payload) is not bytes:
            raise TypeError("authority payload must be immutable bytes")
        if _SHA256.fullmatch(self.content_sha256) is None:
            raise ValueError("authority content hash must be canonical sha256")
        if hashlib.sha256(self.payload).hexdigest() != self.content_sha256:
            raise ValueError("authority payload hash mismatch")
        if (
            type(self.approved) is not bool
            or type(self.tombstoned) is not bool
            or type(self.active) is not bool
        ):
            raise TypeError("authority visibility flags must be exact booleans")


def authority_source_snapshot_sha256(
    source: AuthoritySourceSpec,
    records: Sequence[AuthorityRecord],
) -> str:
    """Hash the exact eligible row set without copying any authority body."""

    eligible = tuple(
        sorted(
            (
                record
                for record in records
                if record.approved and record.active and not record.tombstoned
            ),
            key=lambda value: (
                value.object_id,
                value.version,
                value.content_sha256,
            ),
        )
    )
    if any(record.source != source for record in records):
        raise ValueError("authority source snapshot contains a foreign record")
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_authority_source.v1",
            "source": source.model_dump(mode="json"),
            "records": [
                {
                    "object_id": record.object_id,
                    "version": record.version,
                    "content_sha256": record.content_sha256,
                }
                for record in eligible
            ],
        }
    )


@dataclass(frozen=True)
class BuiltArtifact:
    """Transient staged artifact; durable reports retain only its fingerprints."""

    builder_id: str
    output_purpose: str
    version: int
    content_sha256: str
    semantic_fingerprint_sha256: str
    payload: bytes
    comparison_content_sha256: str | None = None

    def __post_init__(self) -> None:
        if _SAFE_KEY.fullmatch(self.builder_id) is None:
            raise ValueError("artifact builder id must be lower snake case")
        if _SAFE_KEY.fullmatch(self.output_purpose) is None:
            raise ValueError("artifact output purpose must be lower snake case")
        if type(self.version) is not int or self.version < 0:
            raise ValueError("artifact version must be non-negative")
        if type(self.payload) is not bytes:
            raise TypeError("artifact payload must be immutable bytes")
        if hashlib.sha256(self.payload).hexdigest() != self.content_sha256:
            raise ValueError("built artifact payload hash mismatch")
        if _SHA256.fullmatch(self.semantic_fingerprint_sha256) is None:
            raise ValueError("artifact semantic fingerprint must be sha256")
        if (
            self.comparison_content_sha256 is not None
            and _SHA256.fullmatch(self.comparison_content_sha256) is None
        ):
            raise ValueError("artifact comparison fingerprint must be sha256")

    @classmethod
    def create(
        cls,
        *,
        builder_id: str,
        output_purpose: str,
        version: int,
        payload: bytes,
        semantic_fingerprint_sha256: str,
        comparison_content_sha256: str | None = None,
    ) -> "BuiltArtifact":
        return cls(
            builder_id=builder_id,
            output_purpose=output_purpose,
            version=version,
            content_sha256=hashlib.sha256(payload).hexdigest(),
            semantic_fingerprint_sha256=semantic_fingerprint_sha256,
            payload=payload,
            comparison_content_sha256=comparison_content_sha256,
        )

    @property
    def fingerprint(self) -> ArtifactFingerprint:
        return ArtifactFingerprint(
            artifact_key=self.output_purpose,
            version=self.version,
            content_sha256=(
                self.content_sha256
                if self.comparison_content_sha256 is None
                else self.comparison_content_sha256
            ),
            semantic_fingerprint_sha256=self.semantic_fingerprint_sha256,
        )


@dataclass(frozen=True)
class BuildContext:
    job: RebuildJob
    descriptor: BuilderDescriptor
    authority_versions: tuple[AuthorityVersionRef, ...]
    authority_records: tuple[AuthorityRecord, ...]
    dependency_artifacts: tuple[BuiltArtifact, ...]
    policy_sha256: str | None
    model_descriptor_sha256: str | None
    tombstone_epoch: int

    def __post_init__(self) -> None:
        allowed_sources = {
            source.key for source in self.descriptor.authority_sources
        }
        if tuple(value.source for value in self.authority_versions) != (
            self.descriptor.authority_sources
        ):
            raise ValueError("builder context authority version closure mismatch")
        if any(
            record.source.key not in allowed_sources
            or not record.approved
            or record.tombstoned
            or not record.active
            for record in self.authority_records
        ):
            raise ValueError("builder context contains unauthorized authority records")
        actual_dependencies = tuple(
            artifact.builder_id for artifact in self.dependency_artifacts
        )
        if actual_dependencies != self.descriptor.dependencies:
            raise ValueError("builder context dependency closure mismatch")


class RebuildAuthoritySource(Protocol):
    """Read-only adapter over historical authority snapshots.

    Implementations must resolve the exact aggregate version hash and must not
    expose generation scratch, unapproved drafts, or model intermediate state.
    """

    def inventory(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory: ...

    def resolve_exact(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        input_authority_versions_sha256: str,
        tombstone_epoch: int,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory: ...

    def read_exact(
        self, inventory: AuthorityInventory
    ) -> Mapping[str, Sequence[AuthorityRecord]]: ...

    def current_tombstone_epoch(
        self, *, database_scope: DatabaseScope, scope_sha256: str
    ) -> int: ...


@dataclass(frozen=True, slots=True)
class _CasColumn:
    digest_column: str | None = None
    reference_column: str | None = None
    size_column: str | None = None
    optional: bool = False


@dataclass(frozen=True, slots=True)
class _AuthorityRule:
    identity_columns: tuple[str, ...]
    version_columns: tuple[str, ...]
    where_sql: str
    cas_columns: tuple[_CasColumn, ...] = ()
    tombstone_identities: tuple[tuple[str, str], ...] = ()
    tombstone_lookup: tuple[tuple[str, str, tuple[str, ...]], ...] = ()


_GLOBAL_AUTHORITY_RULES: dict[str, _AuthorityRule] = {
    "sources": _AuthorityRule(
        ("source_id",),
        ("current_version",),
        "WHERE EXISTS (SELECT 1 FROM source_versions AS v "
        "WHERE v.source_id = t.source_id AND v.version = t.current_version "
        "AND v.status = 'APPROVED')",
        tombstone_identities=(("source", "source_id"),),
    ),
    "source_versions": _AuthorityRule(
        ("source_id", "version"),
        ("version",),
        "WHERE t.status = 'APPROVED'",
        (_CasColumn("content_sha256", "content_object_ref", "size_bytes"),),
        (("source", "source_id"),),
    ),
    "passages": _AuthorityRule(
        ("passage_id", "version"),
        ("version", "source_version"),
        "WHERE t.review_status = 'APPROVED'",
        (
            _CasColumn(reference_column="raw_content_ref"),
            _CasColumn(reference_column="retrieval_content_ref"),
            _CasColumn(reference_column="context_before_ref", optional=True),
            _CasColumn(reference_column="context_after_ref", optional=True),
        ),
        (
            ("passage", "passage_id"),
            ("source", "source_id"),
        ),
    ),
    "claims": _AuthorityRule(
        ("claim_id", "version"),
        ("version", "theory_revision"),
        "WHERE t.review_status = 'APPROVED'",
        (
            _CasColumn(
                "claim_sha256",
                "claim_object_ref",
                "claim_object_size_bytes",
            ),
        ),
        (
            ("claim", "claim_id"),
            ("theory_revision", "theory_revision_id"),
        ),
    ),
    "claim_evidence": _AuthorityRule(
        ("claim_id", "claim_version", "passage_id", "passage_version", "relation"),
        ("claim_version", "passage_version"),
        "WHERE EXISTS (SELECT 1 FROM claims AS c WHERE c.claim_id = t.claim_id "
        "AND c.version = t.claim_version AND c.review_status = 'APPROVED') "
        "AND EXISTS (SELECT 1 FROM passages AS p WHERE p.passage_id = t.passage_id "
        "AND p.version = t.passage_version AND p.review_status = 'APPROVED')",
        tombstone_identities=(
            ("claim", "claim_id"),
            ("passage", "passage_id"),
        ),
    ),
    "theory_revisions": _AuthorityRule(
        ("theory_id", "revision"),
        ("revision", "source_version"),
        "WHERE t.status = 'ACTIVE'",
        (
            _CasColumn(
                reference_column="revision_object_ref",
                size_column="revision_object_size_bytes",
            ),
        ),
        (
            ("theory_revision", "theory_id"),
            ("source", "source_id"),
        ),
    ),
    "theory_revision_passages": _AuthorityRule(
        ("theory_id", "theory_revision", "passage_id", "passage_version"),
        ("theory_revision", "passage_version"),
        "WHERE EXISTS (SELECT 1 FROM theory_revisions AS r "
        "WHERE r.theory_id = t.theory_id AND r.revision = t.theory_revision "
        "AND r.status = 'ACTIVE') AND EXISTS (SELECT 1 FROM passages AS p "
        "WHERE p.passage_id = t.passage_id AND p.version = t.passage_version "
        "AND p.review_status = 'APPROVED')",
        tombstone_identities=(
            ("theory_revision", "theory_id"),
            ("passage", "passage_id"),
        ),
    ),
    "scope_policy_versions": _AuthorityRule(
        ("policy_id", "version"),
        ("version",),
        "WHERE t.status = 'APPROVED'",
        (
            _CasColumn(
                "cas_object_sha256",
                "cas_object_ref",
                "cas_object_size_bytes",
            ),
        ),
        (("scope_policy", "policy_id"),),
    ),
    "scope_policy_approval_bindings": _AuthorityRule(
        ("approval_request_id",),
        ("version",),
        "WHERE t.action = 'APPROVE' AND EXISTS ("
        "SELECT 1 FROM scope_policy_versions AS p "
        "WHERE p.policy_id = t.policy_id AND p.version = t.version "
        "AND p.status = 'APPROVED' "
        "AND p.approval_request_id = t.approval_request_id)",
        tombstone_identities=(("scope_policy", "policy_id"),),
    ),
    "review_decisions": _AuthorityRule(
        ("decision_id",),
        ("object_version",),
        "WHERE t.decision = 'APPROVE'",
    ),
    "wiki_revisions": _AuthorityRule(
        ("wiki_id", "revision"),
        ("revision", "base_revision"),
        "WHERE t.review_status = 'ACTIVE'",
        (
            _CasColumn("body_sha256", "body_object_ref", "body_object_size_bytes"),
            _CasColumn("diff_sha256", "diff_object_ref", "diff_object_size_bytes"),
        ),
        (("wiki_revision", "wiki_id"),),
    ),
    "wiki_revision_claims": _AuthorityRule(
        ("wiki_id", "wiki_revision", "section_key", "claim_id", "claim_version"),
        ("wiki_revision", "claim_version"),
        "WHERE EXISTS (SELECT 1 FROM wiki_revisions AS w "
        "WHERE w.wiki_id = t.wiki_id AND w.revision = t.wiki_revision "
        "AND w.review_status = 'ACTIVE') AND EXISTS (SELECT 1 FROM claims AS c "
        "WHERE c.claim_id = t.claim_id AND c.version = t.claim_version "
        "AND c.review_status = 'APPROVED')",
        tombstone_identities=(
            ("wiki_revision", "wiki_id"),
            ("claim", "claim_id"),
        ),
    ),
    "cases": _AuthorityRule(
        ("case_id",),
        ("current_version",),
        "WHERE t.state = 'ACTIVE'",
        tombstone_identities=(("case", "case_id"),),
    ),
    "case_versions": _AuthorityRule(
        ("case_id", "version"),
        ("version", "candidate_version", "provenance_version"),
        "WHERE t.state = 'ACTIVE'",
        (
            _CasColumn(
                "global_content_sha256",
                "global_content_ref",
                "global_content_size_bytes",
            ),
        ),
        (
            ("case", "case_id"),
            ("case_provenance", "provenance_id"),
        ),
    ),
    "case_authorizations": _AuthorityRule(
        ("case_id", "case_version"),
        ("case_version", "authorization_version"),
        "WHERE t.reuse_authorized = 1 AND t.revoked_at IS NULL "
        "AND EXISTS (SELECT 1 FROM case_versions AS v "
        "WHERE v.case_id = t.case_id AND v.version = t.case_version "
        "AND v.state = 'ACTIVE')",
        tombstone_identities=(
            ("case", "case_id"),
            ("case_authorization", "authorization_id"),
        ),
    ),
    "case_review_decisions": _AuthorityRule(
        ("case_id", "case_version"),
        ("case_version", "review_version", "release_policy_version"),
        "WHERE t.decision = 'approved' AND EXISTS (SELECT 1 FROM case_versions AS v "
        "WHERE v.case_id = t.case_id AND v.version = t.case_version "
        "AND v.state = 'ACTIVE')",
        tombstone_identities=(("case", "case_id"),),
    ),
    "case_provenance": _AuthorityRule(
        ("provenance_id", "provenance_version"),
        ("provenance_version", "artifact_version", "derivation_rule_version"),
        "WHERE EXISTS (SELECT 1 FROM case_versions AS v "
        "WHERE v.provenance_id = t.provenance_id "
        "AND v.provenance_version = t.provenance_version "
        "AND v.state = 'ACTIVE')",
        (_CasColumn("artifact_sha256"),),
        (("case_provenance", "provenance_id"),),
        (
            (
                "case",
                "SELECT case_id FROM case_versions "
                "WHERE provenance_id = ? AND provenance_version = ? "
                "AND state = 'ACTIVE'",
                ("provenance_id", "provenance_version"),
            ),
        ),
    ),
    "case_patterns": _AuthorityRule(
        ("pattern_id", "version"),
        ("version", "provenance_version"),
        "WHERE t.state = 'ACTIVE'",
        (
            _CasColumn(
                "global_content_sha256",
                "global_content_ref",
                "global_content_size_bytes",
            ),
        ),
        (
            ("case_pattern", "pattern_id"),
            ("case_provenance", "provenance_id"),
        ),
    ),
    "case_regeneration_proofs": _AuthorityRule(
        ("proof_id", "proof_version"),
        ("proof_version",),
        "",
        tombstone_identities=(("case_regeneration_proof", "proof_id"),),
    ),
    "case_leave_one_out_variants": _AuthorityRule(
        ("mapping_id", "mapping_version"),
        (
            "mapping_version",
            "parent_version",
            "variant_version",
            "content_version",
            "provenance_version",
            "regeneration_proof_version",
        ),
        "WHERE t.state = 'ACTIVE' AND t.review_status = 'approved'",
        (_CasColumn("content_sha256"),),
        (
            ("case_leave_one_out", "mapping_id"),
            ("case_leave_one_out_variant", "mapping_id"),
            ("case_pattern", "parent_object_id"),
            ("case_pattern", "variant_object_id"),
            ("case_provenance", "provenance_id"),
            ("case_regeneration_proof", "regeneration_proof_id"),
        ),
    ),
}


_CLIENT_AUTHORITY_RULES: dict[str, _AuthorityRule] = {
    "fact_events": _AuthorityRule(
        ("event_id",),
        ("event_version", "commit_version", "visible_runtime_epoch"),
        "WHERE t.review_status = 'approved' AND t.validity_status <> 'invalidated'",
        tombstone_identities=(("fact_event", "event_id"),),
    ),
    "fact_evidence": _AuthorityRule(
        ("event_id", "evidence_id"),
        (),
        "WHERE EXISTS (SELECT 1 FROM fact_events AS e WHERE e.event_id = t.event_id "
        "AND e.review_status = 'approved' AND e.validity_status <> 'invalidated')",
        tombstone_identities=(("fact_event", "event_id"),),
    ),
    "fact_dependencies": _AuthorityRule(
        ("edge_id",),
        ("created_commit_version",),
        "WHERE EXISTS (SELECT 1 FROM fact_events AS e "
        "WHERE e.event_id = t.source_event_id AND e.review_status = 'approved' "
        "AND e.validity_status <> 'invalidated')",
        tombstone_identities=(
            ("fact_dependency", "edge_id"),
            ("fact_event", "source_event_id"),
        ),
    ),
    "fact_merge_members": _AuthorityRule(
        ("projection_event_id", "member_event_id"),
        ("ordinal",),
        "WHERE EXISTS (SELECT 1 FROM fact_events AS e "
        "WHERE e.event_id = t.projection_event_id AND e.review_status = 'approved' "
        "AND e.validity_status <> 'invalidated') AND EXISTS "
        "(SELECT 1 FROM fact_events AS m WHERE m.event_id = t.member_event_id "
        "AND m.review_status = 'approved' AND m.validity_status <> 'invalidated')",
        tombstone_identities=(
            ("fact_event", "projection_event_id"),
            ("fact_event", "member_event_id"),
        ),
    ),
    "review_decisions": _AuthorityRule(
        ("decision_id",),
        (),
        "WHERE t.decision = 'APPROVED'",
    ),
    "archive_bundles": _AuthorityRule(
        ("bundle_id",),
        ("actual_transcript_version",),
        "WHERE EXISTS (SELECT 1 FROM archive_purpose_states AS s "
        "WHERE s.bundle_id = t.bundle_id AND s.purpose = 'private_archive' "
        "AND s.state = 'ACTIVE')",
        (
            _CasColumn(
                "actual_transcript_sha256",
                size_column="actual_transcript_size_bytes",
            ),
        ),
        (
            ("archive_bundle", "bundle_id"),
            ("session", "session_id"),
        ),
    ),
    "archive_purpose_states": _AuthorityRule(
        ("bundle_id", "purpose"),
        (),
        "WHERE t.state = 'ACTIVE'",
        tombstone_identities=(("archive_bundle", "bundle_id"),),
    ),
    "private_archive_revisions": _AuthorityRule(
        ("revision_id",),
        ("revision",),
        "WHERE t.state = 'ACTIVE'",
        (
            _CasColumn("draft_sha256", size_column="draft_size_bytes"),
            _CasColumn("actual_transcript_sha256"),
        ),
        (
            ("private_archive_revision", "revision_id"),
            ("archive_bundle", "bundle_id"),
        ),
    ),
    "profile_revisions": _AuthorityRule(
        ("revision_id",),
        ("source_commit_version", "visible_runtime_epoch"),
        "",
        tombstone_identities=(("profile_revision", "revision_id"),),
    ),
    "profile_members": _AuthorityRule(
        ("revision_id", "ordinal"),
        ("ordinal",),
        "",
        tombstone_identities=(
            ("profile_revision", "revision_id"),
            ("fact_event", "event_id"),
        ),
    ),
}


_AUTHORITY_RULES: dict[DatabaseScope, Mapping[str, _AuthorityRule]] = {
    "global": _GLOBAL_AUTHORITY_RULES,
    "client": _CLIENT_AUTHORITY_RULES,
}


def _json_compatible(value: object) -> object:
    if value is None or type(value) in {str, int, float}:
        return value
    if type(value) is bytes:
        return {"base64": base64.b64encode(value).decode("ascii")}
    raise RebuildCoordinatorError("REBUILD_AUTHORITY_SQL_VALUE_INVALID")


class SqliteRebuildAuthoritySource:
    """Production reader for the fixed v1-v6 authority allowlist and scoped CAS."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        content_store: ContentStore,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("REBUILD_SCOPED_SQLITE_CONNECTION_REQUIRED")
        if database_scope not in {"global", "client"}:
            raise ValueError("REBUILD_DATABASE_SCOPE_INVALID")
        if _SHA256.fullmatch(scope_sha256) is None:
            raise ValueError("REBUILD_SCOPE_HASH_INVALID")
        if not isinstance(content_store, ContentStore):
            raise TypeError("REBUILD_CONTENT_STORE_REQUIRED")
        self._connection = connection
        self._database_scope = database_scope
        self._scope_sha256 = scope_sha256
        self._content_store = content_store

    def inventory(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory:
        exact_sources = self._validate_request(database_scope, scope_sha256, sources)
        epoch, records = self._read_snapshot(exact_sources)
        return AuthorityInventory.create(
            database_scope=self._database_scope,
            scope_sha256=self._scope_sha256,
            tombstone_epoch=epoch,
            versions=tuple(
                AuthorityVersionRef(
                    source=source,
                    version=max(
                        (record.version for record in records[source.key]),
                        default=0,
                    ),
                    snapshot_sha256=authority_source_snapshot_sha256(
                        source, records[source.key]
                    ),
                )
                for source in exact_sources
            ),
        )

    def resolve_exact(
        self,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        input_authority_versions_sha256: str,
        tombstone_epoch: int,
        sources: Sequence[AuthoritySourceSpec],
    ) -> AuthorityInventory:
        current = self.inventory(
            database_scope=database_scope,
            scope_sha256=scope_sha256,
            sources=sources,
        )
        if (
            current.input_authority_versions_sha256
            != input_authority_versions_sha256
            or current.tombstone_epoch != tombstone_epoch
        ):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_SNAPSHOT_CHANGED")
        return current

    def read_exact(
        self, inventory: AuthorityInventory
    ) -> Mapping[str, Sequence[AuthorityRecord]]:
        exact = AuthorityInventory.model_validate(inventory)
        sources = self._validate_request(
            exact.database_scope,
            exact.scope_sha256,
            tuple(value.source for value in exact.versions),
        )
        epoch, records = self._read_snapshot(sources)
        if epoch != exact.tombstone_epoch:
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_SNAPSHOT_CHANGED")
        expected = {value.source.key: value for value in exact.versions}
        for source in sources:
            if (
                authority_source_snapshot_sha256(source, records[source.key])
                != expected[source.key].snapshot_sha256
            ):
                raise RebuildCoordinatorError(
                    "REBUILD_AUTHORITY_SOURCE_HASH_MISMATCH"
                )
        return records

    def current_tombstone_epoch(
        self, *, database_scope: DatabaseScope, scope_sha256: str
    ) -> int:
        self._validate_request(database_scope, scope_sha256, ())
        return self._read_epoch(self._connection)

    def _validate_request(
        self,
        database_scope: DatabaseScope,
        scope_sha256: str,
        sources: Sequence[AuthoritySourceSpec],
    ) -> tuple[AuthoritySourceSpec, ...]:
        if (
            database_scope != self._database_scope
            or scope_sha256 != self._scope_sha256
        ):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_SCOPE_MISMATCH")
        exact = tuple(sorted(sources, key=lambda value: value.key))
        keys = tuple(source.key for source in exact)
        if len(set(keys)) != len(keys):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_SOURCE_DUPLICATE")
        rules = _AUTHORITY_RULES[self._database_scope]
        for source in exact:
            if (
                source.database_scope != self._database_scope
                or source.table
                not in AUTHORITY_TABLE_ALLOWLIST[self._database_scope]
                or source.table not in rules
            ):
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_SOURCE_FORBIDDEN")
        return exact

    def _read_snapshot(
        self, sources: tuple[AuthoritySourceSpec, ...]
    ) -> tuple[int, dict[str, tuple[AuthorityRecord, ...]]]:
        read_context = (
            nullcontext(self._connection)
            if self._connection.in_transaction
            else transaction(self._connection, immediate=False)
        )
        with read_context:
            epoch = self._read_epoch(self._connection)
            direct, lineage = self._read_tombstones(self._connection)
            records = {
                source.key: self._read_source(
                    self._connection, source, direct, lineage
                )
                for source in sources
            }
            return epoch, self._apply_referential_closure(records)

    @staticmethod
    def _read_epoch(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT tombstone_epoch FROM deletion_authority_state "
            "WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_INVALID")
        return int(row[0])

    @staticmethod
    def _read_tombstones(
        connection: sqlite3.Connection,
    ) -> tuple[set[tuple[str, str]], set[str]]:
        rows = connection.execute(
            "SELECT target_type, target_id_hash, source_lineage_hash FROM tombstones"
        ).fetchall()
        return (
            {(str(row[0]), str(row[1])) for row in rows},
            {str(row[2]) for row in rows if str(row[2])},
        )

    def _read_source(
        self,
        connection: sqlite3.Connection,
        source: AuthoritySourceSpec,
        direct_tombstones: set[tuple[str, str]],
        lineage_tombstones: set[str],
    ) -> tuple[AuthorityRecord, ...]:
        rule = _AUTHORITY_RULES[self._database_scope][source.table]
        try:
            cursor = connection.execute(
                f'SELECT t.* FROM "{source.table}" AS t {rule.where_sql}'
            )
            columns = tuple(str(value[0]) for value in cursor.description)
            rows = tuple(
                dict(zip(columns, raw, strict=True)) for raw in cursor.fetchall()
            )
        except sqlite3.DatabaseError as exc:
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_SCHEMA_INVALID") from exc
        records: list[AuthorityRecord] = []
        for row in rows:
            keys = set(row.keys())
            required = set(rule.identity_columns) | set(rule.version_columns)
            for cas in rule.cas_columns:
                required.update(
                    value
                    for value in (
                        cas.digest_column,
                        cas.reference_column,
                        cas.size_column,
                    )
                    if value is not None
                )
            if not required <= keys:
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_SCHEMA_INVALID")
            if self._row_tombstoned(
                connection,
                row,
                rule,
                direct_tombstones,
                lineage_tombstones,
            ):
                continue
            row_body = {key: _json_compatible(row[key]) for key in sorted(keys)}
            content_objects = tuple(
                value
                for cas in rule.cas_columns
                if (value := self._read_cas(row, cas)) is not None
            )
            payload = canonical_json_bytes(
                {
                    "domain": "consultation_kb.rebuild_authority_record.v1",
                    "source": source.model_dump(mode="json"),
                    "row": row_body,
                    "content_objects": content_objects,
                }
            )
            identity = canonical_sha256(
                {
                    "table": source.table,
                    "identity": [
                        _json_compatible(row[column])
                        for column in rule.identity_columns
                    ],
                }
            )
            versions = [
                int(row[column])
                for column in rule.version_columns
                if type(row[column]) is int and int(row[column]) >= 0
            ]
            records.append(
                AuthorityRecord(
                    source=source,
                    object_id=identity,
                    version=max(versions, default=1),
                    content_sha256=hashlib.sha256(payload).hexdigest(),
                    payload=payload,
                    approved=True,
                    tombstoned=False,
                    active=True,
                )
            )
        return tuple(
            sorted(
                records,
                key=lambda value: (
                    value.object_id,
                    value.version,
                    value.content_sha256,
                ),
            )
        )

    def _apply_referential_closure(
        self,
        records: Mapping[str, Sequence[AuthorityRecord]],
    ) -> dict[str, tuple[AuthorityRecord, ...]]:
        """Remove relation rows whose selected authority endpoint is absent.

        SQL foreign keys only prove that a historical parent row exists.  They do
        not prove that the parent survived the active/approved/tombstone filters
        used by this exact rebuild snapshot.  The fixed-point pass therefore
        closes the selected subgraph after all row-level tombstone checks.
        """

        current = {key: tuple(value) for key, value in records.items()}
        while True:
            decoded = {
                key: tuple((record, self._authority_row(record)) for record in value)
                for key, value in current.items()
            }

            def present(table: str) -> bool:
                return f"{self._database_scope}.{table}" in decoded

            def rows(table: str) -> tuple[tuple[AuthorityRecord, dict[str, object]], ...]:
                return decoded.get(f"{self._database_scope}.{table}", ())

            def keys(table: str, *columns: str) -> set[tuple[object, ...]]:
                return {
                    tuple(row[column] for column in columns)
                    for _, row in rows(table)
                }

            predicates: dict[str, Callable[[Mapping[str, object]], bool]] = {}
            if self._database_scope == "global":
                if present("source_versions"):
                    source_versions = keys("source_versions", "source_id", "version")
                    predicates["sources"] = lambda row: (
                        row["source_id"], row["current_version"]
                    ) in source_versions
                if present("sources"):
                    source_ids = keys("sources", "source_id")
                    predicates["source_versions"] = lambda row: (
                        row["source_id"],
                    ) in source_ids
                if present("source_versions"):
                    source_versions = keys("source_versions", "source_id", "version")
                    predicates["passages"] = lambda row: (
                        row["source_id"], row["source_version"]
                    ) in source_versions
                    predicates["theory_revisions"] = lambda row: (
                        row["source_id"], row["source_version"]
                    ) in source_versions
                if present("claims") and present("passages"):
                    claims = keys("claims", "claim_id", "version")
                    passages = keys("passages", "passage_id", "version")
                    predicates["claim_evidence"] = lambda row: (
                        (row["claim_id"], row["claim_version"]) in claims
                        and (row["passage_id"], row["passage_version"]) in passages
                    )
                if present("theory_revisions") and present("passages"):
                    theories = keys("theory_revisions", "theory_id", "revision")
                    passages = keys("passages", "passage_id", "version")
                    predicates["theory_revision_passages"] = lambda row: (
                        (row["theory_id"], row["theory_revision"]) in theories
                        and (row["passage_id"], row["passage_version"]) in passages
                    )
                if present("scope_policy_versions"):
                    scope_policies = keys(
                        "scope_policy_versions", "policy_id", "version"
                    )
                    predicates["scope_policy_approval_bindings"] = lambda row: (
                        row["policy_id"], row["version"]
                    ) in scope_policies
                if present("wiki_revisions") and present("claims"):
                    wikis = keys("wiki_revisions", "wiki_id", "revision")
                    claims = keys("claims", "claim_id", "version")
                    predicates["wiki_revision_claims"] = lambda row: (
                        (row["wiki_id"], row["wiki_revision"]) in wikis
                        and (row["claim_id"], row["claim_version"]) in claims
                    )
                if present("cases"):
                    cases = keys("cases", "case_id", "current_version")
                    predicates["case_versions"] = lambda row: (
                        row["case_id"], row["version"]
                    ) in cases
                if present("case_versions"):
                    case_versions = keys("case_versions", "case_id", "version")
                    provenances = keys(
                        "case_versions", "provenance_id", "provenance_version"
                    )
                    predicates["case_authorizations"] = lambda row: (
                        row["case_id"], row["case_version"]
                    ) in case_versions
                    predicates["case_review_decisions"] = lambda row: (
                        row["case_id"], row["case_version"]
                    ) in case_versions
                    predicates["case_provenance"] = lambda row: (
                        row["provenance_id"], row["provenance_version"]
                    ) in provenances
                if present("case_provenance"):
                    provenances = keys(
                        "case_provenance", "provenance_id", "provenance_version"
                    )
                    predicates["case_patterns"] = lambda row: (
                        row["provenance_id"], row["provenance_version"]
                    ) in provenances
                if present("case_patterns"):
                    patterns = keys("case_patterns", "pattern_id", "version")
                    predicates["case_leave_one_out_variants"] = lambda row: (
                        row["parent_object_id"], row["parent_version"]
                    ) in patterns
                if present("case_regeneration_proofs"):
                    proofs = keys(
                        "case_regeneration_proofs", "proof_id", "proof_version"
                    )
                    existing = predicates.get("case_leave_one_out_variants")

                    def has_exact_proof(
                        row: Mapping[str, object],
                        prior: Callable[[Mapping[str, object]], bool] | None = existing,
                    ) -> bool:
                        return (
                            (prior is None or prior(row))
                            and (
                                row["regeneration_proof_id"],
                                row["regeneration_proof_version"],
                            )
                            in proofs
                        )

                    predicates["case_leave_one_out_variants"] = has_exact_proof
                if present("case_leave_one_out_variants"):
                    referenced_proofs = keys(
                        "case_leave_one_out_variants",
                        "regeneration_proof_id",
                        "regeneration_proof_version",
                    )
                    predicates["case_regeneration_proofs"] = lambda row: (
                        row["proof_id"], row["proof_version"]
                    ) in referenced_proofs
            else:
                if present("fact_events"):
                    event_ids = keys("fact_events", "event_id")
                    fact_ids = keys("fact_events", "fact_id")
                    predicates["fact_evidence"] = lambda row: (
                        row["event_id"],
                    ) in event_ids
                    predicates["fact_dependencies"] = lambda row: (
                        (row["source_event_id"],) in event_ids
                        and (row["dependent_fact_id"],) in fact_ids
                        and (row["prerequisite_fact_id"],) in fact_ids
                    )
                    predicates["fact_merge_members"] = lambda row: (
                        (row["projection_event_id"],) in event_ids
                        and (row["member_event_id"],) in event_ids
                    )
                if present("profile_revisions") and present("fact_events"):
                    revisions = keys("profile_revisions", "revision_id")
                    event_ids = keys("fact_events", "event_id")
                    predicates["profile_members"] = lambda row: (
                        (row["revision_id"],) in revisions
                        and (row["event_id"],) in event_ids
                    )
                if present("archive_bundles"):
                    bundle_ids = keys("archive_bundles", "bundle_id")
                    predicates["archive_purpose_states"] = lambda row: (
                        row["bundle_id"],
                    ) in bundle_ids
                    predicates["private_archive_revisions"] = lambda row: (
                        row["bundle_id"],
                    ) in bundle_ids

            updated = dict(current)
            for table, predicate in predicates.items():
                key = f"{self._database_scope}.{table}"
                if key not in decoded:
                    continue
                updated[key] = tuple(
                    record for record, row in decoded[key] if predicate(row)
                )
            if updated == current:
                return updated
            current = updated

    @staticmethod
    def _authority_row(record: AuthorityRecord) -> dict[str, object]:
        try:
            payload = json.loads(record.payload)
            row = payload["row"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RebuildCoordinatorError(
                "REBUILD_AUTHORITY_RECORD_INVALID"
            ) from exc
        if not isinstance(row, dict) or any(type(key) is not str for key in row):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_RECORD_INVALID")
        return cast(dict[str, object], row)

    @staticmethod
    def _row_tombstoned(
        connection: sqlite3.Connection,
        row: Mapping[str, object],
        rule: _AuthorityRule,
        direct_tombstones: set[tuple[str, str]],
        lineage_tombstones: set[str],
    ) -> bool:
        identities: list[tuple[str, str]] = []
        for object_type, column in rule.tombstone_identities:
            raw = row[column]
            if raw is None:
                continue
            if type(raw) is not str or not raw:
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_SCHEMA_INVALID")
            identities.append((object_type, raw))
        for object_type, sql, parameter_columns in rule.tombstone_lookup:
            parameters = tuple(row[column] for column in parameter_columns)
            try:
                linked_rows = connection.execute(sql, parameters).fetchall()
            except sqlite3.DatabaseError as exc:
                raise RebuildCoordinatorError(
                    "REBUILD_AUTHORITY_SCHEMA_INVALID"
                ) from exc
            for linked_row in linked_rows:
                raw = linked_row[0]
                if type(raw) is not str or not raw:
                    raise RebuildCoordinatorError(
                        "REBUILD_AUTHORITY_SCHEMA_INVALID"
                    )
                identities.append((object_type, raw))
        return any(
            (object_type, target_hash(object_type, object_id)) in direct_tombstones
            or lineage_hash(object_type, object_id) in lineage_tombstones
            for object_type, object_id in identities
        )

    def _read_cas(
        self, row: Mapping[str, object], binding: _CasColumn
    ) -> dict[str, object] | None:
        reference = (
            None
            if binding.reference_column is None
            else row[binding.reference_column]
        )
        digest_value = (
            None if binding.digest_column is None else row[binding.digest_column]
        )
        if reference is None and digest_value is None:
            if binding.optional:
                return None
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_REF_INVALID")
        digest: str
        if digest_value is not None:
            digest = str(digest_value)
            if _SHA256.fullmatch(digest) is None:
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_REF_INVALID")
            if reference is not None and str(reference) != f"sha256:{digest}":
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_REF_INVALID")
        else:
            reference_text = str(reference)
            if not reference_text.startswith("sha256:"):
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_REF_INVALID")
            digest = reference_text[7:]
            if _SHA256.fullmatch(digest) is None:
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_REF_INVALID")
        payload = self._content_store.read_hash_verified(digest)
        if binding.size_column is not None:
            size_value = row[binding.size_column]
            if type(size_value) is not int or int(size_value) != len(payload):
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_CAS_SIZE_MISMATCH")
        return {
            "column": binding.reference_column or binding.digest_column,
            "content_sha256": digest,
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        }


class ArtifactBuilder(Protocol):
    descriptor: BuilderDescriptor

    def build(self, context: BuildContext) -> BuiltArtifact: ...


class RebuildArtifactStore(Protocol):
    """Empty-target staging plus closure verification and one atomic switch."""

    def begin_empty_stage(
        self,
        *,
        job_id: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> str: ...

    def stage_artifact(self, *, stage_ref: str, artifact: BuiltArtifact) -> None: ...

    def verify_stage(
        self,
        *,
        stage_ref: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> "StageVerification": ...

    def activate_atomically(
        self,
        *,
        stage_ref: str,
        output_manifest_set_sha256: str,
        tombstone_epoch: int,
    ) -> "ActivationReceipt": ...

    def resume_stage(self, *, job_id: str) -> str: ...

    def discard_stage(self, *, stage_ref: str) -> None: ...


def output_manifest_set_sha256(
    artifacts: Sequence[BuiltArtifact],
) -> str:
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_output_manifest_set.v1",
            "artifacts": [
                {
                    "builder_id": artifact.builder_id,
                    "output_purpose": artifact.output_purpose,
                    "version": artifact.version,
                    "content_sha256": artifact.content_sha256,
                    "semantic_fingerprint_sha256": (
                        artifact.semantic_fingerprint_sha256
                    ),
                }
                for artifact in sorted(
                    artifacts, key=lambda value: value.output_purpose
                )
            ],
        }
    )


class StageVerification(StrictModel):
    output_manifest_set_sha256: Sha256Hex
    artifact_count: NonNegativeInt
    closure_valid: bool
    equivalence_report: EquivalenceReport

    @classmethod
    def create(
        cls,
        *,
        artifacts: tuple[BuiltArtifact, ...],
        equivalence_report: EquivalenceReport,
    ) -> "StageVerification":
        return cls(
            output_manifest_set_sha256=output_manifest_set_sha256(artifacts),
            artifact_count=len(artifacts),
            closure_valid=True,
            equivalence_report=equivalence_report,
        )


class ActivationReceipt(StrictModel):
    output_manifest_set_sha256: Sha256Hex
    tombstone_epoch: NonNegativeInt
    already_active: bool


@dataclass(frozen=True, slots=True)
class _StageRegistration:
    operation_id: str
    job_id: str
    output_purposes: tuple[str, ...]
    manifest_by_purpose: Mapping[str, str]
    tombstone_epoch: int
    expected_current_epoch: int | None


@dataclass(frozen=True, slots=True)
class _StageOperation:
    operation_id: str
    job_id: str
    plan_sha256: str
    approval_request_id: str
    attempt_count: int
    descriptor_sha256: str
    state: str
    required_manifest_ids: tuple[str, ...]
    authority_base_version: int
    expected_current_epoch: int | None
    runtime_epoch: int | None
    tombstone_epoch: int


@dataclass(frozen=True, slots=True)
class _ActivationAuthority:
    job_id: str
    plan_sha256: str
    approval_request_id: str
    scope_sha256: str
    tombstone_epoch: int
    attempt_count: int


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("rebuild clock must return timezone-aware UTC")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stage_descriptor_sha256(
    *,
    database_scope: DatabaseScope,
    scope_sha256: str,
    job_id: str,
    plan_sha256: str,
    tombstone_epoch: int,
    expected_current_epoch: int | None,
    manifest_by_purpose: Mapping[str, str],
) -> str:
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_durable_stage.v1",
            "database_scope": database_scope,
            "scope_sha256": scope_sha256,
            "job_id": job_id,
            "plan_sha256": plan_sha256,
            "tombstone_epoch": tombstone_epoch,
            "expected_current_epoch": expected_current_epoch,
            "manifests": [
                {"output_purpose": key, "manifest_id": manifest_by_purpose[key]}
                for key in sorted(manifest_by_purpose)
            ],
        }
    )


class SqliteCasRebuildArtifactStore:
    """Durable CAS staging and one-transaction SQLite manifest-set activation."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        content_store: ContentStore,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if database_scope not in {"global", "client"}:
            raise ValueError("REBUILD_DATABASE_SCOPE_INVALID")
        if _SHA256.fullmatch(scope_sha256) is None:
            raise ValueError("REBUILD_SCOPE_HASH_INVALID")
        if not isinstance(content_store, ContentStore):
            raise TypeError("REBUILD_CONTENT_STORE_REQUIRED")
        self._connection = connection
        self._database_scope = database_scope
        self._scope_sha256 = scope_sha256
        self._content_store = content_store
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory()
        self._manifests = ManifestRepository(connection)
        self._registrations: dict[str, _StageRegistration] = {}
        self._staged_purposes: dict[str, set[str]] = {}
        required = {
            "publication_operations",
            "runtime_epochs",
            "artifact_manifests",
            "artifact_members",
            "active_artifacts",
            "deletion_authority_state",
            "rebuild_stage_bindings",
            "rebuild_structured_artifacts",
        }
        actual = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if not required <= actual:
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_SCHEMA_INVALID")

    def _publication_authority_version(
        self,
        tombstone_epoch: int,
        *,
        job_id: str,
    ) -> int:
        """Bind manifests to the real scoped authority, not deletion count.

        Legacy/generic tests may intentionally have an empty authority ledger;
        they retain the historical tombstone+1 spelling.  A populated
        production scope always uses its catalog/commit version so existing
        integrity consumers can verify the rebuilt active epoch.
        """

        del job_id
        if self._database_scope == "global":
            row = self._connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
        else:
            row = self._connection.execute(
                "SELECT commit_version FROM client_fact_authority "
                "WHERE singleton = 1"
            ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_VERSION_INVALID")
        value = int(row[0])
        return tombstone_epoch + 1 if value == 0 else value

    def _before_manifest_activation(self, operation: _StageOperation) -> None:
        del operation

    def begin_empty_stage(
        self,
        *,
        job_id: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> str:
        purposes = tuple(output_purposes)
        if (
            not purposes
            or len(set(purposes)) != len(purposes)
            or any(_SAFE_KEY.fullmatch(value) is None for value in purposes)
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_OUTPUTS_INVALID")
        if type(tombstone_epoch) is not int or tombstone_epoch < 0:
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_INVALID")
        now = _utc_text(self._clock.now())
        with transaction(self._connection):
            authority = self._assert_activation_authority(
                job_id,
                tombstone_epoch=tombstone_epoch,
                allowed_job_states=("running",),
            )
            operation_id = self._ids.object_id("rebuild_operation")
            manifest_by_purpose = {
                purpose: rebuild_manifest_id(
                    job_id=job_id,
                    attempt_count=authority.attempt_count,
                    output_purpose=purpose,
                )
                for purpose in purposes
            }
            required_ids = tuple(sorted(manifest_by_purpose.values()))
            active_rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchall()
            if len(active_rows) > 1:
                raise RebuildCoordinatorError("REBUILD_ACTIVE_EPOCH_INVALID")
            expected_epoch = (
                None if not active_rows else int(active_rows[0][0])
            )
            authority_base_version = self._publication_authority_version(
                tombstone_epoch,
                job_id=job_id,
            )
            self._connection.execute(
                """
                UPDATE publication_operations SET state = 'FAILED'
                 WHERE purpose = 'rebuild'
                   AND state IN ('PREPARED', 'VERIFIED')
                   AND operation_id IN (
                       SELECT operation_id FROM rebuild_stage_bindings
                        WHERE job_id = ?
                   )
                """,
                (job_id,),
            )
            descriptor_sha256 = _stage_descriptor_sha256(
                database_scope=self._database_scope,
                scope_sha256=self._scope_sha256,
                job_id=job_id,
                plan_sha256=authority.plan_sha256,
                tombstone_epoch=tombstone_epoch,
                expected_current_epoch=expected_epoch,
                manifest_by_purpose=manifest_by_purpose,
            )
            self._connection.execute(
                """
                INSERT INTO publication_operations(
                    operation_id, purpose, authority_base_version,
                    approval_request_id, descriptor_sha256, state,
                    required_manifests_json, required_manifest_count,
                    verified_manifest_count, expected_current_epoch,
                    runtime_epoch, created_at, activated_at
                ) VALUES (?, 'rebuild', ?, ?, ?, 'PREPARED', ?, ?, 0, ?,
                          NULL, ?, NULL)
                """,
                (
                    operation_id,
                    authority_base_version,
                    authority.approval_request_id,
                    descriptor_sha256,
                    json.dumps(required_ids, ensure_ascii=True, separators=(",", ":")),
                    len(required_ids),
                    expected_epoch,
                    now,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO rebuild_stage_bindings(
                    operation_id, job_id, attempt_count, approval_request_id,
                    plan_sha256, scope_sha256, tombstone_epoch, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    job_id,
                    authority.attempt_count,
                    authority.approval_request_id,
                    authority.plan_sha256,
                    authority.scope_sha256,
                    authority.tombstone_epoch,
                    now,
                ),
            )
        registration = _StageRegistration(
            operation_id=operation_id,
            job_id=job_id,
            output_purposes=purposes,
            manifest_by_purpose=manifest_by_purpose,
            tombstone_epoch=tombstone_epoch,
            expected_current_epoch=expected_epoch,
        )
        self._registrations[operation_id] = registration
        self._staged_purposes[operation_id] = set()
        return operation_id

    def stage_artifact(self, *, stage_ref: str, artifact: BuiltArtifact) -> None:
        if not isinstance(artifact, BuiltArtifact) or artifact.version <= 0:
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_INVALID")
        registration = self._registrations.get(stage_ref)
        if registration is None:
            raise RebuildCoordinatorError("REBUILD_STAGE_NOT_FOUND")
        purpose = artifact.output_purpose
        if (
            purpose not in registration.manifest_by_purpose
            or purpose in self._staged_purposes[stage_ref]
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_ARTIFACT_CONFLICT")
        manifest_id = registration.manifest_by_purpose[purpose]
        structured = parse_structured_artifact(artifact.payload)
        if structured is not None:
            self._stage_structured_artifact(
                stage_ref=stage_ref,
                manifest_id=manifest_id,
                artifact=artifact,
                structured=structured,
            )
            self._staged_purposes[stage_ref].add(purpose)
            return
        metadata = canonical_json_bytes(
            {
                "domain": "consultation_kb.rebuild_staged_artifact.v1",
                "builder_id": artifact.builder_id,
                "output_purpose": purpose,
                "version": artifact.version,
                "content_sha256": artifact.content_sha256,
                "semantic_fingerprint_sha256": (
                    artifact.semantic_fingerprint_sha256
                ),
                "size_bytes": len(artifact.payload),
            }
        )
        payload_ref = self._content_store.finalize(
            self._content_store.stage_bytes(
                artifact.payload,
                purpose="rebuild_artifact",
                manifest_id=manifest_id,
                media_type="application/octet-stream",
            )
        )
        metadata_ref = self._content_store.finalize(
            self._content_store.stage_bytes(
                metadata,
                purpose="rebuild_metadata",
                manifest_id=manifest_id,
                media_type="application/json",
            )
        )
        lineage = tuple(
            sorted(
                {
                    artifact.content_sha256,
                    artifact.semantic_fingerprint_sha256,
                }
            )
        )
        members = (
            ManifestMember(
                ordinal=0,
                object_type="rebuild_artifact",
                object_id=self._ids.object_id("rebuild_artifact"),
                object_sha256=payload_ref.content_sha256,
                source_version=artifact.version,
                media_type=payload_ref.media_type,
                size_bytes=payload_ref.size_bytes,
                source_lineage_hashes=lineage,
            ),
            ManifestMember(
                ordinal=1,
                object_type="rebuild_metadata",
                object_id=self._ids.object_id("rebuild_metadata"),
                object_sha256=metadata_ref.content_sha256,
                source_version=artifact.version,
                media_type=metadata_ref.media_type,
                size_bytes=metadata_ref.size_bytes,
                source_lineage_hashes=lineage,
            ),
        )
        self._manifests.insert_prepared(
            manifest_id=manifest_id,
            operation_id=registration.operation_id,
            artifact_key=purpose,
            artifact_kind="rebuild_artifact",
            source_version=artifact.version,
            members=members,
            created_at=_utc_text(self._clock.now()),
        )
        self._staged_purposes[stage_ref].add(purpose)

    def _stage_structured_artifact(
        self,
        *,
        stage_ref: str,
        manifest_id: str,
        artifact: BuiltArtifact,
        structured: StructuredArtifactEnvelope,
    ) -> None:
        if (
            structured.artifact_key != artifact.output_purpose
            or structured.source_version != artifact.version
            or artifact.builder_id != structured.artifact_key
            or artifact.comparison_content_sha256
            != structured.comparison_content_sha256
            or artifact.semantic_fingerprint_sha256
            != structured.semantic_fingerprint_sha256
        ):
            raise RebuildCoordinatorError("REBUILD_STRUCTURED_ARTIFACT_INVALID")
        members: list[ManifestMember] = []
        for ordinal, member in enumerate(structured.members):
            reference = self._content_store.finalize(
                self._content_store.stage_bytes(
                    member.payload,
                    purpose="rebuild_artifact",
                    manifest_id=manifest_id,
                    media_type=member.media_type,
                )
            )
            members.append(
                ManifestMember(
                    ordinal=ordinal,
                    object_type=member.role,
                    object_id=(
                        self._ids.object_id(member.role)
                        if member.object_id is None
                        else member.object_id
                    ),
                    object_sha256=reference.content_sha256,
                    source_version=artifact.version,
                    media_type=member.media_type,
                    size_bytes=reference.size_bytes,
                    source_lineage_hashes=member.source_lineage_hashes,
                )
            )
        self._manifests.insert_prepared(
            manifest_id=manifest_id,
            operation_id=stage_ref,
            artifact_key=structured.artifact_key,
            artifact_kind=structured.artifact_kind,
            source_version=artifact.version,
            members=tuple(members),
            created_at=_utc_text(self._clock.now()),
        )
        comparisons = json.dumps(
            [
                {
                    "ordinal": ordinal,
                    "role": member.role,
                    "object_id": member.object_id,
                    "comparison_sha256": member.comparison_sha256,
                }
                for ordinal, member in enumerate(structured.members)
            ],
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._connection.execute(
            "INSERT INTO rebuild_structured_artifacts("
            "manifest_id, artifact_key, artifact_kind, source_version, "
            "semantic_basis_sha256, member_comparisons_json, envelope_sha256"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                manifest_id,
                structured.artifact_key,
                structured.artifact_kind,
                structured.source_version,
                structured.semantic_basis_sha256,
                comparisons,
                artifact.content_sha256,
            ),
        )

    def verify_stage(
        self,
        *,
        stage_ref: str,
        output_purposes: Sequence[str],
        tombstone_epoch: int,
    ) -> StageVerification:
        purposes = tuple(output_purposes)
        operation = self._load_operation(stage_ref)
        if operation.state != "PREPARED":
            raise RebuildCoordinatorError("REBUILD_STAGE_NOT_PREPARED")
        manifests = self._load_complete_manifest_set(operation, purposes)
        self._validate_stage_descriptor(operation, manifests)
        if operation.tombstone_epoch != tombstone_epoch:
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
        artifacts = tuple(self._artifact_from_manifest(value) for value in manifests)
        before = self._active_fingerprints(
            output_purposes=tuple(value.artifact_key for value in manifests),
            epoch=operation.expected_current_epoch,
        )
        after = tuple(artifact.fingerprint for artifact in artifacts)
        report = compare_artifact_sets(before, after)
        report_payload = equivalence_report_bytes(report)
        report_ref = self._content_store.finalize(
            self._content_store.stage_bytes(
                report_payload,
                purpose="rebuild_report",
                manifest_id=operation.operation_id,
                media_type="application/json",
            )
        )
        if report_ref.content_sha256 != report.report_sha256:
            raise RebuildCoordinatorError("REBUILD_EQUIVALENCE_REPORT_HASH_MISMATCH")
        now = _utc_text(self._clock.now())
        with transaction(self._connection):
            self._assert_activation_authority(
                operation.job_id,
                tombstone_epoch=tombstone_epoch,
                allowed_job_states=("verifying",),
            )
            current_epoch = self._read_tombstone_epoch()
            if current_epoch != tombstone_epoch:
                raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
            row = self._connection.execute(
                "SELECT state FROM publication_operations WHERE operation_id = ?",
                (operation.operation_id,),
            ).fetchone()
            if row != ("PREPARED",):
                raise RebuildCoordinatorError("REBUILD_STAGE_NOT_PREPARED")
            for manifest in manifests:
                self._manifests.mark_verified(
                    manifest.manifest_id,
                    expected_source_version=manifest.source_version,
                    verified_at=now,
                )
            changed = self._connection.execute(
                """
                UPDATE publication_operations
                   SET state = 'VERIFIED', verified_manifest_count = ?
                 WHERE operation_id = ? AND state = 'PREPARED'
                   AND verified_manifest_count = 0
                """,
                (len(manifests), operation.operation_id),
            ).rowcount
            if changed != 1:
                raise RebuildCoordinatorError("REBUILD_STAGE_VERIFY_CONFLICT")
        return StageVerification.create(
            artifacts=artifacts,
            equivalence_report=report,
        )

    def activate_atomically(
        self,
        *,
        stage_ref: str,
        output_manifest_set_sha256: str,
        tombstone_epoch: int,
    ) -> ActivationReceipt:
        operation = self._load_operation(stage_ref)
        if operation.tombstone_epoch != tombstone_epoch:
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
        manifests = self._load_complete_manifest_set(operation, None)
        self._validate_stage_descriptor(operation, manifests)
        artifacts = tuple(self._artifact_from_manifest(value) for value in manifests)
        actual_manifest_sha256 = output_manifest_set_sha256_for_artifacts(artifacts)
        if (
            _SHA256.fullmatch(output_manifest_set_sha256) is None
            or actual_manifest_sha256 != output_manifest_set_sha256
        ):
            raise RebuildCoordinatorError("REBUILD_OUTPUT_MANIFEST_HASH_MISMATCH")
        if operation.state == "ACTIVE":
            if operation.runtime_epoch is None:
                raise RebuildCoordinatorError("REBUILD_ACTIVE_EPOCH_INVALID")
            with transaction(self._connection):
                self._assert_activation_authority(
                    operation.job_id,
                    tombstone_epoch=tombstone_epoch,
                    allowed_job_states=("activating",),
                    require_current_epoch=False,
                )
                self._ack_source_rebuild_intent(
                    operation.job_id,
                    finished_at=_utc_text(self._clock.now()),
                )
            return ActivationReceipt(
                output_manifest_set_sha256=actual_manifest_sha256,
                tombstone_epoch=tombstone_epoch,
                already_active=True,
            )
        if operation.state != "VERIFIED":
            raise RebuildCoordinatorError("REBUILD_STAGE_NOT_VERIFIED")
        now = _utc_text(self._clock.now())
        with transaction(self._connection):
            self._assert_activation_authority(
                operation.job_id,
                tombstone_epoch=tombstone_epoch,
                allowed_job_states=("activating",),
            )
            if self._read_tombstone_epoch() != tombstone_epoch:
                raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
            self._before_manifest_activation(operation)
            self._manifests.activate_expected(
                operation.operation_id,
                expected_current_epoch=operation.expected_current_epoch,
                activated_at=now,
                drop_tombstoned_carry_forward=True,
            )
            active_operation = self._connection.execute(
                "SELECT runtime_epoch FROM publication_operations "
                "WHERE operation_id = ? AND state = 'ACTIVE'",
                (operation.operation_id,),
            ).fetchone()
            if active_operation is None or type(active_operation[0]) is not int:
                raise RebuildCoordinatorError("REBUILD_ACTIVE_EPOCH_INVALID")
            # A rebuild activation is a complete replacement closure.  Keeping
            # a non-tombstoned row from the previous operation would make the
            # active epoch unverifiable and could retain an obsolete optional
            # authority artifact (for example a retired C1 revision).
            self._connection.execute(
                "DELETE FROM active_artifacts WHERE epoch = ? AND manifest_id IN ("
                "SELECT manifest_id FROM artifact_manifests "
                "WHERE operation_id != ?)",
                (int(active_operation[0]), operation.operation_id),
            )
            self._ack_source_rebuild_intent(
                operation.job_id,
                finished_at=now,
            )
        return ActivationReceipt(
            output_manifest_set_sha256=actual_manifest_sha256,
            tombstone_epoch=tombstone_epoch,
            already_active=False,
        )

    def resume_stage(self, *, job_id: str) -> str:
        rows = self._connection.execute(
            """
            SELECT p.operation_id, p.state
              FROM rebuild_stage_bindings AS b
              JOIN publication_operations AS p
                ON p.operation_id = b.operation_id
             WHERE b.job_id = ? AND p.purpose = 'rebuild'
               AND p.state IN ('VERIFIED', 'ACTIVE')
             ORDER BY CASE p.state WHEN 'ACTIVE' THEN 0 ELSE 1 END,
                      b.attempt_count DESC
            """,
            (job_id,),
        ).fetchall()
        if len(rows) != 1:
            raise RebuildCoordinatorError("REBUILD_DURABLE_STAGE_NOT_FOUND")
        operation = self._load_operation(str(rows[0][0]))
        if operation.job_id != job_id:
            raise RebuildCoordinatorError("REBUILD_DURABLE_STAGE_NOT_FOUND")
        self._assert_activation_authority(
            job_id,
            tombstone_epoch=operation.tombstone_epoch,
            allowed_job_states=("activating",),
            require_current_epoch=operation.state != "ACTIVE",
        )
        return operation.operation_id

    def discard_stage(self, *, stage_ref: str) -> None:
        with transaction(self._connection):
            self._connection.execute(
                """
                UPDATE publication_operations SET state = 'FAILED'
                 WHERE operation_id = ? AND purpose = 'rebuild'
                   AND state IN ('PREPARED', 'VERIFIED')
                """,
                (stage_ref,),
            )
        self._registrations.pop(stage_ref, None)
        self._staged_purposes.pop(stage_ref, None)

    def _assert_global_activation_approval(
        self,
        *,
        approval_operation_id: str,
        approval_request_id: str,
        source_intent_id: str | None,
        plan_sha256: str,
        scope_sha256: str,
        tombstone_epoch: int,
        purpose: str,
        builder_dag_sha256: str,
        input_authority_versions_sha256: str,
        policy_sha256: str | None,
        model_descriptor_sha256: str | None,
    ) -> None:
        approval = self._connection.execute(
            """
            SELECT e.request_id, e.draft_sha256, e.descriptor_base_version,
                   e.target_scope_hash, e.state, e.descriptor_sha256,
                   r.descriptor_sha256, r.descriptor_json,
                   r.diff_object_ref_json, r.purpose,
                   r.target_scope_hash, r.base_version
              FROM approval_executions AS e
              JOIN approval_requests AS r ON r.request_id = e.request_id
             WHERE e.operation_id = ?
            """,
            (approval_operation_id,),
        ).fetchone()
        if approval is None or tuple(approval[:5]) != (
            approval_request_id,
            plan_sha256,
            tombstone_epoch,
            scope_sha256,
            "APPLIED",
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        try:
            descriptor = DraftDescriptor.model_validate_json(str(approval[7]))
            diff_ref = VersionRef.model_validate_json(str(approval[8]))
            payload = self._content_store.read_hash_verified(
                diff_ref.content_sha256
            )
            envelope = json.loads(payload)
            if (
                type(envelope) is not dict
                or canonical_json_bytes(envelope) != payload
                or set(envelope)
                != {
                    "schema_version",
                    "action",
                    "operation_id",
                    "plan",
                    "job_id",
                    "job_plan_sha256",
                    "base_versions",
                    "plan_sha256",
                    "descriptor",
                }
            ):
                raise ValueError
            exact_plan = RebuildPlan.model_validate_json(
                canonical_json_bytes(envelope["plan"]),
                strict=True,
            )
            envelope_descriptor = DraftDescriptor.model_validate_json(
                canonical_json_bytes(envelope["descriptor"]),
                strict=True,
            )
        except (
            ContentStoreError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            ) from None
        exact_descriptor_sha256 = descriptor_sha256(descriptor)
        if (
            diff_ref.version != 1
            or str(approval[5]) != exact_descriptor_sha256
            or str(approval[6]) != exact_descriptor_sha256
            or str(approval[9]) != "rebuild"
            or str(approval[10]) != scope_sha256
            or int(approval[11]) != tombstone_epoch
            or descriptor
            != DraftDescriptor(
                purpose="rebuild",
                target_id=f"global_rebuild:{purpose}",
                base_version=tombstone_epoch,
                draft_sha256=plan_sha256,
            )
            or envelope_descriptor != descriptor
            or envelope["schema_version"] != "global_rebuild_plan.v1"
            or envelope["action"] != "start"
            or envelope["operation_id"] != approval_operation_id
            or envelope["job_id"] is not None
            or envelope["job_plan_sha256"] is not None
            or envelope["plan_sha256"] != plan_sha256
            or envelope["base_versions"]
            != [
                {
                    "authority_key": "tombstone_epoch",
                    "scope_sha256": scope_sha256,
                    "version": tombstone_epoch,
                }
            ]
            or exact_plan.database_scope != "global"
            or exact_plan.source_intent_id != source_intent_id
            or exact_plan.scope_sha256 != scope_sha256
            or exact_plan.purpose != purpose
            or exact_plan.builder_dag_sha256 != builder_dag_sha256
            or exact_plan.input_authority_versions_sha256
            != input_authority_versions_sha256
            or exact_plan.tombstone_epoch != tombstone_epoch
            or exact_plan.policy_sha256 != policy_sha256
            or exact_plan.model_descriptor_sha256
            != model_descriptor_sha256
            or exact_plan.plan_sha256 != plan_sha256
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )

    def _assert_client_activation_approval(
        self,
        *,
        approval_operation_id: str,
        approval_request_id: str,
        source_intent_id: str | None,
        plan_sha256: str,
        scope_sha256: str,
        tombstone_epoch: int,
        purpose: str,
        builder_dag_sha256: str,
        input_authority_versions_sha256: str,
        policy_sha256: str | None,
        model_descriptor_sha256: str | None,
    ) -> None:
        rows = self._connection.execute(
            "SELECT object_id, version, content_sha256, size_bytes, "
            "media_type, purpose, operation_id, plan_sha256, base_version, "
            "target_scope_hash FROM lifecycle_plan_objects "
            "WHERE operation_id = ?",
            (approval_operation_id,),
        ).fetchall()
        if len(rows) != 1:
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        plan_row = rows[0]
        if str(plan_row[5]) == "rollback":
            self._assert_client_rollback_activation_approval(
                plan_row=tuple(plan_row),
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
                source_intent_id=source_intent_id,
                plan_sha256=plan_sha256,
                scope_sha256=scope_sha256,
                tombstone_epoch=tombstone_epoch,
                purpose=purpose,
                builder_dag_sha256=builder_dag_sha256,
                input_authority_versions_sha256=(
                    input_authority_versions_sha256
                ),
                policy_sha256=policy_sha256,
                model_descriptor_sha256=model_descriptor_sha256,
            )
            return
        if (
            int(plan_row[1]) != 1
            or str(plan_row[4]) != "application/json"
            or str(plan_row[5]) != "rebuild"
            or str(plan_row[6]) != approval_operation_id
            or str(plan_row[7]) != plan_sha256
            or int(plan_row[8]) != tombstone_epoch
            or str(plan_row[9]) != scope_sha256
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        self._assert_client_rebuild_activation_approval(
            plan_row=tuple(plan_row),
            approval_operation_id=approval_operation_id,
            approval_request_id=approval_request_id,
            source_intent_id=source_intent_id,
            plan_sha256=plan_sha256,
            scope_sha256=scope_sha256,
            tombstone_epoch=tombstone_epoch,
            purpose=purpose,
            builder_dag_sha256=builder_dag_sha256,
            input_authority_versions_sha256=input_authority_versions_sha256,
            policy_sha256=policy_sha256,
            model_descriptor_sha256=model_descriptor_sha256,
        )

    def _assert_client_rollback_activation_approval(
        self,
        *,
        plan_row: tuple[str | int, ...],
        approval_operation_id: str,
        approval_request_id: str,
        source_intent_id: str | None,
        plan_sha256: str,
        scope_sha256: str,
        tombstone_epoch: int,
        purpose: str,
        builder_dag_sha256: str,
        input_authority_versions_sha256: str,
        policy_sha256: str | None,
        model_descriptor_sha256: str | None,
    ) -> None:
        """Validate the closed rollback authority without weakening rebuilds."""

        # Local imports avoid a module cycle: rollback planning depends on the
        # rebuild contracts, while activation needs to parse that exact plan.
        from consultation_kb.lifecycle.rollback import (
            ArtifactRollbackPlan,
            FactRollbackPlan,
            RollbackPlanEnvelope,
        )
        from consultation_kb.storage.client_ledger import FactEventRepository

        if (
            len(plan_row) != 10
            or int(plan_row[1]) != 1
            or str(plan_row[4]) != "application/json"
            or str(plan_row[5]) != "rollback"
            or str(plan_row[6]) != approval_operation_id
            or str(plan_row[9]) != scope_sha256
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        try:
            payload = self._content_store.read_verified(
                self._content_store.reference(
                    content_sha256=str(plan_row[2]),
                    media_type=str(plan_row[4]),
                    size_bytes=int(plan_row[3]),
                )
            )
            envelope = RollbackPlanEnvelope.model_validate_json(
                payload,
                strict=True,
            )
            if canonical_json_bytes(envelope.model_dump(mode="json")) != payload:
                raise ValueError
            outer_plan = envelope.plan
            if isinstance(outer_plan, FactRollbackPlan):
                source_plan = outer_plan
            elif (
                isinstance(outer_plan, ArtifactRollbackPlan)
                and outer_plan.database_scope == "client"
                and outer_plan.source_rollback_kind == "profile_fact"
            ):
                source_row = self._connection.execute(
                    "SELECT object_id, version, content_sha256, size_bytes, "
                    "media_type, purpose, operation_id, plan_sha256, "
                    "base_version, target_scope_hash FROM lifecycle_plan_objects "
                    "WHERE object_id = ?",
                    (outer_plan.source_plan_ref.object_id,),
                ).fetchone()
                if source_row is None or tuple(source_row[:5]) != (
                    outer_plan.source_plan_ref.object_id,
                    outer_plan.source_plan_ref.version,
                    outer_plan.source_plan_ref.content_sha256,
                    outer_plan.source_plan_ref.size_bytes,
                    outer_plan.source_plan_ref.media_type,
                ):
                    raise ValueError
                source_payload = self._content_store.read_verified(
                    self._content_store.reference(
                        content_sha256=str(source_row[2]),
                        media_type=str(source_row[4]),
                        size_bytes=int(source_row[3]),
                    )
                )
                source_envelope = RollbackPlanEnvelope.model_validate_json(
                    source_payload,
                    strict=True,
                )
                if (
                    canonical_json_bytes(
                        source_envelope.model_dump(mode="json")
                    )
                    != source_payload
                    or not isinstance(source_envelope.plan, FactRollbackPlan)
                    or source_envelope.database_scope != "client"
                    or source_envelope.scope_sha256 != scope_sha256
                    or source_envelope.rollback_kind != "profile_fact"
                    or source_envelope.plan.plan_sha256
                    != outer_plan.source_plan_sha256
                    or source_envelope.plan.base_versions
                    != outer_plan.base_versions
                    or tuple(source_row[5:])
                    != (
                        "rollback",
                        source_envelope.operation_id,
                        source_envelope.plan.plan_sha256,
                        source_envelope.plan.descriptor.base_version,
                        scope_sha256,
                    )
                ):
                    raise ValueError
                source_plan = source_envelope.plan
            else:
                raise ValueError
        except (
            ContentStoreError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            ) from None

        rebuild_plan = source_plan.rebuild_plan
        intent = self._connection.execute(
            "SELECT intent_kind FROM rebuild_source_intents WHERE intent_id = ?",
            (source_intent_id,),
        ).fetchall()
        try:
            stored_event = FactEventRepository(self._connection).get_event(
                source_plan.new_event.event_id
            )
            latest_event = FactEventRepository(self._connection).get_latest_event(
                source_plan.fact_id
            )
        except (KeyError, RuntimeError, ValueError):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            ) from None
        descriptor = outer_plan.descriptor
        exact_descriptor_sha256 = descriptor_sha256(descriptor)
        attestation = self._connection.execute(
            "SELECT request_id, descriptor_sha256, plan_object_id, "
            "plan_version, plan_content_sha256, plan_size_bytes, "
            "plan_media_type, purpose, base_version, target_scope_hash "
            "FROM lifecycle_approval_attestations WHERE operation_id = ?",
            (approval_operation_id,),
        ).fetchone()
        approval = self._connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, state, "
            "applied_commit_version, applied_at FROM approval_executions "
            "WHERE operation_id = ?",
            (approval_operation_id,),
        ).fetchone()
        valid = (
            envelope.database_scope == "client"
            and envelope.scope_sha256 == scope_sha256
            and envelope.operation_id == approval_operation_id
            and outer_plan.plan_sha256 == str(plan_row[7])
            and outer_plan.descriptor.base_version == int(plan_row[8])
            and source_intent_id is not None
            and source_plan.operation_id == source_intent_id
            and intent == [("rollback",)]
            and purpose == "all"
            and rebuild_plan.database_scope == "client"
            and rebuild_plan.source_intent_id == source_intent_id
            and rebuild_plan.scope_sha256 == scope_sha256
            and rebuild_plan.purpose == "all"
            and rebuild_plan.builder_dag_sha256 == builder_dag_sha256
            and rebuild_plan.input_authority_versions_sha256
            == input_authority_versions_sha256
            and rebuild_plan.tombstone_epoch == tombstone_epoch
            and rebuild_plan.policy_sha256 == policy_sha256
            and rebuild_plan.model_descriptor_sha256
            == model_descriptor_sha256
            and rebuild_plan.plan_sha256 == plan_sha256
            and stored_event == source_plan.new_event
            and latest_event == source_plan.new_event
            and attestation
            == (
                approval_request_id,
                exact_descriptor_sha256,
                str(plan_row[0]),
                int(plan_row[1]),
                str(plan_row[2]),
                int(plan_row[3]),
                str(plan_row[4]),
                "rollback",
                descriptor.base_version,
                scope_sha256,
            )
            and approval is not None
            and tuple(approval[:6])
            == (
                approval_request_id,
                exact_descriptor_sha256,
                outer_plan.plan_sha256,
                descriptor.base_version,
                scope_sha256,
                "APPLIED",
            )
            and type(approval[6]) is int
            and int(approval[6]) > 0
            and approval[7] is not None
        )
        if not valid:
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )

    def _assert_client_rebuild_activation_approval(
        self,
        *,
        plan_row: tuple[str | int, ...],
        approval_operation_id: str,
        approval_request_id: str,
        source_intent_id: str | None,
        plan_sha256: str,
        scope_sha256: str,
        tombstone_epoch: int,
        purpose: str,
        builder_dag_sha256: str,
        input_authority_versions_sha256: str,
        policy_sha256: str | None,
        model_descriptor_sha256: str | None,
    ) -> None:
        """Keep the existing ordinary client-rebuild authority closed."""

        try:
            payload = self._content_store.read_verified(
                self._content_store.reference(
                    content_sha256=str(plan_row[2]),
                    media_type=str(plan_row[4]),
                    size_bytes=int(plan_row[3]),
                )
            )
            envelope = json.loads(payload)
            if (
                type(envelope) is not dict
                or canonical_json_bytes(envelope) != payload
            ):
                raise ValueError
            expected_keys = {
                "schema_version",
                "action",
                "operation_id",
                "client_id",
                "session_id",
                "plan",
                "job_id",
                "job_plan_sha256",
                "base_versions",
                "plan_sha256",
                "descriptor",
            }
            if set(envelope) != expected_keys:
                raise ValueError
            exact_plan = RebuildPlan.model_validate_json(
                canonical_json_bytes(envelope["plan"]),
                strict=True,
            )
            descriptor = DraftDescriptor.model_validate_json(
                canonical_json_bytes(envelope["descriptor"]),
                strict=True,
            )
        except (
            ContentStoreError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            ) from None
        client_id = envelope["client_id"]
        session_id = envelope["session_id"]
        if (
            type(client_id) is not str
            or not client_id
            or type(session_id) is not str
            or not session_id
            or envelope["schema_version"] != "client_rebuild_plan.v1"
            or envelope["action"] != "start"
            or envelope["operation_id"] != approval_operation_id
            or envelope["job_id"] is not None
            or envelope["job_plan_sha256"] is not None
            or envelope["plan_sha256"] != plan_sha256
            or envelope["base_versions"]
            != [
                {
                    "authority_key": "tombstone_epoch",
                    "scope_sha256": scope_sha256,
                    "version": tombstone_epoch,
                }
            ]
            or exact_plan.database_scope != "client"
            or exact_plan.source_intent_id != source_intent_id
            or exact_plan.scope_sha256 != scope_sha256
            or exact_plan.purpose != purpose
            or exact_plan.builder_dag_sha256 != builder_dag_sha256
            or exact_plan.input_authority_versions_sha256
            != input_authority_versions_sha256
            or exact_plan.tombstone_epoch != tombstone_epoch
            or exact_plan.policy_sha256 != policy_sha256
            or exact_plan.model_descriptor_sha256
            != model_descriptor_sha256
            or exact_plan.plan_sha256 != plan_sha256
            or descriptor
            != DraftDescriptor(
                purpose="rebuild",
                target_id=f"client_rebuild:{purpose}",
                client_id=client_id,
                session_id=session_id,
                base_version=tombstone_epoch,
                draft_sha256=plan_sha256,
            )
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        attestation = self._connection.execute(
            "SELECT request_id, descriptor_sha256, plan_object_id, "
            "plan_version, plan_content_sha256, plan_size_bytes, "
            "plan_media_type, purpose, base_version, target_scope_hash "
            "FROM lifecycle_approval_attestations WHERE operation_id = ?",
            (approval_operation_id,),
        ).fetchone()
        if attestation != (
            approval_request_id,
            descriptor_sha256(descriptor),
            str(plan_row[0]),
            int(plan_row[1]),
            str(plan_row[2]),
            int(plan_row[3]),
            str(plan_row[4]),
            "rebuild",
            tombstone_epoch,
            scope_sha256,
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        approval = self._connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, state, "
            "applied_commit_version, applied_at FROM approval_executions "
            "WHERE operation_id = ?",
            (approval_operation_id,),
        ).fetchone()
        if (
            approval is None
            or tuple(approval[:6])
            != (
                approval_request_id,
                descriptor_sha256(descriptor),
                plan_sha256,
                tombstone_epoch,
                scope_sha256,
                "APPLIED",
            )
            or type(approval[6]) is not int
            or int(approval[6]) <= 0
            or approval[7] is None
        ):
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )

    def _assert_activation_authority(
        self,
        job_id: str,
        *,
        tombstone_epoch: int | None,
        allowed_job_states: tuple[str, ...],
        require_current_epoch: bool = True,
    ) -> _ActivationAuthority:
        row = self._connection.execute(
            """
            SELECT source_intent_id, approval_operation_id,
                   approval_request_id, plan_sha256, scope_sha256,
                   tombstone_epoch, state, attempt_count, purpose,
                   builder_dag_sha256, input_authority_versions_sha256,
                   policy_sha256, model_descriptor_sha256
              FROM rebuild_jobs WHERE job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_AUTHORITY_INVALID")
        source_intent_id = None if row[0] is None else str(row[0])
        approval_operation_id = None if row[1] is None else str(row[1])
        approval_request_id = None if row[2] is None else str(row[2])
        plan_sha256 = str(row[3])
        scope_sha256 = str(row[4])
        job_tombstone_epoch = int(row[5])
        attempt_count = int(row[7])
        purpose = str(row[8])
        builder_dag_sha256 = str(row[9])
        input_authority_versions_sha256 = str(row[10])
        policy_sha256 = None if row[11] is None else str(row[11])
        model_descriptor_sha256 = (
            None if row[12] is None else str(row[12])
        )
        if (
            _SHA256.fullmatch(plan_sha256) is None
            or scope_sha256 != self._scope_sha256
            or str(row[6]) not in allowed_job_states
            or attempt_count <= 0
            or (
                tombstone_epoch is not None
                and job_tombstone_epoch != tombstone_epoch
            )
        ):
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_AUTHORITY_INVALID")
        current_authority = self._connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        if current_authority is None:
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_AUTHORITY_INVALID")
        if approval_operation_id is None or approval_request_id is None:
            raise RebuildCoordinatorError(
                "REBUILD_ACTIVATION_AUTHORITY_INVALID"
            )
        if self._database_scope == "global":
            self._assert_global_activation_approval(
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
                source_intent_id=source_intent_id,
                plan_sha256=plan_sha256,
                scope_sha256=scope_sha256,
                tombstone_epoch=job_tombstone_epoch,
                purpose=purpose,
                builder_dag_sha256=builder_dag_sha256,
                input_authority_versions_sha256=(
                    input_authority_versions_sha256
                ),
                policy_sha256=policy_sha256,
                model_descriptor_sha256=model_descriptor_sha256,
            )
        else:
            self._assert_client_activation_approval(
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
                source_intent_id=source_intent_id,
                plan_sha256=plan_sha256,
                scope_sha256=scope_sha256,
                tombstone_epoch=job_tombstone_epoch,
                purpose=purpose,
                builder_dag_sha256=builder_dag_sha256,
                input_authority_versions_sha256=(
                    input_authority_versions_sha256
                ),
                policy_sha256=policy_sha256,
                model_descriptor_sha256=model_descriptor_sha256,
            )
        if (
            require_current_epoch
            and int(current_authority[1]) != job_tombstone_epoch
        ):
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
        resolved_request_id = approval_request_id
        rollback_source = False
        if source_intent_id is not None:
            rollback_rows = self._connection.execute(
                "SELECT i.intent_kind, p.purpose FROM rebuild_source_intents AS i "
                "JOIN lifecycle_plan_objects AS p ON p.operation_id = ? "
                "WHERE i.intent_id = ?",
                (approval_operation_id, source_intent_id),
            ).fetchall()
            rollback_source = rollback_rows == [("rollback", "rollback")]
        if source_intent_id is not None and not rollback_source:
            deletion = self._connection.execute(
                """
                SELECT i.action_type, i.authority_scope, i.state,
                       i.request_id, i.action_id, i.object_type,
                       i.target_id_hash, i.target_version,
                       i.target_content_sha256,
                       r.operation_id, r.plan_sha256, r.target_scope_hash,
                       r.base_deletion_version, r.committed_deletion_version,
                       r.tombstone_epoch, r.approval_request_id,
                       r.approval_descriptor_sha256,
                       r.approval_target_scope_hash, r.state,
                       e.request_id, e.descriptor_sha256, e.draft_sha256,
                       e.descriptor_base_version, e.target_scope_hash, e.state,
                       p.request_id, p.action_id, p.deletion_plan_sha256,
                       p.root_object_type, p.root_target_id_hash,
                       p.root_lineage_hash, p.action_descriptor_sha256,
                       t.tombstone_id, r.target_type, r.target_id_hash,
                       e.applied_commit_version
                  FROM deletion_queue_intents AS i
                  JOIN deletion_requests AS r ON r.request_id = i.request_id
                  JOIN approval_executions AS e ON e.operation_id = r.operation_id
                  JOIN deletion_intent_authority_proofs AS p
                    ON p.intent_id = i.intent_id
                   AND p.request_id = i.request_id
                   AND p.action_id = i.action_id
                  JOIN tombstones AS t
                    ON t.target_type = p.root_object_type
                   AND t.target_id_hash = p.root_target_id_hash
                   AND t.source_lineage_hash = p.root_lineage_hash
                 WHERE i.intent_id = ?
                """,
                (source_intent_id,),
            ).fetchone()
            if deletion is None:
                raise RebuildCoordinatorError(
                    "REBUILD_ACTIVATION_AUTHORITY_INVALID"
                )
            expected_action_descriptor = deletion_intent_authority_sha256(
                intent_id=source_intent_id,
                request_id=str(deletion[3]),
                action_id=str(deletion[4]),
                action_type=cast(DeletionActionType, str(deletion[0])),
                object_type=str(deletion[5]),
                target_id_hash=str(deletion[6]),
                target_version=int(deletion[7]),
                target_content_sha256=str(deletion[8]),
                authority_scope=cast(DeletionAuthorityScope, str(deletion[1])),
                deletion_plan_sha256=str(deletion[10]),
                root_object_type=str(deletion[28]),
                root_target_id_hash=str(deletion[29]),
                root_lineage_hash=str(deletion[30]),
            )
            valid_intent_states = {"PENDING", "CLAIMED"}
            if not require_current_epoch:
                valid_intent_states.add("SUCCEEDED")
            valid = (
                purpose == "all"
                and str(deletion[0]) == "rebuild"
                and str(deletion[1]) == self._database_scope
                and str(deletion[2]) in valid_intent_states
                and str(deletion[11]) == scope_sha256
                and int(deletion[14]) == job_tombstone_epoch
                and str(deletion[17]) == scope_sha256
                and str(deletion[18])
                in {"TOMBSTONED", "PHYSICAL_CLEANUP_COMPLETE"}
                and str(deletion[19]) == str(deletion[15])
                and str(deletion[20]) == str(deletion[16])
                and str(deletion[21]) == str(deletion[10])
                and int(deletion[22]) == int(deletion[12])
                and str(deletion[23]) == scope_sha256
                and str(deletion[24]) == "APPLIED"
                and str(deletion[25]) == str(deletion[3])
                and str(deletion[26]) == str(deletion[4])
                and str(deletion[27]) == str(deletion[10])
                and str(deletion[28]) == str(deletion[33])
                and str(deletion[29]) == str(deletion[34])
                and str(deletion[31]) == expected_action_descriptor
                and bool(str(deletion[32]))
                and int(deletion[35]) > 0
            )
            if not valid:
                raise RebuildCoordinatorError(
                    "REBUILD_ACTIVATION_AUTHORITY_INVALID"
                )
            if require_current_epoch and (
                int(current_authority[0]) != int(deletion[13])
                or int(current_authority[1]) != job_tombstone_epoch
            ):
                raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
        return _ActivationAuthority(
            job_id=job_id,
            plan_sha256=plan_sha256,
            approval_request_id=resolved_request_id,
            scope_sha256=scope_sha256,
            tombstone_epoch=job_tombstone_epoch,
            attempt_count=attempt_count,
        )

    def _ack_source_rebuild_intent(
        self,
        job_id: str,
        *,
        finished_at: str,
    ) -> None:
        row = self._connection.execute(
            """
            SELECT j.source_intent_id, i.request_id, i.action_type,
                   i.authority_scope, i.state, i.finished_at
              FROM rebuild_jobs AS j
              LEFT JOIN deletion_queue_intents AS i
                ON i.intent_id = j.source_intent_id
             WHERE j.job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_AUTHORITY_INVALID")
        source_intent_id = None if row[0] is None else str(row[0])
        if source_intent_id is None:
            return
        rollback = self._connection.execute(
            "SELECT i.intent_kind, p.purpose FROM rebuild_jobs AS j "
            "JOIN rebuild_source_intents AS i "
            "ON i.intent_id = j.source_intent_id "
            "JOIN lifecycle_plan_objects AS p "
            "ON p.operation_id = j.approval_operation_id "
            "WHERE j.job_id = ? AND i.intent_id = ?",
            (job_id, source_intent_id),
        ).fetchall()
        if rollback == [("rollback", "rollback")]:
            # The immutable rollback intent is acknowledged by this atomic
            # activation and the enclosing durable job transition.  It is not
            # a deletion queue item and must never mutate that queue.
            return
        if (
            row[1] is None
            or str(row[2]) != "rebuild"
            or str(row[3]) != self._database_scope
            or str(row[4]) not in {"PENDING", "CLAIMED", "SUCCEEDED"}
        ):
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_AUTHORITY_INVALID")
        request_id = str(row[1])
        state = str(row[4])
        if state == "PENDING":
            claimed = self._connection.execute(
                """
                UPDATE deletion_queue_intents
                   SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                       last_error_code = NULL, claimed_at = ?, finished_at = NULL
                 WHERE intent_id = ? AND state = 'PENDING'
                   AND action_type = 'rebuild' AND authority_scope = ?
                """,
                (finished_at, source_intent_id, self._database_scope),
            ).rowcount
            if claimed != 1:
                raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")
            state = "CLAIMED"
        if state == "CLAIMED":
            changed = self._connection.execute(
                """
                UPDATE deletion_queue_intents
                   SET state = 'SUCCEEDED', finished_at = ?,
                       last_error_code = NULL
                 WHERE intent_id = ? AND state = 'CLAIMED'
                   AND action_type = 'rebuild' AND authority_scope = ?
                """,
                (finished_at, source_intent_id, self._database_scope),
            ).rowcount
            if changed != 1:
                raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")
        elif row[5] is None:
            raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")

        request = self._connection.execute(
            "SELECT state, queue_state FROM deletion_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if request is None or str(request[0]) not in {
            "TOMBSTONED",
            "PHYSICAL_CLEANUP_COMPLETE",
        }:
            raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")
        if str(request[0]) == "PHYSICAL_CLEANUP_COMPLETE":
            if str(request[1]) != "SUCCEEDED":
                raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")
            return
        self._connection.execute(
            """
            UPDATE deletion_requests SET queue_state = 'RUNNING'
             WHERE request_id = ? AND state = 'TOMBSTONED'
               AND queue_state IN ('PENDING', 'PARTIAL', 'FAILED')
            """,
            (request_id,),
        )
        remaining = int(
            self._connection.execute(
                "SELECT count(*) FROM deletion_queue_intents "
                "WHERE request_id = ? AND state != 'SUCCEEDED'",
                (request_id,),
            ).fetchone()[0]
        )
        backup_pending = int(
            self._connection.execute(
                "SELECT count(*) FROM backup_destruction_queue "
                "WHERE request_id = ? AND state != 'succeeded'",
                (request_id,),
            ).fetchone()[0]
        )
        if remaining == 0 and backup_pending == 0:
            changed = self._connection.execute(
                """
                UPDATE deletion_requests
                   SET queue_state = 'SUCCEEDED',
                       state = 'PHYSICAL_CLEANUP_COMPLETE'
                 WHERE request_id = ? AND state = 'TOMBSTONED'
                   AND queue_state = 'RUNNING'
                """,
                (request_id,),
            ).rowcount
            if changed != 1:
                raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")
        else:
            changed = self._connection.execute(
                """
                UPDATE deletion_requests SET queue_state = 'PARTIAL'
                 WHERE request_id = ? AND state = 'TOMBSTONED'
                   AND queue_state = 'RUNNING'
                """,
                (request_id,),
            ).rowcount
            if changed != 1:
                raise RebuildCoordinatorError("REBUILD_INTENT_ACK_FAILED")

    def _load_operation(self, operation_id: str) -> _StageOperation:
        row = self._connection.execute(
            """
            SELECT p.operation_id, b.job_id, b.plan_sha256,
                   b.approval_request_id, b.attempt_count,
                   p.descriptor_sha256, p.state,
                   p.required_manifests_json, p.required_manifest_count,
                   p.expected_current_epoch, p.runtime_epoch,
                   p.authority_base_version, p.approval_request_id,
                   b.scope_sha256, b.tombstone_epoch
              FROM publication_operations AS p
              JOIN rebuild_stage_bindings AS b
                ON b.operation_id = p.operation_id
             WHERE p.operation_id = ? AND p.purpose = 'rebuild'
            """,
            (operation_id,),
        ).fetchone()
        if row is None:
            raise RebuildCoordinatorError("REBUILD_STAGE_NOT_FOUND")
        try:
            decoded = json.loads(str(row[7]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_SCHEMA_INVALID") from exc
        if (
            type(decoded) is not list
            or any(type(value) is not str for value in decoded)
            or tuple(sorted(set(decoded))) != tuple(decoded)
            or len(decoded) != int(row[8])
        ):
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_SCHEMA_INVALID")
        authority_base_version = int(row[11])
        binding_tombstone_epoch = int(row[14])
        attempt_count = int(row[4])
        job_binding = self._connection.execute(
            """
            SELECT plan_sha256, scope_sha256, tombstone_epoch, attempt_count
              FROM rebuild_jobs WHERE job_id = ?
            """,
            (str(row[1]),),
        ).fetchone()
        if job_binding is None:
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_SCHEMA_INVALID")
        if (
            authority_base_version <= 0
            or attempt_count <= 0
            or str(row[2]) != str(job_binding[0])
            or str(row[13]) != self._scope_sha256
            or str(row[13]) != str(job_binding[1])
            or binding_tombstone_epoch != int(job_binding[2])
            or attempt_count != int(job_binding[3])
            or str(row[3]) != str(row[12])
            or _SHA256.fullmatch(str(row[2])) is None
        ):
            raise RebuildCoordinatorError("REBUILD_ARTIFACT_SCHEMA_INVALID")
        return _StageOperation(
            operation_id=str(row[0]),
            job_id=str(row[1]),
            plan_sha256=str(row[2]),
            approval_request_id=str(row[3]),
            attempt_count=attempt_count,
            descriptor_sha256=str(row[5]),
            state=str(row[6]),
            required_manifest_ids=tuple(decoded),
            authority_base_version=authority_base_version,
            expected_current_epoch=None if row[9] is None else int(row[9]),
            runtime_epoch=None if row[10] is None else int(row[10]),
            tombstone_epoch=binding_tombstone_epoch,
        )

    def _load_complete_manifest_set(
        self,
        operation: _StageOperation,
        output_purposes: Sequence[str] | None,
    ) -> tuple[ArtifactManifest, ...]:
        manifests = self._manifests.list_for_operation(operation.operation_id)
        if tuple(sorted(value.manifest_id for value in manifests)) != (
            operation.required_manifest_ids
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_CLOSURE_INCOMPLETE")
        keys = tuple(value.artifact_key for value in manifests)
        if len(set(keys)) != len(keys):
            raise RebuildCoordinatorError("REBUILD_STAGE_CLOSURE_INVALID")
        if output_purposes is not None and set(output_purposes) != set(keys):
            raise RebuildCoordinatorError("REBUILD_STAGE_CLOSURE_INVALID")
        return tuple(sorted(manifests, key=lambda value: value.artifact_key))

    def _validate_stage_descriptor(
        self,
        operation: _StageOperation,
        manifests: Sequence[ArtifactManifest],
    ) -> None:
        manifest_by_purpose = {
            manifest.artifact_key: manifest.manifest_id for manifest in manifests
        }
        expected = _stage_descriptor_sha256(
            database_scope=self._database_scope,
            scope_sha256=self._scope_sha256,
            job_id=operation.job_id,
            plan_sha256=operation.plan_sha256,
            tombstone_epoch=operation.tombstone_epoch,
            expected_current_epoch=operation.expected_current_epoch,
            manifest_by_purpose=manifest_by_purpose,
        )
        if expected != operation.descriptor_sha256:
            raise RebuildCoordinatorError("REBUILD_STAGE_DESCRIPTOR_MISMATCH")

    def _artifact_from_manifest(self, manifest: ArtifactManifest) -> BuiltArtifact:
        structured = self._connection.execute(
            "SELECT artifact_key, artifact_kind, source_version, "
            "semantic_basis_sha256, member_comparisons_json, envelope_sha256 "
            "FROM rebuild_structured_artifacts WHERE manifest_id = ?",
            (manifest.manifest_id,),
        ).fetchone()
        if structured is not None:
            return self._structured_artifact_from_manifest(manifest, structured)
        if manifest.artifact_kind != "rebuild_artifact" or len(manifest.members) != 2:
            raise RebuildCoordinatorError("REBUILD_STAGE_MANIFEST_INVALID")
        by_type = {member.object_type: member for member in manifest.members}
        if set(by_type) != {"rebuild_artifact", "rebuild_metadata"}:
            raise RebuildCoordinatorError("REBUILD_STAGE_MANIFEST_INVALID")
        payload_member = by_type["rebuild_artifact"]
        metadata_member = by_type["rebuild_metadata"]
        payload = self._content_store.read_hash_verified(
            payload_member.object_sha256
        )
        metadata_payload = self._content_store.read_hash_verified(
            metadata_member.object_sha256
        )
        if (
            len(payload) != payload_member.size_bytes
            or len(metadata_payload) != metadata_member.size_bytes
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_CAS_SIZE_MISMATCH")
        try:
            metadata = json.loads(metadata_payload)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RebuildCoordinatorError("REBUILD_STAGE_METADATA_INVALID") from exc
        if type(metadata) is not dict:
            raise RebuildCoordinatorError("REBUILD_STAGE_METADATA_INVALID")
        expected_keys = {
            "domain",
            "builder_id",
            "output_purpose",
            "version",
            "content_sha256",
            "semantic_fingerprint_sha256",
            "size_bytes",
        }
        if set(metadata) != expected_keys or metadata.get("domain") != (
            "consultation_kb.rebuild_staged_artifact.v1"
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_METADATA_INVALID")
        artifact = BuiltArtifact.create(
            builder_id=cast(str, metadata["builder_id"]),
            output_purpose=cast(str, metadata["output_purpose"]),
            version=cast(int, metadata["version"]),
            payload=payload,
            semantic_fingerprint_sha256=cast(
                str, metadata["semantic_fingerprint_sha256"]
            ),
        )
        if (
            artifact.output_purpose != manifest.artifact_key
            or artifact.version != manifest.source_version
            or artifact.content_sha256 != metadata["content_sha256"]
            or len(payload) != metadata["size_bytes"]
        ):
            raise RebuildCoordinatorError("REBUILD_STAGE_METADATA_INVALID")
        return artifact

    def _structured_artifact_from_manifest(
        self,
        manifest: ArtifactManifest,
        row: tuple[object, ...],
    ) -> BuiltArtifact:
        try:
            comparisons_value = json.loads(str(row[4]))
            if (
                type(comparisons_value) is not list
                or any(
                    type(item) is not dict
                    or set(item)
                    != {"comparison_sha256", "object_id", "ordinal", "role"}
                    or type(item["ordinal"]) is not int
                    or type(item["role"]) is not str
                    or (
                        item["object_id"] is not None
                        and type(item["object_id"]) is not str
                    )
                    or type(item["comparison_sha256"]) is not str
                    for item in comparisons_value
                )
            ):
                raise ValueError
            if tuple(int(item["ordinal"]) for item in comparisons_value) != tuple(
                range(len(comparisons_value))
            ):
                raise ValueError
            members = tuple(
                StructuredArtifactMember.from_bytes(
                    role=member.object_type,
                    object_id=cast(str | None, comparison["object_id"]),
                    media_type=member.media_type,
                    payload=self._content_store.read_hash_verified(
                        member.object_sha256
                    ),
                    comparison_sha256=str(comparison["comparison_sha256"]),
                    source_lineage_hashes=member.source_lineage_hashes,
                )
                for member, comparison in zip(
                    manifest.members, comparisons_value, strict=True
                )
                if (
                    str(comparison["role"]) == member.object_type
                    and (
                        comparison["object_id"] is None
                        or comparison["object_id"] == member.object_id
                    )
                )
            )
            envelope = StructuredArtifactEnvelope(
                artifact_key=str(row[0]),
                artifact_kind=str(row[1]),
                source_version=int(str(row[2])),
                semantic_basis_sha256=str(row[3]),
                members=members,
            )
            artifact = BuiltArtifact.create(
                builder_id=envelope.artifact_key,
                output_purpose=envelope.artifact_key,
                version=envelope.source_version,
                payload=envelope.canonical_bytes,
                semantic_fingerprint_sha256=(
                    envelope.semantic_fingerprint_sha256
                ),
                comparison_content_sha256=(
                    envelope.comparison_content_sha256
                ),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StructuredArtifactError,
        ) as exc:
            raise RebuildCoordinatorError(
                "REBUILD_STRUCTURED_ARTIFACT_INVALID"
            ) from exc
        if (
            manifest.artifact_key != envelope.artifact_key
            or manifest.artifact_kind != envelope.artifact_kind
            or manifest.source_version != envelope.source_version
            or len(members) != len(manifest.members)
            or tuple(member.role for member in members)
            != tuple(member.object_type for member in manifest.members)
            or artifact.content_sha256 != str(row[5])
        ):
            raise RebuildCoordinatorError("REBUILD_STRUCTURED_ARTIFACT_INVALID")
        return artifact

    def _active_fingerprints(
        self, *, output_purposes: Sequence[str], epoch: int | None
    ) -> tuple[ArtifactFingerprint, ...]:
        if epoch is None:
            return ()
        placeholders = ",".join("?" for _ in output_purposes)
        rows = self._connection.execute(
            f"SELECT manifest_id FROM active_artifacts WHERE epoch = ? "
            f"AND artifact_key IN ({placeholders}) ORDER BY artifact_key",
            (epoch, *output_purposes),
        ).fetchall()
        return tuple(
            self._fingerprint_from_active_manifest(
                self._manifests.get(str(row[0]))
            )
            for row in rows
        )

    def _fingerprint_from_active_manifest(
        self, manifest: ArtifactManifest
    ) -> ArtifactFingerprint:
        for member in manifest.members:
            payload = self._content_store.read_hash_verified(member.object_sha256)
            if len(payload) != member.size_bytes:
                raise RebuildCoordinatorError("REBUILD_ACTIVE_CAS_SIZE_MISMATCH")
        if manifest.artifact_kind == "rebuild_artifact":
            return self._artifact_from_manifest(manifest).fingerprint
        structured = self._connection.execute(
            "SELECT 1 FROM rebuild_structured_artifacts WHERE manifest_id = ?",
            (manifest.manifest_id,),
        ).fetchone()
        if structured is not None:
            return self._artifact_from_manifest(manifest).fingerprint
        stable_members = [
            {
                "role": member.object_type,
                "media_type": member.media_type,
                "object_sha256": member.object_sha256,
                "source_lineage_hashes": list(member.source_lineage_hashes),
            }
            for member in manifest.members
        ]
        content_sha256 = canonical_sha256(
            {
                "domain": "consultation_kb.rebuild_existing_content.v1",
                "artifact_key": manifest.artifact_key,
                "artifact_kind": manifest.artifact_kind,
                "members": stable_members,
            }
        )
        return ArtifactFingerprint(
            artifact_key=manifest.artifact_key,
            version=manifest.source_version,
            content_sha256=content_sha256,
            semantic_fingerprint_sha256=canonical_sha256(
                {
                    "domain": "consultation_kb.rebuild_existing_semantics.v1",
                    "artifact_key": manifest.artifact_key,
                    "artifact_kind": manifest.artifact_kind,
                    "members": stable_members,
                }
            ),
        )

    def _read_tombstone_epoch(self) -> int:
        row = self._connection.execute(
            "SELECT tombstone_epoch FROM deletion_authority_state "
            "WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_INVALID")
        return int(row[0])


def output_manifest_set_sha256_for_artifacts(
    artifacts: Sequence[BuiltArtifact],
) -> str:
    """Internal spelling that avoids shadowing the activation argument."""

    return output_manifest_set_sha256(artifacts)


class RebuildCoordinator:
    """Plan quickly, queue durably, then build and atomically activate in worker time."""

    def __init__(
        self,
        *,
        registry: BuilderRegistry,
        jobs: RebuildJobRepository,
        authority: RebuildAuthoritySource,
        artifact_store: RebuildArtifactStore,
        builders: Mapping[str, ArtifactBuilder],
        case_index_intent_set_sha256: Callable[[], str] | None = None,
    ) -> None:
        self._registry = registry
        self._jobs = jobs
        self._authority = authority
        self._artifact_store = artifact_store
        self._builders = dict(builders)
        self._case_index_intent_set_sha256 = case_index_intent_set_sha256

    def _case_intent_set_sha256(self, database_scope: DatabaseScope) -> str:
        if database_scope != "global" or self._case_index_intent_set_sha256 is None:
            return EMPTY_CASE_INDEX_INTENT_SET_SHA256
        value = self._case_index_intent_set_sha256()
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_INTENT_SET_INVALID"
            )
        return value

    def plan(self, request: RebuildRequest) -> RebuildPlan:
        exact = RebuildRequest.model_validate(request)
        descriptors = self._registry.plan(
            database_scope=exact.database_scope,
            purpose=exact.purpose,
        )
        self._registry.validate_bindings(
            database_scope=exact.database_scope,
            purpose=exact.purpose,
            policy_sha256=exact.policy_sha256,
            model_descriptor_sha256=exact.model_descriptor_sha256,
        )
        sources = _ordered_sources(descriptors)
        inventory = AuthorityInventory.model_validate(
            self._authority.inventory(
                database_scope=exact.database_scope,
                scope_sha256=exact.scope_sha256,
                sources=sources,
            )
        )
        self._assert_inventory(
            inventory=inventory,
            database_scope=exact.database_scope,
            scope_sha256=exact.scope_sha256,
            sources=sources,
        )
        values: dict[str, object] = {
            "database_scope": exact.database_scope,
            "source_intent_id": exact.source_intent_id,
            "scope_sha256": exact.scope_sha256,
            "purpose": exact.purpose,
            "builder_ids": tuple(value.builder_id for value in descriptors),
            "builder_dag_sha256": self._registry.dag_sha256(
                database_scope=exact.database_scope,
                purpose=exact.purpose,
            ),
            "input_authority_versions_sha256": (
                inventory.input_authority_versions_sha256
            ),
            "case_index_intent_set_sha256": self._case_intent_set_sha256(
                exact.database_scope
            ),
            "tombstone_epoch": inventory.tombstone_epoch,
            "policy_sha256": exact.policy_sha256,
            "model_descriptor_sha256": exact.model_descriptor_sha256,
        }
        values["plan_sha256"] = canonical_sha256(
            _plan_payload(
                database_scope=exact.database_scope,
                source_intent_id=exact.source_intent_id,
                scope_sha256=exact.scope_sha256,
                purpose=exact.purpose,
                builder_ids=tuple(value.builder_id for value in descriptors),
                builder_dag_sha256=str(values["builder_dag_sha256"]),
                input_authority_versions_sha256=(
                    inventory.input_authority_versions_sha256
                ),
                case_index_intent_set_sha256=str(
                    values["case_index_intent_set_sha256"]
                ),
                tombstone_epoch=inventory.tombstone_epoch,
                policy_sha256=exact.policy_sha256,
                model_descriptor_sha256=exact.model_descriptor_sha256,
            )
        )
        return RebuildPlan.model_validate(values)

    def start(
        self,
        plan: RebuildPlan,
        *,
        idempotency_key: str,
        approval_operation_id: str | None = None,
        approval_request_id: str | None = None,
    ) -> RebuildJob:
        exact = RebuildPlan.model_validate(plan)
        self.assert_executable(exact)
        return self._jobs.enqueue(
            self._job_create(
                exact,
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
            ),
            idempotency_key=idempotency_key,
        )

    def start_in_transaction(
        self,
        plan: RebuildPlan,
        *,
        idempotency_key: str,
        approval_operation_id: str | None = None,
        approval_request_id: str | None = None,
    ) -> RebuildJob:
        """Atomically enqueue inside an existing P1 target transaction."""

        exact = RebuildPlan.model_validate(plan)
        self.assert_executable(exact)
        return self._jobs.enqueue_in_transaction(
            self._job_create(
                exact,
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
            ),
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _job_create(
        plan: RebuildPlan,
        *,
        approval_operation_id: str | None,
        approval_request_id: str | None,
    ) -> RebuildJobCreate:
        return RebuildJobCreate(
            database_scope=plan.database_scope,
            source_intent_id=plan.source_intent_id,
            approval_operation_id=approval_operation_id,
            approval_request_id=approval_request_id,
            plan_sha256=plan.plan_sha256,
            scope_sha256=plan.scope_sha256,
            purpose=plan.purpose,
            builder_dag_sha256=plan.builder_dag_sha256,
            input_authority_versions_sha256=(
                plan.input_authority_versions_sha256
            ),
            policy_sha256=plan.policy_sha256,
            model_descriptor_sha256=plan.model_descriptor_sha256,
            tombstone_epoch=plan.tombstone_epoch,
        )

    def assert_executable(self, plan: RebuildPlan) -> None:
        """Prove every persisted builder can be resolved before enqueue.

        A queued job is an operational promise that a background process can
        resume after an MCP disconnect or process restart.  Persisting a plan
        backed only by declaration metadata would violate that promise, so the
        exact production adapters are checked before the durable row exists.
        """

        exact = RebuildPlan.model_validate(plan)
        descriptors = self._registry.plan(
            database_scope=exact.database_scope,
            purpose=exact.purpose,
        )
        if tuple(value.builder_id for value in descriptors) != exact.builder_ids:
            raise RebuildCoordinatorError("REBUILD_PLAN_REGISTRY_CHANGED")
        if self._registry.dag_sha256(
            database_scope=exact.database_scope,
            purpose=exact.purpose,
        ) != exact.builder_dag_sha256:
            raise RebuildCoordinatorError("REBUILD_PLAN_REGISTRY_CHANGED")
        if self._case_intent_set_sha256(exact.database_scope) != (
            exact.case_index_intent_set_sha256
        ):
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_INTENT_SET_CHANGED"
            )
        self._registry.validate_bindings(
            database_scope=exact.database_scope,
            purpose=exact.purpose,
            policy_sha256=exact.policy_sha256,
            model_descriptor_sha256=exact.model_descriptor_sha256,
        )
        for descriptor in descriptors:
            builder = self._builders.get(descriptor.builder_id)
            if builder is None or builder.descriptor != descriptor:
                raise RebuildCoordinatorError("REBUILD_BUILDER_UNAVAILABLE")

    def recover_interrupted(self) -> tuple[str, ...]:
        return self._jobs.recover_interrupted()

    def run_next(self) -> RebuildJob | None:
        job = self._jobs.claim_next()
        if job is None:
            return None
        if job.state == "activating":
            return self._resume_activation(job)
        if job.state != "running":
            raise RebuildCoordinatorError("REBUILD_JOB_NOT_RUNNABLE")
        return self._run_build(job)

    def _run_build(self, job: RebuildJob) -> RebuildJob:
        stage_ref: str | None = None
        try:
            descriptors = self._registry.plan(
                database_scope=job.database_scope,
                purpose=job.purpose,
            )
            if self._registry.dag_sha256(
                database_scope=job.database_scope,
                purpose=job.purpose,
            ) != job.builder_dag_sha256:
                raise RebuildCoordinatorError("REBUILD_BUILDER_DAG_CHANGED")
            if rebuild_job_plan_sha256(
                job,
                registry=self._registry,
                case_index_intent_set_sha256=self._case_intent_set_sha256(
                    job.database_scope
                ),
            ) != job.plan_sha256:
                raise RebuildCoordinatorError(
                    "REBUILD_CASE_INDEX_INTENT_SET_CHANGED"
                )
            self._registry.validate_bindings(
                database_scope=job.database_scope,
                purpose=job.purpose,
                policy_sha256=job.policy_sha256,
                model_descriptor_sha256=job.model_descriptor_sha256,
            )
            sources = _ordered_sources(descriptors)
            inventory = AuthorityInventory.model_validate(
                self._authority.resolve_exact(
                    database_scope=job.database_scope,
                    scope_sha256=job.scope_sha256,
                    input_authority_versions_sha256=(
                        job.input_authority_versions_sha256
                    ),
                    tombstone_epoch=job.tombstone_epoch,
                    sources=sources,
                )
            )
            self._assert_inventory(
                inventory=inventory,
                database_scope=job.database_scope,
                scope_sha256=job.scope_sha256,
                sources=sources,
            )
            if (
                inventory.input_authority_versions_sha256
                != job.input_authority_versions_sha256
                or inventory.tombstone_epoch != job.tombstone_epoch
            ):
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_SNAPSHOT_CHANGED")
            records_by_source = self._read_authority_records(inventory)
            output_purposes = tuple(
                descriptor.output_purpose for descriptor in descriptors
            )
            stage_ref = self._artifact_store.begin_empty_stage(
                job_id=job.job_id,
                output_purposes=output_purposes,
                tombstone_epoch=job.tombstone_epoch,
            )
            built_by_id: dict[str, BuiltArtifact] = {}
            authority_version_by_key = {
                value.source.key: value for value in inventory.versions
            }
            for descriptor in descriptors:
                builder = self._builders.get(descriptor.builder_id)
                if builder is None or builder.descriptor != descriptor:
                    raise RebuildCoordinatorError("REBUILD_BUILDER_UNAVAILABLE")
                authority_records = tuple(
                    sorted(
                        (
                            record
                            for source in descriptor.authority_sources
                            for record in records_by_source[source.key]
                        ),
                        key=lambda value: (
                            value.source.key,
                            value.object_id,
                            value.version,
                            value.content_sha256,
                        ),
                    )
                )
                dependencies = tuple(
                    built_by_id[dependency]
                    for dependency in descriptor.dependencies
                )
                artifact = builder.build(
                    BuildContext(
                        job=job,
                        descriptor=descriptor,
                        authority_versions=tuple(
                            authority_version_by_key[source.key]
                            for source in descriptor.authority_sources
                        ),
                        authority_records=authority_records,
                        dependency_artifacts=dependencies,
                        policy_sha256=job.policy_sha256,
                        model_descriptor_sha256=job.model_descriptor_sha256,
                        tombstone_epoch=job.tombstone_epoch,
                    )
                )
                if (
                    not isinstance(artifact, BuiltArtifact)
                    or artifact.builder_id != descriptor.builder_id
                    or artifact.output_purpose != descriptor.output_purpose
                ):
                    raise RebuildCoordinatorError("REBUILD_BUILDER_OUTPUT_INVALID")
                built_by_id[descriptor.builder_id] = artifact
                self._artifact_store.stage_artifact(
                    stage_ref=stage_ref,
                    artifact=artifact,
                )
                if self._jobs.get(job.job_id).state == "cancelled":
                    self._artifact_store.discard_stage(stage_ref=stage_ref)
                    return self._jobs.get(job.job_id)
            self._jobs.mark_verifying(job.job_id)
            verification = StageVerification.model_validate(
                self._artifact_store.verify_stage(
                    stage_ref=stage_ref,
                    output_purposes=output_purposes,
                    tombstone_epoch=job.tombstone_epoch,
                )
            )
            artifacts = tuple(
                built_by_id[descriptor.builder_id]
                for descriptor in descriptors
            )
            expected_manifest_sha256 = output_manifest_set_sha256(artifacts)
            report_keys = tuple(
                item.artifact_key for item in verification.equivalence_report.items
            )
            if (
                not verification.closure_valid
                or verification.artifact_count != len(artifacts)
                or verification.output_manifest_set_sha256
                != expected_manifest_sha256
                or set(report_keys)
                != {artifact.output_purpose for artifact in artifacts}
                or not verification.equivalence_report.activation_eligible
            ):
                raise RebuildCoordinatorError("REBUILD_STAGE_VERIFICATION_FAILED")
            if (
                self._authority.current_tombstone_epoch(
                    database_scope=job.database_scope,
                    scope_sha256=job.scope_sha256,
                )
                != job.tombstone_epoch
            ):
                raise RebuildCoordinatorError("REBUILD_TOMBSTONE_EPOCH_CHANGED")
            self._jobs.mark_activating(
                job.job_id,
                output_manifest_set_sha256=expected_manifest_sha256,
                equivalence_report_sha256=(
                    verification.equivalence_report.report_sha256
                ),
            )
            receipt = ActivationReceipt.model_validate(
                self._artifact_store.activate_atomically(
                    stage_ref=stage_ref,
                    output_manifest_set_sha256=expected_manifest_sha256,
                    tombstone_epoch=job.tombstone_epoch,
                )
            )
            self._validate_activation_receipt(job, expected_manifest_sha256, receipt)
            return self._jobs.mark_succeeded(job.job_id)
        except Exception as exc:
            current = self._jobs.get(job.job_id)
            if stage_ref is not None and current.state != "activating":
                self._artifact_store.discard_stage(stage_ref=stage_ref)
            if current.state in {"queued", "running", "verifying"}:
                code = (
                    exc.code
                    if isinstance(exc, RebuildCoordinatorError)
                    else "REBUILD_BUILD_FAILED"
                )
                return self._jobs.mark_failed(job.job_id, error_code=code)
            if current.state in {"failed", "cancelled"}:
                return current
            # Once activation begins, an exception may mean the switch committed
            # but its acknowledgement was lost.  Leave the job activating so a
            # fresh process can invoke the store's idempotent activation path.
            raise

    def _resume_activation(self, job: RebuildJob) -> RebuildJob:
        if (
            job.output_manifest_set_sha256 is None
            or job.equivalence_report_sha256 is None
        ):
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_PROOF_MISSING")
        stage_ref = self._artifact_store.resume_stage(job_id=job.job_id)
        receipt = ActivationReceipt.model_validate(
            self._artifact_store.activate_atomically(
                stage_ref=stage_ref,
                output_manifest_set_sha256=job.output_manifest_set_sha256,
                tombstone_epoch=job.tombstone_epoch,
            )
        )
        self._validate_activation_receipt(
            job,
            job.output_manifest_set_sha256,
            receipt,
        )
        return self._jobs.mark_succeeded(job.job_id)

    def _read_authority_records(
        self, inventory: AuthorityInventory
    ) -> dict[str, tuple[AuthorityRecord, ...]]:
        expected = tuple(value.source.key for value in inventory.versions)
        raw = self._authority.read_exact(inventory)
        if set(raw) != set(expected):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_READ_CLOSURE_MISMATCH")
        result: dict[str, tuple[AuthorityRecord, ...]] = {}
        for version in inventory.versions:
            values = tuple(raw[version.source.key])
            if any(
                not isinstance(record, AuthorityRecord)
                or record.source != version.source
                for record in values
            ):
                raise RebuildCoordinatorError("REBUILD_AUTHORITY_RECORD_INVALID")
            if (
                authority_source_snapshot_sha256(version.source, values)
                != version.snapshot_sha256
            ):
                raise RebuildCoordinatorError(
                    "REBUILD_AUTHORITY_SOURCE_HASH_MISMATCH"
                )
            result[version.source.key] = tuple(
                record
                for record in values
                if record.approved and record.active and not record.tombstoned
            )
        return result

    @staticmethod
    def _assert_inventory(
        *,
        inventory: AuthorityInventory,
        database_scope: DatabaseScope,
        scope_sha256: str,
        sources: tuple[AuthoritySourceSpec, ...],
    ) -> None:
        if (
            inventory.database_scope != database_scope
            or inventory.scope_sha256 != scope_sha256
            or tuple(value.source for value in inventory.versions) != sources
        ):
            raise RebuildCoordinatorError("REBUILD_AUTHORITY_INVENTORY_MISMATCH")

    @staticmethod
    def _validate_activation_receipt(
        job: RebuildJob,
        expected_manifest_sha256: str,
        receipt: ActivationReceipt,
    ) -> None:
        if (
            receipt.output_manifest_set_sha256 != expected_manifest_sha256
            or receipt.tombstone_epoch != job.tombstone_epoch
        ):
            raise RebuildCoordinatorError("REBUILD_ACTIVATION_RECEIPT_MISMATCH")


def _ordered_sources(
    descriptors: Sequence[BuilderDescriptor],
) -> tuple[AuthoritySourceSpec, ...]:
    by_key = {
        source.key: source
        for descriptor in descriptors
        for source in descriptor.authority_sources
    }
    return tuple(by_key[key] for key in sorted(by_key))


__all__ = [
    "ActivationReceipt",
    "ArtifactBuilder",
    "AuthorityInventory",
    "AuthorityRecord",
    "AuthorityVersionRef",
    "BuildContext",
    "BuiltArtifact",
    "RebuildArtifactStore",
    "RebuildAuthoritySource",
    "RebuildCoordinator",
    "RebuildCoordinatorError",
    "RebuildPlan",
    "RebuildRequest",
    "SqliteCasRebuildArtifactStore",
    "SqliteRebuildAuthoritySource",
    "StageVerification",
    "authority_inventory_sha256",
    "authority_source_snapshot_sha256",
    "output_manifest_set_sha256",
]
