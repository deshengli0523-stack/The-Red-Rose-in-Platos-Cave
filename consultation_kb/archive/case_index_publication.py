"""Approval-bound durable publication and replay of governed case indexes.

``CaseIndexingService`` deliberately produces an in-memory derivation.  This
module is the production boundary: one P1 approval binds the complete CAS
manifest, every provenance row is made durable, and replay is accepted only
from the exact active manifest and live case authority.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, cast

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.archive.case_indexing import (
    CaseIndexArtifact,
    CaseIndexBundle,
    CaseIndexRootAuthority,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PreparedArtifactDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.models.cases import (
    CaseArtifactKind,
    CaseProvenanceRecord,
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    ReviewCategory,
)
from consultation_kb.models.common import (
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.retrieval.contracts import (
    CandidateRef,
    candidate_capability_payload,
)
from consultation_kb.retrieval.filters import assert_case_index_text_safe
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.case_index_serialization import (
    CaseIndexPublicationError,
    CaseIndexRebuildIdentity,
    CaseIndexRebuildIntent,
    CaseIndexRebuildSnapshot,
    invalidate_pending_case_indexes_in_transaction,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestMember,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
    lineage_hash,
    target_hash,
)
from consultation_kb.vault.content_store import ContentStore, ContentStoreError


_PIPELINE_KINDS: tuple[CaseArtifactKind, ...] = (
    "case",
    "case_pattern",
    "claim",
    "wiki_section",
    "graph_edge",
    "lexical_row",
    "vector_row",
)
_DESCRIPTOR_KIND = "case_index_descriptor"
_MANIFEST_KIND = "case_index"
_PURPOSE: Literal["case_publish"] = "case_publish"


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CaseIndexPublicationError("CASE_INDEX_TIMESTAMP_INVALID")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise CaseIndexPublicationError("CASE_INDEX_AUTHORITY_ROW_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CaseIndexPublicationError(
            "CASE_INDEX_AUTHORITY_ROW_INVALID"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise CaseIndexPublicationError("CASE_INDEX_AUTHORITY_ROW_INVALID")
    return parsed


def _json_set(value: object) -> frozenset[str]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise CaseIndexPublicationError(
            "CASE_INDEX_AUTHORITY_ROW_INVALID"
        ) from None
    if (
        type(decoded) is not list
        or any(type(item) is not str or not item for item in decoded)
        or decoded != sorted(set(decoded))
    ):
        raise CaseIndexPublicationError("CASE_INDEX_AUTHORITY_ROW_INVALID")
    return frozenset(decoded)


def _object_type(reference: VersionRef) -> str:
    identifier = reference.object_id
    if len(identifier) <= 37 or identifier[-37] != "_":
        raise CaseIndexPublicationError("CASE_INDEX_OBJECT_ID_INVALID")
    return identifier[:-37]


def _manifest_ref(manifest: ArtifactManifest) -> VersionRef:
    return VersionRef(
        object_id=manifest.manifest_id,
        version=manifest.source_version,
        content_sha256=manifest.manifest_sha256,
    )


class CaseIndexReplayArtifact(StrictModel):
    """Text-free artifact metadata stored in the approved replay descriptor."""

    artifact_ref: VersionRef
    artifact_kind: CaseArtifactKind
    content_ref: VersionRef
    statement_scope: Literal["case_record", "reviewed_case_pattern"]
    provenance_ref: VersionRef
    authorization_refs: tuple[VersionRef, ...]
    review_ref: VersionRef
    release_decision_sha256: Sha256Hex
    allowed_uses: frozenset[SafePolicyKey]
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None = None
    source_catalog_version: PositiveInt
    candidate_template: CandidateRef | None = None

    @field_serializer("allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("authorization_refs")
    @classmethod
    def _canonical_authorizations(
        cls, value: tuple[VersionRef, ...]
    ) -> tuple[VersionRef, ...]:
        keys = tuple(
            (item.object_id, item.version, item.content_sha256) for item in value
        )
        if not value or len(keys) != len(set(keys)):
            raise ValueError("case index authorization closure is invalid")
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

    @model_validator(mode="after")
    def _template_is_unbound(self) -> "CaseIndexReplayArtifact":
        template = self.candidate_template
        if template is not None and (
            template.filter_binding is not None
            or template.reference != self.artifact_ref
            or template.content_ref != self.content_ref
            or template.object_type != self.artifact_kind
        ):
            raise ValueError("case index candidate template is invalid")
        return self

    @classmethod
    def from_artifact(cls, value: CaseIndexArtifact) -> "CaseIndexReplayArtifact":
        exact = CaseIndexArtifact.model_validate(value)
        return cls(
            artifact_ref=exact.artifact_ref,
            artifact_kind=exact.artifact_kind,
            content_ref=exact.content_ref,
            statement_scope=exact.statement_scope,
            provenance_ref=exact.provenance.provenance_ref,
            authorization_refs=exact.authorization_refs,
            review_ref=exact.review_ref,
            release_decision_sha256=exact.release_decision_sha256,
            allowed_uses=exact.allowed_uses,
            effective_from=exact.effective_from,
            effective_to=exact.effective_to,
            source_catalog_version=exact.source_catalog_version,
            candidate_template=exact.candidate,
        )


class CaseIndexReplayDescriptor(StrictModel):
    """Canonical, text-free recipe for deterministic restart/rebuild replay."""

    schema_version: Literal["case_index_replay.v1"] = "case_index_replay.v1"
    manifest_id: ObjectId
    artifact_key: SafePolicyKey
    root_case_ref: VersionRef
    source_authority_manifest_ref: VersionRef
    artifacts: tuple[CaseIndexReplayArtifact, ...]

    @field_validator("artifacts")
    @classmethod
    def _complete_pipeline(
        cls, value: tuple[CaseIndexReplayArtifact, ...]
    ) -> tuple[CaseIndexReplayArtifact, ...]:
        if tuple(item.artifact_kind for item in value) != _PIPELINE_KINDS:
            raise ValueError("case index replay pipeline is incomplete")
        return value

    @model_validator(mode="after")
    def _root_and_templates(self) -> "CaseIndexReplayDescriptor":
        if self.artifacts[0].artifact_ref != self.root_case_ref:
            raise ValueError("case index replay root does not match")
        if any(
            item.candidate_template is not None
            and item.candidate_template.metadata.manifest_ref
            != self.source_authority_manifest_ref
            for item in self.artifacts
        ):
            raise ValueError("case index source authority manifest does not match")
        return self


@dataclass(frozen=True, slots=True)
class CaseIndexPublicationPlan:
    operation_id: str
    descriptor: DraftDescriptor
    authority_base_version: int
    expected_current_epoch: int | None
    manifest_id: str
    replay_descriptor_ref: VersionRef
    artifacts: tuple[PreparedArtifactDraft, ...]
    bundle: CaseIndexBundle


class CaseIndexPublication(StrictModel):
    manifest_ref: VersionRef
    replay_descriptor_ref: VersionRef
    root_case_ref: VersionRef
    rebuild_queue_id: ObjectId
    catalog_version: PositiveInt
    candidates: tuple[CandidateRef, ...]


class SqliteCaseIndexAuthorityResolver:
    """Resolve one exact active v0005 case authority without opening its body."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("case index authority requires SQLite")
        self._connection = connection
        self._clock = clock if clock is not None else SystemClock()

    def resolve_case_index_authority(
        self,
        *,
        case_ref: VersionRef,
        authority_manifest_ref: VersionRef,
    ) -> CaseIndexRootAuthority | None:
        case = VersionRef.model_validate(case_ref)
        requested_manifest = VersionRef.model_validate(authority_manifest_ref)
        rows = self._connection.execute(
            """
            SELECT cv.candidate_id, cv.candidate_version, cv.candidate_sha256,
                   cv.release_decision_sha256, cv.allowed_uses_json,
                   cv.manifest_id, manifest.source_version,
                   manifest.manifest_sha256,
                   ca.authorization_id, ca.authorization_version,
                   ca.authorization_sha256, ca.contributor_client_hash,
                   ca.reuse_authorized, ca.allowed_uses_json, ca.valid_from,
                   ca.expires_at, ca.revoked_at, ca.terms_sha256,
                   review.review_id, review.review_version, review.review_sha256,
                   review.candidate_sha256, review.decision,
                   review.checked_categories_json, review.residual_risk,
                   review.rare_combination_disposition,
                   review.allowed_uses_json,
                   review.reviewer_attestation_sha256,
                   review.release_policy_id, review.release_policy_version,
                   review.release_policy_sha256, review.reviewed_at,
                   review.evaluated_at, cases.state, cv.state, cv.version
              FROM cases
              JOIN case_versions AS cv
                ON cv.case_id = cases.case_id
               AND cv.version = cases.current_version
              JOIN case_authorizations AS ca
                ON ca.case_id = cv.case_id AND ca.case_version = cv.version
              JOIN case_review_decisions AS review
                ON review.case_id = cv.case_id
               AND review.case_version = cv.version
              JOIN artifact_manifests AS manifest
                ON manifest.manifest_id = cv.manifest_id
              JOIN publication_operations AS operation
                ON operation.operation_id = manifest.operation_id
             WHERE cases.case_id = ? AND cases.current_version = ?
               AND cv.global_content_sha256 = ?
               AND manifest.state = 'VERIFIED' AND manifest.verified = 1
               AND manifest.artifact_kind = 'shared_case'
               AND operation.purpose = 'case_publish'
               AND operation.state = 'VERIFIED'
               AND operation.runtime_epoch IS NULL
               AND operation.activated_at IS NULL
               AND NOT EXISTS(
                   SELECT 1 FROM active_artifacts AS standalone
                    WHERE standalone.manifest_id = manifest.manifest_id
               )
            """,
            (case.object_id, case.version, case.content_sha256),
        ).fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        try:
            manifest_ref = VersionRef(
                object_id=str(row[5]),
                version=int(str(row[6])),
                content_sha256=str(row[7]),
            )
            if manifest_ref != requested_manifest:
                return None
            authorization = CaseReuseAuthorization(
                authorization_ref=VersionRef(
                    object_id=str(row[8]),
                    version=int(str(row[9])),
                    content_sha256=str(row[10]),
                ),
                contributor_client_hash=str(row[11]),
                reuse_authorized=bool(int(row[12])),
                allowed_uses=_json_set(row[13]),
                valid_from=_parse_utc(row[14]),
                expires_at=None if row[15] is None else _parse_utc(row[15]),
                revoked_at=None if row[16] is None else _parse_utc(row[16]),
                terms_sha256=str(row[17]),
            )
            review = DeidentificationHumanReview(
                review_ref=VersionRef(
                    object_id=str(row[18]),
                    version=int(str(row[19])),
                    content_sha256=str(row[20]),
                ),
                candidate_sha256=str(row[21]),
                decision=cast(Literal["approved", "rejected", "quarantine"], str(row[22])),
                checked_categories=cast(
                    frozenset[ReviewCategory], _json_set(row[23])
                ),
                residual_risk=cast(Literal["low", "medium", "high"], str(row[24])),
                rare_combination_disposition=cast(
                    Literal["not_present", "mitigated", "unresolved"],
                    str(row[25]),
                ),
                allowed_uses=_json_set(row[26]),
                reviewer_attestation_sha256=str(row[27]),
                reviewed_at=_parse_utc(row[31]),
            )
            release = CaseReleaseDecision(
                candidate_sha256=str(row[21]),
                outcome="eligible",
                reasons=(),
                authorization_ref=authorization.authorization_ref,
                review_ref=review.review_ref,
                policy_ref=VersionRef(
                    object_id=str(row[28]),
                    version=int(str(row[29])),
                    content_sha256=str(row[30]),
                ),
                allowed_uses=_json_set(row[4]),
                evaluated_at=_parse_utc(row[32]),
            )
            if canonical_sha256(release.model_dump(mode="json")) != str(row[3]):
                return None
            now = self._clock.now()
            state: Literal["active", "revoked"] = (
                "active"
                if str(row[33]) == str(row[34]) == "ACTIVE"
                and authorization.reuse_authorized
                and authorization.valid_from <= now
                and (
                    authorization.expires_at is None
                    or now < authorization.expires_at
                )
                and (
                    authorization.revoked_at is None
                    or now < authorization.revoked_at
                )
                else "revoked"
            )
            return CaseIndexRootAuthority(
                case_ref=case,
                source_candidate_ref=VersionRef(
                    object_id=str(row[0]),
                    version=int(str(row[1])),
                    content_sha256=str(row[2]),
                ),
                authorization=authorization,
                review=review,
                release_decision=release,
                authority_manifest_ref=manifest_ref,
                source_catalog_version=int(str(row[35])),
                state=state,
            )
        except (CaseIndexPublicationError, TypeError, ValueError):
            return None


class CaseIndexPublicationService:
    """Plan, approve, publish, and recover one exact case-index closure."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        approval_service: ApprovalService,
        execution_guard: ApprovalExecutionGuard,
        id_factory: IdFactory,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("case index publication requires SQLite")
        if type(content_store) is not ContentStore:
            raise TypeError("case index publication requires ContentStore")
        if not isinstance(approval_service, ApprovalService):
            raise TypeError("case index publication requires ApprovalService")
        if not isinstance(execution_guard, ApprovalExecutionGuard):
            raise TypeError("case index publication requires ApprovalExecutionGuard")
        if getattr(execution_guard, "_connection", None) is not connection:
            raise CaseIndexPublicationError("CASE_INDEX_APPROVAL_SCOPE_MISMATCH")
        if not isinstance(id_factory, IdFactory):
            raise TypeError("case index publication requires IdFactory")
        self._connection = connection
        self._store = content_store
        self._approvals = approval_service
        self._guard = execution_guard
        self._ids = id_factory
        self._clock = clock if clock is not None else SystemClock()
        self._coordinator = PublishCoordinator(
            connection,
            content_store,
            VisibilityGuard(TombstoneRepository(connection, clock=self._clock)),
            clock=self._clock,
        )

    def plan(self, bundle: CaseIndexBundle) -> CaseIndexPublicationPlan:
        if self._connection.in_transaction:
            raise CaseIndexPublicationError("CASE_INDEX_PLAN_TRANSACTION_OPEN")
        exact = CaseIndexBundle.model_validate(bundle)
        self._assert_text_free_of_authority_hashes(exact)
        source_body, source_manifest = self._source_case_body(exact)
        authority_version, expected_epoch = self._next_publication_identity()
        operation_id = self._ids.object_id("case_index_operation")
        manifest_id = self._ids.object_id("case_index_manifest")
        artifact_key = self._artifact_key(exact.root_case_ref)
        replay = CaseIndexReplayDescriptor(
            manifest_id=manifest_id,
            artifact_key=artifact_key,
            root_case_ref=exact.root_case_ref,
            source_authority_manifest_ref=source_manifest,
            artifacts=tuple(
                CaseIndexReplayArtifact.from_artifact(item)
                for item in exact.artifacts
            ),
        )
        replay_bytes = canonical_json_bytes(replay.model_dump(mode="json"))
        replay_ref = VersionRef(
            object_id=self._ids.object_id(_DESCRIPTOR_KIND),
            version=authority_version,
            content_sha256=hashlib.sha256(replay_bytes).hexdigest(),
        )
        lineage = (ObjectIdentity("case", exact.root_case_ref.object_id),)
        members: list[ContentDraft] = [
            ContentDraft(
                object_type="case",
                object_id=exact.root_case_ref.object_id,
                data=source_body,
                source_version=authority_version,
                media_type="application/json",
                source_lineage=lineage,
            )
        ]
        seen = {exact.root_case_ref.object_id}
        for artifact in exact.artifacts:
            if artifact.content_ref.object_id in seen:
                if artifact.content_ref != exact.root_case_ref:
                    raise CaseIndexPublicationError(
                        "CASE_INDEX_MEMBER_ID_CONFLICT"
                    )
                continue
            body = artifact.rendered_text.encode("utf-8", errors="strict")
            if hashlib.sha256(body).hexdigest() != artifact.content_ref.content_sha256:
                raise CaseIndexPublicationError("CASE_INDEX_CONTENT_HASH_MISMATCH")
            members.append(
                ContentDraft(
                    object_type=_object_type(artifact.content_ref),
                    object_id=artifact.content_ref.object_id,
                    data=body,
                    source_version=authority_version,
                    media_type="text/plain",
                    source_lineage=lineage,
                )
            )
            seen.add(artifact.content_ref.object_id)
        if replay_ref.object_id in seen:
            raise CaseIndexPublicationError("CASE_INDEX_MEMBER_ID_CONFLICT")
        members.append(
            ContentDraft(
                object_type=_DESCRIPTOR_KIND,
                object_id=replay_ref.object_id,
                data=replay_bytes,
                source_version=authority_version,
                media_type="application/json",
                source_lineage=lineage,
            )
        )
        draft = ArtifactDraft(
            manifest_id=manifest_id,
            artifact_key=artifact_key,
            artifact_kind=_MANIFEST_KIND,
            source_version=authority_version,
            members=tuple(members),
        )
        prepared = self._coordinator.stage_artifacts(
            purpose=_PURPOSE,
            artifacts=(draft,),
        )
        closure = publication_closure_sha256(
            purpose=_PURPOSE,
            authority_base_version=authority_version,
            expected_current_epoch=expected_epoch,
            artifacts=prepared,
        )
        descriptor = DraftDescriptor(
            purpose=_PURPOSE,
            target_id=exact.root_case_ref.object_id,
            base_version=authority_version - 1,
            draft_sha256=closure,
        )
        return CaseIndexPublicationPlan(
            operation_id=operation_id,
            descriptor=descriptor,
            authority_base_version=authority_version,
            expected_current_epoch=expected_epoch,
            manifest_id=manifest_id,
            replay_descriptor_ref=replay_ref,
            artifacts=prepared,
            bundle=exact,
        )

    def execute(
        self,
        plan: CaseIndexPublicationPlan,
        *,
        approval_request_id: str,
    ) -> CaseIndexPublication:
        if type(plan) is not CaseIndexPublicationPlan:
            raise TypeError("case index publication plan required")
        closure = publication_closure_sha256(
            purpose=_PURPOSE,
            authority_base_version=plan.authority_base_version,
            expected_current_epoch=plan.expected_current_epoch,
            artifacts=plan.artifacts,
        )
        if closure != plan.descriptor.draft_sha256:
            raise CaseIndexPublicationError("CASE_INDEX_PLAN_CLOSURE_MISMATCH")
        ticket = self._approvals.issue_for_execution(
            approval_request_id,
            plan.descriptor,
            operation_id=plan.operation_id,
        )

        def persist(_connection: sqlite3.Connection) -> object:
            operation = self._coordinator.prepare(
                operation_id=plan.operation_id,
                purpose=_PURPOSE,
                authority_base_version=plan.authority_base_version,
                approval_request_id=approval_request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=plan.expected_current_epoch,
                artifacts=plan.artifacts,
            )
            self._persist_ledger(plan)
            return operation

        proof = self._guard.apply_in_transaction(ticket, plan.descriptor, persist)
        self._approvals.acknowledge(proof)
        self._coordinator.verify(plan.operation_id)
        queue_id, catalog_version = self._ensure_rebuild_intent(plan)
        return self._result(
            manifest_id=plan.manifest_id,
            source_version=plan.authority_base_version,
            queue_id=queue_id,
            catalog_version=catalog_version,
            replay_descriptor_ref=plan.replay_descriptor_ref,
        )

    def recover(self, operation_id: str) -> CaseIndexPublication:
        """Finish the exact committed publication after a process restart.

        The approval execution and ledger PREPARE share one transaction.  Once
        either is visible, reissuing the same ticket can only attest that exact
        APPLIED row; the callback below must never run on recovery.
        """

        row = self._connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, required_manifests_json, state, runtime_epoch "
            "FROM publication_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise CaseIndexPublicationError("CASE_INDEX_RECOVERY_NOT_FOUND")
        try:
            required = json.loads(str(row[4]))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise CaseIndexPublicationError(
                "CASE_INDEX_RECOVERY_INVALID"
            ) from None
        if (
            str(row[0]) != _PURPOSE
            or type(required) is not list
            or len(required) != 1
            or type(required[0]) is not str
            or str(row[5]) not in {"PREPARED", "VERIFIED"}
            or row[6] is not None
        ):
            raise CaseIndexPublicationError("CASE_INDEX_RECOVERY_INVALID")
        request = self._approvals.get(str(row[2]))
        if request.descriptor_sha256 != str(row[3]):
            raise CaseIndexPublicationError("CASE_INDEX_RECOVERY_INVALID")
        ticket = self._approvals.issue_for_execution(
            request.request_id,
            request.descriptor,
            operation_id=operation_id,
        )

        def committed_only(_connection: sqlite3.Connection) -> object:
            raise CaseIndexPublicationError("CASE_INDEX_RECOVERY_WRITE_FORBIDDEN")

        proof = self._guard.apply_in_transaction(
            ticket,
            request.descriptor,
            committed_only,
        )
        self._approvals.acknowledge(proof)
        self._coordinator.verify(operation_id)
        manifest_id = str(required[0])
        manifest = ManifestRepository(self._connection).get(manifest_id)
        if (
            manifest.operation_id != operation_id
            or manifest.source_version != int(str(row[1]))
        ):
            raise CaseIndexPublicationError("CASE_INDEX_RECOVERY_INVALID")
        queue_id, catalog_version = self._ensure_rebuild_intent_identity(
            operation_id=operation_id,
            manifest_id=manifest_id,
            authority_base_version=manifest.source_version,
        )
        descriptor_members = tuple(
            member
            for member in manifest.members
            if member.object_type == _DESCRIPTOR_KIND
        )
        if len(descriptor_members) != 1:
            raise CaseIndexPublicationError("CASE_INDEX_DESCRIPTOR_MISSING")
        descriptor_member = descriptor_members[0]
        return self._result(
            manifest_id=manifest_id,
            source_version=manifest.source_version,
            queue_id=queue_id,
            catalog_version=catalog_version,
            replay_descriptor_ref=VersionRef(
                object_id=descriptor_member.object_id,
                version=descriptor_member.source_version,
                content_sha256=descriptor_member.object_sha256,
            ),
        )

    def _result(
        self,
        *,
        manifest_id: str,
        source_version: int,
        queue_id: str,
        catalog_version: int,
        replay_descriptor_ref: VersionRef,
    ) -> CaseIndexPublication:
        manifest = ManifestRepository(self._connection).get(manifest_id)
        if manifest.source_version != source_version:
            raise CaseIndexPublicationError("CASE_INDEX_MANIFEST_REF_MISMATCH")
        bundle = CaseIndexPublicationRepository(
            self._connection,
            self._store,
            clock=self._clock,
        ).replay_manifest(
            VersionRef(
                object_id=manifest.manifest_id,
                version=manifest.source_version,
                content_sha256=manifest.manifest_sha256,
            ),
        )
        first_candidate = bundle.artifacts[0].candidate
        if first_candidate is None:
            raise CaseIndexPublicationError("CASE_INDEX_ROOT_CANDIDATE_MISSING")
        return CaseIndexPublication(
            manifest_ref=first_candidate.metadata.manifest_ref,
            replay_descriptor_ref=replay_descriptor_ref,
            root_case_ref=bundle.root_case_ref,
            rebuild_queue_id=queue_id,
            catalog_version=catalog_version,
            candidates=bundle.candidates,
        )

    def _next_publication_identity(self) -> tuple[int, int | None]:
        active = self._connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(active) > 1:
            raise CaseIndexPublicationError("CASE_INDEX_RUNTIME_EPOCH_INVALID")
        expected = None if not active else int(active[0][0])
        row = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state "
            "WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise CaseIndexPublicationError("CASE_INDEX_AUTHORITY_VERSION_INVALID")
        return int(row[0]) + 1, expected

    @staticmethod
    def _artifact_key(root: VersionRef) -> str:
        return "case_index_" + hashlib.sha256(
            root.object_id.encode("ascii", errors="strict")
        ).hexdigest()[:32]

    def _source_case_body(
        self, bundle: CaseIndexBundle
    ) -> tuple[bytes, VersionRef]:
        root = bundle.artifacts[0]
        if root.candidate is None:
            raise CaseIndexPublicationError("CASE_INDEX_ROOT_CANDIDATE_MISSING")
        purpose = next(iter(sorted(root.allowed_uses)), None)
        if purpose is None:
            raise CaseIndexPublicationError("CASE_INDEX_SOURCE_CASE_NOT_ACTIVE")
        catalog_record = CaseCatalog(
            self._connection,
            self._store,
            clock=self._clock,
        ).get_active(bundle.root_case_ref.object_id, purpose=purpose)
        if catalog_record is None or catalog_record.case_ref != bundle.root_case_ref:
            raise CaseIndexPublicationError("CASE_INDEX_SOURCE_CASE_NOT_ACTIVE")
        rows = self._connection.execute(
            """
            SELECT cv.global_content_sha256, cv.global_content_media_type,
                   cv.global_content_size_bytes, cv.manifest_id,
                   manifest.source_version, manifest.manifest_sha256
              FROM cases
              JOIN case_versions AS cv
                ON cv.case_id = cases.case_id
               AND cv.version = cases.current_version
              JOIN artifact_manifests AS manifest
                ON manifest.manifest_id = cv.manifest_id
              JOIN publication_operations AS operation
                ON operation.operation_id = manifest.operation_id
             WHERE cases.case_id = ? AND cases.current_version = ?
               AND cases.state = 'ACTIVE' AND cv.state = 'ACTIVE'
               AND cv.global_content_sha256 = ?
               AND manifest.state = 'VERIFIED' AND manifest.verified = 1
               AND manifest.artifact_kind = 'shared_case'
               AND operation.purpose = 'case_publish'
               AND operation.state = 'VERIFIED'
               AND operation.runtime_epoch IS NULL
               AND operation.activated_at IS NULL
               AND NOT EXISTS(
                   SELECT 1 FROM active_artifacts AS standalone
                    WHERE standalone.manifest_id = manifest.manifest_id
               )
            """,
            (
                bundle.root_case_ref.object_id,
                bundle.root_case_ref.version,
                bundle.root_case_ref.content_sha256,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise CaseIndexPublicationError("CASE_INDEX_SOURCE_CASE_NOT_ACTIVE")
        row = rows[0]
        manifest = VersionRef(
            object_id=str(row[3]),
            version=int(str(row[4])),
            content_sha256=str(row[5]),
        )
        if (
            catalog_record.manifest_id != manifest.object_id
            or root.candidate.metadata.manifest_ref != manifest
        ):
            raise CaseIndexPublicationError("CASE_INDEX_SOURCE_MANIFEST_MISMATCH")
        try:
            body = self._store.read_verified(
                self._store.reference(
                    content_sha256=str(row[0]),
                    media_type=str(row[1]),
                    size_bytes=int(str(row[2])),
                )
            )
        except (ContentStoreError, OSError, TypeError, ValueError):
            raise CaseIndexPublicationError(
                "CASE_INDEX_SOURCE_CONTENT_INVALID"
            ) from None
        return body, manifest

    @staticmethod
    def _assert_text_free_of_authority_hashes(bundle: CaseIndexBundle) -> None:
        for artifact in bundle.artifacts:
            hashes = artifact.provenance.contributor_client_hashes
            if any(value in artifact.rendered_text for value in hashes):
                raise CaseIndexPublicationError("CASE_INDEX_TEXT_CONTAINS_HMAC")
            if artifact.candidate is not None:
                assert_case_index_text_safe(
                    artifact.candidate,
                    artifact.rendered_text,
                )

    def _persist_ledger(self, plan: CaseIndexPublicationPlan) -> None:
        for artifact in plan.bundle.artifacts:
            self._persist_provenance(artifact.provenance)
        pattern = plan.bundle.artifacts[1]
        now = _utc(self._clock.now())
        row = self._connection.execute(
            "SELECT global_content_ref, global_content_sha256, "
            "global_content_size_bytes, manifest_id, provenance_id, "
            "provenance_version, allowed_uses_json, state, created_at "
            "FROM case_patterns WHERE pattern_id = ? AND version = ?",
            (pattern.artifact_ref.object_id, pattern.artifact_ref.version),
        ).fetchone()
        expected = (
            f"sha256:{pattern.content_ref.content_sha256}",
            pattern.content_ref.content_sha256,
            len(pattern.rendered_text.encode("utf-8")),
            plan.manifest_id,
            pattern.provenance.provenance_ref.object_id,
            pattern.provenance.provenance_ref.version,
            json.dumps(sorted(pattern.allowed_uses), separators=(",", ":")),
        )
        if row is not None:
            if tuple(row[:7]) != expected or str(row[7]) not in {
                "PREPARED",
                "ACTIVE",
            }:
                raise CaseIndexPublicationError("CASE_INDEX_PATTERN_CONFLICT")
            return
        self._connection.execute(
            """
            INSERT INTO case_patterns(
                pattern_id, version, global_content_ref,
                global_content_sha256, global_content_size_bytes, manifest_id,
                provenance_id, provenance_version, allowed_uses_json,
                state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?)
            """,
            (
                pattern.artifact_ref.object_id,
                pattern.artifact_ref.version,
                *expected,
                now,
            ),
        )

    def _persist_provenance(self, value: CaseProvenanceRecord) -> None:
        exact = CaseProvenanceRecord.model_validate(value)
        existing = self._connection.execute(
            "SELECT closure_json FROM case_provenance "
            "WHERE provenance_id = ? AND provenance_version = ?",
            (exact.provenance_ref.object_id, exact.provenance_ref.version),
        ).fetchone()
        if existing is not None:
            try:
                stored = CaseProvenanceRecord.model_validate_json(
                    str(existing[0]), strict=True
                )
            except ValueError:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_PROVENANCE_CONFLICT"
                ) from None
            if stored != exact:
                raise CaseIndexPublicationError("CASE_INDEX_PROVENANCE_CONFLICT")
            return
        closure_json = canonical_json_bytes(
            exact.model_dump(mode="json")
        ).decode("ascii")
        self._connection.execute(
            """
            INSERT INTO case_provenance(
                provenance_id, provenance_version, provenance_sha256,
                artifact_object_id, artifact_version, artifact_sha256,
                artifact_kind, contributor_client_hashes_json,
                independent_source_count, derivation_rule_id,
                derivation_rule_version, derivation_rule_sha256,
                policy_manifest_id, policy_manifest_version,
                policy_manifest_sha256, source_grade, provenance_scope,
                allowed_uses_json, effective_to, closure_json, closure_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?)
            """,
            (
                exact.provenance_ref.object_id,
                exact.provenance_ref.version,
                exact.closure_sha256,
                exact.artifact_ref.object_id,
                exact.artifact_ref.version,
                exact.artifact_ref.content_sha256,
                exact.artifact_kind,
                json.dumps(
                    sorted(exact.contributor_client_hashes),
                    separators=(",", ":"),
                ),
                len(exact.independent_evidence),
                exact.derivation_rule_ref.object_id,
                exact.derivation_rule_ref.version,
                exact.derivation_rule_ref.content_sha256,
                exact.policy_manifest_ref.object_id,
                exact.policy_manifest_ref.version,
                exact.policy_manifest_ref.content_sha256,
                exact.source_grade,
                exact.provenance_scope,
                json.dumps(sorted(exact.allowed_uses), separators=(",", ":")),
                None if exact.effective_to is None else _utc(exact.effective_to),
                closure_json,
                exact.closure_sha256,
            ),
        )

    def _ensure_rebuild_intent(
        self, plan: CaseIndexPublicationPlan
    ) -> tuple[str, int]:
        return self._ensure_rebuild_intent_identity(
            operation_id=plan.operation_id,
            manifest_id=plan.manifest_id,
            authority_base_version=plan.authority_base_version,
        )

    def _ensure_rebuild_intent_identity(
        self,
        *,
        operation_id: str,
        manifest_id: str,
        authority_base_version: int,
    ) -> tuple[str, int]:
        with transaction(self._connection):
            operation = self._connection.execute(
                "SELECT state, runtime_epoch FROM publication_operations "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            manifest = self._connection.execute(
                "SELECT state, verified FROM artifact_manifests "
                "WHERE manifest_id = ? AND operation_id = ?",
                (manifest_id, operation_id),
            ).fetchone()
            if operation != ("VERIFIED", None) or manifest != ("VERIFIED", 1):
                raise CaseIndexPublicationError(
                    "CASE_INDEX_LEDGER_NOT_VERIFIED"
                )
            patterns = self._connection.execute(
                "SELECT pattern_id, version, state FROM case_patterns "
                "WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchall()
            if len(patterns) != 1:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_PATTERN_AUTHORITY_INVALID"
                )
            pattern_state = str(patterns[0][2])
            if pattern_state not in {"PREPARED", "ACTIVE"}:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_PATTERN_AUTHORITY_INVALID"
                )
            queue = self._connection.execute(
                "SELECT queue_id, catalog_version, required_outputs_json, "
                "reason, state FROM rebuild_queue "
                "WHERE upstream_type = 'case_index' AND upstream_id = ? "
                "ORDER BY catalog_version DESC",
                (manifest_id,),
            ).fetchall()
            if queue:
                expected_outputs = json.dumps(
                    ["bm25", "graph", "vector", "wiki"],
                    separators=(",", ":"),
                )
                if (
                    len(queue) != 1
                    or int(queue[0][1]) != authority_base_version
                    or str(queue[0][2]) != expected_outputs
                    or str(queue[0][3]) != "case_index_authority_published"
                    or str(queue[0][4])
                    not in {"PENDING", "CLAIMED", "COMPLETED"}
                    or (pattern_state == "ACTIVE" and str(queue[0][4]) != "COMPLETED")
                    or (pattern_state == "PREPARED" and str(queue[0][4]) == "COMPLETED")
                ):
                    raise CaseIndexPublicationError(
                        "CASE_INDEX_REBUILD_QUEUE_INVALID"
                    )
                return str(queue[0][0]), int(queue[0][1])
            if pattern_state != "PREPARED":
                raise CaseIndexPublicationError(
                    "CASE_INDEX_REBUILD_QUEUE_INVALID"
                )
            state = self._connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
            if state is None:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_CATALOG_STATE_MISSING"
                )
            if int(state[0]) + 1 != authority_base_version:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_CATALOG_VERSION_CONFLICT"
                )
            catalog_version = authority_base_version
            queue_id = self._ids.object_id("rebuild_request")
            self._connection.execute(
                """
                INSERT INTO rebuild_queue(
                    queue_id, upstream_type, upstream_id, catalog_version,
                    required_outputs_json, reason, state, created_at
                ) VALUES (?, 'case_index', ?, ?, ?,
                          'case_index_authority_published', 'PENDING', ?)
                """,
                (
                    queue_id,
                    manifest_id,
                    catalog_version,
                    json.dumps(
                        ["bm25", "graph", "vector", "wiki"],
                        separators=(",", ":"),
                    ),
                    _utc(self._clock.now()),
                ),
            )
            return queue_id, catalog_version


class CaseIndexPublicationRepository:
    """Deterministic source-of-truth replay for retrieval and production rebuild."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        *,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("case index replay requires SQLite")
        if type(content_store) is not ContentStore:
            raise TypeError("case index replay requires ContentStore")
        self._connection = connection
        self._store = content_store
        self._clock = clock if clock is not None else SystemClock()
        self._manifests = ManifestRepository(connection)

    def replay_approved(self) -> tuple[CaseIndexBundle, ...]:
        """Replay every exact approved ledger which is eligible for rebuild.

        Case-index ledgers are deliberately not runtime roots.  Their manifests
        remain ``VERIFIED`` while the production rebuild copies their body-free
        candidate authority into the ordinary five-root publication.
        """

        rows = self._connection.execute(
            "SELECT manifest.manifest_id, manifest.source_version, "
            "manifest.manifest_sha256 "
            "FROM artifact_manifests AS manifest "
            "JOIN publication_operations AS operation "
            "  ON operation.operation_id = manifest.operation_id "
            "JOIN case_patterns AS pattern "
            "  ON pattern.manifest_id = manifest.manifest_id "
            "WHERE manifest.artifact_kind = ? "
            "AND manifest.state = 'VERIFIED' AND manifest.verified = 1 "
            "AND operation.state = 'VERIFIED' "
            "AND operation.runtime_epoch IS NULL "
            "AND pattern.state IN ('PREPARED', 'ACTIVE') "
            "ORDER BY manifest.manifest_id",
            (_MANIFEST_KIND,),
        ).fetchall()
        return tuple(
            self.replay_manifest(
                VersionRef(
                    object_id=str(row[0]),
                    version=int(str(row[1])),
                    content_sha256=str(row[2]),
                ),
            )
            for row in rows
        )

    def pending_rebuild_intents(
        self,
        *,
        target_catalog_version: int | None = None,
    ) -> tuple[CaseIndexRebuildIntent, ...]:
        """Return the canonical pending set which activation must match exactly."""

        if target_catalog_version is not None and (
            type(target_catalog_version) is not int
            or target_catalog_version <= 0
        ):
            raise TypeError("positive target catalog version required")
        rows = self._connection.execute(
            "SELECT manifest.manifest_id, manifest.source_version, "
            "manifest.manifest_sha256, operation.operation_id, "
            "operation.descriptor_sha256, pattern.pattern_id, pattern.version, "
            "queue.queue_id, queue.catalog_version, queue.state "
            "FROM artifact_manifests AS manifest "
            "JOIN publication_operations AS operation "
            "  ON operation.operation_id = manifest.operation_id "
            "JOIN case_patterns AS pattern "
            "  ON pattern.manifest_id = manifest.manifest_id "
            "JOIN rebuild_queue AS queue "
            "  ON queue.upstream_type = 'case_index' "
            " AND queue.upstream_id = manifest.manifest_id "
            "LEFT JOIN case_index_rebuild_invalidations AS invalidation "
            "  ON invalidation.queue_id = queue.queue_id "
            "WHERE manifest.artifact_kind = 'case_index' "
            "AND manifest.state = 'VERIFIED' AND manifest.verified = 1 "
            "AND operation.state = 'VERIFIED' "
            "AND operation.runtime_epoch IS NULL "
            "AND pattern.state = 'PREPARED' "
            "AND queue.state IN ('PENDING', 'CLAIMED') "
            "AND invalidation.queue_id IS NULL "
            "ORDER BY manifest.manifest_id"
        ).fetchall()
        current = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state "
            "WHERE singleton = 1"
        ).fetchone()
        if current is None or type(current[0]) is not int:
            raise CaseIndexPublicationError("CASE_INDEX_CATALOG_STATE_MISSING")
        expected_target = int(current[0]) + 1
        intents: list[CaseIndexRebuildIntent] = []
        for row in rows:
            target = int(str(row[8]))
            if target != int(str(row[1])) or target != expected_target:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_REBUILD_QUEUE_INVALID"
                )
            if target_catalog_version is not None and target != target_catalog_version:
                continue
            manifest_ref = VersionRef(
                object_id=str(row[0]),
                version=int(str(row[1])),
                content_sha256=str(row[2]),
            )
            # This rechecks the P1 closure, all seven provenance rows, live case
            # authority, immutable CAS members, and the exact PREPARED intent.
            self.replay_manifest(manifest_ref)
            intents.append(
                CaseIndexRebuildIntent(
                    manifest_ref=manifest_ref,
                    operation_id=str(row[3]),
                    approval_descriptor_sha256=str(row[4]),
                    pattern_id=str(row[5]),
                    pattern_version=int(str(row[6])),
                    queue_id=str(row[7]),
                    target_catalog_version=target,
                    queue_state=cast(Literal["PENDING", "CLAIMED"], str(row[9])),
                )
            )
        return tuple(intents)

    def pending_rebuild_snapshot(
        self,
        *,
        target_catalog_version: int | None = None,
    ) -> CaseIndexRebuildSnapshot:
        """Return the approval-stable full pending identity set.

        Queue claiming is an operational state change and is intentionally not
        part of this descriptor.  Adding, removing, invalidating, or retargeting
        a ledger changes the tuple and therefore ``identity_sha256``.
        """

        current = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state "
            "WHERE singleton = 1"
        ).fetchone()
        if current is None or type(current[0]) is not int:
            raise CaseIndexPublicationError("CASE_INDEX_CATALOG_STATE_MISSING")
        expected_target = int(current[0]) + 1
        if target_catalog_version is None:
            target_catalog_version = expected_target
        if (
            type(target_catalog_version) is not int
            or target_catalog_version != expected_target
        ):
            raise CaseIndexPublicationError(
                "CASE_INDEX_CATALOG_VERSION_CONFLICT"
            )
        control_plane = snapshot_pending_case_index_invalidations(self._connection)
        intents = self.pending_rebuild_intents(
            target_catalog_version=target_catalog_version
        )
        identities = tuple(
            sorted(
                (item.stable_identity() for item in intents),
                key=lambda item: (
                    item.manifest_ref.object_id,
                    item.manifest_ref.version,
                    item.manifest_ref.content_sha256,
                    item.operation_id,
                    item.approval_descriptor_sha256,
                    item.pattern_id,
                    item.pattern_version,
                    item.queue_id,
                    item.target_catalog_version,
                ),
            )
        )
        snapshot = CaseIndexRebuildSnapshot(
            target_catalog_version=target_catalog_version,
            identities=identities,
        )
        if snapshot != control_plane:
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_BATCH_CHANGED")
        return snapshot

    def transition_rebuild_batch(
        self,
        expected_snapshot: CaseIndexRebuildSnapshot,
    ) -> None:
        """Transition one complete, exact batch inside the caller's transaction.

        The production rebuild owns the surrounding ``BEGIN IMMEDIATE`` and the
        five-root runtime switch.  It calls this method immediately before its
        catalog compare-and-swap.  Omitting even one still-valid intent leaves
        the catalog trigger armed, so the entire activation rolls back.
        """

        if not self._connection.in_transaction:
            raise CaseIndexPublicationError(
                "CASE_INDEX_REBUILD_TRANSACTION_REQUIRED"
            )
        if type(expected_snapshot) is not CaseIndexRebuildSnapshot:
            raise TypeError("case index rebuild snapshot required")
        if not expected_snapshot.identities:
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_BATCH_INVALID")
        target_catalog_version = expected_snapshot.target_catalog_version
        current = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state "
            "WHERE singleton = 1"
        ).fetchone()
        if (
            current is None
            or type(current[0]) is not int
            or int(current[0]) + 1 != target_catalog_version
        ):
            raise CaseIndexPublicationError(
                "CASE_INDEX_CATALOG_VERSION_CONFLICT"
            )
        canonical = self.pending_rebuild_snapshot(
            target_catalog_version=target_catalog_version
        )
        if canonical != expected_snapshot:
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_BATCH_CHANGED")
        for identity in expected_snapshot.identities:
            changed_pattern = self._connection.execute(
                "UPDATE case_patterns SET state = 'ACTIVE' "
                "WHERE pattern_id = ? AND version = ? "
                "AND manifest_id = ? AND state = 'PREPARED'",
                (
                    identity.pattern_id,
                    identity.pattern_version,
                    identity.manifest_ref.object_id,
                ),
            ).rowcount
            changed_queue = self._connection.execute(
                "UPDATE rebuild_queue SET state = 'COMPLETED' "
                "WHERE queue_id = ? AND upstream_type = 'case_index' "
                "AND upstream_id = ? AND catalog_version = ? "
                "AND state IN ('PENDING', 'CLAIMED') "
                "AND NOT EXISTS ("
                "SELECT 1 FROM case_index_rebuild_invalidations "
                "WHERE queue_id = rebuild_queue.queue_id)",
                (
                    identity.queue_id,
                    identity.manifest_ref.object_id,
                    target_catalog_version,
                ),
            ).rowcount
            if changed_pattern != 1 or changed_queue != 1:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_REBUILD_BATCH_CHANGED"
                )
        remaining = self._connection.execute(
            "SELECT COUNT(*) FROM rebuild_queue AS queue "
            "JOIN case_patterns AS pattern "
            "  ON pattern.manifest_id = queue.upstream_id "
            "LEFT JOIN case_index_rebuild_invalidations AS invalidation "
            "  ON invalidation.queue_id = queue.queue_id "
            "WHERE queue.upstream_type = 'case_index' "
            "AND queue.catalog_version = ? "
            "AND queue.state IN ('PENDING', 'CLAIMED') "
            "AND pattern.state = 'PREPARED' "
            "AND invalidation.queue_id IS NULL",
            (target_catalog_version,),
        ).fetchone()
        if remaining is None or int(str(remaining[0])) != 0:
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_BATCH_CHANGED")

    def replay_manifest(
        self,
        manifest_ref: VersionRef,
    ) -> CaseIndexBundle:
        requested = VersionRef.model_validate(manifest_ref)
        try:
            manifest = self._manifests.get(requested.object_id)
        except Exception:
            raise CaseIndexPublicationError(
                "CASE_INDEX_MANIFEST_NOT_APPROVED"
            ) from None
        if _manifest_ref(manifest) != requested:
            raise CaseIndexPublicationError("CASE_INDEX_MANIFEST_REF_MISMATCH")
        self._assert_manifest_authority(manifest)
        descriptor_members = tuple(
            member
            for member in manifest.members
            if member.object_type == _DESCRIPTOR_KIND
        )
        if len(descriptor_members) != 1:
            raise CaseIndexPublicationError("CASE_INDEX_DESCRIPTOR_MISSING")
        descriptor_member = descriptor_members[0]
        descriptor_bytes = self._read_member(descriptor_member)
        try:
            descriptor = CaseIndexReplayDescriptor.model_validate_json(
                descriptor_bytes, strict=True
            )
        except ValueError:
            raise CaseIndexPublicationError(
                "CASE_INDEX_DESCRIPTOR_INVALID"
            ) from None
        if (
            descriptor.manifest_id != manifest.manifest_id
            or descriptor.artifact_key != manifest.artifact_key
        ):
            raise CaseIndexPublicationError("CASE_INDEX_DESCRIPTOR_INVALID")
        source_row = self._assert_live_case_authority(
            descriptor,
        )
        by_id = {member.object_id: member for member in manifest.members}
        expected_ids = {
            descriptor_member.object_id,
            descriptor.root_case_ref.object_id,
        }
        artifacts: list[CaseIndexArtifact] = []
        actual_manifest_ref = _manifest_ref(manifest)
        for replay in descriptor.artifacts:
            content_member = by_id.get(replay.content_ref.object_id)
            if (
                content_member is None
                or content_member.object_sha256
                != replay.content_ref.content_sha256
            ):
                raise CaseIndexPublicationError("CASE_INDEX_MEMBER_CLOSURE_INVALID")
            expected_ids.add(content_member.object_id)
            body = self._read_member(content_member)
            if content_member.media_type != "text/plain":
                raise CaseIndexPublicationError("CASE_INDEX_CONTENT_MEDIA_INVALID")
            try:
                text = body.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise CaseIndexPublicationError(
                    "CASE_INDEX_CONTENT_ENCODING_INVALID"
                ) from None
            provenance = self._read_provenance(replay)
            if any(value in text for value in provenance.contributor_client_hashes):
                raise CaseIndexPublicationError("CASE_INDEX_TEXT_CONTAINS_HMAC")
            candidate = replay.candidate_template
            if candidate is not None:
                if (
                    candidate.metadata.media_type != content_member.media_type
                    or candidate.metadata.size_bytes != content_member.size_bytes
                ):
                    raise CaseIndexPublicationError(
                        "CASE_INDEX_CANDIDATE_CONTENT_MISMATCH"
                    )
                candidate = candidate.model_copy(
                    update={
                        "metadata": candidate.metadata.model_copy(
                            update={"manifest_ref": actual_manifest_ref}
                        )
                    }
                )
                assert_case_index_text_safe(candidate, text)
            artifacts.append(
                CaseIndexArtifact(
                    artifact_ref=replay.artifact_ref,
                    artifact_kind=replay.artifact_kind,
                    content_ref=replay.content_ref,
                    rendered_text=text,
                    statement_scope=replay.statement_scope,
                    provenance=provenance,
                    authorization_refs=replay.authorization_refs,
                    review_ref=replay.review_ref,
                    release_decision_sha256=replay.release_decision_sha256,
                    allowed_uses=replay.allowed_uses,
                    effective_from=replay.effective_from,
                    effective_to=replay.effective_to,
                    source_catalog_version=replay.source_catalog_version,
                    candidate=candidate,
                )
            )
        if set(by_id) != expected_ids:
            raise CaseIndexPublicationError("CASE_INDEX_MEMBER_CLOSURE_INVALID")
        root_member = by_id.get(descriptor.root_case_ref.object_id)
        if (
            root_member is None
            or root_member.media_type != str(source_row[0])
            or root_member.size_bytes != int(str(source_row[1]))
        ):
            raise CaseIndexPublicationError("CASE_INDEX_ROOT_MEMBER_INVALID")
        self._read_member(root_member)
        bundle = CaseIndexBundle(
            root_case_ref=descriptor.root_case_ref,
            artifacts=tuple(artifacts),
        )
        self._assert_pattern_row(bundle, manifest)
        return bundle

    def is_exact_published_candidate(self, candidate: CandidateRef) -> bool:
        """Validate one route-shaped candidate against a published ledger."""

        try:
            exact = CandidateRef.model_validate(candidate)
            bundle = self.replay_manifest(exact.metadata.manifest_ref)
            if self._pattern_state(exact.metadata.manifest_ref.object_id) != "ACTIVE":
                return False
            allowed_channels = {
                "case": frozenset({"case", "lexical", "vector"}),
                "wiki": frozenset({"wiki"}),
                "global_graph": frozenset({"global_graph"}),
                "lexical": frozenset({"lexical"}),
                "vector": frozenset({"vector"}),
            }
            governed = next(
                (
                    item
                    for item in bundle.candidates
                    if item.reference == exact.reference
                    and item.content_ref == exact.content_ref
                    and item.object_type == exact.object_type
                    and exact.channel in allowed_channels.get(
                        item.channel, frozenset()
                    )
                ),
                None,
            )
            if governed is None:
                return False
            routed = governed.model_copy(update={"channel": exact.channel})
            return candidate_capability_payload(routed) == (
                candidate_capability_payload(exact)
            )
        except Exception:
            return False

    def _pattern_state(self, manifest_id: str) -> str:
        rows = self._connection.execute(
            "SELECT state FROM case_patterns WHERE manifest_id = ?",
            (manifest_id,),
        ).fetchall()
        if len(rows) != 1 or str(rows[0][0]) not in {"PREPARED", "ACTIVE"}:
            raise CaseIndexPublicationError("CASE_INDEX_PATTERN_AUTHORITY_INVALID")
        return str(rows[0][0])

    def _assert_manifest_authority(
        self,
        manifest: ArtifactManifest,
    ) -> None:
        row = self._connection.execute(
            """
            SELECT operation.purpose, operation.authority_base_version,
                   operation.approval_request_id, operation.descriptor_sha256,
                   operation.state, operation.required_manifests_json,
                   operation.required_manifest_count,
                   operation.verified_manifest_count,
                   operation.expected_current_epoch, operation.runtime_epoch,
                   execution.request_id, execution.descriptor_sha256,
                   execution.draft_sha256,
                   execution.descriptor_base_version, execution.state,
                   execution.applied_commit_version, execution.applied_at,
                   attestation.approval_draft_sha256,
                   attestation.closure_sha256,
                   request.descriptor_json, request.state,
                   receipt.operation_id, receipt.state,
                   operation.activated_at
              FROM publication_operations AS operation
              JOIN approval_executions AS execution
                ON execution.operation_id = operation.operation_id
              JOIN publication_closure_attestations AS attestation
                ON attestation.operation_id = operation.operation_id
              JOIN approval_requests AS request
                ON request.request_id = operation.approval_request_id
              JOIN approval_receipts AS receipt
                ON receipt.request_id = request.request_id
             WHERE operation.operation_id = ?
            """,
            (manifest.operation_id,),
        ).fetchone()
        if row is None:
            raise CaseIndexPublicationError("CASE_INDEX_APPROVAL_AUTHORITY_INVALID")
        try:
            required = json.loads(str(row[5]))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise CaseIndexPublicationError(
                "CASE_INDEX_APPROVAL_AUTHORITY_INVALID"
            ) from None
        closure = publication_closure_sha256(
            purpose=_PURPOSE,
            authority_base_version=manifest.source_version,
            expected_current_epoch=None if row[8] is None else int(row[8]),
            artifacts=(manifest,),
        )
        try:
            descriptor = DraftDescriptor.model_validate_json(str(row[19]))
        except ValueError:
            raise CaseIndexPublicationError(
                "CASE_INDEX_APPROVAL_AUTHORITY_INVALID"
            ) from None
        if (
            manifest.artifact_kind != _MANIFEST_KIND
            or manifest.state != "VERIFIED"
            or not manifest.verified
            or str(row[0]) != _PURPOSE
            or int(row[1]) != manifest.source_version
            or str(row[4]) != "VERIFIED"
            or required != [manifest.manifest_id]
            or int(row[6]) != 1
            or int(row[7]) != 1
            or row[9] is not None
            or str(row[10]) != str(row[2])
            or str(row[11]) != str(row[3])
            or str(row[12]) != str(row[17])
            or int(row[13]) + 1 != manifest.source_version
            or str(row[14]) != "APPLIED"
            or int(row[15]) <= 0
            or row[16] is None
            or str(row[18]) != closure
            or descriptor
            != DraftDescriptor(
                purpose=_PURPOSE,
                target_id=self._root_case_id(manifest),
                base_version=manifest.source_version - 1,
                draft_sha256=closure,
            )
            or str(row[20]) != "ACKNOWLEDGED"
            or str(row[21]) != manifest.operation_id
            or str(row[22]) != "ACKNOWLEDGED"
            or row[23] is not None
        ):
            raise CaseIndexPublicationError("CASE_INDEX_APPROVAL_AUTHORITY_INVALID")

    def _root_case_id(self, manifest: ArtifactManifest) -> str:
        descriptor_members = tuple(
            member
            for member in manifest.members
            if member.object_type == _DESCRIPTOR_KIND
        )
        if len(descriptor_members) != 1:
            raise CaseIndexPublicationError("CASE_INDEX_DESCRIPTOR_MISSING")
        try:
            descriptor = CaseIndexReplayDescriptor.model_validate_json(
                self._read_member(descriptor_members[0]), strict=True
            )
        except ValueError:
            raise CaseIndexPublicationError(
                "CASE_INDEX_DESCRIPTOR_INVALID"
            ) from None
        return descriptor.root_case_ref.object_id

    def _assert_live_case_authority(
        self,
        descriptor: CaseIndexReplayDescriptor,
    ) -> tuple[object, object]:
        root = descriptor.root_case_ref
        root_replay = descriptor.artifacts[0]
        purpose = next(iter(sorted(root_replay.allowed_uses)), None)
        if purpose is None:
            raise CaseIndexPublicationError("CASE_INDEX_CASE_AUTHORITY_INVALID")
        catalog_record = CaseCatalog(
            self._connection,
            self._store,
            clock=self._clock,
        ).get_active(root.object_id, purpose=purpose)
        if catalog_record is None or catalog_record.case_ref != root:
            raise CaseIndexPublicationError("CASE_INDEX_CASE_AUTHORITY_INVALID")
        row = self._connection.execute(
            """
            SELECT cv.global_content_media_type, cv.global_content_size_bytes,
                   cv.manifest_id, source_manifest.source_version,
                   source_manifest.manifest_sha256
              FROM cases
              JOIN case_versions AS cv
                ON cv.case_id = cases.case_id
               AND cv.version = cases.current_version
              JOIN artifact_manifests AS source_manifest
                ON source_manifest.manifest_id = cv.manifest_id
              JOIN publication_operations AS source_operation
                ON source_operation.operation_id = source_manifest.operation_id
             WHERE cases.case_id = ? AND cases.current_version = ?
               AND cases.state = 'ACTIVE' AND cv.state = 'ACTIVE'
               AND cv.global_content_sha256 = ?
               AND source_manifest.state = 'VERIFIED'
               AND source_manifest.verified = 1
               AND source_manifest.artifact_kind = 'shared_case'
               AND source_operation.purpose = 'case_publish'
               AND source_operation.state = 'VERIFIED'
               AND source_operation.runtime_epoch IS NULL
               AND source_operation.activated_at IS NULL
               AND NOT EXISTS(
                   SELECT 1 FROM active_artifacts AS standalone
                    WHERE standalone.manifest_id = source_manifest.manifest_id
               )
            """,
            (root.object_id, root.version, root.content_sha256),
        ).fetchone()
        if row is None:
            raise CaseIndexPublicationError("CASE_INDEX_CASE_AUTHORITY_INVALID")
        source_manifest_ref = VersionRef(
            object_id=str(row[2]),
            version=int(str(row[3])),
            content_sha256=str(row[4]),
        )
        if (
            catalog_record.manifest_id != source_manifest_ref.object_id
            or source_manifest_ref != descriptor.source_authority_manifest_ref
        ):
            raise CaseIndexPublicationError("CASE_INDEX_CASE_AUTHORITY_INVALID")
        now = self._clock.now()
        for replay in descriptor.artifacts:
            provenance = self._read_provenance(replay)
            for contribution in provenance.case_contributions:
                authority = self._connection.execute(
                    """
                    SELECT cases.state, cv.state, ca.authorization_id,
                           ca.authorization_version, ca.authorization_sha256,
                           ca.reuse_authorized, ca.allowed_uses_json,
                           ca.valid_from, ca.expires_at, ca.revoked_at
                      FROM cases
                      JOIN case_versions AS cv
                        ON cv.case_id = cases.case_id
                       AND cv.version = cases.current_version
                      JOIN case_authorizations AS ca
                        ON ca.case_id = cv.case_id
                       AND ca.case_version = cv.version
                     WHERE cases.case_id = ? AND cases.current_version = ?
                       AND cv.global_content_sha256 = ?
                    """,
                    (
                        contribution.case_ref.object_id,
                        contribution.case_ref.version,
                        contribution.case_ref.content_sha256,
                    ),
                ).fetchone()
                if authority is None:
                    raise CaseIndexPublicationError(
                        "CASE_INDEX_CASE_AUTHORITY_INVALID"
                    )
                valid_from = _parse_utc(authority[7])
                expires = None if authority[8] is None else _parse_utc(authority[8])
                revoked = None if authority[9] is None else _parse_utc(authority[9])
                if (
                    tuple(authority[:2]) != ("ACTIVE", "ACTIVE")
                    or tuple(authority[2:5])
                    != (
                        contribution.authorization_ref.object_id,
                        contribution.authorization_ref.version,
                        contribution.authorization_ref.content_sha256,
                    )
                    or int(authority[5]) != 1
                    or not replay.allowed_uses <= _json_set(authority[6])
                    or now < valid_from
                    or (expires is not None and now >= expires)
                    or (revoked is not None and now >= revoked)
                    or self._is_tombstoned(
                        "case",
                        contribution.case_ref.object_id,
                        contribution.source_lineage_sha256,
                    )
                ):
                    raise CaseIndexPublicationError(
                        "CASE_INDEX_CASE_AUTHORITY_INVALID"
                    )
        review = descriptor.artifacts[0]
        review_row = self._connection.execute(
            "SELECT review_id, review_version, review_sha256, decision, "
            "release_decision_sha256 FROM case_review_decisions "
            "WHERE case_id = ? AND case_version = ?",
            (root.object_id, root.version),
        ).fetchone()
        if review_row is None or tuple(review_row) != (
            review.review_ref.object_id,
            review.review_ref.version,
            review.review_ref.content_sha256,
            "approved",
            review.release_decision_sha256,
        ):
            raise CaseIndexPublicationError("CASE_INDEX_REVIEW_AUTHORITY_INVALID")
        if self._is_tombstoned("case", root.object_id, lineage_hash("case", root.object_id)):
            raise CaseIndexPublicationError("CASE_INDEX_CASE_AUTHORITY_INVALID")
        return row[0], row[1]

    def _is_tombstoned(
        self,
        object_type: str,
        object_id: str,
        source_lineage_sha256: str,
    ) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM tombstones WHERE "
            "(target_type = ? AND target_id_hash = ?) "
            "OR source_lineage_hash IN (?, ?) LIMIT 1",
            (
                object_type,
                target_hash(object_type, object_id),
                source_lineage_sha256,
                lineage_hash(object_type, object_id),
            ),
        ).fetchone()
        return row is not None

    def _read_provenance(
        self, replay: CaseIndexReplayArtifact
    ) -> CaseProvenanceRecord:
        row = self._connection.execute(
            "SELECT provenance_sha256, artifact_object_id, artifact_version, "
            "artifact_sha256, artifact_kind, closure_json, closure_sha256 "
            "FROM case_provenance WHERE provenance_id = ? "
            "AND provenance_version = ?",
            (replay.provenance_ref.object_id, replay.provenance_ref.version),
        ).fetchone()
        if row is None:
            raise CaseIndexPublicationError("CASE_INDEX_PROVENANCE_MISSING")
        try:
            provenance = CaseProvenanceRecord.model_validate_json(
                str(row[5]), strict=True
            )
        except ValueError:
            raise CaseIndexPublicationError(
                "CASE_INDEX_PROVENANCE_INVALID"
            ) from None
        if (
            tuple(row[:5])
            != (
                replay.provenance_ref.content_sha256,
                replay.artifact_ref.object_id,
                replay.artifact_ref.version,
                replay.artifact_ref.content_sha256,
                replay.artifact_kind,
            )
            or str(row[6]) != replay.provenance_ref.content_sha256
            or provenance.provenance_ref != replay.provenance_ref
            or provenance.artifact_ref != replay.artifact_ref
            or provenance.allowed_uses != replay.allowed_uses
            or provenance.effective_to != replay.effective_to
        ):
            raise CaseIndexPublicationError("CASE_INDEX_PROVENANCE_INVALID")
        return provenance

    def _assert_pattern_row(
        self,
        bundle: CaseIndexBundle,
        manifest: ArtifactManifest,
    ) -> None:
        pattern = bundle.artifacts[1]
        row = self._connection.execute(
            "SELECT global_content_ref, global_content_sha256, "
            "global_content_size_bytes, manifest_id, provenance_id, "
            "provenance_version, allowed_uses_json, state "
            "FROM case_patterns WHERE pattern_id = ? AND version = ?",
            (pattern.artifact_ref.object_id, pattern.artifact_ref.version),
        ).fetchone()
        if row is None or tuple(row[:7]) != (
            f"sha256:{pattern.content_ref.content_sha256}",
            pattern.content_ref.content_sha256,
            len(pattern.rendered_text.encode("utf-8")),
            manifest.manifest_id,
            pattern.provenance.provenance_ref.object_id,
            pattern.provenance.provenance_ref.version,
            json.dumps(sorted(pattern.allowed_uses), separators=(",", ":")),
        ) or str(row[7]) not in {"PREPARED", "ACTIVE"}:
            raise CaseIndexPublicationError("CASE_INDEX_PATTERN_AUTHORITY_INVALID")
        queue = self._connection.execute(
            "SELECT catalog_version, required_outputs_json, reason, state "
            "FROM rebuild_queue WHERE upstream_type = 'case_index' "
            "AND upstream_id = ?",
            (manifest.manifest_id,),
        ).fetchall()
        expected_outputs = json.dumps(
            ["bm25", "graph", "vector", "wiki"],
            separators=(",", ":"),
        )
        if len(queue) != 1 or tuple(queue[0][:3]) != (
            manifest.source_version,
            expected_outputs,
            "case_index_authority_published",
        ):
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_QUEUE_INVALID")
        pattern_state = str(row[7])
        queue_state = str(queue[0][3])
        if (
            (pattern_state == "PREPARED" and queue_state not in {"PENDING", "CLAIMED"})
            or (pattern_state == "ACTIVE" and queue_state != "COMPLETED")
        ):
            raise CaseIndexPublicationError("CASE_INDEX_REBUILD_QUEUE_INVALID")
        if pattern_state == "PREPARED":
            catalog = self._connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                catalog is None
                or type(catalog[0]) is not int
                or int(catalog[0]) + 1 != manifest.source_version
            ):
                raise CaseIndexPublicationError(
                    "CASE_INDEX_CATALOG_VERSION_CONFLICT"
                )

    def _read_member(self, member: ManifestMember) -> bytes:
        try:
            return self._store.read_verified(
                self._store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
            )
        except (ContentStoreError, OSError, TypeError, ValueError):
            raise CaseIndexPublicationError(
                "CASE_INDEX_CAS_CONTENT_INVALID"
            ) from None


__all__ = [
    "CaseIndexPublication",
    "CaseIndexPublicationError",
    "CaseIndexPublicationPlan",
    "CaseIndexPublicationRepository",
    "CaseIndexPublicationService",
    "CaseIndexRebuildIdentity",
    "CaseIndexRebuildIntent",
    "CaseIndexRebuildSnapshot",
    "CaseIndexReplayArtifact",
    "CaseIndexReplayDescriptor",
    "SqliteCaseIndexAuthorityResolver",
    "invalidate_pending_case_indexes_in_transaction",
    "snapshot_pending_case_index_invalidations",
]
