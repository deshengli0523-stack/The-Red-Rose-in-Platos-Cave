"""Claim draft, preview and approval state machine."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import cast

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ObjectId, Sha256Hex, StrictModel
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EmpiricalSupport, Provenance, SourceGrade
from consultation_kb.models.knowledge import (
    ClaimApplicability,
    ClaimDraft,
    ClaimRecord,
    CognitiveType,
    FrameworkEligibility,
    PrivacyScope,
    ReviewStatus,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.case_index_serialization import (
    CaseIndexRebuildSnapshot,
    CaseIndexSerializationError,
    invalidate_pending_case_indexes_in_transaction,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore

from ._canonical import canonical_sha256, text_sha256
from .approval import GovernedWriteExecutor
from .provenance import (
    ProvenanceClosure,
    ProvenanceEdge,
    ProvenanceError,
    ProvenancePolicyManifest,
    ProvenanceRepository,
)
from .review import ClaimReviewResolver, ClaimReviewView


class ClaimGovernanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ClaimProposal(StrictModel):
    proposal_id: ObjectId
    draft: ClaimDraft
    draft_sha256: Sha256Hex
    catalog_base_version: int
    created_at: datetime


class ClaimPreview(StrictModel):
    proposal_id: ObjectId
    descriptor: DraftDescriptor
    review: ClaimReviewView


class ClaimProposalService:
    def __init__(
        self,
        *,
        review_resolver: ClaimReviewResolver,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
        connection: sqlite3.Connection | None = None,
        approval_executor: GovernedWriteExecutor | None = None,
        content_store: ContentStore | None = None,
        provenance_policy: ProvenancePolicyManifest | None = None,
    ) -> None:
        self._resolver = review_resolver
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()
        self._connection = connection
        self._approval_executor = approval_executor
        self._content_store = content_store
        self._provenance_policy = (
            None
            if provenance_policy is None
            else ProvenancePolicyManifest.model_validate(provenance_policy)
        )
        self._provenance = (
            None if provenance_policy is None else ProvenanceClosure(provenance_policy)
        )
        self._proposals: dict[str, ClaimProposal] = {}
        self._records: dict[tuple[str, int], ClaimRecord] = {}

    def _catalog_version(self) -> int:
        if self._connection is None:
            return 0
        row = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int:
            raise ClaimGovernanceError("KNOWLEDGE_CATALOG_STATE_INVALID")
        return int(row[0])

    def propose(self, draft: ClaimDraft) -> ClaimProposal:
        validated = ClaimDraft.model_validate(draft)
        if validated.source_grade == "C1":
            raise ClaimGovernanceError("GENERIC_CLAIM_CANNOT_ASSIGN_C1")
        if self._connection is not None and self._provenance is None:
            raise ClaimGovernanceError("PROVENANCE_POLICY_REQUIRED")
        if self._provenance is not None:
            try:
                recomputed = self._provenance.compute(
                    (validated.provenance,),
                    derivation_rule_ref=validated.provenance.derivation_rule_ref,
                    target_scope=validated.provenance.provenance_scope,
                )
            except ProvenanceError as exc:
                raise ClaimGovernanceError(exc.code) from exc
            if recomputed != validated.provenance:
                raise ClaimGovernanceError("PROVENANCE_CLOSURE_MISMATCH")
        proposal = ClaimProposal(
            proposal_id=self._ids.object_id("claim_proposal"),
            draft=validated,
            draft_sha256=canonical_sha256(validated.model_dump(mode="json")),
            catalog_base_version=self._catalog_version(),
            created_at=self._clock.now(),
        )
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def restore_proposal(self, proposal: ClaimProposal) -> ClaimProposal:
        """Restore one hash-verified durable proposal into this service lifespan."""

        validated = ClaimProposal.model_validate(proposal)
        if canonical_sha256(validated.draft.model_dump(mode="json")) != (
            validated.draft_sha256
        ):
            raise ClaimGovernanceError("CLAIM_PROPOSAL_HASH_MISMATCH")
        current = self._proposals.get(validated.proposal_id)
        if current is not None and current != validated:
            raise ClaimGovernanceError("CLAIM_PROPOSAL_RESTORE_CONFLICT")
        self._proposals[validated.proposal_id] = validated
        return validated

    def preview(self, proposal_id: str) -> ClaimPreview:
        try:
            proposal = self._proposals[proposal_id]
        except KeyError:
            raise ClaimGovernanceError("CLAIM_PROPOSAL_NOT_FOUND") from None
        descriptor = DraftDescriptor(
            purpose="claim_approve",
            target_id=proposal.proposal_id,
            base_version=proposal.catalog_base_version,
            draft_sha256=proposal.draft_sha256,
        )
        return ClaimPreview(
            proposal_id=proposal.proposal_id,
            descriptor=descriptor,
            review=self._resolver.resolve(proposal.draft),
        )

    def commit(
        self,
        proposal_id: str,
        *,
        descriptor: DraftDescriptor,
        approval_request_id: str,
    ) -> ClaimRecord:
        try:
            proposal = self._proposals[proposal_id]
        except KeyError:
            raise ClaimGovernanceError("CLAIM_PROPOSAL_NOT_FOUND") from None
        expected = self.preview(proposal_id).descriptor
        if DraftDescriptor.model_validate(descriptor) != expected:
            raise ClaimGovernanceError("CLAIM_APPROVAL_DESCRIPTOR_MISMATCH")
        if self._catalog_version() != proposal.catalog_base_version:
            raise ClaimGovernanceError("CLAIM_CATALOG_VERSION_CONFLICT")
        if self._approval_executor is None:
            raise ClaimGovernanceError("CLAIM_APPROVAL_EXECUTOR_REQUIRED")
        claim_id = self._ids.object_id("claim")
        now = self._clock.now()
        draft = proposal.draft
        record = ClaimRecord(
            claim_id=claim_id,
            version=1,
            text=draft.text,
            text_sha256=text_sha256(draft.text),
            cognitive_type=draft.cognitive_type,
            source_grade=draft.source_grade,
            framework_eligibility="conditional",
            empirical_support=draft.empirical_support,
            model_confidence=draft.model_confidence,
            review_status="approved",
            effective_from=now,
            effective_to=None,
            review_due_at=None,
            applicability=draft.applicability,
            privacy_scope=draft.privacy_scope,
            allowed_uses=draft.allowed_uses,
            passage_refs=tuple(item.passage_ref for item in draft.evidence),
            provenance=draft.provenance,
            created_at=now,
        )
        content_reference = None
        if self._connection is not None:
            if self._content_store is None:
                raise ClaimGovernanceError("CLAIM_CONTENT_STORE_REQUIRED")
            payload = record.text.encode("utf-8", errors="strict")
            content_reference = self._content_store.finalize(
                self._content_store.stage_bytes(
                    payload,
                    purpose="claim_text",
                    manifest_id=record.claim_id,
                    media_type="text/plain",
                )
            )
            if content_reference.content_sha256 != record.text_sha256:
                raise ClaimGovernanceError("CLAIM_CONTENT_HASH_MISMATCH")

        def apply(connection: sqlite3.Connection) -> None:
            if self._connection is None:
                return
            if connection is not self._connection:
                raise ClaimGovernanceError("CLAIM_TARGET_CONNECTION_MISMATCH")
            if content_reference is None:
                raise ClaimGovernanceError("CLAIM_CONTENT_STORE_REQUIRED")
            current_row = connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if current_row != (proposal.catalog_base_version,):
                raise ClaimGovernanceError("CLAIM_CATALOG_VERSION_CONFLICT")
            authoritative_provenance = self._derive_authoritative_provenance(
                connection,
                draft,
            )
            if authoritative_provenance != draft.provenance:
                raise ClaimGovernanceError("PROVENANCE_CLOSURE_MISMATCH")
            try:
                connection.execute(
                    """
                    INSERT INTO claims(
                        claim_id, version, claim_object_ref,
                        claim_object_size_bytes, claim_object_media_type,
                        claim_sha256,
                        cognitive_type, source_grade, framework_eligibility,
                        empirical_support, model_confidence, review_status,
                        effective_from, effective_to, review_due_at,
                        applicability_json, privacy_scope, allowed_uses_json,
                        provenance_json, theory_revision_id, theory_revision,
                        theory_revision_sha256, created_at
                    ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, 'CONDITIONAL', ?, ?,
                              'APPROVED', ?, NULL, NULL, ?, ?, ?, ?, NULL,
                              NULL, NULL, ?)
                    """,
                    (
                        record.claim_id,
                        f"sha256:{content_reference.content_sha256}",
                        content_reference.size_bytes,
                        content_reference.media_type,
                        record.text_sha256,
                        record.cognitive_type,
                        record.source_grade,
                        record.empirical_support,
                        record.model_confidence,
                        _utc(now),
                        _json(record.applicability.model_dump(mode="json")),
                        record.privacy_scope.upper(),
                        _json(sorted(record.allowed_uses)),
                        _json(record.provenance.model_dump(mode="json")),
                        _utc(now),
                    ),
                )
                for evidence in draft.evidence:
                    connection.execute(
                        """
                        INSERT INTO claim_evidence(
                            claim_id, claim_version, passage_id,
                            passage_version, relation, evidence_role
                        ) VALUES (?, 1, ?, ?, ?, ?)
                        """,
                        (
                            record.claim_id,
                            evidence.passage_ref.object_id,
                            evidence.passage_ref.version,
                            evidence.relation.upper(),
                            evidence.evidence_role.upper(),
                        ),
                    )
                    if self._provenance_policy is None:
                        raise ClaimGovernanceError("PROVENANCE_POLICY_REQUIRED")
                    try:
                        ProvenanceRepository(
                            connection,
                            policy_manifest=self._provenance_policy,
                            allowed_relations={"SUPPORTS", "CONTRADICTS"},
                        ).add(
                            ProvenanceEdge(
                                source_ref=evidence.passage_ref,
                                target_ref=VersionRef(
                                    object_id=record.claim_id,
                                    version=record.version,
                                    content_sha256=record.text_sha256,
                                ),
                                relation=evidence.relation.upper(),
                                derivation_rule_ref=draft.provenance.derivation_rule_ref,
                            ),
                            source_type="passage",
                            target_type="claim",
                            target_provenance=draft.provenance,
                        )
                    except ProvenanceError as exc:
                        raise ClaimGovernanceError(exc.code) from exc
                connection.execute(
                    """
                    INSERT INTO review_decisions(
                        decision_id, object_type, object_id, object_version,
                        decision, diff_sha256, approver_role,
                        approval_request_id, decided_at
                    ) VALUES (?, 'claim', ?, 1, 'APPROVE', ?, 'knowledge_reviewer', ?, ?)
                    """,
                    (
                        self._ids.object_id("review_decision"),
                        record.claim_id,
                        proposal.draft_sha256,
                        approval_request_id,
                        _utc(now),
                    ),
                )
                connection.execute(
                    "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
                )
            except sqlite3.IntegrityError as exc:
                raise ClaimGovernanceError("CLAIM_COMMIT_CONFLICT") from exc
        self._approval_executor.execute(
            approval_request_id=approval_request_id,
            descriptor=expected,
            operation_kind="claim_approval_operation",
            apply=apply,
        )
        self._records[(record.claim_id, record.version)] = record
        return record

    def _derive_authoritative_provenance(
        self,
        connection: sqlite3.Connection,
        draft: ClaimDraft,
    ) -> Provenance:
        if self._provenance is None:
            raise ClaimGovernanceError("PROVENANCE_POLICY_REQUIRED")
        inputs: list[Provenance] = []
        for evidence in draft.evidence:
            row = connection.execute(
                """
                SELECT normalized_text_sha256, review_status, privacy_scope,
                       provenance_json, source_id
                  FROM passages WHERE passage_id = ? AND version = ?
                """,
                (evidence.passage_ref.object_id, evidence.passage_ref.version),
            ).fetchone()
            if (
                row is None
                or str(row[0]) != evidence.passage_ref.content_sha256
                or str(row[1]) != "APPROVED"
            ):
                raise ClaimGovernanceError("CLAIM_PASSAGE_AUTHORITY_INVALID")
            try:
                provenance = Provenance.model_validate_json(str(row[3]))
            except ValueError:
                raise ClaimGovernanceError("PASSAGE_PROVENANCE_INVALID") from None
            expected_scope = {
                "GLOBAL": "global_source",
                "PRIVATE": "client_private",
                "CASE": "case_derived",
            }.get(str(row[2]))
            if (
                expected_scope is None
                or provenance.provenance_scope != expected_scope
                or evidence.passage_ref.object_id not in provenance.passage_ids
                or (
                    expected_scope == "global_source"
                    and provenance.source_ids != frozenset({str(row[4])})
                )
            ):
                raise ClaimGovernanceError("PASSAGE_PROVENANCE_INVALID")
            inputs.append(provenance)
        try:
            return self._provenance.compute(
                inputs,
                derivation_rule_ref=draft.provenance.derivation_rule_ref,
                target_scope=draft.provenance.provenance_scope,
            )
        except ProvenanceError as exc:
            raise ClaimGovernanceError(exc.code) from exc

    def get(self, claim_id: str, version: int = 1) -> ClaimRecord:
        if self._connection is not None:
            return self._load_from_db(claim_id, version)
        try:
            return self._records[(claim_id, version)]
        except KeyError:
            raise ClaimGovernanceError("CLAIM_NOT_FOUND") from None

    def _pending_case_index_snapshot(self) -> CaseIndexRebuildSnapshot | None:
        if self._connection is None:
            return None
        try:
            return snapshot_pending_case_index_invalidations(self._connection)
        except CaseIndexSerializationError as exc:
            raise ClaimGovernanceError(exc.code) from exc

    @staticmethod
    def _revoke_descriptor(
        current: ClaimRecord,
        pending_case_indexes: CaseIndexRebuildSnapshot | None,
    ) -> DraftDescriptor:
        return DraftDescriptor(
            purpose="claim_revoke",
            target_id=current.claim_id,
            base_version=current.version,
            draft_sha256=canonical_sha256(
                {
                    "action": "revoke",
                    "claim": current.model_dump(mode="json"),
                    "pending_case_index_invalidation": (
                        None
                        if pending_case_indexes is None
                        else {
                            "identity_sha256": (
                                pending_case_indexes.identity_sha256
                            ),
                            "snapshot": pending_case_indexes.model_dump(
                                mode="json"
                            ),
                        }
                    ),
                }
            ),
        )

    def _preview_revoke_bound(
        self,
        claim_id: str,
        version: int,
    ) -> tuple[DraftDescriptor, CaseIndexRebuildSnapshot | None]:
        current = self.get(claim_id, version)
        if current.source_grade == "C1":
            raise ClaimGovernanceError("C1_CLAIM_REVOKE_REQUIRES_THEORY")
        if current.review_status not in {"approved", "reviewed"}:
            raise ClaimGovernanceError("CLAIM_NOT_REVOKABLE")
        pending_case_indexes = self._pending_case_index_snapshot()
        return (
            self._revoke_descriptor(current, pending_case_indexes),
            pending_case_indexes,
        )

    def preview_revoke(self, claim_id: str, version: int = 1) -> DraftDescriptor:
        descriptor, _ = self._preview_revoke_bound(claim_id, version)
        return descriptor

    def revoke(
        self,
        claim_id: str,
        version: int = 1,
        *,
        approval_request_id: str,
    ) -> ClaimRecord:
        if self._approval_executor is None:
            raise ClaimGovernanceError("CLAIM_APPROVAL_EXECUTOR_REQUIRED")
        descriptor, pending_case_indexes = self._preview_revoke_bound(
            claim_id,
            version,
        )
        now = self._clock.now()

        def apply(connection: sqlite3.Connection) -> None:
            if self._connection is None or connection is not self._connection:
                raise ClaimGovernanceError("CLAIM_TARGET_CONNECTION_MISMATCH")
            current_descriptor, current_case_indexes = self._preview_revoke_bound(
                claim_id,
                version,
            )
            if (
                current_descriptor != descriptor
                or current_case_indexes != pending_case_indexes
            ):
                raise ClaimGovernanceError("CLAIM_REVOKE_AUTHORITY_CHANGED")
            if pending_case_indexes is not None and pending_case_indexes.identities:
                epoch_row = connection.execute(
                    "SELECT authorization_epoch, tombstone_epoch "
                    "FROM knowledge_catalog_state WHERE singleton = 1"
                ).fetchone()
                if (
                    epoch_row is None
                    or type(epoch_row[0]) is not int
                    or type(epoch_row[1]) is not int
                ):
                    raise ClaimGovernanceError("KNOWLEDGE_CATALOG_STATE_INVALID")
                try:
                    invalidate_pending_case_indexes_in_transaction(
                        connection,
                        expected_snapshot=pending_case_indexes,
                        authority_request_id=approval_request_id,
                        reason_code="claim_revoked",
                        next_authorization_epoch=int(epoch_row[0]) + 1,
                        next_tombstone_epoch=int(epoch_row[1]) + 1,
                        invalidated_at=now,
                    )
                except CaseIndexSerializationError as exc:
                    raise ClaimGovernanceError(exc.code) from exc
            changed = connection.execute(
                """
                UPDATE claims SET review_status = 'REVOKED'
                 WHERE claim_id = ? AND version = ?
                   AND source_grade <> 'C1'
                   AND review_status IN ('APPROVED', 'REVIEWED')
                """,
                (claim_id, version),
            ).rowcount
            if changed != 1:
                raise ClaimGovernanceError("CLAIM_REVOKE_CONFLICT")
            connection.execute(
                """
                UPDATE wiki_revisions SET review_status = 'REVOKED'
                 WHERE review_status IN ('PREPARED', 'ACTIVE') AND EXISTS (
                    SELECT 1 FROM wiki_revision_claims AS wc
                     WHERE wc.wiki_id = wiki_revisions.wiki_id
                       AND wc.wiki_revision = wiki_revisions.revision
                       AND wc.claim_id = ? AND wc.claim_version = ?
                 )
                """,
                (claim_id, version),
            )
            connection.execute(
                "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
            )
            connection.execute(
                """
                UPDATE artifact_versions SET state = 'STALE'
                 WHERE state IN ('CURRENT', 'REBUILD_QUEUED')
                """
            )
            identity = f"{claim_id}@{version}"
            connection.execute(
                """
                INSERT INTO tombstones(
                    tombstone_id, target_type, target_id_hash,
                    source_lineage_hash, reason_code, created_at
                ) VALUES (?, 'claim_revision', ?, ?, 'claim_revoked', ?)
                """,
                (
                    self._ids.object_id("tombstone"),
                    target_hash("claim_revision", identity),
                    lineage_hash("claim_revision", identity),
                    _utc(now),
                ),
            )
            connection.execute(
                """
                INSERT INTO review_decisions(
                    decision_id, object_type, object_id, object_version,
                    decision, diff_sha256, approver_role,
                    approval_request_id, decided_at
                ) VALUES (?, 'claim', ?, ?, 'REVOKE', ?,
                          'knowledge_reviewer', ?, ?)
                """,
                (
                    self._ids.object_id("review_decision"),
                    claim_id,
                    version,
                    descriptor.draft_sha256,
                    approval_request_id,
                    _utc(now),
                ),
            )
            connection.execute(
                """
                UPDATE knowledge_catalog_state
                   SET catalog_version = catalog_version + 1,
                       authorization_epoch = authorization_epoch + 1,
                       tombstone_epoch = tombstone_epoch + 1
                 WHERE singleton = 1
                """
            )

        self._approval_executor.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind="claim_revocation_operation",
            apply=apply,
        )
        revoked = self.get(claim_id, version)
        self._records[(claim_id, version)] = revoked
        return revoked

    def serialize_retrieval_text(self, claim_id: str, version: int = 1) -> str:
        """Return only claim prose; controlled provenance never enters vectors."""

        return self.get(claim_id, version).text

    def _load_from_db(self, claim_id: str, version: int) -> ClaimRecord:
        if self._connection is None or self._content_store is None:
            raise ClaimGovernanceError("CLAIM_CONTENT_STORE_REQUIRED")
        row = self._connection.execute(
            """
            SELECT claim_object_ref, claim_object_size_bytes,
                   claim_object_media_type, claim_sha256, cognitive_type,
                   source_grade, framework_eligibility, empirical_support,
                   model_confidence, review_status, effective_from,
                   effective_to, review_due_at, applicability_json,
                   privacy_scope, allowed_uses_json, provenance_json,
                   theory_revision_id, theory_revision,
                   theory_revision_sha256, created_at
              FROM claims WHERE claim_id = ? AND version = ?
            """,
            (claim_id, version),
        ).fetchone()
        if row is None:
            raise ClaimGovernanceError("CLAIM_NOT_FOUND")
        digest = _content_digest(str(row[0]))
        reference = self._content_store.reference(
            content_sha256=digest,
            size_bytes=int(row[1]),
            media_type=str(row[2]),
        )
        try:
            text = self._content_store.read_verified(reference).decode(
                "utf-8", errors="strict"
            )
        except UnicodeDecodeError:
            raise ClaimGovernanceError("CLAIM_CONTENT_INVALID") from None
        if digest != str(row[3]) or text_sha256(text) != str(row[3]):
            raise ClaimGovernanceError("CLAIM_CONTENT_HASH_MISMATCH")
        evidence_rows = self._connection.execute(
            """
            SELECT e.passage_id, e.passage_version, p.normalized_text_sha256
              FROM claim_evidence AS e
              JOIN passages AS p
                ON p.passage_id = e.passage_id AND p.version = e.passage_version
             WHERE e.claim_id = ? AND e.claim_version = ?
             ORDER BY e.passage_id, e.passage_version
            """,
            (claim_id, version),
        ).fetchall()
        passage_refs = tuple(
            VersionRef(
                object_id=str(item[0]),
                version=int(item[1]),
                content_sha256=str(item[2]),
            )
            for item in evidence_rows
        )
        theory_ref = None
        if row[17] is not None:
            theory_ref = VersionRef(
                object_id=str(row[17]),
                version=int(row[18]),
                content_sha256=str(row[19]),
            )
        record = ClaimRecord(
            claim_id=claim_id,
            version=version,
            text=text,
            text_sha256=str(row[3]),
            cognitive_type=cast(CognitiveType, str(row[4])),
            source_grade=cast(SourceGrade, str(row[5])),
            framework_eligibility=cast(
                FrameworkEligibility, str(row[6]).lower()
            ),
            empirical_support=cast(EmpiricalSupport, str(row[7])),
            model_confidence=None if row[8] is None else float(row[8]),
            review_status=cast(ReviewStatus, str(row[9]).lower()),
            effective_from=_parse_utc(row[10]),
            effective_to=_parse_utc(row[11]),
            review_due_at=_parse_utc(row[12]),
            applicability=ClaimApplicability.model_validate_json(str(row[13])),
            privacy_scope=cast(PrivacyScope, str(row[14]).lower()),
            allowed_uses=frozenset(json.loads(str(row[15]))),
            passage_refs=passage_refs,
            provenance=Provenance.model_validate_json(str(row[16])),
            theory_revision_ref=theory_ref,
            created_at=_required_utc(row[20]),
        )
        self._records[(record.claim_id, record.version)] = record
        return record


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime | None:
    if value is None:
        return None
    if type(value) is not str:
        raise ClaimGovernanceError("CLAIM_TIMESTAMP_INVALID")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ClaimGovernanceError("CLAIM_TIMESTAMP_INVALID") from None


def _required_utc(value: object) -> datetime:
    parsed = _parse_utc(value)
    if parsed is None:
        raise ClaimGovernanceError("CLAIM_TIMESTAMP_INVALID")
    return parsed


def _content_digest(value: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise ClaimGovernanceError("CLAIM_CONTENT_REF_INVALID")
    return value[len(prefix) :]


__all__ = [
    "ClaimGovernanceError",
    "ClaimPreview",
    "ClaimProposal",
    "ClaimProposalService",
]
