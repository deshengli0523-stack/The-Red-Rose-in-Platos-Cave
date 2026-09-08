"""Exclusive C1 proposal and primary-counselor governance."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.theory import (
    TheoryProposal,
    TheoryRevision,
    TheoryRevisionDraft,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.case_index_serialization import (
    CaseIndexRebuildSnapshot,
    CaseIndexSerializationError,
    invalidate_pending_case_indexes_in_transaction,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore

from ._canonical import canonical_json_bytes, canonical_sha256, text_sha256
from .approval import GovernedWriteExecutor
from .scope_policy import ScopePolicyError, ScopePolicyRepository


class TheoryGovernanceError(RuntimeError):
    pass


class PrimaryCounselorApprovalRequired(TheoryGovernanceError):
    def __init__(self) -> None:
        super().__init__("PRIMARY_COUNSELOR_APPROVAL_REQUIRED")


class TheoryActivationForbidden(TheoryGovernanceError):
    def __init__(self) -> None:
        super().__init__("THEORY_ACTIVATION_REQUIRES_COMBINED_PUBLICATION")


class TheoryRevisionNotFound(TheoryGovernanceError):
    def __init__(self) -> None:
        super().__init__("THEORY_REVISION_NOT_FOUND")


class TheoryVersionConflict(TheoryGovernanceError):
    def __init__(self) -> None:
        super().__init__("THEORY_VERSION_CONFLICT")


class TheoryRevisionService:
    """Prepare C1 revisions; only KnowledgePublicationService may activate."""

    def __init__(
        self,
        *,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
        connection: sqlite3.Connection | None = None,
        primary_role: str = "primary_counselor",
        approval_executor: GovernedWriteExecutor | None = None,
        content_store: ContentStore | None = None,
        scope_policy_repository: ScopePolicyRepository | None = None,
    ) -> None:
        self.id_factory = id_factory or IdFactory()
        self._clock = clock or SystemClock()
        self._connection = connection
        self._primary_role = primary_role
        self._approval_executor = approval_executor
        self._content_store = content_store
        self._scope_policy_repository = scope_policy_repository
        if (
            connection is not None
            and scope_policy_repository is not None
            and scope_policy_repository._connection is not connection
        ):
            raise TypeError(
                "theory and scope policy must share one authority connection"
            )
        self._proposals: dict[str, TheoryProposal] = {}
        self._revisions: dict[tuple[str, int], TheoryRevision] = {}
        self._active: dict[str, int] = {}

    def propose(self, draft: TheoryRevisionDraft, *, actor: str) -> TheoryProposal:
        validated = TheoryRevisionDraft.model_validate(draft)
        if type(actor) is not str or not actor.strip():
            raise ValueError("theory proposal actor is required")
        proposal = TheoryProposal(
            request_id=self.id_factory.object_id("theory_request"),
            draft=validated,
            draft_sha256=canonical_sha256(validated.model_dump(mode="json")),
            actor=actor,
            created_at=self._clock.now(),
        )
        self._proposals[proposal.request_id] = proposal
        return proposal

    def restore_proposal(self, proposal: TheoryProposal) -> TheoryProposal:
        """Restore one hash-verified durable proposal into this service lifespan."""

        validated = TheoryProposal.model_validate(proposal)
        if canonical_sha256(validated.draft.model_dump(mode="json")) != (
            validated.draft_sha256
        ):
            raise TheoryGovernanceError("THEORY_PROPOSAL_HASH_MISMATCH")
        current = self._proposals.get(validated.request_id)
        if current is not None and current != validated:
            raise TheoryGovernanceError("THEORY_PROPOSAL_RESTORE_CONFLICT")
        self._proposals[validated.request_id] = validated
        return validated

    def _next_revision(self, theory_id: str) -> int:
        in_memory = [revision for candidate, revision in self._revisions if candidate == theory_id]
        maximum = max(in_memory, default=0)
        if self._connection is not None:
            row = self._connection.execute(
                "SELECT coalesce(max(revision), 0) FROM theory_revisions WHERE theory_id = ?",
                (theory_id,),
            ).fetchone()
            if row is not None:
                maximum = max(maximum, int(row[0]))
        return maximum + 1

    def approve(
        self,
        request_id: str,
        *,
        actor: str,
        approval_request_id: str | None = None,
    ) -> TheoryRevision:
        if actor != self._primary_role or approval_request_id is None:
            raise PrimaryCounselorApprovalRequired
        if self._approval_executor is None:
            raise PrimaryCounselorApprovalRequired
        try:
            proposal = self._proposals[request_id]
        except KeyError:
            raise TheoryRevisionNotFound from None
        draft = proposal.draft
        self.assert_scope_policy_authority(draft)
        revision_number = self._next_revision(draft.theory_id)
        claim_refs = tuple(
            VersionRef(
                object_id=self.id_factory.object_id("claim"),
                version=1,
                content_sha256=text_sha256(claim),
            )
            for claim in draft.core_claims
        )
        prepared = TheoryRevision(
            theory_id=draft.theory_id,
            revision=revision_number,
            source_ref=draft.source_ref,
            document_sha256=draft.document_sha256,
            author=draft.author,
            declared_version=draft.declared_version,
            empirical_support=draft.empirical_support,
            status="prepared",
            approval_request_id=approval_request_id,
            approved_at=self._clock.now(),
            effective_from=draft.effective_from,
            effective_to=draft.effective_to,
            scope=draft.scope,
            core_claims=draft.core_claims,
            methods=draft.methods,
            contraindications=draft.contraindications,
            counterexamples=draft.counterexamples,
            passage_refs=draft.passage_refs,
            claim_refs=claim_refs,
            citation_refs=draft.citation_refs,
            scope_policy_ref=draft.scope_policy_ref,
            supersedes_ref=draft.supersedes_ref,
            revokes_ref=draft.revokes_ref,
            created_at=self._clock.now(),
        )
        descriptor = self.preview(request_id)
        revision_reference: ContentObjectRef | None = None
        claim_content_references: tuple[ContentObjectRef, ...] = ()
        if self._connection is not None:
            if self._content_store is None:
                raise TheoryGovernanceError("THEORY_CONTENT_STORE_REQUIRED")
            revision_reference = self._content_store.finalize(
                self._content_store.stage_bytes(
                    canonical_json_bytes(prepared.model_dump(mode="json")),
                    purpose="theory_revision",
                    manifest_id=prepared.theory_id,
                    media_type="application/json",
                )
            )
            claim_content_references = tuple(
                self._content_store.finalize(
                    self._content_store.stage_bytes(
                        claim_text.encode("utf-8", errors="strict"),
                        purpose="claim_text",
                        manifest_id=claim_ref.object_id,
                        media_type="text/plain",
                    )
                )
                for claim_text, claim_ref in zip(
                    prepared.core_claims,
                    prepared.claim_refs,
                    strict=True,
                )
            )
            if any(
                reference.content_sha256 != claim_ref.content_sha256
                for reference, claim_ref in zip(
                    claim_content_references,
                    prepared.claim_refs,
                    strict=True,
                )
            ):
                raise TheoryGovernanceError("THEORY_CLAIM_CONTENT_HASH_MISMATCH")

        def apply(connection: sqlite3.Connection) -> None:
            if self._connection is None:
                return
            if connection is not self._connection:
                raise TheoryVersionConflict
            # Re-resolve inside the governed write transaction so a policy
            # revoked or superseded after preview cannot authorize PREPARED.
            self.assert_scope_policy_authority(prepared)
            if revision_reference is None:
                raise TheoryGovernanceError("THEORY_CONTENT_STORE_REQUIRED")
            current_row = connection.execute(
                "SELECT coalesce(max(revision), 0) FROM theory_revisions WHERE theory_id = ?",
                (prepared.theory_id,),
            ).fetchone()
            if current_row != (prepared.revision - 1,):
                raise TheoryVersionConflict
            lineage_ref = prepared.supersedes_ref or prepared.revokes_ref
            if prepared.revision == 1 and lineage_ref is not None:
                raise TheoryGovernanceError("THEORY_INITIAL_LINEAGE_INVALID")
            if prepared.revision > 1 and lineage_ref is None:
                raise TheoryGovernanceError("THEORY_SUCCESSOR_LINEAGE_REQUIRED")
            if lineage_ref is not None:
                lineage_row = connection.execute(
                    """
                    SELECT revision_sha256, status FROM theory_revisions
                     WHERE theory_id = ? AND revision = ?
                    """,
                    (lineage_ref.object_id, lineage_ref.version),
                ).fetchone()
                if (
                    lineage_ref.object_id != prepared.theory_id
                    or lineage_ref.version != prepared.revision - 1
                    or lineage_row is None
                    or str(lineage_row[0]) != lineage_ref.content_sha256
                    or str(lineage_row[1])
                    not in {"PREPARED", "ACTIVE", "SUPERSEDED"}
                ):
                    raise TheoryGovernanceError("THEORY_LINEAGE_AUTHORITY_INVALID")
            source_row = connection.execute(
                """
                SELECT sv.content_sha256, sv.source_grade, s.logical_path,
                       sv.status
                  FROM source_versions AS sv
                  JOIN sources AS s ON s.source_id = sv.source_id
                 WHERE sv.source_id = ? AND sv.version = ?
                """,
                (prepared.source_ref.object_id, prepared.source_ref.version),
            ).fetchone()
            if (
                source_row is None
                or str(source_row[0]) != prepared.source_ref.content_sha256
                or str(source_row[0]) != prepared.document_sha256
                or str(source_row[1]) != "C1"
                or str(source_row[2]).split("/", 1)[0].lower()
                != "consultant-theory"
                or str(source_row[3]) not in {"DRAFT", "REVIEWED", "APPROVED"}
                or prepared.source_ref not in prepared.citation_refs
            ):
                raise TheoryGovernanceError("THEORY_SOURCE_AUTHORITY_INVALID")
            for citation in prepared.citation_refs:
                citation_row = connection.execute(
                    """
                    SELECT content_sha256, status FROM source_versions
                     WHERE source_id = ? AND version = ?
                    """,
                    (citation.object_id, citation.version),
                ).fetchone()
                if (
                    citation_row is None
                    or str(citation_row[0]) != citation.content_sha256
                    or str(citation_row[1])
                    not in {"DRAFT", "REVIEWED", "APPROVED"}
                ):
                    raise TheoryGovernanceError("THEORY_CITATION_AUTHORITY_INVALID")
            for passage in prepared.passage_refs:
                passage_row = connection.execute(
                    """
                    SELECT normalized_text_sha256, source_id, source_version,
                           review_status, privacy_scope
                      FROM passages WHERE passage_id = ? AND version = ?
                    """,
                    (passage.object_id, passage.version),
                ).fetchone()
                if passage_row != (
                    passage.content_sha256,
                    prepared.source_ref.object_id,
                    prepared.source_ref.version,
                    "APPROVED",
                    "GLOBAL",
                ):
                    raise TheoryGovernanceError("THEORY_PASSAGE_AUTHORITY_INVALID")
            try:
                source_changed = connection.execute(
                    """
                    UPDATE source_versions SET status = 'APPROVED'
                     WHERE source_id = ? AND version = ?
                       AND status IN ('DRAFT', 'REVIEWED', 'APPROVED')
                    """,
                    (prepared.source_ref.object_id, prepared.source_ref.version),
                ).rowcount
                if source_changed != 1:
                    raise TheoryGovernanceError("THEORY_SOURCE_AUTHORITY_INVALID")
                connection.execute(
                    """
                    INSERT INTO theory_revisions(
                        theory_id, revision, source_id, source_version,
                        document_sha256, revision_sha256, revision_object_ref,
                        revision_object_size_bytes, revision_object_media_type,
                        author,
                        declared_version, source_grade, empirical_support,
                        status, approval_request_id, approved_at,
                        effective_from, effective_to, applicability_json,
                        core_claims_json, methods_json, contraindications_json,
                        counterexamples_json, citations_json,
                        scope_policy_ref_json, supersedes_revision,
                        revokes_revision, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'C1', ?,
                              'PREPARED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?)
                    """,
                    (
                        prepared.theory_id,
                        prepared.revision,
                        prepared.source_ref.object_id,
                        prepared.source_ref.version,
                        prepared.document_sha256,
                        _revision_content_hash(prepared),
                        f"sha256:{revision_reference.content_sha256}",
                        revision_reference.size_bytes,
                        revision_reference.media_type,
                        prepared.author,
                        prepared.declared_version,
                        prepared.empirical_support,
                        prepared.approval_request_id,
                        _utc(prepared.approved_at),
                        _utc(prepared.effective_from),
                        _utc(prepared.effective_to),
                        _json(prepared.scope.model_dump(mode="json")),
                        _json(prepared.core_claims),
                        _json(prepared.methods),
                        _json(prepared.contraindications),
                        _json(prepared.counterexamples),
                        _json([item.model_dump(mode="json") for item in prepared.citation_refs]),
                        _json(prepared.scope_policy_ref.model_dump(mode="json")),
                        None if prepared.supersedes_ref is None else prepared.supersedes_ref.version,
                        None if prepared.revokes_ref is None else prepared.revokes_ref.version,
                        _utc(prepared.created_at),
                    ),
                )
                for ordinal, passage in enumerate(prepared.passage_refs):
                    connection.execute(
                        """
                        INSERT INTO theory_revision_passages(
                            theory_id, theory_revision, passage_id,
                            passage_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            prepared.theory_id,
                            prepared.revision,
                            passage.object_id,
                            passage.version,
                            ordinal,
                        ),
                    )
                provenance_json = _json(
                    {
                        "case_contributor_client_ids": [],
                        "case_ids": [],
                        "client_ids": [],
                        "derivation_rule_ref": prepared.scope_policy_ref.model_dump(
                            mode="json"
                        ),
                        "passage_ids": sorted(
                            item.object_id for item in prepared.passage_refs
                        ),
                        "private_owner_client_id": None,
                        "provenance_scope": "global_source",
                        "source_ids": [prepared.source_ref.object_id],
                    }
                )
                applicability_json = _json(prepared.scope.model_dump(mode="json"))
                theory_revision_sha256 = _revision_content_hash(prepared)
                for claim_text, claim_ref, claim_content_reference in zip(
                    prepared.core_claims,
                    prepared.claim_refs,
                    claim_content_references,
                    strict=True,
                ):
                    connection.execute(
                        """
                        INSERT INTO claims(
                            claim_id, version, claim_object_ref, claim_sha256,
                            claim_object_size_bytes, claim_object_media_type,
                            cognitive_type, source_grade,
                            framework_eligibility, empirical_support,
                            model_confidence, review_status, effective_from,
                            effective_to, review_due_at, applicability_json,
                            privacy_scope, allowed_uses_json, provenance_json,
                            theory_revision_id, theory_revision,
                            theory_revision_sha256, created_at
                        ) VALUES (?, 1, ?, ?, ?, ?, 'counselor_judgment', 'C1',
                                  'CONDITIONAL', ?, NULL, 'REVIEWED', ?, ?, NULL,
                                  ?, 'GLOBAL', '["consultation"]', ?, ?, ?, ?, ?)
                        """,
                        (
                            claim_ref.object_id,
                            f"sha256:{claim_content_reference.content_sha256}",
                            claim_ref.content_sha256,
                            claim_content_reference.size_bytes,
                            claim_content_reference.media_type,
                            prepared.empirical_support,
                            _utc(prepared.effective_from),
                            _utc(prepared.effective_to),
                            applicability_json,
                            provenance_json,
                            prepared.theory_id,
                            prepared.revision,
                            theory_revision_sha256,
                            _utc(prepared.created_at),
                        ),
                    )
                    for passage in prepared.passage_refs:
                        connection.execute(
                            """
                            INSERT INTO claim_evidence(
                                claim_id, claim_version, passage_id,
                                passage_version, relation, evidence_role
                            ) VALUES (?, 1, ?, ?, 'SUPPORTS', 'PRIMARY')
                            """,
                            (
                                claim_ref.object_id,
                                passage.object_id,
                                passage.version,
                            ),
                        )
                connection.execute(
                    "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
                )
            except sqlite3.IntegrityError as exc:
                raise TheoryVersionConflict from exc
        self._approval_executor.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind="theory_approval_operation",
            apply=apply,
        )
        self._revisions[(prepared.theory_id, prepared.revision)] = prepared
        return self.get(prepared.theory_id, prepared.revision)

    def preview(self, request_id: str) -> DraftDescriptor:
        try:
            proposal = self._proposals[request_id]
        except KeyError:
            raise TheoryRevisionNotFound from None
        return DraftDescriptor(
            purpose="theory_approve",
            target_id=proposal.draft.theory_id,
            base_version=self._next_revision(proposal.draft.theory_id) - 1,
            draft_sha256=proposal.draft_sha256,
        )

    def activate(self, theory_id: str, revision: int) -> None:
        del theory_id, revision
        raise TheoryActivationForbidden

    def assert_scope_policy_authority(
        self,
        theory: TheoryRevisionDraft | TheoryRevision,
    ) -> None:
        """Require one exact, approved CAS-backed policy for this theory interval.

        This check is intentionally reusable by combined publication.  Approval
        validates before staging and again in its write transaction; publication
        validates once more immediately before activation.  A service without an
        injected repository has no authority to trust caller-supplied refs.
        """

        repository = self._scope_policy_repository
        if repository is None:
            raise TheoryGovernanceError("THEORY_SCOPE_POLICY_AUTHORITY_REQUIRED")
        try:
            record = repository.get_record(theory.scope_policy_ref)
        except (ScopePolicyError, sqlite3.Error):
            raise TheoryGovernanceError(
                "THEORY_SCOPE_POLICY_AUTHORITY_INVALID"
            ) from None
        authority_at = max(self._clock.now(), theory.effective_from)
        if (
            record.semantic_ref != theory.scope_policy_ref
            or record.status != "APPROVED"
            or theory.effective_from < record.effective_from
            or (theory.effective_to is not None and theory.effective_to <= authority_at)
            or (
                record.effective_to is not None
                and (
                    record.effective_to <= authority_at
                    or theory.effective_to is None
                    or theory.effective_to > record.effective_to
                )
            )
        ):
            raise TheoryGovernanceError("THEORY_SCOPE_POLICY_AUTHORITY_INVALID")

    def _activate_from_publication(self, theory_id: str, revision: int) -> TheoryRevision:
        if self._connection is not None:
            active = self._load_from_db(theory_id, revision)
            if active.status != "active":
                raise TheoryVersionConflict
            self._revisions[(theory_id, revision)] = active
            self._active[theory_id] = revision
            return active
        try:
            prepared = self._revisions[(theory_id, revision)]
        except KeyError:
            raise TheoryRevisionNotFound from None
        self.assert_scope_policy_authority(prepared)
        if prepared.status != "prepared":
            raise TheoryVersionConflict
        previous = self._active.get(theory_id)
        if previous is not None:
            old = self._revisions[(theory_id, previous)]
            self._revisions[(theory_id, previous)] = old.model_copy(
                update={"status": "superseded"}
            )
        active = prepared.model_copy(update={"status": "active"})
        self._revisions[(theory_id, revision)] = active
        self._active[theory_id] = revision
        return active

    def revoke(
        self,
        theory_id: str,
        revision: int,
        *,
        actor: str,
        approval_request_id: str | None = None,
    ) -> TheoryRevision:
        if actor != self._primary_role or approval_request_id is None:
            raise PrimaryCounselorApprovalRequired
        if self._approval_executor is None:
            raise PrimaryCounselorApprovalRequired
        descriptor, pending_case_indexes = self._preview_revoke_bound(
            theory_id,
            revision,
        )
        current = self.get(theory_id, revision)
        revoked = current.model_copy(update={"status": "revoked"})
        now = self._clock.now()

        def apply(connection: sqlite3.Connection) -> None:
            if self._connection is None:
                return
            if connection is not self._connection:
                raise TheoryVersionConflict
            current_descriptor, current_case_indexes = self._preview_revoke_bound(
                theory_id,
                revision,
            )
            if (
                current_descriptor != descriptor
                or current_case_indexes != pending_case_indexes
            ):
                raise TheoryGovernanceError("THEORY_REVOKE_AUTHORITY_CHANGED")
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
                    raise TheoryGovernanceError("KNOWLEDGE_CATALOG_STATE_INVALID")
                try:
                    invalidate_pending_case_indexes_in_transaction(
                        connection,
                        expected_snapshot=pending_case_indexes,
                        authority_request_id=approval_request_id,
                        reason_code="theory_revoked",
                        next_authorization_epoch=int(epoch_row[0]) + 1,
                        next_tombstone_epoch=int(epoch_row[1]) + 1,
                        invalidated_at=now,
                    )
                except CaseIndexSerializationError as exc:
                    raise TheoryGovernanceError(str(exc)) from exc
            changed = connection.execute(
                "UPDATE theory_revisions SET status = 'REVOKED' WHERE theory_id = ? AND revision = ? AND status IN ('PREPARED', 'ACTIVE')",
                (theory_id, revision),
            ).rowcount
            if changed != 1:
                raise TheoryVersionConflict
            connection.execute(
                """
                UPDATE claims SET review_status = 'REVOKED'
                 WHERE source_grade = 'C1' AND theory_revision_id = ?
                   AND theory_revision = ?
                   AND review_status IN ('REVIEWED', 'APPROVED')
                """,
                (theory_id, revision),
            )
            dependent_wikis = connection.execute(
                """
                SELECT DISTINCT wc.wiki_id, wc.wiki_revision
                  FROM wiki_revision_claims AS wc
                  JOIN claims AS c
                    ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
                 WHERE c.source_grade = 'C1' AND c.theory_revision_id = ?
                   AND c.theory_revision = ?
                """,
                (theory_id, revision),
            ).fetchall()
            for wiki_id, wiki_revision in dependent_wikis:
                connection.execute(
                    """
                    UPDATE wiki_revisions SET review_status = 'REVOKED'
                     WHERE wiki_id = ? AND revision = ?
                       AND review_status IN ('PREPARED', 'ACTIVE')
                    """,
                    (wiki_id, wiki_revision),
                )
            # An emergency authority revoke retires the current runtime epoch.
            # No stale graph/vector/Wiki closure remains addressable as current;
            # a complete newly approved publication is required to resume.
            connection.execute(
                "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
            )
            connection.execute(
                """
                UPDATE artifact_versions SET state = 'STALE'
                 WHERE state IN ('CURRENT', 'REBUILD_QUEUED')
                """
            )
            identity = f"{theory_id}@{revision}"
            connection.execute(
                """
                INSERT INTO tombstones(
                    tombstone_id, target_type, target_id_hash,
                    source_lineage_hash, reason_code, created_at
                ) VALUES (?, 'theory_revision', ?, ?, 'theory_revoked', ?)
                """,
                (
                    self.id_factory.object_id("tombstone"),
                    target_hash("theory_revision", identity),
                    lineage_hash("theory_revision", identity),
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
            operation_kind="theory_revocation_operation",
            apply=apply,
        )
        self._revisions[(theory_id, revision)] = revoked
        if self._active.get(theory_id) == revision:
            del self._active[theory_id]
        return self.get(theory_id, revision)

    def _pending_case_index_snapshot(self) -> CaseIndexRebuildSnapshot | None:
        if self._connection is None:
            return None
        try:
            return snapshot_pending_case_index_invalidations(self._connection)
        except CaseIndexSerializationError as exc:
            raise TheoryGovernanceError(str(exc)) from exc

    @staticmethod
    def _revoke_descriptor(
        current: TheoryRevision,
        pending_case_indexes: CaseIndexRebuildSnapshot | None,
    ) -> DraftDescriptor:
        return DraftDescriptor(
            purpose="theory_revoke",
            target_id=current.theory_id,
            base_version=current.revision,
            draft_sha256=canonical_sha256(
                {
                    "action": "revoke",
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
                    "revision": current.model_dump(mode="json"),
                }
            ),
        )

    def _preview_revoke_bound(
        self,
        theory_id: str,
        revision: int,
    ) -> tuple[DraftDescriptor, CaseIndexRebuildSnapshot | None]:
        current = self.get(theory_id, revision)
        pending_case_indexes = self._pending_case_index_snapshot()
        return (
            self._revoke_descriptor(current, pending_case_indexes),
            pending_case_indexes,
        )

    def preview_revoke(self, theory_id: str, revision: int) -> DraftDescriptor:
        descriptor, _ = self._preview_revoke_bound(theory_id, revision)
        return descriptor

    def get(self, theory_id: str, revision: int) -> TheoryRevision:
        if self._connection is not None:
            return self._load_from_db(theory_id, revision)
        try:
            return self._revisions[(theory_id, revision)]
        except KeyError:
            raise TheoryRevisionNotFound from None

    def version_ref(self, theory_id: str, revision: int) -> VersionRef:
        value = self.get(theory_id, revision)
        return VersionRef(
            object_id=value.theory_id,
            version=value.revision,
            content_sha256=_revision_content_hash(value),
        )

    def get_by_ref(self, reference: VersionRef) -> TheoryRevision:
        validated = VersionRef.model_validate(reference)
        value = self.get(validated.object_id, validated.version)
        if _revision_content_hash(value) != validated.content_sha256:
            raise TheoryVersionConflict
        return value

    def get_active(
        self, theory_id: str, *, at: datetime | None = None
    ) -> TheoryRevision | None:
        if self._connection is not None:
            rows = self._connection.execute(
                """
                SELECT revision FROM theory_revisions
                 WHERE theory_id = ? AND status = 'ACTIVE'
                """,
                (theory_id,),
            ).fetchall()
            if len(rows) > 1:
                raise TheoryVersionConflict
            if not rows:
                return None
            value = self._load_from_db(theory_id, int(rows[0][0]))
        else:
            revision = self._active.get(theory_id)
            if revision is None:
                return None
            value = self._revisions[(theory_id, revision)]
        effective = at or self._clock.now()
        if value.status != "active" or effective < value.effective_from:
            return None
        if value.effective_to is not None and effective >= value.effective_to:
            return None
        return value

    def _load_from_db(self, theory_id: str, revision: int) -> TheoryRevision:
        if self._connection is None or self._content_store is None:
            raise TheoryGovernanceError("THEORY_CONTENT_STORE_REQUIRED")
        row = self._connection.execute(
            """
            SELECT revision_object_ref, revision_object_size_bytes,
                   revision_object_media_type, status, source_id,
                   source_version, document_sha256, approval_request_id,
                   revision_sha256
              FROM theory_revisions
             WHERE theory_id = ? AND revision = ?
            """,
            (theory_id, revision),
        ).fetchone()
        if row is None:
            raise TheoryRevisionNotFound
        digest = _content_digest(str(row[0]))
        reference = self._content_store.reference(
            content_sha256=digest,
            size_bytes=int(row[1]),
            media_type=str(row[2]),
        )
        payload = self._content_store.read_verified(reference)
        try:
            stored = TheoryRevision.model_validate_json(payload)
        except ValueError:
            raise TheoryGovernanceError("THEORY_CONTENT_INVALID") from None
        if (
            stored.theory_id != theory_id
            or stored.revision != revision
            or stored.source_ref.object_id != str(row[4])
            or stored.source_ref.version != int(row[5])
            or stored.document_sha256 != str(row[6])
            or stored.approval_request_id != str(row[7])
        ):
            raise TheoryGovernanceError("THEORY_AUTHORITY_ROW_MISMATCH")
        status = str(row[3]).lower()
        if status not in {
            "draft",
            "prepared",
            "active",
            "superseded",
            "revoked",
            "expired",
        }:
            raise TheoryGovernanceError("THEORY_STATUS_INVALID")
        loaded = stored.model_copy(update={"status": status})
        expected_revision_sha256 = _revision_content_hash(loaded)
        if str(row[8]) != expected_revision_sha256:
            raise TheoryGovernanceError("THEORY_AUTHORITY_ROW_MISMATCH")
        claim_rows = self._connection.execute(
            """
            SELECT claim_id, version, claim_sha256, theory_revision_sha256
              FROM claims
             WHERE source_grade = 'C1' AND theory_revision_id = ?
               AND theory_revision = ?
             ORDER BY claim_id, version
            """,
            (theory_id, revision),
        ).fetchall()
        database_claims = {
            (str(item[0]), int(item[1]), str(item[2])) for item in claim_rows
        }
        stored_claims = {
            (item.object_id, item.version, item.content_sha256)
            for item in loaded.claim_refs
        }
        if database_claims != stored_claims or any(
            str(item[3]) != expected_revision_sha256 for item in claim_rows
        ):
            raise TheoryGovernanceError("THEORY_CLAIM_BINDING_MISMATCH")
        if loaded.status in {"prepared", "active"}:
            self.assert_scope_policy_authority(loaded)
        self._revisions[(loaded.theory_id, loaded.revision)] = loaded
        if loaded.status == "active":
            self._active[loaded.theory_id] = loaded.revision
        return loaded


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _revision_content_hash(value: TheoryRevision) -> str:
    payload = value.model_dump(mode="json")
    payload.pop("status", None)
    return canonical_sha256(payload)


def _content_digest(value: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise TheoryGovernanceError("THEORY_CONTENT_REF_INVALID")
    return value[len(prefix) :]


__all__ = [
    "PrimaryCounselorApprovalRequired",
    "TheoryActivationForbidden",
    "TheoryGovernanceError",
    "TheoryRevisionNotFound",
    "TheoryRevisionService",
    "TheoryVersionConflict",
]
