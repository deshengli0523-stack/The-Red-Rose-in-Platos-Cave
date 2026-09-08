"""Structured LLM Wiki diffs and prepared revisions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from typing import Literal

from pydantic import model_validator

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import (
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.wiki import WikiRevision, WikiRevisionDraft
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.evidence import SourceGrade
from consultation_kb.vault.content_store import ContentStore

from ._canonical import canonical_json_bytes, canonical_sha256
from .approval import GovernedWriteExecutor


class WikiGovernanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WikiProposal(StrictModel):
    proposal_id: ObjectId
    draft: WikiRevisionDraft
    draft_sha256: Sha256Hex
    created_at: UtcDateTime


class WikiClaimAuthority(StrictModel):
    status: Literal["approved", "prepared", "unavailable"]
    source_grade: SourceGrade
    theory_revision_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _validate_theory_binding(self) -> "WikiClaimAuthority":
        if self.source_grade == "C1" and self.theory_revision_ref is None:
            raise ValueError("C1 Wiki claim authority requires a theory revision")
        if self.source_grade != "C1" and self.theory_revision_ref is not None:
            raise ValueError("only C1 Wiki claims bind a theory revision")
        return self


def wiki_revision_body_payload(
    value: WikiRevision | WikiRevisionDraft,
) -> dict[str, object]:
    """Return the one canonical Wiki body shared by write/read/graph authority."""

    return {
        "graph_relations": [
            item.model_dump(mode="json") for item in value.graph_relations
        ],
        "relationships": [
            item.model_dump(mode="json") for item in value.relationships
        ],
        "sections": [item.model_dump(mode="json") for item in value.sections],
        "theory_revision_refs": [
            item.model_dump(mode="json") for item in value.theory_revision_refs
        ],
        "title": value.title,
        "unresolved_questions": value.unresolved_questions,
    }


def wiki_revision_body_sha256(value: WikiRevision | WikiRevisionDraft) -> str:
    """Hash exactly the persisted Wiki body, including graph declarations."""

    return canonical_sha256(wiki_revision_body_payload(value))


class WikiRevisionService:
    """Prepare Wiki diffs; activation is reserved for combined publication."""

    def __init__(
        self,
        *,
        claim_resolver: Callable[[VersionRef], WikiClaimAuthority | str] | None = None,
        passage_resolver: Callable[[VersionRef], object] | None = None,
        theory_resolver: Callable[[VersionRef], str] | None = None,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
        connection: sqlite3.Connection | None = None,
        approval_executor: GovernedWriteExecutor | None = None,
        content_store: ContentStore | None = None,
    ) -> None:
        self._claims = claim_resolver
        self._passages = passage_resolver
        self._theories = theory_resolver
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()
        self._connection = connection
        self._approval_executor = approval_executor
        self._content_store = content_store
        self._proposals: dict[str, WikiProposal] = {}
        self._revisions: dict[tuple[str, int], WikiRevision] = {}
        self._active: dict[str, int] = {}

    def propose_diff(self, draft: WikiRevisionDraft) -> WikiProposal:
        validated = WikiRevisionDraft.model_validate(draft)
        proposal = WikiProposal(
            proposal_id=self._ids.object_id("wiki_proposal"),
            draft=validated,
            draft_sha256=canonical_sha256(validated.model_dump(mode="json")),
            created_at=self._clock.now(),
        )
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def restore_proposal(self, proposal: WikiProposal) -> WikiProposal:
        """Restore one hash-verified durable proposal into this service lifespan."""

        validated = WikiProposal.model_validate(proposal)
        if canonical_sha256(validated.draft.model_dump(mode="json")) != (
            validated.draft_sha256
        ):
            raise WikiGovernanceError("WIKI_PROPOSAL_HASH_MISMATCH")
        current = self._proposals.get(validated.proposal_id)
        if current is not None and current != validated:
            raise WikiGovernanceError("WIKI_PROPOSAL_RESTORE_CONFLICT")
        self._proposals[validated.proposal_id] = validated
        return validated

    def _current_revision(self, wiki_id: str) -> int:
        values = [revision for candidate, revision in self._revisions if candidate == wiki_id]
        maximum = max(values, default=0)
        if self._connection is not None:
            row = self._connection.execute(
                "SELECT coalesce(max(revision), 0) FROM wiki_revisions WHERE wiki_id = ?",
                (wiki_id,),
            ).fetchone()
            if row is not None:
                maximum = max(maximum, int(row[0]))
        return maximum

    def approve(
        self,
        proposal_id: str,
        *,
        actor: str,
        approval_request_id: str,
    ) -> WikiRevision:
        if actor not in {"primary_counselor", "knowledge_reviewer"}:
            raise WikiGovernanceError("WIKI_REVIEWER_APPROVAL_REQUIRED")
        if self._approval_executor is None:
            raise WikiGovernanceError("WIKI_APPROVAL_EXECUTOR_REQUIRED")
        try:
            proposal = self._proposals[proposal_id]
        except KeyError:
            raise WikiGovernanceError("WIKI_PROPOSAL_NOT_FOUND") from None
        draft = proposal.draft
        if self._connection is not None and (
            self._claims is None or self._passages is None or self._theories is None
        ):
            raise WikiGovernanceError("WIKI_AUTHORITY_RESOLVERS_REQUIRED")
        if self._current_revision(draft.wiki_id) != draft.base_revision:
            raise WikiGovernanceError("WIKI_BASE_VERSION_CONFLICT")
        theory_statuses: dict[tuple[str, int, str], str] = {}
        for theory_ref in draft.theory_revision_refs:
            status = "unavailable" if self._theories is None else self._theories(theory_ref)
            if status not in {"prepared", "active"}:
                raise WikiGovernanceError("WIKI_THEORY_NOT_APPROVED")
            theory_statuses[
                (
                    theory_ref.object_id,
                    theory_ref.version,
                    theory_ref.content_sha256,
                )
            ] = status
        for section in draft.sections:
            for claim_ref in section.claim_refs:
                if self._claims is not None:
                    resolved = self._claims(claim_ref)
                    if isinstance(resolved, str):
                        if self._connection is not None:
                            raise WikiGovernanceError("WIKI_CLAIM_AUTHORITY_INVALID")
                        if resolved != "approved":
                            raise WikiGovernanceError("WIKI_CLAIM_NOT_APPROVED")
                    else:
                        authority = WikiClaimAuthority.model_validate(resolved)
                        if authority.source_grade == "C1":
                            bound_theory_ref = authority.theory_revision_ref
                            assert bound_theory_ref is not None
                            theory_key = (
                                bound_theory_ref.object_id,
                                bound_theory_ref.version,
                                bound_theory_ref.content_sha256,
                            )
                            theory_status = theory_statuses.get(theory_key)
                            valid = (
                                authority.status == "prepared"
                                and theory_status == "prepared"
                            ) or (
                                authority.status == "approved"
                                and theory_status == "active"
                            )
                            if not valid:
                                raise WikiGovernanceError(
                                    "WIKI_C1_CLAIM_THEORY_BINDING_INVALID"
                                )
                        elif authority.status != "approved":
                            raise WikiGovernanceError("WIKI_CLAIM_NOT_APPROVED")
            for passage_ref in section.passage_refs:
                if self._passages is not None:
                    self._passages(passage_ref)
        revision = draft.base_revision + 1
        body_payload = wiki_revision_body_payload(draft)
        prepared = WikiRevision(
            wiki_id=draft.wiki_id,
            revision=revision,
            slug=draft.slug,
            title=draft.title,
            base_revision=draft.base_revision,
            diff_kind=draft.diff_kind,
            sections=draft.sections,
            theory_revision_refs=draft.theory_revision_refs,
            relationships=draft.relationships,
            graph_relations=draft.graph_relations,
            review_due_at=draft.review_due_at,
            unresolved_questions=draft.unresolved_questions,
            body_sha256=wiki_revision_body_sha256(draft),
            diff_sha256=proposal.draft_sha256,
            status="prepared",
            approval_request_id=approval_request_id,
            created_at=self._clock.now(),
        )
        descriptor = self.preview(proposal_id)
        body_reference = None
        diff_reference = None
        if self._connection is not None:
            if self._content_store is None:
                raise WikiGovernanceError("WIKI_CONTENT_STORE_REQUIRED")
            body_reference = self._content_store.finalize(
                self._content_store.stage_bytes(
                    canonical_json_bytes(body_payload),
                    purpose="wiki_body",
                    manifest_id=prepared.wiki_id,
                    media_type="application/json",
                )
            )
            diff_reference = self._content_store.finalize(
                self._content_store.stage_bytes(
                    canonical_json_bytes(draft.model_dump(mode="json")),
                    purpose="wiki_diff",
                    manifest_id=proposal.proposal_id,
                    media_type="application/json",
                )
            )
            if (
                body_reference.content_sha256 != prepared.body_sha256
                or diff_reference.content_sha256 != prepared.diff_sha256
            ):
                raise WikiGovernanceError("WIKI_CONTENT_HASH_MISMATCH")

        def apply(connection: sqlite3.Connection) -> None:
            if self._connection is None:
                return
            if connection is not self._connection:
                raise WikiGovernanceError("WIKI_TARGET_CONNECTION_MISMATCH")
            if body_reference is None or diff_reference is None:
                raise WikiGovernanceError("WIKI_CONTENT_STORE_REQUIRED")
            current_row = connection.execute(
                "SELECT coalesce(max(revision), 0) FROM wiki_revisions WHERE wiki_id = ?",
                (prepared.wiki_id,),
            ).fetchone()
            if current_row != (prepared.base_revision,):
                raise WikiGovernanceError("WIKI_BASE_VERSION_CONFLICT")
            authoritative_theories: dict[tuple[str, int, str], str] = {}
            for reference in prepared.theory_revision_refs:
                theory_row = connection.execute(
                    """
                    SELECT revision_sha256, status FROM theory_revisions
                     WHERE theory_id = ? AND revision = ?
                    """,
                    (reference.object_id, reference.version),
                ).fetchone()
                if (
                    theory_row is None
                    or str(theory_row[0]) != reference.content_sha256
                    or str(theory_row[1]) not in {"PREPARED", "ACTIVE"}
                ):
                    raise WikiGovernanceError("WIKI_THEORY_AUTHORITY_CHANGED")
                authoritative_theories[
                    (reference.object_id, reference.version, reference.content_sha256)
                ] = str(theory_row[1])
            for section in prepared.sections:
                for claim in section.claim_refs:
                    claim_row = connection.execute(
                        """
                        SELECT claim_sha256, review_status, source_grade,
                               privacy_scope, theory_revision_id,
                               theory_revision, theory_revision_sha256
                          FROM claims WHERE claim_id = ? AND version = ?
                        """,
                        (claim.object_id, claim.version),
                    ).fetchone()
                    if (
                        claim_row is None
                        or str(claim_row[0]) != claim.content_sha256
                        or str(claim_row[3]) != "GLOBAL"
                    ):
                        raise WikiGovernanceError("WIKI_CLAIM_AUTHORITY_CHANGED")
                    if str(claim_row[2]) == "C1":
                        key = (str(claim_row[4]), int(claim_row[5]), str(claim_row[6]))
                        theory_status = authoritative_theories.get(key)
                        valid = (
                            str(claim_row[1]) == "REVIEWED"
                            and theory_status == "PREPARED"
                        ) or (
                            str(claim_row[1]) == "APPROVED"
                            and theory_status == "ACTIVE"
                        )
                        if not valid:
                            raise WikiGovernanceError(
                                "WIKI_C1_CLAIM_AUTHORITY_CHANGED"
                            )
                    elif str(claim_row[1]) != "APPROVED":
                        raise WikiGovernanceError("WIKI_CLAIM_AUTHORITY_CHANGED")
                for passage in section.passage_refs:
                    passage_row = connection.execute(
                        """
                        SELECT normalized_text_sha256, review_status, privacy_scope
                          FROM passages WHERE passage_id = ? AND version = ?
                        """,
                        (passage.object_id, passage.version),
                    ).fetchone()
                    if passage_row != (
                        passage.content_sha256,
                        "APPROVED",
                        "GLOBAL",
                    ):
                        raise WikiGovernanceError("WIKI_PASSAGE_AUTHORITY_CHANGED")
            for relationship in prepared.relationships:
                for source in relationship.source_refs:
                    source_row = connection.execute(
                        """
                        SELECT content_sha256, status FROM source_versions
                         WHERE source_id = ? AND version = ?
                        """,
                        (source.object_id, source.version),
                    ).fetchone()
                    if (
                        source_row is None
                        or str(source_row[0]) != source.content_sha256
                        or str(source_row[1]) not in {"REVIEWED", "APPROVED"}
                    ):
                        raise WikiGovernanceError("WIKI_RELATION_SOURCE_INVALID")
            try:
                connection.execute(
                    """
                    INSERT INTO wiki_revisions(
                        wiki_id, revision, slug, title, body_object_ref,
                        body_object_size_bytes, body_object_media_type,
                        body_sha256, base_revision, diff_kind, diff_object_ref,
                        diff_object_size_bytes, diff_object_media_type, diff_sha256,
                        review_status, review_due_at, approval_request_id,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'PREPARED', ?, ?, ?)
                    """,
                    (
                        prepared.wiki_id,
                        prepared.revision,
                        prepared.slug,
                        prepared.title,
                        f"sha256:{body_reference.content_sha256}",
                        body_reference.size_bytes,
                        body_reference.media_type,
                        prepared.body_sha256,
                        prepared.base_revision,
                        prepared.diff_kind.upper(),
                        f"sha256:{diff_reference.content_sha256}",
                        diff_reference.size_bytes,
                        diff_reference.media_type,
                        prepared.diff_sha256,
                        None if prepared.review_due_at is None else _utc(prepared.review_due_at),
                        prepared.approval_request_id,
                        _utc(prepared.created_at),
                    ),
                )
                for section in prepared.sections:
                    for ordinal, claim in enumerate(section.claim_refs):
                        connection.execute(
                            """
                            INSERT INTO wiki_revision_claims(
                                wiki_id, wiki_revision, section_key,
                                claim_id, claim_version, stance, ordinal
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                prepared.wiki_id,
                                prepared.revision,
                                section.key,
                                claim.object_id,
                                claim.version,
                                section.stance.upper(),
                                ordinal,
                            ),
                        )
                connection.execute(
                    "UPDATE knowledge_catalog_state SET catalog_version = catalog_version + 1 WHERE singleton = 1"
                )
            except sqlite3.IntegrityError as exc:
                raise WikiGovernanceError("WIKI_COMMIT_CONFLICT") from exc
        self._approval_executor.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind="wiki_approval_operation",
            apply=apply,
        )
        self._revisions[(prepared.wiki_id, prepared.revision)] = prepared
        return self.get(prepared.wiki_id, prepared.revision)

    def preview(self, proposal_id: str) -> DraftDescriptor:
        try:
            proposal = self._proposals[proposal_id]
        except KeyError:
            raise WikiGovernanceError("WIKI_PROPOSAL_NOT_FOUND") from None
        return DraftDescriptor(
            purpose="wiki_publish",
            target_id=proposal.draft.wiki_id,
            base_version=proposal.draft.base_revision,
            draft_sha256=proposal.draft_sha256,
        )

    def activate(self, wiki_id: str, revision: int) -> None:
        del wiki_id, revision
        raise WikiGovernanceError("WIKI_ACTIVATION_REQUIRES_COMBINED_PUBLICATION")

    def _activate_from_publication(self, wiki_id: str, revision: int) -> WikiRevision:
        if self._connection is not None:
            active = self._load_from_db(wiki_id, revision)
            if active.status != "active":
                raise WikiGovernanceError("WIKI_REVISION_NOT_ACTIVE")
            self._revisions[(wiki_id, revision)] = active
            self._active[wiki_id] = revision
            return active
        try:
            prepared = self._revisions[(wiki_id, revision)]
        except KeyError:
            raise WikiGovernanceError("WIKI_REVISION_NOT_FOUND") from None
        if prepared.status != "prepared":
            raise WikiGovernanceError("WIKI_REVISION_NOT_PREPARED")
        previous = self._active.get(wiki_id)
        if previous is not None:
            old = self._revisions[(wiki_id, previous)]
            self._revisions[(wiki_id, previous)] = old.model_copy(
                update={"status": "superseded"}
            )
        active = prepared.model_copy(update={"status": "active"})
        self._revisions[(wiki_id, revision)] = active
        self._active[wiki_id] = revision
        return active

    def get(self, wiki_id: str, revision: int) -> WikiRevision:
        if self._connection is not None:
            return self._load_from_db(wiki_id, revision)
        try:
            return self._revisions[(wiki_id, revision)]
        except KeyError:
            raise WikiGovernanceError("WIKI_REVISION_NOT_FOUND") from None

    def get_active(self, wiki_id: str) -> WikiRevision | None:
        if self._connection is not None:
            rows = self._connection.execute(
                """
                SELECT revision FROM wiki_revisions
                 WHERE wiki_id = ? AND review_status = 'ACTIVE'
                """,
                (wiki_id,),
            ).fetchall()
            if len(rows) > 1:
                raise WikiGovernanceError("WIKI_MULTIPLE_ACTIVE_REVISIONS")
            if not rows:
                return None
            value = self._load_from_db(wiki_id, int(rows[0][0]))
            return value if self._runtime_authority_is_usable(value) else None
        revision = self._active.get(wiki_id)
        return None if revision is None else self._revisions[(wiki_id, revision)]

    def _runtime_authority_is_usable(self, value: WikiRevision) -> bool:
        if self._connection is None:
            return True
        if self._claims is None or self._passages is None or self._theories is None:
            return False
        theory_keys = {
            (reference.object_id, reference.version, reference.content_sha256)
            for reference in value.theory_revision_refs
        }
        try:
            if any(
                self._theories(reference) != "active"
                for reference in value.theory_revision_refs
            ):
                return False
            for section in value.sections:
                for claim in section.claim_refs:
                    row = self._connection.execute(
                        """
                        SELECT claim_sha256, review_status, privacy_scope,
                               source_grade, theory_revision_id,
                               theory_revision, theory_revision_sha256
                          FROM claims WHERE claim_id = ? AND version = ?
                        """,
                        (claim.object_id, claim.version),
                    ).fetchone()
                    if (
                        row is None
                        or str(row[0]) != claim.content_sha256
                        or str(row[1]) != "APPROVED"
                        or str(row[2]) != "GLOBAL"
                    ):
                        return False
                    if str(row[3]) == "C1" and (
                        str(row[4]),
                        int(row[5]),
                        str(row[6]),
                    ) not in theory_keys:
                        return False
                for passage in section.passage_refs:
                    row = self._connection.execute(
                        """
                        SELECT normalized_text_sha256, review_status,
                               privacy_scope FROM passages
                         WHERE passage_id = ? AND version = ?
                        """,
                        (passage.object_id, passage.version),
                    ).fetchone()
                    if (
                        row is None
                        or str(row[0]) != passage.content_sha256
                        or str(row[1]) != "APPROVED"
                        or str(row[2]) != "GLOBAL"
                    ):
                        return False
            for relationship in value.relationships:
                for source in relationship.source_refs:
                    row = self._connection.execute(
                        """
                        SELECT content_sha256, status FROM source_versions
                         WHERE source_id = ? AND version = ?
                        """,
                        (source.object_id, source.version),
                    ).fetchone()
                    if (
                        row is None
                        or str(row[0]) != source.content_sha256
                        or str(row[1]) not in {"REVIEWED", "APPROVED"}
                    ):
                        return False
        except (RuntimeError, TypeError, ValueError):
            return False
        return True

    def _load_from_db(self, wiki_id: str, revision: int) -> WikiRevision:
        if self._connection is None or self._content_store is None:
            raise WikiGovernanceError("WIKI_CONTENT_STORE_REQUIRED")
        row = self._connection.execute(
            """
            SELECT slug, title, body_object_ref, body_object_size_bytes,
                   body_object_media_type, body_sha256, base_revision,
                   diff_kind, diff_object_ref, diff_object_size_bytes,
                   diff_object_media_type, diff_sha256, review_status,
                   review_due_at, approval_request_id, created_at
              FROM wiki_revisions WHERE wiki_id = ? AND revision = ?
            """,
            (wiki_id, revision),
        ).fetchone()
        if row is None:
            raise WikiGovernanceError("WIKI_REVISION_NOT_FOUND")
        body_digest = _content_digest(str(row[2]), code="WIKI_BODY_REF_INVALID")
        diff_digest = _content_digest(str(row[8]), code="WIKI_DIFF_REF_INVALID")
        if body_digest != str(row[5]):
            raise WikiGovernanceError("WIKI_BODY_HASH_MISMATCH")
        if diff_digest != str(row[11]):
            raise WikiGovernanceError("WIKI_DIFF_HASH_MISMATCH")
        body_reference = self._content_store.reference(
            content_sha256=body_digest,
            size_bytes=int(row[3]),
            media_type=str(row[4]),
        )
        diff_reference = self._content_store.reference(
            content_sha256=diff_digest,
            size_bytes=int(row[9]),
            media_type=str(row[10]),
        )
        body_bytes = self._content_store.read_verified(body_reference)
        diff_bytes = self._content_store.read_verified(diff_reference)
        try:
            body = json.loads(body_bytes)
            draft = WikiRevisionDraft.model_validate_json(diff_bytes)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise WikiGovernanceError("WIKI_CONTENT_INVALID") from None
        if (
            type(body) is not dict
            or draft.wiki_id != wiki_id
            or draft.base_revision != int(row[6])
            or draft.slug != str(row[0])
            or draft.title != str(row[1])
            or canonical_sha256(draft.model_dump(mode="json")) != diff_digest
        ):
            raise WikiGovernanceError("WIKI_AUTHORITY_ROW_MISMATCH")
        model_payload = {
            "wiki_id": wiki_id,
            "revision": revision,
            "slug": str(row[0]),
            "title": body.get("title"),
            "base_revision": int(row[6]),
            "diff_kind": str(row[7]).lower(),
            "sections": body.get("sections"),
            "theory_revision_refs": body.get("theory_revision_refs"),
            "relationships": body.get("relationships"),
            "graph_relations": body.get("graph_relations", ()),
            "review_due_at": row[13],
            "unresolved_questions": body.get("unresolved_questions"),
            "body_sha256": str(row[5]),
            "diff_sha256": diff_digest,
            "status": str(row[12]).lower(),
            "approval_request_id": row[14],
            "created_at": str(row[15]),
        }
        try:
            loaded = WikiRevision.model_validate_json(
                canonical_json_bytes(model_payload)
            )
        except ValueError:
            raise WikiGovernanceError("WIKI_CONTENT_INVALID") from None
        if (
            wiki_revision_body_sha256(loaded) != loaded.body_sha256
            or canonical_json_bytes(wiki_revision_body_payload(loaded)) != body_bytes
        ):
            raise WikiGovernanceError("WIKI_BODY_HASH_MISMATCH")
        database_claims = sorted(
            (
                str(item[0]),
                str(item[1]),
                int(item[2]),
                str(item[3]),
                str(item[4]).lower(),
                int(item[5]),
            )
            for item in self._connection.execute(
                """
                SELECT wc.section_key, wc.claim_id, wc.claim_version,
                       c.claim_sha256, wc.stance, wc.ordinal
                  FROM wiki_revision_claims AS wc
                  JOIN claims AS c
                    ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
                 WHERE wc.wiki_id = ? AND wc.wiki_revision = ?
                """,
                (wiki_id, revision),
            )
        )
        body_claims = sorted(
            (
                section.key,
                reference.object_id,
                reference.version,
                reference.content_sha256,
                section.stance,
                ordinal,
            )
            for section in loaded.sections
            for ordinal, reference in enumerate(section.claim_refs)
        )
        if database_claims != body_claims:
            raise WikiGovernanceError("WIKI_CLAIM_BINDING_MISMATCH")
        self._revisions[(loaded.wiki_id, loaded.revision)] = loaded
        if loaded.status == "active":
            self._active[loaded.wiki_id] = loaded.revision
        return loaded


__all__ = [
    "WikiClaimAuthority",
    "WikiGovernanceError",
    "WikiProposal",
    "WikiRevisionService",
    "wiki_revision_body_payload",
    "wiki_revision_body_sha256",
]


def _utc(value: UtcDateTime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _content_digest(value: str, *, code: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise WikiGovernanceError(code)
    return value[len(prefix) :]
