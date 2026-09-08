"""Governed case-to-retrieval derivation.

The service keeps the two things that must never be conflated separate:
deidentified index text is safe to score, while contributor identity and
authorization remain body-free deterministic metadata used before resolution.
Destructive authority changes belong to the approval-bound lifecycle service.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.archive.provenance import (
    CaseContributorHasher,
    CaseProvenanceError,
    CaseProvenanceService,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.cases import (
    CaseArtifactKind,
    CaseProvenanceRecord,
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    assert_shared_text_safe,
    version_ref_key,
)
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.evidence import (
    EvidenceChannel,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
)
from consultation_kb.models.lint import RebuildRequest
from consultation_kb.retrieval.contracts import CandidateMetadata, CandidateRef
from consultation_kb.retrieval.filters import assert_case_index_text_safe
from consultation_kb.storage.tombstones import lineage_hash


CaseStatementScope = Literal["case_record", "reviewed_case_pattern"]
_PIPELINE_KINDS: tuple[CaseArtifactKind, ...] = (
    "case",
    "case_pattern",
    "claim",
    "wiki_section",
    "graph_edge",
    "lexical_row",
    "vector_row",
)
_CHANNEL_BY_KIND: dict[CaseArtifactKind, EvidenceChannel] = {
    "case": "case",
    "wiki_section": "wiki",
    "graph_edge": "global_graph",
    "lexical_row": "lexical",
    "vector_row": "vector",
}
_UNIVERSAL_LAW_PHRASES: tuple[str, ...] = (
    "证明所有人",
    "对所有人都有效",
    "普遍必然",
    "proves universally",
    "works for everyone",
)
class CaseIndexingError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CaseContributorBinding(StrictModel):
    """Controlled mapping retained outside index text and shared bodies."""

    client_id: ClientId
    contributor_client_hash: Sha256Hex


class CaseIndexTextSet(StrictModel):
    case_record: NonEmptyStr
    reviewed_pattern: NonEmptyStr
    conditional_claim: NonEmptyStr
    wiki_section: NonEmptyStr
    graph_relation: NonEmptyStr


class CaseIndexRootAuthority(StrictModel):
    """Authoritative catalog binding for one exact active global case version."""

    case_ref: VersionRef
    source_candidate_ref: VersionRef
    authorization: CaseReuseAuthorization
    review: DeidentificationHumanReview
    release_decision: CaseReleaseDecision
    authority_manifest_ref: VersionRef
    source_catalog_version: PositiveInt
    state: Literal["active", "revoked"] = "active"

    @model_validator(mode="after")
    def _candidate_binding(self) -> "CaseIndexRootAuthority":
        if (
            self.review.candidate_sha256
            != self.source_candidate_ref.content_sha256
            or self.release_decision.candidate_sha256
            != self.source_candidate_ref.content_sha256
        ):
            raise ValueError("case index authority candidate binding mismatch")
        return self


@runtime_checkable
class CaseIndexAuthorityResolver(Protocol):
    def resolve_case_index_authority(
        self,
        *,
        case_ref: VersionRef,
        authority_manifest_ref: VersionRef,
    ) -> CaseIndexRootAuthority | None: ...


class CaseIndexGovernance(StrictModel):
    source_candidate_ref: VersionRef
    authority_manifest_ref: VersionRef
    release_policy_ref: VersionRef
    locator_policy_ref: VersionRef
    freshness_policy_ref: VersionRef
    source_catalog_version: PositiveInt
    indexed_at: UtcDateTime
    purpose: SafePolicyKey = "answer_support"
    sensitivity: NonNegativeInt = 1
    minimum_leave_one_out_sources: PositiveInt = 2


class CaseIndexArtifact(StrictModel):
    artifact_ref: VersionRef
    artifact_kind: CaseArtifactKind
    content_ref: VersionRef
    rendered_text: NonEmptyStr
    statement_scope: CaseStatementScope
    provenance: CaseProvenanceRecord
    authorization_refs: tuple[VersionRef, ...]
    review_ref: VersionRef
    release_decision_sha256: Sha256Hex
    allowed_uses: frozenset[SafePolicyKey]
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None = None
    source_catalog_version: PositiveInt
    candidate: CandidateRef | None = None
    universal_claim: Literal[False] = False

    @field_serializer("allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("authorization_refs")
    @classmethod
    def _canonical_authorizations(
        cls, value: tuple[VersionRef, ...]
    ) -> tuple[VersionRef, ...]:
        keys = tuple(version_ref_key(item) for item in value)
        if not value or len(keys) != len(set(keys)):
            raise ValueError(
                "case index authorization refs must be non-empty and unique"
            )
        return tuple(sorted(value, key=version_ref_key))

    @model_validator(mode="after")
    def _closed_artifact(self) -> "CaseIndexArtifact":
        if (
            self.provenance.artifact_ref != self.artifact_ref
            or self.provenance.artifact_kind != self.artifact_kind
        ):
            raise ValueError("case index artifact/provenance binding mismatch")
        if text_sha256(self.rendered_text) != self.content_ref.content_sha256:
            raise ValueError("case index content hash mismatch")
        try:
            assert_shared_text_safe(self.rendered_text)
        except ValueError:
            raise ValueError("case index text is unsafe") from None
        expected_authorizations = tuple(
            sorted(
                (item.authorization_ref for item in self.provenance.case_contributions),
                key=version_ref_key,
            )
        )
        if self.authorization_refs != expected_authorizations:
            raise ValueError("case index authorization closure mismatch")
        if (
            self.allowed_uses != self.provenance.allowed_uses
            or self.effective_to != self.provenance.effective_to
        ):
            raise ValueError("case index authority window mismatch")
        expected_channel = _CHANNEL_BY_KIND.get(self.artifact_kind)
        if expected_channel is None:
            if self.candidate is not None:
                raise ValueError("non-retrieval case artifact cannot carry a candidate")
            return self
        if self.candidate is None:
            raise ValueError("retrieval case artifact requires a candidate")
        if (
            self.candidate.reference != self.artifact_ref
            or self.candidate.content_ref != self.content_ref
            or self.candidate.object_type != self.artifact_kind
            or self.candidate.channel != expected_channel
            or self.candidate.metadata.allowed_uses != self.allowed_uses
            or self.candidate.metadata.effective_from != self.effective_from
            or self.candidate.metadata.effective_to != self.effective_to
        ):
            raise ValueError("case index candidate authority mismatch")
        assert_case_index_text_safe(self.candidate, self.rendered_text)
        return self


class CaseIndexBundle(StrictModel):
    root_case_ref: VersionRef
    artifacts: tuple[CaseIndexArtifact, ...]

    @field_validator("artifacts")
    @classmethod
    def _complete_pipeline(
        cls, value: tuple[CaseIndexArtifact, ...]
    ) -> tuple[CaseIndexArtifact, ...]:
        if tuple(item.artifact_kind for item in value) != _PIPELINE_KINDS:
            raise ValueError("case index pipeline is incomplete or out of order")
        return value

    @model_validator(mode="after")
    def _root_binding(self) -> "CaseIndexBundle":
        if self.artifacts[0].artifact_ref != self.root_case_ref:
            raise ValueError("case index root mismatch")
        return self

    @property
    def candidates(self) -> tuple[CandidateRef, ...]:
        return tuple(
            item.candidate for item in self.artifacts if item.candidate is not None
        )

    def body_for(self, candidate: CandidateRef) -> bytes:
        exact = CandidateRef.model_validate(candidate)
        for artifact in self.artifacts:
            if artifact.content_ref == exact.content_ref:
                return artifact.rendered_text.encode("utf-8")
        raise CaseIndexingError("CASE_INDEX_CONTENT_NOT_FOUND")


class CaseRevocationResult(StrictModel):
    tombstone_id: NonEmptyStr
    target_id_hash: Sha256Hex
    source_lineage_hash: Sha256Hex
    rebuild_request: RebuildRequest
    authorization_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt


class CaseIndexingService:
    """Build one exact case lineage and publish only body-free candidates."""

    def __init__(
        self,
        *,
        id_factory: IdFactory,
        provenance_service: CaseProvenanceService,
        contributor_hasher: CaseContributorHasher,
        authority_resolver: CaseIndexAuthorityResolver,
        connection: sqlite3.Connection | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(id_factory, IdFactory):
            raise TypeError("case indexing requires IdFactory")
        if not isinstance(provenance_service, CaseProvenanceService):
            raise TypeError("case indexing requires CaseProvenanceService")
        if not isinstance(contributor_hasher, CaseContributorHasher):
            raise TypeError("case indexing requires CaseContributorHasher")
        if not isinstance(authority_resolver, CaseIndexAuthorityResolver):
            raise TypeError("case indexing requires an authority resolver")
        if connection is not None and not isinstance(connection, sqlite3.Connection):
            raise TypeError("case indexing connection must be SQLite")
        self._ids = id_factory
        self._provenance = provenance_service
        self._hasher = contributor_hasher
        self._authority = authority_resolver
        self._connection = connection
        self._clock = clock if clock is not None else SystemClock()

    def build(
        self,
        root: CaseProvenanceRecord,
        *,
        authorization: CaseReuseAuthorization,
        review: DeidentificationHumanReview,
        release_decision: CaseReleaseDecision,
        contributor: CaseContributorBinding,
        texts: CaseIndexTextSet,
        governance: CaseIndexGovernance,
        derivation_rule_ref: VersionRef,
    ) -> CaseIndexBundle:
        lineage = self._validate_root_authority(
            root,
            authorization=authorization,
            review=review,
            release_decision=release_decision,
            contributor=contributor,
            governance=governance,
            derivation_rule_ref=derivation_rule_ref,
        )
        checked_texts = CaseIndexTextSet.model_validate(texts)
        client_ids = frozenset({contributor.client_id})
        contributor_aliases = frozenset(
            {self._hasher.pseudonymous_client_id(contributor.client_id)}
        )
        effective_from = authorization.valid_from
        review_ref = review.review_ref
        release_decision_sha256 = canonical_sha256(
            release_decision.model_dump(mode="json")
        )

        rendered = {
            "case": self._render_case_text(
                "案例记录限定说明", checked_texts.case_record, client_ids
            ),
            "case_pattern": self._render_case_text(
                "经审核案例模式限定说明", checked_texts.reviewed_pattern, client_ids
            ),
            "claim": self._render_case_text(
                "案例支持的条件性观察", checked_texts.conditional_claim, client_ids
            ),
            "wiki_section": self._render_case_text(
                "案例知识条目限定说明", checked_texts.wiki_section, client_ids
            ),
            "graph_edge": self._render_case_text(
                "案例关系限定说明", checked_texts.graph_relation, client_ids
            ),
        }
        rendered["lexical_row"] = rendered["wiki_section"]
        rendered["vector_row"] = rendered["wiki_section"]

        artifacts: list[CaseIndexArtifact] = []
        root_content_ref = self._content_ref("case_content", rendered["case"])
        artifacts.append(
            self._artifact(
                lineage,
                content_ref=root_content_ref,
                text=rendered["case"],
                statement_scope="case_record",
                governance=governance,
                contributor_ids=contributor_aliases,
                effective_from=effective_from,
                review_ref=review_ref,
                release_decision_sha256=release_decision_sha256,
            )
        )

        lineages: dict[CaseArtifactKind, CaseProvenanceRecord] = {"case": lineage}
        parent_kind: dict[CaseArtifactKind, CaseArtifactKind] = {
            "case_pattern": "case",
            "claim": "case_pattern",
            "wiki_section": "claim",
            "graph_edge": "wiki_section",
            "lexical_row": "graph_edge",
            "vector_row": "wiki_section",
        }
        for kind in _PIPELINE_KINDS[1:]:
            text = rendered[kind]
            parent = lineages[parent_kind[kind]]
            artifact_ref = VersionRef(
                object_id=self._ids.object_id(kind),
                version=1,
                content_sha256=text_sha256(text),
            )
            try:
                current = self._provenance.propagate(
                    artifact_ref,
                    kind,
                    (parent,),
                    derivation_rule_ref=derivation_rule_ref,
                )
            except CaseProvenanceError as exc:
                raise CaseIndexingError(exc.code) from exc
            artifacts.append(
                self._artifact(
                    current,
                    content_ref=artifact_ref,
                    text=text,
                    statement_scope="reviewed_case_pattern",
                    governance=governance,
                    contributor_ids=contributor_aliases,
                    effective_from=effective_from,
                    review_ref=review_ref,
                    release_decision_sha256=release_decision_sha256,
                )
            )
            lineages[kind] = current
        return CaseIndexBundle(
            root_case_ref=lineage.artifact_ref, artifacts=tuple(artifacts)
        )

    def revoke(
        self,
        case_ref: VersionRef,
        *,
        authorization_ref: VersionRef,
        catalog_version: int,
        reason: SafePolicyKey = "authorization_revoked",
    ) -> CaseRevocationResult:
        """Reject the removed direct-write path.

        Callers must use the two-stage, P1-bound ``DeletionService`` flow. The
        legacy signature remains only so old callers fail before validation,
        authority lookup, or any database mutation.
        """

        raise CaseIndexingError("CASE_REVOCATION_REQUIRES_FORMAL_DELETION")

    def _validate_root_authority(
        self,
        root: CaseProvenanceRecord,
        *,
        authorization: CaseReuseAuthorization,
        review: DeidentificationHumanReview,
        release_decision: CaseReleaseDecision,
        contributor: CaseContributorBinding,
        governance: CaseIndexGovernance,
        derivation_rule_ref: VersionRef,
    ) -> CaseProvenanceRecord:
        lineage = CaseProvenanceRecord.model_validate(root)
        grant = CaseReuseAuthorization.model_validate(authorization)
        checked_review = DeidentificationHumanReview.model_validate(review)
        decision = CaseReleaseDecision.model_validate(release_decision)
        binding = CaseContributorBinding.model_validate(contributor)
        authority = CaseIndexGovernance.model_validate(governance)
        rule = VersionRef.model_validate(derivation_rule_ref)
        try:
            lineage = self._provenance.assert_current(
                lineage, expected_derivation_rule_ref=rule
            )
        except CaseProvenanceError as exc:
            raise CaseIndexingError(exc.code) from exc
        try:
            resolved = self._authority.resolve_case_index_authority(
                case_ref=lineage.artifact_ref,
                authority_manifest_ref=authority.authority_manifest_ref,
            )
            catalog_authority = (
                None
                if resolved is None
                else CaseIndexRootAuthority.model_validate(resolved)
            )
        except Exception:
            raise CaseIndexingError(
                "CASE_INDEX_AUTHORITY_RESOLUTION_FAILED"
            ) from None
        if catalog_authority is None:
            raise CaseIndexingError("CASE_INDEX_AUTHORITY_NOT_FOUND")
        if catalog_authority.state != "active":
            raise CaseIndexingError("CASE_INDEX_AUTHORITY_NOT_ACTIVE")
        if (
            catalog_authority.case_ref != lineage.artifact_ref
            or catalog_authority.source_candidate_ref
            != authority.source_candidate_ref
            or catalog_authority.authorization != grant
            or catalog_authority.review != checked_review
            or catalog_authority.release_decision != decision
            or catalog_authority.authority_manifest_ref
            != authority.authority_manifest_ref
            or catalog_authority.source_catalog_version
            != authority.source_catalog_version
        ):
            raise CaseIndexingError("CASE_INDEX_AUTHORITY_MISMATCH")
        if lineage.artifact_kind != "case" or len(lineage.case_contributions) != 1:
            raise CaseIndexingError("CASE_INDEX_ROOT_REQUIRED")
        contribution = lineage.case_contributions[0]
        if (
            self._hasher.hash_client_id(binding.client_id)
            != binding.contributor_client_hash
            or contribution.contributor_client_hashes
            != frozenset({binding.contributor_client_hash})
            or grant.contributor_client_hash != binding.contributor_client_hash
        ):
            raise CaseIndexingError("CASE_INDEX_CONTRIBUTOR_MISMATCH")
        if contribution.authorization_ref != grant.authorization_ref:
            raise CaseIndexingError("CASE_INDEX_AUTHORIZATION_REF_MISMATCH")
        at = authority.indexed_at
        if not grant.reuse_authorized:
            raise CaseIndexingError("CASE_INDEX_REUSE_NOT_AUTHORIZED")
        if at < grant.valid_from:
            raise CaseIndexingError("CASE_INDEX_AUTHORIZATION_NOT_YET_EFFECTIVE")
        if grant.expires_at is not None and at >= grant.expires_at:
            raise CaseIndexingError("CASE_INDEX_AUTHORIZATION_EXPIRED")
        if grant.revoked_at is not None and at >= grant.revoked_at:
            raise CaseIndexingError("CASE_INDEX_AUTHORIZATION_REVOKED")
        if (
            authority.purpose not in grant.allowed_uses
            or authority.purpose not in lineage.allowed_uses
            or not lineage.allowed_uses <= grant.allowed_uses
        ):
            raise CaseIndexingError("CASE_INDEX_USE_NOT_AUTHORIZED")
        if (
            decision.outcome != "eligible"
            or decision.reasons
            or decision.authorization_ref != grant.authorization_ref
            or decision.review_ref != checked_review.review_ref
            or decision.candidate_sha256 != checked_review.candidate_sha256
            or decision.policy_ref != authority.release_policy_ref
            or decision.allowed_uses != lineage.allowed_uses
            or decision.allowed_uses != grant.allowed_uses
            or not decision.allowed_uses <= checked_review.allowed_uses
            or checked_review.decision != "approved"
            or checked_review.residual_risk == "high"
            or checked_review.rare_combination_disposition == "unresolved"
            or checked_review.reviewed_at > decision.evaluated_at
            or decision.evaluated_at > authority.indexed_at
        ):
            raise CaseIndexingError("CASE_INDEX_RELEASE_NOT_ELIGIBLE")
        authority_end = min(
            (
                value
                for value in (grant.expires_at, grant.revoked_at)
                if value is not None
            ),
            default=None,
        )
        if (
            contribution.effective_to != authority_end
            or lineage.effective_to != authority_end
        ):
            raise CaseIndexingError("CASE_INDEX_AUTHORIZATION_WINDOW_MISMATCH")
        return lineage

    def _artifact(
        self,
        provenance: CaseProvenanceRecord,
        *,
        content_ref: VersionRef,
        text: str,
        statement_scope: CaseStatementScope,
        governance: CaseIndexGovernance,
        contributor_ids: frozenset[str],
        effective_from: datetime,
        review_ref: VersionRef,
        release_decision_sha256: str,
    ) -> CaseIndexArtifact:
        candidate = None
        if provenance.artifact_kind in _CHANNEL_BY_KIND:
            candidate = self._candidate(
                provenance,
                content_ref=content_ref,
                text=text,
                channel=_CHANNEL_BY_KIND[provenance.artifact_kind],
                governance=governance,
                contributor_ids=contributor_ids,
                effective_from=effective_from,
            )
        return CaseIndexArtifact(
            artifact_ref=provenance.artifact_ref,
            artifact_kind=provenance.artifact_kind,
            content_ref=content_ref,
            rendered_text=text,
            statement_scope=statement_scope,
            provenance=provenance,
            authorization_refs=tuple(
                sorted(
                    (item.authorization_ref for item in provenance.case_contributions),
                    key=version_ref_key,
                )
            ),
            review_ref=review_ref,
            release_decision_sha256=release_decision_sha256,
            allowed_uses=provenance.allowed_uses,
            effective_from=effective_from,
            effective_to=provenance.effective_to,
            source_catalog_version=governance.source_catalog_version,
            candidate=candidate,
        )

    def _candidate(
        self,
        provenance: CaseProvenanceRecord,
        *,
        content_ref: VersionRef,
        text: str,
        channel: EvidenceChannel,
        governance: CaseIndexGovernance,
        contributor_ids: frozenset[str],
        effective_from: datetime,
    ) -> CandidateRef:
        case_ids = frozenset(
            item.case_ref.object_id for item in provenance.case_contributions
        )
        source_ids = frozenset(
            item.evidence_ref.object_id for item in provenance.independent_evidence
        )
        scope = provenance.provenance_scope
        evidence_provenance = Provenance(
            source_ids=source_ids,
            passage_ids=frozenset(),
            case_ids=case_ids,
            client_ids=contributor_ids,
            provenance_scope=scope,
            case_contributor_client_ids=contributor_ids,
            derivation_rule_ref=provenance.derivation_rule_ref,
        )
        lineage_hashes = {
            item.source_lineage_sha256 for item in provenance.case_contributions
        }
        lineage_hashes.update(
            lineage_hash("case", item.case_ref.object_id)
            for item in provenance.case_contributions
        )
        lineage_hashes.update(
            item.source_lineage_sha256 for item in provenance.independent_evidence
        )
        candidate = CandidateRef(
            reference=provenance.artifact_ref,
            content_ref=content_ref,
            object_type=provenance.artifact_kind,
            channel=channel,
            metadata=CandidateMetadata(
                manifest_ref=governance.authority_manifest_ref,
                review_status="approved",
                allowed_uses=provenance.allowed_uses,
                approved_at=governance.indexed_at,
                effective_from=effective_from,
                effective_to=provenance.effective_to,
                sensitivity=governance.sensitivity,
                source_grade=provenance.source_grade,
                framework_priority="not_applicable",
                empirical_support="unassessed",
                source_count=(
                    len(provenance.case_contributions)
                    + len(provenance.independent_evidence)
                ),
                minimum_leave_one_out_sources=(
                    governance.minimum_leave_one_out_sources
                ),
                contributor_identity_scheme="hmac_alias_v1",
                source_lineage_hashes=tuple(sorted(lineage_hashes)),
                # Scope-local CAS manifests accept the canonical bare media
                # type.  UTF-8 is part of the case-index publication contract
                # and is verified again when the immutable body is replayed.
                media_type="text/plain",
                size_bytes=len(text.encode("utf-8")),
            ),
            provenance=evidence_provenance,
            location=EvidenceLocator(
                locator_kind="case_turn",
                anchor_refs=(content_ref,),
                display_locator=(f"case:{next(iter(sorted(case_ids)))};turn:1"),
                locator_policy_ref=governance.locator_policy_ref,
            ),
            freshness=EvidenceFreshnessSnapshot(
                status="current",
                evaluated_at=governance.indexed_at,
                source_observed_at=governance.indexed_at,
                last_reviewed_at=governance.indexed_at,
                review_due_at=None,
                policy_ref=governance.freshness_policy_ref,
            ),
            score=0.0,
        )
        assert_case_index_text_safe(candidate, text)
        return candidate

    def _content_ref(self, kind: str, text: str) -> VersionRef:
        return VersionRef(
            object_id=self._ids.object_id(kind),
            version=1,
            content_sha256=text_sha256(text),
        )

    @staticmethod
    def _render_case_text(
        label: str,
        text: str,
        contributor_ids: frozenset[str],
    ) -> str:
        try:
            assert_shared_text_safe(text)
        except ValueError:
            raise CaseIndexingError("CASE_INDEX_TEXT_UNSAFE") from None
        folded = text.casefold()
        if any(phrase.casefold() in folded for phrase in _UNIVERSAL_LAW_PHRASES):
            raise CaseIndexingError("CASE_INDEX_UNIVERSAL_CLAIM_FORBIDDEN")
        if any(client_id in text for client_id in contributor_ids):
            raise CaseIndexingError("CASE_INDEX_TEXT_CONTAINS_CLIENT_ID")
        rendered = f"{label}：{text}；仅供条件匹配参考，不代表普遍规律"
        try:
            assert_shared_text_safe(rendered)
        except ValueError:
            raise CaseIndexingError("CASE_INDEX_TEXT_UNSAFE") from None
        return rendered


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "CaseIndexAuthorityResolver",
    "CaseContributorBinding",
    "CaseIndexArtifact",
    "CaseIndexBundle",
    "CaseIndexGovernance",
    "CaseIndexRootAuthority",
    "CaseIndexTextSet",
    "CaseIndexingError",
    "CaseIndexingService",
    "CaseRevocationResult",
]
