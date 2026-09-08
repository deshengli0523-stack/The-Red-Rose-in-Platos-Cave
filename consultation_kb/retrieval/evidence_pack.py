"""Fail-closed EvidencePack assembly and active artifact version gating.

This module is the one-way privacy boundary between retrieval and generation.
It accepts already filtered and resolved evidence, rechecks the exact authority
binding and immutable bytes, projects full provenance into its safe view, and
returns only the frozen P0 :class:`EvidencePack` contract.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from typing import Literal, Protocol, TypeAlias

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.knowledge.anchors import PassageAnchor
from consultation_kb.models.common import (
    FiniteFloat,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    AuthoritySnapshotBinding,
    C1ApplicabilityDecision,
    ClientExclusionStatus,
    EmpiricalSupport,
    EvidenceCandidate,
    EvidenceLocator,
    EvidencePack,
    EvidenceProvenanceView,
    RetrievalScope,
)
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.vault.content_store import ContentStore

from .contracts import ResolvedEvidence, canonical_json_bytes


ReferenceScope: TypeAlias = Literal["global", "client_private", "session", "run"]
FrameworkPriority: TypeAlias = Literal["highest", "normal", "not_applicable"]
ReviewStatus: TypeAlias = Literal["approved", "draft"]

_ROOT_ARTIFACT_KEYS: Mapping[str, str] = {
    "wiki_manifest": "wiki_index",
    "lexical_manifest": "lexical",
    "vector_manifest": "vector",
    "graph_manifest": "graph",
}
_DOCUMENT_LOCATOR_KINDS: Mapping[str, frozenset[str]] = {
    "pdf": frozenset({"source_page_span"}),
    "docx": frozenset({"source_paragraph_span", "source_table_span"}),
    "txt": frozenset({"source_line_span"}),
    "md": frozenset({"source_line_span"}),
    "csv": frozenset({"source_table_span"}),
    "xlsx": frozenset({"source_sheet_range"}),
}


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _canonical_refs(values: tuple[VersionRef, ...], label: str) -> tuple[VersionRef, ...]:
    keys = [_ref_key(value) for value in values]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} must not contain duplicate references")
    return tuple(sorted(values, key=_ref_key))


class ArtifactVersionMismatch(RuntimeError):
    """A required active artifact cannot satisfy its exact version closure."""

    def __init__(self) -> None:
        super().__init__("ARTIFACT_VERSION_MISMATCH")


class EvidenceClosureMismatch(RuntimeError):
    """A non-root EvidencePack reference failed its exact scope/closure check."""

    def __init__(self) -> None:
        super().__init__("EVIDENCE_CLOSURE_MISMATCH")


class RootManifestSet(StrictModel):
    """The four immutable global roots required for every P4 query."""

    catalog_version: PositiveInt
    wiki_manifest_ref: VersionRef
    lexical_manifest_ref: VersionRef
    vector_manifest_ref: VersionRef
    graph_manifest_ref: VersionRef

    @model_validator(mode="after")
    def _one_catalog_version(self) -> "RootManifestSet":
        references = self.references()
        if len({_ref_key(reference) for reference in references.values()}) != 4:
            raise ValueError("ROOT_MANIFEST_REFS_MUST_BE_DISTINCT")
        if any(reference.version != self.catalog_version for reference in references.values()):
            raise ValueError("ROOT_CATALOG_VERSION_MISMATCH")
        return self

    def references(self) -> dict[str, VersionRef]:
        return {
            "wiki_manifest": self.wiki_manifest_ref,
            "lexical_manifest": self.lexical_manifest_ref,
            "vector_manifest": self.vector_manifest_ref,
            "graph_manifest": self.graph_manifest_ref,
        }


class C1PolicyVocabulary(StrictModel):
    """Verified safe vocabulary materialized from one approved scope policy."""

    scope_policy_ref: VersionRef
    approved_rule_ids: frozenset[SafePolicyKey]
    approved_context_fields: frozenset[SafePolicyKey]

    @field_serializer("approved_rule_ids", "approved_context_fields")
    def _serialize_keys(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class CandidateEvidenceInput(StrictModel):
    """Internal enrichment of one resolver-returned candidate.

    Full provenance and body bytes are deliberately confined to this input and
    never appear in :class:`EvidencePackBuildResult`.
    """

    evidence_id: ObjectId
    resolved: ResolvedEvidence
    provenance_ref: VersionRef
    independent_source_count: NonNegativeInt
    client_exclusion_status: ClientExclusionStatus
    leave_one_out_variant_ref: VersionRef | None
    leave_one_out_mapping_ref: VersionRef | None = None
    leave_one_out_parent_ref: VersionRef | None = None
    leave_one_out_authority_manifest_ref: VersionRef | None = None
    leave_one_out_provenance_ref: VersionRef | None = None
    current_client_is_case_contributor: bool | None = None
    framework_priority: FrameworkPriority
    empirical_support: EmpiricalSupport
    score: FiniteFloat
    supports_evidence_ids: tuple[ObjectId, ...]
    contradicts_evidence_ids: tuple[ObjectId, ...]

    @field_validator("supports_evidence_ids", "contradicts_evidence_ids")
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("candidate relationship IDs must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _validate_loo_binding(self) -> "CandidateEvidenceInput":
        is_loo = self.client_exclusion_status == "leave_one_subject_out_applied"
        authority_refs = (
            self.leave_one_out_mapping_ref,
            self.leave_one_out_parent_ref,
            self.leave_one_out_authority_manifest_ref,
            self.leave_one_out_provenance_ref,
        )
        if is_loo:
            if self.leave_one_out_variant_ref != self.resolved.candidate.reference:
                raise ValueError("LEAVE_ONE_OUT_VARIANT_REF_MISMATCH")
            if any(reference is None for reference in authority_refs):
                raise ValueError("LEAVE_ONE_OUT_AUTHORITY_CLOSURE_REQUIRED")
            if (
                self.leave_one_out_authority_manifest_ref
                != self.resolved.candidate.metadata.manifest_ref
            ):
                raise ValueError("LEAVE_ONE_OUT_MANIFEST_REF_MISMATCH")
        elif self.leave_one_out_variant_ref is not None or any(
            reference is not None for reference in authority_refs
        ):
            raise ValueError("LEAVE_ONE_OUT_VARIANT_REF_UNEXPECTED")
        return self


class EvidencePackInputs(StrictModel):
    """Private build envelope; it is never serialized across generation."""

    scope: RetrievalScope
    authority_snapshot: AuthoritativeFilterSnapshot
    authority_snapshot_ref: VersionRef
    client_snapshot_ref: VersionRef
    temporary_fact_refs: tuple[VersionRef, ...]
    supporting: tuple[CandidateEvidenceInput, ...]
    contradicting: tuple[CandidateEvidenceInput, ...]
    unresolved_conflict_refs: tuple[VersionRef, ...]
    c1_applicability: C1ApplicabilityDecision
    c1_policy_vocabulary: C1PolicyVocabulary
    exclusion_proof_ref: VersionRef
    roots: RootManifestSet
    reranker_descriptor_ref: VersionRef

    @field_validator("temporary_fact_refs", "unresolved_conflict_refs")
    @classmethod
    def _sort_refs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        return _canonical_refs(value, "EvidencePack input")

    @field_validator("supporting", "contradicting")
    @classmethod
    def _sort_candidates(
        cls, value: tuple[CandidateEvidenceInput, ...]
    ) -> tuple[CandidateEvidenceInput, ...]:
        identifiers = [item.evidence_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("EvidencePack role contains duplicate evidence IDs")
        return tuple(
            sorted(value, key=lambda item: item.evidence_id)
        )

    @model_validator(mode="after")
    def _cross_role_copies_match(self) -> "EvidencePackInputs":
        supporting = {
            item.evidence_id: item for item in self.supporting
        }
        for item in self.contradicting:
            existing = supporting.get(item.evidence_id)
            if existing is not None and existing != item:
                raise ValueError("cross-role candidate copies must be identical")
        return self


class ClosureRequirement(StrictModel):
    """One exact reference edge the scope-aware verifier must resolve."""

    role: SafePolicyKey
    reference: VersionRef
    scope: ReferenceScope
    root_manifest_ref: VersionRef | None = None
    evidence_id: ObjectId | None = None


class EvidencePackBuildResult(StrictModel):
    pack: EvidencePack
    canonical_sha256: Sha256Hex

    @model_validator(mode="after")
    def _hash_matches_pack(self) -> "EvidencePackBuildResult":
        expected = hashlib.sha256(
            canonical_json_bytes(self.pack.model_dump(mode="json"))
        ).hexdigest()
        if expected != self.canonical_sha256:
            raise ValueError("EvidencePack canonical hash mismatch")
        return self


class EvidenceClosureVerifier(Protocol):
    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None: ...


class ExactReferenceResolver(Protocol):
    """Resolve one exact reference only inside its pre-bound physical scope."""

    def verify_exact(self, requirement: ClosureRequirement) -> None: ...


class C1VocabularyVerifier(Protocol):
    def verify_vocabulary(self, vocabulary: C1PolicyVocabulary) -> None: ...


class ScopeAwareEvidenceClosureVerifier:
    """Route every closure edge to one fixed scope without fallback lookup."""

    def __init__(
        self,
        *,
        global_resolver: ExactReferenceResolver,
        client_resolver: ExactReferenceResolver,
        session_resolver: ExactReferenceResolver,
        run_resolver: ExactReferenceResolver,
        vocabulary_verifier: C1VocabularyVerifier,
    ) -> None:
        resolvers = {
            "global": global_resolver,
            "client_private": client_resolver,
            "session": session_resolver,
            "run": run_resolver,
        }
        if any(
            not callable(getattr(resolver, "verify_exact", None))
            for resolver in resolvers.values()
        ) or not callable(getattr(vocabulary_verifier, "verify_vocabulary", None)):
            raise TypeError("EVIDENCE_SCOPE_RESOLVER_REQUIRED")
        self._resolvers = resolvers
        self._vocabulary = vocabulary_verifier

    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None:
        if type(requirements) is not tuple or any(
            type(requirement) is not ClosureRequirement for requirement in requirements
        ):
            raise EvidenceClosureMismatch
        identities = [
            (
                requirement.role,
                requirement.scope,
                requirement.evidence_id,
                _ref_key(requirement.reference),
            )
            for requirement in requirements
        ]
        if len(identities) != len(set(identities)):
            raise EvidenceClosureMismatch
        try:
            self._vocabulary.verify_vocabulary(vocabulary)
            for requirement in requirements:
                self._resolvers[requirement.scope].verify_exact(requirement)
        except EvidenceClosureMismatch:
            raise
        except Exception:
            # Missing, unauthorized, wrong-scope, and corrupt references share
            # one safe boundary result; no second store is ever tried.
            raise EvidenceClosureMismatch from None


class ArtifactVersionGate(Protocol):
    def verify(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
    ) -> None: ...


class ActiveArtifactVersionGate:
    """Verify four exact active manifests and all CAS member bytes."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        *,
        artifact_keys: Mapping[str, str] = _ROOT_ARTIFACT_KEYS,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if type(content_store) is not ContentStore:
            raise TypeError("CONTENT_STORE_REQUIRED")
        if set(artifact_keys) != set(_ROOT_ARTIFACT_KEYS):
            raise ValueError("ROOT_ARTIFACT_KEY_REGISTRY_INVALID")
        keys = dict(artifact_keys)
        if any(type(value) is not str or not value for value in keys.values()):
            raise ValueError("ROOT_ARTIFACT_KEY_REGISTRY_INVALID")
        if len(set(keys.values())) != len(keys):
            raise ValueError("ROOT_ARTIFACT_KEYS_MUST_BE_DISTINCT")
        self._connection = connection
        self._store = content_store
        self._artifact_keys = keys

    def verify(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
    ) -> None:
        validated_snapshot = AuthoritativeFilterSnapshot.model_validate(snapshot)
        validated_roots = RootManifestSet.model_validate(roots)
        if validated_snapshot.global_runtime_epoch <= 0:
            raise ArtifactVersionMismatch
        began = False
        try:
            if not self._connection.in_transaction:
                self._connection.execute("BEGIN")
                began = True
            state = self._connection.execute(
                "SELECT state FROM runtime_epochs WHERE epoch = ?",
                (validated_snapshot.global_runtime_epoch,),
            ).fetchone()
            if state != ("ACTIVE",):
                raise ArtifactVersionMismatch
            repository = ManifestRepository(self._connection)
            for field, expected_ref in validated_roots.references().items():
                manifest = repository.get_active(
                    self._artifact_keys[field],
                    epoch=validated_snapshot.global_runtime_epoch,
                )
                actual_ref = VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                )
                if (
                    actual_ref != expected_ref
                    or manifest.source_version != validated_roots.catalog_version
                    or not manifest.verified
                    or manifest.state != "ACTIVE"
                ):
                    raise ArtifactVersionMismatch
                for member in manifest.members:
                    if member.source_version != validated_roots.catalog_version:
                        raise ArtifactVersionMismatch
                    reference = self._store.reference(
                        content_sha256=member.object_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                    payload = self._store.read_verified(reference)
                    if (
                        len(payload) != member.size_bytes
                        or hashlib.sha256(payload).hexdigest() != member.object_sha256
                    ):
                        raise ArtifactVersionMismatch
            if began:
                self._connection.execute("COMMIT")
        except ArtifactVersionMismatch:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except Exception:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise ArtifactVersionMismatch from None


class EvidenceLocatorRenderer:
    """Return only an approved source anchor's canonical locator grammar."""

    def render(
        self,
        anchor: PassageAnchor,
        *,
        review_status: ReviewStatus,
    ) -> EvidenceLocator:
        validated = PassageAnchor.model_validate(anchor)
        if review_status != "approved":
            raise ValueError("PASSAGE_ANCHOR_NOT_APPROVED")
        allowed = _DOCUMENT_LOCATOR_KINDS.get(validated.document_type)
        if allowed is None or validated.locator.locator_kind not in allowed:
            raise ValueError("LOCATOR_DOCUMENT_GRAMMAR_MISMATCH")
        return EvidenceLocator.model_validate(validated.locator)


class EvidencePackBuilder:
    """Build one safe, version-closed pack from resolver-returned evidence."""

    def __init__(
        self,
        *,
        closure_verifier: EvidenceClosureVerifier,
        version_gate: ArtifactVersionGate,
    ) -> None:
        if not callable(getattr(closure_verifier, "verify", None)):
            raise TypeError("EVIDENCE_CLOSURE_VERIFIER_REQUIRED")
        if not callable(getattr(version_gate, "verify", None)):
            raise TypeError("ARTIFACT_VERSION_GATE_REQUIRED")
        self._closure = closure_verifier
        self._versions = version_gate

    def verify_active_artifacts(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
    ) -> None:
        """Fail before retrieval if the frozen epoch cannot prove every root."""

        try:
            self._versions.verify(
                AuthoritativeFilterSnapshot.model_validate(snapshot),
                RootManifestSet.model_validate(roots),
            )
        except ArtifactVersionMismatch:
            raise
        except Exception:
            raise ArtifactVersionMismatch from None

    def build(self, inputs: EvidencePackInputs) -> EvidencePackBuildResult:
        values = EvidencePackInputs.model_validate(inputs)
        self._assert_snapshot_hash(values)
        self.verify_active_artifacts(values.authority_snapshot, values.roots)
        self._assert_c1_policy_membership(values)

        packed_by_id: dict[str, EvidenceCandidate] = {}
        source_by_id: dict[str, CandidateEvidenceInput] = {}
        for item in (*values.supporting, *values.contradicting):
            evidence_id = item.evidence_id
            existing_source = source_by_id.get(evidence_id)
            if existing_source is not None:
                if existing_source != item:
                    raise ValueError("cross-role candidate copies must be identical")
                continue
            packed_by_id[evidence_id] = self._pack_candidate(values, item)
            source_by_id[evidence_id] = item

        supporting = tuple(
            packed_by_id[item.evidence_id]
            for item in values.supporting
        )
        contradicting = tuple(
            packed_by_id[item.evidence_id]
            for item in values.contradicting
        )
        binding = self._authority_binding(values)
        pack = EvidencePack(
            run_id=values.authority_snapshot.run_id,
            authority=binding,
            client_snapshot_ref=values.client_snapshot_ref,
            temporary_fact_refs=values.temporary_fact_refs,
            supporting=supporting,
            contradicting=contradicting,
            unresolved_conflict_refs=values.unresolved_conflict_refs,
            c1_applicability=values.c1_applicability,
            exclusion_proof_ref=values.exclusion_proof_ref,
            wiki_manifest_ref=values.roots.wiki_manifest_ref,
            lexical_manifest_ref=values.roots.lexical_manifest_ref,
            vector_manifest_ref=values.roots.vector_manifest_ref,
            graph_manifest_ref=values.roots.graph_manifest_ref,
            reranker_descriptor_ref=values.reranker_descriptor_ref,
        )
        requirements = self._requirements(values, source_by_id)
        try:
            self._closure.verify(
                requirements,
                vocabulary=values.c1_policy_vocabulary,
            )
        except EvidenceClosureMismatch:
            raise
        except Exception:
            raise EvidenceClosureMismatch from None
        digest = hashlib.sha256(
            canonical_json_bytes(pack.model_dump(mode="json"))
        ).hexdigest()
        return EvidencePackBuildResult(pack=pack, canonical_sha256=digest)

    @staticmethod
    def _assert_snapshot_hash(values: EvidencePackInputs) -> None:
        expected = hashlib.sha256(
            canonical_json_bytes(values.authority_snapshot.model_dump(mode="json"))
        ).hexdigest()
        if values.authority_snapshot_ref.content_sha256 != expected:
            raise ValueError("AUTHORITY_SNAPSHOT_HASH_MISMATCH")

    @staticmethod
    def _assert_c1_policy_membership(values: EvidencePackInputs) -> None:
        decision = values.c1_applicability
        vocabulary = values.c1_policy_vocabulary
        if (
            vocabulary.scope_policy_ref != decision.scope_policy_ref
            or not set(decision.matched_rule_ids) <= vocabulary.approved_rule_ids
            or not set(decision.missing_context_fields)
            <= vocabulary.approved_context_fields
        ):
            raise ValueError("C1_POLICY_MEMBERSHIP_INVALID")

    @staticmethod
    def _authority_binding(values: EvidencePackInputs) -> AuthoritySnapshotBinding:
        snapshot = values.authority_snapshot
        return AuthoritySnapshotBinding(
            snapshot_ref=values.authority_snapshot_ref,
            run_id=snapshot.run_id,
            global_runtime_epoch=snapshot.global_runtime_epoch,
            client_runtime_epoch=snapshot.client_runtime_epoch,
            tombstone_epoch=snapshot.tombstone_epoch,
            authorization_epoch=snapshot.authorization_epoch,
            policy_ref=snapshot.policy_ref,
            created_at=snapshot.created_at,
        )

    @staticmethod
    def _pack_candidate(
        values: EvidencePackInputs,
        item: CandidateEvidenceInput,
    ) -> EvidenceCandidate:
        candidate = item.resolved.candidate
        binding = candidate.filter_binding
        snapshot = values.authority_snapshot
        if binding is None or (
            binding.run_id != snapshot.run_id
            or binding.global_runtime_epoch != snapshot.global_runtime_epoch
            or binding.client_runtime_epoch != snapshot.client_runtime_epoch
            or binding.tombstone_epoch != snapshot.tombstone_epoch
            or binding.authorization_epoch != snapshot.authorization_epoch
            or binding.policy_ref != snapshot.policy_ref
        ):
            raise ValueError("FILTER_BINDING_STALE")
        if candidate.reference.object_id not in snapshot.allowed_ref_ids:
            raise ValueError("CANDIDATE_NOT_AUTHORIZED")
        body = item.resolved.body
        if (
            hashlib.sha256(body).hexdigest() != candidate.content_ref.content_sha256
            or len(body) != candidate.metadata.size_bytes
        ):
            raise ValueError("RESOLVED_BODY_HASH_MISMATCH")
        expected_provenance_hash = hashlib.sha256(
            canonical_json_bytes(candidate.provenance.model_dump(mode="json"))
        ).hexdigest()
        if item.provenance_ref.content_sha256 != expected_provenance_hash:
            raise ValueError("PROVENANCE_REF_HASH_MISMATCH")
        if candidate.metadata.review_status != "approved":
            raise ValueError("CANDIDATE_REVIEW_NOT_APPROVED")
        provenance = candidate.provenance
        current_client = values.scope.current_client_id
        if provenance.provenance_scope == "client_private":
            if provenance.private_owner_client_id != current_client:
                raise ValueError("PRIVATE_OWNER_SCOPE_MISMATCH")
        elif provenance.provenance_scope in {"case_derived", "mixed"}:
            if item.current_client_is_case_contributor is not False:
                raise ValueError("CURRENT_SUBJECT_CASE_NOT_EXCLUDED")
            if item.client_exclusion_status == "leave_one_subject_out_applied" and (
                item.leave_one_out_mapping_ref is None
                or item.leave_one_out_parent_ref is None
                or item.leave_one_out_authority_manifest_ref
                != candidate.metadata.manifest_ref
                or item.leave_one_out_provenance_ref is None
            ):
                raise ValueError("LEAVE_ONE_OUT_AUTHORITY_CLOSURE_REQUIRED")

        view = EvidenceProvenanceView(
            provenance_ref=item.provenance_ref,
            provenance_scope=provenance.provenance_scope,
            derivation_rule_ref=provenance.derivation_rule_ref,
            source_count=len(provenance.source_ids),
            passage_count=len(provenance.passage_ids),
            case_count=len(provenance.case_ids),
            case_contributor_count=len(provenance.case_contributor_client_ids),
            independent_source_count=item.independent_source_count,
            client_exclusion_status=item.client_exclusion_status,
        )
        return EvidenceCandidate(
            evidence_id=item.evidence_id,
            text_ref=candidate.content_ref,
            location=candidate.location,
            freshness=candidate.freshness,
            channel=candidate.channel,
            review_status="approved",
            source_grade=candidate.metadata.source_grade,
            framework_priority=item.framework_priority,
            empirical_support=item.empirical_support,
            provenance=view,
            supports_evidence_ids=item.supports_evidence_ids,
            contradicts_evidence_ids=item.contradicts_evidence_ids,
            score=item.score,
        )

    @classmethod
    def _requirements(
        cls,
        values: EvidencePackInputs,
        source_by_id: Mapping[str, CandidateEvidenceInput],
    ) -> tuple[ClosureRequirement, ...]:
        requirements: list[ClosureRequirement] = [
            ClosureRequirement(
                role="authority_snapshot",
                reference=values.authority_snapshot_ref,
                scope="run",
            ),
            ClosureRequirement(
                role="authority_policy",
                reference=values.authority_snapshot.policy_ref,
                scope="global",
            ),
            ClosureRequirement(
                role="client_snapshot",
                reference=values.client_snapshot_ref,
                scope="client_private",
            ),
            ClosureRequirement(
                role="exclusion_proof",
                reference=values.exclusion_proof_ref,
                scope="run",
            ),
            ClosureRequirement(
                role="reranker_descriptor",
                reference=values.reranker_descriptor_ref,
                scope="global",
            ),
        ]
        for reference in values.temporary_fact_refs:
            requirements.append(
                ClosureRequirement(
                    role="temporary_fact", reference=reference, scope="session"
                )
            )
        for reference in values.unresolved_conflict_refs:
            requirements.append(
                ClosureRequirement(
                    role="unresolved_conflict", reference=reference, scope="run"
                )
            )
        for field, reference in values.roots.references().items():
            requirements.append(
                ClosureRequirement(role=field, reference=reference, scope="global")
            )
        decision = values.c1_applicability
        requirements.append(
            ClosureRequirement(
                role="c1_scope_policy",
                reference=decision.scope_policy_ref,
                scope="global",
            )
        )
        if decision.revision is not None:
            requirements.append(
                ClosureRequirement(
                    role="c1_revision", reference=decision.revision, scope="global"
                )
            )

        for evidence_id, item in source_by_id.items():
            candidate = item.resolved.candidate
            scope: ReferenceScope = (
                "client_private"
                if candidate.provenance.provenance_scope == "client_private"
                else "global"
            )
            root = candidate.metadata.manifest_ref
            requirements.extend(
                (
                    ClosureRequirement(
                        role="candidate_manifest",
                        reference=root,
                        scope=scope,
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="candidate_object",
                        reference=candidate.reference,
                        scope=scope,
                        root_manifest_ref=root,
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="candidate_text",
                        reference=candidate.content_ref,
                        scope=scope,
                        root_manifest_ref=root,
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="candidate_provenance",
                        reference=item.provenance_ref,
                        scope="run",
                        root_manifest_ref=root,
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="locator_policy",
                        reference=candidate.location.locator_policy_ref,
                        scope="global",
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="freshness_policy",
                        reference=candidate.freshness.policy_ref,
                        scope="global",
                        evidence_id=evidence_id,
                    ),
                    ClosureRequirement(
                        role="derivation_rule",
                        reference=candidate.provenance.derivation_rule_ref,
                        scope="global",
                        evidence_id=evidence_id,
                    ),
                )
            )
            requirements.extend(
                ClosureRequirement(
                    role="candidate_anchor",
                    reference=reference,
                    scope=scope,
                    root_manifest_ref=root,
                    evidence_id=evidence_id,
                )
                for reference in candidate.location.anchor_refs
            )
            if item.leave_one_out_variant_ref is not None:
                assert item.leave_one_out_mapping_ref is not None
                assert item.leave_one_out_parent_ref is not None
                assert item.leave_one_out_authority_manifest_ref is not None
                assert item.leave_one_out_provenance_ref is not None
                requirements.extend(
                    (
                        ClosureRequirement(
                            role="leave_one_out_variant",
                            reference=item.leave_one_out_variant_ref,
                            scope="global",
                            root_manifest_ref=root,
                            evidence_id=evidence_id,
                        ),
                        ClosureRequirement(
                            role="leave_one_out_mapping",
                            reference=item.leave_one_out_mapping_ref,
                            scope="global",
                            evidence_id=evidence_id,
                        ),
                        ClosureRequirement(
                            role="leave_one_out_parent",
                            reference=item.leave_one_out_parent_ref,
                            scope="global",
                            evidence_id=evidence_id,
                        ),
                        ClosureRequirement(
                            role="leave_one_out_authority_manifest",
                            reference=item.leave_one_out_authority_manifest_ref,
                            scope="global",
                            evidence_id=evidence_id,
                        ),
                        ClosureRequirement(
                            role="leave_one_out_provenance",
                            reference=item.leave_one_out_provenance_ref,
                            scope="global",
                            root_manifest_ref=item.leave_one_out_authority_manifest_ref,
                            evidence_id=evidence_id,
                        ),
                    )
                )
        return tuple(
            sorted(
                requirements,
                key=lambda value: (
                    value.role,
                    value.scope,
                    "" if value.evidence_id is None else value.evidence_id,
                    *_ref_key(value.reference),
                ),
            )
        )


__all__ = [
    "ActiveArtifactVersionGate",
    "ArtifactVersionGate",
    "ArtifactVersionMismatch",
    "C1PolicyVocabulary",
    "C1VocabularyVerifier",
    "CandidateEvidenceInput",
    "ClosureRequirement",
    "EvidenceClosureMismatch",
    "EvidenceClosureVerifier",
    "ExactReferenceResolver",
    "EvidenceLocatorRenderer",
    "EvidencePackBuildResult",
    "EvidencePackBuilder",
    "EvidencePackInputs",
    "FrameworkPriority",
    "RootManifestSet",
    "ScopeAwareEvidenceClosureVerifier",
]
