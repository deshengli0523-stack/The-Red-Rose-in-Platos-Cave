"""Trusted P6 composition over the existing P4 retrieval coordinator.

This module deliberately owns orchestration, not retrieval algorithms.  Every
query still passes through :class:`RetrievalCoordinator`; the adapters below
only bind its one-query API to a governed multi-subquery generation plan and
join worker-verified private evidence to a global-only authority snapshot.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import model_validator

from consultation_kb.client.graph_serialization import (
    canonical_graph_bytes,
    load_graph,
)
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.generation.evidence_registry import (
    GenerationCandidateProofSource,
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceContextItem,
    GenerationEvidenceTypeProof,
    GenerationRiskContextBinding,
    GenerationRetrievalMetadata,
    GenerationRunObject,
    evidence_pack_sha256,
    validate_generation_evidence_type_proof_pack_closure,
    validate_generation_required_evidence_proofs,
    validate_retrieved_generation_evidence_context,
)
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.common import SafePolicyKey, Sha256Hex, StrictModel, VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
    EvidencePack,
    RetrievalScope,
)
from consultation_kb.retrieval.budget import ContextBudget
from consultation_kb.retrieval.contracts import (
    CandidateRef,
    FilterCapabilityBinding,
    Retriever,
    canonical_json_bytes,
)
from consultation_kb.retrieval.coordinator import (
    AuthoritySnapshotRepository,
    CandidateSemanticsResolver,
    RetrievalArtifactGate,
    RetrievalCoordinator,
    RetrievalCoordinatorError,
    RetrievalRequest,
    TokenCounter,
)
from consultation_kb.retrieval.evidence_pack import (
    ArtifactVersionGate,
    C1PolicyVocabulary,
    ClosureRequirement,
    EvidenceClosureVerifier,
    EvidenceClosureMismatch,
    EvidencePackBuilder,
    RootManifestSet,
)
from consultation_kb.retrieval.filters import (
    AuthoritySnapshotStale,
    CandidateAuthorityStatus,
    CandidateFilter,
    ContributorIdentityHasher,
    LeaveOneOutAuthorityVerifier,
    is_current_client_contributor,
)
from consultation_kb.retrieval.fusion import ReciprocalRankFusion
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.retrieval.resolver import (
    EvidenceResolutionDenied,
    EvidenceResolver,
    ScopeRoutingContentReader,
    VerifiedContentReader,
)
from consultation_kb.security.worker_protocol import (
    GenerationClientBinding,
    PrivateGenerationEvidence,
)
from consultation_kb.vault.content_store import ContentStore


_PRIVATE_ROUTES = frozenset({"profile", "client_history"})
_TOMBSTONE_CLIENT_MASK = 2**32 - 1


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _candidate_key(
    candidate: CandidateRef,
) -> tuple[str, int, str, str, int, str, str]:
    return (
        candidate.reference.object_id,
        candidate.reference.version,
        candidate.reference.content_sha256,
        candidate.content_ref.object_id,
        candidate.content_ref.version,
        candidate.content_ref.content_sha256,
        candidate.channel,
    )


def _exact_candidate_bytes(candidate: CandidateRef) -> bytes:
    unbound = candidate.model_copy(update={"filter_binding": None})
    return canonical_json_bytes(unbound.model_dump(mode="json"))


class GenerationRetrievalOrchestratorError(RuntimeError):
    """A fixed-code failure at the P6/P4 composition boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ActiveGenerationArtifacts(Protocol):
    """The exact active closure discovered by the production P4 runtime."""

    @property
    def active_runtime_epoch(self) -> int: ...

    @property
    def roots(self) -> object: ...

    def bindings(self) -> tuple[object, ...]: ...


class GlobalAuthorityRepository(AuthoritySnapshotRepository, Protocol):
    """Global-only authority source used underneath the composite guard."""

    def candidate_status(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus: ...


class GenerationRetrievalDependencyFactory(Protocol):
    """Strict injection point for production graph, C1 and model components."""

    def build(
        self,
        *,
        plan: QueryPlan,
        c1_applicability_input: C1ApplicabilityInput,
        active_artifacts: ActiveGenerationArtifacts,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
    ) -> "GenerationRetrievalDependencies": ...


class GenerationC1Context(StrictModel):
    """A policy-resolved C1 decision plus its approved safe vocabulary."""

    decision: C1ApplicabilityDecision
    vocabulary: C1PolicyVocabulary
    structured_context_trusted: bool
    applicability_input_sha256: Sha256Hex

    @model_validator(mode="after")
    def _policy_closure(self) -> "GenerationC1Context":
        if self.decision.scope_policy_ref != self.vocabulary.scope_policy_ref:
            raise ValueError("GENERATION_C1_POLICY_MISMATCH")
        if (
            self.decision.effective_status == "active"
            and not self.structured_context_trusted
            and self.decision.status != "insufficient_context"
        ):
            raise ValueError("GENERATION_C1_CONTEXT_UNTRUSTED")
        return self


@dataclass(frozen=True, slots=True)
class GenerationRetrievalDependencies:
    """Invocation-local, production-built P4 dependencies.

    The factory may assemble graph and C1 components using application-specific
    registries, but it cannot replace the coordinator, filter, resolver, pack
    builder, snapshot join, or multi-subquery execution implemented here.
    """

    global_snapshot_repository: GlobalAuthorityRepository
    artifact_gate: RetrievalArtifactGate
    global_retrievers: Mapping[str, Retriever]
    global_content_reader: VerifiedContentReader
    semantics_resolver: CandidateSemanticsResolver
    fusion: ReciprocalRankFusion
    reranker: EvidenceReranker
    context_budget: ContextBudget
    token_counter: TokenCounter
    closure_verifier: EvidenceClosureVerifier
    version_gate: ArtifactVersionGate
    c1_context: GenerationC1Context | None
    reranker_descriptor_ref: VersionRef
    allowed_uses: frozenset[str] = frozenset({"consultation_answer"})
    maximum_sensitivity: int = 3
    per_route_limit: int = 20
    fusion_limit: int = 40
    unresolved_conflict_refs: tuple[VersionRef, ...] = ()
    mandatory_conflict_claim_refs: tuple[VersionRef, ...] = ()


class GenerationRetrievalOutcome(StrictModel):
    """Exact immutable retrieval result accepted by the scoped worker."""

    evidence_pack: EvidencePack
    evidence_pack_sha256: Sha256Hex
    evidence_context: tuple[GenerationEvidenceContextItem, ...]
    run_objects: tuple[GenerationRunObject, ...]
    metadata: GenerationRetrievalMetadata

    @model_validator(mode="after")
    def _exact_closure(self) -> "GenerationRetrievalOutcome":
        if evidence_pack_sha256(self.evidence_pack) != self.evidence_pack_sha256:
            raise ValueError("GENERATION_EVIDENCE_PACK_HASH_MISMATCH")
        try:
            validate_retrieved_generation_evidence_context(
                self.evidence_pack,
                self.evidence_context,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("GENERATION_EVIDENCE_CONTEXT_MISMATCH") from None
        identities = tuple(
            (item.object_type, *_ref_key(item.reference)) for item in self.run_objects
        )
        if identities != tuple(sorted(set(identities))):
            raise ValueError("GENERATION_RUN_OBJECTS_NOT_CANONICAL")
        authority = tuple(
            item for item in self.run_objects if item.object_type == "authority_snapshot"
        )
        proof = tuple(
            item for item in self.run_objects if item.object_type == "exclusion_proof"
        )
        provenance = {
            item.reference
            for item in self.run_objects
            if item.object_type == "provenance"
        }
        expected_provenance = {
            item.provenance.provenance_ref
            for item in (
                *self.evidence_pack.supporting,
                *self.evidence_pack.contradicting,
            )
        }
        try:
            validate_generation_evidence_type_proof_pack_closure(
                self.evidence_pack,
                self.evidence_context,
                self.metadata.evidence_type_proofs,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("GENERATION_EVIDENCE_PROOF_CLOSURE_MISMATCH") from None
        if (
            len(authority) != 1
            or authority[0].reference != self.evidence_pack.authority.snapshot_ref
            or len(proof) != 1
            or proof[0].reference != self.evidence_pack.exclusion_proof_ref
            or provenance != expected_provenance
        ):
            raise ValueError("GENERATION_RUN_OBJECT_CLOSURE_MISMATCH")
        return self


class _RunObjectPublisher:
    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], GenerationRunObject] = {}

    def publish(self, object_type: SafePolicyKey, payload: bytes) -> VersionRef:
        if object_type not in {"authority_snapshot", "exclusion_proof", "provenance"}:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_RUN_OBJECT_TYPE_INVALID"
            )
        digest = hashlib.sha256(payload).hexdigest()
        reference = VersionRef(
            object_id=deterministic_object_id(object_type, digest),
            version=1,
            content_sha256=digest,
        )
        try:
            canonical_json = payload.decode("utf-8", errors="strict")
            record = GenerationRunObject(
                object_type=cast(
                    Literal["authority_snapshot", "exclusion_proof", "provenance"],
                    object_type,
                ),
                reference=reference,
                canonical_json=canonical_json,
            )
        except (TypeError, ValueError, UnicodeError):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_RUN_OBJECT_INVALID"
            ) from None
        key = (record.object_type, record.reference.object_id)
        existing = self._objects.get(key)
        if existing is not None and existing != record:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_RUN_OBJECT_CONFLICT"
            )
        self._objects[key] = record
        return reference

    def objects(self) -> tuple[GenerationRunObject, ...]:
        return tuple(
            sorted(
                self._objects.values(),
                key=lambda item: (item.object_type, *_ref_key(item.reference)),
            )
        )

    def contains(self, reference: VersionRef) -> bool:
        return any(item.reference == reference for item in self._objects.values())


class _CompositeClosureVerifier:
    """Resolve worker-owned and run-local refs without a client DB fallback."""

    def __init__(
        self,
        *,
        global_verifier: EvidenceClosureVerifier,
        publisher: _RunObjectPublisher,
        client_binding: GenerationClientBinding,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        leave_one_out_verifier: LeaveOneOutAuthorityVerifier | None = None,
    ) -> None:
        self._global = global_verifier
        self._publisher = publisher
        self._client_snapshot = client_binding.client_snapshot_ref
        self._temporary = frozenset(client_binding.temporary_fact_refs)
        self._leave_one_out = leave_one_out_verifier
        client: set[tuple[str, VersionRef, VersionRef | None]] = set()
        for item in private_evidence:
            candidate = item.candidate
            root = candidate.metadata.manifest_ref
            client.update(
                {
                    ("candidate_manifest", root, None),
                    ("candidate_object", candidate.reference, root),
                    ("candidate_text", candidate.content_ref, root),
                }
            )
            client.update(
                ("candidate_anchor", reference, root)
                for reference in candidate.location.anchor_refs
            )
        self._client = frozenset(client)

    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None:
        global_requirements: list[ClosureRequirement] = []
        loo_roles = frozenset(
            {
                "leave_one_out_variant",
                "leave_one_out_mapping",
                "leave_one_out_parent",
                "leave_one_out_authority_manifest",
                "leave_one_out_provenance",
            }
        )
        loo_by_evidence: dict[str, dict[str, ClosureRequirement]] = {}
        try:
            for requirement in requirements:
                if requirement.role in loo_roles:
                    evidence_id = requirement.evidence_id
                    if requirement.scope != "global" or evidence_id is None:
                        raise EvidenceClosureMismatch
                    group = loo_by_evidence.setdefault(evidence_id, {})
                    if requirement.role in group:
                        raise EvidenceClosureMismatch
                    group[requirement.role] = requirement
                elif requirement.scope == "global":
                    global_requirements.append(requirement)
                elif requirement.scope == "run":
                    if not self._publisher.contains(requirement.reference):
                        raise EvidenceClosureMismatch
                elif requirement.scope == "session":
                    if (
                        requirement.role != "temporary_fact"
                        or requirement.reference not in self._temporary
                    ):
                        raise EvidenceClosureMismatch
                elif requirement.scope == "client_private":
                    if requirement.role == "client_snapshot":
                        if requirement.reference != self._client_snapshot:
                            raise EvidenceClosureMismatch
                    elif (
                        requirement.role,
                        requirement.reference,
                        requirement.root_manifest_ref,
                    ) not in self._client:
                        raise EvidenceClosureMismatch
                else:
                    raise EvidenceClosureMismatch
            for group in loo_by_evidence.values():
                if set(group) != loo_roles or self._leave_one_out is None:
                    raise EvidenceClosureMismatch
                variant = group["leave_one_out_variant"]
                manifest = group["leave_one_out_authority_manifest"]
                provenance = group["leave_one_out_provenance"]
                if (
                    variant.root_manifest_ref != manifest.reference
                    or provenance.root_manifest_ref != manifest.reference
                    or self._leave_one_out.is_exact_active_closure(
                        mapping_ref=group["leave_one_out_mapping"].reference,
                        parent_ref=group["leave_one_out_parent"].reference,
                        variant_ref=variant.reference,
                        authority_manifest_ref=manifest.reference,
                        provenance_ref=provenance.reference,
                    )
                    is not True
                ):
                    raise EvidenceClosureMismatch
            self._global.verify(tuple(global_requirements), vocabulary=vocabulary)
        except EvidenceClosureMismatch:
            raise
        except Exception:
            raise EvidenceClosureMismatch from None


class _ExactPrivateRetriever:
    def __init__(
        self,
        *,
        route: str,
        client_id: str,
        evidence: tuple[PrivateGenerationEvidence, ...],
    ) -> None:
        self._route = route
        self._client_id = client_id
        selected = tuple(
            item.candidate for item in evidence if item.candidate.channel == route
        )
        self._candidates = tuple(
            sorted(selected, key=lambda item: (-item.score, _candidate_key(item)))
        )

    @property
    def artifact_binding(self) -> None:
        return None

    def search(
        self,
        query: str,
        scope: object,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        del query
        if (
            type(scope) is not RetrievalScope
            or scope.current_client_id != self._client_id
            or authority_snapshot.client_runtime_epoch <= 0
        ):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_PRIVATE_SCOPE_MISMATCH"
            )
        return self._candidates[:limit]


class _MultiSubqueryRetriever:
    def __init__(
        self,
        *,
        route: str,
        questions: tuple[str, ...],
        aggregate_query: str,
        delegate: Retriever,
    ) -> None:
        if not questions:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_ROUTE_WITHOUT_SUBQUERY"
            )
        self._route = route
        self._questions = questions
        self._aggregate_query = aggregate_query
        self._delegate = delegate

    @property
    def artifact_binding(self) -> object | None:
        return getattr(self._delegate, "artifact_binding", None)

    def search(
        self,
        query: str,
        scope: object,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        if query != self._aggregate_query:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_AGGREGATE_QUERY_MISMATCH"
            )
        best: dict[
            tuple[str, int, str, str, int, str, str], CandidateRef
        ] = {}
        for question in self._questions:
            values = self._delegate.search(
                question,
                scope,
                authority_snapshot,
                limit=limit,
            )
            if type(values) is not tuple:
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_RETRIEVER_RESULT_INVALID"
                )
            for candidate in values:
                if (
                    type(candidate) is not CandidateRef
                    or candidate.channel != self._route
                    or candidate.filter_binding is not None
                ):
                    raise GenerationRetrievalOrchestratorError(
                        "GENERATION_RETRIEVER_RESULT_INVALID"
                    )
                key = _candidate_key(candidate)
                previous = best.get(key)
                if previous is None or candidate.score > previous.score:
                    best[key] = candidate
        ordered = sorted(best.values(), key=lambda item: (-item.score, _candidate_key(item)))
        return tuple(ordered[:limit])


class _ExactPrivateContentReader:
    def __init__(self, evidence: tuple[PrivateGenerationEvidence, ...]) -> None:
        exact: dict[bytes, bytes] = {}
        for item in evidence:
            key = _exact_candidate_bytes(item.candidate)
            body = item.body.encode("utf-8")
            existing = exact.get(key)
            if existing is not None and existing != body:
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_PRIVATE_EVIDENCE_CONFLICT"
                )
            exact[key] = body
        self._exact = exact

    def read_verified(self, candidate: CandidateRef) -> bytes:
        body = self._exact.get(_exact_candidate_bytes(candidate))
        if (
            body is None
            or hashlib.sha256(body).hexdigest()
            != candidate.content_ref.content_sha256
            or len(body) != candidate.metadata.size_bytes
        ):
            raise EvidenceResolutionDenied
        return body


class _GenerationEvidenceContextReader:
    """Capture only already-filtered, hash-verified UTF-8 resolver bodies."""

    def __init__(self, delegate: VerifiedContentReader) -> None:
        self._delegate = delegate
        self._bodies: dict[tuple[str, int, str], str] = {}
        self._candidates: dict[
            tuple[str, int, str, str, int, str, str], CandidateRef
        ] = {}

    def read_verified(self, candidate: CandidateRef) -> bytes:
        try:
            body = self._delegate.read_verified(candidate)
            if type(body) is not bytes:
                raise ValueError
            text = body.decode("utf-8", errors="strict")
        except (TypeError, ValueError, UnicodeError, EvidenceResolutionDenied):
            raise EvidenceResolutionDenied from None
        if (
            not text.strip()
            or hashlib.sha256(body).hexdigest()
            != candidate.content_ref.content_sha256
            or len(body) != candidate.metadata.size_bytes
        ):
            raise EvidenceResolutionDenied
        key = _ref_key(candidate.content_ref)
        existing = self._bodies.get(key)
        if existing is not None and existing != text:
            raise EvidenceResolutionDenied
        self._bodies[key] = text
        candidate_key = _candidate_key(candidate)
        existing_candidate = self._candidates.get(candidate_key)
        if existing_candidate is not None and existing_candidate != candidate:
            raise EvidenceResolutionDenied
        self._candidates[candidate_key] = candidate
        return body

    def context_for(
        self,
        pack: EvidencePack,
    ) -> tuple[GenerationEvidenceContextItem, ...]:
        selected = {
            item.evidence_id: item
            for item in (*pack.supporting, *pack.contradicting)
        }
        try:
            context = tuple(
                GenerationEvidenceContextItem(
                    evidence_id=evidence_id,
                    context_kind="retrieved_candidate",
                    text_ref=item.text_ref,
                    body=self._bodies[_ref_key(item.text_ref)],
                )
                for evidence_id, item in sorted(selected.items())
            )
            return validate_retrieved_generation_evidence_context(pack, context)
        except (KeyError, TypeError, ValueError, GenerationEvidenceBindingMismatch):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_EVIDENCE_CONTEXT_MISMATCH"
            ) from None

    def selected_candidates_for(
        self,
        pack: EvidencePack,
    ) -> dict[str, CandidateRef]:
        """Resolve each packed ID to one exact filtered candidate read by resolver."""

        selected = {
            item.evidence_id: item
            for item in (*pack.supporting, *pack.contradicting)
        }
        result: dict[str, CandidateRef] = {}
        for evidence_id, packed in sorted(selected.items()):
            matches: list[CandidateRef] = []
            for candidate in self._candidates.values():
                provenance_sha256 = hashlib.sha256(
                    canonical_json_bytes(candidate.provenance.model_dump(mode="json"))
                ).hexdigest()
                if (
                    candidate.filter_binding is not None
                    and candidate.content_ref == packed.text_ref
                    and candidate.channel == packed.channel
                    and candidate.location == packed.location
                    and candidate.freshness == packed.freshness
                    and candidate.metadata.review_status == "approved"
                    and candidate.metadata.source_grade == packed.source_grade
                    and candidate.provenance.derivation_rule_ref
                    == packed.provenance.derivation_rule_ref
                    and provenance_sha256
                    == packed.provenance.provenance_ref.content_sha256
                ):
                    matches.append(candidate)
            if len(matches) != 1:
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_EVIDENCE_SOURCE_AMBIGUOUS"
                )
            result[evidence_id] = matches[0]
        return result


class _CompositeAuthorityRepository:
    """Join a live global snapshot to one worker-owned client binding."""

    def __init__(
        self,
        *,
        plan: QueryPlan,
        client_binding: GenerationClientBinding,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        global_repository: GlobalAuthorityRepository,
        revalidate_binding: Callable[[], GenerationClientBinding],
    ) -> None:
        self._plan = plan
        self._binding = client_binding
        self._global_repository = global_repository
        self._revalidate_binding = revalidate_binding
        self._private = {
            _exact_candidate_bytes(item.candidate): item.candidate
            for item in private_evidence
        }
        self._private_ref_ids = frozenset(
            item.candidate.reference.object_id for item in private_evidence
        )
        self._global_snapshot: AuthoritativeFilterSnapshot | None = None
        self._snapshot: AuthoritativeFilterSnapshot | None = None

    def _assert_client_current(self) -> None:
        try:
            current = GenerationClientBinding.model_validate(
                self._revalidate_binding(), strict=True
            )
        except Exception:
            raise AuthoritySnapshotStale from None
        if current != self._binding:
            raise AuthoritySnapshotStale

    def freeze(self, scope: RetrievalScope) -> AuthoritativeFilterSnapshot:
        if self._snapshot is not None:
            raise AuthoritySnapshotStale
        self._assert_client_current()
        try:
            global_snapshot = self._global_repository.freeze(scope)
        except Exception:
            raise AuthoritySnapshotStale from None
        self._assert_client_current()
        expected_tombstone = (
            (global_snapshot.tombstone_epoch >> 32) << 32
        ) | self._binding.client_tombstone_count
        if (
            global_snapshot.client_runtime_epoch != 0
            or global_snapshot.tombstone_epoch & _TOMBSTONE_CLIENT_MASK
            or global_snapshot.global_runtime_epoch != self._plan.global_runtime_epoch
            or global_snapshot.authorization_epoch != self._plan.authorization_epoch
            or expected_tombstone != self._plan.tombstone_epoch
        ):
            raise AuthoritySnapshotStale
        snapshot = global_snapshot.model_copy(
            update={
                "run_id": self._plan.envelope.run_id,
                "client_runtime_epoch": self._binding.client_runtime_epoch,
                "tombstone_epoch": expected_tombstone,
                "allowed_ref_ids": global_snapshot.allowed_ref_ids
                | self._private_ref_ids,
            }
        )
        self._global_snapshot = global_snapshot
        self._snapshot = snapshot
        return snapshot

    def assert_snapshot_current(
        self, snapshot: AuthoritativeFilterSnapshot
    ) -> None:
        if snapshot != self._snapshot or self._global_snapshot is None:
            raise AuthoritySnapshotStale
        try:
            self._global_repository.assert_snapshot_current(self._global_snapshot)
            self._assert_client_current()
        except Exception:
            raise AuthoritySnapshotStale from None

    def assert_current(self) -> None:
        if self._snapshot is None:
            raise AuthoritySnapshotStale
        self.assert_snapshot_current(self._snapshot)

    def candidate_status(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        if snapshot != self._snapshot or self._global_snapshot is None:
            raise AuthoritySnapshotStale
        if candidate.provenance.provenance_scope == "client_private":
            exact = self._private.get(_exact_candidate_bytes(candidate))
            if exact is None or candidate.reference.object_id not in snapshot.allowed_ref_ids:
                return "unauthorized"
            return "visible"
        return self._global_repository.candidate_status(candidate, self._global_snapshot)

    def assert_binding_current(self, binding: FilterCapabilityBinding) -> None:
        snapshot = self._snapshot
        if snapshot is None or (
            binding.run_id != snapshot.run_id
            or binding.global_runtime_epoch != snapshot.global_runtime_epoch
            or binding.client_runtime_epoch != snapshot.client_runtime_epoch
            or binding.tombstone_epoch != snapshot.tombstone_epoch
            or binding.authorization_epoch != snapshot.authorization_epoch
            or binding.policy_ref != snapshot.policy_ref
        ):
            raise AuthoritySnapshotStale
        self.assert_snapshot_current(snapshot)

    def assert_candidate_binding_visible(
        self,
        candidate: CandidateRef,
        binding: FilterCapabilityBinding,
    ) -> None:
        self.assert_binding_current(binding)
        if self._snapshot is None or self.candidate_status(candidate, self._snapshot) != "visible":
            raise AuthoritySnapshotStale


class GenerationRetrievalOrchestrator:
    """Execute one governed generation query plan through the real P4 pipeline."""

    def __init__(
        self,
        *,
        active_artifacts: ActiveGenerationArtifacts,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        dependency_factory: GenerationRetrievalDependencyFactory,
        contributor_identity_hasher: ContributorIdentityHasher | None = None,
        leave_one_out_verifier: LeaveOneOutAuthorityVerifier | None = None,
    ) -> None:
        if not isinstance(global_connection, sqlite3.Connection):
            raise TypeError("GENERATION_GLOBAL_CONNECTION_REQUIRED")
        if type(global_content_store) is not ContentStore:
            raise TypeError("GENERATION_GLOBAL_CONTENT_STORE_REQUIRED")
        if not callable(getattr(active_artifacts, "bindings", None)):
            raise TypeError("GENERATION_ACTIVE_ARTIFACTS_REQUIRED")
        if not callable(getattr(dependency_factory, "build", None)):
            raise TypeError("GENERATION_DEPENDENCY_FACTORY_REQUIRED")
        self._active = active_artifacts
        self._global_connection = global_connection
        self._global_store = global_content_store
        self._factory = dependency_factory
        self._contributor_hasher = contributor_identity_hasher
        self._leave_one_out_verifier = leave_one_out_verifier

    def retrieve(
        self,
        plan: QueryPlan,
        client_id: str,
        client_binding: GenerationClientBinding,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        revalidate_binding: Callable[[], GenerationClientBinding],
        *,
        c1_applicability_input: C1ApplicabilityInput | None = None,
        risk_context_binding: GenerationRiskContextBinding | None = None,
    ) -> GenerationRetrievalOutcome:
        values = QueryPlan.model_validate(plan, strict=True)
        binding = GenerationClientBinding.model_validate(client_binding, strict=True)
        private = tuple(
            PrivateGenerationEvidence.model_validate(item, strict=True)
            for item in private_evidence
        )
        self._validate_inputs(values, client_id, binding, private, revalidate_binding)
        if c1_applicability_input is None:
            applicability = C1ApplicabilityInput.bind(
                values,
                client_snapshot_ref=binding.client_snapshot_ref,
                client_runtime_epoch=binding.client_runtime_epoch,
                client_tombstone_count=binding.client_tombstone_count,
                temporary_fact_refs=binding.temporary_fact_refs,
            )
        else:
            try:
                applicability = C1ApplicabilityInput.model_validate(
                    c1_applicability_input,
                    strict=True,
                )
                applicability.assert_plan_closure(values)
            except (TypeError, ValueError):
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_C1_INPUT_INVALID"
                ) from None
            if (
                applicability.client_snapshot_ref != binding.client_snapshot_ref
                or applicability.client_runtime_epoch != binding.client_runtime_epoch
                or applicability.client_tombstone_count
                != binding.client_tombstone_count
                or applicability.temporary_fact_refs != binding.temporary_fact_refs
            ):
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_C1_INPUT_BINDING_MISMATCH"
                )
        self._verify_active_artifacts(values)
        dependencies = self._factory.build(
            plan=values,
            c1_applicability_input=applicability,
            active_artifacts=self._active,
            global_connection=self._global_connection,
            global_content_store=self._global_store,
        )
        if type(dependencies) is not GenerationRetrievalDependencies:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_RETRIEVAL_DEPENDENCIES_INVALID"
            )
        c1 = self._validate_dependencies(dependencies, applicability)
        aggregate_query, questions = self._query_routes(values)
        route_retrievers = self._route_retrievers(
            questions=questions,
            aggregate_query=aggregate_query,
            client_id=client_id,
            private_evidence=private,
            dependencies=dependencies,
        )
        authority = _CompositeAuthorityRepository(
            plan=values,
            client_binding=binding,
            private_evidence=private,
            global_repository=dependencies.global_snapshot_repository,
            revalidate_binding=revalidate_binding,
        )
        publisher = _RunObjectPublisher()
        reader = _GenerationEvidenceContextReader(
            ScopeRoutingContentReader(
                global_reader=dependencies.global_content_reader,
                client_reader=_ExactPrivateContentReader(private),
            )
        )
        coordinator = RetrievalCoordinator(
            snapshot_repository=authority,
            artifact_gate=dependencies.artifact_gate,
            retrievers=route_retrievers,
            candidate_filter=CandidateFilter(
                authority,
                contributor_identity_hasher=self._contributor_hasher,
                leave_one_out_verifier=self._leave_one_out_verifier,
            ),
            resolver=EvidenceResolver(authority, reader),
            semantics_resolver=dependencies.semantics_resolver,
            fusion=dependencies.fusion,
            reranker=dependencies.reranker,
            context_budget=dependencies.context_budget,
            token_counter=dependencies.token_counter,
            object_publisher=publisher,
            pack_builder=EvidencePackBuilder(
                closure_verifier=_CompositeClosureVerifier(
                    global_verifier=dependencies.closure_verifier,
                    publisher=publisher,
                    client_binding=binding,
                    private_evidence=private,
                    leave_one_out_verifier=self._leave_one_out_verifier,
                ),
                version_gate=dependencies.version_gate,
            ),
            contributor_identity_hasher=self._contributor_hasher,
            leave_one_out_verifier=self._leave_one_out_verifier,
        )
        scope = RetrievalScope(
            current_client_id=client_id,
            allowed_uses=dependencies.allowed_uses,
            maximum_sensitivity=dependencies.maximum_sensitivity,
            effective_at=values.envelope.created_at,
            known_at=values.envelope.created_at,
        )
        try:
            result = coordinator.retrieve(
                RetrievalRequest(
                    query=aggregate_query,
                    scope=scope,
                    routes=tuple(questions),
                    required_routes=frozenset(questions),
                    route_allowed_uses=(
                        {"case": frozenset({"answer_support"})}
                        if "case" in questions
                        else {}
                    ),
                    per_route_limit=dependencies.per_route_limit,
                    fusion_limit=dependencies.fusion_limit,
                    minimum_contradictions=(
                        1
                        if any(
                            item.category == "counterevidence_conflict"
                            for item in values.subqueries
                        )
                        else 0
                    ),
                    client_snapshot_ref=binding.client_snapshot_ref,
                    temporary_fact_refs=binding.temporary_fact_refs,
                    unresolved_conflict_refs=dependencies.unresolved_conflict_refs,
                    mandatory_conflict_claim_refs=(
                        dependencies.mandatory_conflict_claim_refs
                    ),
                    c1_applicability=c1.decision,
                    c1_policy_vocabulary=c1.vocabulary,
                    roots=RootManifestSet.model_validate(self._active.roots),
                    reranker_descriptor_ref=dependencies.reranker_descriptor_ref,
                )
            )
        except RetrievalCoordinatorError as error:
            raise GenerationRetrievalOrchestratorError(error.code) from None
        if any(result.route_candidate_counts.get(route, 0) == 0 for route in questions):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_REQUIRED_ROUTE_EMPTY"
            )
        if result.selected_evidence_count <= 0:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_EVIDENCE_PACK_EMPTY"
            )
        evidence_context = reader.context_for(result.evidence_pack.pack)
        selected_candidates = reader.selected_candidates_for(
            result.evidence_pack.pack
        )
        evidence_type_proofs = self._verify_required_evidence_types(
            values,
            result.evidence_pack.pack,
            evidence_context,
            selected_candidates,
            c1,
            risk_context_binding,
            client_id=client_id,
            contributor_identity_hasher=self._contributor_hasher,
        )
        self._verify_active_artifacts(values)
        authority.assert_current()
        metadata = GenerationRetrievalMetadata(
            route_candidate_counts=result.route_candidate_counts,
            filtered_candidate_count=result.filtered_candidate_count,
            resolved_evidence_count=result.resolved_evidence_count,
            selected_evidence_count=result.selected_evidence_count,
            degraded_components=result.degraded_components,
            evidence_type_proofs=evidence_type_proofs,
        )
        try:
            validate_generation_required_evidence_proofs(
                values,
                result.evidence_pack.pack,
                evidence_context,
                metadata.evidence_type_proofs,
                risk_context_binding=risk_context_binding,
            )
        except GenerationEvidenceBindingMismatch:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_REQUIRED_EVIDENCE_PROOF_CLOSURE_MISMATCH"
            ) from None
        return GenerationRetrievalOutcome(
            evidence_pack=result.evidence_pack.pack,
            evidence_pack_sha256=result.evidence_pack.canonical_sha256,
            evidence_context=evidence_context,
            run_objects=publisher.objects(),
            metadata=metadata,
        )

    @classmethod
    def _verify_required_evidence_types(
        cls,
        plan: QueryPlan,
        pack: EvidencePack,
        evidence_context: tuple[GenerationEvidenceContextItem, ...],
        selected_candidates: Mapping[str, CandidateRef],
        c1: GenerationC1Context,
        risk_context_binding: GenerationRiskContextBinding | None,
        *,
        client_id: str,
        contributor_identity_hasher: ContributorIdentityHasher | None,
    ) -> tuple[GenerationEvidenceTypeProof, ...]:
        """Fulfill every closed required pair from its real source authority.

        QueryPlan labels are requests, never proof.  Each supported type is
        recomputed from selected candidate metadata/body, active C1 authority,
        or a worker-verified turn risk result.  Unknown and unavailable source
        kinds fail closed.
        """

        context_by_id = {item.evidence_id: item for item in evidence_context}
        supporting_ids = {item.evidence_id for item in pack.supporting}
        contradicting_ids = {item.evidence_id for item in pack.contradicting}
        proofs: list[GenerationEvidenceTypeProof] = []
        for subquery in plan.subqueries:
            for evidence_type in subquery.required_evidence_types:
                evidence_ids: tuple[str, ...]
                if evidence_type == "temporal_graph_edge":
                    evidence_ids = cls._selected_temporal_graph_edge_ids(
                        pack,
                        evidence_context,
                        selected_candidates,
                        allowed_channels=frozenset(subquery.routes),
                    )
                    proofs.append(
                        GenerationEvidenceTypeProof(
                            subquery_id=subquery.subquery_id,
                            evidence_type=evidence_type,
                            proof_kind="candidate_selection",
                            evidence_ids=evidence_ids,
                            candidate_sources=cls._candidate_proof_sources(
                                evidence_ids,
                                pack,
                                context_by_id,
                                selected_candidates,
                                supporting_ids=supporting_ids,
                                contradicting_ids=contradicting_ids,
                            ),
                        )
                    )
                elif evidence_type == "case_provenance":
                    evidence_ids = cls._selected_case_provenance_ids(
                        pack,
                        selected_candidates,
                        client_id=client_id,
                        contributor_identity_hasher=(
                            contributor_identity_hasher
                        ),
                        allowed_channels=frozenset(subquery.routes),
                    )
                    proofs.append(
                        GenerationEvidenceTypeProof(
                            subquery_id=subquery.subquery_id,
                            evidence_type=evidence_type,
                            proof_kind="candidate_selection",
                            evidence_ids=evidence_ids,
                            candidate_sources=cls._candidate_proof_sources(
                                evidence_ids,
                                pack,
                                context_by_id,
                                selected_candidates,
                                supporting_ids=supporting_ids,
                                contradicting_ids=contradicting_ids,
                            ),
                        )
                    )
                elif evidence_type == "contradicting_evidence":
                    evidence_ids = tuple(
                        sorted(
                            item.evidence_id
                            for item in pack.contradicting
                            if item.channel in subquery.routes
                        )
                    )
                    proofs.append(
                        GenerationEvidenceTypeProof(
                            subquery_id=subquery.subquery_id,
                            evidence_type=evidence_type,
                            proof_kind="candidate_selection",
                            evidence_ids=evidence_ids,
                            candidate_sources=cls._candidate_proof_sources(
                                evidence_ids,
                                pack,
                                context_by_id,
                                selected_candidates,
                                supporting_ids=supporting_ids,
                                contradicting_ids=contradicting_ids,
                            ),
                        )
                    )
                elif evidence_type in {"theory_applicability", "theory_boundary"}:
                    decision = c1.decision
                    if decision != pack.c1_applicability:
                        raise GenerationRetrievalOrchestratorError(
                            "GENERATION_REQUIRED_C1_EVIDENCE_UNAVAILABLE"
                        )
                    proofs.append(
                        GenerationEvidenceTypeProof(
                            subquery_id=subquery.subquery_id,
                            evidence_type=evidence_type,
                            proof_kind="c1_authority",
                            c1_revision_ref=decision.revision,
                            c1_scope_policy_ref=decision.scope_policy_ref,
                            c1_decision_status=decision.status,
                            c1_effective_status=decision.effective_status,
                        )
                    )
                elif evidence_type == "risk_context":
                    if (
                        risk_context_binding is None
                        or risk_context_binding.turn_id != plan.envelope.turn_id
                    ):
                        raise GenerationRetrievalOrchestratorError(
                            "GENERATION_REQUIRED_RISK_CONTEXT_UNAVAILABLE"
                        )
                    proofs.append(
                        GenerationEvidenceTypeProof(
                            subquery_id=subquery.subquery_id,
                            evidence_type=evidence_type,
                            proof_kind="risk_evaluation",
                            evidence_ids=(
                                risk_context_binding.visible_observation_ids
                            ),
                            risk_turn_id=risk_context_binding.turn_id,
                            risk_client_message_sha256=(
                                risk_context_binding.client_message_sha256
                            ),
                            risk_evaluation_observation_ids=(
                                risk_context_binding.evaluation_observation_ids
                            ),
                            risk_authority=risk_context_binding.authority,
                            risk_evaluation_set_sha256=(
                                risk_context_binding.evaluation_set_sha256
                            ),
                            risk_evaluation_count=(
                                risk_context_binding.evaluation_count
                            ),
                            risk_visible_set_sha256=(
                                risk_context_binding.visible_set_sha256
                            ),
                            risk_visible_count=risk_context_binding.visible_count,
                        )
                    )
                else:
                    raise GenerationRetrievalOrchestratorError(
                        "GENERATION_REQUIRED_EVIDENCE_TYPE_UNSUPPORTED"
                    )

        expected = tuple(
            sorted(
                (subquery.subquery_id, evidence_type)
                for subquery in plan.subqueries
                for evidence_type in subquery.required_evidence_types
            )
        )
        actual = tuple(
            sorted((proof.subquery_id, proof.evidence_type) for proof in proofs)
        )
        if actual != expected or len(actual) != len(set(actual)):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_REQUIRED_EVIDENCE_PROOF_CLOSURE_MISMATCH"
            )
        return tuple(
            sorted(proofs, key=lambda item: (item.subquery_id, item.evidence_type))
        )

    @staticmethod
    def _selected_temporal_graph_edge_ids(
        pack: EvidencePack,
        evidence_context: tuple[GenerationEvidenceContextItem, ...],
        selected_candidates: Mapping[str, CandidateRef],
        *,
        allowed_channels: frozenset[str],
    ) -> tuple[str, ...]:
        selected = {
            item.evidence_id: item
            for item in (*pack.supporting, *pack.contradicting)
        }
        context_by_id = {item.evidence_id: item for item in evidence_context}
        fulfilled: list[str] = []
        for evidence_id, packed in sorted(selected.items()):
            if packed.channel != "client_history":
                continue
            exact = selected_candidates.get(evidence_id)
            context = context_by_id.get(evidence_id)
            if (
                "client_history" not in allowed_channels
                or exact is None
                or exact.object_type != "client_graph"
                or exact.metadata.media_type != "application/json"
                or context is None
                or context.context_kind != "retrieved_candidate"
                or context.text_ref != exact.content_ref
            ):
                continue
            body = context.body.encode("utf-8")
            try:
                graph, payload = load_graph(body)
            except (TypeError, ValueError, UnicodeError):
                continue
            if canonical_graph_bytes(payload) != body or graph.number_of_edges() <= 0:
                continue
            fulfilled.append(evidence_id)
        return tuple(sorted(fulfilled))

    @staticmethod
    def _selected_case_provenance_ids(
        pack: EvidencePack,
        selected_candidates: Mapping[str, CandidateRef],
        *,
        client_id: str,
        contributor_identity_hasher: ContributorIdentityHasher | None,
        allowed_channels: frozenset[str],
    ) -> tuple[str, ...]:
        if "case" not in allowed_channels:
            return ()
        fulfilled: list[str] = []
        for packed in (*pack.supporting, *pack.contradicting):
            exact = selected_candidates.get(packed.evidence_id)
            if (
                packed.channel != "case"
                or packed.provenance.provenance_scope
                not in {"case_derived", "mixed"}
                or packed.provenance.client_exclusion_status
                not in {
                    "no_subject_contribution",
                    "leave_one_subject_out_applied",
                }
                or exact is None
                or exact.channel != "case"
                or exact.provenance.provenance_scope
                not in {"case_derived", "mixed"}
                or is_current_client_contributor(
                    client_id,
                    exact,
                    contributor_identity_hasher=contributor_identity_hasher,
                )
                is not False
            ):
                continue
            fulfilled.append(packed.evidence_id)
        return tuple(sorted(fulfilled))

    @staticmethod
    def _candidate_proof_sources(
        evidence_ids: tuple[str, ...],
        pack: EvidencePack,
        context_by_id: Mapping[str, GenerationEvidenceContextItem],
        selected_candidates: Mapping[str, CandidateRef],
        *,
        supporting_ids: set[str],
        contradicting_ids: set[str],
    ) -> tuple[GenerationCandidateProofSource, ...]:
        if not evidence_ids:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_REQUIRED_EVIDENCE_TYPE_UNFULFILLED"
            )
        packed_by_id = {
            item.evidence_id: item
            for item in (*pack.supporting, *pack.contradicting)
        }
        sources: list[GenerationCandidateProofSource] = []
        for evidence_id in evidence_ids:
            packed = packed_by_id.get(evidence_id)
            exact = selected_candidates.get(evidence_id)
            context = context_by_id.get(evidence_id)
            if (
                packed is None
                or exact is None
                or exact.filter_binding is None
                or context is None
                or context.context_kind != "retrieved_candidate"
                or context.text_ref != exact.content_ref
                or context.body.encode("utf-8") == b""
                or hashlib.sha256(context.body.encode("utf-8")).hexdigest()
                != exact.content_ref.content_sha256
                or evidence_id not in supporting_ids | contradicting_ids
            ):
                raise GenerationRetrievalOrchestratorError(
                    "GENERATION_REQUIRED_EVIDENCE_SOURCE_INVALID"
                )
            sources.append(
                GenerationCandidateProofSource(
                    evidence_id=evidence_id,
                    pack_role=(
                        "supporting"
                        if evidence_id in supporting_ids
                        else "contradicting"
                    ),
                    candidate_ref=exact.reference,
                    text_ref=exact.content_ref,
                    provenance_ref=packed.provenance.provenance_ref,
                    channel=exact.channel,
                    object_type=exact.object_type,
                )
            )
        return tuple(sorted(sources, key=lambda item: item.evidence_id))

    @staticmethod
    def _validate_inputs(
        plan: QueryPlan,
        client_id: str,
        binding: GenerationClientBinding,
        private: tuple[PrivateGenerationEvidence, ...],
        revalidate_binding: Callable[[], GenerationClientBinding],
    ) -> None:
        if type(client_id) is not str or not client_id:
            raise GenerationRetrievalOrchestratorError("GENERATION_CLIENT_ID_INVALID")
        if not callable(revalidate_binding):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_BINDING_REVALIDATOR_REQUIRED"
            )
        if (
            plan.client_snapshot_ref != binding.client_snapshot_ref
            or plan.client_runtime_epoch != binding.client_runtime_epoch
            or (plan.tombstone_epoch & _TOMBSTONE_CLIENT_MASK)
            != binding.client_tombstone_count
        ):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_BINDING_MISMATCH"
            )
        private_keys = tuple(_candidate_key(item.candidate) for item in private)
        if len(private_keys) != len(set(private_keys)):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_PRIVATE_EVIDENCE_DUPLICATE"
            )
        if any(
            item.candidate.provenance.private_owner_client_id != client_id
            for item in private
        ):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_PRIVATE_OWNER_MISMATCH"
            )

    def _verify_active_artifacts(self, plan: QueryPlan) -> None:
        if self._active.active_runtime_epoch != plan.global_runtime_epoch:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_ACTIVE_ARTIFACT_EPOCH_MISMATCH"
            )
        try:
            bindings = self._active.bindings()
            if type(bindings) is not tuple or not bindings:
                raise ValueError
            for binding in bindings:
                verify_scope = getattr(binding, "verify_authority_connection", None)
                if callable(verify_scope):
                    verify_scope(self._global_connection)
                verify_current = getattr(binding, "verify_current", None)
                if not callable(verify_current):
                    raise ValueError
                verify_current()
        except Exception:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_ACTIVE_ARTIFACT_INVALID"
            ) from None

    @staticmethod
    def _validate_dependencies(
        dependencies: GenerationRetrievalDependencies,
        applicability_input: C1ApplicabilityInput,
    ) -> GenerationC1Context:
        c1 = dependencies.c1_context
        if c1 is None:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_C1_POLICY_UNAVAILABLE"
            )
        try:
            exact_c1 = GenerationC1Context.model_validate(c1, strict=True)
        except (TypeError, ValueError):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_C1_CONTEXT_INVALID"
            ) from None
        if exact_c1.applicability_input_sha256 != applicability_input.canonical_sha256:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_C1_INPUT_CLOSURE_MISMATCH"
            )
        routes = dict(dependencies.global_retrievers)
        if any(route in _PRIVATE_ROUTES for route in routes):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_PRIVATE_ROUTE_IN_GLOBAL_REGISTRY"
            )
        if (
            not dependencies.allowed_uses
            or dependencies.maximum_sensitivity < 0
            or dependencies.per_route_limit <= 0
            or dependencies.fusion_limit <= 0
        ):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_RETRIEVAL_POLICY_INVALID"
            )
        return exact_c1

    @staticmethod
    def _query_routes(
        plan: QueryPlan,
    ) -> tuple[str, dict[str, tuple[str, ...]]]:
        route_questions: dict[str, list[str]] = {}
        ordered_subqueries = sorted(plan.subqueries, key=lambda item: item.subquery_id)
        for subquery in ordered_subqueries:
            for route in subquery.routes:
                values = route_questions.setdefault(route, [])
                if subquery.question not in values:
                    values.append(subquery.question)
        if not route_questions:
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_QUERY_PLAN_HAS_NO_RETRIEVAL_ROUTE"
            )
        omitted = {item.route for item in plan.route_omissions}
        if omitted & set(route_questions):
            raise GenerationRetrievalOrchestratorError(
                "GENERATION_QUERY_PLAN_ROUTE_CONFLICT"
            )
        aggregate_query = "\n".join(
            f"[{item.subquery_id}] {item.question}" for item in ordered_subqueries
        )
        return aggregate_query, {
            route: tuple(route_questions[route]) for route in sorted(route_questions)
        }

    @staticmethod
    def _route_retrievers(
        *,
        questions: Mapping[str, tuple[str, ...]],
        aggregate_query: str,
        client_id: str,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        dependencies: GenerationRetrievalDependencies,
    ) -> dict[str, Retriever]:
        routes: dict[str, Retriever] = {}
        for route, route_questions in questions.items():
            if route in _PRIVATE_ROUTES:
                delegate: Retriever = _ExactPrivateRetriever(
                    route=route,
                    client_id=client_id,
                    evidence=private_evidence,
                )
            else:
                delegate = dependencies.global_retrievers.get(route)  # type: ignore[assignment]
                if delegate is None:
                    raise GenerationRetrievalOrchestratorError(
                        "RETRIEVAL_ROUTE_UNAVAILABLE"
                    )
            routes[route] = _MultiSubqueryRetriever(
                route=route,
                questions=route_questions,
                aggregate_query=aggregate_query,
                delegate=delegate,
            )
        return routes


__all__ = [
    "ActiveGenerationArtifacts",
    "GenerationC1Context",
    "GenerationRetrievalDependencies",
    "GenerationRetrievalDependencyFactory",
    "GenerationRetrievalOrchestrator",
    "GenerationRetrievalOrchestratorError",
    "GenerationRetrievalOutcome",
    "GlobalAuthorityRepository",
]
