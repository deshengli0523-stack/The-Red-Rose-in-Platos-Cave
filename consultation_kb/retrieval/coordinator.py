"""One-snapshot orchestration for hybrid retrieval and EvidencePack assembly."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Mapping
from typing import Protocol

from pydantic import Field, field_serializer, field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.cases import LeaveOneOutVariantAuthority
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
    ClientExclusionStatus,
    Provenance,
    RetrievalScope,
)

from .budget import BudgetItem, BudgetSelection, ContextBudget
from .contracts import (
    CandidateRef,
    DeniedReason,
    ExclusionProof,
    FilterCapabilityBinding,
    FilterDecision,
    Retriever,
    candidate_set_sha256,
    canonical_json_bytes,
    capability_sha256,
)
from .evidence_pack import (
    ArtifactVersionMismatch,
    C1PolicyVocabulary,
    CandidateEvidenceInput,
    EvidencePackBuildResult,
    EvidencePackBuilder,
    EvidencePackInputs,
    FrameworkPriority,
    RootManifestSet,
)
from .filters import (
    CandidateFilter,
    ContributorIdentityHasher,
    LeaveOneOutAuthorityVerifier,
    is_current_client_contributor,
)
from .fusion import (
    EvidenceStance,
    FusedCandidate,
    FusionEvidence,
    ReciprocalRankFusion,
)
from .rerank import EvidenceReranker, RerankRun, RerankedCandidate
from .resolver import EvidenceResolver


_ROUTES = frozenset(
    {"profile", "client_history", "wiki", "lexical", "vector", "global_graph", "case"}
)


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _canonical_refs(values: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
    keys = [_ref_key(value) for value in values]
    if len(keys) != len(set(keys)):
        raise ValueError("retrieval request contains duplicate references")
    return tuple(sorted(values, key=_ref_key))


class RetrievalCoordinatorError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CandidateSemantics(StrictModel):
    stance: EvidenceStance
    theory_ref: VersionRef | None = None


class CandidateSemanticsResolver(Protocol):
    def resolve(self, candidate: CandidateRef) -> CandidateSemantics: ...


class AuthoritySnapshotRepository(Protocol):
    def freeze(self, scope: RetrievalScope) -> AuthoritativeFilterSnapshot: ...

    def assert_snapshot_current(self, snapshot: AuthoritativeFilterSnapshot) -> None: ...


class RetrievalArtifactGate(Protocol):
    """Verify the exact active derived set outside channel degradation paths."""

    def verify(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
        retrievers: Mapping[str, Retriever],
        routes: tuple[str, ...],
    ) -> None: ...


class RetrievalObjectPublisher(Protocol):
    def publish(self, object_type: SafePolicyKey, payload: bytes) -> VersionRef: ...


class TokenCounter(Protocol):
    def count(self, payload: bytes) -> int: ...


class RetrievalRequest(StrictModel):
    """Private request envelope supplied by the governed query plan."""

    query: NonEmptyStr
    scope: RetrievalScope
    routes: tuple[SafePolicyKey, ...]
    required_routes: frozenset[SafePolicyKey]
    route_allowed_uses: dict[SafePolicyKey, frozenset[SafePolicyKey]] = Field(
        default_factory=dict
    )
    per_route_limit: PositiveInt = 20
    fusion_limit: PositiveInt = 40
    minimum_contradictions: NonNegativeInt = 1
    minimum_alternatives: NonNegativeInt = 0
    client_snapshot_ref: VersionRef
    temporary_fact_refs: tuple[VersionRef, ...]
    unresolved_conflict_refs: tuple[VersionRef, ...]
    mandatory_conflict_claim_refs: tuple[VersionRef, ...] = ()
    c1_applicability: C1ApplicabilityDecision
    c1_policy_vocabulary: C1PolicyVocabulary
    roots: RootManifestSet
    reranker_descriptor_ref: VersionRef

    @field_validator("routes")
    @classmethod
    def _canonical_routes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)) or not set(value) <= _ROUTES:
            raise ValueError("RETRIEVAL_ROUTE_SET_INVALID")
        return tuple(sorted(value))

    @field_validator("required_routes")
    @classmethod
    def _valid_required_routes(cls, value: frozenset[str]) -> frozenset[str]:
        if not value <= _ROUTES:
            raise ValueError("RETRIEVAL_REQUIRED_ROUTE_SET_INVALID")
        return value

    @field_serializer("required_routes")
    def _serialize_required_routes(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_serializer("route_allowed_uses")
    def _serialize_route_allowed_uses(
        self,
        value: dict[str, frozenset[str]],
    ) -> dict[str, list[str]]:
        return {route: sorted(uses) for route, uses in sorted(value.items())}

    @field_validator("route_allowed_uses")
    @classmethod
    def _canonical_route_allowed_uses(
        cls,
        value: dict[str, frozenset[str]],
    ) -> dict[str, frozenset[str]]:
        if any(route not in _ROUTES or not uses for route, uses in value.items()):
            raise ValueError("RETRIEVAL_ROUTE_ALLOWED_USES_INVALID")
        return dict(sorted(value.items()))

    @field_validator(
        "temporary_fact_refs",
        "unresolved_conflict_refs",
        "mandatory_conflict_claim_refs",
    )
    @classmethod
    def _sort_refs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        return _canonical_refs(value)

    @field_validator("mandatory_conflict_claim_refs")
    @classmethod
    def _claim_refs_only(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        if any(reference.object_id[:-37] != "claim" for reference in value):
            raise ValueError("C1_CONFLICT_CLAIM_REF_REQUIRED")
        return value

    @model_validator(mode="after")
    def _validate_request_closure(self) -> "RetrievalRequest":
        if not self.required_routes <= frozenset(self.routes):
            raise ValueError("REQUIRED_ROUTE_NOT_REQUESTED")
        if not set(self.route_allowed_uses) <= set(self.routes):
            raise ValueError("ROUTE_ALLOWED_USES_NOT_REQUESTED")
        if self.c1_policy_vocabulary.scope_policy_ref != (
            self.c1_applicability.scope_policy_ref
        ):
            raise ValueError("C1_POLICY_REF_MISMATCH")
        if self.c1_applicability.conflict_evidence_ids:
            raise ValueError("C1_PACK_EVIDENCE_IDS_MUST_BE_UNSET_BEFORE_RETRIEVAL")
        return self


class RetrievalCoordinatorResult(StrictModel):
    evidence_pack: EvidencePackBuildResult
    route_candidate_counts: dict[SafePolicyKey, NonNegativeInt]
    filtered_candidate_count: NonNegativeInt
    resolved_evidence_count: NonNegativeInt
    selected_evidence_count: NonNegativeInt
    degraded_components: tuple[SafePolicyKey, ...]

    @field_validator("route_candidate_counts")
    @classmethod
    def _canonical_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if any(key not in _ROUTES or type(count) is not int or count < 0 for key, count in value.items()):
            raise ValueError("route candidate counts are invalid")
        return dict(sorted(value.items()))

    @field_validator("degraded_components")
    @classmethod
    def _canonical_degraded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("degraded components must be unique")
        return tuple(sorted(value))


class RetrievalCoordinator:
    """Execute every retrieval channel against one live authority snapshot."""

    def __init__(
        self,
        *,
        snapshot_repository: AuthoritySnapshotRepository,
        artifact_gate: RetrievalArtifactGate,
        retrievers: Mapping[str, Retriever],
        candidate_filter: CandidateFilter,
        resolver: EvidenceResolver,
        semantics_resolver: CandidateSemanticsResolver,
        fusion: ReciprocalRankFusion,
        reranker: EvidenceReranker,
        context_budget: ContextBudget,
        token_counter: TokenCounter,
        object_publisher: RetrievalObjectPublisher,
        pack_builder: EvidencePackBuilder,
        contributor_identity_hasher: ContributorIdentityHasher | None = None,
        leave_one_out_verifier: LeaveOneOutAuthorityVerifier | None = None,
    ) -> None:
        if not callable(getattr(snapshot_repository, "freeze", None)) or not callable(
            getattr(snapshot_repository, "assert_snapshot_current", None)
        ):
            raise TypeError("AUTHORITY_SNAPSHOT_REPOSITORY_REQUIRED")
        if not callable(getattr(artifact_gate, "verify", None)):
            raise TypeError("RETRIEVAL_ARTIFACT_GATE_REQUIRED")
        route_map = dict(retrievers)
        if not route_map or not set(route_map) <= _ROUTES or any(
            not callable(getattr(retriever, "search", None))
            for retriever in route_map.values()
        ):
            raise TypeError("RETRIEVER_REGISTRY_INVALID")
        if not callable(getattr(semantics_resolver, "resolve", None)):
            raise TypeError("CANDIDATE_SEMANTICS_RESOLVER_REQUIRED")
        if not callable(getattr(token_counter, "count", None)):
            raise TypeError("TOKEN_COUNTER_REQUIRED")
        if not callable(getattr(object_publisher, "publish", None)):
            raise TypeError("RETRIEVAL_OBJECT_PUBLISHER_REQUIRED")
        self._snapshots = snapshot_repository
        self._artifact_gate = artifact_gate
        self._retrievers = route_map
        self._filter = candidate_filter
        self._resolver = resolver
        self._semantics = semantics_resolver
        self._fusion = fusion
        self._reranker = reranker
        self._budget = context_budget
        self._tokens = token_counter
        self._publisher = object_publisher
        self._pack_builder = pack_builder
        self._contributor_hasher = contributor_identity_hasher
        self._leave_one_out_verifier = leave_one_out_verifier

    def retrieve(self, request: RetrievalRequest) -> RetrievalCoordinatorResult:
        values = RetrievalRequest.model_validate(request)
        if not set(values.routes) <= set(self._retrievers):
            raise RetrievalCoordinatorError("RETRIEVAL_ROUTE_UNAVAILABLE")
        try:
            snapshot = self._snapshots.freeze(values.scope)
        except Exception:
            raise RetrievalCoordinatorError("AUTHORITY_SNAPSHOT_INVALID") from None
        self._verify_artifacts(snapshot, values.roots, values.routes)
        self._pack_builder.verify_active_artifacts(snapshot, values.roots)
        snapshot_ref = self._publish_exact(
            "authority_snapshot",
            canonical_json_bytes(snapshot.model_dump(mode="json")),
        )

        raw: list[CandidateRef] = []
        routed_candidates: dict[str, tuple[CandidateRef, ...]] = {}
        counts: dict[str, int] = {}
        degraded: set[str] = set()
        for route in values.routes:
            try:
                candidates = self._retrievers[route].search(
                    values.query,
                    values.scope,
                    snapshot,
                    limit=values.per_route_limit,
                )
                if type(candidates) is not tuple or any(
                    type(candidate) is not CandidateRef for candidate in candidates
                ):
                    raise TypeError
            except Exception:
                # A corrupt, stale, or substituted derived artifact is never an
                # optional-channel degradation.  Recheck the governed set before
                # deciding whether the route's own failure may be degraded.
                self._verify_artifacts(snapshot, values.roots, values.routes)
                if route in values.required_routes:
                    raise RetrievalCoordinatorError(
                        "RETRIEVAL_REQUIRED_CHANNEL_FAILED"
                    ) from None
                counts[route] = 0
                degraded.add(f"route_{route}")
                continue
            self._verify_artifacts(snapshot, values.roots, values.routes)
            counts[route] = len(candidates)
            routed_candidates[route] = candidates
            raw.extend(candidates)

        raw_candidates = tuple(raw)
        try:
            decision = self._filter_candidates(
                values,
                routed_candidates,
                raw_candidates,
                snapshot,
            )
            resolved = self._resolver.resolve_many(decision.allowed)
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_FILTER_OR_RESOLUTION_FAILED") from None
        proof_ref = decision.exclusion_proof_ref or self._publish_exact(
            "exclusion_proof",
            canonical_json_bytes(decision.proof.model_dump(mode="json")),
        )

        rankings: dict[str, list[FusionEvidence]] = {}
        try:
            for candidate in decision.allowed:
                semantics = self._semantics.resolve(candidate)
                evidence = FusionEvidence(
                    candidate=candidate,
                    stance=semantics.stance,
                    theory_ref=semantics.theory_ref,
                    empirical_support=candidate.metadata.empirical_support,
                )
                rankings.setdefault(candidate.channel, []).append(evidence)
            fused = self._fusion.fuse(
                {channel: tuple(items) for channel, items in sorted(rankings.items())},
                c1_applicability=values.c1_applicability,
                limit=values.fusion_limit,
                minimum_contradictions=values.minimum_contradictions,
                minimum_alternatives=values.minimum_alternatives,
            )
            reranked = self._reranker.rerank(values.query, fused, resolved)
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_FUSION_OR_RERANK_FAILED") from None
        degraded.update(reranked.manifest.degraded_components)
        self._assert_reranker_descriptor(values.reranker_descriptor_ref, reranked)

        try:
            budget_items = tuple(self._budget_item(item, values) for item in reranked.candidates)
            selection = self._budget.select(budget_items)
            supporting, contradicting, conflict_ids = self._pack_inputs(
                selection,
                values,
                raw_candidates,
                snapshot,
            )
        except RetrievalCoordinatorError:
            raise
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_BUDGET_FAILED") from None

        final_c1 = values.c1_applicability.model_copy(
            update={"conflict_evidence_ids": conflict_ids}
        )
        try:
            self._snapshots.assert_snapshot_current(snapshot)
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_AUTHORITY_STALE") from None
        self._verify_artifacts(snapshot, values.roots, values.routes)
        try:
            pack = self._pack_builder.build(
                EvidencePackInputs(
                    scope=values.scope,
                    authority_snapshot=snapshot,
                    authority_snapshot_ref=snapshot_ref,
                    client_snapshot_ref=values.client_snapshot_ref,
                    temporary_fact_refs=values.temporary_fact_refs,
                    supporting=supporting,
                    contradicting=contradicting,
                    unresolved_conflict_refs=values.unresolved_conflict_refs,
                    c1_applicability=final_c1,
                    c1_policy_vocabulary=values.c1_policy_vocabulary,
                    exclusion_proof_ref=proof_ref,
                    roots=values.roots,
                    reranker_descriptor_ref=values.reranker_descriptor_ref,
                )
            )
        except ArtifactVersionMismatch:
            raise
        self._verify_artifacts(snapshot, values.roots, values.routes)
        try:
            self._snapshots.assert_snapshot_current(snapshot)
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_AUTHORITY_STALE") from None
        return RetrievalCoordinatorResult(
            evidence_pack=pack,
            route_candidate_counts=counts,
            filtered_candidate_count=len(decision.allowed),
            resolved_evidence_count=len(resolved),
            selected_evidence_count=len(supporting) + len(contradicting),
            degraded_components=tuple(degraded),
        )

    def _filter_candidates(
        self,
        request: RetrievalRequest,
        routed_candidates: Mapping[str, tuple[CandidateRef, ...]],
        raw_candidates: tuple[CandidateRef, ...],
        snapshot: AuthoritativeFilterSnapshot,
    ) -> FilterDecision:
        """Apply per-route use grants and emit one resolver capability."""

        if not request.route_allowed_uses:
            return self._filter.filter(request.scope, raw_candidates, snapshot)

        allowed_unbound: list[CandidateRef] = []
        denied: Counter[DeniedReason] = Counter()
        for route in request.routes:
            route_scope = request.scope.model_copy(
                update={
                    "allowed_uses": request.route_allowed_uses.get(
                        route,
                        request.scope.allowed_uses,
                    )
                }
            )
            decision = self._filter.filter(
                route_scope,
                routed_candidates.get(route, ()),
                snapshot,
            )
            denied.update(decision.proof.reasons)
            allowed_unbound.extend(
                candidate.model_copy(update={"filter_binding": None})
                for candidate in decision.allowed
            )

        unbound = tuple(allowed_unbound)
        binding = FilterCapabilityBinding(
            run_id=snapshot.run_id,
            global_runtime_epoch=snapshot.global_runtime_epoch,
            client_runtime_epoch=snapshot.client_runtime_epoch,
            tombstone_epoch=snapshot.tombstone_epoch,
            authorization_epoch=snapshot.authorization_epoch,
            policy_ref=snapshot.policy_ref,
            decision_sha256=capability_sha256(snapshot, unbound),
        )
        allowed = tuple(
            candidate.model_copy(update={"filter_binding": binding})
            for candidate in unbound
        )
        return FilterDecision(
            allowed=allowed,
            proof=ExclusionProof(
                run_id=snapshot.run_id,
                policy_ref=snapshot.policy_ref,
                input_count=len(raw_candidates),
                allowed_count=len(allowed),
                denied_count=len(raw_candidates) - len(allowed),
                candidate_ids_sha256=candidate_set_sha256(raw_candidates),
                reasons=dict(denied),
            ),
        )

    def _verify_artifacts(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
        routes: tuple[str, ...],
    ) -> None:
        try:
            self._artifact_gate.verify(
                snapshot,
                roots,
                self._retrievers,
                routes,
            )
        except ArtifactVersionMismatch:
            raise
        except Exception:
            raise ArtifactVersionMismatch from None

    def _publish_exact(self, object_type: str, payload: bytes) -> VersionRef:
        try:
            reference = self._publisher.publish(object_type, payload)
            validated = VersionRef.model_validate(reference)
        except Exception:
            raise RetrievalCoordinatorError("RETRIEVAL_OBJECT_PUBLICATION_FAILED") from None
        if (
            validated.object_id[:-37] != object_type
            or validated.content_sha256 != hashlib.sha256(payload).hexdigest()
        ):
            raise RetrievalCoordinatorError("RETRIEVAL_OBJECT_PUBLICATION_FAILED")
        return validated

    @staticmethod
    def _assert_reranker_descriptor(
        reference: VersionRef,
        run: RerankRun,
    ) -> None:
        if reference.content_sha256 != run.manifest.descriptor_id:
            raise RetrievalCoordinatorError("RERANKER_DESCRIPTOR_MISMATCH")

    def _budget_item(
        self,
        item: RerankedCandidate,
        request: RetrievalRequest,
    ) -> BudgetItem:
        if not item.resolved:
            raise RetrievalCoordinatorError("RERANKED_EVIDENCE_UNRESOLVED")
        bodies = tuple(value.body for value in item.resolved)
        joined = b"\n\n".join(bodies)
        token_count = self._tokens.count(joined)
        if type(token_count) is not int or token_count <= 0:
            raise RetrievalCoordinatorError("TOKEN_COUNT_INVALID")
        roles = self._roles(item.fused, request)
        model_score = item.model_score
        marginal = item.fused.rrf_score + (
            0.0 if model_score is None else max(0.0, model_score)
        )
        if not math.isfinite(marginal):
            raise RetrievalCoordinatorError("RERANK_SCORE_INVALID")
        return BudgetItem(
            evidence_id=item.fused.evidence_id,
            body=joined,
            token_count=token_count,
            roles=roles,
            source_keys=item.fused.source_keys,
            marginal_value=marginal,
            fused=item.fused,
            resolved=item.resolved,
        )

    @staticmethod
    def _roles(
        fused: FusedCandidate,
        request: RetrievalRequest,
    ) -> frozenset[str]:
        roles: set[str] = set()
        roles.add(
            {
                "support": "support",
                "contradiction": "contradiction",
                "alternative": "alternative",
                "context": "context",
            }[fused.stance]
        )
        channels = {candidate.channel for candidate in fused.members}
        if channels & {"profile", "client_history"}:
            roles.add("current_fact")
        if "lexical" in channels:
            roles.add("exact_quote")
        if fused.primary_framework:
            roles.add("c1_scope")
        if _ref_key(fused.claim_ref) in {
            _ref_key(reference)
            for reference in request.mandatory_conflict_claim_refs
        }:
            roles.add("c1_limit")
        return frozenset(roles)

    def _pack_inputs(
        self,
        selection: BudgetSelection,
        request: RetrievalRequest,
        raw_candidates: tuple[CandidateRef, ...],
        snapshot: AuthoritativeFilterSnapshot,
    ) -> tuple[
        tuple[CandidateEvidenceInput, ...],
        tuple[CandidateEvidenceInput, ...],
        tuple[str, ...],
    ]:
        selected_claim_refs = {
            _ref_key(item.fused.claim_ref)
            for item in selection.selected
            if item.fused is not None
        }
        required_conflicts = {
            _ref_key(reference)
            for reference in request.mandatory_conflict_claim_refs
        }
        if not required_conflicts <= selected_claim_refs:
            raise RetrievalCoordinatorError("RETRIEVAL_MANDATORY_EVIDENCE_OMITTED")
        loo_authorities, expected_loo_refs = self._leave_one_out_authorities(
            request,
            raw_candidates,
            snapshot,
        )
        supporting: list[CandidateEvidenceInput] = []
        contradicting: list[CandidateEvidenceInput] = []
        used_ids: set[str] = set()
        conflict_ids: dict[tuple[str, int, str], str] = {}
        provenance_refs: dict[bytes, VersionRef] = {}
        for budget_item in selection.selected:
            fused = budget_item.fused
            if fused is None or not budget_item.resolved:
                raise RetrievalCoordinatorError("BUDGET_EVIDENCE_BINDING_INVALID")
            final_score = (
                fused.rrf_score
                if budget_item.marginal_value == fused.rrf_score
                else budget_item.marginal_value
            )
            passage_ids = {
                (
                    passage.candidate.reference.object_id,
                    passage.candidate.reference.version,
                    passage.candidate.reference.content_sha256,
                    passage.candidate.content_ref.object_id,
                    passage.candidate.content_ref.version,
                    passage.candidate.content_ref.content_sha256,
                ): passage.evidence_id
                for passage in fused.passages
            }
            for resolved in budget_item.resolved:
                candidate = resolved.candidate
                passage_key = (
                    candidate.reference.object_id,
                    candidate.reference.version,
                    candidate.reference.content_sha256,
                    candidate.content_ref.object_id,
                    candidate.content_ref.version,
                    candidate.content_ref.content_sha256,
                )
                evidence_id = passage_ids.get(passage_key)
                if evidence_id is None or evidence_id in used_ids:
                    raise RetrievalCoordinatorError("FUSED_PASSAGE_IDENTITY_INVALID")
                used_ids.add(evidence_id)
                claim_key = _ref_key(fused.claim_ref)
                if claim_key in required_conflicts:
                    conflict_ids.setdefault(claim_key, evidence_id)
                provenance = resolved.candidate.provenance
                provenance_payload = canonical_json_bytes(
                    provenance.model_dump(mode="json")
                )
                provenance_ref = provenance_refs.get(provenance_payload)
                if provenance_ref is None:
                    provenance_ref = self._publish_exact(
                        "provenance", provenance_payload
                    )
                    provenance_refs[provenance_payload] = provenance_ref
                exclusion_status, loo_authority = self._exclusion_status(
                    resolved.candidate,
                    loo_authorities,
                    expected_loo_refs,
                )
                loo_ref = (
                    None if loo_authority is None else loo_authority.variant_ref
                )
                current_client_is_case_contributor: bool | None = None
                if provenance.provenance_scope in {"case_derived", "mixed"}:
                    current_client_is_case_contributor = (
                        is_current_client_contributor(
                            request.scope.current_client_id,
                            resolved.candidate,
                            contributor_identity_hasher=self._contributor_hasher,
                        )
                    )
                    if current_client_is_case_contributor is None:
                        raise RetrievalCoordinatorError(
                            "RETRIEVAL_CONTRIBUTOR_IDENTITY_UNAVAILABLE"
                        )
                framework_priority: FrameworkPriority = (
                    "highest"
                    if fused.primary_framework
                    else (
                        "not_applicable"
                        if resolved.candidate.metadata.framework_priority
                        == "not_applicable"
                        else "normal"
                    )
                )
                candidate_input = CandidateEvidenceInput(
                    evidence_id=evidence_id,
                    resolved=resolved,
                    provenance_ref=provenance_ref,
                    independent_source_count=self._independent_source_count(
                        provenance
                    ),
                    client_exclusion_status=exclusion_status,
                    leave_one_out_variant_ref=loo_ref,
                    leave_one_out_mapping_ref=(
                        None if loo_authority is None else loo_authority.mapping_ref
                    ),
                    leave_one_out_parent_ref=(
                        None if loo_authority is None else loo_authority.parent_ref
                    ),
                    leave_one_out_authority_manifest_ref=(
                        None
                        if loo_authority is None
                        else loo_authority.authority_manifest_ref
                    ),
                    leave_one_out_provenance_ref=(
                        None
                        if loo_authority is None
                        else loo_authority.provenance_ref
                    ),
                    current_client_is_case_contributor=(
                        current_client_is_case_contributor
                    ),
                    framework_priority=framework_priority,
                    empirical_support=fused.empirical_support,
                    score=final_score,
                    supports_evidence_ids=(),
                    contradicts_evidence_ids=(),
                )
                if fused.stance in {"contradiction", "alternative"}:
                    contradicting.append(candidate_input)
                else:
                    supporting.append(candidate_input)
        return (
            tuple(supporting),
            tuple(contradicting),
            tuple(
                conflict_ids[_ref_key(claim_ref)]
                for claim_ref in request.mandatory_conflict_claim_refs
            ),
        )

    def _leave_one_out_authorities(
        self,
        request: RetrievalRequest,
        raw_candidates: tuple[CandidateRef, ...],
        snapshot: AuthoritativeFilterSnapshot,
    ) -> tuple[
        dict[tuple[str, int, str], LeaveOneOutVariantAuthority],
        set[tuple[str, int, str]],
    ]:
        authorities: dict[
            tuple[str, int, str], LeaveOneOutVariantAuthority
        ] = {}
        expected: set[tuple[str, int, str]] = set()
        case_scope = request.scope.model_copy(
            update={
                "allowed_uses": request.route_allowed_uses.get(
                    "case",
                    request.scope.allowed_uses,
                )
            }
        )
        for candidate in raw_candidates:
            variant = candidate.metadata.leave_one_out
            if variant is None:
                continue
            is_contributor = is_current_client_contributor(
                case_scope.current_client_id,
                candidate,
                contributor_identity_hasher=self._contributor_hasher,
            )
            if is_contributor is None:
                raise RetrievalCoordinatorError(
                    "RETRIEVAL_CONTRIBUTOR_IDENTITY_UNAVAILABLE"
                )
            if not is_contributor:
                continue
            key = _ref_key(variant.reference)
            expected.add(key)
            verifier = self._leave_one_out_verifier
            if verifier is None:
                continue
            try:
                authority = verifier.resolve_exact_approved_variant(
                    original=candidate,
                    variant=variant,
                    scope=case_scope,
                    authority_snapshot=snapshot,
                )
            except Exception:
                authority = None
            if authority is None:
                continue
            exact = LeaveOneOutVariantAuthority.model_validate(authority)
            if (
                exact.parent_ref != candidate.reference
                or exact.variant_ref != variant.reference
                or exact.content_ref != variant.content_ref
                or exact.authority_manifest_ref != variant.manifest_ref
            ):
                raise RetrievalCoordinatorError(
                    "RETRIEVAL_LOO_AUTHORITY_CLOSURE_INVALID"
                )
            previous = authorities.setdefault(key, exact)
            if previous != exact:
                raise RetrievalCoordinatorError(
                    "RETRIEVAL_LOO_AUTHORITY_CLOSURE_INVALID"
                )
        return authorities, expected

    @staticmethod
    def _exclusion_status(
        candidate: CandidateRef,
        loo_authorities: Mapping[
            tuple[str, int, str], LeaveOneOutVariantAuthority
        ],
        expected_loo_refs: set[tuple[str, int, str]],
    ) -> tuple[ClientExclusionStatus, LeaveOneOutVariantAuthority | None]:
        provenance = candidate.provenance
        if provenance.provenance_scope == "global_source":
            return "not_applicable", None
        if provenance.provenance_scope == "client_private":
            return "current_subject_private", None
        key = _ref_key(candidate.reference)
        authority = loo_authorities.get(key)
        if authority is not None:
            return "leave_one_subject_out_applied", authority
        if key in expected_loo_refs:
            raise RetrievalCoordinatorError("RETRIEVAL_LOO_AUTHORITY_CLOSURE_MISSING")
        return "no_subject_contribution", None

    @staticmethod
    def _independent_source_count(provenance: Provenance) -> int:
        if provenance.provenance_scope in {"global_source", "mixed"}:
            return len(provenance.source_ids)
        return 0


__all__ = [
    "AuthoritySnapshotRepository",
    "CandidateSemantics",
    "CandidateSemanticsResolver",
    "RetrievalCoordinator",
    "RetrievalCoordinatorError",
    "RetrievalCoordinatorResult",
    "RetrievalArtifactGate",
    "RetrievalObjectPublisher",
    "RetrievalRequest",
    "TokenCounter",
]
