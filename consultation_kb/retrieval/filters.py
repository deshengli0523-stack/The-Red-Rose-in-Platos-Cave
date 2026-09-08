"""Deterministic, body-free candidate filtering."""

from __future__ import annotations

from collections import Counter
import re
from typing import Literal, Protocol, TypeAlias

from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)
from consultation_kb.models.cases import LeaveOneOutVariantAuthority
from consultation_kb.models.cases import assert_shared_text_safe

from .contracts import (
    CandidateMetadata,
    CandidateRef,
    DeniedReason,
    ExclusionProof,
    ExclusionProofPublisher,
    FilterCapabilityBinding,
    FilterDecision,
    LeaveOneOutVariant,
    candidate_set_sha256,
    capability_sha256,
)


CandidateAuthorityStatus: TypeAlias = Literal["visible", "unauthorized", "tombstoned"]
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")


def assert_case_index_text_safe(candidate: CandidateRef, text: str) -> None:
    """Reject unsafe case-derived text before it reaches any scoring channel.

    Contributor identifiers are intentionally retained only in governed,
    body-free metadata so deterministic leave-one-client-out filtering can run
    before a resolver opens bytes.  They must never become lexical tokens,
    embedding input, graph statement text, or reranker input.
    """

    value = CandidateRef.model_validate(candidate)
    if type(text) is not str or not text.strip():
        raise ValueError("CASE_INDEX_TEXT_REQUIRED")
    if value.provenance.provenance_scope not in {"case_derived", "mixed"}:
        return
    if _CLIENT_ID_RE.search(text) or any(
        client_id in text for client_id in value.provenance.case_contributor_client_ids
    ):
        raise ValueError("CASE_INDEX_TEXT_CONTAINS_CLIENT_ID")
    try:
        assert_shared_text_safe(text)
    except ValueError:
        raise ValueError("CASE_INDEX_TEXT_UNSAFE") from None


class AuthoritySnapshotStale(RuntimeError):
    def __init__(self) -> None:
        super().__init__("AUTHORITY_SNAPSHOT_STALE")


class CandidateAuthorityGuard(Protocol):
    """Live metadata-only authority checks shared by filter and resolver."""

    def assert_snapshot_current(
        self, snapshot: AuthoritativeFilterSnapshot
    ) -> None: ...

    def candidate_status(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus: ...

    def assert_binding_current(
        self,
        binding: FilterCapabilityBinding,
    ) -> None: ...

    def assert_candidate_binding_visible(
        self,
        candidate: CandidateRef,
        binding: FilterCapabilityBinding,
    ) -> None: ...


class LeaveOneOutAuthorityVerifier(Protocol):
    """Verify that a replacement came from one exact approved LOO mapping.

    Candidate metadata is not authority.  Implementations must resolve the
    canonical mapping/proof from the live authority store and bind the exact
    parent, excluded client, variant, content, manifest, and authority epoch.
    """

    def is_exact_approved_variant(
        self,
        *,
        original: CandidateRef,
        variant: LeaveOneOutVariant,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> bool: ...

    def resolve_exact_approved_variant(
        self,
        *,
        original: CandidateRef,
        variant: LeaveOneOutVariant,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> LeaveOneOutVariantAuthority | None: ...

    def is_exact_active_closure(
        self,
        *,
        mapping_ref: VersionRef,
        parent_ref: VersionRef,
        variant_ref: VersionRef,
        authority_manifest_ref: VersionRef,
        provenance_ref: VersionRef,
    ) -> bool: ...


class ContributorIdentityHasher(Protocol):
    """Derive the non-reversible alias used in global case candidates."""

    def pseudonymous_client_id(self, client_id: str) -> str: ...


def is_current_client_contributor(
    current_client_id: str,
    candidate: CandidateRef,
    *,
    contributor_identity_hasher: ContributorIdentityHasher | None,
) -> bool | None:
    """Match one contributor using the candidate's declared identity scheme.

    ``None`` is the fail-closed result for an HMAC-bound candidate when the
    invocation does not have the exact contributor hasher.  Keeping this logic
    in one function prevents filtering, evidence projection, and generation
    proof code from silently disagreeing about the current subject.
    """

    contributors = candidate.provenance.case_contributor_client_ids
    if candidate.metadata.contributor_identity_scheme == "direct_v1":
        return current_client_id in contributors
    if contributor_identity_hasher is None:
        return None
    try:
        alias = contributor_identity_hasher.pseudonymous_client_id(
            current_client_id
        )
    except Exception:
        return None
    return alias in contributors


class StaticAuthorityGuard:
    """Small deterministic guard useful for offline builders and tests."""

    def __init__(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        *,
        tombstoned_ids: frozenset[str] = frozenset(),
    ) -> None:
        self._snapshot = snapshot
        self._tombstoned = tombstoned_ids

    def assert_snapshot_current(
        self, snapshot: AuthoritativeFilterSnapshot
    ) -> None:
        if snapshot != self._snapshot:
            raise AuthoritySnapshotStale

    def candidate_status(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        self.assert_snapshot_current(snapshot)
        if candidate.reference.object_id in self._tombstoned:
            return "tombstoned"
        if candidate.reference.object_id not in snapshot.allowed_ref_ids:
            return "unauthorized"
        return "visible"

    def assert_binding_current(self, binding: FilterCapabilityBinding) -> None:
        expected = self._snapshot
        if (
            binding.run_id != expected.run_id
            or binding.global_runtime_epoch != expected.global_runtime_epoch
            or binding.client_runtime_epoch != expected.client_runtime_epoch
            or binding.tombstone_epoch != expected.tombstone_epoch
            or binding.authorization_epoch != expected.authorization_epoch
            or binding.policy_ref != expected.policy_ref
        ):
            raise AuthoritySnapshotStale

    def assert_candidate_binding_visible(
        self,
        candidate: CandidateRef,
        binding: FilterCapabilityBinding,
    ) -> None:
        self.assert_binding_current(binding)
        if self.candidate_status(candidate, self._snapshot) != "visible":
            raise AuthoritySnapshotStale


class CandidateFilter:
    """Apply every deterministic gate before a body resolver can be called."""

    def __init__(
        self,
        authority_guard: CandidateAuthorityGuard,
        *,
        proof_publisher: ExclusionProofPublisher | None = None,
        leave_one_out_verifier: LeaveOneOutAuthorityVerifier | None = None,
        contributor_identity_hasher: ContributorIdentityHasher | None = None,
    ) -> None:
        self._authority = authority_guard
        self._proof_publisher = proof_publisher
        self._leave_one_out = leave_one_out_verifier
        self._contributor_hasher = contributor_identity_hasher

    def filter(
        self,
        scope: RetrievalScope,
        candidates: tuple[CandidateRef, ...],
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> FilterDecision:
        if type(candidates) is not tuple:
            raise TypeError("CANDIDATE_TUPLE_REQUIRED")
        self._authority.assert_snapshot_current(authority_snapshot)

        allowed_unbound: list[CandidateRef] = []
        denied: Counter[DeniedReason] = Counter()
        for candidate in candidates:
            if type(candidate) is not CandidateRef or candidate.filter_binding is not None:
                raise TypeError("UNBOUND_CANDIDATE_REQUIRED")
            authority_status = self._authority.candidate_status(
                candidate, authority_snapshot
            )
            if authority_status == "unauthorized":
                denied["not_authorized"] += 1
                continue
            if authority_status == "tombstoned":
                denied["tombstoned"] += 1
                continue

            reason = self._scope_or_use_reason(scope, candidate)
            if reason is not None:
                denied[reason] += 1
                continue
            reason = self._review_reason(scope, candidate.metadata)
            if reason is not None:
                denied[reason] += 1
                continue
            reason = self._validity_reason(scope, candidate.metadata)
            if reason is not None:
                denied[reason] += 1
                continue
            if candidate.metadata.sensitivity > scope.maximum_sensitivity:
                denied["sensitivity_denied"] += 1
                continue

            replacement, reason = self._case_provenance_decision(
                scope,
                candidate,
                authority_snapshot,
            )
            if reason is not None:
                denied[reason] += 1
                continue
            allowed_unbound.append(candidate if replacement is None else replacement)

        unbound = tuple(allowed_unbound)
        decision_sha256 = capability_sha256(authority_snapshot, unbound)
        binding = FilterCapabilityBinding(
            run_id=authority_snapshot.run_id,
            global_runtime_epoch=authority_snapshot.global_runtime_epoch,
            client_runtime_epoch=authority_snapshot.client_runtime_epoch,
            tombstone_epoch=authority_snapshot.tombstone_epoch,
            authorization_epoch=authority_snapshot.authorization_epoch,
            policy_ref=authority_snapshot.policy_ref,
            decision_sha256=decision_sha256,
        )
        allowed = tuple(
            candidate.model_copy(update={"filter_binding": binding})
            for candidate in unbound
        )
        proof = ExclusionProof(
            run_id=authority_snapshot.run_id,
            policy_ref=authority_snapshot.policy_ref,
            input_count=len(candidates),
            allowed_count=len(allowed),
            denied_count=len(candidates) - len(allowed),
            candidate_ids_sha256=candidate_set_sha256(candidates),
            reasons=dict(denied),
        )
        proof_ref = (
            None
            if self._proof_publisher is None
            else self._proof_publisher.publish(proof)
        )
        return FilterDecision(
            allowed=allowed,
            proof=proof,
            exclusion_proof_ref=proof_ref,
        )

    @staticmethod
    def _scope_or_use_reason(
        scope: RetrievalScope,
        candidate: CandidateRef,
    ) -> DeniedReason | None:
        provenance = candidate.provenance
        if provenance.provenance_scope == "client_private":
            if (
                provenance.private_owner_client_id != scope.current_client_id
                or candidate.channel not in {"profile", "client_history"}
            ):
                return "scope_denied"
            if "case_example" in scope.allowed_uses:
                return "use_denied"
        elif provenance.private_owner_client_id is not None:
            return "scope_denied"

        if not scope.allowed_uses or not scope.allowed_uses <= candidate.metadata.allowed_uses:
            return "use_denied"
        return None

    @staticmethod
    def _review_reason(
        scope: RetrievalScope,
        metadata: CandidateMetadata,
    ) -> DeniedReason | None:
        if metadata.review_status != "approved" or metadata.approved_at > scope.known_at:
            return "review_not_approved"
        return None

    @staticmethod
    def _validity_reason(
        scope: RetrievalScope,
        metadata: CandidateMetadata,
    ) -> DeniedReason | None:
        if metadata.effective_from is not None and metadata.effective_from > scope.effective_at:
            return "not_yet_effective"
        if metadata.effective_to is not None and metadata.effective_to <= scope.effective_at:
            return "expired"
        if metadata.review_due_at is not None and metadata.review_due_at <= scope.known_at:
            return "review_overdue"
        return None

    def _case_provenance_decision(
        self,
        scope: RetrievalScope,
        candidate: CandidateRef,
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> tuple[CandidateRef | None, DeniedReason | None]:
        is_contributor = self._is_current_client_contributor(scope, candidate)
        if is_contributor is None:
            return None, "leave_one_out_ineligible"
        if not is_contributor:
            return None, None
        variant = candidate.metadata.leave_one_out
        if variant is None:
            return None, "source_client_excluded"
        verifier = self._leave_one_out
        if verifier is None:
            return None, "leave_one_out_ineligible"
        try:
            exact_approved = verifier.is_exact_approved_variant(
                original=candidate,
                variant=variant,
                scope=scope,
                authority_snapshot=authority_snapshot,
            )
        except Exception:
            exact_approved = False
        if exact_approved is not True:
            return None, "leave_one_out_ineligible"
        replacement = self._from_leave_one_out(candidate, variant)
        replacement_contains_client = self._is_current_client_contributor(
            scope,
            replacement,
        )
        if (
            replacement_contains_client is not False
            or variant.source_count < candidate.metadata.minimum_leave_one_out_sources
            or self._authority.candidate_status(
                replacement,
                authority_snapshot,
            )
            != "visible"
        ):
            return None, "leave_one_out_ineligible"
        reason = self._scope_or_use_reason(scope, replacement)
        if reason is None:
            reason = self._review_reason(scope, replacement.metadata)
        if reason is None:
            reason = self._validity_reason(scope, replacement.metadata)
        if reason is None and replacement.metadata.sensitivity > scope.maximum_sensitivity:
            reason = "sensitivity_denied"
        return (replacement, None) if reason is None else (None, "leave_one_out_ineligible")

    def _is_current_client_contributor(
        self,
        scope: RetrievalScope,
        candidate: CandidateRef,
    ) -> bool | None:
        return is_current_client_contributor(
            scope.current_client_id,
            candidate,
            contributor_identity_hasher=self._contributor_hasher,
        )

    @staticmethod
    def _from_leave_one_out(
        original: CandidateRef,
        variant: LeaveOneOutVariant,
    ) -> CandidateRef:
        metadata = CandidateMetadata(
            manifest_ref=variant.manifest_ref,
            review_status=variant.review_status,
            allowed_uses=variant.allowed_uses,
            approved_at=variant.approved_at,
            effective_from=variant.effective_from,
            effective_to=variant.effective_to,
            review_due_at=variant.review_due_at,
            sensitivity=variant.sensitivity,
            source_grade=variant.source_grade,
            framework_priority=variant.framework_priority,
            empirical_support=variant.empirical_support,
            source_count=variant.source_count,
            minimum_leave_one_out_sources=original.metadata.minimum_leave_one_out_sources,
            contributor_identity_scheme=(
                original.metadata.contributor_identity_scheme
            ),
            source_lineage_hashes=variant.source_lineage_hashes,
            media_type=variant.media_type,
            size_bytes=variant.size_bytes,
            leave_one_out=None,
        )
        return CandidateRef(
            reference=variant.reference,
            content_ref=variant.content_ref,
            object_type=variant.object_type,
            channel=original.channel,
            metadata=metadata,
            provenance=variant.provenance,
            location=variant.location,
            freshness=variant.freshness,
            score=original.score,
            score_components=original.score_components,
        )


__all__ = [
    "AuthoritySnapshotStale",
    "CandidateAuthorityGuard",
    "CandidateAuthorityStatus",
    "CandidateFilter",
    "ContributorIdentityHasher",
    "LeaveOneOutAuthorityVerifier",
    "StaticAuthorityGuard",
    "assert_case_index_text_safe",
    "is_current_client_contributor",
]
