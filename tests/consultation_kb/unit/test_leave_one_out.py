from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import cast

import pytest

from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    descriptor_sha256,
)
from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.leave_one_out import (
    LeaveOneOutAuthorityRepository,
    LeaveOneOutBuilder,
    LeaveOneOutError,
)
from consultation_kb.archive.provenance import (
    CaseContributionAuthority,
    CaseContributorHasher,
    CaseProvenanceService,
    IndependentEvidenceAuthority,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.cases import (
    CaseArtifactKind,
    CaseContribution,
    CaseProvenanceRecord,
    IndependentEvidence,
    LeaveOneOutBuildResult,
    LeaveOneOutDraft,
    LeaveOneOutVariantAuthority,
    RegeneratedCaseArtifact,
    leave_one_out_authority_payload,
    leave_one_out_draft_payload,
    regenerated_case_request_payload,
    version_ref_key,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import ApprovalReceipt, DraftDescriptor
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.approval_support import TestProtector


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
REGENERATED_TEXT = (
    "Several independent sources support a reviewed communication pattern."
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ids() -> IdFactory:
    counter = iter(range(30000, 60000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, seed: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=_digest(seed),
    )


class _AuthorityRepository:
    def __init__(self) -> None:
        self.cases: dict[tuple[object, ...], CaseContributionAuthority] = {}
        self.evidence: dict[tuple[object, ...], IndependentEvidenceAuthority] = {}

    def authorize_case(self, value: CaseContribution) -> None:
        exact = CaseContribution.model_validate(value)
        self.cases[
            (
                version_ref_key(exact.case_ref),
                version_ref_key(exact.source_provenance_ref),
                version_ref_key(exact.authorization_ref),
            )
        ] = CaseContributionAuthority(exact)

    def authorize_evidence(self, value: IndependentEvidence) -> None:
        exact = IndependentEvidence.model_validate(value)
        self.evidence[
            (
                version_ref_key(exact.evidence_ref),
                version_ref_key(exact.source_provenance_ref),
            )
        ] = IndependentEvidenceAuthority(exact)

    def resolve_case_contribution(
        self,
        *,
        case_ref: VersionRef,
        source_provenance_ref: VersionRef,
        authorization_ref: VersionRef,
    ) -> CaseContributionAuthority | None:
        return self.cases.get(
            (
                version_ref_key(case_ref),
                version_ref_key(source_provenance_ref),
                version_ref_key(authorization_ref),
            )
        )

    def resolve_independent_evidence(
        self,
        *,
        evidence_ref: VersionRef,
        source_provenance_ref: VersionRef,
    ) -> IndependentEvidenceAuthority | None:
        return self.evidence.get(
            (
                version_ref_key(evidence_ref),
                version_ref_key(source_provenance_ref),
            )
        )


def _service(
    ids: IdFactory,
    rule: VersionRef,
    authority: _AuthorityRepository,
    *additional_rules: VersionRef,
) -> CaseProvenanceService:
    return CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=_ref(ids, "case_provenance_policy", "manifest"),
        approved_derivation_rules=(rule, *additional_rules),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )


def _case_root(
    ids: IdFactory,
    service: CaseProvenanceService,
    authority: _AuthorityRepository,
    rule: VersionRef,
    label: str,
) -> CaseProvenanceRecord:
    case_ref = _ref(ids, "case", f"case-{label}")
    contribution = CaseContribution(
        case_ref=case_ref,
        source_provenance_ref=_ref(
            ids, "case_source_provenance", f"source-{label}"
        ),
        contributor_client_hashes=frozenset({_digest(f"subject-{label}")}),
        authorization_ref=_ref(ids, "case_authorization", f"auth-{label}"),
        allowed_uses=frozenset({"answer_support", "pattern_derivation"}),
        source_grade="K1",
        source_lineage_sha256=_digest(f"lineage-{label}"),
    )
    authority.authorize_case(contribution)
    return service.root_case(
        case_ref,
        contribution,
        derivation_rule_ref=rule,
    )


def _pattern(
    ids: IdFactory,
    service: CaseProvenanceService,
    authority: _AuthorityRepository,
    rule: VersionRef,
    labels: str,
    *,
    parent_content_sha256: str | None = None,
) -> tuple[CaseProvenanceRecord, tuple[CaseProvenanceRecord, ...]]:
    roots = tuple(
        _case_root(ids, service, authority, rule, label) for label in labels
    )
    pattern_ref = _ref(ids, "case_pattern", f"pattern-{labels}")
    if parent_content_sha256 is not None:
        pattern_ref = pattern_ref.model_copy(
            update={"content_sha256": parent_content_sha256}
        )
    pattern = service.propagate(
        pattern_ref,
        "case_pattern",
        roots,
        derivation_rule_ref=rule,
    )
    return pattern, roots


class _TrustedRegenerator:
    def __init__(
        self,
        ids: IdFactory,
        *,
        text: str = REGENERATED_TEXT,
        case_refs_override: tuple[VersionRef, ...] | None = None,
        source_refs_override: tuple[VersionRef, ...] | None = None,
        rule_override: VersionRef | None = None,
        corrupt_proof: bool = False,
    ) -> None:
        self.ids = ids
        self.text = text
        self.case_refs_override = case_refs_override
        self.source_refs_override = source_refs_override
        self.rule_override = rule_override
        self.corrupt_proof = corrupt_proof

    def regenerate(
        self,
        *,
        parent_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        regeneration_rule_ref: VersionRef,
        input_case_refs: tuple[VersionRef, ...],
        input_independent_source_refs: tuple[VersionRef, ...],
        operation_idempotency_key: str | None,
    ) -> RegeneratedCaseArtifact:
        del operation_idempotency_key
        case_refs = (
            input_case_refs
            if self.case_refs_override is None
            else self.case_refs_override
        )
        source_refs = (
            input_independent_source_refs
            if self.source_refs_override is None
            else self.source_refs_override
        )
        rule = (
            regeneration_rule_ref
            if self.rule_override is None
            else self.rule_override
        )
        digest = text_sha256(self.text)
        variant_ref = VersionRef(
            object_id=self.ids.object_id(artifact_kind),
            version=1,
            content_sha256=digest,
        )
        content_ref = VersionRef(
            object_id=self.ids.object_id("case_content"),
            version=1,
            content_sha256=digest,
        )
        request_sha256 = canonical_sha256(
            regenerated_case_request_payload(
                parent_ref=parent_ref,
                variant_ref=variant_ref,
                content_ref=content_ref,
                regeneration_rule_ref=rule,
                input_case_refs=case_refs,
                input_independent_source_refs=source_refs,
                rendered_text_sha256=digest,
            )
        )
        proof_ref = VersionRef(
            object_id=self.ids.object_id("case_regeneration_proof"),
            version=1,
            content_sha256=request_sha256,
        )
        artifact: object = {
            "parent_ref": parent_ref,
            "variant_ref": variant_ref,
            "content_ref": content_ref,
            "regeneration_rule_ref": rule,
            "input_case_refs": case_refs,
            "input_independent_source_refs": source_refs,
            "rendered_text": self.text,
            "rendered_text_sha256": digest,
            "regeneration_request_sha256": request_sha256,
            "regeneration_proof_ref": proof_ref,
        }
        if self.corrupt_proof:
            artifact = {**cast(dict[str, object], artifact), "regeneration_request_sha256": "f" * 64}
        return RegeneratedCaseArtifact.model_validate(artifact)


class _ApprovalVerifier:
    def __init__(self) -> None:
        self.ticket: ApprovalExecutionTicket | None = None
        self.approval_ref: VersionRef | None = None

    def authorize(
        self,
        ticket: ApprovalExecutionTicket,
        approval_ref: VersionRef,
    ) -> None:
        self.ticket = ticket
        self.approval_ref = approval_ref

    def verify_leave_one_out_approval(
        self,
        *,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
    ) -> VersionRef | None:
        if self.ticket == ticket and ticket.descriptor == descriptor:
            return self.approval_ref
        return None


def _ticket(
    ids: IdFactory,
    descriptor: DraftDescriptor,
    *,
    seed: str = "approved",
) -> ApprovalExecutionTicket:
    receipt = ApprovalReceipt(
        request_id=ids.object_id("approval_request"),
        descriptor_sha256=descriptor_sha256(descriptor),
        approver_role="primary_counselor",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=f"nonce-{seed}",
        provider_id="test-review-agent",
        signature=f"signature-{seed}",
    )
    return ApprovalExecutionTicket(
        operation_id=ids.object_id("publication_operation"),
        target_scope_hash=_digest("target-scope"),
        descriptor=descriptor,
        receipt=receipt,
        issuance_signature=_digest(f"issuance-{seed}"),
    )


def _builder(
    ids: IdFactory,
    service: CaseProvenanceService,
    *,
    regenerator: _TrustedRegenerator | None = None,
    verifier: _ApprovalVerifier | None = None,
) -> LeaveOneOutBuilder:
    return LeaveOneOutBuilder(
        id_factory=ids,
        provenance_service=service,
        regenerator=regenerator or _TrustedRegenerator(ids),
        approval_verifier=verifier,
    )


def _rehash_loo_draft(
    draft: LeaveOneOutDraft,
    **updates: object,
) -> LeaveOneOutDraft:
    values = dict(draft.__dict__)
    values.update(updates)
    untrusted = LeaveOneOutDraft.model_construct(**values)
    digest = canonical_sha256(
        leave_one_out_draft_payload(
            draft_id=untrusted.draft_ref.object_id,
            version=untrusted.draft_ref.version,
            artifact_kind=untrusted.artifact_kind,
            parent_ref=untrusted.parent_ref,
            parent_provenance_ref=untrusted.parent_provenance_ref,
            excluded_client_hash=untrusted.excluded_client_hash,
            variant_ref=untrusted.variant_ref,
            variant_provenance_ref=untrusted.variant_provenance_ref,
            content_ref=untrusted.content_ref,
            regeneration_rule_ref=untrusted.regeneration_rule_ref,
            regeneration_request_sha256=untrusted.regeneration_request_sha256,
            regeneration_proof_ref=untrusted.regeneration_proof_ref,
            remaining_case_count=untrusted.remaining_case_count,
            remaining_contributor_count=untrusted.remaining_contributor_count,
            remaining_independent_evidence_count=(
                untrusted.remaining_independent_evidence_count
            ),
            remaining_independent_source_count=(
                untrusted.remaining_independent_source_count
            ),
            minimum_independent_source_count=(
                untrusted.minimum_independent_source_count
            ),
            source_grade=untrusted.source_grade,
            provenance_scope=untrusted.provenance_scope,
            eligible_for_approval=untrusted.eligible_for_approval,
            ineligibility_reason=untrusted.ineligibility_reason,
        )
    )
    return LeaveOneOutDraft.model_validate(
        {
            **untrusted.model_dump(mode="python"),
            "draft_ref": untrusted.draft_ref.model_copy(
                update={"content_sha256": digest}
            ),
            "draft_sha256": digest,
        }
    )


def test_build_result_rejects_rehashed_source_count_and_eligibility_forgery() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "ab")
    result = _builder(ids, service).build(
        parent,
        excluded_client_hash=_digest("subject-a"),
        minimum_independent_source_count=2,
    )
    assert result.draft.remaining_independent_source_count == 1
    assert result.draft.eligible_for_approval is False

    forged_draft = _rehash_loo_draft(
        result.draft,
        remaining_independent_source_count=2,
        eligible_for_approval=True,
        ineligibility_reason=None,
    )
    with pytest.raises(ValueError, match="LOO draft source count binding mismatch"):
        forged_result = dict(result.__dict__)
        forged_result["draft"] = forged_draft
        LeaveOneOutBuildResult.model_validate(forged_result)


def test_build_result_rejects_rehashed_cross_parent_draft() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "abc")
    result = _builder(ids, service).build(
        parent,
        excluded_client_hash=_digest("subject-a"),
    )
    forged_draft = _rehash_loo_draft(
        result.draft,
        parent_ref=_ref(ids, "case_pattern", "unrelated-parent"),
        parent_provenance_ref=_ref(
            ids, "case_provenance", "unrelated-parent-provenance"
        ),
    )

    with pytest.raises(ValueError, match="LOO draft parent binding mismatch"):
        forged_result = dict(result.__dict__)
        forged_result["draft"] = forged_draft
        LeaveOneOutBuildResult.model_validate(forged_result)


def test_leave_one_out_regenerates_from_b_and_c_and_binds_exact_authority() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    source_authority = _AuthorityRepository()
    service = _service(ids, rule, source_authority)
    parent, _roots = _pattern(ids, service, source_authority, rule, "abc")
    verifier = _ApprovalVerifier()
    builder = _builder(ids, service, verifier=verifier)

    result = builder.build(
        parent,
        excluded_client_hash=_digest("subject-a"),
        minimum_independent_source_count=2,
    )
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    uses = frozenset({"answer_support"})
    descriptor = builder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    ticket = _ticket(ids, descriptor)
    approval_ref = _approval_binding_ref(ticket)
    verifier.authorize(ticket, approval_ref)
    authority = builder.approve(
        result,
        approval_ticket=ticket,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )

    assert result.draft.eligible_for_approval is True
    assert result.draft.source_grade == "K3"
    assert result.draft.remaining_independent_source_count == 2
    assert _digest("subject-a") not in (
        result.variant_provenance.contributor_client_hashes
    )
    assert authority.variant_ref == result.regeneration.variant_ref
    assert authority.regeneration_proof_ref == (
        result.regeneration.regeneration_proof_ref
    )
    assert authority.approval_ref == approval_ref
    assert authority.approval_descriptor_sha256 == ticket.descriptor_sha256


def test_single_client_case_cannot_be_forged_as_leave_one_out() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "a")

    with pytest.raises(LeaveOneOutError, match="LOO_NO_REMAINING_EVIDENCE"):
        _builder(ids, service).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )

    with pytest.raises(ValueError, match="contributor hash closure mismatch"):
        parent.model_copy(update={"contributor_client_hashes": frozenset()})


def test_one_remaining_client_cannot_keep_k3_or_be_approved() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "ab")
    builder = _builder(ids, service)

    result = builder.build(
        parent,
        excluded_client_hash=_digest("subject-a"),
        minimum_independent_source_count=2,
    )

    assert result.draft.eligible_for_approval is False
    assert result.draft.source_grade == "K1"
    assert result.draft.ineligibility_reason == "insufficient_independent_sources"
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    descriptor = builder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=frozenset({"answer_support"}),
    )
    with pytest.raises(LeaveOneOutError, match="LOO_VARIANT_NOT_ELIGIBLE"):
        builder.approve(
            result,
            approval_ticket=_ticket(ids, descriptor),
            authority_manifest_ref=manifest_ref,
            allowed_uses=frozenset({"answer_support"}),
        )


def test_trusted_regenerator_output_must_use_exact_remaining_case_set() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, roots = _pattern(ids, service, authority, rule, "abc")
    regenerator = _TrustedRegenerator(
        ids,
        case_refs_override=tuple(root.artifact_ref for root in roots),
    )

    with pytest.raises(LeaveOneOutError, match="CASE_INPUT_MISMATCH"):
        _builder(ids, service, regenerator=regenerator).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )


def test_regeneration_must_use_the_exact_parent_rule_version() -> None:
    ids = _ids()
    parent_rule = _ref(ids, "case_derivation_rule", "rule-v1")
    other_rule = _ref(ids, "case_derivation_rule", "rule-v2")
    authority = _AuthorityRepository()
    service = _service(ids, parent_rule, authority, other_rule)
    parent, _ = _pattern(ids, service, authority, parent_rule, "abc")

    with pytest.raises(LeaveOneOutError, match="RULE_VERSION_MISMATCH"):
        _builder(
            ids,
            service,
            regenerator=_TrustedRegenerator(ids, rule_override=other_rule),
        ).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )


def test_independent_non_case_evidence_survives_without_a_case_support() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    independent = IndependentEvidence(
        evidence_ref=_ref(ids, "claim", "independent-c1"),
        source_provenance_ref=_ref(ids, "source_provenance", "lineage"),
        source_grade="C1",
        allowed_uses=frozenset({"answer_support", "pattern_derivation"}),
        source_lineage_sha256=_digest("independent-source"),
    )
    authority.authorize_evidence(independent)
    parent = service.propagate(
        _ref(ids, "claim", "mixed-claim"),
        "claim",
        (case_a,),
        derivation_rule_ref=rule,
        independent_evidence=(independent,),
    )

    result = _builder(ids, service).build(
        parent,
        excluded_client_hash=_digest("subject-a"),
        minimum_independent_source_count=1,
    )

    assert result.draft.eligible_for_approval is True
    assert result.variant_provenance.provenance_scope == "global_source"
    assert result.variant_provenance.source_grade == "C1"
    assert result.variant_provenance.case_contributions == ()
    assert result.variant_provenance.independent_evidence == (independent,)


def test_parent_identical_bytes_are_rejected_even_with_a_new_object_id() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(
        ids,
        service,
        authority,
        rule,
        "abc",
        parent_content_sha256=text_sha256(REGENERATED_TEXT),
    )

    with pytest.raises(LeaveOneOutError, match="LOO_REGENERATION_PROOF_INVALID"):
        _builder(ids, service).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )


def test_regeneration_proof_mutation_is_rejected() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "abc")

    with pytest.raises(LeaveOneOutError, match="LOO_REGENERATION_PROOF_INVALID"):
        _builder(
            ids,
            service,
            regenerator=_TrustedRegenerator(ids, corrupt_proof=True),
        ).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )


def test_random_or_missing_p1_authority_cannot_approve_a_variant() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "abc")
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    uses = frozenset({"answer_support"})
    result = _builder(ids, service).build(
        parent,
        excluded_client_hash=_digest("subject-a"),
    )
    descriptor = LeaveOneOutBuilder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    ticket = _ticket(ids, descriptor, seed="untrusted")

    with pytest.raises(LeaveOneOutError, match="LOO_APPROVAL_VERIFIER_REQUIRED"):
        _builder(ids, service).approve(
            result,
            approval_ticket=ticket,
            authority_manifest_ref=manifest_ref,
            allowed_uses=uses,
        )

    with pytest.raises(LeaveOneOutError, match="LOO_APPROVAL_NOT_AUTHORIZED"):
        _builder(ids, service, verifier=_ApprovalVerifier()).approve(
            result,
            approval_ticket=ticket,
            authority_manifest_ref=manifest_ref,
            allowed_uses=uses,
        )


def test_approval_rechecks_variant_source_authority_after_build() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority)
    parent, _ = _pattern(ids, service, authority, rule, "abc")
    verifier = _ApprovalVerifier()
    builder = _builder(ids, service, verifier=verifier)
    result = builder.build(
        parent,
        excluded_client_hash=_digest("subject-a"),
    )
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    uses = frozenset({"answer_support"})
    descriptor = builder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    ticket = _ticket(ids, descriptor, seed="revoked-after-build")
    verifier.authorize(ticket, _approval_binding_ref(ticket))
    revoked = result.variant_provenance.case_contributions[0]
    authority.cases[
        (
            version_ref_key(revoked.case_ref),
            version_ref_key(revoked.source_provenance_ref),
            version_ref_key(revoked.authorization_ref),
        )
    ] = CaseContributionAuthority(revoked, authority_state="revoked")

    with pytest.raises(
        LeaveOneOutError,
        match="CASE_CONTRIBUTION_AUTHORITY_REVOKED",
    ):
        builder.approve(
            result,
            approval_ticket=ticket,
            authority_manifest_ref=manifest_ref,
            allowed_uses=uses,
        )


def _install_loo_backing_rows(
    connection: sqlite3.Connection,
    *,
    result: object,
    authority: object,
    ticket: ApprovalExecutionTicket | None = None,
    approval_request_id: str | None = None,
) -> None:
    from consultation_kb.models.cases import (  # local to keep fixture narrow
        LeaveOneOutBuildResult,
        LeaveOneOutVariantAuthority,
    )

    built = LeaveOneOutBuildResult.model_validate(result)
    approved = LeaveOneOutVariantAuthority.model_validate(authority)
    provenance = built.variant_provenance
    now_text = NOW.isoformat().replace("+00:00", "Z")
    if ticket is not None:
        exact_ticket = ApprovalExecutionTicket.model_validate(ticket)
        nonce_sha256 = _digest(exact_ticket.receipt.nonce)
        connection.execute(
            """
            INSERT INTO approval_requests(
                request_id, descriptor_sha256, descriptor_json,
                diff_object_ref_json, purpose, target_scope_hash, session_id,
                base_version, created_at, expires_at, nonce_sha256,
                nonce_ciphertext, state, provider_event_sha256, confirmed_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 'ISSUED', ?, ?)
            """,
            (
                exact_ticket.request_id,
                exact_ticket.descriptor_sha256,
                json.dumps(
                    exact_ticket.descriptor.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    approved.draft_ref.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                exact_ticket.descriptor.purpose,
                exact_ticket.target_scope_hash,
                exact_ticket.descriptor.base_version,
                (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                exact_ticket.receipt.expires_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                nonce_sha256,
                b"test-protected-nonce",
                _digest("provider-event"),
                now_text,
            ),
        )
        connection.execute(
            """
            INSERT INTO approval_receipts(
                request_id, receipt_json, operation_id, confirmed_at,
                acknowledged_at, state
            ) VALUES (?, 'opaque-test-receipt', ?, ?, NULL, 'ISSUED')
            """,
            (exact_ticket.request_id, exact_ticket.operation_id, now_text),
        )
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                exact_ticket.operation_id,
                exact_ticket.request_id,
                exact_ticket.descriptor_sha256,
                exact_ticket.descriptor.draft_sha256,
                exact_ticket.descriptor.base_version,
                exact_ticket.target_scope_hash,
                nonce_sha256,
            ),
        )
        connection.execute(
            """
            UPDATE approval_executions
               SET state = 'APPLIED', applied_commit_version = ?, applied_at = ?
             WHERE operation_id = ? AND state = 'CLAIMED'
            """,
            (
                approved.approval_ref.version,
                now_text,
                exact_ticket.operation_id,
            ),
        )
    operation_id = "publication_operation_018f0000-0000-7000-8000-000000009001"
    manifest_approval_request_id = (
        approval_request_id
        if approval_request_id is not None
        else (
            ticket.request_id
            if ticket is not None
            else "approval_request_018f0000-0000-7000-8000-000000009002"
        )
    )
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version,
            approval_request_id, descriptor_sha256, state,
            required_manifests_json, required_manifest_count,
            verified_manifest_count, created_at
        ) VALUES (?, 'case_publish', 1, ?, ?, 'ACTIVE', '[]', 0, 0, ?)
        """,
        (
            operation_id,
            manifest_approval_request_id,
            approved.approval_descriptor_sha256,
            now_text,
        ),
    )
    connection.execute(
        """
        INSERT INTO artifact_manifests(
            manifest_id, operation_id, artifact_key, artifact_kind,
            source_version, manifest_sha256, state, verified,
            created_at, verified_at
        ) VALUES (?, ?, 'loo-authority', 'case', '1', ?, 'ACTIVE', 1, ?, ?)
        """,
        (
            approved.authority_manifest_ref.object_id,
            operation_id,
            approved.authority_manifest_ref.content_sha256,
            now_text,
            now_text,
        ),
    )
    connection.execute(
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            provenance.provenance_ref.object_id,
            provenance.provenance_ref.version,
            provenance.provenance_ref.content_sha256,
            provenance.artifact_ref.object_id,
            provenance.artifact_ref.version,
            provenance.artifact_ref.content_sha256,
            provenance.artifact_kind,
            json.dumps(sorted(provenance.contributor_client_hashes), separators=(",", ":")),
            len(provenance.independent_evidence),
            provenance.derivation_rule_ref.object_id,
            provenance.derivation_rule_ref.version,
            provenance.derivation_rule_ref.content_sha256,
            provenance.policy_manifest_ref.object_id,
            provenance.policy_manifest_ref.version,
            provenance.policy_manifest_ref.content_sha256,
            provenance.source_grade,
            provenance.provenance_scope,
            json.dumps(sorted(provenance.allowed_uses), separators=(",", ":")),
            None
            if provenance.effective_to is None
            else provenance.effective_to.isoformat().replace("+00:00", "Z"),
            json.dumps(provenance.model_dump(mode="json"), sort_keys=True),
            provenance.closure_sha256,
        ),
    )


def _approval_binding_ref(ticket: ApprovalExecutionTicket) -> VersionRef:
    return VersionRef(
        object_id=ticket.operation_id,
        version=1,
        content_sha256=canonical_sha256(
            {
                "approved_at": ticket.receipt.approved_at.isoformat(),
                "descriptor_base_version": ticket.descriptor.base_version,
                "descriptor_sha256": ticket.descriptor_sha256,
                "draft_sha256": ticket.descriptor.draft_sha256,
                "expires_at": ticket.receipt.expires_at.isoformat(),
                "nonce_sha256": _digest(ticket.receipt.nonce),
                "operation_id": ticket.operation_id,
                "request_id": ticket.request_id,
                "schema_version": "loo_approval_execution_binding.v1",
                "target_scope_hash": ticket.target_scope_hash,
            }
        ),
    )


def _issued_guard(
    connection: sqlite3.Connection,
    ids: IdFactory,
    descriptor: DraftDescriptor,
) -> tuple[ApprovalExecutionGuard, ApprovalExecutionTicket]:
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="loo-review-agent",
        clock=FixedClock(NOW),
    )
    service = ApprovalService(
        connection,
        provider=LocalHmacApprovalVerifier(
            secret=b"p" * 32,
            provider_id="loo-review-agent",
        ),
        protector=TestProtector(),
        clock=FixedClock(NOW),
        id_factory=ids,
        target_scope_hash=_digest("target-scope"),
        vault_id="loo-test-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="loo-target-writer",
        ),
        nonce_source=lambda size: bytes(range(size)),
    )
    request = service.request(
        descriptor,
        diff_object_ref=_ref(ids, "approval_diff", "loo-diff"),
    )
    service.confirm(
        signer.confirm(service.challenge_for_review(request.request_id))
    )
    ticket = service.issue_for_execution(
        request.request_id,
        descriptor,
        operation_id=ids.object_id("publication_operation"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="loo-target-writer",
        ),
        clock=FixedClock(NOW),
    )
    return guard, ticket


def _atomic_loo_harness(
    tmp_path: Path,
    *,
    database_name: str,
) -> tuple[
    sqlite3.Connection,
    LeaveOneOutAuthorityRepository,
    ApprovalExecutionGuard,
    ApprovalExecutionTicket,
    LeaveOneOutBuildResult,
    LeaveOneOutVariantAuthority,
]:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    source_authority = _AuthorityRepository()
    service = _service(ids, rule, source_authority)
    parent, _ = _pattern(ids, service, source_authority, rule, "abc")
    verifier = _ApprovalVerifier()
    builder = _builder(ids, service, verifier=verifier)
    result = builder.build(
        parent,
        excluded_client_hash=_digest("subject-a"),
    )
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    uses = frozenset({"answer_support"})
    descriptor = builder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    connection = connect_database(tmp_path / database_name, "writer")
    MigrationRunner.for_scope(connection, "global").apply()
    guard, ticket = _issued_guard(connection, ids, descriptor)
    verifier.authorize(ticket, _approval_binding_ref(ticket))
    authority = builder.approve(
        result,
        approval_ticket=ticket,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    _install_loo_backing_rows(
        connection,
        result=result,
        authority=authority,
        approval_request_id=ticket.request_id,
    )
    return (
        connection,
        LeaveOneOutAuthorityRepository(connection),
        guard,
        ticket,
        result,
        authority,
    )


def _remap_authority(
    ids: IdFactory,
    authority: LeaveOneOutVariantAuthority,
) -> LeaveOneOutVariantAuthority:
    mapping_id = ids.object_id("case_leave_one_out_variant")
    mapping_sha256 = canonical_sha256(
        leave_one_out_authority_payload(
            mapping_id=mapping_id,
            version=1,
            parent_ref=authority.parent_ref,
            excluded_client_hash=authority.excluded_client_hash,
            variant_ref=authority.variant_ref,
            content_ref=authority.content_ref,
            authority_manifest_ref=authority.authority_manifest_ref,
            provenance_ref=authority.provenance_ref,
            approval_ref=authority.approval_ref,
            approval_version=authority.approval_version,
            approval_descriptor_sha256=(
                authority.approval_descriptor_sha256
            ),
            draft_ref=authority.draft_ref,
            regeneration_rule_ref=authority.regeneration_rule_ref,
            regeneration_request_sha256=(
                authority.regeneration_request_sha256
            ),
            regeneration_proof_ref=authority.regeneration_proof_ref,
            allowed_uses=authority.allowed_uses,
            approved_at=authority.approved_at,
            effective_to=authority.effective_to,
            source_grade=authority.source_grade,
            remaining_independent_source_count=(
                authority.remaining_independent_source_count
            ),
            minimum_independent_source_count=(
                authority.minimum_independent_source_count
            ),
        )
    )
    return authority.model_copy(
        update={
            "mapping_ref": VersionRef(
                object_id=mapping_id,
                version=1,
                content_sha256=mapping_sha256,
            ),
            "mapping_sha256": mapping_sha256,
        }
    )


def test_guarded_prepare_rolls_back_claim_and_business_rows_on_callback_failure(
    tmp_path: Path,
) -> None:
    connection, repository, guard, ticket, result, authority = (
        _atomic_loo_harness(tmp_path, database_name="atomic-failure.sqlite3")
    )
    try:
        def fail_after_business_write(phase: str) -> None:
            assert phase == "after_business_write"
            raise RuntimeError("synthetic callback failure")

        with pytest.raises(RuntimeError, match="synthetic callback failure"):
            repository.prepare_guarded(
                authority,
                regeneration=result.regeneration,
                approval_ticket=ticket,
                approval_guard=guard,
                created_at=NOW,
                fault_hook=fail_after_business_write,
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM case_regeneration_proofs"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM case_leave_one_out_variants"
        ).fetchone() == (0,)

        prepared, proof = repository.prepare_guarded(
            authority,
            regeneration=result.regeneration,
            approval_ticket=ticket,
            approval_guard=guard,
            created_at=NOW,
        )
        assert prepared == authority
        assert proof.state == "applied"
    finally:
        connection.close()


def test_applied_execution_without_mapping_cannot_be_replayed_to_backfill(
    tmp_path: Path,
) -> None:
    connection, repository, guard, ticket, result, authority = (
        _atomic_loo_harness(tmp_path, database_name="orphan-applied.sqlite3")
    )
    try:
        guard.apply_in_transaction(ticket, ticket.descriptor, lambda _connection: None)
        with pytest.raises(
            LeaveOneOutError,
            match="LOO_APPROVAL_MAPPING_MISSING",
        ):
            repository.prepare_guarded(
                authority,
                regeneration=result.regeneration,
                approval_ticket=ticket,
                approval_guard=guard,
                created_at=NOW,
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM case_regeneration_proofs"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM case_leave_one_out_variants"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_applied_execution_replay_accepts_exact_and_rejects_a_different_mapping(
    tmp_path: Path,
) -> None:
    connection, repository, guard, ticket, result, authority = (
        _atomic_loo_harness(tmp_path, database_name="wrong-replay.sqlite3")
    )
    try:
        prepared, _proof = repository.prepare_guarded(
            authority,
            regeneration=result.regeneration,
            approval_ticket=ticket,
            approval_guard=guard,
            created_at=NOW,
        )
        assert prepared == authority
        replayed, replay_proof = repository.prepare_guarded(
            authority,
            regeneration=result.regeneration,
            approval_ticket=ticket,
            approval_guard=guard,
            created_at=NOW,
        )
        assert replayed == authority
        assert replay_proof.state == "applied"
        assert connection.execute(
            "SELECT COUNT(*) FROM case_leave_one_out_variants"
        ).fetchone() == (1,)
        wrong_mapping = _remap_authority(_ids(), authority)
        with pytest.raises(
            LeaveOneOutError,
            match="LOO_APPROVAL_MAPPING_MISSING",
        ):
            repository.prepare_guarded(
                wrong_mapping,
                regeneration=result.regeneration,
                approval_ticket=ticket,
                approval_guard=guard,
                created_at=NOW,
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM case_leave_one_out_variants"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_global_approval_execution_must_begin_claimed(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "execution-guard.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval execution must begin claimed",
        ):
            connection.execute(
                """
                INSERT INTO approval_executions(
                    operation_id, request_id, descriptor_sha256, draft_sha256,
                    descriptor_base_version, target_scope_hash, nonce_sha256,
                    state, applied_commit_version, applied_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?, 'APPLIED', 1, ?)
                """,
                (
                    "publication_operation_018f0000-0000-7000-8000-000000008001",
                    "approval_request_018f0000-0000-7000-8000-000000008002",
                    _digest("descriptor"),
                    _digest("draft"),
                    _digest("scope"),
                    _digest("nonce"),
                    NOW.isoformat().replace("+00:00", "Z"),
                ),
            )
    finally:
        connection.close()


def test_repository_rejects_missing_durable_p1_execution(tmp_path: Path) -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    source_authority = _AuthorityRepository()
    service = _service(ids, rule, source_authority)
    parent, _ = _pattern(ids, service, source_authority, rule, "abc")
    verifier = _ApprovalVerifier()
    builder = _builder(ids, service, verifier=verifier)
    result = builder.build(
        parent,
        excluded_client_hash=_digest("subject-a"),
    )
    manifest_ref = _ref(ids, "case_authority_manifest", "authority")
    uses = frozenset({"answer_support"})
    descriptor = builder.approval_descriptor(
        result,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    ticket = _ticket(ids, descriptor, seed="missing-durable-execution")
    verifier.authorize(ticket, _approval_binding_ref(ticket))
    authority = builder.approve(
        result,
        approval_ticket=ticket,
        authority_manifest_ref=manifest_ref,
        allowed_uses=uses,
    )
    connection = connect_database(tmp_path / "missing-approval.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        _install_loo_backing_rows(
            connection,
            result=result,
            authority=authority,
        )
        with pytest.raises(
            LeaveOneOutError,
            match="LOO_ATOMIC_PREPARE_REQUIRED",
        ):
            LeaveOneOutAuthorityRepository(connection).prepare(
                authority,
                regeneration=result.regeneration,
                created_at=NOW,
            )
    finally:
        connection.close()


def test_loo_authority_repository_persists_exact_proof_and_state(
    tmp_path: Path,
) -> None:
    ids = _ids()
    connection, repository, guard, ticket, result, authority = (
        _atomic_loo_harness(tmp_path, database_name="global.sqlite3")
    )
    try:
        prepared, proof = repository.prepare_guarded(
            authority,
            regeneration=result.regeneration,
            approval_ticket=ticket,
            approval_guard=guard,
            created_at=NOW,
        )
        assert prepared == authority
        assert proof.state == "applied"
        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval executions cannot be deleted",
        ):
            connection.execute(
                "DELETE FROM approval_executions WHERE operation_id = ?",
                (authority.approval_ref.object_id,),
            )
        assert repository.activate(authority.mapping_ref) == authority
        assert connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (1, 0)
        assert repository.activate(authority.mapping_ref) == authority
        assert connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (1, 0)
        assert repository.resolve_active(
            parent_ref=authority.parent_ref,
            excluded_client_hash=authority.excluded_client_hash,
        ) == authority
        connection.execute(
            """
            INSERT INTO runtime_epochs(
                epoch, operation_id, state, created_at, activated_at
            ) VALUES (1, ?, 'ACTIVE', ?, ?)
            """,
            (
                "publication_operation_018f0000-0000-7000-8000-000000009001",
                NOW.isoformat().replace("+00:00", "Z"),
                NOW.isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.execute(
            """
            INSERT INTO active_artifacts(
                epoch, artifact_key, manifest_id, activated_at
            ) VALUES (1, 'loo-authority', ?, ?)
            """,
            (
                authority.authority_manifest_ref.object_id,
                NOW.isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.execute(
            """
            INSERT INTO artifact_members(
                manifest_id, ordinal, object_type, object_id, object_sha256,
                source_version, source_lineage_json, media_type, size_bytes
            ) VALUES (?, 0, 'case_content', ?, ?, '1', '[]', 'text/plain', ?)
            """,
            (
                authority.authority_manifest_ref.object_id,
                authority.content_ref.object_id,
                authority.content_ref.content_sha256,
                len(result.regeneration.rendered_text.encode("utf-8")),
            ),
        )

        from consultation_kb.retrieval.contracts import LeaveOneOutVariant
        from consultation_kb.retrieval.loo_authority import (
            SqliteLeaveOneOutAuthorityVerifier,
        )
        from tests.consultation_kb.retrieval_support import (
            CLIENT_A,
            CLIENT_B,
            candidate,
            case_provenance,
            scope,
            snapshot,
        )

        class _MappedHasher(CaseContributorHasher):
            def hash_client_id(self, client_id: str) -> str:
                assert client_id == CLIENT_A
                return authority.excluded_client_hash

        base_original = candidate(
            910,
            provenance=case_provenance(910, CLIENT_A, CLIENT_B),
            object_type="case_pattern",
        )
        original = base_original.model_copy(
            update={
                "reference": authority.parent_ref,
                "content_ref": authority.parent_ref,
            }
        )
        base_variant_provenance = case_provenance(911, CLIENT_B)
        variant_provenance = base_variant_provenance.model_copy(
            update={"derivation_rule_ref": authority.regeneration_rule_ref}
        )
        variant = LeaveOneOutVariant(
            reference=authority.variant_ref,
            content_ref=authority.content_ref,
            object_type="case_pattern",
            manifest_ref=authority.authority_manifest_ref,
            review_status="approved",
            allowed_uses=authority.allowed_uses,
            approved_at=authority.approved_at,
            effective_from=authority.approved_at,
            effective_to=authority.effective_to,
            sensitivity=1,
            source_grade=authority.source_grade,
            source_count=authority.remaining_independent_source_count,
            provenance=variant_provenance,
            location=original.location.model_copy(
                update={"anchor_refs": (authority.content_ref,)}
            ),
            freshness=original.freshness,
            source_lineage_hashes=(),
            media_type="text/plain",
            size_bytes=len(result.regeneration.rendered_text.encode("utf-8")),
        )
        live_snapshot = snapshot(original, candidate(912))
        live_snapshot = live_snapshot.model_copy(
            update={
                "authorization_epoch": 1,
                "allowed_ref_ids": frozenset(
                    {
                        original.reference.object_id,
                        variant.reference.object_id,
                    }
                )
            }
        )
        authority_verifier = SqliteLeaveOneOutAuthorityVerifier(
            connection,
            contributor_hasher=_MappedHasher(
                hash_key=b"mapped-test-hasher-key-material-32bytes"
            ),
        )
        assert authority_verifier.is_exact_approved_variant(
            original=original,
            variant=variant,
            scope=scope(client_id=CLIENT_A),
            authority_snapshot=live_snapshot,
        )
        client_tombstone_snapshot = live_snapshot.model_copy(
            update={"tombstone_epoch": 7}
        )
        assert authority_verifier.is_exact_approved_variant(
            original=original,
            variant=variant,
            scope=scope(client_id=CLIENT_A),
            authority_snapshot=client_tombstone_snapshot,
        )
        connection.execute(
            "UPDATE artifact_manifests SET source_version = '2' WHERE manifest_id = ?",
            (authority.authority_manifest_ref.object_id,),
        )
        assert not authority_verifier.is_exact_approved_variant(
            original=original,
            variant=variant,
            scope=scope(client_id=CLIENT_A),
            authority_snapshot=client_tombstone_snapshot,
        )
        connection.execute(
            "UPDATE artifact_manifests SET source_version = '1' WHERE manifest_id = ?",
            (authority.authority_manifest_ref.object_id,),
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval execution transition invalid",
        ):
            connection.execute(
                """
                UPDATE approval_executions
                   SET state = 'CLAIMED', applied_commit_version = NULL,
                       applied_at = NULL
                 WHERE operation_id = ?
                """,
                (authority.approval_ref.object_id,),
            )
        assert authority_verifier.is_exact_approved_variant(
            original=original,
            variant=variant,
            scope=scope(client_id=CLIENT_A),
            authority_snapshot=client_tombstone_snapshot,
        )
        assert not authority_verifier.is_exact_approved_variant(
            original=original,
            variant=variant.model_copy(
                update={"content_ref": _ref(ids, "case_content", "forged")}
            ),
            scope=scope(client_id=CLIENT_A),
            authority_snapshot=live_snapshot,
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE case_regeneration_proofs SET request_sha256 = ?",
                ("f" * 64,),
            )
        repository.revoke(authority.mapping_ref)
        assert connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (2, 1)
        assert connection.execute(
            """
            SELECT COUNT(*) FROM security_invalidation_events
             WHERE upstream_id = ?
            """,
            (authority.mapping_ref.object_id,),
        ).fetchone() == (3,)
        repository.revoke(authority.mapping_ref)
        assert connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (2, 1)
        assert repository.resolve_active(
            parent_ref=authority.parent_ref,
            excluded_client_hash=authority.excluded_client_hash,
        ) is None
    finally:
        connection.close()

def test_leave_one_out_rejects_parent_made_stale_by_rule_rotation() -> None:
    ids = _ids()
    old_rule = _ref(ids, "case_derivation_rule", "rule-v1")
    new_rule = _ref(ids, "case_derivation_rule", "rule-v2")
    authority = _AuthorityRepository()
    old_service = _service(ids, old_rule, authority)
    parent, _ = _pattern(ids, old_service, authority, old_rule, "abc")
    current_service = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=old_service.policy_manifest_ref,
        approved_derivation_rules=(new_rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    with pytest.raises(LeaveOneOutError, match="CASE_DERIVATION_RULE_STALE"):
        _builder(ids, current_service).build(
            parent,
            excluded_client_hash=_digest("subject-a"),
        )
