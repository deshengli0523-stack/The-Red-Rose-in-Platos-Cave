from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import PassageAnchor, deterministic_object_id
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
)
from consultation_kb.retrieval.contracts import (
    CandidateMetadata,
    CandidateRef,
    FilterCapabilityBinding,
    ResolvedEvidence,
    canonical_json_bytes,
)
from consultation_kb.retrieval.evidence_pack import (
    ArtifactVersionMismatch,
    C1PolicyVocabulary,
    CandidateEvidenceInput,
    ClosureRequirement,
    EvidenceLocatorRenderer,
    EvidencePackBuilder,
    EvidencePackInputs,
    RootManifestSet,
    ScopeAwareEvidenceClosureVerifier,
)


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12


def _ids(index: int = 1) -> IdFactory:
    return IdFactory(FixedClock(NOW), lambda: index)


def _ref(kind: str, index: int, *, data: bytes | None = None, version: int = 1) -> VersionRef:
    payload = data if data is not None else f"{kind}:{index}".encode()
    return VersionRef(
        object_id=_ids(index).object_id(kind),
        version=version,
        content_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _snapshot() -> tuple[AuthoritativeFilterSnapshot, VersionRef]:
    value = AuthoritativeFilterSnapshot(
        run_id=_ids(100).uuid7(),
        global_runtime_epoch=7,
        client_runtime_epoch=5,
        tombstone_epoch=11,
        authorization_epoch=13,
        allowed_ref_ids=frozenset({_ids(200).object_id("evidence")}),
        policy_ref=_ref("authority_policy", 101),
        created_at=NOW,
    )
    payload = canonical_json_bytes(value.model_dump(mode="json"))
    return value, _ref("authority_snapshot", 102, data=payload)


def _scope() -> RetrievalScope:
    return RetrievalScope(
        current_client_id=CLIENT_A,
        allowed_uses=frozenset({"consultation_answer"}),
        maximum_sensitivity=2,
        effective_at=NOW,
        known_at=NOW,
    )


def _locator(index: int) -> EvidenceLocator:
    return EvidenceLocator(
        locator_kind="source_line_span",
        anchor_refs=(_ref("source_anchor", index),),
        display_locator="lines:2-3",
        locator_policy_ref=_ref("locator_policy", index + 1),
    )


def _freshness(index: int) -> EvidenceFreshnessSnapshot:
    return EvidenceFreshnessSnapshot(
        status="current",
        evaluated_at=NOW,
        source_observed_at=NOW - timedelta(days=1),
        last_reviewed_at=NOW,
        review_due_at=NOW + timedelta(days=30),
        policy_ref=_ref("freshness_policy", index),
    )


def _provenance_ref(provenance: Provenance, index: int) -> VersionRef:
    payload = canonical_json_bytes(provenance.model_dump(mode="json"))
    return _ref("provenance", index, data=payload)


def _candidate_input(
    snapshot: AuthoritativeFilterSnapshot,
    *,
    scope_kind: str = "global_source",
    current_client_in_case: bool = False,
    exclusion_status: str | None = None,
    loo_authority_refs: tuple[VersionRef, VersionRef, VersionRef, VersionRef] | None = None,
) -> CandidateEvidenceInput:
    body = b"approved synthetic evidence"
    evidence_ref = VersionRef(
        object_id=next(iter(snapshot.allowed_ref_ids)),
        version=1,
        content_sha256=hashlib.sha256(b"evidence-object").hexdigest(),
    )
    content_ref = _ref("passage", 201, data=body)
    derivation = _ref("derivation_rule", 202)
    if scope_kind == "global_source":
        provenance = Provenance(
            source_ids=frozenset({_ids(203).object_id("source")}),
            passage_ids=frozenset({content_ref.object_id}),
            provenance_scope="global_source",
            derivation_rule_ref=derivation,
        )
        channel = "wiki"
        status = "not_applicable"
        independent = 1
    elif scope_kind == "client_private":
        provenance = Provenance(
            passage_ids=frozenset({content_ref.object_id}),
            client_ids=frozenset({CLIENT_A}),
            provenance_scope="client_private",
            private_owner_client_id=CLIENT_A,
            derivation_rule_ref=derivation,
        )
        channel = "client_history"
        status = "current_subject_private"
        independent = 0
    else:
        contributor = CLIENT_A if current_client_in_case else CLIENT_B
        provenance = Provenance(
            passage_ids=frozenset({content_ref.object_id}),
            case_ids=frozenset({_ids(204).object_id("case")}),
            client_ids=frozenset({contributor}),
            provenance_scope="case_derived",
            case_contributor_client_ids=frozenset({contributor}),
            derivation_rule_ref=derivation,
        )
        channel = "case"
        status = exclusion_status or "no_subject_contribution"
        independent = 0
    manifest = (
        _ref("manifest", 205, version=3)
        if loo_authority_refs is None
        else loo_authority_refs[2]
    )
    candidate = CandidateRef(
        reference=evidence_ref,
        content_ref=content_ref,
        object_type="evidence",
        channel=channel,
        metadata=CandidateMetadata(
            manifest_ref=manifest,
            review_status="approved",
            allowed_uses=frozenset({"consultation_answer"}),
            approved_at=NOW,
            sensitivity=1,
            source_grade="T1",
            source_count=1,
            media_type="text/plain",
            size_bytes=len(body),
        ),
        provenance=provenance,
        location=_locator(206),
        freshness=_freshness(207),
        score=0.75,
        filter_binding=FilterCapabilityBinding(
            run_id=snapshot.run_id,
            global_runtime_epoch=snapshot.global_runtime_epoch,
            client_runtime_epoch=snapshot.client_runtime_epoch,
            tombstone_epoch=snapshot.tombstone_epoch,
            authorization_epoch=snapshot.authorization_epoch,
            policy_ref=snapshot.policy_ref,
            decision_sha256="d" * 64,
        ),
    )
    return CandidateEvidenceInput(
        evidence_id=evidence_ref.object_id,
        resolved=ResolvedEvidence(candidate=candidate, body=body),
        provenance_ref=_provenance_ref(provenance, 208),
        independent_source_count=independent,
        client_exclusion_status=status,
        leave_one_out_variant_ref=(
            evidence_ref if status == "leave_one_subject_out_applied" else None
        ),
        leave_one_out_mapping_ref=(
            None if loo_authority_refs is None else loo_authority_refs[0]
        ),
        leave_one_out_parent_ref=(
            None if loo_authority_refs is None else loo_authority_refs[1]
        ),
        leave_one_out_authority_manifest_ref=(
            None if loo_authority_refs is None else loo_authority_refs[2]
        ),
        leave_one_out_provenance_ref=(
            None if loo_authority_refs is None else loo_authority_refs[3]
        ),
        current_client_is_case_contributor=(
            current_client_in_case if scope_kind == "case_derived" else None
        ),
        framework_priority="normal",
        empirical_support="empirically_supported",
        score=0.75,
        supports_evidence_ids=(),
        contradicts_evidence_ids=(),
    )


class RecordingClosureVerifier:
    def __init__(self) -> None:
        self.requirements: tuple[ClosureRequirement, ...] = ()
        self.vocabulary: C1PolicyVocabulary | None = None

    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None:
        self.requirements = requirements
        self.vocabulary = vocabulary


class RecordingVersionGate:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def verify(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
    ) -> None:
        del snapshot, roots
        self.calls += 1
        if self.fail:
            raise ArtifactVersionMismatch


def _inputs(
    snapshot: AuthoritativeFilterSnapshot,
    snapshot_ref: VersionRef,
    candidate: CandidateEvidenceInput,
) -> EvidencePackInputs:
    roots = RootManifestSet(
        catalog_version=3,
        wiki_manifest_ref=candidate.resolved.candidate.metadata.manifest_ref,
        lexical_manifest_ref=_ref("manifest", 301, version=3),
        vector_manifest_ref=_ref("manifest", 302, version=3),
        graph_manifest_ref=_ref("manifest", 303, version=3),
    )
    c1 = C1ApplicabilityDecision(
        status="applicable",
        revision=_ref("theory_revision", 304),
        scope_policy_ref=_ref("scope_policy", 305),
        matched_rule_ids=("relationship_context",),
        missing_context_fields=(),
        effective_status="active",
        empirical_support="case_supported",
        conflict_evidence_ids=(),
    )
    return EvidencePackInputs(
        scope=_scope(),
        authority_snapshot=snapshot,
        authority_snapshot_ref=snapshot_ref,
        client_snapshot_ref=_ref("client_snapshot", 306),
        temporary_fact_refs=(_ref("temporary_fact", 307),),
        supporting=(candidate,),
        contradicting=(),
        unresolved_conflict_refs=(),
        c1_applicability=c1,
        c1_policy_vocabulary=C1PolicyVocabulary(
            scope_policy_ref=c1.scope_policy_ref,
            approved_rule_ids=frozenset({"relationship_context"}),
            approved_context_fields=frozenset({"relationship_stage"}),
        ),
        exclusion_proof_ref=_ref("exclusion_proof", 308),
        roots=roots,
        reranker_descriptor_ref=_ref("reranker_descriptor", 309),
    )


def test_builder_projects_full_provenance_and_emits_complete_safe_closure() -> None:
    snapshot, snapshot_ref = _snapshot()
    candidate = _candidate_input(snapshot)
    closure = RecordingClosureVerifier()
    gate = RecordingVersionGate()

    result = EvidencePackBuilder(closure_verifier=closure, version_gate=gate).build(
        _inputs(snapshot, snapshot_ref, candidate)
    )

    assert gate.calls == 1
    assert result.canonical_sha256 == hashlib.sha256(
        canonical_json_bytes(result.pack.model_dump(mode="json"))
    ).hexdigest()
    safe_json = result.pack.model_dump_json()
    assert CLIENT_A not in safe_json
    assert CLIENT_B not in safe_json
    assert "allowed_ref_ids" not in safe_json
    view = result.pack.supporting[0].provenance
    assert view.source_count == 1
    assert view.passage_count == 1
    assert view.client_exclusion_status == "not_applicable"
    roles = {item.role for item in closure.requirements}
    assert {
        "authority_snapshot",
        "authority_policy",
        "client_snapshot",
        "temporary_fact",
        "candidate_object",
        "candidate_text",
        "candidate_anchor",
        "locator_policy",
        "freshness_policy",
        "candidate_provenance",
        "derivation_rule",
        "candidate_manifest",
        "c1_revision",
        "c1_scope_policy",
        "exclusion_proof",
        "wiki_manifest",
        "lexical_manifest",
        "vector_manifest",
        "graph_manifest",
        "reranker_descriptor",
    } <= roles


def test_builder_allows_current_subject_history_without_leaking_owner() -> None:
    snapshot, snapshot_ref = _snapshot()
    candidate = _candidate_input(snapshot, scope_kind="client_private")
    result = EvidencePackBuilder(
        closure_verifier=RecordingClosureVerifier(),
        version_gate=RecordingVersionGate(),
    ).build(_inputs(snapshot, snapshot_ref, candidate))

    packed = result.pack.supporting[0]
    assert packed.channel == "client_history"
    assert packed.provenance.client_exclusion_status == "current_subject_private"
    assert CLIENT_A not in result.pack.model_dump_json()


def test_builder_rejects_current_subject_case_even_if_caller_claims_no_contribution() -> None:
    snapshot, snapshot_ref = _snapshot()
    candidate = _candidate_input(
        snapshot,
        scope_kind="case_derived",
        current_client_in_case=True,
        exclusion_status="no_subject_contribution",
    )
    with pytest.raises(ValueError, match="CURRENT_SUBJECT_CASE_NOT_EXCLUDED"):
        EvidencePackBuilder(
            closure_verifier=RecordingClosureVerifier(),
            version_gate=RecordingVersionGate(),
        ).build(_inputs(snapshot, snapshot_ref, candidate))


def test_builder_loo_closure_contains_exact_mapping_manifest_and_provenance() -> None:
    snapshot, snapshot_ref = _snapshot()
    mapping_ref = _ref("case_leave_one_out_variant", 401)
    parent_ref = _ref("case_pattern", 402)
    manifest_ref = _ref("case_loo_manifest", 403, version=3)
    provenance_ref = _ref("case_provenance", 404)
    candidate = _candidate_input(
        snapshot,
        scope_kind="case_derived",
        exclusion_status="leave_one_subject_out_applied",
        loo_authority_refs=(
            mapping_ref,
            parent_ref,
            manifest_ref,
            provenance_ref,
        ),
    )
    closure = RecordingClosureVerifier()

    EvidencePackBuilder(
        closure_verifier=closure,
        version_gate=RecordingVersionGate(),
    ).build(_inputs(snapshot, snapshot_ref, candidate))

    refs_by_role = {item.role: item.reference for item in closure.requirements}
    assert refs_by_role["leave_one_out_mapping"] == mapping_ref
    assert refs_by_role["leave_one_out_parent"] == parent_ref
    assert refs_by_role["leave_one_out_authority_manifest"] == manifest_ref
    assert refs_by_role["leave_one_out_provenance"] == provenance_ref


def test_builder_rejects_c1_rule_or_context_outside_approved_vocabulary() -> None:
    snapshot, snapshot_ref = _snapshot()
    candidate = _candidate_input(snapshot)
    inputs = _inputs(snapshot, snapshot_ref, candidate)
    bad = inputs.model_copy(
        update={
            "c1_policy_vocabulary": C1PolicyVocabulary(
                scope_policy_ref=inputs.c1_applicability.scope_policy_ref,
                approved_rule_ids=frozenset({"different_rule"}),
                approved_context_fields=frozenset(),
            )
        }
    )
    with pytest.raises(ValueError, match="C1_POLICY_MEMBERSHIP_INVALID"):
        EvidencePackBuilder(
            closure_verifier=RecordingClosureVerifier(),
            version_gate=RecordingVersionGate(),
        ).build(bad)


def test_builder_fails_closed_before_pack_when_root_gate_fails() -> None:
    snapshot, snapshot_ref = _snapshot()
    with pytest.raises(ArtifactVersionMismatch, match="ARTIFACT_VERSION_MISMATCH"):
        EvidencePackBuilder(
            closure_verifier=RecordingClosureVerifier(),
            version_gate=RecordingVersionGate(fail=True),
        ).build(_inputs(snapshot, snapshot_ref, _candidate_input(snapshot)))


def test_builder_rejects_snapshot_or_body_not_bound_to_exact_hash() -> None:
    snapshot, snapshot_ref = _snapshot()
    candidate = _candidate_input(snapshot)
    bad_snapshot = snapshot_ref.model_copy(update={"content_sha256": "f" * 64})
    builder = EvidencePackBuilder(
        closure_verifier=RecordingClosureVerifier(),
        version_gate=RecordingVersionGate(),
    )
    with pytest.raises(ValueError, match="AUTHORITY_SNAPSHOT_HASH_MISMATCH"):
        builder.build(_inputs(snapshot, bad_snapshot, candidate))

    forged = candidate.model_copy(
        update={
            "resolved": ResolvedEvidence(
                candidate=candidate.resolved.candidate,
                body=b"forged body",
            )
        }
    )
    with pytest.raises(ValueError, match="RESOLVED_BODY_HASH_MISMATCH"):
        builder.build(_inputs(snapshot, snapshot_ref, forged))


@pytest.mark.parametrize(
    ("document_type", "locator_kind", "display"),
    [
        ("pdf", "source_page_span", "pages:1:2-2:3"),
        ("docx", "source_paragraph_span", "paragraphs:2-4"),
        ("docx", "source_table_span", "table:1;rows:2-3;columns:1-4"),
        ("txt", "source_line_span", "lines:2-4"),
        ("md", "source_line_span", "lines:2-4"),
        ("csv", "source_table_span", "table:1;rows:2-3;columns:1-4"),
        ("xlsx", "source_sheet_range", "sheet:1;range:A2-D3"),
    ],
)
def test_locator_renderer_accepts_only_document_grammar(
    document_type: str,
    locator_kind: str,
    display: str,
) -> None:
    logical_source = _ids(400).object_id("source")
    path = f"synthetic/{document_type}/{locator_kind}"
    anchor = PassageAnchor(
        passage_id=deterministic_object_id(
            "passage", logical_source, document_type, path
        ),
        logical_source_id=logical_source,
        document_type=document_type,
        structural_path=path,
        locator=EvidenceLocator(
            locator_kind=locator_kind,
            anchor_refs=(_ref("source_anchor", 401),),
            display_locator=display,
            locator_policy_ref=_ref("locator_policy", 402),
        ),
    )
    assert EvidenceLocatorRenderer().render(anchor, review_status="approved") == anchor.locator


def test_locator_renderer_rejects_kind_mismatch_and_unapproved_anchor() -> None:
    logical_source = _ids(410).object_id("source")
    anchor = PassageAnchor(
        passage_id=deterministic_object_id(
            "passage", logical_source, "pdf", "synthetic/pdf"
        ),
        logical_source_id=logical_source,
        document_type="pdf",
        structural_path="synthetic/pdf",
        locator=EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(_ref("source_anchor", 411),),
            display_locator="lines:1-2",
            locator_policy_ref=_ref("locator_policy", 412),
        ),
    )
    renderer = EvidenceLocatorRenderer()
    with pytest.raises(ValueError, match="LOCATOR_DOCUMENT_GRAMMAR_MISMATCH"):
        renderer.render(anchor, review_status="approved")
    with pytest.raises(ValueError, match="PASSAGE_ANCHOR_NOT_APPROVED"):
        renderer.render(anchor, review_status="draft")


def test_pack_hash_is_invariant_to_set_semantic_input_order() -> None:
    snapshot, snapshot_ref = _snapshot()
    first = _inputs(snapshot, snapshot_ref, _candidate_input(snapshot))
    second = first.model_copy(
        update={
            "temporary_fact_refs": tuple(reversed(first.temporary_fact_refs)),
            "unresolved_conflict_refs": tuple(reversed(first.unresolved_conflict_refs)),
        }
    )
    builder = EvidencePackBuilder(
        closure_verifier=RecordingClosureVerifier(),
        version_gate=RecordingVersionGate(),
    )
    assert builder.build(first).canonical_sha256 == builder.build(second).canonical_sha256
    assert json.loads(builder.build(first).pack.model_dump_json())["schema_version"] == "1.0"


class ScopeResolver:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[ClosureRequirement] = []

    def verify_exact(self, requirement: ClosureRequirement) -> None:
        self.calls.append(requirement)
        if self.fail:
            raise LookupError("intentionally indistinguishable")


class VocabularyVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify_vocabulary(self, vocabulary: C1PolicyVocabulary) -> None:
        assert vocabulary.scope_policy_ref.object_id.startswith("scope_policy_")
        self.calls += 1


def test_scope_closure_routes_once_without_alternate_store_fallback() -> None:
    global_scope = ScopeResolver(fail=True)
    client_scope = ScopeResolver()
    session_scope = ScopeResolver()
    run_scope = ScopeResolver()
    vocabulary = VocabularyVerifier()
    verifier = ScopeAwareEvidenceClosureVerifier(
        global_resolver=global_scope,
        client_resolver=client_scope,
        session_resolver=session_scope,
        run_resolver=run_scope,
        vocabulary_verifier=vocabulary,
    )
    requirement = ClosureRequirement(
        role="candidate_text",
        reference=_ref("passage", 900),
        scope="global",
    )
    policy = C1PolicyVocabulary(
        scope_policy_ref=_ref("scope_policy", 901),
        approved_rule_ids=frozenset({"relationship_context"}),
        approved_context_fields=frozenset(),
    )

    with pytest.raises(RuntimeError, match="EVIDENCE_CLOSURE_MISMATCH"):
        verifier.verify((requirement,), vocabulary=policy)

    assert global_scope.calls == [requirement]
    assert client_scope.calls == []
    assert session_scope.calls == []
    assert run_scope.calls == []
    assert vocabulary.calls == 1
