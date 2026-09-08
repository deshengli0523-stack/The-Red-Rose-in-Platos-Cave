from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re

import pytest

from consultation_kb.archive.provenance import (
    CaseContributionAuthority,
    CaseContributorHasher,
    CaseProvenanceError,
    CaseProvenanceService,
    IndependentEvidenceAuthority,
    SourceAuthorityState,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.cases import (
    CaseContribution,
    CaseProvenanceRecord,
    IndependentEvidence,
    case_provenance_payload,
    version_ref_key,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.knowledge._canonical import canonical_sha256


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


class _AuthorityRepository:
    def __init__(self) -> None:
        self._cases: dict[
            tuple[
                tuple[str, int, str],
                tuple[str, int, str],
                tuple[str, int, str],
            ],
            CaseContributionAuthority,
        ] = {}
        self._evidence: dict[
            tuple[tuple[str, int, str], tuple[str, int, str]],
            IndependentEvidenceAuthority,
        ] = {}
        self._provenance: dict[
            tuple[str, int, str],
            CaseProvenanceRecord,
        ] = {}

    def authorize_case(
        self,
        contribution: CaseContribution,
        *,
        state: SourceAuthorityState = "active",
    ) -> None:
        value = CaseContribution.model_validate(contribution)
        self._cases[self._case_key(value)] = CaseContributionAuthority(
            value,
            state,
        )

    def authorize_evidence(
        self,
        evidence: IndependentEvidence,
        *,
        state: SourceAuthorityState = "active",
    ) -> None:
        value = IndependentEvidence.model_validate(evidence)
        self._evidence[self._evidence_key(value)] = IndependentEvidenceAuthority(
            value,
            state,
        )

    def set_case_state(
        self,
        contribution: CaseContribution,
        state: SourceAuthorityState,
    ) -> None:
        self.authorize_case(contribution, state=state)

    def set_evidence_state(
        self,
        evidence: IndependentEvidence,
        state: SourceAuthorityState,
    ) -> None:
        self.authorize_evidence(evidence, state=state)

    def persist_provenance(self, record: CaseProvenanceRecord) -> None:
        value = CaseProvenanceRecord.model_validate(record)
        self._provenance[version_ref_key(value.provenance_ref)] = value

    def resolve_provenance(
        self,
        *,
        provenance_ref: VersionRef,
    ) -> CaseProvenanceRecord | None:
        return self._provenance.get(version_ref_key(provenance_ref))

    def resolve_case_contribution(
        self,
        *,
        case_ref: VersionRef,
        source_provenance_ref: VersionRef,
        authorization_ref: VersionRef,
    ) -> CaseContributionAuthority | None:
        return self._cases.get(
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
        return self._evidence.get(
            (
                version_ref_key(evidence_ref),
                version_ref_key(source_provenance_ref),
            )
        )

    @staticmethod
    def _case_key(
        value: CaseContribution,
    ) -> tuple[
        tuple[str, int, str],
        tuple[str, int, str],
        tuple[str, int, str],
    ]:
        return (
            version_ref_key(value.case_ref),
            version_ref_key(value.source_provenance_ref),
            version_ref_key(value.authorization_ref),
        )

    @staticmethod
    def _evidence_key(
        value: IndependentEvidence,
    ) -> tuple[tuple[str, int, str], tuple[str, int, str]]:
        return (
            version_ref_key(value.evidence_ref),
            version_ref_key(value.source_provenance_ref),
        )


class _SourceOnlyAuthority:
    """Legacy source resolver intentionally lacking provenance resolution."""

    def __init__(self, source: _AuthorityRepository) -> None:
        self._source = source

    def resolve_case_contribution(
        self,
        *,
        case_ref: VersionRef,
        source_provenance_ref: VersionRef,
        authorization_ref: VersionRef,
    ) -> CaseContributionAuthority | None:
        return self._source.resolve_case_contribution(
            case_ref=case_ref,
            source_provenance_ref=source_provenance_ref,
            authorization_ref=authorization_ref,
        )

    def resolve_independent_evidence(
        self,
        *,
        evidence_ref: VersionRef,
        source_provenance_ref: VersionRef,
    ) -> IndependentEvidenceAuthority | None:
        return self._source.resolve_independent_evidence(
            evidence_ref=evidence_ref,
            source_provenance_ref=source_provenance_ref,
        )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ids() -> IdFactory:
    counter = iter(range(10000, 30000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, seed: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=_digest(seed),
    )


def _service(
    ids: IdFactory,
    *rules: VersionRef,
    authority: _AuthorityRepository,
) -> CaseProvenanceService:
    return CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=_ref(ids, "case_provenance_policy", "manifest"),
        approved_derivation_rules=rules,
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
            ids, "case_source_provenance", f"source-provenance-{label}"
        ),
        contributor_client_hashes=frozenset({_digest(f"subject-{label}")}),
        authorization_ref=_ref(ids, "case_authorization", f"authorization-{label}"),
        allowed_uses=frozenset({"answer_support", "pattern_derivation"}),
        source_grade="K1",
        source_lineage_sha256=_digest(f"lineage-{label}"),
    )
    authority.authorize_case(contribution)
    return service.root_case(case_ref, contribution, derivation_rule_ref=rule)


def _rehash_record(
    record: CaseProvenanceRecord,
    **updates: object,
) -> CaseProvenanceRecord:
    values = dict(record.__dict__)
    values.update(updates)
    changed = CaseProvenanceRecord.model_construct(**values)
    closure_sha256 = canonical_sha256(
        case_provenance_payload(
            provenance_id=changed.provenance_ref.object_id,
            version=changed.provenance_ref.version,
            artifact_ref=changed.artifact_ref,
            artifact_kind=changed.artifact_kind,
            parent_provenance_refs=changed.parent_provenance_refs,
            ancestor_artifact_refs=changed.ancestor_artifact_refs,
            case_contributions=changed.case_contributions,
            independent_evidence=changed.independent_evidence,
            contributor_client_hashes=frozenset(
                changed.contributor_client_hashes
            ),
            derivation_rule_ref=changed.derivation_rule_ref,
            policy_manifest_ref=changed.policy_manifest_ref,
            source_grade=changed.source_grade,
            provenance_scope=changed.provenance_scope,
            allowed_uses=frozenset(changed.allowed_uses),
            effective_to=changed.effective_to,
        )
    )
    rebuilt = {
        key: value
        for key, value in changed.__dict__.items()
        if key not in {"provenance_ref", "closure_sha256"}
    }
    return CaseProvenanceRecord(
        **rebuilt,
        provenance_ref=changed.provenance_ref.model_copy(
            update={"content_sha256": closure_sha256}
        ),
        closure_sha256=closure_sha256,
    )


def test_case_to_index_closure_inherits_all_cases_and_hashed_contributors() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    roots = tuple(_case_root(ids, service, authority, rule, label) for label in "abc")

    pattern = service.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        roots,
        derivation_rule_ref=rule,
    )
    claim = service.propagate(
        _ref(ids, "claim", "claim"),
        "claim",
        (pattern,),
        derivation_rule_ref=rule,
    )
    wiki = service.propagate(
        _ref(ids, "wiki_section", "wiki"),
        "wiki_section",
        (claim,),
        derivation_rule_ref=rule,
    )
    edge = service.propagate(
        _ref(ids, "graph_edge", "edge"),
        "graph_edge",
        (wiki,),
        derivation_rule_ref=rule,
    )
    lexical = service.propagate(
        _ref(ids, "lexical_row", "lexical"),
        "lexical_row",
        (edge,),
        derivation_rule_ref=rule,
    )
    vector = service.propagate(
        _ref(ids, "vector_row", "vector"),
        "vector_row",
        (wiki,),
        derivation_rule_ref=rule,
    )

    expected_cases = frozenset(root.artifact_ref for root in roots)
    expected_contributors = frozenset(_digest(f"subject-{label}") for label in "abc")
    assert pattern.source_grade == "K3"
    for artifact in (pattern, claim, wiki, edge, lexical, vector):
        assert (
            frozenset(item.case_ref for item in artifact.case_contributions)
            == expected_cases
        )
        assert artifact.contributor_client_hashes == expected_contributors
        assert artifact.policy_manifest_ref == service.policy_manifest_ref
        serialized = artifact.model_dump_json()
        assert "client_" + "aaaaaaaaaaaa" not in serialized
        assert "client_" + "bbbbbbbbbbbb" not in serialized
        assert "client_" + "cccccccccccc" not in serialized


def test_contributor_hasher_never_exposes_raw_stable_client_id() -> None:
    hasher = CaseContributorHasher(hash_key=b"synthetic-contributor-key-32-bytes!!")

    first = hasher.hash_client_id("client_" + "aaaaaaaaaaaa")
    repeated = hasher.hash_client_id("client_" + "aaaaaaaaaaaa")
    second = hasher.hash_client_id("client_" + "bbbbbbbbbbbb")

    assert first == repeated
    assert first != second
    assert len(first) == 64
    assert "client_" + "aaaaaaaaaaaa" not in first

    first_alias = hasher.pseudonymous_client_id("client_" + "aaaaaaaaaaaa")
    repeated_alias = hasher.pseudonymous_client_id("client_" + "aaaaaaaaaaaa")
    second_alias = hasher.pseudonymous_client_id("client_" + "bbbbbbbbbbbb")

    assert first_alias == repeated_alias
    assert first_alias != second_alias
    assert re.fullmatch(r"client_[a-z2-7]{12}", first_alias)
    assert "aaaaaaaaaaaa" not in first_alias


def test_independent_c1_evidence_is_preserved_in_mixed_closure() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    evidence = IndependentEvidence(
        evidence_ref=_ref(ids, "claim", "c1-claim"),
        source_provenance_ref=_ref(ids, "source_provenance", "c1-provenance"),
        source_grade="C1",
        allowed_uses=frozenset({"answer_support", "pattern_derivation"}),
        source_lineage_sha256=_digest("c1-lineage"),
    )
    authority.authorize_evidence(evidence)

    result = service.propagate(
        _ref(ids, "claim", "mixed-claim"),
        "claim",
        (case_a,),
        derivation_rule_ref=rule,
        independent_evidence=(evidence,),
    )

    assert result.provenance_scope == "mixed"
    assert result.source_grade == "C1"
    assert result.independent_evidence == (evidence,)


def test_unapproved_rule_and_invalid_derivation_path_fail_closed() -> None:
    ids = _ids()
    approved = _ref(ids, "case_derivation_rule", "approved")
    unapproved = _ref(ids, "case_derivation_rule", "unapproved")
    authority = _AuthorityRepository()
    service = _service(ids, approved, authority=authority)
    case_a = _case_root(ids, service, authority, approved, "a")

    with pytest.raises(CaseProvenanceError, match="CASE_DERIVATION_RULE_NOT_APPROVED"):
        service.propagate(
            _ref(ids, "case_pattern", "pattern"),
            "case_pattern",
            (case_a,),
            derivation_rule_ref=unapproved,
        )

    with pytest.raises(CaseProvenanceError, match="DERIVATION_PATH_INVALID"):
        service.propagate(
            _ref(ids, "wiki_section", "wiki"),
            "wiki_section",
            (case_a,),
            derivation_rule_ref=approved,
        )


def test_derivation_rule_version_is_bound_into_each_closure() -> None:
    ids = _ids()
    first_rule = _ref(ids, "case_derivation_rule", "rule-v1")
    second_rule = _ref(ids, "case_derivation_rule", "rule-v2")
    authority = _AuthorityRepository()
    service = _service(ids, first_rule, second_rule, authority=authority)
    roots = tuple(
        _case_root(ids, service, authority, first_rule, label) for label in "ab"
    )
    artifact = _ref(ids, "case_pattern", "pattern")

    first = service.propagate(
        artifact,
        "case_pattern",
        roots,
        derivation_rule_ref=first_rule,
    )
    second = service.propagate(
        artifact,
        "case_pattern",
        roots,
        derivation_rule_ref=second_rule,
    )

    assert first.derivation_rule_ref == first_rule
    assert second.derivation_rule_ref == second_rule
    assert first.closure_sha256 != second.closure_sha256


def test_old_policy_manifest_cannot_be_laundered_into_a_new_downstream_closure() -> (
    None
):
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    old_service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, old_service, authority, rule, "a")
    new_service = _service(ids, rule, authority=authority)

    assert new_service.is_stale(case_a) is True
    with pytest.raises(CaseProvenanceError, match="CASE_PROVENANCE_POLICY_STALE"):
        new_service.propagate(
            _ref(ids, "case_pattern", "new-pattern"),
            "case_pattern",
            (case_a,),
            derivation_rule_ref=rule,
        )


def test_revoked_rule_version_marks_existing_closure_stale() -> None:
    ids = _ids()
    old_rule = _ref(ids, "case_derivation_rule", "rule-v1")
    new_rule = _ref(ids, "case_derivation_rule", "rule-v2")
    authority = _AuthorityRepository()
    old_service = _service(ids, old_rule, authority=authority)
    case_a = _case_root(ids, old_service, authority, old_rule, "a")
    current_service = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=old_service.policy_manifest_ref,
        approved_derivation_rules=(new_rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    assert current_service.is_stale(case_a) is True
    with pytest.raises(CaseProvenanceError, match="CASE_DERIVATION_RULE_STALE"):
        current_service.assert_current(case_a)


def test_same_object_version_with_two_hashes_is_a_provenance_conflict() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    evidence_ref = _ref(ids, "claim", "evidence-v1")
    conflicting_ref = VersionRef(
        object_id=evidence_ref.object_id,
        version=evidence_ref.version,
        content_sha256=_digest("different-bytes-for-v1"),
    )
    first = IndependentEvidence(
        evidence_ref=evidence_ref,
        source_provenance_ref=_ref(ids, "source_provenance", "first"),
        source_grade="C1",
        allowed_uses=frozenset({"answer_support"}),
        source_lineage_sha256=_digest("first-lineage"),
    )
    second = IndependentEvidence(
        evidence_ref=conflicting_ref,
        source_provenance_ref=_ref(ids, "source_provenance", "second"),
        source_grade="C1",
        allowed_uses=frozenset({"answer_support"}),
        source_lineage_sha256=_digest("second-lineage"),
    )
    authority.authorize_evidence(first)
    authority.authorize_evidence(second)

    with pytest.raises(
        CaseProvenanceError,
        match="INDEPENDENT_EVIDENCE_VERSION_CONFLICT",
    ):
        service.propagate(
            _ref(ids, "claim", "derived"),
            "claim",
            (case_a,),
            derivation_rule_ref=rule,
            independent_evidence=(first, second),
        )


def test_missing_authoritative_resolver_rejects_bare_source_dto() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    case_ref = _ref(ids, "case", "case-a")
    contribution = CaseContribution(
        case_ref=case_ref,
        source_provenance_ref=_ref(ids, "case_source_provenance", "source-a"),
        contributor_client_hashes=frozenset({_digest("subject-a")}),
        authorization_ref=_ref(ids, "case_authorization", "authorization-a"),
        allowed_uses=frozenset({"answer_support"}),
        source_grade="K1",
        source_lineage_sha256=_digest("lineage-a"),
    )
    service = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=_ref(ids, "case_provenance_policy", "manifest"),
        approved_derivation_rules=(rule,),
        clock=FixedClock(NOW),
    )

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_SOURCE_AUTHORITY_RESOLVER_REQUIRED",
    ):
        service.root_case(case_ref, contribution, derivation_rule_ref=rule)


@pytest.mark.parametrize(
    "mutation",
    (
        {"source_grade": "K2"},
        {"allowed_uses": frozenset({"answer_support"})},
        {"effective_to": NOW + timedelta(days=30)},
        {"source_lineage_sha256": _digest("forged-lineage")},
    ),
    ids=("grade", "uses", "effective_to", "lineage"),
)
def test_same_refs_cannot_mutate_authoritative_case_fields(
    mutation: dict[str, object],
) -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    root = _case_root(ids, service, authority, rule, "a")
    canonical = root.case_contributions[0]
    forged = canonical.model_copy(update=mutation)

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_CONTRIBUTION_AUTHORITY_MISMATCH",
    ):
        service.root_case(
            root.artifact_ref,
            forged,
            derivation_rule_ref=rule,
        )


def test_same_refs_cannot_self_declare_fake_c1_or_expand_uses() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    canonical = IndependentEvidence(
        evidence_ref=_ref(ids, "claim", "independent-claim"),
        source_provenance_ref=_ref(ids, "source_provenance", "source-record"),
        source_grade="T2",
        allowed_uses=frozenset({"answer_support"}),
        source_lineage_sha256=_digest("authoritative-lineage"),
    )
    authority.authorize_evidence(canonical)
    fake_c1 = canonical.model_copy(update={"source_grade": "C1"})
    expanded = canonical.model_copy(
        update={"allowed_uses": frozenset({"answer_support", "pattern_derivation"})}
    )

    for forged in (fake_c1, expanded):
        with pytest.raises(
            CaseProvenanceError,
            match="INDEPENDENT_EVIDENCE_AUTHORITY_MISMATCH",
        ):
            service.propagate(
                _ref(ids, "claim", "forged-result"),
                "claim",
                (case_a,),
                derivation_rule_ref=rule,
                independent_evidence=(forged,),
            )


@pytest.mark.parametrize("state", ("expired", "revoked"))
def test_expired_or_revoked_parent_source_cannot_propagate(
    state: SourceAuthorityState,
) -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    authority.set_case_state(case_a.case_contributions[0], state)

    with pytest.raises(
        CaseProvenanceError,
        match=f"CASE_CONTRIBUTION_AUTHORITY_{state.upper()}",
    ):
        service.propagate(
            _ref(ids, "case_pattern", f"blocked-{state}"),
            "case_pattern",
            (case_a,),
            derivation_rule_ref=rule,
        )


def test_effective_to_is_checked_even_if_repository_reports_active() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_ref = _ref(ids, "case", "expired-case")
    expired = CaseContribution(
        case_ref=case_ref,
        source_provenance_ref=_ref(ids, "case_source_provenance", "expired"),
        contributor_client_hashes=frozenset({_digest("expired-subject")}),
        authorization_ref=_ref(ids, "case_authorization", "expired-grant"),
        allowed_uses=frozenset({"answer_support"}),
        effective_to=NOW,
        source_grade="K1",
        source_lineage_sha256=_digest("expired-lineage"),
    )
    authority.authorize_case(expired, state="active")

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_CONTRIBUTION_AUTHORITY_EXPIRED",
    ):
        service.root_case(case_ref, expired, derivation_rule_ref=rule)


def test_idempotency_key_replays_exact_record_and_rejects_conflict() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    service = _service(ids, rule, authority=authority)
    case_a = _case_root(ids, service, authority, rule, "a")
    source_a = case_a.case_contributions[0]

    first = service.root_case(
        case_a.artifact_ref,
        source_a,
        derivation_rule_ref=rule,
        operation_idempotency_key="archive.case.publish-001",
    )
    replay = service.root_case(
        case_a.artifact_ref,
        source_a,
        derivation_rule_ref=rule,
        operation_idempotency_key="archive.case.publish-001",
    )
    case_b = _case_root(ids, service, authority, rule, "b")

    assert replay == first
    with pytest.raises(
        CaseProvenanceError,
        match="CASE_PROVENANCE_IDEMPOTENCY_CONFLICT",
    ):
        service.root_case(
            case_b.artifact_ref,
            case_b.case_contributions[0],
            derivation_rule_ref=rule,
            operation_idempotency_key="archive.case.publish-001",
        )


def test_cross_instance_assert_current_resolves_complete_persisted_ancestry() -> (
    None
):
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    writer = _service(ids, rule, authority=authority)
    root = _case_root(ids, writer, authority, rule, "a")
    pattern = writer.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        (root,),
        derivation_rule_ref=rule,
    )
    claim = writer.propagate(
        _ref(ids, "claim", "claim"),
        "claim",
        (pattern,),
        derivation_rule_ref=rule,
    )
    for record in (root, pattern, claim):
        authority.persist_provenance(record)
    reader = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=writer.policy_manifest_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    assert reader.assert_current(claim) == claim


def test_cross_instance_parent_without_provenance_resolver_fails_closed() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    writer = _service(ids, rule, authority=authority)
    root = _case_root(ids, writer, authority, rule, "a")
    pattern = writer.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        (root,),
        derivation_rule_ref=rule,
    )
    reader = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=writer.policy_manifest_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=_SourceOnlyAuthority(authority),
        clock=FixedClock(NOW),
    )

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_PROVENANCE_PARENT_RESOLVER_REQUIRED",
    ):
        reader.assert_current(pattern)


def test_self_hashed_forgery_with_missing_parent_is_not_authority() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    writer = _service(ids, rule, authority=authority)
    root = _case_root(ids, writer, authority, rule, "a")
    pattern = writer.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        (root,),
        derivation_rule_ref=rule,
    )
    forged = _rehash_record(
        pattern,
        parent_provenance_refs=(
            _ref(ids, "case_provenance", "missing-parent"),
        ),
    )
    authority.persist_provenance(forged)
    reader = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=writer.policy_manifest_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_PROVENANCE_PARENT_NOT_FOUND",
    ):
        reader.assert_current(forged)


def test_persisted_parent_kind_hop_is_recursively_rejected() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    writer = _service(ids, rule, authority=authority)
    root = _case_root(ids, writer, authority, rule, "a")
    pattern = writer.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        (root,),
        derivation_rule_ref=rule,
    )
    claim = writer.propagate(
        _ref(ids, "claim", "claim"),
        "claim",
        (pattern,),
        derivation_rule_ref=rule,
    )
    wiki = writer.propagate(
        _ref(ids, "wiki_section", "wiki"),
        "wiki_section",
        (claim,),
        derivation_rule_ref=rule,
    )
    illegal = _rehash_record(
        wiki,
        parent_provenance_refs=(pattern.provenance_ref,),
        ancestor_artifact_refs=(
            root.artifact_ref,
            pattern.artifact_ref,
        ),
    )
    for record in (root, pattern, illegal):
        authority.persist_provenance(record)
    reader = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=writer.policy_manifest_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_PROVENANCE_DERIVATION_PATH_INVALID",
    ):
        reader.assert_current(illegal)


def test_persisted_record_cannot_omit_parent_ancestor_closure() -> None:
    ids = _ids()
    rule = _ref(ids, "case_derivation_rule", "rule-v1")
    authority = _AuthorityRepository()
    writer = _service(ids, rule, authority=authority)
    root = _case_root(ids, writer, authority, rule, "a")
    pattern = writer.propagate(
        _ref(ids, "case_pattern", "pattern"),
        "case_pattern",
        (root,),
        derivation_rule_ref=rule,
    )
    claim = writer.propagate(
        _ref(ids, "claim", "claim"),
        "claim",
        (pattern,),
        derivation_rule_ref=rule,
    )
    incomplete = _rehash_record(
        claim,
        ancestor_artifact_refs=(root.artifact_ref,),
    )
    for record in (root, pattern, incomplete):
        authority.persist_provenance(record)
    reader = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=writer.policy_manifest_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=authority,
        clock=FixedClock(NOW),
    )

    with pytest.raises(
        CaseProvenanceError,
        match="CASE_PROVENANCE_ANCESTOR_CLOSURE_MISMATCH",
    ):
        reader.assert_current(incomplete)
