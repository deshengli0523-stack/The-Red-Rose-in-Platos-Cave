from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import itertools
import json
import sqlite3

import pytest

from consultation_kb.archive.case_indexing import (
    CaseContributorBinding,
    CaseIndexGovernance,
    CaseIndexRootAuthority,
    CaseIndexTextSet,
    CaseIndexingError,
    CaseIndexingService,
)
from consultation_kb.archive.provenance import (
    CaseContributorHasher,
    CaseProvenanceService,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.cases import (
    CaseContribution,
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    case_reuse_authorization_payload,
    deidentification_human_review_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)
from consultation_kb.retrieval.contracts import FilterCapabilityBinding
from consultation_kb.retrieval.filters import (
    AuthoritySnapshotStale,
    CandidateAuthorityStatus,
    CandidateFilter,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    ObjectTombstoned,
    TombstoneRepository,
    VisibilityGuard,
)
from tests.consultation_kb.case_index_support import (
    StaticCaseIndexAuthority,
    StaticCaseSourceAuthority,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("CASE-02"),
]

NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12
HASH_KEY = b"task-six-case-contributor-key-material"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ids() -> IdFactory:
    values = itertools.count(90000)
    return IdFactory(FixedClock(NOW), lambda: next(values))


def _ref(ids: IdFactory, kind: str, seed: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=_digest(seed),
    )


def _authorization(
    ids: IdFactory,
    contributor_hash: str,
    *,
    reuse: bool = True,
    valid_from: datetime = NOW,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> CaseReuseAuthorization:
    authorization_id = ids.object_id("case_authorization")
    allowed_uses = frozenset({"answer_support"}) if reuse else frozenset()
    terms_sha256 = _digest("authorization-terms")
    payload = case_reuse_authorization_payload(
        authorization_id=authorization_id,
        version=1,
        contributor_client_hash=contributor_hash,
        reuse_authorized=reuse,
        allowed_uses=allowed_uses,
        valid_from=valid_from,
        expires_at=expires_at,
        revoked_at=revoked_at,
        terms_sha256=terms_sha256,
    )
    return CaseReuseAuthorization(
        authorization_ref=VersionRef(
            object_id=authorization_id,
            version=1,
            content_sha256=canonical_sha256(payload),
        ),
        contributor_client_hash=contributor_hash,
        reuse_authorized=reuse,
        allowed_uses=allowed_uses,
        valid_from=valid_from,
        expires_at=expires_at,
        revoked_at=revoked_at,
        terms_sha256=terms_sha256,
    )


def _release_authority(
    ids: IdFactory,
    authorization: CaseReuseAuthorization,
    policy_ref: VersionRef,
    *,
    evaluated_at: datetime,
) -> tuple[DeidentificationHumanReview, CaseReleaseDecision]:
    candidate_sha256 = _digest("deidentified-candidate")
    review_id = ids.object_id("case_deidentification_review")
    checked_categories = frozenset(
        {
            "direct_identifiers",
            "third_party_people",
            "rare_attributes",
            "location_occupation_family_time",
            "section_boundaries",
            "no_verbatim_quotes",
        }
    )
    attestation = _digest("reviewer-attestation")
    review_ref = VersionRef(
        object_id=review_id,
        version=1,
        content_sha256=canonical_sha256(
            deidentification_human_review_payload(
                review_id=review_id,
                version=1,
                candidate_sha256=candidate_sha256,
                decision="approved",
                checked_categories=checked_categories,
                residual_risk="low",
                rare_combination_disposition="not_present",
                allowed_uses=frozenset({"answer_support"}),
                reviewed_at=evaluated_at,
                reviewer_attestation_sha256=attestation,
            )
        ),
    )
    review = DeidentificationHumanReview(
        review_ref=review_ref,
        candidate_sha256=candidate_sha256,
        decision="approved",
        checked_categories=checked_categories,
        residual_risk="low",
        rare_combination_disposition="not_present",
        allowed_uses=frozenset({"answer_support"}),
        reviewed_at=evaluated_at,
        reviewer_attestation_sha256=attestation,
    )
    eligible = authorization.reuse_authorized
    return review, CaseReleaseDecision(
        candidate_sha256=candidate_sha256,
        outcome="eligible" if eligible else "private_only",
        reasons=() if eligible else ("reuse_not_authorized",),
        authorization_ref=authorization.authorization_ref,
        review_ref=review.review_ref,
        policy_ref=policy_ref,
        allowed_uses=(frozenset({"answer_support"}) if eligible else frozenset()),
        evaluated_at=evaluated_at,
    )


def _context(
    *,
    connection: sqlite3.Connection | None = None,
    reuse: bool = True,
    valid_from: datetime = NOW,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
):
    ids = _ids()
    hasher = CaseContributorHasher(hash_key=HASH_KEY)
    contributor_hash = hasher.hash_client_id(CLIENT_A)
    authorization = _authorization(
        ids,
        contributor_hash,
        reuse=reuse,
        valid_from=valid_from,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )
    rule = _ref(ids, "case_derivation_rule", "rule")
    policy_ref = _ref(ids, "case_provenance_policy", "policy")
    source_authority = StaticCaseSourceAuthority()
    creation_provenance = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=policy_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=source_authority,
        clock=FixedClock(valid_from),
    )
    case_ref = _ref(ids, "case", "global-case-body")
    authority_end = min(
        (value for value in (expires_at, revoked_at) if value is not None),
        default=None,
    )
    contribution = CaseContribution(
        case_ref=case_ref,
        source_provenance_ref=_ref(ids, "case_source_provenance", "source"),
        contributor_client_hashes=frozenset({contributor_hash}),
        authorization_ref=authorization.authorization_ref,
        allowed_uses=frozenset({"answer_support"}),
        effective_to=authority_end,
        source_grade="K1",
        source_lineage_sha256=_digest("source-lineage"),
    )
    source_authority.authorize_case(contribution)
    root = creation_provenance.root_case(
        case_ref,
        contribution,
        derivation_rule_ref=rule,
    )
    if revoked_at is not None and revoked_at <= NOW:
        source_authority.authorize_case(contribution, state="revoked")
    provenance = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=policy_ref,
        approved_derivation_rules=(rule,),
        authority_resolver=source_authority,
        clock=FixedClock(NOW),
    )
    release_policy_ref = _ref(ids, "case_release_policy", "release-policy")
    review, release_decision = _release_authority(
        ids,
        authorization,
        release_policy_ref,
        evaluated_at=valid_from,
    )
    source_candidate_ref = VersionRef(
        object_id=ids.object_id("shared_case_candidate"),
        version=1,
        content_sha256=review.candidate_sha256,
    )
    authority_manifest_ref = _ref(
        ids, "case_authority_manifest", "manifest"
    )
    index_authority = StaticCaseIndexAuthority()
    index_authority.authorize(
        CaseIndexRootAuthority(
            case_ref=root.artifact_ref,
            source_candidate_ref=source_candidate_ref,
            authorization=authorization,
            review=review,
            release_decision=release_decision,
            authority_manifest_ref=authority_manifest_ref,
            source_catalog_version=1,
            state=(
                "revoked"
                if revoked_at is not None and revoked_at <= NOW
                else "active"
            ),
        )
    )
    service = CaseIndexingService(
        id_factory=ids,
        provenance_service=provenance,
        contributor_hasher=hasher,
        authority_resolver=index_authority,
        connection=connection,
        clock=FixedClock(NOW),
    )
    build_arguments = {
        "authorization": authorization,
        "review": review,
        "release_decision": release_decision,
        "contributor": CaseContributorBinding(
            client_id=CLIENT_A,
            contributor_client_hash=contributor_hash,
        ),
        "texts": CaseIndexTextSet(
            case_record="来访者在冲突后先稳定情绪并澄清需求",
            reviewed_pattern="在相似条件下先稳定情绪可改善沟通准备",
            conditional_claim="高唤醒条件下可先暂停并确认需求",
            wiki_section="稳定情绪与澄清需求可作为条件性参考顺序",
            graph_relation="情绪稳定可能支持后续需求澄清",
        ),
        "governance": CaseIndexGovernance(
            source_candidate_ref=source_candidate_ref,
            authority_manifest_ref=authority_manifest_ref,
            release_policy_ref=release_policy_ref,
            locator_policy_ref=_ref(ids, "locator_policy", "locator"),
            freshness_policy_ref=_ref(ids, "freshness_policy", "freshness"),
            source_catalog_version=1,
            indexed_at=NOW,
        ),
        "derivation_rule_ref": rule,
    }
    return service, root, authorization, build_arguments


@pytest.mark.parametrize(
    ("updates", "code"),
    (
        ({"reuse": False}, "CASE_INDEX_REUSE_NOT_AUTHORIZED"),
        (
            {
                "valid_from": NOW - timedelta(days=2),
                "expires_at": NOW - timedelta(days=1),
            },
            "CASE_CONTRIBUTION_AUTHORITY_EXPIRED",
        ),
        (
            {
                "valid_from": NOW - timedelta(days=2),
                "revoked_at": NOW - timedelta(hours=1),
            },
            "CASE_CONTRIBUTION_AUTHORITY_REVOKED",
        ),
    ),
)
def test_false_expired_and_revoked_authority_never_enter_global_indexes(
    updates: dict[str, object], code: str
) -> None:
    private_profile = {"current_goal": "improve_communication"}
    service, root, _authorization_value, arguments = _context(**updates)

    with pytest.raises(CaseIndexingError, match=code):
        service.build(root, **arguments)

    # Private profile persistence is an independent purpose and succeeds even
    # when shared-case reuse is denied.
    assert private_profile == {"current_goal": "improve_communication"}


def test_release_decision_from_another_candidate_cannot_be_laundered() -> None:
    service, root, _authorization_value, arguments = _context()
    decision = arguments["release_decision"]
    assert isinstance(decision, CaseReleaseDecision)
    arguments["release_decision"] = decision.model_copy(
        update={"candidate_sha256": "f" * 64}
    )

    with pytest.raises(CaseIndexingError, match="CASE_INDEX_AUTHORITY_MISMATCH"):
        service.build(root, **arguments)


class _TombstoneAwareGuard:
    def __init__(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        repository: TombstoneRepository,
    ) -> None:
        self._snapshot = snapshot
        self._visibility = VisibilityGuard(repository)

    def assert_snapshot_current(self, snapshot: AuthoritativeFilterSnapshot) -> None:
        if snapshot != self._snapshot:
            raise AuthoritySnapshotStale

    def candidate_status(
        self,
        candidate,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        self.assert_snapshot_current(snapshot)
        try:
            self._visibility.assert_visible(
                ObjectIdentity(candidate.object_type, candidate.reference.object_id),
                source_lineage_hashes=candidate.metadata.source_lineage_hashes,
            )
        except ObjectTombstoned:
            return "tombstoned"
        return (
            "visible"
            if candidate.reference.object_id in snapshot.allowed_ref_ids
            else "unauthorized"
        )

    def assert_binding_current(self, binding: FilterCapabilityBinding) -> None:
        if binding.run_id != self._snapshot.run_id:
            raise AuthoritySnapshotStale

    def assert_candidate_binding_visible(self, candidate, binding) -> None:
        self.assert_binding_current(binding)
        if self.candidate_status(candidate, self._snapshot) != "visible":
            raise AuthoritySnapshotStale


def _install_case_database(
    connection: sqlite3.Connection,
    root,
    authorization: CaseReuseAuthorization,
) -> None:
    for name in ("v0001_initial", "v0002_knowledge", "v0005_cases"):
        importlib.import_module(
            f"consultation_kb.storage.migrations.global.{name}"
        ).upgrade(connection)
    now_text = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    case_ref = root.artifact_ref
    provenance_ref = root.provenance_ref
    connection.execute(
        "INSERT INTO cases(case_id, state, current_version, created_at, updated_at) VALUES (?, 'ACTIVE', 1, ?, ?)",
        (case_ref.object_id, now_text, now_text),
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
        ) VALUES (?, ?, ?, ?, ?, ?, 'case', ?, 0, ?, ?, ?, ?, ?, ?, 'K1',
                  'case_derived', ?, NULL, ?, ?)
        """,
        (
            provenance_ref.object_id,
            provenance_ref.version,
            provenance_ref.content_sha256,
            case_ref.object_id,
            case_ref.version,
            case_ref.content_sha256,
            json.dumps(sorted(root.contributor_client_hashes)),
            root.derivation_rule_ref.object_id,
            root.derivation_rule_ref.version,
            root.derivation_rule_ref.content_sha256,
            root.policy_manifest_ref.object_id,
            root.policy_manifest_ref.version,
            root.policy_manifest_ref.content_sha256,
            json.dumps(sorted(root.allowed_uses)),
            root.model_dump_json(),
            root.closure_sha256,
        ),
    )
    connection.execute(
        """
        INSERT INTO case_versions(
            case_id, version, candidate_id, candidate_version,
            candidate_sha256, global_content_ref, global_content_sha256,
            global_content_media_type, global_content_size_bytes, manifest_id,
            release_decision_sha256, allowed_uses_json, source_grade,
            provenance_id, provenance_version, state, prepared_at, activated_at
        ) VALUES (?, 1, ?, 1, ?, ?, ?, 'application/json', 1, ?, ?, ?, 'K1',
                  ?, ?, 'ACTIVE', ?, ?)
        """,
        (
            case_ref.object_id,
            "candidate-fixture",
            _digest("candidate"),
            f"sha256:{case_ref.content_sha256}",
            case_ref.content_sha256,
            "manifest-fixture",
            _digest("release"),
            json.dumps(["answer_support"]),
            provenance_ref.object_id,
            provenance_ref.version,
            now_text,
            now_text,
        ),
    )
    connection.execute(
        """
        INSERT INTO case_authorizations(
            case_id, case_version, authorization_id, authorization_version,
            authorization_sha256, contributor_client_hash, reuse_authorized,
            allowed_uses_json, valid_from, expires_at, revoked_at, terms_sha256
        ) VALUES (?, 1, ?, ?, ?, ?, 1, ?, ?, NULL, NULL, ?)
        """,
        (
            case_ref.object_id,
            authorization.authorization_ref.object_id,
            authorization.authorization_ref.version,
            authorization.authorization_ref.content_sha256,
            authorization.contributor_client_hash,
            json.dumps(sorted(authorization.allowed_uses)),
            now_text,
            authorization.terms_sha256,
        ),
    )


def _snapshot(bundle) -> AuthoritativeFilterSnapshot:
    first_candidate = bundle.candidates[0]
    return AuthoritativeFilterSnapshot(
        run_id="019f743d-4400-7000-8000-000000000002",
        global_runtime_epoch=1,
        client_runtime_epoch=0,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(
            candidate.reference.object_id for candidate in bundle.candidates
        ),
        policy_ref=first_candidate.metadata.manifest_ref,
        created_at=NOW,
    )


def _scope() -> RetrievalScope:
    return RetrievalScope(
        current_client_id=CLIENT_B,
        allowed_uses=frozenset({"answer_support"}),
        maximum_sensitivity=1,
        effective_at=NOW,
        known_at=NOW,
    )


def test_legacy_direct_revocation_fails_before_any_database_write() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    service, root, authorization, arguments = _context(connection=connection)
    bundle = service.build(root, **arguments)
    _install_case_database(connection, root, authorization)
    authorization_row_before = connection.execute(
        "SELECT authorization_sha256, revoked_at FROM case_authorizations"
    ).fetchone()
    snapshot = _snapshot(bundle)
    guard = _TombstoneAwareGuard(snapshot, TombstoneRepository(connection))
    candidate_filter = CandidateFilter(
        guard,
        contributor_identity_hasher=CaseContributorHasher(hash_key=HASH_KEY),
    )
    assert all(
        candidate_filter.filter(_scope(), (candidate,), snapshot).allowed
        for candidate in bundle.candidates
    )

    total_changes = connection.total_changes
    with pytest.raises(
        CaseIndexingError,
        match="CASE_REVOCATION_REQUIRES_FORMAL_DELETION",
    ):
        service.revoke(
            root.artifact_ref,
            authorization_ref=authorization.authorization_ref,
            catalog_version=0,
        )

    assert connection.total_changes == total_changes
    assert connection.execute("SELECT state FROM cases").fetchone() == ("ACTIVE",)
    assert connection.execute("SELECT state FROM case_versions").fetchone() == (
        "ACTIVE",
    )
    assert (
        connection.execute(
            "SELECT authorization_sha256, revoked_at FROM case_authorizations"
        ).fetchone()
        == authorization_row_before
    )
    assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM rebuild_queue").fetchone() == (0,)
    assert connection.execute(
        "SELECT authorization_epoch, tombstone_epoch "
        "FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone() == (0, 0)
    assert all(
        candidate_filter.filter(_scope(), (candidate,), snapshot).allowed
        for candidate in bundle.candidates
    )
