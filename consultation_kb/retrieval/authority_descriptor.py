"""Independent reconstruction of governed retrieval inputs for publication."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, cast

from pydantic import ValidationError, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.theory import TheoryRevision
from consultation_kb.models.evidence import (
    EmpiricalSupport,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    SourceGrade,
)
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactKind,
    DerivedAuthorityObjectVersion,
    DerivedAuthoritySnapshotV2,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
)
from consultation_kb.retrieval.contracts import CandidateMetadata, CandidateRef
from consultation_kb.models.wiki import (
    WikiGraphRelationDeclaration,
    WikiRelationship,
    WikiSection,
)
from consultation_kb.vault.content_store import ContentStore, ContentStoreError
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256


_BASE_CLAIM_TARGETS: tuple[DerivedArtifactKind, ...] = (
    "lexical",
    "vector",
)


class AuthorityDescriptorError(RuntimeError):
    def __init__(self, code: str = "KNOWLEDGE_AUTHORITY_DESCRIPTOR_INVALID") -> None:
        super().__init__(code)
        self.code = code


class RetrievalRoutePolicy(StrictModel):
    """The single P4 global routing policy; no caller-selected rules exist."""

    contract: Literal["retrieval_route_policy_v1"] = "retrieval_route_policy_v1"
    required_use: Literal["consultation"] = "consultation"
    base_claim_targets: tuple[DerivedArtifactKind, ...] = _BASE_CLAIM_TARGETS
    wiki_claim_target: Literal["wiki_index"] = "wiki_index"
    graph_relation_target: Literal["graph"] = "graph"
    case_loo_authority: Literal["deny_until_governed_authority"] = (
        "deny_until_governed_authority"
    )
    wiki_navigation_text_role: Literal["navigation_text_non_evidence"] = (
        "navigation_text_non_evidence"
    )

    @model_validator(mode="after")
    def _fixed_policy(self) -> "RetrievalRoutePolicy":
        if self.base_claim_targets != _BASE_CLAIM_TARGETS:
            raise ValueError("RETRIEVAL_ROUTE_POLICY_TARGETS_INVALID")
        return self


class _WikiAuthorityBody(StrictModel):
    graph_relations: tuple[WikiGraphRelationDeclaration, ...]
    relationships: tuple[WikiRelationship, ...]
    sections: tuple[WikiSection, ...]
    theory_revision_refs: tuple[VersionRef, ...]
    title: NonEmptyStr
    unresolved_questions: tuple[NonEmptyStr, ...]


def canonical_retrieval_route_policy_bytes() -> bytes:
    return _canonical_json(RetrievalRoutePolicy().model_dump(mode="json"))


class AuthorityManifestMember(StrictModel):
    object_type: str
    object_id: str
    object_sha256: str
    source_version: int
    source_lineage_hashes: tuple[str, ...]
    media_type: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class WikiGraphRelationBinding:
    """One governed graph declaration bound to its exact Wiki revision."""

    wiki_ref: VersionRef
    declaration: WikiGraphRelationDeclaration


@dataclass(frozen=True, slots=True)
class RebuiltPublicationAuthority:
    snapshot: DerivedAuthoritySnapshotV2
    descriptor: RetrievalInputDescriptor
    route_policy_ref: VersionRef
    assignments: tuple[RetrievalInputAssignment, ...]
    wikis: tuple[DerivedAuthorityObjectVersion, ...]
    theories: tuple[DerivedAuthorityObjectVersion, ...]
    graph_relation_bindings: tuple[WikiGraphRelationBinding, ...]

    @property
    def graph_relations(self) -> tuple[WikiGraphRelationDeclaration, ...]:
        return tuple(binding.declaration for binding in self.graph_relation_bindings)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_ref(value: object) -> str:
    text = str(value)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in text[7:])
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_CONTENT_REF_INVALID")
    return text[7:]


def _utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise AuthorityDescriptorError("KNOWLEDGE_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AuthorityDescriptorError("KNOWLEDGE_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


def _read_cas(
    store: ContentStore,
    *,
    digest: str,
    media_type: str,
    size_bytes: int,
) -> bytes:
    try:
        payload = store.read_verified(
            store.reference(
                content_sha256=digest,
                media_type=media_type,
                size_bytes=size_bytes,
            )
        )
    except (ContentStoreError, OSError, TypeError, ValueError):
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_CAS_INVALID") from None
    if hashlib.sha256(payload).hexdigest() != digest:
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_CAS_INVALID")
    return payload


def _parse_wiki_authority_body(
    payload: bytes,
    *,
    title: str,
    body_sha256: str,
    object_sha256: str,
) -> _WikiAuthorityBody:
    try:
        body = _WikiAuthorityBody.model_validate_json(payload, strict=True)
    except (ValidationError, ValueError):
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_BODY_INVALID") from None
    canonical = canonical_json_bytes(body.model_dump(mode="json"))
    if body.title != title or payload != canonical:
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_BODY_INVALID")
    canonical_hash = hashlib.sha256(canonical).hexdigest()
    if body_sha256 != canonical_hash or object_sha256 != canonical_hash:
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_BODY_HASH_MISMATCH")
    return body


def _verify_theory_revision_payload(
    payload: bytes,
    *,
    theory_id: str,
    revision: int,
    revision_sha256: str,
) -> None:
    try:
        stored = TheoryRevision.model_validate_json(payload, strict=True)
    except (ValidationError, ValueError):
        raise AuthorityDescriptorError("KNOWLEDGE_THEORY_REVISION_INVALID") from None
    if (
        stored.theory_id != theory_id
        or stored.revision != revision
        or stored.status != "prepared"
        or payload != canonical_json_bytes(stored.model_dump(mode="json"))
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_THEORY_REVISION_INVALID")
    content = stored.model_dump(mode="json")
    content.pop("status", None)
    if canonical_sha256(content) != revision_sha256:
        raise AuthorityDescriptorError("KNOWLEDGE_THEORY_REVISION_HASH_MISMATCH")


def _parse_route_policy(
    store: ContentStore,
    member: AuthorityManifestMember,
) -> tuple[RetrievalRoutePolicy, VersionRef]:
    if (
        member.object_type != "retrieval_route_policy"
        or member.media_type != "application/json"
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_ROUTE_POLICY_INVALID")
    payload = _read_cas(
        store,
        digest=member.object_sha256,
        media_type=member.media_type,
        size_bytes=member.size_bytes,
    )
    try:
        policy = RetrievalRoutePolicy.model_validate_json(payload, strict=True)
    except (ValidationError, ValueError):
        raise AuthorityDescriptorError("KNOWLEDGE_ROUTE_POLICY_INVALID") from None
    if payload != _canonical_json(policy.model_dump(mode="json")):
        raise AuthorityDescriptorError("KNOWLEDGE_ROUTE_POLICY_INVALID")
    return policy, VersionRef(
        object_id=member.object_id,
        version=member.source_version,
        content_sha256=member.object_sha256,
    )


def _authority_object(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    table: Literal["theory", "wiki"],
    object_id: str,
    version: int,
    allowed_statuses: frozenset[str] = frozenset({"PREPARED"}),
) -> DerivedAuthorityObjectVersion:
    if not allowed_statuses or not allowed_statuses <= frozenset(
        {"PREPARED", "ACTIVE"}
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_STATUS_INVALID")
    placeholders = ",".join("?" for _value in sorted(allowed_statuses))
    status_values = tuple(sorted(allowed_statuses))
    if table == "theory":
        row = connection.execute(
            "SELECT revision_object_ref, revision_object_size_bytes, "
            "revision_object_media_type, revision_sha256 FROM theory_revisions "
            f"WHERE theory_id = ? AND revision = ? AND status IN ({placeholders})",
            (object_id, version, *status_values),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT body_object_ref, body_object_size_bytes, body_object_media_type, "
            "body_sha256, title "
            "FROM wiki_revisions WHERE wiki_id = ? AND revision = ? "
            f"AND review_status IN ({placeholders})",
            (object_id, version, *status_values),
        ).fetchone()
    if row is None:
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_ROW_MISSING")
    digest = _digest_ref(row[0])
    payload = _read_cas(
        store,
        digest=digest,
        size_bytes=int(row[1]),
        media_type=str(row[2]),
    )
    if table == "theory":
        _verify_theory_revision_payload(
            payload,
            theory_id=object_id,
            revision=version,
            revision_sha256=str(row[3]),
        )
    else:
        _parse_wiki_authority_body(
            payload,
            title=str(row[4]),
            body_sha256=str(row[3]),
            object_sha256=digest,
        )
    return DerivedAuthorityObjectVersion(
        object_id=object_id,
        version=version,
        object_sha256=digest,
    )


def _wiki_route_claims(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    wiki_id: str,
    wiki_revision: int,
    allowed_statuses: frozenset[str] = frozenset({"PREPARED"}),
) -> tuple[
    frozenset[tuple[str, int, str]],
    frozenset[tuple[str, int, str]],
    tuple[WikiGraphRelationDeclaration, ...],
]:
    if not allowed_statuses or not allowed_statuses <= frozenset(
        {"PREPARED", "ACTIVE"}
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_STATUS_INVALID")
    placeholders = ",".join("?" for _value in sorted(allowed_statuses))
    status_values = tuple(sorted(allowed_statuses))
    row = connection.execute(
        "SELECT title, body_object_ref, body_object_size_bytes, "
        "body_object_media_type, body_sha256 FROM wiki_revisions "
        f"WHERE wiki_id = ? AND revision = ? "
        f"AND review_status IN ({placeholders})",
        (wiki_id, wiki_revision, *status_values),
    ).fetchone()
    if row is None:
        raise AuthorityDescriptorError("KNOWLEDGE_AUTHORITY_ROW_MISSING")
    digest = _digest_ref(row[1])
    payload = _read_cas(
        store,
        digest=digest,
        size_bytes=int(row[2]),
        media_type=str(row[3]),
    )
    body = _parse_wiki_authority_body(
        payload,
        title=str(row[0]),
        body_sha256=str(row[4]),
        object_sha256=digest,
    )

    database_claims = tuple(
        sorted(
            (
                str(item[0]),
                str(item[1]),
                int(item[2]),
                str(item[3]),
                str(item[4]).lower(),
                int(item[5]),
            )
            for item in connection.execute(
                "SELECT wc.section_key, wc.claim_id, wc.claim_version, "
                "c.claim_sha256, wc.stance, wc.ordinal "
                "FROM wiki_revision_claims AS wc JOIN claims AS c "
                "ON c.claim_id = wc.claim_id AND c.version = wc.claim_version "
                "WHERE wc.wiki_id = ? AND wc.wiki_revision = ?",
                (wiki_id, wiki_revision),
            )
        )
    )
    body_claims = tuple(
        sorted(
            (
                section.key,
                reference.object_id,
                reference.version,
                reference.content_sha256,
                section.stance,
                ordinal,
            )
            for section in body.sections
            for ordinal, reference in enumerate(section.claim_refs)
        )
    )
    if database_claims != body_claims:
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_CLAIM_BINDING_MISMATCH")
    wiki_claims = frozenset(
        (claim_id, claim_version, claim_sha256)
        for _section, claim_id, claim_version, claim_sha256, _stance, _ordinal
        in database_claims
    )
    graph_claims = frozenset(
        (
            relation.claim_ref.object_id,
            relation.claim_ref.version,
            relation.claim_ref.content_sha256,
        )
        for relation in body.graph_relations
    )
    if not graph_claims.issubset(wiki_claims):
        raise AuthorityDescriptorError("KNOWLEDGE_GRAPH_CLAIM_BINDING_MISMATCH")
    return wiki_claims, graph_claims, body.graph_relations


def _target_claim_rows(
    connection: sqlite3.Connection,
    *,
    theory_refs: tuple[VersionRef, ...],
    wiki_refs: tuple[VersionRef, ...],
) -> tuple[tuple[object, ...], ...]:
    by_key: dict[tuple[str, int], tuple[object, ...]] = {}
    for wiki_ref in wiki_refs:
        rows = connection.execute(
            "SELECT DISTINCT c.claim_id, c.version, c.claim_object_ref, "
            "c.claim_object_size_bytes, c.claim_object_media_type, c.claim_sha256, "
            "c.source_grade, c.empirical_support, c.review_status, c.effective_from, "
            "c.effective_to, c.review_due_at, c.allowed_uses_json, c.provenance_json, "
            "c.privacy_scope, c.created_at "
            "FROM wiki_revision_claims AS wc JOIN claims AS c "
            "ON c.claim_id = wc.claim_id AND c.version = wc.claim_version "
            "WHERE wc.wiki_id = ? AND wc.wiki_revision = ? "
            "ORDER BY c.claim_id, c.version",
            (wiki_ref.object_id, wiki_ref.version),
        ).fetchall()
        by_key.update(
            {(str(row[0]), int(row[1])): tuple(row) for row in rows}
        )
    for theory_ref in theory_refs:
        for row in connection.execute(
            "SELECT claim_id, version, claim_object_ref, claim_object_size_bytes, "
            "claim_object_media_type, claim_sha256, source_grade, empirical_support, "
            "review_status, effective_from, effective_to, review_due_at, "
            "allowed_uses_json, provenance_json, privacy_scope, created_at "
            "FROM claims WHERE source_grade = 'C1' AND theory_revision_id = ? "
            "AND theory_revision = ? ORDER BY claim_id, version",
            (theory_ref.object_id, theory_ref.version),
        ):
            by_key[(str(row[0]), int(str(row[1])))] = tuple(row)
    values = tuple(
        sorted(by_key.values(), key=lambda row: (str(row[0]), int(str(row[1]))))
    )
    stable_versions: dict[str, tuple[int, str]] = {}
    for row in values:
        claim_id = str(row[0])
        exact = (int(str(row[1])), str(row[5]))
        if stable_versions.setdefault(claim_id, exact) != exact:
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_VERSION_CONFLICT")
        allowed_statuses = (
            frozenset({"REVIEWED", "APPROVED"})
            if str(row[6]) == "C1"
            else frozenset({"APPROVED"})
        )
        if str(row[8]) not in allowed_statuses or str(row[14]) != "GLOBAL":
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_NOT_PUBLISHABLE")
    if not values:
        raise AuthorityDescriptorError("KNOWLEDGE_RETRIEVAL_INPUT_EMPTY")
    return values


def _json_string_set(value: object, *, code: str) -> frozenset[str]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise AuthorityDescriptorError(code) from None
    if (
        type(parsed) is not list
        or not parsed
        or any(type(item) is not str or not item for item in parsed)
        or parsed != sorted(set(parsed))
    ):
        raise AuthorityDescriptorError(code)
    return frozenset(parsed)


def _claim_assignments(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    claim_rows: tuple[tuple[object, ...], ...],
    claims_manifest_ref: VersionRef,
    claim_members: tuple[AuthorityManifestMember, ...],
    wiki_claim_refs: frozenset[tuple[str, int, str]],
    graph_claim_refs: frozenset[tuple[str, int, str]],
    route_policy: RetrievalRoutePolicy,
    route_policy_ref: VersionRef,
) -> tuple[RetrievalInputAssignment, ...]:
    member_by_id = {member.object_id: member for member in claim_members}
    if (
        len(member_by_id) != len(claim_members)
        or any(member.object_type != "claim" for member in claim_members)
        or set(member_by_id) != {str(row[0]) for row in claim_rows}
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_CLOSURE_MISMATCH")

    assignments: list[RetrievalInputAssignment] = []
    for row in claim_rows:
        claim_id = str(row[0])
        claim_version = int(str(row[1]))
        claim_digest = _digest_ref(row[2])
        exact_claim_key = (claim_id, claim_version, claim_digest)
        if claim_digest != str(row[5]):
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_ROW_MISMATCH")
        member = member_by_id[claim_id]
        if (
            member.object_sha256 != claim_digest
            or member.source_version != claims_manifest_ref.version
            or member.media_type != str(row[4])
            or member.size_bytes != int(str(row[3]))
        ):
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_CLOSURE_MISMATCH")
        _read_cas(
            store,
            digest=claim_digest,
            size_bytes=int(str(row[3])),
            media_type=str(row[4]),
        )
        try:
            provenance = Provenance.model_validate_json(str(row[13]), strict=True)
        except (ValidationError, ValueError):
            raise AuthorityDescriptorError("KNOWLEDGE_PROVENANCE_INVALID") from None
        if provenance.provenance_scope != "global_source":
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_NOT_PUBLISHABLE")
        allowed_uses = _json_string_set(
            row[12], code="KNOWLEDGE_CLAIM_ALLOWED_USES_INVALID"
        )
        if route_policy.required_use not in allowed_uses:
            raise AuthorityDescriptorError("KNOWLEDGE_CLAIM_NOT_PUBLISHABLE")

        raw_edge_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM claim_evidence "
                "WHERE claim_id = ? AND claim_version = ? "
                "AND relation = 'SUPPORTS'",
                (claim_id, claim_version),
            ).fetchone()[0]
        )
        passage_rows = connection.execute(
            "SELECT p.passage_id, p.version, p.normalized_text_sha256, "
            "p.retrieval_content_ref, p.locator_json, p.created_at, p.source_id, "
            "sv.imported_at FROM claim_evidence AS ce "
            "JOIN passages AS p ON p.passage_id = ce.passage_id "
            "AND p.version = ce.passage_version "
            "JOIN source_versions AS sv ON sv.source_id = p.source_id "
            "AND sv.version = p.source_version "
            "JOIN sources AS s ON s.source_id = p.source_id "
            "WHERE ce.claim_id = ? AND ce.claim_version = ? "
            "AND ce.relation = 'SUPPORTS' "
            "AND p.review_status = 'APPROVED' AND p.privacy_scope = 'GLOBAL' "
            "AND sv.status = 'APPROVED' AND s.current_version = sv.version "
            "ORDER BY p.passage_id, p.version",
            (claim_id, claim_version),
        ).fetchall()
        if not passage_rows or len(passage_rows) != raw_edge_count:
            raise AuthorityDescriptorError("KNOWLEDGE_PASSAGE_CLOSURE_MISMATCH")
        source_count = len({str(passage[6]) for passage in passage_rows})
        for passage in passage_rows:
            passage_digest = _digest_ref(passage[3])
            if passage_digest != str(passage[2]):
                raise AuthorityDescriptorError("KNOWLEDGE_PASSAGE_ROW_MISMATCH")
            try:
                body = store.read_hash_verified(passage_digest)
            except (ContentStoreError, OSError, TypeError, ValueError):
                raise AuthorityDescriptorError(
                    "KNOWLEDGE_AUTHORITY_CAS_INVALID"
                ) from None
            passage_ref = VersionRef(
                object_id=str(passage[0]),
                version=int(passage[1]),
                content_sha256=passage_digest,
            )
            try:
                locator = EvidenceLocator.model_validate_json(
                    str(passage[4]), strict=True
                )
            except (ValidationError, ValueError):
                raise AuthorityDescriptorError("KNOWLEDGE_LOCATOR_INVALID") from None
            candidate = CandidateRef(
                reference=VersionRef(
                    object_id=claim_id,
                    version=claim_version,
                    content_sha256=claim_digest,
                ),
                content_ref=passage_ref,
                object_type="claim",
                channel="lexical",
                metadata=CandidateMetadata(
                    manifest_ref=claims_manifest_ref,
                    review_status="approved",
                    allowed_uses=allowed_uses,
                    approved_at=_utc(row[15]),
                    effective_from=None if row[9] is None else _utc(row[9]),
                    effective_to=None if row[10] is None else _utc(row[10]),
                    review_due_at=None if row[11] is None else _utc(row[11]),
                    sensitivity=1,
                    source_grade=cast(SourceGrade, str(row[6])),
                    framework_priority=(
                        "highest" if str(row[6]) == "C1" else "normal"
                    ),
                    empirical_support=cast(EmpiricalSupport, str(row[7])),
                    source_count=source_count,
                    source_lineage_hashes=member.source_lineage_hashes,
                    media_type="text/plain",
                    size_bytes=len(body),
                ),
                provenance=provenance,
                location=locator.model_copy(
                    update={
                        "anchor_refs": tuple(
                            sorted(
                                {*locator.anchor_refs, passage_ref},
                                key=lambda reference: (
                                    reference.object_id,
                                    reference.version,
                                    reference.content_sha256,
                                ),
                            )
                        )
                    }
                ),
                freshness=EvidenceFreshnessSnapshot(
                    status="not_time_sensitive",
                    evaluated_at=_utc(passage[5]),
                    source_observed_at=_utc(passage[7]),
                    last_reviewed_at=_utc(passage[5]),
                    review_due_at=None,
                    policy_ref=route_policy_ref,
                ),
                score=0.0,
            )
            assignments.append(
                RetrievalInputAssignment.from_candidate(
                    candidate,
                    target_channels=frozenset(
                        (*route_policy.base_claim_targets,)
                        + (
                            (route_policy.wiki_claim_target,)
                            if exact_claim_key in wiki_claim_refs
                            else ()
                        )
                        + (
                            (route_policy.graph_relation_target,)
                            if exact_claim_key in graph_claim_refs
                            else ()
                        )
                    ),
                )
            )
    return tuple(assignments)


def rebuild_publication_authority(
    connection: sqlite3.Connection,
    store: ContentStore,
    *,
    publication_authority_version: int,
    expected_current_epoch: int | None,
    theory_id: str | None,
    theory_revision: int | None,
    wiki_id: str,
    wiki_revision: int,
    governed_wiki_refs: tuple[VersionRef, ...] | None = None,
    governed_theory_refs: tuple[VersionRef, ...] | None = None,
    claims_manifest_ref: VersionRef,
    claim_members: tuple[AuthorityManifestMember, ...],
    route_policy_member: AuthorityManifestMember,
) -> RebuiltPublicationAuthority:
    """Rebuild snapshot and descriptor without consuming builder declarations."""

    if not isinstance(connection, sqlite3.Connection) or type(store) is not ContentStore:
        raise TypeError("KNOWLEDGE_AUTHORITY_ADAPTER_REQUIRED")
    if (
        claims_manifest_ref.version != publication_authority_version
        or route_policy_member.source_version != publication_authority_version
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_ARTIFACT_VERSION_MISMATCH")
    route_policy, route_policy_ref = _parse_route_policy(store, route_policy_member)
    active_rows = connection.execute(
        "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchall()
    if len(active_rows) > 1:
        raise AuthorityDescriptorError("KNOWLEDGE_RUNTIME_EPOCH_INVALID")
    active_epoch = None if not active_rows else int(active_rows[0][0])
    maximum_epoch = int(
        connection.execute(
            "SELECT COALESCE(MAX(epoch), 0) FROM runtime_epochs"
        ).fetchone()[0]
    )
    if active_epoch != expected_current_epoch:
        raise AuthorityDescriptorError("KNOWLEDGE_RUNTIME_EPOCH_INVALID")
    catalog = connection.execute(
        "SELECT catalog_version, authorization_epoch, tombstone_epoch "
        "FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone()
    if catalog is None:
        raise AuthorityDescriptorError("KNOWLEDGE_CATALOG_SNAPSHOT_UNAVAILABLE")
    theory = None
    if theory_id is not None and theory_revision is not None:
        theory = _authority_object(
            connection,
            store,
            table="theory",
            object_id=theory_id,
            version=theory_revision,
        )
    wiki = _authority_object(
        connection,
        store,
        table="wiki",
        object_id=wiki_id,
        version=wiki_revision,
    )
    target_wiki_ref = VersionRef(
        object_id=wiki.object_id,
        version=wiki.version,
        content_sha256=wiki.object_sha256,
    )
    wiki_refs = (
        (target_wiki_ref,)
        if governed_wiki_refs is None
        else tuple(
            sorted(
                (VersionRef.model_validate(value) for value in governed_wiki_refs),
                key=lambda value: (
                    value.object_id,
                    value.version,
                    value.content_sha256,
                ),
            )
        )
    )
    if (
        target_wiki_ref not in wiki_refs
        or len({value.object_id for value in wiki_refs}) != len(wiki_refs)
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_CLOSURE_MISMATCH")
    governed_wikis = tuple(
        _authority_object(
            connection,
            store,
            table="wiki",
            object_id=reference.object_id,
            version=reference.version,
            allowed_statuses=frozenset({"PREPARED", "ACTIVE"}),
        )
        for reference in wiki_refs
    )
    if any(
        item.object_sha256 != reference.content_sha256
        for item, reference in zip(governed_wikis, wiki_refs, strict=True)
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_WIKI_CLOSURE_MISMATCH")

    theory_refs = tuple(
        sorted(
            (
                VersionRef.model_validate(value)
                for value in (governed_theory_refs or ())
            ),
            key=lambda value: (
                value.object_id,
                value.version,
                value.content_sha256,
            ),
        )
    )
    if len({value.object_id for value in theory_refs}) != len(theory_refs):
        raise AuthorityDescriptorError("KNOWLEDGE_THEORY_CLOSURE_MISMATCH")
    if theory is not None:
        target_theory_ref = VersionRef(
            object_id=theory.object_id,
            version=theory.version,
            content_sha256=theory.object_sha256,
        )
        if not theory_refs:
            theory_refs = (target_theory_ref,)
        elif target_theory_ref not in theory_refs:
            raise AuthorityDescriptorError("KNOWLEDGE_THEORY_CLOSURE_MISMATCH")
    governed_theories = tuple(
        _authority_object(
            connection,
            store,
            table="theory",
            object_id=reference.object_id,
            version=reference.version,
            allowed_statuses=frozenset({"PREPARED", "ACTIVE"}),
        )
        for reference in theory_refs
    )
    if any(
        item.object_sha256 != reference.content_sha256
        for item, reference in zip(governed_theories, theory_refs, strict=True)
    ):
        raise AuthorityDescriptorError("KNOWLEDGE_THEORY_CLOSURE_MISMATCH")

    wiki_claim_refs: set[tuple[str, int, str]] = set()
    graph_claim_refs: set[tuple[str, int, str]] = set()
    graph_relation_bindings: list[WikiGraphRelationBinding] = []
    for wiki_ref in wiki_refs:
        page_claims, page_graph_claims, page_relations = _wiki_route_claims(
            connection,
            store,
            wiki_id=wiki_ref.object_id,
            wiki_revision=wiki_ref.version,
            allowed_statuses=frozenset({"PREPARED", "ACTIVE"}),
        )
        wiki_claim_refs.update(page_claims)
        graph_claim_refs.update(page_graph_claims)
        graph_relation_bindings.extend(
            WikiGraphRelationBinding(
                wiki_ref=wiki_ref,
                declaration=declaration,
            )
            for declaration in page_relations
        )
    claim_rows = _target_claim_rows(
        connection,
        theory_refs=theory_refs,
        wiki_refs=wiki_refs,
    )
    claims = tuple(
        DerivedAuthorityObjectVersion(
            object_id=str(row[0]),
            version=int(str(row[1])),
            object_sha256=str(row[5]),
        )
        for row in claim_rows
    )
    snapshot = DerivedAuthoritySnapshotV2(
        catalog_version=int(catalog[0]),
        authorization_epoch=int(catalog[1]),
        tombstone_epoch=int(catalog[2]),
        publication_authority_version=publication_authority_version,
        expected_current_epoch=expected_current_epoch,
        maximum_runtime_epoch=maximum_epoch,
        target_runtime_epoch=maximum_epoch + 1,
        theory=theory,
        wiki=wiki,
        claims=claims,
    )
    assignments = _claim_assignments(
        connection,
        store,
        claim_rows=claim_rows,
        claims_manifest_ref=claims_manifest_ref,
        claim_members=claim_members,
        wiki_claim_refs=frozenset(wiki_claim_refs),
        graph_claim_refs=frozenset(graph_claim_refs),
        route_policy=route_policy,
        route_policy_ref=route_policy_ref,
    )
    descriptor = RetrievalInputDescriptor.from_assignments(
        assignments,
        route_policy_ref=route_policy_ref,
    )
    return RebuiltPublicationAuthority(
        snapshot=snapshot,
        descriptor=descriptor,
        route_policy_ref=route_policy_ref,
        assignments=assignments,
        wikis=governed_wikis,
        theories=governed_theories,
        graph_relation_bindings=tuple(
            sorted(
                graph_relation_bindings,
                key=lambda item: (
                    item.wiki_ref.object_id,
                    item.wiki_ref.version,
                    item.declaration.claim_ref.object_id,
                    item.declaration.source_ref.object_id,
                    item.declaration.target_ref.object_id,
                ),
            )
        ),
    )


__all__ = [
    "AuthorityDescriptorError",
    "AuthorityManifestMember",
    "RebuiltPublicationAuthority",
    "WikiGraphRelationBinding",
    "RetrievalRoutePolicy",
    "canonical_retrieval_route_policy_bytes",
    "rebuild_publication_authority",
]
