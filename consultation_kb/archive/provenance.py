"""Transitive, client-hash-only provenance closure for shared case artifacts."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import hmac
import re
from threading import Lock
from typing import Literal, Protocol, TypeAlias, TypeVar

from pydantic import TypeAdapter

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.cases import (
    CaseArtifactKind,
    CaseContribution,
    CaseProvenanceRecord,
    CaseProvenanceScope,
    IndependentEvidence,
    case_provenance_payload,
    recompute_case_source_grade,
    stable_version_ref_key,
    version_ref_key,
)
from consultation_kb.models.common import ClientId, UtcDateTime, VersionRef
from consultation_kb.models.evidence import SourceGrade


class CaseProvenanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_ALLOWED_PARENT_KINDS: dict[CaseArtifactKind, frozenset[CaseArtifactKind]] = {
    "case": frozenset(),
    "case_pattern": frozenset({"case"}),
    "claim": frozenset({"case", "case_pattern"}),
    "wiki_section": frozenset({"claim"}),
    "graph_edge": frozenset({"case_pattern", "claim", "wiki_section"}),
    "lexical_row": frozenset(
        {"case", "case_pattern", "claim", "wiki_section", "graph_edge"}
    ),
    "vector_row": frozenset(
        {"case", "case_pattern", "claim", "wiki_section", "graph_edge"}
    ),
}

_T = TypeVar("_T")
_CLIENT_ID_ADAPTER = TypeAdapter(ClientId)
_UTC_ADAPTER = TypeAdapter(UtcDateTime)
_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

SourceAuthorityState: TypeAlias = Literal[
    "active", "expired", "revoked", "unauthorized"
]


@dataclass(frozen=True)
class CaseContributionAuthority:
    """One authoritative case-source record and its live authority state."""

    contribution: CaseContribution
    authority_state: SourceAuthorityState = "active"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contribution",
            CaseContribution.model_validate(self.contribution),
        )
        if self.authority_state not in {
            "active",
            "expired",
            "revoked",
            "unauthorized",
        }:
            raise ValueError("invalid case contribution authority state")


@dataclass(frozen=True)
class IndependentEvidenceAuthority:
    """One authoritative non-case source record and its live authority state."""

    evidence: IndependentEvidence
    authority_state: SourceAuthorityState = "active"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence",
            IndependentEvidence.model_validate(self.evidence),
        )
        if self.authority_state not in {
            "active",
            "expired",
            "revoked",
            "unauthorized",
        }:
            raise ValueError("invalid independent evidence authority state")


class CaseSourceAuthorityResolver(Protocol):
    """Resolve authoritative source metadata by every exact identifying ref."""

    def resolve_case_contribution(
        self,
        *,
        case_ref: VersionRef,
        source_provenance_ref: VersionRef,
        authorization_ref: VersionRef,
    ) -> CaseContributionAuthority | None: ...

    def resolve_independent_evidence(
        self,
        *,
        evidence_ref: VersionRef,
        source_provenance_ref: VersionRef,
    ) -> IndependentEvidenceAuthority | None: ...


class CaseProvenanceRecordResolver(Protocol):
    """Optional authority extension for exact persisted provenance records."""

    def resolve_provenance(
        self,
        *,
        provenance_ref: VersionRef,
    ) -> CaseProvenanceRecord | None: ...


class CaseContributorHasher:
    """Create the only client pseudonym permitted in shared case lineage."""

    def __init__(self, *, hash_key: bytes) -> None:
        if not isinstance(hash_key, bytes) or len(hash_key) < 32:
            raise ValueError("case contributor hash key must contain at least 32 bytes")
        self._key = bytes(hash_key)

    def hash_client_id(self, client_id: str) -> str:
        checked = _CLIENT_ID_ADAPTER.validate_python(client_id)
        return hmac.new(
            self._key,
            f"case_contributor\0{checked}".encode("ascii", errors="strict"),
            hashlib.sha256,
        ).hexdigest()

    def pseudonymous_client_id(self, client_id: str) -> str:
        """Return a type-safe HMAC alias for global retrieval metadata."""

        checked = _CLIENT_ID_ADAPTER.validate_python(client_id)
        digest = hmac.new(
            self._key,
            f"case_candidate_alias\0{checked}".encode("ascii", errors="strict"),
            hashlib.sha256,
        ).digest()
        # The public ClientId shape permits twelve lower-case base32 symbols.
        # Keeping 60 HMAC bits materially lowers accidental alias collisions
        # compared with twelve hexadecimal symbols (48 bits).
        encoded = base64.b32encode(digest).decode("ascii").lower()
        return _CLIENT_ID_ADAPTER.validate_python(f"client_{encoded[:12]}")


def _merge_exact_records(
    values: Iterable[_T],
    *,
    key: Callable[[_T], tuple[str, int, str]],
    conflict_code: str,
) -> tuple[_T, ...]:
    merged: dict[tuple[str, int, str], _T] = {}
    stable_versions: dict[tuple[str, int], tuple[str, int, str]] = {}
    for value in values:
        identity = key(value)
        stable_identity = identity[0], identity[1]
        existing_identity = stable_versions.get(stable_identity)
        if existing_identity is not None and existing_identity != identity:
            raise CaseProvenanceError(conflict_code)
        existing = merged.get(identity)
        if existing is not None and existing != value:
            raise CaseProvenanceError(conflict_code)
        stable_versions[stable_identity] = identity
        merged[identity] = value
    return tuple(merged[identity] for identity in sorted(merged))


class CaseProvenanceService:
    """Compute lineage from metadata only; case bodies are never inspected."""

    def __init__(
        self,
        *,
        id_factory: IdFactory,
        policy_manifest_ref: VersionRef,
        approved_derivation_rules: Iterable[VersionRef],
        authority_resolver: CaseSourceAuthorityResolver | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(id_factory, IdFactory):
            raise TypeError("case provenance service requires IdFactory")
        if authority_resolver is not None and (
            not callable(getattr(authority_resolver, "resolve_case_contribution", None))
            or not callable(
                getattr(authority_resolver, "resolve_independent_evidence", None)
            )
            or (
                getattr(authority_resolver, "resolve_provenance", None) is not None
                and not callable(
                    getattr(authority_resolver, "resolve_provenance", None)
                )
            )
        ):
            raise TypeError("CASE_SOURCE_AUTHORITY_RESOLVER_INVALID")
        selected_clock = SystemClock() if clock is None else clock
        if not callable(getattr(selected_clock, "now", None)):
            raise TypeError("CASE_PROVENANCE_CLOCK_INVALID")
        self._ids = id_factory
        self._authority = authority_resolver
        self._clock = selected_clock
        self._policy_manifest_ref = VersionRef.model_validate(policy_manifest_ref)
        rules = tuple(
            VersionRef.model_validate(value) for value in approved_derivation_rules
        )
        keys = [version_ref_key(value) for value in rules]
        if not rules or len(keys) != len(set(keys)):
            raise CaseProvenanceError("CASE_PROVENANCE_RULE_MANIFEST_INVALID")
        self._approved_rules = frozenset(keys)
        self._idempotency_lock = Lock()
        self._idempotency_records: dict[str, tuple[str, CaseProvenanceRecord]] = {}
        self._provenance_lock = Lock()
        self._minted_provenance: dict[
            tuple[str, int, str], CaseProvenanceRecord
        ] = {}
        self._minted_stable_versions: dict[
            tuple[str, int], tuple[str, int, str]
        ] = {}

    @property
    def policy_manifest_ref(self) -> VersionRef:
        return self._policy_manifest_ref

    def is_stale(
        self,
        record: CaseProvenanceRecord,
        *,
        expected_derivation_rule_ref: VersionRef | None = None,
    ) -> bool:
        """Report whether a stored closure is outside the current rule authority."""

        try:
            self.assert_current(
                record,
                expected_derivation_rule_ref=expected_derivation_rule_ref,
            )
        except (CaseProvenanceError, TypeError, ValueError):
            return True
        return False

    def assert_current(
        self,
        record: CaseProvenanceRecord,
        *,
        expected_derivation_rule_ref: VersionRef | None = None,
    ) -> CaseProvenanceRecord:
        """Fail closed instead of laundering stale lineage into a new artifact."""

        value = self._parse_provenance_record(record)
        expected = (
            None
            if expected_derivation_rule_ref is None
            else VersionRef.model_validate(expected_derivation_rule_ref)
        )
        return self._assert_current_record(
            value,
            expected_derivation_rule_ref=expected,
            known_from_resolver=False,
            visiting=set(),
            validated={},
        )

    @staticmethod
    def _parse_provenance_record(
        record: CaseProvenanceRecord,
    ) -> CaseProvenanceRecord:
        """Re-parse even model instances so model_copy cannot bypass closure checks."""

        try:
            if not isinstance(record, CaseProvenanceRecord):
                raise TypeError
            return CaseProvenanceRecord.model_validate_json(
                record.model_dump_json(),
                strict=True,
            )
        except Exception:
            raise CaseProvenanceError("CASE_PROVENANCE_RECORD_INVALID") from None

    def _assert_current_record(
        self,
        value: CaseProvenanceRecord,
        *,
        expected_derivation_rule_ref: VersionRef | None,
        known_from_resolver: bool,
        visiting: set[tuple[str, int, str]],
        validated: dict[tuple[str, int, str], CaseProvenanceRecord],
    ) -> CaseProvenanceRecord:
        self._assert_record_policy_and_sources(
            value,
            expected_derivation_rule_ref=expected_derivation_rule_ref,
        )
        key = version_ref_key(value.provenance_ref)
        existing = validated.get(key)
        if existing is not None:
            if existing != value:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_PARENT_REFERENCE_MISMATCH"
                )
            return existing

        minted = self._minted_record(value.provenance_ref)
        if minted is not None:
            if minted != value:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_PARENT_REFERENCE_MISMATCH"
                )
            # Same-instance records were constructed only after path and closure
            # validation. Live source authority is still rechecked above.
            validated[key] = minted
            return minted

        if value.parent_provenance_refs and not known_from_resolver:
            persisted = self._resolve_persisted_provenance(value.provenance_ref)
            if persisted != value:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_RECORD_AUTHORITY_MISMATCH"
                )
            value = persisted

        if not value.parent_provenance_refs:
            validated[key] = value
            return value
        if key in visiting:
            raise CaseProvenanceError("CASE_PROVENANCE_CYCLE")
        visiting.add(key)
        try:
            parents = tuple(
                self._assert_current_record(
                    self._resolve_known_provenance(reference),
                    expected_derivation_rule_ref=None,
                    known_from_resolver=True,
                    visiting=visiting,
                    validated=validated,
                )
                for reference in value.parent_provenance_refs
            )
            allowed_parent_kinds = _ALLOWED_PARENT_KINDS[value.artifact_kind]
            if any(
                parent.artifact_kind not in allowed_parent_kinds
                for parent in parents
            ):
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_DERIVATION_PATH_INVALID"
                )
            expected_parent_refs = self._unique_refs(
                parent.provenance_ref for parent in parents
            )
            if value.parent_provenance_refs != expected_parent_refs:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_PARENT_REFERENCE_MISMATCH"
                )
            expected_ancestors = self._unique_refs(
                reference
                for parent in parents
                for reference in (
                    parent.artifact_ref,
                    *parent.ancestor_artifact_refs,
                )
            )
            if value.ancestor_artifact_refs != expected_ancestors:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_ANCESTOR_CLOSURE_MISMATCH"
                )
            inherited_cases = _merge_exact_records(
                (
                    contribution
                    for parent in parents
                    for contribution in parent.case_contributions
                ),
                key=lambda item: version_ref_key(item.case_ref),
                conflict_code="CASE_CONTRIBUTION_VERSION_CONFLICT",
            )
            if value.case_contributions != inherited_cases:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_SOURCE_CLOSURE_MISMATCH"
                )
            inherited_evidence = _merge_exact_records(
                (
                    evidence
                    for parent in parents
                    for evidence in parent.independent_evidence
                ),
                key=lambda item: version_ref_key(item.evidence_ref),
                conflict_code="INDEPENDENT_EVIDENCE_VERSION_CONFLICT",
            )
            actual_evidence = {
                version_ref_key(item.evidence_ref): item
                for item in value.independent_evidence
            }
            if any(
                actual_evidence.get(version_ref_key(item.evidence_ref)) != item
                for item in inherited_evidence
            ):
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_SOURCE_CLOSURE_MISMATCH"
                )
        finally:
            visiting.remove(key)
        validated[key] = value
        return value

    def _assert_record_policy_and_sources(
        self,
        value: CaseProvenanceRecord,
        *,
        expected_derivation_rule_ref: VersionRef | None,
    ) -> None:
        if value.policy_manifest_ref != self._policy_manifest_ref:
            raise CaseProvenanceError("CASE_PROVENANCE_POLICY_STALE")
        if version_ref_key(value.derivation_rule_ref) not in self._approved_rules:
            raise CaseProvenanceError("CASE_DERIVATION_RULE_STALE")
        if (
            expected_derivation_rule_ref is not None
            and value.derivation_rule_ref != expected_derivation_rule_ref
        ):
            raise CaseProvenanceError("CASE_DERIVATION_RULE_STALE")
        self._assert_authoritative_sources(
            value.case_contributions,
            value.independent_evidence,
        )

    def _minted_record(
        self,
        reference: VersionRef,
    ) -> CaseProvenanceRecord | None:
        key = version_ref_key(reference)
        with self._provenance_lock:
            return self._minted_provenance.get(key)

    def _resolve_known_provenance(
        self,
        reference: VersionRef,
    ) -> CaseProvenanceRecord:
        exact = VersionRef.model_validate(reference)
        minted = self._minted_record(exact)
        if minted is not None:
            return minted
        return self._resolve_persisted_provenance(exact)

    def _resolve_persisted_provenance(
        self,
        reference: VersionRef,
    ) -> CaseProvenanceRecord:
        authority = self._authority
        resolver = (
            None
            if authority is None
            else getattr(authority, "resolve_provenance", None)
        )
        if not callable(resolver):
            raise CaseProvenanceError(
                "CASE_PROVENANCE_PARENT_RESOLVER_REQUIRED"
            )
        try:
            resolved = resolver(provenance_ref=reference)
        except Exception:
            raise CaseProvenanceError(
                "CASE_PROVENANCE_PARENT_RESOLUTION_FAILED"
            ) from None
        if resolved is None:
            raise CaseProvenanceError("CASE_PROVENANCE_PARENT_NOT_FOUND")
        parsed = self._parse_provenance_record(resolved)
        if parsed.provenance_ref != reference:
            raise CaseProvenanceError(
                "CASE_PROVENANCE_PARENT_REFERENCE_MISMATCH"
            )
        return parsed

    def root_case(
        self,
        artifact_ref: VersionRef,
        contribution: CaseContribution,
        *,
        derivation_rule_ref: VersionRef,
        operation_idempotency_key: str | None = None,
    ) -> CaseProvenanceRecord:
        artifact = VersionRef.model_validate(artifact_ref)
        source = CaseContribution.model_validate(contribution)
        rule = self._approved_rule(derivation_rule_ref)
        if source.case_ref != artifact:
            raise CaseProvenanceError("CASE_ROOT_REFERENCE_MISMATCH")
        self._assert_case_contribution_authority(source)
        return self._record(
            operation_kind="root_case",
            operation_idempotency_key=operation_idempotency_key,
            artifact_ref=artifact,
            artifact_kind="case",
            parent_provenance_refs=(),
            ancestor_artifact_refs=(),
            case_contributions=(source,),
            independent_evidence=(),
            derivation_rule_ref=rule,
            source_grade=source.source_grade,
        )

    def propagate(
        self,
        artifact_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        parents: Iterable[CaseProvenanceRecord],
        *,
        derivation_rule_ref: VersionRef,
        independent_evidence: Iterable[IndependentEvidence] = (),
        operation_idempotency_key: str | None = None,
    ) -> CaseProvenanceRecord:
        artifact = VersionRef.model_validate(artifact_ref)
        if artifact_kind == "case":
            raise CaseProvenanceError("CASE_ROOT_REQUIRES_ROOT_CASE")
        values = tuple(CaseProvenanceRecord.model_validate(item) for item in parents)
        if not values:
            raise CaseProvenanceError("CASE_PROVENANCE_PARENT_REQUIRED")
        values = tuple(self.assert_current(item) for item in values)
        rule = self._approved_rule(derivation_rule_ref)
        allowed_parent_kinds = _ALLOWED_PARENT_KINDS[artifact_kind]
        if any(item.artifact_kind not in allowed_parent_kinds for item in values):
            raise CaseProvenanceError("CASE_PROVENANCE_DERIVATION_PATH_INVALID")

        parent_refs = tuple(item.provenance_ref for item in values)
        parent_keys = [version_ref_key(item) for item in parent_refs]
        if len(parent_keys) != len(set(parent_keys)):
            raise CaseProvenanceError("CASE_PROVENANCE_PARENT_DUPLICATE")
        ancestor_values = tuple(
            reference
            for parent in values
            for reference in (parent.artifact_ref, *parent.ancestor_artifact_refs)
        )
        ancestor_refs = self._unique_refs(ancestor_values)
        if version_ref_key(artifact) in {
            version_ref_key(reference) for reference in ancestor_refs
        }:
            raise CaseProvenanceError("CASE_PROVENANCE_CYCLE")

        cases = _merge_exact_records(
            (
                contribution
                for parent in values
                for contribution in parent.case_contributions
            ),
            key=lambda item: version_ref_key(item.case_ref),
            conflict_code="CASE_CONTRIBUTION_VERSION_CONFLICT",
        )
        direct_independent = tuple(
            IndependentEvidence.model_validate(item) for item in independent_evidence
        )
        self._assert_authoritative_sources((), direct_independent)
        independent = _merge_exact_records(
            (evidence for parent in values for evidence in parent.independent_evidence),
            key=lambda item: version_ref_key(item.evidence_ref),
            conflict_code="INDEPENDENT_EVIDENCE_VERSION_CONFLICT",
        )
        independent = _merge_exact_records(
            (*independent, *direct_independent),
            key=lambda item: version_ref_key(item.evidence_ref),
            conflict_code="INDEPENDENT_EVIDENCE_VERSION_CONFLICT",
        )
        source_grade = self.recompute_grade(
            artifact_kind=artifact_kind,
            case_contributions=cases,
            independent_evidence=independent,
        )
        return self._record(
            operation_kind="propagate",
            operation_idempotency_key=operation_idempotency_key,
            artifact_ref=artifact,
            artifact_kind=artifact_kind,
            parent_provenance_refs=self._unique_refs(parent_refs),
            ancestor_artifact_refs=ancestor_refs,
            case_contributions=cases,
            independent_evidence=independent,
            derivation_rule_ref=rule,
            source_grade=source_grade,
        )

    def regenerate_from_exact_sources(
        self,
        artifact_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        *,
        case_contributions: Iterable[CaseContribution],
        independent_evidence: Iterable[IndependentEvidence],
        derivation_rule_ref: VersionRef,
        operation_idempotency_key: str | None = None,
    ) -> CaseProvenanceRecord:
        """Rebuild lineage from an explicit reduced input set.

        This is the only provenance entry point used by leave-one-out builds.
        It does not inherit the parent artifact closure; doing so would silently
        reintroduce the excluded contributor.
        """

        artifact = VersionRef.model_validate(artifact_ref)
        if artifact_kind == "case":
            raise CaseProvenanceError("LOO_CASE_ROOT_REGENERATION_FORBIDDEN")
        rule = self._approved_rule(derivation_rule_ref)
        cases = _merge_exact_records(
            (CaseContribution.model_validate(item) for item in case_contributions),
            key=lambda item: version_ref_key(item.case_ref),
            conflict_code="CASE_CONTRIBUTION_VERSION_CONFLICT",
        )
        independent = _merge_exact_records(
            (IndependentEvidence.model_validate(item) for item in independent_evidence),
            key=lambda item: version_ref_key(item.evidence_ref),
            conflict_code="INDEPENDENT_EVIDENCE_VERSION_CONFLICT",
        )
        if not cases and not independent:
            raise CaseProvenanceError("LOO_NO_REMAINING_EVIDENCE")
        self._assert_authoritative_sources(cases, independent)
        parent_refs = self._unique_refs(
            (
                *(item.source_provenance_ref for item in cases),
                *(item.source_provenance_ref for item in independent),
            )
        )
        ancestor_refs = self._unique_refs(
            (
                *(item.case_ref for item in cases),
                *(item.evidence_ref for item in independent),
            )
        )
        source_grade = self.recompute_grade(
            artifact_kind=artifact_kind,
            case_contributions=cases,
            independent_evidence=independent,
        )
        return self._record(
            operation_kind="regenerate_from_exact_sources",
            operation_idempotency_key=operation_idempotency_key,
            artifact_ref=artifact,
            artifact_kind=artifact_kind,
            parent_provenance_refs=parent_refs,
            ancestor_artifact_refs=ancestor_refs,
            case_contributions=cases,
            independent_evidence=independent,
            derivation_rule_ref=rule,
            source_grade=source_grade,
        )

    @staticmethod
    def recompute_grade(
        *,
        artifact_kind: CaseArtifactKind,
        case_contributions: tuple[CaseContribution, ...],
        independent_evidence: tuple[IndependentEvidence, ...],
    ) -> SourceGrade:
        del artifact_kind
        return recompute_case_source_grade(case_contributions, independent_evidence)

    def _record(
        self,
        *,
        operation_kind: Literal[
            "root_case", "propagate", "regenerate_from_exact_sources"
        ],
        operation_idempotency_key: str | None,
        artifact_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        parent_provenance_refs: tuple[VersionRef, ...],
        ancestor_artifact_refs: tuple[VersionRef, ...],
        case_contributions: tuple[CaseContribution, ...],
        independent_evidence: tuple[IndependentEvidence, ...],
        derivation_rule_ref: VersionRef,
        source_grade: SourceGrade,
    ) -> CaseProvenanceRecord:
        contributor_hashes = frozenset(
            value
            for item in case_contributions
            for value in item.contributor_client_hashes
        )
        if case_contributions and independent_evidence:
            scope: CaseProvenanceScope = "mixed"
        elif case_contributions:
            scope = "case_derived"
        else:
            scope = "global_source"
        source_sets: list[frozenset[str]] = [
            item.allowed_uses for item in case_contributions
        ]
        source_sets.extend(item.allowed_uses for item in independent_evidence)
        if not source_sets:
            raise CaseProvenanceError("CASE_PROVENANCE_SOURCE_REQUIRED")
        allowed_uses = set(source_sets[0])
        for value in source_sets[1:]:
            allowed_uses.intersection_update(value)
        if not allowed_uses:
            raise CaseProvenanceError("CASE_PROVENANCE_USE_INTERSECTION_EMPTY")
        expiries = [
            item.effective_to
            for item in case_contributions
            if item.effective_to is not None
        ]
        expiries.extend(
            item.effective_to
            for item in independent_evidence
            if item.effective_to is not None
        )
        effective_to = min(expiries) if expiries else None
        request_sha256 = canonical_sha256(
            {
                "ancestor_artifact_refs": [
                    item.model_dump(mode="json") for item in ancestor_artifact_refs
                ],
                "artifact_kind": artifact_kind,
                "artifact_ref": artifact_ref.model_dump(mode="json"),
                "case_contributions": [
                    item.model_dump(mode="json") for item in case_contributions
                ],
                "derivation_rule_ref": derivation_rule_ref.model_dump(mode="json"),
                "independent_evidence": [
                    item.model_dump(mode="json") for item in independent_evidence
                ],
                "operation_kind": operation_kind,
                "parent_provenance_refs": [
                    item.model_dump(mode="json") for item in parent_provenance_refs
                ],
                "policy_manifest_ref": self._policy_manifest_ref.model_dump(
                    mode="json"
                ),
                "source_grade": source_grade,
            }
        )
        checked_idempotency_key = self._validate_idempotency_key(
            operation_idempotency_key
        )
        if checked_idempotency_key is None:
            return self._create_record(
                artifact_ref=artifact_ref,
                artifact_kind=artifact_kind,
                parent_provenance_refs=parent_provenance_refs,
                ancestor_artifact_refs=ancestor_artifact_refs,
                case_contributions=case_contributions,
                independent_evidence=independent_evidence,
                contributor_hashes=contributor_hashes,
                derivation_rule_ref=derivation_rule_ref,
                source_grade=source_grade,
                scope=scope,
                allowed_uses=frozenset(allowed_uses),
                effective_to=effective_to,
            )
        with self._idempotency_lock:
            existing = self._idempotency_records.get(checked_idempotency_key)
            if existing is not None:
                existing_request_sha256, existing_record = existing
                if not hmac.compare_digest(
                    existing_request_sha256,
                    request_sha256,
                ):
                    raise CaseProvenanceError("CASE_PROVENANCE_IDEMPOTENCY_CONFLICT")
                return existing_record
            record = self._create_record(
                artifact_ref=artifact_ref,
                artifact_kind=artifact_kind,
                parent_provenance_refs=parent_provenance_refs,
                ancestor_artifact_refs=ancestor_artifact_refs,
                case_contributions=case_contributions,
                independent_evidence=independent_evidence,
                contributor_hashes=contributor_hashes,
                derivation_rule_ref=derivation_rule_ref,
                source_grade=source_grade,
                scope=scope,
                allowed_uses=frozenset(allowed_uses),
                effective_to=effective_to,
            )
            self._idempotency_records[checked_idempotency_key] = (
                request_sha256,
                record,
            )
            return record

    def _create_record(
        self,
        *,
        artifact_ref: VersionRef,
        artifact_kind: CaseArtifactKind,
        parent_provenance_refs: tuple[VersionRef, ...],
        ancestor_artifact_refs: tuple[VersionRef, ...],
        case_contributions: tuple[CaseContribution, ...],
        independent_evidence: tuple[IndependentEvidence, ...],
        contributor_hashes: frozenset[str],
        derivation_rule_ref: VersionRef,
        source_grade: SourceGrade,
        scope: CaseProvenanceScope,
        allowed_uses: frozenset[str],
        effective_to: UtcDateTime | None,
    ) -> CaseProvenanceRecord:
        provenance_id = self._ids.object_id("case_provenance")
        version = 1
        closure_sha256 = canonical_sha256(
            case_provenance_payload(
                provenance_id=provenance_id,
                version=version,
                artifact_ref=artifact_ref,
                artifact_kind=artifact_kind,
                parent_provenance_refs=parent_provenance_refs,
                ancestor_artifact_refs=ancestor_artifact_refs,
                case_contributions=case_contributions,
                independent_evidence=independent_evidence,
                contributor_client_hashes=contributor_hashes,
                derivation_rule_ref=derivation_rule_ref,
                policy_manifest_ref=self._policy_manifest_ref,
                source_grade=source_grade,
                provenance_scope=scope,
                allowed_uses=allowed_uses,
                effective_to=effective_to,
            )
        )
        record = CaseProvenanceRecord(
            provenance_ref=VersionRef(
                object_id=provenance_id,
                version=version,
                content_sha256=closure_sha256,
            ),
            artifact_ref=artifact_ref,
            artifact_kind=artifact_kind,
            parent_provenance_refs=parent_provenance_refs,
            ancestor_artifact_refs=ancestor_artifact_refs,
            case_contributions=case_contributions,
            independent_evidence=independent_evidence,
            contributor_client_hashes=contributor_hashes,
            derivation_rule_ref=derivation_rule_ref,
            policy_manifest_ref=self._policy_manifest_ref,
            source_grade=source_grade,
            provenance_scope=scope,
            allowed_uses=allowed_uses,
            effective_to=effective_to,
            closure_sha256=closure_sha256,
        )
        self._register_minted_record(record)
        return record

    def _register_minted_record(self, record: CaseProvenanceRecord) -> None:
        value = self._parse_provenance_record(record)
        key = version_ref_key(value.provenance_ref)
        stable = stable_version_ref_key(value.provenance_ref)
        with self._provenance_lock:
            existing_key = self._minted_stable_versions.get(stable)
            if existing_key is not None and existing_key != key:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_REFERENCE_VERSION_CONFLICT"
                )
            existing = self._minted_provenance.get(key)
            if existing is not None and existing != value:
                raise CaseProvenanceError(
                    "CASE_PROVENANCE_PARENT_REFERENCE_MISMATCH"
                )
            self._minted_stable_versions[stable] = key
            self._minted_provenance[key] = value

    @staticmethod
    def _validate_idempotency_key(value: str | None) -> str | None:
        if value is None:
            return None
        if type(value) is not str or _IDEMPOTENCY_KEY_RE.fullmatch(value) is None:
            raise CaseProvenanceError("CASE_PROVENANCE_IDEMPOTENCY_KEY_INVALID")
        return value

    def _assert_authoritative_sources(
        self,
        case_contributions: Iterable[CaseContribution],
        independent_evidence: Iterable[IndependentEvidence],
    ) -> None:
        checked_at = self._checked_now()
        for contribution in case_contributions:
            self._assert_case_contribution_authority(
                CaseContribution.model_validate(contribution),
                checked_at=checked_at,
            )
        for evidence in independent_evidence:
            self._assert_independent_evidence_authority(
                IndependentEvidence.model_validate(evidence),
                checked_at=checked_at,
            )

    def _assert_case_contribution_authority(
        self,
        contribution: CaseContribution,
        *,
        checked_at: UtcDateTime | None = None,
    ) -> None:
        authority = self._authority
        if authority is None:
            raise CaseProvenanceError("CASE_SOURCE_AUTHORITY_RESOLVER_REQUIRED")
        value = CaseContribution.model_validate(contribution)
        try:
            resolved = authority.resolve_case_contribution(
                case_ref=value.case_ref,
                source_provenance_ref=value.source_provenance_ref,
                authorization_ref=value.authorization_ref,
            )
        except Exception:
            raise CaseProvenanceError(
                "CASE_CONTRIBUTION_AUTHORITY_RESOLUTION_FAILED"
            ) from None
        if resolved is None:
            raise CaseProvenanceError("CASE_CONTRIBUTION_AUTHORITY_NOT_FOUND")
        if type(resolved) is not CaseContributionAuthority:
            raise CaseProvenanceError("CASE_CONTRIBUTION_AUTHORITY_INVALID")
        authoritative = resolved.contribution
        if (
            authoritative.case_ref != value.case_ref
            or authoritative.source_provenance_ref != value.source_provenance_ref
            or authoritative.authorization_ref != value.authorization_ref
            or authoritative.contributor_client_hashes
            != value.contributor_client_hashes
            or authoritative.source_grade != value.source_grade
            or authoritative.allowed_uses != value.allowed_uses
            or authoritative.effective_to != value.effective_to
            or authoritative.source_lineage_sha256 != value.source_lineage_sha256
        ):
            raise CaseProvenanceError("CASE_CONTRIBUTION_AUTHORITY_MISMATCH")
        self._assert_live_authority(
            resolved.authority_state,
            effective_to=value.effective_to,
            checked_at=self._checked_now() if checked_at is None else checked_at,
            source_kind="CASE_CONTRIBUTION",
        )

    def _assert_independent_evidence_authority(
        self,
        evidence: IndependentEvidence,
        *,
        checked_at: UtcDateTime | None = None,
    ) -> None:
        authority = self._authority
        if authority is None:
            raise CaseProvenanceError("CASE_SOURCE_AUTHORITY_RESOLVER_REQUIRED")
        value = IndependentEvidence.model_validate(evidence)
        try:
            resolved = authority.resolve_independent_evidence(
                evidence_ref=value.evidence_ref,
                source_provenance_ref=value.source_provenance_ref,
            )
        except Exception:
            raise CaseProvenanceError(
                "INDEPENDENT_EVIDENCE_AUTHORITY_RESOLUTION_FAILED"
            ) from None
        if resolved is None:
            raise CaseProvenanceError("INDEPENDENT_EVIDENCE_AUTHORITY_NOT_FOUND")
        if type(resolved) is not IndependentEvidenceAuthority:
            raise CaseProvenanceError("INDEPENDENT_EVIDENCE_AUTHORITY_INVALID")
        authoritative = resolved.evidence
        if (
            authoritative.evidence_ref != value.evidence_ref
            or authoritative.source_provenance_ref != value.source_provenance_ref
            or authoritative.source_grade != value.source_grade
            or authoritative.allowed_uses != value.allowed_uses
            or authoritative.effective_to != value.effective_to
            or authoritative.source_lineage_sha256 != value.source_lineage_sha256
        ):
            raise CaseProvenanceError("INDEPENDENT_EVIDENCE_AUTHORITY_MISMATCH")
        self._assert_live_authority(
            resolved.authority_state,
            effective_to=value.effective_to,
            checked_at=self._checked_now() if checked_at is None else checked_at,
            source_kind="INDEPENDENT_EVIDENCE",
        )

    @staticmethod
    def _assert_live_authority(
        state: SourceAuthorityState,
        *,
        effective_to: UtcDateTime | None,
        checked_at: UtcDateTime,
        source_kind: Literal["CASE_CONTRIBUTION", "INDEPENDENT_EVIDENCE"],
    ) -> None:
        if state == "revoked":
            raise CaseProvenanceError(f"{source_kind}_AUTHORITY_REVOKED")
        if state == "unauthorized":
            raise CaseProvenanceError(f"{source_kind}_NOT_AUTHORIZED")
        if state == "expired" or (
            effective_to is not None and effective_to <= checked_at
        ):
            raise CaseProvenanceError(f"{source_kind}_AUTHORITY_EXPIRED")
        if state != "active":
            raise CaseProvenanceError(f"{source_kind}_AUTHORITY_INVALID")

    def _checked_now(self) -> UtcDateTime:
        try:
            return _UTC_ADAPTER.validate_python(self._clock.now())
        except Exception:
            raise CaseProvenanceError("CASE_PROVENANCE_CLOCK_INVALID") from None

    def _approved_rule(self, value: VersionRef) -> VersionRef:
        rule = VersionRef.model_validate(value)
        if version_ref_key(rule) not in self._approved_rules:
            raise CaseProvenanceError("CASE_DERIVATION_RULE_NOT_APPROVED")
        return rule

    @staticmethod
    def _unique_refs(values: Iterable[VersionRef]) -> tuple[VersionRef, ...]:
        merged: dict[tuple[str, int, str], VersionRef] = {}
        stable_versions: dict[tuple[str, int], tuple[str, int, str]] = {}
        for item in values:
            key = version_ref_key(item)
            stable = stable_version_ref_key(item)
            existing = stable_versions.get(stable)
            if existing is not None and existing != key:
                raise CaseProvenanceError("CASE_PROVENANCE_REFERENCE_VERSION_CONFLICT")
            stable_versions[stable] = key
            merged[key] = item
        return tuple(merged[key] for key in sorted(merged))


__all__ = [
    "CaseContributionAuthority",
    "CaseContributorHasher",
    "CaseProvenanceError",
    "CaseProvenanceRecordResolver",
    "CaseProvenanceService",
    "CaseSourceAuthorityResolver",
    "IndependentEvidenceAuthority",
    "SourceAuthorityState",
]
