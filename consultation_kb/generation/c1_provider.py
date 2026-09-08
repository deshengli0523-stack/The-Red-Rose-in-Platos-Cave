"""Production deterministic provider for counselor-authored C1 applicability."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from consultation_kb.core.clock import Clock, FixedClock, SystemClock
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.generation.retrieval_orchestrator import GenerationC1Context
from consultation_kb.knowledge.applicability import (
    ApplicabilityGate,
    ApplicabilityPolicyError,
    ScopePolicyManifest,
)
from consultation_kb.knowledge.scope_policy import (
    ScopePolicyError,
    ScopePolicyRepository,
)
from consultation_kb.knowledge.theory import (
    TheoryGovernanceError,
    TheoryRevisionService,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import C1ApplicabilityDecision
from consultation_kb.models.scope_policy import ScopePolicyDocument
from consultation_kb.models.theory import TheoryRevision
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    DerivedAuthorityObjectVersion,
)
from consultation_kb.retrieval.artifact_discovery import ActiveRetrievalArtifactSet
from consultation_kb.retrieval.evidence_pack import C1PolicyVocabulary
from consultation_kb.vault.content_store import ContentStore


class GenerationC1ProviderError(RuntimeError):
    """One content-free, fixed-code C1 authority or input failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _ActiveClosure:
    builder_input: DerivedArtifactBuilderInputV2
    active_theory_object: DerivedAuthorityObjectVersion | None


def _theory_ref_from_row(row: sqlite3.Row | tuple[object, ...]) -> VersionRef:
    try:
        return VersionRef(
            object_id=str(row[0]),
            version=int(str(row[1])),
            content_sha256=str(row[2]),
        )
    except (TypeError, ValueError):
        raise GenerationC1ProviderError("GENERATION_C1_AUTHORITY_INVALID") from None


def _policy_vocabulary(
    reference: VersionRef,
    document: ScopePolicyDocument,
) -> C1PolicyVocabulary:
    return C1PolicyVocabulary(
        scope_policy_ref=reference,
        approved_rule_ids=document.rule_members,
        approved_context_fields=document.context_fields,
    )


class DeterministicGenerationC1Provider:
    """Resolve C1 only from one active artifact/theory/policy closure.

    The caller supplies safe assertions, never a decision.  Every call rereads
    the active SQLite and CAS authorities, and validity is evaluated at the
    immutable QueryPlan ``created_at`` rather than wall-clock completion time.
    """

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()

    def is_available(
        self,
        *,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        active_artifacts: ActiveRetrievalArtifactSet,
    ) -> bool:
        """Report structural availability without caching any authority read."""

        try:
            at = self._clock.now()
            closure = self._active_closure(
                global_connection,
                active_artifacts,
                expected_epoch=active_artifacts.active_runtime_epoch,
            )
            rows = self._active_theory_rows(global_connection)
            if len(rows) > 1:
                raise GenerationC1ProviderError(
                    "GENERATION_C1_SELECTION_AMBIGUOUS"
                )
            policies = ScopePolicyRepository(
                global_connection,
                content_store=global_content_store,
                clock=FixedClock(at),
            )
            if not rows:
                if closure.active_theory_object is not None:
                    raise GenerationC1ProviderError(
                        "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
                    )
                self._unique_effective_policy(
                    global_connection, policies, at=at
                )
            else:
                reference = _theory_ref_from_row(rows[0])
                if not self._artifact_theory_matches(closure, rows[0]):
                    raise GenerationC1ProviderError(
                        "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
                    )
                theory = self._load_theory(
                    global_connection,
                    global_content_store,
                    policies,
                    closure,
                    reference,
                    at=at,
                )
                policy = policies.resolve_approved(theory.scope_policy_ref, at=at)
                self._validate_theory_vocabulary(theory, policy)
            self._verify_active_fresh(active_artifacts)
            return True
        except Exception:
            return False

    def resolve(
        self,
        plan: QueryPlan,
        applicability_input: C1ApplicabilityInput,
        *,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        active_artifacts: ActiveRetrievalArtifactSet,
    ) -> GenerationC1Context:
        try:
            if not isinstance(global_connection, sqlite3.Connection):
                raise GenerationC1ProviderError(
                    "GENERATION_C1_GLOBAL_CONNECTION_REQUIRED"
                )
            if type(global_content_store) is not ContentStore:
                raise GenerationC1ProviderError(
                    "GENERATION_C1_CONTENT_STORE_REQUIRED"
                )
            exact_plan = QueryPlan.model_validate(plan, strict=True)
            exact_input = C1ApplicabilityInput.model_validate(
                applicability_input, strict=True
            )
            exact_input.assert_plan_closure(exact_plan)
            closure = self._active_closure(
                global_connection,
                active_artifacts,
                expected_epoch=exact_plan.global_runtime_epoch,
            )
            rows = self._active_theory_rows(global_connection)
            if len(rows) > 1:
                raise GenerationC1ProviderError(
                    "GENERATION_C1_SELECTION_AMBIGUOUS"
                )

            at = exact_plan.envelope.created_at
            policies = ScopePolicyRepository(
                global_connection,
                content_store=global_content_store,
                clock=FixedClock(at),
            )
            if not rows:
                if closure.active_theory_object is not None:
                    raise GenerationC1ProviderError(
                        "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
                    )
                policy_ref, policy = self._unique_effective_policy(
                    global_connection,
                    policies,
                    at=at,
                )
                self._validate_input_vocabulary(exact_input, policy)
                result = GenerationC1Context(
                    decision=C1ApplicabilityDecision(
                        status="unavailable",
                        revision=None,
                        scope_policy_ref=policy_ref,
                        matched_rule_ids=(),
                        missing_context_fields=(),
                        effective_status="none",
                        empirical_support="unassessed",
                        conflict_evidence_ids=(),
                    ),
                    vocabulary=_policy_vocabulary(policy_ref, policy),
                    structured_context_trusted=True,
                    applicability_input_sha256=exact_input.canonical_sha256,
                )
                self._verify_active_fresh(active_artifacts)
                return result

            reference = _theory_ref_from_row(rows[0])
            if not self._artifact_theory_matches(closure, rows[0]):
                raise GenerationC1ProviderError(
                    "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
                )
            theory = self._load_theory(
                global_connection,
                global_content_store,
                policies,
                closure,
                reference,
                at=at,
            )
            policy = policies.resolve_approved(theory.scope_policy_ref, at=at)
            self._validate_theory_vocabulary(theory, policy)
            self._validate_input_vocabulary(exact_input, policy)
            active = theory.effective_from <= at and (
                theory.effective_to is None or at < theory.effective_to
            )
            gate = ApplicabilityGate(
                ScopePolicyManifest(
                    policy_ref=theory.scope_policy_ref,
                    rule_members=policy.rule_members,
                    context_fields=policy.context_fields,
                )
            )
            decision = gate.evaluate(
                revision=reference,
                scope=theory.scope,
                context=exact_input.context_values(),
                effective_status="active" if active else "expired",
                empirical_support=theory.empirical_support,
            )
            result = GenerationC1Context(
                decision=decision,
                vocabulary=_policy_vocabulary(theory.scope_policy_ref, policy),
                structured_context_trusted=True,
                applicability_input_sha256=exact_input.canonical_sha256,
            )
            self._verify_active_fresh(active_artifacts)
            return result
        except GenerationC1ProviderError:
            raise
        except ScopePolicyError as error:
            raise GenerationC1ProviderError(error.code) from None
        except ApplicabilityPolicyError as error:
            raise GenerationC1ProviderError(str(error)) from None
        except (TheoryGovernanceError, sqlite3.Error, TypeError, ValueError, OSError):
            raise GenerationC1ProviderError("GENERATION_C1_AUTHORITY_INVALID") from None

    @staticmethod
    def _active_theory_rows(
        connection: sqlite3.Connection,
    ) -> tuple[tuple[object, ...], ...]:
        try:
            rows = connection.execute(
                "SELECT theory_id, revision, revision_sha256, revision_object_ref "
                "FROM theory_revisions WHERE status = 'ACTIVE' "
                "ORDER BY theory_id, revision"
            ).fetchall()
        except sqlite3.Error:
            raise GenerationC1ProviderError(
                "GENERATION_C1_AUTHORITY_INVALID"
            ) from None
        return tuple(tuple(row) for row in rows)

    @staticmethod
    def _active_closure(
        connection: sqlite3.Connection,
        active: ActiveRetrievalArtifactSet,
        *,
        expected_epoch: int,
    ) -> _ActiveClosure:
        if (
            type(active) is not ActiveRetrievalArtifactSet
            or active.active_runtime_epoch != expected_epoch
        ):
            raise GenerationC1ProviderError(
                "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
            )
        values: list[DerivedArtifactBuilderInputV2] = []
        try:
            for binding in active.bindings():
                binding.verify_authority_connection(connection)
                identity = binding.verify_current()
                role = f"{identity.artifact_key}_builder_input"
                value = DerivedArtifactBuilderInputV2.model_validate_json(
                    binding.path_for(role).read_bytes(),
                    strict=True,
                )
                if (
                    value.target_runtime_epoch != expected_epoch
                    or value.source_catalog_version != active.source_catalog_version
                ):
                    raise ValueError
                values.append(value)
            first = values[0]
            shared = (
                first.authority_closure_sha256,
                first.authority_snapshot,
                first.retrieval_input_descriptor,
                first.target_runtime_epoch,
            )
            if len(values) != 5 or any(
                (
                    value.authority_closure_sha256,
                    value.authority_snapshot,
                    value.retrieval_input_descriptor,
                    value.target_runtime_epoch,
                )
                != shared
                for value in values
            ):
                raise ValueError
            return _ActiveClosure(
                builder_input=first,
                active_theory_object=first.authority_snapshot.theory,
            )
        except GenerationC1ProviderError:
            raise
        except Exception:
            raise GenerationC1ProviderError(
                "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
            ) from None

    @staticmethod
    def _unique_effective_policy(
        connection: sqlite3.Connection,
        repository: ScopePolicyRepository,
        *,
        at: datetime,
    ) -> tuple[VersionRef, ScopePolicyDocument]:
        try:
            rows = connection.execute(
                "SELECT policy_id, version, semantic_sha256 "
                "FROM scope_policy_versions WHERE status = 'APPROVED' "
                "ORDER BY policy_id, version"
            ).fetchall()
        except sqlite3.Error:
            raise GenerationC1ProviderError(
                "GENERATION_C1_POLICY_UNAVAILABLE"
            ) from None
        effective: list[tuple[VersionRef, ScopePolicyDocument]] = []
        for row in rows:
            reference = _theory_ref_from_row(row)
            try:
                document = repository.resolve_approved(reference, at=at)
            except ScopePolicyError as error:
                if error.code == "SCOPE_POLICY_NOT_EFFECTIVE":
                    continue
                raise
            effective.append((reference, document))
        if not effective:
            raise GenerationC1ProviderError("GENERATION_C1_POLICY_UNAVAILABLE")
        if len(effective) != 1:
            raise GenerationC1ProviderError("GENERATION_C1_POLICY_AMBIGUOUS")
        return effective[0]

    @staticmethod
    def _artifact_theory_matches(
        closure: _ActiveClosure,
        row: tuple[object, ...],
    ) -> bool:
        artifact = closure.active_theory_object
        object_ref = str(row[3]) if len(row) > 3 else ""
        return bool(
            artifact is not None
            and artifact.object_id == str(row[0])
            and artifact.version == int(str(row[1]))
            and object_ref.startswith("sha256:")
            and artifact.object_sha256 == object_ref.removeprefix("sha256:")
        )

    @staticmethod
    def _load_theory(
        connection: sqlite3.Connection,
        store: ContentStore,
        policies: ScopePolicyRepository,
        closure: _ActiveClosure,
        reference: VersionRef,
        *,
        at: datetime,
    ) -> TheoryRevision:
        theory = TheoryRevisionService(
            connection=connection,
            content_store=store,
            clock=FixedClock(at),
            scope_policy_repository=policies,
        ).get_by_ref(reference)
        if theory.status != "active":
            raise GenerationC1ProviderError("GENERATION_C1_AUTHORITY_INVALID")
        descriptor = closure.builder_input.retrieval_input_descriptor
        claim_records = {
            record.candidate_ref: record
            for record in descriptor.records
            if record.candidate_ref in set(theory.claim_refs)
        }
        if set(claim_records) != set(theory.claim_refs):
            raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")
        if not set(theory.passage_refs) <= {
            record.content_ref for record in claim_records.values()
        }:
            raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")

        source = connection.execute(
            "SELECT sv.content_sha256, sv.source_grade, sv.status, s.logical_path "
            "FROM source_versions AS sv JOIN sources AS s "
            "ON s.source_id = sv.source_id "
            "WHERE sv.source_id = ? AND sv.version = ?",
            (theory.source_ref.object_id, theory.source_ref.version),
        ).fetchone()
        if (
            source is None
            or str(source[0]) != theory.source_ref.content_sha256
            or str(source[1]) != "C1"
            or str(source[2]) != "APPROVED"
            or str(source[3]).split("/", 1)[0].lower() != "consultant-theory"
        ):
            raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")
        for citation in theory.citation_refs:
            row = connection.execute(
                "SELECT content_sha256, status FROM source_versions "
                "WHERE source_id = ? AND version = ?",
                (citation.object_id, citation.version),
            ).fetchone()
            if row != (citation.content_sha256, "APPROVED"):
                raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")
        passage_rows = connection.execute(
            "SELECT trp.passage_id, trp.passage_version, p.normalized_text_sha256, "
            "p.review_status, p.privacy_scope, trp.ordinal "
            "FROM theory_revision_passages AS trp JOIN passages AS p "
            "ON p.passage_id = trp.passage_id AND p.version = trp.passage_version "
            "WHERE trp.theory_id = ? AND trp.theory_revision = ? "
            "ORDER BY trp.ordinal",
            (theory.theory_id, theory.revision),
        ).fetchall()
        database_passages = tuple(
            VersionRef(
                object_id=str(row[0]),
                version=int(row[1]),
                content_sha256=str(row[2]),
            )
            for row in passage_rows
        )
        if database_passages != theory.passage_refs or any(
            str(row[3]) != "APPROVED" or str(row[4]) != "GLOBAL"
            for row in passage_rows
        ):
            raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")
        claim_rows = connection.execute(
            "SELECT claim_id, version, claim_sha256, review_status, "
            "theory_revision_id, theory_revision, theory_revision_sha256 "
            "FROM claims WHERE theory_revision_id = ? AND theory_revision = ? "
            "ORDER BY claim_id, version",
            (theory.theory_id, theory.revision),
        ).fetchall()
        if {
            VersionRef(
                object_id=str(row[0]),
                version=int(row[1]),
                content_sha256=str(row[2]),
            )
            for row in claim_rows
        } != set(theory.claim_refs) or any(
            str(row[3]) != "APPROVED"
            or str(row[4]) != theory.theory_id
            or int(row[5]) != theory.revision
            or str(row[6]) != reference.content_sha256
            for row in claim_rows
        ):
            raise GenerationC1ProviderError("GENERATION_C1_ORPHAN_REF")
        return theory

    @staticmethod
    def _validate_input_vocabulary(
        applicability_input: C1ApplicabilityInput,
        policy: ScopePolicyDocument,
    ) -> None:
        by_field = {
            item.context_field: item.value_members
            for item in policy.field_value_members
        }
        input_fields = {
            *(item.context_field for item in applicability_input.assertions),
            *applicability_input.known_empty_fields,
        }
        if not input_fields <= policy.context_fields:
            raise GenerationC1ProviderError("POLICY_KEY_NOT_APPROVED")
        for assertion in applicability_input.assertions:
            if not set(assertion.value_keys) <= by_field[assertion.context_field]:
                raise GenerationC1ProviderError("POLICY_VALUE_NOT_APPROVED")

    @staticmethod
    def _validate_theory_vocabulary(
        theory: TheoryRevision,
        policy: ScopePolicyDocument,
    ) -> None:
        by_field = {
            item.context_field: item.value_members
            for item in policy.field_value_members
        }
        theory_values = {
            "domain": theory.scope.domains,
            "population": theory.scope.populations,
            "context": theory.scope.contexts,
            "conditions": theory.scope.required_conditions,
            "exclusions": theory.scope.exclusions,
            "contraindications": theory.scope.contraindications,
        }
        for field, values in theory_values.items():
            if values and (
                field not in by_field or not set(values) <= by_field[field]
            ):
                raise GenerationC1ProviderError(
                    "GENERATION_C1_THEORY_POLICY_VOCABULARY_MISMATCH"
                )

    @staticmethod
    def _verify_active_fresh(active: ActiveRetrievalArtifactSet) -> None:
        try:
            for binding in active.bindings():
                binding.verify_current()
        except Exception:
            raise GenerationC1ProviderError(
                "GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH"
            ) from None


__all__ = [
    "DeterministicGenerationC1Provider",
    "GenerationC1ProviderError",
]
