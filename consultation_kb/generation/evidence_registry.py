"""Client-scoped, append-only registry for trusted generation EvidencePacks.

The public generation tool never accepts a caller-asserted pack as authority.
Only the control-plane retrieval composition may register a pack through the
scoped worker.  Later stage validators resolve the exact immutable bytes from
this registry and recompute their canonical hash before use.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime
from typing import Annotated, Literal, cast

from pydantic import Field, field_validator, model_validator

from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.models.common import (
    NonNegativeInt,
    NonEmptyStr,
    ObjectId,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EvidenceChannel,
    EvidencePack,
    Provenance,
)
from consultation_kb.models.session import StoredContentRef
from consultation_kb.retrieval.contracts import ExclusionProof, canonical_json_bytes
from consultation_kb.risk.repository import RiskEvaluationAuthorityBinding
from consultation_kb.session.repository import SessionRepository
from consultation_kb.storage.connection import transaction


_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")


class GenerationEvidenceRegistryError(RuntimeError):
    """A fixed-code failure at the trusted EvidencePack boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GenerationEvidenceBindingMismatch(GenerationEvidenceRegistryError):
    def __init__(self) -> None:
        super().__init__("GENERATION_BINDING_MISMATCH")


class GenerationEvidenceConflict(GenerationEvidenceRegistryError):
    def __init__(self) -> None:
        super().__init__("GENERATION_STAGE_CONFLICT")


class GenerationRunObject(StrictModel):
    object_type: Literal["authority_snapshot", "exclusion_proof", "provenance"]
    reference: VersionRef
    canonical_json: str

    @model_validator(mode="after")
    def _exact_bytes(self) -> "GenerationRunObject":
        try:
            encoded = self.canonical_json.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("generation run object is not UTF-8") from None
        if (
            not encoded
            or self.reference.object_id[:-37] != self.object_type
            or self.reference.version != 1
            or hashlib.sha256(encoded).hexdigest()
            != self.reference.content_sha256
            or deterministic_object_id(
                self.object_type,
                self.reference.content_sha256,
            )
            != self.reference.object_id
        ):
            raise ValueError("generation run object reference mismatch")
        if self.object_type == "authority_snapshot":
            value: StrictModel = AuthoritativeFilterSnapshot.model_validate_json(
                encoded,
                strict=True,
            )
        elif self.object_type == "exclusion_proof":
            value = ExclusionProof.model_validate_json(encoded, strict=True)
        else:
            value = Provenance.model_validate_json(encoded, strict=True)
        if canonical_json_bytes(value.model_dump(mode="json")) != encoded:
            raise ValueError("generation run object is not canonical")
        return self

    def bytes(self) -> bytes:
        return self.canonical_json.encode("utf-8")


class GenerationCandidateProofSource(StrictModel):
    """Exact selected candidate metadata/body closure used by one proof."""

    evidence_id: ObjectId
    pack_role: Literal["supporting", "contradicting"]
    candidate_ref: VersionRef
    text_ref: VersionRef
    provenance_ref: VersionRef
    channel: EvidenceChannel
    object_type: SafePolicyKey


class GenerationRiskContextBinding(StrictModel):
    """Worker-verified risk closure for this turn and the visible session set.

    The evaluation set proves that the exact turn completed under the pinned
    authority.  The visible set independently carries forward every open or
    acknowledged counselor-only observation from earlier turns.
    """

    turn_id: Uuid7String
    client_message_sha256: Sha256Hex
    authority: RiskEvaluationAuthorityBinding
    evaluation_observation_ids: tuple[ObjectId, ...]
    evaluation_set_sha256: Sha256Hex
    evaluation_count: NonNegativeInt
    visible_observation_ids: tuple[ObjectId, ...]
    visible_set_sha256: Sha256Hex
    visible_count: NonNegativeInt

    @field_validator("evaluation_observation_ids", "visible_observation_ids")
    @classmethod
    def _canonical_observation_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("risk context observation IDs must be canonical")
        return value

    @model_validator(mode="after")
    def _count_closure(self) -> "GenerationRiskContextBinding":
        if (
            self.evaluation_count != len(self.evaluation_observation_ids)
            or self.visible_count != len(self.visible_observation_ids)
        ):
            raise ValueError("risk context observation count mismatch")
        return self


class GenerationEvidenceTypeProof(StrictModel):
    """Deterministic proof for exactly one required subquery/type pair.

    The three proof kinds have disjoint source matrices.  In particular, C1
    authority and private risk evaluations are not disguised as retrieved
    candidates and therefore do not have to resolve in ``EvidencePack`` IDs.
    """

    subquery_id: SafePolicyKey
    evidence_type: Literal[
        "temporal_graph_edge",
        "theory_applicability",
        "theory_boundary",
        "case_provenance",
        "contradicting_evidence",
        "risk_context",
    ]
    proof_kind: Literal["candidate_selection", "c1_authority", "risk_evaluation"]
    evidence_ids: tuple[ObjectId, ...] = ()
    candidate_sources: tuple[GenerationCandidateProofSource, ...] = ()
    c1_revision_ref: VersionRef | None = None
    c1_scope_policy_ref: VersionRef | None = None
    c1_decision_status: Literal[
        "applicable", "not_applicable", "insufficient_context", "unavailable"
    ] | None = None
    c1_effective_status: Literal[
        "active", "expired", "superseded", "revoked", "none"
    ] | None = None
    risk_turn_id: Uuid7String | None = None
    risk_client_message_sha256: Sha256Hex | None = None
    risk_authority: RiskEvaluationAuthorityBinding | None = None
    risk_evaluation_observation_ids: tuple[ObjectId, ...] = ()
    risk_evaluation_set_sha256: Sha256Hex | None = None
    risk_evaluation_count: NonNegativeInt | None = None
    risk_visible_set_sha256: Sha256Hex | None = None
    risk_visible_count: NonNegativeInt | None = None

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence type proof IDs must be unique")
        return tuple(sorted(value))

    @field_validator("risk_evaluation_observation_ids")
    @classmethod
    def _canonical_risk_evaluation_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("risk evaluation observation IDs must be canonical")
        return value

    @field_validator("candidate_sources")
    @classmethod
    def _canonical_candidate_sources(
        cls,
        value: tuple[GenerationCandidateProofSource, ...],
    ) -> tuple[GenerationCandidateProofSource, ...]:
        identifiers = tuple(item.evidence_id for item in value)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence type proof sources must be unique")
        return tuple(sorted(value, key=lambda item: item.evidence_id))

    @model_validator(mode="after")
    def _proof_source_matrix(self) -> "GenerationEvidenceTypeProof":
        candidate_types = {
            "temporal_graph_edge",
            "case_provenance",
            "contradicting_evidence",
        }
        c1_types = {"theory_applicability", "theory_boundary"}
        c1_fields = (
            self.c1_revision_ref,
            self.c1_scope_policy_ref,
            self.c1_decision_status,
            self.c1_effective_status,
        )
        risk_fields = (
            self.risk_turn_id,
            self.risk_client_message_sha256,
            self.risk_authority,
            self.risk_evaluation_set_sha256,
            self.risk_evaluation_count,
            self.risk_visible_set_sha256,
            self.risk_visible_count,
        )
        if self.evidence_type in candidate_types:
            valid = (
                self.proof_kind == "candidate_selection"
                and bool(self.evidence_ids)
                and tuple(item.evidence_id for item in self.candidate_sources)
                == self.evidence_ids
                and not any(value is not None for value in c1_fields + risk_fields)
            )
        elif self.evidence_type in c1_types:
            has_exact_c1_matrix = (
                self.c1_scope_policy_ref is not None
                and self.c1_decision_status is not None
                and self.c1_effective_status is not None
                and (
                    (
                        self.c1_decision_status
                        in {"applicable", "not_applicable", "insufficient_context"}
                        and self.c1_effective_status == "active"
                        and self.c1_revision_ref is not None
                    )
                    or (
                        self.c1_decision_status == "unavailable"
                        and (
                            (
                                self.c1_effective_status == "none"
                                and self.c1_revision_ref is None
                            )
                            or (
                                self.c1_effective_status
                                in {"expired", "superseded", "revoked"}
                                and self.c1_revision_ref is not None
                            )
                        )
                    )
                )
            )
            valid = (
                self.proof_kind == "c1_authority"
                and not self.evidence_ids
                and not self.candidate_sources
                and has_exact_c1_matrix
                and not any(value is not None for value in risk_fields)
                and not self.risk_evaluation_observation_ids
            )
        else:
            valid = (
                self.proof_kind == "risk_evaluation"
                and not self.candidate_sources
                and not any(value is not None for value in c1_fields)
                and all(value is not None for value in risk_fields)
                and self.risk_evaluation_count
                == len(self.risk_evaluation_observation_ids)
                and self.risk_visible_count == len(self.evidence_ids)
            )
        if not valid:
            raise ValueError("evidence type proof source matrix mismatch")
        return self


class GenerationRetrievalMetadata(StrictModel):
    route_candidate_counts: dict[SafePolicyKey, NonNegativeInt]
    filtered_candidate_count: NonNegativeInt
    resolved_evidence_count: NonNegativeInt
    selected_evidence_count: NonNegativeInt
    degraded_components: tuple[SafePolicyKey, ...] = ()
    evidence_type_proofs: tuple[GenerationEvidenceTypeProof, ...] = ()

    @field_validator("route_candidate_counts")
    @classmethod
    def _canonical_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if any(type(count) is not int or count < 0 for count in value.values()):
            raise ValueError("retrieval counts must be non-negative integers")
        return dict(sorted(value.items()))

    @field_validator("degraded_components")
    @classmethod
    def _canonical_components(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("degraded components must be unique")
        return tuple(sorted(value))

    @field_validator("evidence_type_proofs")
    @classmethod
    def _canonical_evidence_type_proofs(
        cls,
        value: tuple[GenerationEvidenceTypeProof, ...],
    ) -> tuple[GenerationEvidenceTypeProof, ...]:
        keys = tuple((item.subquery_id, item.evidence_type) for item in value)
        if len(keys) != len(set(keys)):
            raise ValueError("evidence type proofs must be unique")
        return tuple(
            sorted(value, key=lambda item: (item.subquery_id, item.evidence_type))
        )


def validate_generation_evidence_type_proof_pack_closure(
    pack: EvidencePack | object,
    context: tuple["GenerationEvidenceContextItem", ...] | object,
    proofs: tuple[GenerationEvidenceTypeProof, ...] | object,
) -> tuple[GenerationEvidenceTypeProof, ...]:
    """Validate every proof against only immutable pack-local source closure."""

    values = EvidencePack.model_validate(pack, strict=True)
    try:
        exact_context = validate_generation_evidence_context(values, context)
    except GenerationEvidenceBindingMismatch:
        exact_context = validate_retrieved_generation_evidence_context(
            values,
            context,
        )
    if type(proofs) is not tuple:
        raise GenerationEvidenceBindingMismatch
    try:
        exact = tuple(
            GenerationEvidenceTypeProof.model_validate(item, strict=True)
            for item in proofs
        )
    except (TypeError, ValueError):
        raise GenerationEvidenceBindingMismatch from None
    keys = tuple((item.subquery_id, item.evidence_type) for item in exact)
    if keys != tuple(sorted(set(keys))):
        raise GenerationEvidenceBindingMismatch

    supporting = {item.evidence_id: item for item in values.supporting}
    contradicting = {item.evidence_id: item for item in values.contradicting}
    selected = {**supporting, **contradicting}
    context_by_id = {item.evidence_id: item for item in exact_context}
    decision = values.c1_applicability
    for proof in exact:
        if proof.proof_kind == "candidate_selection":
            for source in proof.candidate_sources:
                packed = selected.get(source.evidence_id)
                item_context = context_by_id.get(source.evidence_id)
                expected_role = (
                    "supporting"
                    if source.evidence_id in supporting
                    else "contradicting"
                )
                if (
                    packed is None
                    or item_context is None
                    or source.pack_role != expected_role
                    or source.text_ref != packed.text_ref
                    or source.provenance_ref != packed.provenance.provenance_ref
                    or source.channel != packed.channel
                    or item_context.context_kind != "retrieved_candidate"
                    or item_context.text_ref != source.text_ref
                    or hashlib.sha256(item_context.body.encode("utf-8")).hexdigest()
                    != source.text_ref.content_sha256
                ):
                    raise GenerationEvidenceBindingMismatch
                if proof.evidence_type == "temporal_graph_edge" and (
                    source.channel != "client_history"
                    or source.object_type != "client_graph"
                ):
                    raise GenerationEvidenceBindingMismatch
                if proof.evidence_type == "case_provenance" and (
                    source.channel != "case"
                    or packed.provenance.provenance_scope
                    not in {"case_derived", "mixed"}
                    or packed.provenance.client_exclusion_status
                    not in {
                        "no_subject_contribution",
                        "leave_one_subject_out_applied",
                    }
                ):
                    raise GenerationEvidenceBindingMismatch
                if proof.evidence_type == "contradicting_evidence" and (
                    source.pack_role != "contradicting"
                ):
                    raise GenerationEvidenceBindingMismatch
        elif proof.proof_kind == "c1_authority":
            if (
                proof.c1_decision_status != decision.status
                or proof.c1_revision_ref != decision.revision
                or proof.c1_scope_policy_ref != decision.scope_policy_ref
                or proof.c1_effective_status != decision.effective_status
            ):
                raise GenerationEvidenceBindingMismatch
        elif proof.proof_kind != "risk_evaluation":
            raise GenerationEvidenceBindingMismatch
    return exact


def validate_generation_required_evidence_proofs(
    plan: QueryPlan | object,
    pack: EvidencePack | object,
    context: tuple["GenerationEvidenceContextItem", ...] | object,
    proofs: tuple[GenerationEvidenceTypeProof, ...] | object,
    *,
    risk_context_binding: GenerationRiskContextBinding | None,
) -> tuple[GenerationEvidenceTypeProof, ...]:
    """Close one proof, no more and no less, for every required pair."""

    values = QueryPlan.model_validate(plan, strict=True)
    exact = validate_generation_evidence_type_proof_pack_closure(
        pack,
        context,
        proofs,
    )
    expected = tuple(
        sorted(
            (subquery.subquery_id, evidence_type)
            for subquery in values.subqueries
            for evidence_type in subquery.required_evidence_types
        )
    )
    actual = tuple((proof.subquery_id, proof.evidence_type) for proof in exact)
    if actual != expected or len(actual) != len(set(actual)):
        raise GenerationEvidenceBindingMismatch
    for proof in exact:
        if proof.evidence_type != "risk_context":
            continue
        binding = risk_context_binding
        if (
            binding is None
            or binding.turn_id != values.envelope.turn_id
            or proof.evidence_ids != binding.visible_observation_ids
            or proof.risk_turn_id != binding.turn_id
            or proof.risk_client_message_sha256 != binding.client_message_sha256
            or proof.risk_authority != binding.authority
            or proof.risk_evaluation_observation_ids
            != binding.evaluation_observation_ids
            or proof.risk_evaluation_set_sha256 != binding.evaluation_set_sha256
            or proof.risk_evaluation_count != binding.evaluation_count
            or proof.risk_visible_set_sha256 != binding.visible_set_sha256
            or proof.risk_visible_count != binding.visible_count
        ):
            raise GenerationEvidenceBindingMismatch
    return exact


class GenerationEvidenceContextItem(StrictModel):
    """One selected, filtered body exposed to the generation model.

    Deliberately limited to the pack-local evidence identifier, the exact text
    reference, and its verified UTF-8 body.  Client identifiers, provenance,
    authority internals, and source ownership never cross this boundary.
    """

    evidence_id: ObjectId
    context_kind: Literal["retrieved_candidate", "temporary_fact"]
    text_ref: VersionRef
    body: Annotated[NonEmptyStr, Field(max_length=500_000)]

    @model_validator(mode="after")
    def _exact_body(self) -> "GenerationEvidenceContextItem":
        try:
            encoded = self.body.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("generation evidence body is not UTF-8") from None
        if hashlib.sha256(encoded).hexdigest() != self.text_ref.content_sha256:
            raise ValueError("generation evidence body hash mismatch")
        if _CLIENT_ID_RE.search(self.body):
            raise ValueError("generation evidence body contains a client identifier")
        return self


def validate_generation_evidence_context(
    pack: EvidencePack | object,
    context: tuple[GenerationEvidenceContextItem, ...] | object,
) -> tuple[GenerationEvidenceContextItem, ...]:
    """Validate the frozen view of candidates plus every temporary fact."""

    return _validate_generation_evidence_context(
        pack,
        context,
        include_temporary_facts=True,
    )


def validate_retrieved_generation_evidence_context(
    pack: EvidencePack | object,
    context: tuple[GenerationEvidenceContextItem, ...] | object,
) -> tuple[GenerationEvidenceContextItem, ...]:
    """Validate the control-plane portion before worker-owned facts are merged."""

    return _validate_generation_evidence_context(
        pack,
        context,
        include_temporary_facts=False,
    )


def _validate_generation_evidence_context(
    pack: EvidencePack | object,
    context: tuple[GenerationEvidenceContextItem, ...] | object,
    *,
    include_temporary_facts: bool,
) -> tuple[GenerationEvidenceContextItem, ...]:

    values = EvidencePack.model_validate(pack, strict=True)
    if type(context) is not tuple:
        raise GenerationEvidenceBindingMismatch
    try:
        items = tuple(
            GenerationEvidenceContextItem.model_validate(item, strict=True)
            for item in context
        )
    except (TypeError, ValueError, UnicodeError):
        raise GenerationEvidenceBindingMismatch from None
    identifiers = tuple(item.evidence_id for item in items)
    if identifiers != tuple(sorted(set(identifiers))):
        raise GenerationEvidenceBindingMismatch
    selected: dict[str, tuple[VersionRef, str]] = {}
    for candidate in (*values.supporting, *values.contradicting):
        previous = selected.get(candidate.evidence_id)
        expected = (candidate.text_ref, "retrieved_candidate")
        if previous is not None and previous != expected:
            raise GenerationEvidenceBindingMismatch
        selected[candidate.evidence_id] = expected
    if include_temporary_facts:
        for reference in values.temporary_fact_refs:
            if reference.object_id in selected:
                raise GenerationEvidenceBindingMismatch
            selected[reference.object_id] = (reference, "temporary_fact")
    if set(identifiers) != set(selected):
        raise GenerationEvidenceBindingMismatch
    if any(
        (item.text_ref, item.context_kind) != selected[item.evidence_id]
        for item in items
    ):
        raise GenerationEvidenceBindingMismatch
    return items


def generation_evidence_context_bytes(
    context: tuple[GenerationEvidenceContextItem, ...] | object,
) -> bytes:
    if type(context) is not tuple:
        raise GenerationEvidenceBindingMismatch
    try:
        items = tuple(
            GenerationEvidenceContextItem.model_validate(item, strict=True)
            for item in context
        )
    except (TypeError, ValueError, UnicodeError):
        raise GenerationEvidenceBindingMismatch from None
    identifiers = tuple(item.evidence_id for item in items)
    if identifiers != tuple(sorted(set(identifiers))):
        raise GenerationEvidenceBindingMismatch
    return canonical_json_bytes(
        [item.model_dump(mode="json") for item in items]
    )


class GenerationEvidencePackRecord(StrictModel):
    evidence_pack_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    pack_ref: StoredContentRef
    pack: EvidencePack
    evidence_context_ref: StoredContentRef
    evidence_context: tuple[GenerationEvidenceContextItem, ...]
    metadata: GenerationRetrievalMetadata
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _closure(self) -> "GenerationEvidencePackRecord":
        encoded = canonical_json_bytes(self.pack.model_dump(mode="json"))
        context = validate_generation_evidence_context(
            self.pack,
            self.evidence_context,
        )
        context_encoded = generation_evidence_context_bytes(context)
        try:
            validate_generation_evidence_type_proof_pack_closure(
                self.pack,
                context,
                self.metadata.evidence_type_proofs,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("generation EvidencePack proof closure mismatch") from None
        if (
            self.pack.run_id != self.run_id
            or self.pack_ref.content_sha256 != hashlib.sha256(encoded).hexdigest()
            or self.pack_ref.size_bytes != len(encoded)
            or self.pack_ref.media_type != "application/json"
            or self.evidence_context_ref.content_sha256
            != hashlib.sha256(context_encoded).hexdigest()
            or self.evidence_context_ref.size_bytes != len(context_encoded)
            or self.evidence_context_ref.media_type != "application/json"
        ):
            raise ValueError("generation EvidencePack record closure mismatch")
        return self


def evidence_pack_bytes(pack: EvidencePack | object) -> bytes:
    value = EvidencePack.model_validate(pack, strict=True)
    return canonical_json_bytes(value.model_dump(mode="json"))


def evidence_pack_sha256(pack: EvidencePack | object) -> str:
    return hashlib.sha256(evidence_pack_bytes(pack)).hexdigest()


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise GenerationEvidenceBindingMismatch
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GenerationEvidenceBindingMismatch from None
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise GenerationEvidenceBindingMismatch
    return parsed


class GenerationEvidencePackStore:
    """Persist exact retrieval outputs inside one already-scoped client root."""

    def __init__(self, repository: SessionRepository) -> None:
        if not isinstance(repository, SessionRepository):
            raise TypeError("GenerationEvidencePackStore requires SessionRepository")
        self._repository = repository

    def register(
        self,
        *,
        session_id: str,
        turn_id: str,
        run_id: str,
        query_plan_sha256: str,
        pack: EvidencePack | object,
        evidence_context: tuple[GenerationEvidenceContextItem, ...] | object,
        run_objects: tuple[GenerationRunObject, ...],
        metadata: GenerationRetrievalMetadata | object,
    ) -> GenerationEvidencePackRecord:
        values = EvidencePack.model_validate(pack, strict=True)
        context = validate_generation_evidence_context(values, evidence_context)
        retrieval = GenerationRetrievalMetadata.model_validate(metadata, strict=True)
        objects = tuple(
            GenerationRunObject.model_validate(item, strict=True)
            for item in run_objects
        )
        identities = tuple(
            (item.object_type, item.reference.object_id) for item in objects
        )
        if identities != tuple(sorted(set(identities))):
            raise GenerationEvidenceBindingMismatch
        required = {
            object_type: tuple(
                item for item in objects if item.object_type == object_type
            )
            for object_type in ("authority_snapshot", "exclusion_proof")
        }
        if any(len(items) != 1 for items in required.values()):
            raise GenerationEvidenceBindingMismatch
        authority_object = required["authority_snapshot"][0]
        proof_object = required["exclusion_proof"][0]
        authority = AuthoritativeFilterSnapshot.model_validate_json(
            authority_object.bytes(),
            strict=True,
        )
        proof = ExclusionProof.model_validate_json(
            proof_object.bytes(),
            strict=True,
        )
        expected_provenance_refs = {
            item.provenance.provenance_ref
            for item in (*values.supporting, *values.contradicting)
        }
        actual_provenance_refs = {
            item.reference for item in objects if item.object_type == "provenance"
        }
        if (
            values.run_id != run_id
            or authority.run_id != run_id
            or proof.run_id != run_id
            or values.authority.snapshot_ref
            != authority_object.reference
            or values.exclusion_proof_ref != proof_object.reference
            or actual_provenance_refs != expected_provenance_refs
            or values.authority.run_id != authority.run_id
            or values.authority.global_runtime_epoch
            != authority.global_runtime_epoch
            or values.authority.client_runtime_epoch
            != authority.client_runtime_epoch
            or values.authority.tombstone_epoch != authority.tombstone_epoch
            or values.authority.authorization_epoch
            != authority.authorization_epoch
            or values.authority.policy_ref != authority.policy_ref
            or values.authority.created_at != authority.created_at
            or proof.policy_ref != authority.policy_ref
        ):
            raise GenerationEvidenceBindingMismatch

        encoded = evidence_pack_bytes(values)
        digest = hashlib.sha256(encoded).hexdigest()
        context_encoded = generation_evidence_context_bytes(context)
        context_digest = hashlib.sha256(context_encoded).hexdigest()
        existing = self._find_row(
            session_id=session_id,
            turn_id=turn_id,
            run_id=run_id,
            query_plan_sha256=query_plan_sha256,
        )
        if existing is not None:
            record = self._record_from_row(existing)
            if (
                record.pack_ref.content_sha256 != digest
                or record.pack != values
                or record.evidence_context_ref.content_sha256 != context_digest
                or record.evidence_context != context
                or record.metadata != retrieval
            ):
                raise GenerationEvidenceConflict
            return record

        stored_objects = tuple(
            self._store_exact(item.reference.object_id, item.bytes())
            for item in objects
        )
        stored_pack = self._store_exact(
            deterministic_object_id("evidence_pack", digest),
            encoded,
        )
        stored_context = self._store_exact(
            deterministic_object_id("evidence_context", context_digest),
            context_encoded,
        )
        evidence_pack_id = self._repository.id_factory.object_id(
            "generation_evidence_pack"
        )
        now = self._repository.clock.now()
        metadata_json = json.dumps(
            retrieval.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            with transaction(self._repository.connection):
                turn = self._repository.get_turn(session_id, turn_id)
                if (
                    turn.state != "generation_in_progress"
                    or turn.active_run_id != run_id
                ):
                    raise GenerationEvidenceBindingMismatch
                for item, stored in zip(objects, stored_objects, strict=True):
                    self._repository.connection.execute(
                        """
                        INSERT INTO generation_evidence_objects(
                            object_id, session_id, turn_id, run_id, object_type,
                            content_sha256, media_type, size_bytes, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            stored.object_id,
                            session_id,
                            turn_id,
                            run_id,
                            item.object_type,
                            stored.content_sha256,
                            stored.media_type,
                            stored.size_bytes,
                            _utc_text(now),
                        ),
                    )
                self._repository.connection.execute(
                    """
                    INSERT INTO generation_evidence_packs(
                        evidence_pack_id, session_id, turn_id, run_id,
                        query_plan_sha256, pack_object_id, pack_sha256,
                        pack_media_type, pack_size_bytes,
                        context_object_id, context_sha256,
                        context_media_type, context_size_bytes,
                        authority_snapshot_object_id,
                        exclusion_proof_object_id,
                        retrieval_metadata_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_pack_id,
                        session_id,
                        turn_id,
                        run_id,
                        query_plan_sha256,
                        stored_pack.object_id,
                        stored_pack.content_sha256,
                        stored_pack.media_type,
                        stored_pack.size_bytes,
                        stored_context.object_id,
                        stored_context.content_sha256,
                        stored_context.media_type,
                        stored_context.size_bytes,
                        authority_object.reference.object_id,
                        proof_object.reference.object_id,
                        metadata_json,
                        _utc_text(now),
                    ),
                )
        except sqlite3.IntegrityError:
            exact = self._find_row(
                session_id=session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=query_plan_sha256,
            )
            if exact is None:
                raise GenerationEvidenceConflict from None
            record = self._record_from_row(exact)
            if (
                record.pack_ref.content_sha256 != digest
                or record.pack != values
                or record.evidence_context_ref.content_sha256 != context_digest
                or record.evidence_context != context
            ):
                raise GenerationEvidenceConflict from None
            return record
        return self.get_by_hash(
            session_id=session_id,
            turn_id=turn_id,
            run_id=run_id,
            pack_sha256=digest,
        )

    def get_for_plan(
        self,
        *,
        session_id: str,
        turn_id: str,
        run_id: str,
        query_plan_sha256: str,
    ) -> GenerationEvidencePackRecord:
        row = self._find_row(
            session_id=session_id,
            turn_id=turn_id,
            run_id=run_id,
            query_plan_sha256=query_plan_sha256,
        )
        if row is None:
            raise GenerationEvidenceBindingMismatch
        return self._record_from_row(row)

    def get_by_hash(
        self,
        *,
        session_id: str,
        turn_id: str,
        run_id: str,
        pack_sha256: str,
    ) -> GenerationEvidencePackRecord:
        row = self._repository.connection.execute(
            """
            SELECT evidence_pack_id, session_id, turn_id, run_id,
                   query_plan_sha256, pack_object_id, pack_sha256,
                   pack_media_type, pack_size_bytes,
                   context_object_id, context_sha256,
                   context_media_type, context_size_bytes,
                   retrieval_metadata_json, created_at
              FROM generation_evidence_packs
             WHERE session_id = ? AND turn_id = ? AND run_id = ?
               AND pack_sha256 = ?
            """,
            (session_id, turn_id, run_id, pack_sha256),
        ).fetchone()
        if row is None:
            raise GenerationEvidenceBindingMismatch
        return self._record_from_row(tuple(row))

    def _find_row(
        self,
        *,
        session_id: str,
        turn_id: str,
        run_id: str,
        query_plan_sha256: str,
    ) -> tuple[object, ...] | None:
        return cast(
            tuple[object, ...] | None,
            self._repository.connection.execute(
                """
                SELECT evidence_pack_id, session_id, turn_id, run_id,
                       query_plan_sha256, pack_object_id, pack_sha256,
                       pack_media_type, pack_size_bytes,
                       context_object_id, context_sha256,
                       context_media_type, context_size_bytes,
                       retrieval_metadata_json, created_at
                  FROM generation_evidence_packs
                 WHERE session_id = ? AND turn_id = ? AND run_id = ?
                   AND query_plan_sha256 = ?
                """,
                (session_id, turn_id, run_id, query_plan_sha256),
            ).fetchone(),
        )

    def _record_from_row(
        self,
        row: tuple[object, ...],
    ) -> GenerationEvidencePackRecord:
        if len(row) != 15:
            raise GenerationEvidenceBindingMismatch
        try:
            reference = StoredContentRef.model_validate(
                {
                    "object_id": row[5],
                    "content_sha256": row[6],
                    "media_type": row[7],
                    "size_bytes": row[8],
                }
            )
            encoded = self._repository.read_content(reference)
            pack = EvidencePack.model_validate_json(encoded, strict=True)
            context_reference = StoredContentRef.model_validate(
                {
                    "object_id": row[9],
                    "content_sha256": row[10],
                    "media_type": row[11],
                    "size_bytes": row[12],
                }
            )
            context_encoded = self._repository.read_content(context_reference)
            context_value = json.loads(context_encoded.decode("utf-8", errors="strict"))
            if type(context_value) is not list:
                raise ValueError
            context = tuple(
                GenerationEvidenceContextItem.model_validate(item, strict=True)
                for item in context_value
            )
            context = validate_generation_evidence_context(pack, context)
            metadata = GenerationRetrievalMetadata.model_validate_json(
                cast(str, row[13]),
                strict=True,
            )
            record = GenerationEvidencePackRecord.model_validate(
                {
                    "evidence_pack_id": row[0],
                    "session_id": row[1],
                    "turn_id": row[2],
                    "run_id": row[3],
                    "query_plan_sha256": row[4],
                    "pack_ref": reference,
                    "pack": pack,
                    "evidence_context_ref": context_reference,
                    "evidence_context": context,
                    "metadata": metadata,
                    "created_at": _parse_utc(row[14]),
                }
            )
        except (TypeError, ValueError, UnicodeError):
            raise GenerationEvidenceBindingMismatch from None
        if evidence_pack_bytes(record.pack) != encoded:
            raise GenerationEvidenceBindingMismatch
        if generation_evidence_context_bytes(record.evidence_context) != context_encoded:
            raise GenerationEvidenceBindingMismatch
        return record

    def _store_exact(self, object_id: str, payload: bytes) -> StoredContentRef:
        staged = self._repository.content_store.stage_bytes(
            payload,
            purpose="session_content",
            manifest_id=self._repository.id_factory.object_id("session_manifest"),
            media_type="application/json",
        )
        stored = self._repository.content_store.finalize(staged)
        if stored.content_sha256 != hashlib.sha256(payload).hexdigest():
            raise GenerationEvidenceBindingMismatch
        return StoredContentRef(
            object_id=object_id,
            content_sha256=stored.content_sha256,
            media_type=stored.media_type,
            size_bytes=stored.size_bytes,
        )


__all__ = [
    "GenerationCandidateProofSource",
    "GenerationRiskContextBinding",
    "GenerationEvidenceBindingMismatch",
    "GenerationEvidenceConflict",
    "GenerationEvidenceContextItem",
    "GenerationEvidencePackRecord",
    "GenerationEvidencePackStore",
    "GenerationEvidenceRegistryError",
    "GenerationEvidenceTypeProof",
    "GenerationRetrievalMetadata",
    "GenerationRunObject",
    "evidence_pack_bytes",
    "evidence_pack_sha256",
    "generation_evidence_context_bytes",
    "validate_generation_evidence_context",
    "validate_generation_evidence_type_proof_pack_closure",
    "validate_generation_required_evidence_proofs",
    "validate_retrieved_generation_evidence_context",
]
