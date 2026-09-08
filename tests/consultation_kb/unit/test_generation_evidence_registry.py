from __future__ import annotations

import hashlib
import itertools
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceConflict,
    GenerationEvidenceContextItem,
    GenerationEvidencePackRecord,
    GenerationEvidencePackStore,
    GenerationEvidenceTypeProof,
    GenerationRetrievalMetadata,
    GenerationRunObject,
    evidence_pack_sha256,
    generation_evidence_context_bytes,
    validate_generation_required_evidence_proofs,
)
from consultation_kb.generation.contracts import QueryGuardrails, QueryPlan, Subquery
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    AuthoritySnapshotBinding,
    EvidencePack,
    Provenance,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.retrieval.contracts import ExclusionProof, canonical_json_bytes
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.unit.p6_quality_support import (
    NOW,
    candidate,
    object_id,
    pack,
    ref,
    uuid7,
)


SESSION_ID = uuid7(11_000)
TURN_ID = uuid7(11_001)
RUN_ID = uuid7(11_002)
FOREIGN_SESSION_ID = uuid7(11_003)
FOREIGN_TURN_ID = uuid7(11_004)
FOREIGN_RUN_ID = uuid7(11_005)
QUERY_PLAN_SHA256 = "a" * 64


@dataclass(frozen=True, slots=True)
class _RegistryFixture:
    connection: sqlite3.Connection
    repository: SessionRepository
    store: GenerationEvidencePackStore
    evidence_pack: EvidencePack
    run_objects: tuple[GenerationRunObject, ...]
    metadata: GenerationRetrievalMetadata


def _run_object(
    object_type: str,
    value: StrictModel,
) -> GenerationRunObject:
    payload = canonical_json_bytes(value.model_dump(mode="json"))
    digest = hashlib.sha256(payload).hexdigest()
    return GenerationRunObject.model_validate(
        {
            "object_type": object_type,
            "reference": VersionRef(
                object_id=deterministic_object_id(object_type, digest),
                version=1,
                content_sha256=digest,
            ),
            "canonical_json": payload.decode("utf-8"),
        },
        strict=True,
    )


def _nonempty_evidence_closure() -> tuple[
    EvidencePack,
    tuple[GenerationEvidenceContextItem, ...],
    tuple[GenerationRunObject, ...],
]:
    empty_pack, run_objects = _evidence_closure()
    body = "Frozen approved evidence body."
    temporary_body = '{"current":"temporary fact"}\n'
    provenance = Provenance(
        source_ids=frozenset({object_id("source", 11_200)}),
        passage_ids=frozenset({object_id("passage", 11_201)}),
        provenance_scope="global_source",
        derivation_rule_ref=ref("derivation_rule", 11_202),
    )
    provenance_object = _run_object("provenance", provenance)
    base = candidate(11_210)
    evidence = base.model_copy(
        update={
            "text_ref": base.text_ref.model_copy(
                update={
                    "content_sha256": hashlib.sha256(
                        body.encode("utf-8")
                    ).hexdigest()
                }
            ),
            "provenance": base.provenance.model_copy(
                update={
                    "provenance_ref": provenance_object.reference,
                    "derivation_rule_ref": provenance.derivation_rule_ref,
                }
            ),
        }
    )
    temporary_ref = VersionRef(
        object_id=object_id("session_fact", 11_220),
        version=1,
        content_sha256=hashlib.sha256(
            temporary_body.encode("utf-8")
        ).hexdigest(),
    )
    values = empty_pack.model_dump(mode="python")
    values.update(
        {
            "supporting": (evidence,),
            "temporary_fact_refs": (temporary_ref,),
        }
    )
    evidence_pack = EvidencePack.model_validate(values, strict=True)
    context = tuple(
        sorted(
            (
                GenerationEvidenceContextItem(
                    evidence_id=evidence.evidence_id,
                    context_kind="retrieved_candidate",
                    text_ref=evidence.text_ref,
                    body=body,
                ),
                GenerationEvidenceContextItem(
                    evidence_id=temporary_ref.object_id,
                    context_kind="temporary_fact",
                    text_ref=temporary_ref,
                    body=temporary_body,
                ),
            ),
            key=lambda item: item.evidence_id,
        )
    )
    objects = tuple(
        sorted(
            (*run_objects, provenance_object),
            key=lambda item: (item.object_type, item.reference.object_id),
        )
    )
    return evidence_pack, context, objects


def _evidence_closure() -> tuple[
    EvidencePack,
    tuple[GenerationRunObject, ...],
]:
    authority = AuthoritativeFilterSnapshot(
        run_id=RUN_ID,
        global_runtime_epoch=3,
        client_runtime_epoch=4,
        tombstone_epoch=5,
        authorization_epoch=6,
        allowed_ref_ids=frozenset(),
        policy_ref=ref("authority_policy", 11_100),
        created_at=NOW,
    )
    proof = ExclusionProof(
        run_id=RUN_ID,
        policy_ref=authority.policy_ref,
        input_count=0,
        allowed_count=0,
        denied_count=0,
        candidate_ids_sha256=hashlib.sha256(b"[]\n").hexdigest(),
        reasons={},
    )
    authority_object = _run_object("authority_snapshot", authority)
    proof_object = _run_object("exclusion_proof", proof)
    template = pack(supporting=())
    values = template.model_dump(mode="python")
    values.update(
        {
            "run_id": RUN_ID,
            "authority": AuthoritySnapshotBinding(
                snapshot_ref=authority_object.reference,
                run_id=authority.run_id,
                global_runtime_epoch=authority.global_runtime_epoch,
                client_runtime_epoch=authority.client_runtime_epoch,
                tombstone_epoch=authority.tombstone_epoch,
                authorization_epoch=authority.authorization_epoch,
                policy_ref=authority.policy_ref,
                created_at=authority.created_at,
            ),
            "exclusion_proof_ref": proof_object.reference,
        }
    )
    return (
        EvidencePack.model_validate(values, strict=True),
        (authority_object, proof_object),
    )


@pytest.fixture
def registry(tmp_path: Path) -> Iterator[_RegistryFixture]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    ids = IdFactory(FixedClock(NOW), itertools.count(20_000).__next__)
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=FixedClock(NOW),
        id_factory=ids,
    )
    repository.create_session(
        session_id=SESSION_ID,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="b" * 64,
        snapshot_version=0,
        snapshot_canonical_sha256="c" * 64,
        snapshot_bytes=b'{"empty":true}\n',
    )
    turns = TurnService(repository)
    turns.append(SESSION_ID, TURN_ID, "Synthetic client turn.")
    turns.begin_generation(SESSION_ID, TURN_ID, run_id=RUN_ID)
    evidence_pack, run_objects = _evidence_closure()
    value = _RegistryFixture(
        connection=connection,
        repository=repository,
        store=GenerationEvidencePackStore(repository),
        evidence_pack=evidence_pack,
        run_objects=run_objects,
        metadata=GenerationRetrievalMetadata(
            route_candidate_counts={"wiki": 1},
            filtered_candidate_count=1,
            resolved_evidence_count=1,
            selected_evidence_count=1,
        ),
    )
    try:
        yield value
    finally:
        connection.close()


def _register(value: _RegistryFixture) -> GenerationEvidencePackRecord:
    return value.store.register(
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=QUERY_PLAN_SHA256,
        pack=value.evidence_pack,
        evidence_context=(),
        run_objects=value.run_objects,
        metadata=value.metadata,
    )


def test_evidence_type_proof_rejects_caller_defined_type_labels() -> None:
    with pytest.raises(ValueError):
        GenerationEvidenceTypeProof.model_validate(
            {
                "subquery_id": "history",
                "evidence_type": "caller_asserted_type",
                "evidence_ids": (object_id("evidence", 11_099),),
            },
            strict=True,
        )


def _proof_query_plan(
    evidence_pack: EvidencePack,
    *,
    required: bool,
) -> QueryPlan:
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=TURN_ID,
            run_id=RUN_ID,
            parent_sha256s=(),
            created_at=NOW,
        ),
        intent="theory_guidance" if required else "simple_empathic_clarification",
        client_snapshot_ref=evidence_pack.client_snapshot_ref,
        global_runtime_epoch=evidence_pack.authority.global_runtime_epoch,
        client_runtime_epoch=evidence_pack.authority.client_runtime_epoch,
        tombstone_epoch=evidence_pack.authority.tombstone_epoch,
        authorization_epoch=evidence_pack.authority.authorization_epoch,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="theory" if required else "empathy",
                category=(
                    "theory_method_boundary"
                    if required
                    else "emotion_needs_relationship"
                ),
                question="Which exact C1 state applies?",
                routes=("wiki",),
                required_evidence_types=(
                    ("theory_applicability", "theory_boundary")
                    if required
                    else ()
                ),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Exercise exact proof cardinality.",
    )


def _c1_proof(
    evidence_pack: EvidencePack,
    evidence_type: str,
) -> GenerationEvidenceTypeProof:
    decision = evidence_pack.c1_applicability
    return GenerationEvidenceTypeProof.model_validate(
        {
            "subquery_id": "theory",
            "evidence_type": evidence_type,
            "proof_kind": "c1_authority",
            "c1_revision_ref": decision.revision,
            "c1_scope_policy_ref": decision.scope_policy_ref,
            "c1_decision_status": decision.status,
            "c1_effective_status": decision.effective_status,
        },
        strict=True,
    )


def test_required_evidence_proofs_are_exactly_one_per_plan_pair() -> None:
    evidence_pack, _objects = _evidence_closure()
    plan = _proof_query_plan(evidence_pack, required=True)
    proofs = tuple(
        _c1_proof(evidence_pack, evidence_type)
        for evidence_type in ("theory_applicability", "theory_boundary")
    )

    assert validate_generation_required_evidence_proofs(
        plan,
        evidence_pack,
        (),
        proofs,
        risk_context_binding=None,
    ) == proofs

    for invalid in (proofs[:1], ()):
        with pytest.raises(GenerationEvidenceBindingMismatch):
            validate_generation_required_evidence_proofs(
                plan,
                evidence_pack,
                (),
                invalid,
                risk_context_binding=None,
            )


def test_required_evidence_proofs_reject_extra_or_forged_c1_authority() -> None:
    evidence_pack, _objects = _evidence_closure()
    no_requirement = _proof_query_plan(evidence_pack, required=False)
    extra = (_c1_proof(evidence_pack, "theory_applicability"),)

    with pytest.raises(GenerationEvidenceBindingMismatch):
        validate_generation_required_evidence_proofs(
            no_requirement,
            evidence_pack,
            (),
            extra,
            risk_context_binding=None,
        )

    exact = _c1_proof(evidence_pack, "theory_applicability")
    forged = exact.model_copy(update={"c1_decision_status": "not_applicable"})
    with pytest.raises(GenerationEvidenceBindingMismatch):
        validate_generation_required_evidence_proofs(
            _proof_query_plan(evidence_pack, required=True),
            evidence_pack,
            (),
            (
                forged,
                _c1_proof(evidence_pack, "theory_boundary"),
            ),
            risk_context_binding=None,
        )


def test_registry_round_trip_is_bound_to_exact_session_turn_run_and_plan(
    registry: _RegistryFixture,
) -> None:
    registered = _register(registry)

    assert registered.pack == registry.evidence_pack
    assert registered.pack_ref.content_sha256 == evidence_pack_sha256(
        registry.evidence_pack
    )
    assert registry.store.get_for_plan(
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=QUERY_PLAN_SHA256,
    ) == registered
    assert _register(registry) == registered


@pytest.mark.parametrize(
    ("session_id", "turn_id", "run_id", "pack_sha256"),
    [
        (FOREIGN_SESSION_ID, TURN_ID, RUN_ID, None),
        (SESSION_ID, FOREIGN_TURN_ID, RUN_ID, None),
        (SESSION_ID, TURN_ID, FOREIGN_RUN_ID, None),
        (SESSION_ID, TURN_ID, RUN_ID, "f" * 64),
    ],
)
def test_registry_rejects_foreign_scope_or_caller_asserted_pack_hash(
    registry: _RegistryFixture,
    session_id: str,
    turn_id: str,
    run_id: str,
    pack_sha256: str | None,
) -> None:
    registered = _register(registry)

    with pytest.raises(GenerationEvidenceBindingMismatch):
        registry.store.get_by_hash(
            session_id=session_id,
            turn_id=turn_id,
            run_id=run_id,
            pack_sha256=pack_sha256 or registered.pack_ref.content_sha256,
        )


def test_registry_rejects_pack_bound_to_another_run(
    registry: _RegistryFixture,
) -> None:
    values = registry.evidence_pack.model_dump(mode="python")
    values["run_id"] = FOREIGN_RUN_ID
    authority = dict(values["authority"])
    authority["run_id"] = FOREIGN_RUN_ID
    values["authority"] = authority
    foreign_pack = EvidencePack.model_validate(values, strict=True)

    with pytest.raises(GenerationEvidenceBindingMismatch):
        registry.store.register(
            session_id=SESSION_ID,
            turn_id=TURN_ID,
            run_id=RUN_ID,
            query_plan_sha256=QUERY_PLAN_SHA256,
            pack=foreign_pack,
            evidence_context=(),
            run_objects=registry.run_objects,
            metadata=registry.metadata,
        )


def test_registry_rejects_different_pack_for_an_existing_query_plan(
    registry: _RegistryFixture,
) -> None:
    _register(registry)
    values = registry.evidence_pack.model_dump(mode="python")
    values["reranker_descriptor_ref"] = ref("reranker_descriptor", 11_999)
    conflicting_pack = EvidencePack.model_validate(values, strict=True)

    with pytest.raises(GenerationEvidenceConflict):
        registry.store.register(
            session_id=SESSION_ID,
            turn_id=TURN_ID,
            run_id=RUN_ID,
            query_plan_sha256=QUERY_PLAN_SHA256,
            pack=conflicting_pack,
            evidence_context=(),
            run_objects=registry.run_objects,
            metadata=registry.metadata,
        )


def test_registry_rejects_different_retrieval_metadata_for_existing_plan(
    registry: _RegistryFixture,
) -> None:
    _register(registry)
    conflicting_metadata = registry.metadata.model_copy(
        update={"filtered_candidate_count": 2}
    )

    with pytest.raises(GenerationEvidenceConflict):
        registry.store.register(
            session_id=SESSION_ID,
            turn_id=TURN_ID,
            run_id=RUN_ID,
            query_plan_sha256=QUERY_PLAN_SHA256,
            pack=registry.evidence_pack,
            evidence_context=(),
            run_objects=registry.run_objects,
            metadata=conflicting_metadata,
        )


def test_run_object_rejects_forged_reference_or_canonical_body() -> None:
    _pack, run_objects = _evidence_closure()
    authority = run_objects[0]

    with pytest.raises(ValueError, match="reference mismatch"):
        GenerationRunObject.model_validate(
            {
                **authority.model_dump(mode="python"),
                "reference": authority.reference.model_copy(
                    update={"content_sha256": "e" * 64}
                ),
            },
            strict=True,
        )
    with pytest.raises(ValueError, match="reference mismatch"):
        GenerationRunObject.model_validate(
            {
                **authority.model_dump(mode="python"),
                "canonical_json": authority.canonical_json + " ",
            },
            strict=True,
        )


def test_registry_freezes_and_recovers_exact_candidate_and_temporary_bodies(
    registry: _RegistryFixture,
) -> None:
    evidence_pack, context, run_objects = _nonempty_evidence_closure()

    registered = registry.store.register(
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=QUERY_PLAN_SHA256,
        pack=evidence_pack,
        evidence_context=context,
        run_objects=run_objects,
        metadata=registry.metadata,
    )
    recovered = registry.store.get_for_plan(
        session_id=SESSION_ID,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        query_plan_sha256=QUERY_PLAN_SHA256,
    )

    assert recovered.evidence_context == context
    assert generation_evidence_context_bytes(recovered.evidence_context) == (
        generation_evidence_context_bytes(context)
    )
    assert recovered.evidence_context_ref == registered.evidence_context_ref


def test_registry_rejects_missing_foreign_or_text_ref_mismatched_context(
    registry: _RegistryFixture,
) -> None:
    evidence_pack, context, run_objects = _nonempty_evidence_closure()
    candidate_item = next(
        item for item in context if item.context_kind == "retrieved_candidate"
    )
    foreign = GenerationEvidenceContextItem(
        evidence_id=object_id("evidence", 11_999),
        context_kind="retrieved_candidate",
        text_ref=VersionRef(
            object_id=object_id("text", 11_999),
            version=1,
            content_sha256=hashlib.sha256(b"foreign").hexdigest(),
        ),
        body="foreign",
    )
    mismatched_ref = candidate_item.model_copy(
        update={
            "text_ref": candidate_item.text_ref.model_copy(
                update={"object_id": object_id("text", 11_998)}
            )
        }
    )

    for invalid in (
        context[:-1],
        tuple(sorted((*context, foreign), key=lambda item: item.evidence_id)),
        tuple(
            sorted(
                (
                    mismatched_ref,
                    *(item for item in context if item != candidate_item),
                ),
                key=lambda item: item.evidence_id,
            )
        ),
    ):
        with pytest.raises(GenerationEvidenceBindingMismatch):
            registry.store.register(
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                run_id=RUN_ID,
                query_plan_sha256=QUERY_PLAN_SHA256,
                pack=evidence_pack,
                evidence_context=invalid,
                run_objects=run_objects,
                metadata=registry.metadata,
            )


def test_generation_context_body_cannot_expose_a_client_identifier() -> None:
    body = "internal owner client_" + "aaaaaaaaaaaa"
    with pytest.raises(ValueError, match="contains a client identifier"):
        GenerationEvidenceContextItem(
            evidence_id=object_id("evidence", 11_997),
            context_kind="retrieved_candidate",
            text_ref=VersionRef(
                object_id=object_id("text", 11_997),
                version=1,
                content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
            ),
            body=body,
        )
