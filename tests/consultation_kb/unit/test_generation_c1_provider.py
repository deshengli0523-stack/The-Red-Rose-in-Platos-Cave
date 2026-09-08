from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from consultation_kb.generation.c1_context import (
    C1ApplicabilityInput,
    C1ContextAssertion,
)
from consultation_kb.generation.c1_provider import (
    DeterministicGenerationC1Provider,
    GenerationC1ProviderError,
)
from consultation_kb.generation.contracts import QueryGuardrails, QueryPlan, Subquery
from consultation_kb.models.common import VersionRef
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.retrieval.artifact_contracts import DerivedArtifactBuilderInputV2
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
    ActiveRetrievalArtifactSet,
)
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)


@dataclass(frozen=True)
class _Authority:
    harness: GlobalKnowledgeHarness
    knowledge: PreparedKnowledge
    active: ActiveRetrievalArtifactSet


@pytest.fixture
def authority(tmp_path: Path) -> Iterator[_Authority]:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        active = ActiveRetrievalArtifactDiscovery(
            harness.connection,
            harness.store,
        ).discover_current_set()
        assert active is not None
        yield _Authority(harness=harness, knowledge=knowledge, active=active)
    finally:
        harness.close()


def _plan(authority: _Authority) -> QueryPlan:
    snapshot = VersionRef(
        object_id=authority.harness.ids.object_id("client_snapshot"),
        version=1,
        content_sha256="b" * 64,
    )
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=authority.harness.ids.uuid7(),
            run_id=authority.harness.ids.uuid7(),
            parent_sha256s=("a" * 64,),
            created_at=authority.harness.clock.now(),
        ),
        intent="theory_guidance",
        client_snapshot_ref=snapshot,
        global_runtime_epoch=authority.active.active_runtime_epoch,
        client_runtime_epoch=3,
        tombstone_epoch=4,
        authorization_epoch=1,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="theory",
                category="theory_method_boundary",
                question="Which governed theory boundary applies?",
                routes=("lexical",),
                required_evidence_types=("theory_applicability",),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Resolve the exact governed C1 applicability.",
    )


def _input(
    plan: QueryPlan,
    *,
    include_population: bool = True,
    population: str = "adult",
) -> C1ApplicabilityInput:
    source = (plan.client_snapshot_ref.object_id,)
    assertions = [
        C1ContextAssertion(
            context_field="context",
            value_keys=("relationship",),
            source_evidence_ids=source,
        ),
        C1ContextAssertion(
            context_field="domain",
            value_keys=("emotional_consultation",),
            source_evidence_ids=source,
        ),
    ]
    if include_population:
        assertions.append(
            C1ContextAssertion(
                context_field="population",
                value_keys=(population,),
                source_evidence_ids=source,
            )
        )
    return C1ApplicabilityInput.bind(
        plan,
        client_snapshot_ref=plan.client_snapshot_ref,
        client_runtime_epoch=plan.client_runtime_epoch,
        client_tombstone_count=plan.tombstone_epoch,
        temporary_fact_refs=(),
        assertions=tuple(assertions),
        known_empty_fields=("contraindications",),
    )


def _resolve(
    authority: _Authority,
    plan: QueryPlan,
    applicability_input: C1ApplicabilityInput,
):  # type: ignore[no-untyped-def]
    return DeterministicGenerationC1Provider(
        clock=authority.harness.clock
    ).resolve(
        plan,
        applicability_input,
        global_connection=authority.harness.connection,
        global_content_store=authority.harness.store,
        active_artifacts=authority.active,
    )


def test_real_active_theory_and_policy_produce_applicable_decision(
    authority: _Authority,
) -> None:
    plan = _plan(authority)
    applicability_input = _input(plan)

    result = _resolve(authority, plan, applicability_input)

    assert result.decision.status == "applicable"
    assert result.decision.revision == authority.knowledge.theory_service.version_ref(
        authority.knowledge.theory.theory_id,
        authority.knowledge.theory.revision,
    )
    assert result.decision.scope_policy_ref == authority.knowledge.theory.scope_policy_ref
    assert result.applicability_input_sha256 == applicability_input.canonical_sha256
    rendered = applicability_input.model_dump_json()
    assert "client_" + "aaaaaaaaaaaa" not in rendered
    assert "Which governed theory boundary applies?" not in rendered


def test_missing_and_known_empty_are_not_conflated(authority: _Authority) -> None:
    plan = _plan(authority)

    result = _resolve(authority, plan, _input(plan, include_population=False))

    assert result.decision.status == "insufficient_context"
    assert result.decision.missing_context_fields == ("population",)


def test_unapproved_safe_value_fails_closed(authority: _Authority) -> None:
    plan = _plan(authority)
    with pytest.raises(
        GenerationC1ProviderError,
        match="POLICY_VALUE_NOT_APPROVED",
    ):
        _resolve(authority, plan, _input(plan, population="unknown_population"))


def test_multiple_active_c1_theories_are_ambiguous(authority: _Authority) -> None:
    connection = authority.harness.connection
    columns = tuple(
        str(row[1]) for row in connection.execute("PRAGMA table_info(theory_revisions)")
    )
    row = list(
        connection.execute(
            f"SELECT {', '.join(columns)} FROM theory_revisions "  # noqa: S608
            "WHERE theory_id = ? AND revision = ?",
            (
                authority.knowledge.theory.theory_id,
                authority.knowledge.theory.revision,
            ),
        ).fetchone()
    )
    row[columns.index("theory_id")] = authority.harness.ids.object_id("theory")
    placeholders = ", ".join("?" for _ in columns)
    connection.execute(
        f"INSERT INTO theory_revisions({', '.join(columns)}) "  # noqa: S608
        f"VALUES ({placeholders})",
        tuple(row),
    )
    plan = _plan(authority)

    with pytest.raises(
        GenerationC1ProviderError,
        match="GENERATION_C1_SELECTION_AMBIGUOUS",
    ):
        _resolve(authority, plan, _input(plan))


def test_active_artifact_theory_must_match_database_selection(
    authority: _Authority,
) -> None:
    authority.harness.connection.execute(
        "UPDATE theory_revisions SET revision_object_ref = ? "
        "WHERE theory_id = ? AND revision = ?",
        (
            f"sha256:{'f' * 64}",
            authority.knowledge.theory.theory_id,
            authority.knowledge.theory.revision,
        ),
    )
    plan = _plan(authority)

    with pytest.raises(
        GenerationC1ProviderError,
        match="GENERATION_C1_ARTIFACT_CLOSURE_MISMATCH",
    ):
        _resolve(authority, plan, _input(plan))


def test_semantic_theory_hash_must_match_verified_cas_body(
    authority: _Authority,
) -> None:
    authority.harness.connection.execute(
        "UPDATE theory_revisions SET revision_sha256 = ? "
        "WHERE theory_id = ? AND revision = ?",
        (
            "f" * 64,
            authority.knowledge.theory.theory_id,
            authority.knowledge.theory.revision,
        ),
    )
    plan = _plan(authority)

    with pytest.raises(
        GenerationC1ProviderError,
        match="GENERATION_C1_AUTHORITY_INVALID",
    ):
        _resolve(authority, plan, _input(plan))


def test_zero_active_theory_returns_unavailable_with_approved_policy(
    authority: _Authority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = DeterministicGenerationC1Provider(clock=authority.harness.clock)
    original = provider._active_closure  # noqa: SLF001
    active_closure = original(
        authority.harness.connection,
        authority.active,
        expected_epoch=authority.active.active_runtime_epoch,
    )
    authority.harness.connection.execute(
        "UPDATE theory_revisions SET status = 'SUPERSEDED' "
        "WHERE theory_id = ? AND revision = ?",
        (
            authority.knowledge.theory.theory_id,
            authority.knowledge.theory.revision,
        ),
    )
    monkeypatch.setattr(
        provider,
        "_active_closure",
        lambda *args, **kwargs: type(active_closure)(  # noqa: ARG005
            builder_input=active_closure.builder_input,
            active_theory_object=None,
        ),
    )
    plan = _plan(authority)
    applicability_input = _input(plan)

    result = provider.resolve(
        plan,
        applicability_input,
        global_connection=authority.harness.connection,
        global_content_store=authority.harness.store,
        active_artifacts=authority.active,
    )

    assert result.decision.status == "unavailable"
    assert result.decision.revision is None
    assert result.decision.effective_status == "none"


def test_active_claim_authority_cannot_be_orphaned(authority: _Authority) -> None:
    claim = authority.knowledge.theory.claim_refs[0]
    authority.harness.connection.execute(
        "UPDATE claims SET review_status = 'REVOKED' "
        "WHERE claim_id = ? AND version = ?",
        (claim.object_id, claim.version),
    )
    plan = _plan(authority)

    with pytest.raises(
        GenerationC1ProviderError,
        match="GENERATION_C1_ORPHAN_REF",
    ):
        _resolve(authority, plan, _input(plan))


def test_active_closure_builder_input_is_exact(authority: _Authority) -> None:
    payload = authority.active.lexical.path_for("lexical_builder_input").read_bytes()
    builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
        payload,
        strict=True,
    )
    row = authority.harness.connection.execute(
        "SELECT revision_object_ref FROM theory_revisions "
        "WHERE theory_id = ? AND revision = ?",
        (
            authority.knowledge.theory.theory_id,
            authority.knowledge.theory.revision,
        ),
    ).fetchone()
    assert row is not None
    expected_cas_sha256 = str(row[0]).removeprefix("sha256:")

    assert builder_input.authority_snapshot.theory is not None
    assert (
        builder_input.authority_snapshot.theory.object_id,
        builder_input.authority_snapshot.theory.version,
        builder_input.authority_snapshot.theory.object_sha256,
    ) == (
        authority.knowledge.theory.theory_id,
        authority.knowledge.theory.revision,
        expected_cas_sha256,
    )
