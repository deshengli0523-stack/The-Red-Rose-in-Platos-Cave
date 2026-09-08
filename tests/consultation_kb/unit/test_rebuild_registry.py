from __future__ import annotations

import pytest

from consultation_kb.lifecycle.rebuild_registry import (
    AuthoritySourceSpec,
    BuilderDescriptor,
    BuilderRegistry,
    BuilderRegistryError,
)


TEST_IMPLEMENTATION_REVISION = "f" * 64


def test_default_registry_has_fixed_topological_builder_dags() -> None:
    registry = BuilderRegistry.default()

    global_plan = registry.plan(database_scope="global", purpose="all")
    client_plan = registry.plan(database_scope="client", purpose="all")

    assert tuple(item.builder_id for item in global_plan) == (
        "wiki_index",
        "knowledge_registry",
        "graph",
        "lexical",
        "vector",
    )
    assert tuple(item.builder_id for item in client_plan) == (
        "client_fact_snapshot",
        "private_archive",
        "client_profile",
        "client_graph",
    )

    by_id = {item.builder_id: item for item in (*global_plan, *client_plan)}
    assert by_id["knowledge_registry"].dependencies == ("wiki_index",)
    assert by_id["graph"].dependencies == (
        "wiki_index",
        "knowledge_registry",
    )
    assert by_id["lexical"].dependencies == ("knowledge_registry",)
    assert by_id["vector"].dependencies == ("knowledge_registry",)
    assert by_id["client_profile"].dependencies == ("client_fact_snapshot",)
    assert by_id["client_graph"].dependencies == ("client_fact_snapshot",)
    assert by_id["private_archive"].dependencies == ()


def test_registry_exposes_only_approved_authority_tables() -> None:
    registry = BuilderRegistry.default()
    private_archive = next(
        item
        for item in registry.plan(database_scope="client", purpose="all")
        if item.builder_id == "private_archive"
    )
    client_by_id = {
        item.builder_id: item
        for item in registry.plan(database_scope="client", purpose="all")
    }
    global_by_id = {
        item.builder_id: item
        for item in registry.plan(database_scope="global", purpose="all")
    }

    requested = {
        source.key
        for descriptor in registry.plan(database_scope="global", purpose="all")
        for source in descriptor.authority_sources
    } | {
        source.key
        for descriptor in registry.plan(database_scope="client", purpose="all")
        for source in descriptor.authority_sources
    }

    assert "global.sources" in requested
    assert "global.passages" in requested
    assert "global.claims" in requested
    assert "global.theory_revisions" in requested
    assert "global.scope_policy_approval_bindings" in requested
    assert "global.wiki_revisions" in requested
    assert "client.fact_events" in requested
    assert "client.review_decisions" in requested
    assert tuple(source.table for source in private_archive.authority_sources) == (
        "archive_bundles",
        "archive_purpose_states",
        "private_archive_revisions",
    )
    assert (
        private_archive.authority_selection
        == "active_approved_not_tombstoned"
    )
    profile_tables = {
        "fact_events",
        "fact_evidence",
        "fact_dependencies",
        "fact_merge_members",
        "profile_revisions",
        "profile_members",
        "review_decisions",
        "archive_purpose_states",
    }
    assert {
        source.table
        for source in client_by_id["client_fact_snapshot"].authority_sources
    } == profile_tables
    assert {
        source.table for source in client_by_id["client_graph"].authority_sources
    } == profile_tables
    approved_case_tables = {
        "cases",
        "case_versions",
        "case_authorizations",
        "case_review_decisions",
        "case_provenance",
        "case_patterns",
        "case_regeneration_proofs",
        "case_leave_one_out_variants",
    }
    for descriptor in global_by_id.values():
        assert approved_case_tables <= {
            source.table for source in descriptor.authority_sources
        }
    assert "global.case_provenance" in requested
    assert "client.generation_stage_revisions" not in requested
    assert "client.actual_replies" not in requested
    assert "client.shared_case_candidates" not in requested
    assert "client.profile_diff_drafts" not in requested
    assert "global.knowledge_proposal_operations" not in requested


def test_registry_rejects_a_builder_that_reads_generation_scratch() -> None:
    descriptor = BuilderDescriptor(
        builder_id="unsafe_builder",
        database_scope="client",
        output_purpose="profile_view",
        implementation_revision_sha256=TEST_IMPLEMENTATION_REVISION,
        dependencies=(),
        authority_sources=(
            AuthoritySourceSpec(
                database_scope="client",
                table="generation_stage_revisions",
            ),
        ),
        policy_binding="required",
        model_binding="none",
    )

    with pytest.raises(BuilderRegistryError, match="REBUILD_AUTHORITY_SOURCE_FORBIDDEN"):
        BuilderRegistry((descriptor,))


def test_registry_rejects_cycles_and_cross_scope_dependencies() -> None:
    source = AuthoritySourceSpec(database_scope="global", table="sources")
    first = BuilderDescriptor(
        builder_id="first_builder",
        database_scope="global",
        output_purpose="first_output",
        implementation_revision_sha256=TEST_IMPLEMENTATION_REVISION,
        dependencies=("second_builder",),
        authority_sources=(source,),
        policy_binding="none",
        model_binding="none",
    )
    second = BuilderDescriptor(
        builder_id="second_builder",
        database_scope="global",
        output_purpose="second_output",
        implementation_revision_sha256=TEST_IMPLEMENTATION_REVISION,
        dependencies=("first_builder",),
        authority_sources=(source,),
        policy_binding="none",
        model_binding="none",
    )

    with pytest.raises(BuilderRegistryError, match="REBUILD_BUILDER_DAG_CYCLE"):
        BuilderRegistry((first, second))

    cross_scope = BuilderDescriptor(
        builder_id="client_builder",
        database_scope="client",
        output_purpose="client_output",
        implementation_revision_sha256=TEST_IMPLEMENTATION_REVISION,
        dependencies=("first_builder",),
        authority_sources=(
            AuthoritySourceSpec(database_scope="client", table="fact_events"),
        ),
        policy_binding="none",
        model_binding="none",
    )
    acyclic_global = first.model_copy(update={"dependencies": ()})
    with pytest.raises(BuilderRegistryError, match="REBUILD_CROSS_SCOPE_DEPENDENCY"):
        BuilderRegistry((acyclic_global, cross_scope))


def test_registry_digest_and_dependency_closure_are_order_independent() -> None:
    default = BuilderRegistry.default()
    reversed_registry = BuilderRegistry(tuple(reversed(default.descriptors)))

    assert default.dag_sha256(database_scope="global", purpose="all") == (
        reversed_registry.dag_sha256(database_scope="global", purpose="all")
    )
    assert tuple(
        item.builder_id
        for item in default.plan(database_scope="global", purpose="vector")
    ) == ("wiki_index", "knowledge_registry", "vector")


def test_production_registry_declares_complete_eight_output_closure() -> None:
    registry = BuilderRegistry.production()
    plan = registry.plan(database_scope="global", purpose="all")

    assert tuple(value.output_purpose for value in plan) == (
        "c1_revision",
        "claims",
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "graph",
        "lexical",
        "vector",
    )
    assert next(
        value for value in plan if value.builder_id == "wiki_index"
    ).dependencies == ("c1_revision", "claims", "wiki_page")


def test_implementation_revision_is_bound_into_dag_hash() -> None:
    registry = BuilderRegistry.default()
    changed = tuple(
        value.model_copy(
            update={"implementation_revision_sha256": "e" * 64}
        )
        if value.builder_id == "graph"
        else value
        for value in registry.descriptors
    )

    assert BuilderRegistry(changed).dag_sha256(
        database_scope="global", purpose="all"
    ) != registry.dag_sha256(database_scope="global", purpose="all")


def test_registry_rejects_missing_policy_or_model_bindings_at_plan_time() -> None:
    registry = BuilderRegistry.default()

    with pytest.raises(BuilderRegistryError, match="REBUILD_POLICY_BINDING_REQUIRED"):
        registry.validate_bindings(
            database_scope="global",
            purpose="all",
            policy_sha256=None,
            model_descriptor_sha256="a" * 64,
        )
    with pytest.raises(BuilderRegistryError, match="REBUILD_MODEL_BINDING_REQUIRED"):
        registry.validate_bindings(
            database_scope="global",
            purpose="all",
            policy_sha256="a" * 64,
            model_descriptor_sha256=None,
        )
