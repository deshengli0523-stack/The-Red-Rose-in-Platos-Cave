from __future__ import annotations

import hashlib
import importlib

import pytest

from consultation_kb.retrieval.contracts import canonical_json_bytes
from tests.consultation_kb.retrieval_support import candidate, reference


def _contracts():
    try:
        return importlib.import_module("consultation_kb.retrieval.artifact_contracts")
    except ModuleNotFoundError:
        pytest.fail("retrieval artifact contracts are not implemented", pytrace=False)


def _builder_input(module, descriptor, *, expected: int | None, maximum: int):
    authority_snapshot = {
        "authorization_epoch": 3,
        "catalog_version": 41,
        "claims": (),
        "expected_current_epoch": expected,
        "maximum_runtime_epoch": maximum,
        "publication_authority_version": 7,
        "target_runtime_epoch": maximum + 1,
        "theory": None,
        "tombstone_epoch": 5,
        "wiki": None,
    }
    return module.DerivedArtifactBuilderInputV2(
        artifact_kind="lexical",
        authority_closure_sha256=hashlib.sha256(
            canonical_json_bytes(authority_snapshot)
        ).hexdigest(),
        authority_snapshot=authority_snapshot,
        retrieval_input_descriptor=descriptor,
        target_runtime_epoch=maximum + 1,
    )


def _descriptor(module, assignments):
    return module.RetrievalInputDescriptor.from_assignments(
        assignments,
        route_policy_ref=reference("retrieval_route_policy", 600),
    )


def test_v2_builder_input_separates_authority_catalog_source_and_target_epoch() -> None:
    module = _contracts()
    value = candidate(1, text="authoritative passage")
    assignment = module.RetrievalInputAssignment.from_candidate(
        value,
        target_channels=frozenset({"lexical", "vector"}),
    )
    descriptor = _descriptor(module, (assignment,))

    first = _builder_input(module, descriptor, expected=None, maximum=0)
    history_without_active = _builder_input(
        module,
        descriptor,
        expected=None,
        maximum=8,
    )

    assert first.source_catalog_version == 7
    assert first.authority_catalog_version == 41
    assert first.target_runtime_epoch == 1
    assert history_without_active.target_runtime_epoch == 9
    with pytest.raises(ValueError):
        history_without_active.model_copy(
            update={"target_runtime_epoch": 10},
        ).__class__.model_validate(
            history_without_active.model_dump()
            | {"target_runtime_epoch": 10}
        )


def test_descriptor_binds_authority_manifest_and_exact_channel_assignments() -> None:
    module = _contracts()
    first = candidate(2, text="first", channel="lexical")
    second = candidate(3, text="second", channel="lexical")
    assignments = tuple(
        module.RetrievalInputAssignment.from_candidate(
            value,
            target_channels=frozenset({"lexical", "vector"}),
        )
        for value in (first, second)
    )
    descriptor = _descriptor(module, assignments)

    lexical_candidates = (first, second)
    vector_candidates = tuple(
        value.model_copy(update={"channel": "vector"})
        for value in lexical_candidates
    )
    descriptor.verify_candidates("lexical", lexical_candidates)
    descriptor.verify_candidates("vector", vector_candidates)
    with pytest.raises(ValueError, match="RETRIEVAL_INPUT_SET_MISMATCH"):
        descriptor.verify_candidates("vector", vector_candidates[:1])

    changed = first.model_copy(
        update={
            "metadata": first.metadata.model_copy(
                update={"manifest_ref": reference("artifact_manifest", 999)}
            )
        }
    )
    changed_descriptor = _descriptor(
        module,
        (
            module.RetrievalInputAssignment.from_candidate(
                changed,
                target_channels=frozenset({"lexical", "vector"}),
            ),
            assignments[1],
        )
    )

    assert changed_descriptor.descriptor_sha256 != descriptor.descriptor_sha256
    assert changed_descriptor.records[0].candidate_authority_sha256 != (
        descriptor.records[0].candidate_authority_sha256
    )


def test_fixed_role_layout_is_exact_and_reserves_graph_authority_catalog() -> None:
    module = _contracts()

    assert module.derived_artifact_role_layout("lexical") == (
        "lexical_builder_input",
        "lexical_build_manifest",
        "lexical_index",
    )
    graph = module.derived_artifact_role_layout("graph")
    assert "graph_edge_authority_catalog" in graph
    module.validate_derived_artifact_role_layout("graph", graph)
    with pytest.raises(ValueError, match="DERIVED_ARTIFACT_ROLE_LAYOUT_INVALID"):
        module.validate_derived_artifact_role_layout(
            "graph",
            graph + ("uncontrolled_extra",),
        )


def test_descriptor_allows_one_claim_version_with_multiple_passages_only() -> None:
    module = _contracts()
    first = candidate(10, text="first passage", channel="lexical")
    second = candidate(11, text="second passage", channel="lexical").model_copy(
        update={"reference": first.reference}
    )
    assignments = tuple(
        module.RetrievalInputAssignment.from_candidate(
            value,
            target_channels=frozenset({"lexical", "vector"}),
        )
        for value in (first, second)
    )

    descriptor = _descriptor(module, assignments)
    assert len(descriptor.records) == 2
    descriptor.verify_candidates("lexical", (first, second))

    wrong_version = second.model_copy(
        update={
            "reference": first.reference.model_copy(
                update={"version": 2, "content_sha256": "f" * 64}
            )
        }
    )
    with pytest.raises(ValueError, match="RETRIEVAL_INPUT_STABLE_VERSION_CONFLICT"):
        _descriptor(
            module,
            (
                assignments[0],
                module.RetrievalInputAssignment.from_candidate(
                    wrong_version,
                    target_channels=frozenset({"lexical", "vector"}),
                ),
            ),
        )


def test_route_policy_and_governed_candidate_state_are_hash_bound() -> None:
    module = _contracts()
    value = candidate(12, text="governed", channel="global_graph")
    assignment = module.RetrievalInputAssignment.from_candidate(
        value,
        target_channels=frozenset({"graph"}),
    )
    first = module.RetrievalInputDescriptor.from_assignments(
        (assignment,),
        route_policy_ref=reference("retrieval_route_policy", 601),
    )
    second = module.RetrievalInputDescriptor.from_assignments(
        (assignment,),
        route_policy_ref=reference("retrieval_route_policy", 602),
    )

    assert first.descriptor_sha256 != second.descriptor_sha256
    first.verify_candidates("graph", (value,))
    assert first.assigned_records("knowledge_registry") == first.records
    with pytest.raises(ValueError, match="RETRIEVAL_INPUT_CANDIDATE_STATE_INVALID"):
        module.RetrievalInputAssignment.from_candidate(
            value.model_copy(update={"score": 1.0}),
            target_channels=frozenset({"graph"}),
        )
    with pytest.raises(ValueError, match="RETRIEVAL_INPUT_TARGET_INVALID"):
        module.RetrievalInputAssignment.from_candidate(
            value,
            target_channels=frozenset({"knowledge_registry"}),
        )
    with pytest.raises(ValueError, match="RETRIEVAL_ROUTE_POLICY_REF_INVALID"):
        module.RetrievalInputDescriptor.from_assignments(
            (assignment,),
            route_policy_ref=reference("authority_policy", 603),
        )
