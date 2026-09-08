from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.observability.audit import (
    AuditEventV1,
    AuditEventV2,
    AuditSink,
    FrozenCounts,
    ObservabilityStoreError,
)
from consultation_kb.observability.metrics_sink import (
    MetricDimension,
    MetricPoint,
    MetricsSink,
)
from consultation_kb.observability.runs import (
    DuplicateRunError,
    EvidenceCandidateClosure,
    EvidencePackClosureV2,
    GovernedObjectRef,
    NamedVersionRef,
    RunFilterCounts,
    RunLineage,
    RunLineageError,
    RunManifest,
    RunManifestStore,
    RunManifestV1,
    RunManifestV2,
    RunPhase,
    RunReproducibilitySnapshot,
    RunRouteSnapshot,
    RuntimeEnvironmentSnapshot,
    RunVersionSnapshot,
)


NOW = datetime(2026, 7, 22, 16, 0, tzinfo=timezone.utc)


def _sha(index: int) -> str:
    return f"{index:064x}"


def _object_id(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def _uuid7(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def _ref(kind: str, index: int) -> VersionRef:
    return VersionRef(
        object_id=_object_id(kind, index),
        version=index + 1,
        content_sha256=_sha(index + 1),
    )


def _governed(kind: str, index: int) -> GovernedObjectRef:
    return GovernedObjectRef(
        object_id=_object_id(kind, index),
        content_sha256=_sha(index + 1),
    )


def _versions(index: int = 0) -> RunVersionSnapshot:
    return RunVersionSnapshot(
        model_descriptor_ref=_ref("model", index + 1),
        model_parameters_ref=_ref("model_parameters", index + 2),
        prompt_refs=(
            NamedVersionRef(name="reply", ref=_ref("prompt", index + 4)),
            NamedVersionRef(name="query_plan", ref=_ref("prompt", index + 3)),
        ),
        skill_refs=(
            NamedVersionRef(name="retrieval", ref=_ref("skill", index + 6)),
            NamedVersionRef(name="consultation", ref=_ref("skill", index + 5)),
        ),
        client_snapshot_ref=_ref("client_snapshot", index + 7),
        wiki_manifest_ref=_ref("wiki_manifest", index + 8),
        case_manifest_ref=_ref("case_manifest", index + 9),
        graph_manifest_ref=_ref("graph_manifest", index + 10),
        lexical_manifest_ref=_ref("lexical_manifest", index + 11),
        vector_manifest_ref=_ref("vector_manifest", index + 12),
        reranker_descriptor_ref=_ref("reranker", index + 13),
    )


def _routing(index: int = 0) -> RunRouteSnapshot:
    return RunRouteSnapshot(
        query_plan_ref=_ref("query_plan", index + 14),
        route_policy_ref=_ref("route_policy", index + 15),
        routes=("profile", "wiki", "lexical", "vector", "global_graph", "case"),
        filter_counts=RunFilterCounts(
            before=13,
            after=9,
            scope_denied=1,
            freshness_denied=1,
            review_denied=1,
            deduplicated=1,
        ),
    )


def _runtime(index: int = 0) -> RuntimeEnvironmentSnapshot:
    return RuntimeEnvironmentSnapshot(
        python_version="3.12.10",
        base_executable_sha256=_sha(index + 100),
        runtime_source_tag="dedicated_venv",
        runtime_source_sha256=_sha(index + 101),
        schema_bundle_sha256=_sha(index + 102),
        package_set_sha256=_sha(index + 103),
        dependency_lock_sha256=_sha(index + 104),
    )


def _evidence(
    versions: RunVersionSnapshot,
    index: int = 0,
) -> EvidencePackClosureV2:
    pack_ref = _ref("evidence_pack", index + 20)
    return EvidencePackClosureV2(
        evidence_pack_ref=pack_ref,
        evidence_pack_canonical_sha256=pack_ref.content_sha256,
        authority_snapshot_ref=_ref("authority_snapshot", index + 21),
        authority_policy_ref=_ref("authority_policy", index + 22),
        client_snapshot_ref=versions.client_snapshot_ref,
        temporary_fact_refs=(
            _ref("temporary_fact", index + 24),
            _ref("temporary_fact", index + 23),
        ),
        candidates=(
            EvidenceCandidateClosure(
                candidate_ref=_ref("evidence_candidate", index + 25),
                text_ref=_ref("evidence_text", index + 26),
                locator_ref=_ref("evidence_locator", index + 27),
                freshness_policy_ref=_ref("freshness_policy", index + 28),
                provenance_ref=_ref("provenance_record", index + 29),
                derivation_ref=_ref("derivation_record", index + 30),
            ),
        ),
        c1_revision_ref=_ref("c1_revision", index + 31),
        c1_scope_policy_ref=_ref("c1_scope_policy", index + 32),
        c1_applicability_ref=_ref("c1_applicability", index + 33),
        unresolved_conflict_refs=(_ref("conflict", index + 34),),
        exclusion_proof_ref=_ref("exclusion_proof", index + 35),
        wiki_manifest_ref=versions.wiki_manifest_ref,
        lexical_manifest_ref=versions.lexical_manifest_ref,
        vector_manifest_ref=versions.vector_manifest_ref,
        graph_manifest_ref=versions.graph_manifest_ref,
        reranker_descriptor_ref=versions.reranker_descriptor_ref,
    )


def _manifest_v2(index: int = 0) -> RunManifestV2:
    versions = _versions(index)
    run_id = _uuid7(index + 200)
    return RunManifestV2(
        run_id=run_id,
        run_kind="consultation_reply",
        scope_sha256=_sha(index + 300),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
        lineage=RunLineage(
            root_run_id=run_id,
            parent_run_id=None,
            phase="query",
            sequence=0,
            turn_ref=_governed("consultation_turn", index + 201),
        ),
        versions=versions,
        evidence=_evidence(versions, index),
        routing=_routing(index),
        runtime=_runtime(index),
        reproducibility=RunReproducibilitySnapshot(
            queue_order_seed=index + 400,
            generation_seed=index + 401,
            temperature_milli=700,
            host_unknown_fields=(),
        ),
        critique_error_codes=("RERANKER_UNAVAILABLE", "CRITIQUE_RETRY"),
        retry_count=1,
        degraded_components=("reranker",),
        generation_candidate_refs=(
            _governed("reply_candidate", index + 41),
            _governed("reply_candidate", index + 40),
        ),
        actual_reply_ref=_governed("actual_reply", index + 42),
        consultant_edit_diff_ref=_governed("consultant_diff", index + 43),
        consultant_review_decision="approved",
        consultant_review_ref=_governed("consultant_review", index + 44),
        archive_draft_ref=None,
        archive_decision="not_applicable",
        archive_decision_ref=None,
        result_sha256=_sha(index + 500),
    )


def _manifest_v1(index: int = 0) -> RunManifestV1:
    return RunManifestV1(
        run_id=_uuid7(index + 700),
        run_kind="consultation_reply",
        scope_sha256=_sha(index + 701),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        versions=_versions(index + 700),
        routing=_routing(index + 700),
        evidence_object_ids=(_object_id("evidence", index + 702),),
        critique_error_codes=(),
        retry_count=0,
        degraded_components=(),
        generation_candidate_refs=(_governed("reply_candidate", index + 703),),
        actual_reply_ref=_governed("actual_reply", index + 704),
        consultant_edit_diff_ref=None,
        archive_draft_ref=None,
        archive_decision="not_applicable",
        archive_decision_ref=None,
        result_sha256=_sha(index + 705),
    )


def _stage(
    root: RunManifestV2,
    parent: RunManifestV2,
    *,
    index: int,
    phase: RunPhase,
) -> RunManifestV2:
    run_id = _uuid7(index)
    return root.model_copy(
        update={
            "run_id": run_id,
            "lineage": RunLineage(
                root_run_id=root.run_id,
                parent_run_id=parent.run_id,
                phase=phase,
                sequence=parent.lineage.sequence + 1,
                turn_ref=root.lineage.turn_ref,
            ),
        }
    )


def _archive_stage(
    root: RunManifestV2,
    parent: RunManifestV2,
    *,
    index: int,
) -> RunManifestV2:
    run_id = _uuid7(index)
    return root.model_copy(
        update={
            "run_id": run_id,
            "run_kind": "archive",
            "lineage": RunLineage(
                root_run_id=root.run_id,
                parent_run_id=parent.run_id,
                phase="archive",
                sequence=parent.lineage.sequence + 1,
                turn_ref=root.lineage.turn_ref,
            ),
            "generation_candidate_refs": (),
            "actual_reply_ref": None,
            "consultant_edit_diff_ref": None,
            "consultant_review_decision": "not_applicable",
            "consultant_review_ref": None,
            "archive_draft_ref": _governed("archive_draft", index + 1),
            "archive_decision": "approved",
            "archive_decision_ref": _governed("archive_decision", index + 2),
        }
    )


def _metric(index: int = 0) -> MetricPoint:
    run_id = _uuid7(index + 900)
    return MetricPoint(
        metric_id=_object_id("metric", index + 901),
        run_id=run_id,
        root_run_id=run_id,
        parent_run_id=None,
        occurred_at=NOW,
        scope_bucket_sha256=_sha(index + 902),
        name="candidate_count",
        value=3,
        unit="count",
        dimensions=(
            MetricDimension(name="status", value="succeeded"),
            MetricDimension(name="run_phase", value="retrieval"),
            MetricDimension(name="run_kind", value="consultation_reply"),
        ),
    )


def test_v2_captures_complete_exact_closure_without_body_channels() -> None:
    manifest = _manifest_v2()

    assert manifest.schema_version == "2.0"
    assert manifest.evidence.evidence_pack_canonical_sha256 == (
        manifest.evidence.evidence_pack_ref.content_sha256
    )
    assert manifest.evidence.temporary_fact_refs == tuple(
        sorted(
            manifest.evidence.temporary_fact_refs,
            key=lambda ref: (ref.object_id, ref.version, ref.content_sha256),
        )
    )
    assert set(manifest.actual_reply_ref.model_dump()) == {  # type: ignore[union-attr]
        "object_id",
        "content_sha256",
    }
    assert all(
        set(reference.model_dump()) == {"object_id", "content_sha256"}
        for reference in manifest.generation_candidate_refs
    )

    schema = RunManifestV2.model_json_schema()
    assert schema["additionalProperties"] is False
    for definition in schema["$defs"].values():
        if "properties" in definition:
            assert definition["additionalProperties"] is False

    top_level = manifest.model_dump()
    top_level["raw_body"] = "BODY_CANARY"
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(top_level)

    nested_runtime = manifest.model_dump()
    nested_runtime["runtime"]["base_executable_path"] = "C:\\private\\python.exe"
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(nested_runtime)

    expanded_authority = manifest.model_dump()
    expanded_authority["evidence"]["full_authority"] = "FULL_AUTHORITY_CANARY"
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(expanded_authority)

    expanded_provenance = manifest.model_dump()
    expanded_provenance["evidence"]["candidates"][0]["full_provenance"] = (
        "FULL_PROVENANCE_CANARY"
    )
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(expanded_provenance)

    reply_body = manifest.model_dump()
    reply_body["actual_reply_ref"]["text"] = "BODY_CANARY"
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(reply_body)


def test_v2_rejects_incomplete_or_conflicting_exact_closure() -> None:
    manifest = _manifest_v2()

    pack_mismatch = manifest.model_dump()
    pack_mismatch["evidence"]["evidence_pack_canonical_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="canonical hash"):
        RunManifestV2.model_validate(pack_mismatch)

    root_mismatch = manifest.model_dump()
    root_mismatch["evidence"]["wiki_manifest_ref"]["content_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="disagree"):
        RunManifestV2.model_validate(root_mismatch)

    conflict = manifest.model_dump()
    model_ref = conflict["versions"]["model_descriptor_ref"]
    conflict["evidence"]["authority_policy_ref"] = {
        **model_ref,
        "content_sha256": "f" * 64,
    }
    with pytest.raises(ValidationError, match="conflicting exact version"):
        RunManifestV2.model_validate(conflict)


def test_runtime_hashes_approved_interpreter_and_rejects_codex_cache(
    tmp_path: Path,
) -> None:
    interpreter = tmp_path / "production" / "python.exe"
    interpreter.parent.mkdir()
    interpreter.write_bytes(b"synthetic approved interpreter")
    hashes = {
        "runtime_source_sha256": _sha(1),
        "schema_bundle_sha256": _sha(2),
        "package_set_sha256": _sha(3),
        "dependency_lock_sha256": _sha(4),
    }

    runtime = RuntimeEnvironmentSnapshot.from_base_executable(
        base_executable=interpreter,
        python_version="3.12.10",
        runtime_source_tag="managed_install",
        **hashes,
    )

    assert runtime.base_executable_sha256 == hashlib.sha256(
        interpreter.read_bytes()
    ).hexdigest()
    serialized = runtime.model_dump_json()
    assert str(interpreter) not in serialized
    assert "path" not in serialized.casefold()

    cached = tmp_path / ".cache" / "codex-runtimes" / "runtime" / "python.exe"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"forbidden interpreter")
    with pytest.raises(ValueError, match="Codex cache interpreter"):
        RuntimeEnvironmentSnapshot.from_base_executable(
            base_executable=cached,
            python_version="3.12.10",
            runtime_source_tag="managed_install",
            **hashes,
        )


def test_store_dispatches_v1_and_v2_and_enforces_one_turn_lineage(
    tmp_path: Path,
) -> None:
    store = RunManifestStore(tmp_path / "runs.jsonl")
    legacy = _manifest_v1()
    root = _manifest_v2()
    retrieval = _stage(root, root, index=1001, phase="retrieval")
    generation = _stage(root, retrieval, index=1002, phase="generation_stage")
    final_candidate = _stage(root, generation, index=1003, phase="final_candidate")
    actual_reply = _stage(root, final_candidate, index=1004, phase="actual_reply")
    archive = _archive_stage(root, actual_reply, index=1005)

    for manifest in (
        legacy,
        root,
        retrieval,
        generation,
        final_candidate,
        actual_reply,
        archive,
    ):
        store.append(manifest)

    loaded = store.load()
    assert loaded == (
        legacy,
        root,
        retrieval,
        generation,
        final_candidate,
        actual_reply,
        archive,
    )
    assert isinstance(loaded[0], RunManifestV1)
    assert all(isinstance(item, RunManifestV2) for item in loaded[1:])
    assert tuple(item.schema_version for item in loaded) == (
        "1.0",
        "2.0",
        "2.0",
        "2.0",
        "2.0",
        "2.0",
        "2.0",
    )
    assert RunManifest is RunManifestV1


def test_store_rejects_unknown_cross_scope_cross_turn_and_duplicate_lineage(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runs.jsonl"
    store = RunManifestStore(path)
    root = _manifest_v2()
    store.append(root)
    committed = path.read_bytes()

    unknown_parent = _stage(root, root, index=1101, phase="retrieval").model_copy(
        update={
            "lineage": RunLineage(
                root_run_id=root.run_id,
                parent_run_id=_uuid7(1199),
                phase="retrieval",
                sequence=1,
                turn_ref=root.lineage.turn_ref,
            )
        }
    )
    with pytest.raises(RunLineageError, match="not already committed"):
        store.append(unknown_parent)

    cross_scope = _stage(root, root, index=1102, phase="retrieval").model_copy(
        update={"scope_sha256": _sha(9999)}
    )
    with pytest.raises(RunLineageError, match="scope|disagrees"):
        store.append(cross_scope)

    changed_turn = _stage(root, root, index=1103, phase="retrieval").model_copy(
        update={
            "lineage": RunLineage(
                root_run_id=root.run_id,
                parent_run_id=root.run_id,
                phase="retrieval",
                sequence=1,
                turn_ref=root.lineage.turn_ref.model_copy(
                    update={"content_sha256": "f" * 64}
                ),
            )
        }
    )
    with pytest.raises(RunLineageError):
        store.append(changed_turn)

    duplicate_across_scope = root.model_copy(update={"scope_sha256": _sha(9998)})
    with pytest.raises(DuplicateRunError):
        store.append(duplicate_across_scope)

    assert path.read_bytes() == committed


def test_audit_v2_round_trips_refs_and_preserves_v1_compatibility(
    tmp_path: Path,
) -> None:
    sink = AuditSink(tmp_path / "audit.jsonl")
    root = _manifest_v2()
    legacy = AuditEventV1(
        event_id=_object_id("audit", 1200),
        run_id=_uuid7(1201),
        event_type="run_started",
        occurred_at=NOW,
        scope_sha256=_sha(1202),
        counts=FrozenCounts({"records": 1}),
    )
    event = AuditEventV2(
        event_id=_object_id("audit", 1203),
        run_id=root.run_id,
        event_type="run_completed",
        occurred_at=NOW,
        scope_sha256=root.scope_sha256,
        object_ids=(_object_id("result", 1204),),
        versions=(root.evidence.evidence_pack_ref,),
        counts=FrozenCounts({"evidence": 1, "records": 1}),
        result_sha256=root.result_sha256,
        root_run_id=root.run_id,
        parent_run_id=None,
        governed_refs=(
            root.evidence.evidence_pack_ref,
            root.versions.model_descriptor_ref,
        ),
    )

    sink.emit(legacy)
    sink.emit(event)

    assert sink.load() == (legacy, event)
    assert AuditEventV1.model_fields["schema_version"].default == "1.0"
    assert AuditEventV2.model_fields["schema_version"].default == "2.0"
    payload = event.model_dump()
    payload["content"] = "BODY_CANARY"
    with pytest.raises(ValidationError):
        AuditEventV2.model_validate(payload)

    conflicting = event.model_dump()
    conflicting["governed_refs"] = (
        event.versions[0].model_copy(update={"content_sha256": "f" * 64}),
    )
    with pytest.raises(ValidationError, match="conflicting exact version"):
        AuditEventV2.model_validate(conflicting)


def test_metrics_are_registry_only_numeric_and_append_only(tmp_path: Path) -> None:
    point = _metric()
    assert tuple(item.name for item in point.dimensions) == (
        "run_kind",
        "run_phase",
        "status",
    )

    body = point.model_dump()
    body["details"] = "BODY_CANARY"
    with pytest.raises(ValidationError):
        MetricPoint.model_validate(body)

    arbitrary_dimension = point.model_dump()
    arbitrary_dimension["dimensions"][0]["value"] = "client" + "_a1b2c3d4e5f6"
    with pytest.raises(ValidationError):
        MetricPoint.model_validate(arbitrary_dimension)

    float_count = point.model_dump()
    float_count["value"] = 3.0
    with pytest.raises(ValidationError, match="exact integers"):
        MetricPoint.model_validate(float_count)

    nonfinite = point.model_dump()
    nonfinite.update({"name": "evaluation_score", "unit": "score", "value": float("nan")})
    with pytest.raises(ValidationError, match="finite"):
        MetricPoint.model_validate(nonfinite)

    wrong_pair = point.model_dump()
    dimensions = list(wrong_pair["dimensions"])
    dimensions[0] = {
        "name": "run_kind",
        "value": "succeeded",
    }
    wrong_pair["dimensions"] = tuple(dimensions)
    with pytest.raises(ValidationError, match="not registered"):
        MetricPoint.model_validate(wrong_pair)

    sink = MetricsSink(tmp_path / "metrics.jsonl")
    sink.emit(point)
    committed = sink.path.read_bytes()
    assert sink.load() == (point,)
    with pytest.raises(ObservabilityStoreError, match="already present"):
        sink.emit(point)
    assert sink.path.read_bytes() == committed
