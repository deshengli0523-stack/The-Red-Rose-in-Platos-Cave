from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.observability.audit import AuditEventV2, AuditSink, FrozenCounts
from consultation_kb.observability.metrics_sink import (
    MetricDimension,
    MetricPoint,
    MetricsSink,
)
from consultation_kb.observability.runs import (
    EvidenceCandidateClosure,
    EvidencePackClosureV2,
    GovernedObjectRef,
    NamedVersionRef,
    RunFilterCounts,
    RunLineage,
    RunManifestStore,
    RunManifestV2,
    RunPhase,
    RunReproducibilitySnapshot,
    RunRouteSnapshot,
    RuntimeEnvironmentSnapshot,
    RunVersionSnapshot,
)


pytestmark = pytest.mark.integration
NOW = datetime(2026, 7, 22, 18, 0, tzinfo=timezone.utc)


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


def _root_manifest() -> RunManifestV2:
    versions = RunVersionSnapshot(
        model_descriptor_ref=_ref("model", 1),
        model_parameters_ref=_ref("model_parameters", 2),
        prompt_refs=(NamedVersionRef(name="reply", ref=_ref("prompt", 3)),),
        skill_refs=(
            NamedVersionRef(name="consultation", ref=_ref("skill", 4)),
        ),
        client_snapshot_ref=_ref("client_snapshot", 5),
        wiki_manifest_ref=_ref("wiki_manifest", 6),
        case_manifest_ref=_ref("case_manifest", 7),
        graph_manifest_ref=_ref("graph_manifest", 8),
        lexical_manifest_ref=_ref("lexical_manifest", 9),
        vector_manifest_ref=_ref("vector_manifest", 10),
        reranker_descriptor_ref=_ref("reranker", 11),
    )
    evidence_pack_ref = _ref("evidence_pack", 12)
    evidence = EvidencePackClosureV2(
        evidence_pack_ref=evidence_pack_ref,
        evidence_pack_canonical_sha256=evidence_pack_ref.content_sha256,
        authority_snapshot_ref=_ref("authority_snapshot", 13),
        authority_policy_ref=_ref("authority_policy", 14),
        client_snapshot_ref=versions.client_snapshot_ref,
        temporary_fact_refs=(_ref("temporary_fact", 15),),
        candidates=(
            EvidenceCandidateClosure(
                candidate_ref=_ref("evidence_candidate", 16),
                text_ref=_ref("evidence_text", 17),
                locator_ref=_ref("evidence_locator", 18),
                freshness_policy_ref=_ref("freshness_policy", 19),
                provenance_ref=_ref("provenance_record", 20),
                derivation_ref=_ref("derivation_record", 21),
            ),
        ),
        c1_revision_ref=_ref("c1_revision", 22),
        c1_scope_policy_ref=_ref("c1_scope_policy", 23),
        c1_applicability_ref=_ref("c1_applicability", 24),
        unresolved_conflict_refs=(_ref("conflict", 25),),
        exclusion_proof_ref=_ref("exclusion_proof", 26),
        wiki_manifest_ref=versions.wiki_manifest_ref,
        lexical_manifest_ref=versions.lexical_manifest_ref,
        vector_manifest_ref=versions.vector_manifest_ref,
        graph_manifest_ref=versions.graph_manifest_ref,
        reranker_descriptor_ref=versions.reranker_descriptor_ref,
    )
    run_id = _uuid7(100)
    return RunManifestV2(
        run_id=run_id,
        run_kind="consultation_reply",
        scope_sha256=_sha(101),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=3),
        lineage=RunLineage(
            root_run_id=run_id,
            parent_run_id=None,
            phase="query",
            sequence=0,
            turn_ref=_governed("consultation_turn", 102),
        ),
        versions=versions,
        evidence=evidence,
        routing=RunRouteSnapshot(
            query_plan_ref=_ref("query_plan", 27),
            route_policy_ref=_ref("route_policy", 28),
            routes=("profile", "wiki", "lexical", "vector", "global_graph", "case"),
            filter_counts=RunFilterCounts(
                before=8,
                after=6,
                authorization_denied=1,
                freshness_denied=1,
            ),
        ),
        runtime=RuntimeEnvironmentSnapshot(
            python_version="3.12.10",
            base_executable_sha256=_sha(29),
            runtime_source_tag="dedicated_venv",
            runtime_source_sha256=_sha(30),
            schema_bundle_sha256=_sha(31),
            package_set_sha256=_sha(32),
            dependency_lock_sha256=_sha(33),
        ),
        reproducibility=RunReproducibilitySnapshot(
            queue_order_seed=1000,
            generation_seed=None,
            temperature_milli=None,
            host_unknown_fields=("temperature", "generation_seed"),
        ),
        critique_error_codes=(),
        retry_count=0,
        degraded_components=(),
        generation_candidate_refs=(_governed("reply_candidate", 103),),
        actual_reply_ref=_governed("actual_reply", 104),
        consultant_edit_diff_ref=_governed("consultant_diff", 105),
        consultant_review_decision="approved",
        consultant_review_ref=_governed("consultant_review", 106),
        archive_draft_ref=None,
        archive_decision="not_applicable",
        archive_decision_ref=None,
        result_sha256=_sha(107),
    )


def _child_stage(
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
) -> RunManifestV2:
    run_id = _uuid7(205)
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
            "archive_draft_ref": _governed("archive_draft", 206),
            "archive_decision": "approved",
            "archive_decision_ref": _governed("archive_decision", 207),
        }
    )


def _evaluation_stage(
    root: RunManifestV2,
    parent: RunManifestV2,
) -> RunManifestV2:
    run_id = _uuid7(208)
    return root.model_copy(
        update={
            "run_id": run_id,
            "run_kind": "evaluation",
            "lineage": RunLineage(
                root_run_id=root.run_id,
                parent_run_id=parent.run_id,
                phase="evaluation",
                sequence=parent.lineage.sequence + 1,
                turn_ref=root.lineage.turn_ref,
            ),
            "generation_candidate_refs": (),
            "actual_reply_ref": None,
            "consultant_edit_diff_ref": None,
            "consultant_review_decision": "not_applicable",
            "consultant_review_ref": None,
            "archive_draft_ref": None,
            "archive_decision": "not_applicable",
            "archive_decision_ref": None,
        }
    )


def test_turn_observability_keeps_shared_storage_body_free(tmp_path: Path) -> None:
    shared = tmp_path / "shared_observability"
    private = tmp_path / "private_client_cas"
    shared.mkdir()
    private.mkdir()
    synthetic_client_oracle = "client" + "_a1b2c3d4e5f6"
    canaries = (
        "BODY_CANARY_CLIENT_SAID_PARTNER_CHANGED",
        synthetic_client_oracle,
        rf"C:\Clients\{synthetic_client_oracle}\session.txt",
        "FULL_AUTHORITY_CANARY_CONSULTANT_THEORY",
        "FULL_PROVENANCE_CANARY_SOURCE_PARAGRAPH",
    )
    private_body = private / "session-body.txt"
    private_body.write_text("\n".join(canaries), encoding="utf-8")

    root = _root_manifest()
    retrieval = _child_stage(root, root, index=201, phase="retrieval")
    generation = _child_stage(
        root,
        retrieval,
        index=202,
        phase="generation_stage",
    )
    final_candidate = _child_stage(
        root,
        generation,
        index=203,
        phase="final_candidate",
    )
    actual_reply = _child_stage(
        root,
        final_candidate,
        index=204,
        phase="actual_reply",
    )
    archive = _archive_stage(root, actual_reply)
    evaluation = _evaluation_stage(root, archive)
    expected = (
        root,
        retrieval,
        generation,
        final_candidate,
        actual_reply,
        archive,
        evaluation,
    )

    run_store = RunManifestStore(shared / "runs.jsonl")
    for manifest in expected:
        run_store.append(manifest)

    actual_reply_ref = actual_reply.actual_reply_ref
    assert actual_reply_ref is not None
    actual_reply_version = VersionRef(
        object_id=actual_reply_ref.object_id,
        version=1,
        content_sha256=actual_reply_ref.content_sha256,
    )
    audit_event = AuditEventV2(
        event_id=_object_id("audit", 300),
        run_id=actual_reply.run_id,
        event_type="generation_completed",
        occurred_at=NOW,
        scope_sha256=root.scope_sha256,
        object_ids=(),
        versions=(root.evidence.evidence_pack_ref,),
        counts=FrozenCounts({"candidates": 1, "evidence": 1, "retries": 0}),
        result_sha256=actual_reply.result_sha256,
        root_run_id=root.run_id,
        parent_run_id=final_candidate.run_id,
        governed_refs=(
            root.evidence.evidence_pack_ref,
            root.evidence.authority_snapshot_ref,
            root.evidence.candidates[0].provenance_ref,
            actual_reply_version,
        ),
    )
    evaluation_event = AuditEventV2(
        event_id=_object_id("audit", 303),
        run_id=evaluation.run_id,
        event_type="evaluation_completed",
        occurred_at=NOW,
        scope_sha256=root.scope_sha256,
        counts=FrozenCounts({"records": 1}),
        result_sha256=evaluation.result_sha256,
        root_run_id=root.run_id,
        parent_run_id=archive.run_id,
        governed_refs=(root.evidence.evidence_pack_ref,),
    )
    audit_sink = AuditSink(shared / "audit.jsonl")
    audit_sink.emit(audit_event)
    audit_sink.emit(evaluation_event)

    metric = MetricPoint(
        metric_id=_object_id("metric", 301),
        run_id=actual_reply.run_id,
        root_run_id=root.run_id,
        parent_run_id=final_candidate.run_id,
        occurred_at=NOW,
        scope_bucket_sha256=_sha(302),
        name="selected_evidence_count",
        value=1,
        unit="count",
        dimensions=(
            MetricDimension(name="run_kind", value="consultation_reply"),
            MetricDimension(name="run_phase", value="actual_reply"),
            MetricDimension(name="status", value="succeeded"),
        ),
    )
    evaluation_metric = MetricPoint(
        metric_id=_object_id("metric", 304),
        run_id=evaluation.run_id,
        root_run_id=root.run_id,
        parent_run_id=archive.run_id,
        occurred_at=NOW,
        scope_bucket_sha256=_sha(302),
        name="evaluation_score",
        value=0.82,
        unit="score",
        dimensions=(
            MetricDimension(name="evaluation_split", value="test"),
            MetricDimension(name="run_kind", value="evaluation"),
            MetricDimension(name="run_phase", value="evaluation"),
            MetricDimension(name="status", value="succeeded"),
        ),
    )
    metrics_sink = MetricsSink(shared / "metrics.jsonl")
    metrics_sink.emit(metric)
    metrics_sink.emit(evaluation_metric)

    assert run_store.load() == expected
    assert tuple(item.lineage.phase for item in expected) == (
        "query",
        "retrieval",
        "generation_stage",
        "final_candidate",
        "actual_reply",
        "archive",
        "evaluation",
    )
    for parent, child in zip(expected, expected[1:]):
        assert child.lineage.root_run_id == root.run_id
        assert child.lineage.parent_run_id == parent.run_id
        assert child.lineage.turn_ref == root.lineage.turn_ref

    assert set(actual_reply.actual_reply_ref.model_dump()) == {  # type: ignore[union-attr]
        "object_id",
        "content_sha256",
    }
    assert set(actual_reply.generation_candidate_refs[0].model_dump()) == {
        "object_id",
        "content_sha256",
    }

    body_in_manifest = actual_reply.model_dump()
    body_in_manifest["actual_reply_ref"]["text"] = canaries[0]
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(body_in_manifest)

    client_in_manifest = actual_reply.model_dump()
    client_in_manifest["client_id"] = canaries[1]
    with pytest.raises(ValidationError):
        RunManifestV2.model_validate(client_in_manifest)

    provenance_in_audit = audit_event.model_dump()
    provenance_in_audit["full_provenance"] = canaries[4]
    with pytest.raises(ValidationError):
        AuditEventV2.model_validate(provenance_in_audit)

    label_in_metric = metric.model_dump()
    label_in_metric["label"] = canaries[0]
    with pytest.raises(ValidationError):
        MetricPoint.model_validate(label_in_metric)

    shared_bytes = b"".join(
        path.read_bytes()
        for path in sorted(shared.rglob("*"))
        if path.is_file()
    )
    assert private_body.read_bytes()
    for canary in canaries:
        assert canary.encode("utf-8") not in shared_bytes
        escaped = json.dumps(canary, ensure_ascii=True)[1:-1].encode("ascii")
        assert escaped not in shared_bytes
