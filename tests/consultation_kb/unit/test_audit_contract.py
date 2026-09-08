from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.observability.audit import (
    AuditEvent,
    AuditSink,
    FrozenCounts,
    ObservabilityCorruptionError,
    ObservabilityStoreError,
)
from consultation_kb.observability import audit as audit_module
from consultation_kb.observability.runs import (
    DuplicateRunError,
    GovernedObjectRef,
    NamedVersionRef,
    RunFilterCounts,
    RunManifest,
    RunManifestStore,
    RunRouteSnapshot,
    RunVersionSnapshot,
)
from consultation_kb.observability import runs as runs_module


NOW = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)


def _sha(index: int) -> str:
    return f"{index:064x}"


def _object_id(kind: str, index: int = 0) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def _uuid7(index: int = 0) -> str:
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


def _event(index: int = 0) -> AuditEvent:
    return AuditEvent(
        event_id=_object_id("audit", index),
        run_id=_uuid7(index + 10),
        event_type="scope_denied",
        occurred_at=NOW,
        scope_sha256=_sha(index + 20),
        object_ids=(_object_id("result", index + 2), _object_id("input", index + 1)),
        versions=(_ref("policy", index + 4), _ref("schema", index + 3)),
        counts=FrozenCounts({"filtered": 2, "denied": 1}),
        error_codes=("SCOPE_DENIED", "POLICY_REJECTED"),
        result_sha256=_sha(index + 30),
    )


def _manifest(index: int = 0) -> RunManifest:
    versions = RunVersionSnapshot(
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
    routing = RunRouteSnapshot(
        query_plan_ref=_ref("query_plan", index + 14),
        route_policy_ref=_ref("route_policy", index + 15),
        routes=("lexical", "vector", "global_graph"),
        filter_counts=RunFilterCounts(before=12, after=10, scope_denied=2),
    )
    return RunManifest(
        run_id=_uuid7(index + 100),
        run_kind="consultation_reply",
        scope_sha256=_sha(index + 40),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        versions=versions,
        routing=routing,
        evidence_object_ids=(
            _object_id("evidence", index + 16),
            _object_id("evidence", index + 17),
        ),
        critique_error_codes=("RERANKER_UNAVAILABLE", "CRITIQUE_RETRY"),
        retry_count=1,
        degraded_components=("reranker",),
        generation_candidate_refs=(
            _governed("reply_candidate", index + 18),
            _governed("reply_candidate", index + 19),
        ),
        actual_reply_ref=_governed("actual_reply", index + 20),
        consultant_edit_diff_ref=_governed("reply_diff", index + 21),
        archive_draft_ref=None,
        archive_decision="not_applicable",
        archive_decision_ref=None,
        result_sha256=_sha(index + 50),
    )


@pytest.mark.parametrize(
    "forbidden_field",
    ["raw_text", "details", "transcript", "prompt", "content"],
)
def test_audit_event_rejects_body_escape_fields(forbidden_field: str) -> None:
    values = _event().model_dump()
    values[forbidden_field] = "synthetic client body"

    with pytest.raises(ValidationError):
        AuditEvent.model_validate(values)


def test_audit_event_is_canonical_deeply_immutable_and_round_trips() -> None:
    source_counts = {"filtered": 2, "denied": 1}
    event = _event().model_copy(update={"counts": source_counts})
    source_counts["denied"] = 99

    assert tuple(event.counts.items()) == (("denied", 1), ("filtered", 2))
    assert event.object_ids == tuple(sorted(event.object_ids))
    assert tuple(ref.object_id for ref in event.versions) == tuple(
        sorted(ref.object_id for ref in event.versions)
    )
    assert event.error_codes == ("POLICY_REJECTED", "SCOPE_DENIED")
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event
    with pytest.raises(TypeError):
        event.counts["denied"] = 3  # type: ignore[index]
    with pytest.raises(ValidationError):
        event.model_copy(update={"counts": {"denied": True}})
    with pytest.raises(ValidationError):
        event.model_copy(update={"counts": {"client_" + "a1b2c3d4e5f6": 1}})


def test_audit_event_rejects_conflicting_hashes_for_one_object_version() -> None:
    original = _ref("policy", 700)
    conflicting = original.model_copy(update={"content_sha256": "f" * 64})

    with pytest.raises(ValidationError, match="conflicting content hashes"):
        _event().model_copy(update={"versions": (original, conflicting)})


def test_audit_schema_has_only_fixed_safe_fields() -> None:
    schema = AuditEvent.model_json_schema()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "schema_version",
        "event_id",
        "run_id",
        "event_type",
        "occurred_at",
        "scope_sha256",
        "object_ids",
        "versions",
        "counts",
        "error_codes",
        "result_sha256",
    }
    counts_schema = schema["properties"]["counts"]
    assert counts_schema["additionalProperties"] == {
        "minimum": 0,
        "type": "integer",
    }


def test_version_one_models_are_explicitly_frozen_dispatch_targets() -> None:
    assert audit_module.AuditEventV1 is AuditEvent
    assert runs_module.RunManifestV1 is RunManifest
    assert AuditEvent.model_fields["schema_version"].default == "1.0"
    assert RunManifest.model_fields["schema_version"].default == "1.0"


def test_audit_sink_appends_canonical_lines_and_reloads(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = AuditSink(path)
    first_event = _event(0)
    second_event = _event(1)

    assert sink.load() == ()
    sink.emit(first_event)
    first_bytes = path.read_bytes()
    sink.emit(second_event)
    all_bytes = path.read_bytes()

    assert all_bytes.startswith(first_bytes)
    assert all_bytes.count(b"\n") == 2
    assert b"\r" not in all_bytes
    assert sink.load() == (first_event, second_event)
    for line in all_bytes.splitlines():
        assert line == json.dumps(
            json.loads(line),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")


def test_audit_sink_fails_closed_on_duplicate_or_corrupt_stream(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = AuditSink(path)
    sink.emit(_event())

    before_duplicate = path.read_bytes()
    with pytest.raises(ObservabilityStoreError, match="already present"):
        sink.emit(_event())
    assert path.read_bytes() == before_duplicate

    path.write_bytes(before_duplicate + before_duplicate)
    with pytest.raises(ObservabilityCorruptionError, match="duplicate event ID"):
        sink.load()

    path.write_bytes(before_duplicate + b'{"raw_text":"synthetic client body"}\n')
    corrupt_bytes = path.read_bytes()
    with pytest.raises(ObservabilityCorruptionError):
        sink.load()
    with pytest.raises(ObservabilityCorruptionError):
        sink.emit(_event(2))
    assert path.read_bytes() == corrupt_bytes


def test_audit_sink_revalidates_an_internally_tampered_model(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    unsafe = _event()
    object.__setattr__(unsafe, "counts", {"denied": "synthetic client body"})

    with pytest.raises(ValidationError):
        AuditSink(path).emit(unsafe)
    assert not path.exists()


def test_run_manifest_rejects_body_fields_at_every_governed_boundary() -> None:
    manifest = _manifest()
    top_level = manifest.model_dump()
    top_level["actual_reply_text"] = "synthetic client body"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(top_level)

    nested = manifest.model_dump()
    assert isinstance(nested["actual_reply_ref"], dict)
    nested["actual_reply_ref"]["text"] = "synthetic client body"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(nested)

    encoded = manifest.model_dump_json()
    assert "synthetic client body" not in encoded
    assert set(manifest.actual_reply_ref.model_dump()) == {  # type: ignore[union-attr]
        "object_id",
        "content_sha256",
    }


def test_run_manifest_canonicalizes_versions_counts_and_safe_statuses() -> None:
    manifest = _manifest()

    assert tuple(item.name for item in manifest.versions.prompt_refs) == (
        "query_plan",
        "reply",
    )
    assert tuple(item.name for item in manifest.versions.skill_refs) == (
        "consultation",
        "retrieval",
    )
    filter_counts = manifest.routing.filter_counts.model_dump()
    assert filter_counts["before"] == 12
    assert filter_counts["after"] == 10
    assert filter_counts["scope_denied"] == 2
    assert sum(
        value
        for name, value in filter_counts.items()
        if name not in {"before", "after"}
    ) == 2
    assert manifest.critique_error_codes == (
        "CRITIQUE_RETRY",
        "RERANKER_UNAVAILABLE",
    )
    assert RunManifest.model_validate_json(manifest.model_dump_json()) == manifest

    with pytest.raises(ValidationError, match="completed_at"):
        manifest.model_copy(update={"completed_at": NOW - timedelta(seconds=1)})
    with pytest.raises(ValidationError, match="archive state"):
        manifest.model_copy(update={"archive_decision": "approved"})


def test_run_manifest_store_is_append_only_unique_and_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "runs.jsonl"
    store = RunManifestStore(path)
    first = _manifest(0)
    second = _manifest(1000)

    assert store.load() == ()
    store.append(first)
    first_bytes = path.read_bytes()
    store.append(second)
    complete_bytes = path.read_bytes()
    assert complete_bytes.startswith(first_bytes)
    assert store.load() == (first, second)

    with pytest.raises(DuplicateRunError):
        store.append(first)
    assert path.read_bytes() == complete_bytes

    path.write_bytes(complete_bytes + b'{"run_id":')
    corrupt_bytes = path.read_bytes()
    with pytest.raises(ObservabilityCorruptionError):
        store.load()
    with pytest.raises(ObservabilityCorruptionError):
        store.append(_manifest(2000))
    assert path.read_bytes() == corrupt_bytes


def test_store_constructors_and_count_inputs_reject_ambiguous_types() -> None:
    with pytest.raises(TypeError):
        AuditSink("audit.jsonl")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RunManifestStore("runs.jsonl")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        FrozenCounts({"denied": -1})
    with pytest.raises(ValueError):
        FrozenCounts({"denied": True})


def test_observability_labels_are_registry_controlled_not_prose_channels() -> None:
    body_like_label = "she_lives_at_123_main_street"
    body_like_error = "SHE_LIVES_AT_123_MAIN_STREET"

    event = _event().model_dump()
    event["event_type"] = body_like_label
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(event)
    with pytest.raises(ValueError):
        FrozenCounts({body_like_label: 1})
    event = _event().model_dump()
    event["error_codes"] = (body_like_error,)
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(event)

    with pytest.raises(ValidationError):
        NamedVersionRef(name=body_like_label, ref=_ref("prompt", 900))
    routing = _manifest().routing.model_dump()
    routing["routes"] = (body_like_label,)
    with pytest.raises(ValidationError):
        RunRouteSnapshot.model_validate(routing)
    manifest = _manifest().model_dump()
    manifest["degraded_components"] = (body_like_label,)
    with pytest.raises(ValidationError):
        RunManifest.model_validate(manifest)


def test_audit_duplicate_check_and_append_are_serialized_per_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "audit.jsonl"
    original_append = audit_module._append_line

    def slow_append(target: Path, line: bytes) -> None:
        time.sleep(0.05)
        original_append(target, line)

    monkeypatch.setattr(audit_module, "_append_line", slow_append)
    start = threading.Barrier(3)

    def emit(sink: AuditSink) -> str:
        start.wait()
        try:
            sink.emit(_event())
        except ObservabilityStoreError:
            return "duplicate"
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(emit, AuditSink(path)) for _ in range(2)]
        start.wait()
        results = sorted(future.result(timeout=5) for future in futures)

    assert results == ["duplicate", "ok"]
    assert AuditSink(path).load() == (_event(),)


def test_manifest_duplicate_check_and_append_are_serialized_per_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runs.jsonl"
    original_append = runs_module._append_line

    def slow_append(target: Path, line: bytes) -> None:
        time.sleep(0.05)
        original_append(target, line)

    monkeypatch.setattr(runs_module, "_append_line", slow_append)
    start = threading.Barrier(3)

    def append(store: RunManifestStore) -> str:
        start.wait()
        try:
            store.append(_manifest())
        except DuplicateRunError:
            return "duplicate"
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(append, RunManifestStore(path)) for _ in range(2)]
        start.wait()
        results = sorted(future.result(timeout=5) for future in futures)

    assert results == ["duplicate", "ok"]
    assert RunManifestStore(path).load() == (_manifest(),)


def test_audit_duplicate_check_is_serialized_between_processes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    start = tmp_path / "start"
    ready_paths = (tmp_path / "ready-1", tmp_path / "ready-2")
    script = "\n".join(
        (
            "import sys, time",
            "from pathlib import Path",
            "from consultation_kb.observability import audit as module",
            "from consultation_kb.observability.audit import AuditEvent, AuditSink, ObservabilityStoreError",
            "target, raw, ready, start = sys.argv[1:]",
            "original = module._append_line",
            "def slow_append(path, line):",
            "    time.sleep(0.2)",
            "    original(path, line)",
            "module._append_line = slow_append",
            "Path(ready).touch()",
            "while not Path(start).exists(): time.sleep(0.01)",
            "try:",
            "    AuditSink(Path(target)).emit(AuditEvent.model_validate_json(raw))",
            "except ObservabilityStoreError:",
            "    print('duplicate')",
            "else:",
            "    print('ok')",
        )
    )
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(path),
                _event().model_dump_json(),
                str(ready),
                str(start),
            ],
            cwd=Path(__file__).resolve().parents[3],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for ready in ready_paths
    ]
    deadline = time.monotonic() + 5
    while not all(ready.exists() for ready in ready_paths):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    start.touch()
    outputs = [process.communicate(timeout=10) for process in processes]

    assert all(process.returncode == 0 for process in processes), outputs
    assert sorted(stdout.strip() for stdout, _stderr in outputs) == ["duplicate", "ok"]
    assert AuditSink(path).load() == (_event(),)


def test_run_manifest_rejects_incoherent_run_shapes_and_version_closure() -> None:
    edit_without_reply = _manifest().model_dump()
    edit_without_reply["actual_reply_ref"] = None
    with pytest.raises(ValidationError):
        RunManifest.model_validate(edit_without_reply)

    archive_without_draft = _manifest().model_dump()
    archive_without_draft.update(
        {
            "run_kind": "archive",
            "generation_candidate_refs": (),
            "actual_reply_ref": None,
            "consultant_edit_diff_ref": None,
            "archive_draft_ref": None,
            "archive_decision": "approved",
            "archive_decision_ref": _governed("archive_decision", 901).model_dump(),
        }
    )
    with pytest.raises(ValidationError):
        RunManifest.model_validate(archive_without_draft)

    evaluation_with_reply = _manifest().model_dump()
    evaluation_with_reply["run_kind"] = "evaluation"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(evaluation_with_reply)

    conflicting_closure = _manifest().model_dump()
    model_ref = conflicting_closure["versions"]["model_descriptor_ref"]
    conflicting_closure["routing"]["query_plan_ref"] = {
        **model_ref,
        "content_sha256": "f" * 64,
    }
    with pytest.raises(ValidationError):
        RunManifest.model_validate(conflicting_closure)


def test_run_filter_counts_are_fixed_complete_and_balanced() -> None:
    routing = _manifest().routing.model_dump()
    routing["filter_counts"] = {}
    with pytest.raises(ValidationError):
        RunRouteSnapshot.model_validate(routing)

    routing["filter_counts"] = {
        "before": 3,
        "after": 2,
        "scope_denied": 0,
        "authorization_denied": 0,
        "validity_denied": 0,
        "freshness_denied": 0,
        "review_denied": 0,
        "sensitivity_denied": 0,
        "tombstone_denied": 0,
        "deduplicated": 0,
        "other_denied": 0,
    }
    with pytest.raises(ValidationError):
        RunRouteSnapshot.model_validate(routing)
