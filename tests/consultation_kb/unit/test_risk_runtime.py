from __future__ import annotations

import hashlib
import inspect
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest

import consultation_kb.mcp.risk_runtime as risk_runtime_module
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.risk_runtime import (
    RiskEvaluationRuntime,
    RiskEvaluationRuntimeError,
    RiskModelDraftProviderFactory,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.risk.composition import ScopedTurnRiskInput
from consultation_kb.risk.engine import ModelRiskObservationDraft
from consultation_kb.risk.repository import InternalRiskObservationRecord
from consultation_kb.risk.repository import RiskEvaluationAuthorityBinding
from consultation_kb.risk.rules import (
    PersistentRiskRuleCatalogResolver,
    RiskRuleCatalog,
    RiskRulePolicyBinding,
)
from consultation_kb.security.worker_protocol import PersistRiskObservationsRequest
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.risk_support import (
    insert_approved_risk_policy_epoch,
)


NOW = datetime(2026, 7, 19, 13, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000601"
TURN_ID = "018f0000-0000-7000-8000-000000000602"
MODEL_DESCRIPTOR_BYTES = json.dumps(
    {
        "model_key": "risk_review_test",
        "prompt_revision_sha256": "c" * 64,
        "provider_key": "test_provider",
        "schema_version": "1.0",
    },
    ensure_ascii=True,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
MODEL_REF = VersionRef(
    object_id="risk_model_018f0000-0000-7000-8000-000000000605",
    version=1,
    content_sha256=hashlib.sha256(MODEL_DESCRIPTOR_BYTES).hexdigest(),
)


class _TrustedModelDraftProvider:
    def __init__(self, model_ref: VersionRef = MODEL_REF) -> None:
        self._model_ref = model_ref

    def approved_model_ref(self) -> VersionRef:
        return self._model_ref

    def draft_observations(
        self,
        *,
        turn: ScopedTurnRiskInput,
        catalog: RiskRuleCatalog,
    ) -> tuple[ModelRiskObservationDraft, ...]:
        segment = turn.segments[0]
        phrase = "我想伤害自己"
        start = segment.text.find(phrase)
        if start < 0:
            return ()
        rule = next(
            item for item in catalog.rules if item.rule_id == "self_harm_intent_zh"
        )
        return (
            ModelRiskObservationDraft(
                rule_ref=rule.rule_ref,
                category=rule.category,
                level=rule.level,
                model_ref=self._model_ref,
                trigger_turn_id=segment.turn_id,
                trigger_content_ref=segment.content_ref,
                start_offset=start,
                end_offset=start + len(phrase),
                span_sha256=hashlib.sha256(phrase.encode("utf-8")).hexdigest(),
                confidence=0.62,
                rationale_summary=(
                    "Qualified wording requires counselor confirmation."
                ),
            ),
        )


def _content_ref() -> VersionRef:
    return VersionRef(
        object_id="private_turn_text_018f0000-0000-7000-8000-000000000603",
        version=1,
        content_sha256="a" * 64,
    )


def _authority(
    repo_root: Path,
    tmp_path: Path,
    *,
    suffix: int,
    model_factory: RiskModelDraftProviderFactory | None = None,
    install_model_descriptor_payload: bool = True,
) -> tuple[
    RiskEvaluationRuntime,
    sqlite3.Connection,
    AppConfig,
    Callable[[], int],
]:
    vault = tmp_path / f"risk-runtime-vault-{suffix}"
    global_root = vault / "global"
    global_root.mkdir(parents=True)
    config = AppConfig.from_values(repo_root, vault)
    loaded = PolicyLoader.from_config(config).load_all().risk_rules
    writer = connect_database(global_root / "catalog.sqlite3", mode="writer")
    MigrationRunner.for_scope(writer, "global").apply()
    provider_for_authority = (
        None if model_factory is None else model_factory(FixedClock(NOW))
    )
    if provider_for_authority is not None and install_model_descriptor_payload:
        model_ref = provider_for_authority.approved_model_ref()
        staged = ContentStore(global_root).stage_bytes(
            MODEL_DESCRIPTOR_BYTES,
            purpose="risk_model",
            manifest_id=model_ref.object_id,
            media_type=(
                "application/vnd.consultation-kb.risk-model-descriptor+json"
            ),
        )
        if staged.content_sha256 != model_ref.content_sha256:
            raise AssertionError("test model descriptor reference mismatch")
        ContentStore(global_root).finalize(staged)
    insert_approved_risk_policy_epoch(
        writer,
        loaded,
        epoch=1,
        suffix=suffix,
        approved_model_ref=(
            None
            if provider_for_authority is None
            else provider_for_authority.approved_model_ref()
        ),
    )
    if provider_for_authority is not None:
        model_ref = provider_for_authority.approved_model_ref()
        manifest_row = writer.execute(
            """
            SELECT manifest.manifest_id, manifest.operation_id
              FROM active_artifacts AS active
              JOIN artifact_manifests AS manifest
                ON manifest.manifest_id = active.manifest_id
             WHERE active.epoch = 1
               AND active.artifact_key = 'risk_model_descriptor'
            """
        ).fetchone()
        assert manifest_row is not None
        model_member = ManifestMember(
            ordinal=0,
            object_type="risk_model",
            object_id=model_ref.object_id,
            object_sha256=model_ref.content_sha256,
            source_version=model_ref.version,
            media_type=(
                "application/vnd.consultation-kb.risk-model-descriptor+json"
            ),
            size_bytes=len(MODEL_DESCRIPTOR_BYTES),
            source_lineage_hashes=(),
        )
        digest = manifest_sha256(
            manifest_id=str(manifest_row[0]),
            operation_id=str(manifest_row[1]),
            artifact_key="risk_model_descriptor",
            artifact_kind="risk_model_descriptor",
            source_version=model_ref.version,
            members=(model_member,),
        )
        writer.execute(
            "UPDATE artifact_members SET size_bytes = ? WHERE manifest_id = ?",
            (model_member.size_bytes, str(manifest_row[0])),
        )
        writer.execute(
            "UPDATE artifact_manifests SET manifest_sha256 = ? WHERE manifest_id = ?",
            (digest, str(manifest_row[0])),
        )
    values = iter(range(suffix * 10, suffix * 10 + 100))

    def next_value() -> int:
        return next(values)

    runtime = RiskEvaluationRuntime(
        config=config,
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), next_value),
        model_draft_provider_factory=model_factory,
    )
    return runtime, writer, config, next_value


def _evaluate(
    runtime: RiskEvaluationRuntime,
    text: str,
    *,
    session_id: str = SESSION_ID,
    authority: RiskEvaluationAuthorityBinding | None = None,
) -> tuple[InternalRiskObservationRecord, ...]:
    return runtime.evaluate_turn(
        session_id=session_id,
        turn_id=TURN_ID,
        content_ref=_content_ref(),
        text=text,
        approved_context_keys=frozenset({"synthetic_context_present"}),
        authority=authority,
    )


def test_runtime_returns_canonical_internal_records_without_client_text_or_store(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, config, _ = _authority(repo_root, tmp_path, suffix=170)
    private_marker = "PRIVATE-CLIENT-TEXT-DO-NOT-RETURN"
    try:
        records = _evaluate(
            runtime,
            (f"SYNTH-RISK-HIGH-7D1A {private_marker} SYNTH-RISK-GENERAL-4C2E"),
        )
        global_tables = {
            str(row[0])
            for row in writer.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        writer.close()

    assert len(records) == 2
    assert {record.observation.level for record in records} == {"general", "high"}
    assert records == tuple(
        sorted(
            records,
            key=lambda record: record.observation.observation_id,
        )
    )
    assert all(
        record.session_id == SESSION_ID
        and record.status == "open"
        and record.confidence == 1.0
        and {source.source_kind for source in record.sources} == {"deterministic_rule"}
        and {span.turn_id for span in record.trigger_spans} == {TURN_ID}
        and {span.content_ref for span in record.trigger_spans} == {_content_ref()}
        for record in records
    )
    payload = json.dumps(
        [record.model_dump(mode="json") for record in records],
        sort_keys=True,
    )
    assert private_marker not in payload
    assert "text" not in type(records[0]).model_fields
    assert "internal_risk_observations" not in global_tables
    assert not (config.vault_root / "clients").exists()


def test_trusted_model_provider_can_add_counselor_only_review_observation(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    provider = _TrustedModelDraftProvider()
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=175,
        model_factory=lambda _clock: provider,
    )
    try:
        records = _evaluate(runtime, "也许我想伤害自己")
    finally:
        writer.close()

    assert len(records) == 1
    record = records[0]
    assert record.observation.category == "self_harm_intent"
    assert record.observation.client_facing_visibility == "never"
    assert record.confidence == 0.62
    assert {source.source_kind for source in record.sources} == {"model_observation"}
    assert record.sources[0].source_ref == MODEL_REF
    assert (
        "model_drafts"
        not in inspect.signature(RiskEvaluationRuntime.evaluate_turn).parameters
    )


def test_model_provider_requires_independent_active_descriptor_authority(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1751,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    writer.execute(
        "DELETE FROM active_artifacts WHERE artifact_key = 'risk_model_descriptor'"
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_MODEL_INVALID"


def test_model_authority_binds_active_manifest_and_exact_descriptor_ref(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1752,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    try:
        authority = runtime.current_authority()
    finally:
        writer.close()

    assert authority.model_mode == "approved_model"
    assert authority.approved_model_ref == MODEL_REF
    assert authority.risk_model_manifest_ref is not None
    assert authority.risk_model_manifest_ref.object_id.startswith(
        "risk_model_manifest_"
    )


def test_model_authority_requires_hash_verified_descriptor_cas(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1753,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
        install_model_descriptor_payload=False,
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            runtime.current_authority()
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_MODEL_INVALID"


def test_model_authority_rejects_tampered_manifest_digest(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1754,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    writer.execute(
        "UPDATE artifact_manifests SET manifest_sha256 = ? "
        "WHERE artifact_kind = 'risk_model_descriptor'",
        ("f" * 64,),
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            runtime.current_authority()
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_MODEL_INVALID"


def test_model_authority_rejects_rehashed_member_metadata_not_matching_cas(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1755,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    manifest_row = writer.execute(
        """
        SELECT manifest.manifest_id, manifest.operation_id
          FROM active_artifacts AS active
          JOIN artifact_manifests AS manifest
            ON manifest.manifest_id = active.manifest_id
         WHERE active.epoch = 1
           AND active.artifact_key = 'risk_model_descriptor'
        """
    ).fetchone()
    assert manifest_row is not None
    forged_member = ManifestMember(
        ordinal=0,
        object_type="risk_model",
        object_id=MODEL_REF.object_id,
        object_sha256=MODEL_REF.content_sha256,
        source_version=MODEL_REF.version,
        media_type="application/vnd.consultation-kb.risk-model-descriptor+json",
        size_bytes=len(MODEL_DESCRIPTOR_BYTES) + 1,
        source_lineage_hashes=(),
    )
    forged_digest = manifest_sha256(
        manifest_id=str(manifest_row[0]),
        operation_id=str(manifest_row[1]),
        artifact_key="risk_model_descriptor",
        artifact_kind="risk_model_descriptor",
        source_version=MODEL_REF.version,
        members=(forged_member,),
    )
    writer.execute(
        "UPDATE artifact_members SET size_bytes = ? WHERE manifest_id = ?",
        (forged_member.size_bytes, str(manifest_row[0])),
    )
    writer.execute(
        "UPDATE artifact_manifests SET manifest_sha256 = ? WHERE manifest_id = ?",
        (forged_digest, str(manifest_row[0])),
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            runtime.current_authority()
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_MODEL_INVALID"


@pytest.mark.parametrize("remove_active_pointer", [False, True])
def test_required_model_descriptor_cannot_silently_degrade_without_provider(
    repo_root: Path,
    tmp_path: Path,
    remove_active_pointer: bool,
) -> None:
    _runtime, writer, config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=1756,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    if remove_active_pointer:
        writer.execute(
            "DELETE FROM active_artifacts "
            "WHERE artifact_key = 'risk_model_descriptor'"
        )
    deterministic_runtime = RiskEvaluationRuntime(config=config, clock=FixedClock(NOW))
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            deterministic_runtime.current_authority()
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_MODEL_INVALID"


def test_trusted_model_draft_merges_with_exact_deterministic_finding(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=176,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    try:
        records = _evaluate(runtime, "我想伤害自己")
    finally:
        writer.close()

    assert len(records) == 1
    assert records[0].confidence == 1.0
    assert {source.source_kind for source in records[0].sources} == {
        "deterministic_rule",
        "model_observation",
    }


def test_model_provider_cannot_change_its_pinned_model_reference(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    class _WrongModelRefProvider(_TrustedModelDraftProvider):
        def draft_observations(
            self,
            *,
            turn: ScopedTurnRiskInput,
            catalog: RiskRuleCatalog,
        ) -> tuple[ModelRiskObservationDraft, ...]:
            drafts = super().draft_observations(turn=turn, catalog=catalog)
            return tuple(
                draft.model_copy(
                    update={
                        "model_ref": MODEL_REF.model_copy(
                            update={"content_sha256": "c" * 64}
                        )
                    }
                )
                for draft in drafts
            )

    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=177,
        model_factory=lambda _clock: _WrongModelRefProvider(),
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "也许我想伤害自己")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_MODEL_PROVIDER_INVALID"


def test_multi_finding_runtime_output_is_protocol_canonical_across_sessions(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(repo_root, tmp_path, suffix=180)
    rule_order_differs = False
    try:
        for suffix in range(1, 17):
            session_id = f"018f0000-0000-7000-8000-{suffix:012x}"
            records = _evaluate(
                runtime,
                "SYNTH-RISK-GENERAL-4C2E SYNTH-RISK-HIGH-7D1A",
                session_id=session_id,
            )
            identifiers = tuple(record.observation.observation_id for record in records)
            by_rule = tuple(
                record.observation.observation_id
                for record in sorted(
                    records,
                    key=lambda record: record.observation.rule_ref.object_id,
                )
            )
            rule_order_differs = rule_order_differs or by_rule != identifiers
            assert identifiers == tuple(sorted(identifiers))
            PersistRiskObservationsRequest(
                request_id="018f0000-0000-7000-8000-000000000604",
                session_id=session_id,
                turn_id=TURN_ID,
                risk_authority=runtime.current_authority(),
                observations=records,
            )
    finally:
        writer.close()

    assert rule_order_differs is True


def test_runtime_opens_fresh_pure_reader_and_discovers_new_active_epoch_each_call(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, writer, config, _ = _authority(repo_root, tmp_path, suffix=190)
    real_connect = connect_database
    opened: list[tuple[sqlite3.Connection, str, tuple[str, ...], tuple[int, ...]]] = []

    def tracking_connect(path: object, mode: str) -> sqlite3.Connection:
        connection = real_connect(path, mode=mode)  # type: ignore[arg-type]
        opened.append(
            (
                connection,
                mode,
                tuple(
                    str(row[1])
                    for row in connection.execute("PRAGMA database_list").fetchall()
                ),
                tuple(connection.execute("PRAGMA query_only").fetchone() or ()),
            )
        )
        return connection

    monkeypatch.setitem(
        risk_runtime_module.__dict__,
        "connect_database",
        tracking_connect,
    )
    try:
        first = _evaluate(runtime, "SYNTH-RISK-GENERAL-4C2E")
        loaded = PolicyLoader.from_config(config).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            writer,
            loaded,
            epoch=2,
            suffix=210,
            retire_current=True,
        )
        second = _evaluate(runtime, "SYNTH-RISK-GENERAL-4C2E")
    finally:
        writer.close()

    assert len(first) == len(second) == 1
    assert first[0].observation.rule_ref != second[0].observation.rule_ref
    assert len(opened) == 2
    assert opened[0][0] is not opened[1][0]
    assert all(
        mode == "reader" and schemas == ("main",) and query_only == (1,)
        for _connection, mode, schemas, query_only in opened
    )
    for connection, _mode, _schemas, _query_only in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_runtime_rejects_stale_expected_authority_after_epoch_activation(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, config, _ = _authority(repo_root, tmp_path, suffix=211)
    first_authority = runtime.current_authority()
    loaded = PolicyLoader.from_config(config).load_all().risk_rules
    insert_approved_risk_policy_epoch(
        writer,
        loaded,
        epoch=2,
        suffix=212,
        retire_current=True,
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(
                runtime,
                "ordinary non-matching client text",
                authority=first_authority,
            )
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_AUTHORITY_STALE"


def test_current_authority_rejects_epoch_switched_during_closure_verification(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, writer, config, _ = _authority(repo_root, tmp_path, suffix=213)
    loaded = PolicyLoader.from_config(config).load_all().risk_rules
    original_resolve = PersistentRiskRuleCatalogResolver.resolve
    switched = False

    def resolve_after_switch(
        resolver: PersistentRiskRuleCatalogResolver,
        binding: RiskRulePolicyBinding,
    ) -> RiskRuleCatalog:
        nonlocal switched
        if not switched:
            switched = True
            insert_approved_risk_policy_epoch(
                writer,
                loaded,
                epoch=2,
                suffix=214,
                retire_current=True,
            )
        return original_resolve(resolver, binding)

    monkeypatch.setattr(
        PersistentRiskRuleCatalogResolver,
        "resolve",
        resolve_after_switch,
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            runtime.current_authority()
    finally:
        writer.close()

    assert switched is True
    assert failure.value.code == "RISK_RUNTIME_AUTHORITY_STALE"


def test_runtime_reloads_local_policy_instead_of_using_constructor_cache(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    isolated_repo = tmp_path / "isolated-policy-repo"
    shutil.copytree(repo_root / "policies", isolated_repo / "policies")
    (isolated_repo / ".git").mkdir()
    runtime, writer, _config, _ = _authority(
        isolated_repo,
        tmp_path,
        suffix=215,
    )
    policy_path = isolated_repo / "policies" / "risk-rules.yaml"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "SYNTH-RISK-GENERAL-4C2E",
            "UNAPPROVED-HOT-UPDATE",
        ),
        encoding="utf-8",
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_POLICY_UNAVAILABLE"


def test_runtime_active_catalog_tamper_fails_closed_for_non_matching_text(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=217,
    )
    writer.execute(
        """
        UPDATE artifact_members
           SET object_sha256 = ?
         WHERE object_type = 'risk_rule'
           AND ordinal = 1
        """,
        ("f" * 64,),
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_POLICY_CLOSURE_INVALID"


def test_runtime_without_active_policy_fails_closed_even_for_literal_no_match(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=219,
    )
    writer.execute("UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'")
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_EPOCH_INVALID"


def test_model_provider_never_runs_without_an_active_exact_rule_catalog(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, _config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=221,
        model_factory=lambda _clock: _TrustedModelDraftProvider(),
    )
    writer.execute("UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'")
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_EPOCH_INVALID"


def test_runtime_retry_identity_ignores_runtime_clock_and_id_factory(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    first_runtime, writer, config, _ = _authority(
        repo_root,
        tmp_path,
        suffix=220,
    )
    retry_clock = FixedClock(NOW + timedelta(minutes=20))
    retry_runtime = RiskEvaluationRuntime(
        config=config,
        clock=retry_clock,
        id_factory=IdFactory(retry_clock, lambda: (1 << 74) - 1),
    )
    try:
        first = _evaluate(first_runtime, "SYNTH-RISK-HIGH-7D1A")
        retry = _evaluate(retry_runtime, "SYNTH-RISK-HIGH-7D1A")
    finally:
        writer.close()

    assert first[0].observation.observation_id == (retry[0].observation.observation_id)
    assert first[0].observation.detected_at != retry[0].observation.detected_at


def test_applied_risk_policy_approval_cannot_be_reverted_to_claimed(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    _runtime, writer, _config, _ = _authority(repo_root, tmp_path, suffix=230)
    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval execution transition invalid",
        ):
            writer.execute(
                """
                UPDATE approval_executions
                   SET state = 'CLAIMED',
                       applied_commit_version = NULL,
                       applied_at = NULL
                 WHERE operation_id = (
                     SELECT operation_id FROM runtime_epochs WHERE state = 'ACTIVE'
                 )
                """
            )
    finally:
        writer.close()


def test_runtime_requires_exactly_one_active_epoch(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    runtime, writer, config, _ = _authority(repo_root, tmp_path, suffix=250)
    loaded = PolicyLoader.from_config(config).load_all().risk_rules
    writer.execute("DROP INDEX idx_runtime_epochs_one_active")
    insert_approved_risk_policy_epoch(
        writer,
        loaded,
        epoch=2,
        suffix=270,
        retire_current=False,
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            _evaluate(runtime, "ordinary non-matching client text")
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_ACTIVE_EPOCH_INVALID"


def test_runtime_rejects_invalid_worker_input_without_opening_global_database(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, writer, _config, _ = _authority(repo_root, tmp_path, suffix=290)

    def forbidden_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise AssertionError("invalid input must fail before authority access")

    monkeypatch.setitem(
        risk_runtime_module.__dict__,
        "connect_database",
        forbidden_connect,
    )
    try:
        with pytest.raises(RiskEvaluationRuntimeError) as failure:
            runtime.evaluate_turn(
                session_id=SESSION_ID,
                turn_id=TURN_ID,
                content_ref=_content_ref(),
                text="",
                approved_context_keys=frozenset({"synthetic_context_present"}),
            )
    finally:
        writer.close()

    assert failure.value.code == "RISK_RUNTIME_INPUT_INVALID"
