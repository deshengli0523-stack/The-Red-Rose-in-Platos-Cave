from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.policy.loader import LoadedPolicy, RiskRulesPolicy
from consultation_kb.risk.composition import (
    RiskCompositionError,
    ScopedTurnRiskInput,
    evaluate_scoped_turn_risk,
)
from consultation_kb.risk.engine import (
    ModelRiskObservationDraft,
    RiskEvaluationResult,
    RiskTextSegment,
)
from consultation_kb.risk.repository import (
    InternalRiskObservationRepository,
)
from consultation_kb.risk.rules import RiskRuleCatalog, RiskRulePolicyBinding
from tests.consultation_kb.risk_support import (
    insert_approved_risk_policy_epoch,
    persistent_risk_authority,
)


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000501"
TURN_ID = "018f0000-0000-7000-8000-000000000502"


def _ref(kind: str, suffix: int) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )


def _turn(text: str) -> ScopedTurnRiskInput:
    return ScopedTurnRiskInput(
        session_id=SESSION_ID,
        segments=(
            RiskTextSegment(
                turn_id=TURN_ID,
                content_ref=_ref("private_turn_text", 1),
                text=text,
            ),
        ),
        context_keys=frozenset({"synthetic_context_present"}),
    )


def _client_repository() -> tuple[
    sqlite3.Connection,
    InternalRiskObservationRepository,
]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    InternalRiskObservationRepository.install_schema(
        connection,
        database_scope="client",
    )
    return connection, InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=FixedClock(NOW),
    )


def _evaluate(
    *,
    global_connection: sqlite3.Connection,
    loaded_policy: LoadedPolicy[RiskRulesPolicy],
    policy_binding: RiskRulePolicyBinding,
    repository: InternalRiskObservationRepository,
) -> RiskEvaluationResult:
    clock = FixedClock(NOW)
    values = iter(range(500, 600))
    return evaluate_scoped_turn_risk(
        global_connection=global_connection,
        loaded_policy=loaded_policy,
        policy_binding=policy_binding,
        turn=_turn(
            "SYNTH-RISK-GENERAL-4C2E and SYNTH-RISK-HIGH-7D1A"
        ),
        observation_repository=repository,
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )


class _MatchingModelProvider:
    model_ref = _ref("risk_model", 0x5F1)

    def approved_model_ref(self) -> VersionRef:
        return self.model_ref

    def draft_observations(
        self,
        *,
        turn: ScopedTurnRiskInput,
        catalog: RiskRuleCatalog,
    ) -> tuple[ModelRiskObservationDraft, ...]:
        segment = turn.segments[0]
        rule = next(
            item
            for item in catalog.rules
            if item.rule_id == "synthetic_general_observation"
        )
        start = segment.text.index(rule.pattern)
        return (
            ModelRiskObservationDraft(
                rule_ref=rule.rule_ref,
                category=rule.category,
                level=rule.level,
                model_ref=self.model_ref,
                trigger_turn_id=segment.turn_id,
                trigger_content_ref=segment.content_ref,
                start_offset=start,
                end_offset=start + len(rule.pattern),
                span_sha256=hashlib.sha256(
                    rule.pattern.encode("utf-8")
                ).hexdigest(),
                confidence=0.9,
                rationale_summary="Approved model confirms the exact rule span.",
            ),
        )


def test_one_call_composition_uses_active_approved_policy_and_persists_observations(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    global_connection, loaded, _, _, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=70,
    )
    client_connection, repository = _client_repository()
    try:
        global_connection.execute("PRAGMA query_only = ON")
        result = _evaluate(
            global_connection=global_connection,
            loaded_policy=loaded,
            policy_binding=binding,
            repository=repository,
        )
        assert {item.observation.level for item in result.observations} == {
            "general",
            "high",
        }
        assert all(
            {source.source_kind for source in item.sources}
            == {"deterministic_rule"}
            and item.confidence == 1.0
            for item in result.observations
        )
        assert repository.list_visible(SESSION_ID) == (
            result.persisted_visible_observations
        )
    finally:
        client_connection.close()
        global_connection.close()


def test_composition_allows_model_provenance_to_expand_a_stable_existing_hit(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    global_connection, loaded, _, _, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=75,
    )
    client_connection, repository = _client_repository()
    clock = FixedClock(NOW)
    try:
        global_connection.execute("PRAGMA query_only = ON")
        deterministic = _evaluate(
            global_connection=global_connection,
            loaded_policy=loaded,
            policy_binding=binding,
            repository=repository,
        )
        expanded = evaluate_scoped_turn_risk(
            global_connection=global_connection,
            loaded_policy=loaded,
            policy_binding=binding,
            turn=_turn(
                "SYNTH-RISK-GENERAL-4C2E and SYNTH-RISK-HIGH-7D1A"
            ),
            observation_repository=repository,
            model_draft_provider=_MatchingModelProvider(),
            clock=clock,
            id_factory=IdFactory(clock=clock, random_source=lambda: 999),
        )

        first_by_id = {
            item.observation.observation_id: item
            for item in deterministic.observations
        }
        expanded_general = next(
            item
            for item in expanded.observations
            if item.observation.category == "synthetic_general_observation"
        )
        assert expanded_general.observation.observation_id in first_by_id
        assert {source.source_kind for source in expanded_general.sources} == {
            "deterministic_rule",
            "model_observation",
        }
        assert client_connection.execute(
            "SELECT count(*) FROM internal_risk_observations"
        ).fetchone() == (2,)
    finally:
        client_connection.close()
        global_connection.close()


def test_composition_rejects_writable_or_client_attached_global_connection(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, loaded, _, _, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=80,
    )
    client_connection, repository = _client_repository()
    try:
        with pytest.raises(
            RiskCompositionError,
            match="RISK_GLOBAL_CONNECTION_READ_ONLY_REQUIRED",
        ):
            _evaluate(
                global_connection=connection,
                loaded_policy=loaded,
                policy_binding=binding,
                repository=repository,
            )
        connection.execute("ATTACH DATABASE ':memory:' AS client_authority")
        connection.execute("PRAGMA query_only = ON")
        with pytest.raises(
            RiskCompositionError,
            match="RISK_GLOBAL_CONNECTION_SCOPE_INVALID",
        ):
            _evaluate(
                global_connection=connection,
                loaded_policy=loaded,
                policy_binding=binding,
                repository=repository,
            )
    finally:
        client_connection.close()
        connection.close()


def test_composition_rejects_direct_catalog_and_forged_manifest_binding(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, loaded, catalog, _, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=90,
    )
    client_connection, repository = _client_repository()
    try:
        connection.execute("PRAGMA query_only = ON")
        with pytest.raises(
            RiskCompositionError,
            match="RISK_PRODUCTION_INPUT_INVALID",
        ):
            _evaluate(
                global_connection=connection,
                loaded_policy=loaded,
                policy_binding=catalog,  # type: ignore[arg-type]
                repository=repository,
            )
        forged = binding.model_copy(
            update={
                "manifest_ref": binding.manifest_ref.model_copy(
                    update={"content_sha256": "f" * 64}
                )
            }
        )
        with pytest.raises(
            RiskCompositionError,
            match="RISK_RULE_ACTIVE_CLOSURE_INVALID",
        ):
            _evaluate(
                global_connection=connection,
                loaded_policy=loaded,
                policy_binding=forged,
                repository=repository,
            )
    finally:
        client_connection.close()
        connection.close()


def test_composition_never_substitutes_latest_for_explicit_active_binding(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, loaded, _, _, old_binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=100,
    )
    new_binding = insert_approved_risk_policy_epoch(
        connection,
        loaded,
        epoch=2,
        suffix=120,
        retire_current=True,
    )
    client_connection, repository = _client_repository()
    try:
        connection.execute("PRAGMA query_only = ON")
        with pytest.raises(
            RiskCompositionError,
            match="RISK_RULE_ACTIVE_EPOCH_MISMATCH",
        ):
            _evaluate(
                global_connection=connection,
                loaded_policy=loaded,
                policy_binding=old_binding,
                repository=repository,
            )
        result = _evaluate(
            global_connection=connection,
            loaded_policy=loaded,
            policy_binding=new_binding,
            repository=repository,
        )
        assert len(result.observations) == 2
    finally:
        client_connection.close()
        connection.close()


def test_composition_approval_execution_cannot_revert_to_claimed(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _loaded, _, _, _binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=140,
    )
    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval execution transition invalid",
        ):
            connection.execute(
                """
                UPDATE approval_executions
                   SET state = 'CLAIMED',
                       applied_commit_version = NULL,
                       applied_at = NULL
                 WHERE operation_id = (
                     SELECT operation_id FROM runtime_epochs WHERE epoch = 1
                 )
                """
            )
    finally:
        connection.close()
