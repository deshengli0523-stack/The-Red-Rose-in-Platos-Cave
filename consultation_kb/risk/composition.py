"""Production composition for deterministic scoped-turn risk evaluation."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Literal, Protocol

from pydantic import Field, ValidationError, field_validator

from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import (
    SafePolicyKey,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.policy.loader import LoadedPolicy, RiskRulesPolicy
from consultation_kb.storage.connection import transaction

from .engine import (
    ModelRiskObservationDraft,
    RiskEngine,
    RiskEvaluationError,
    RiskEvaluationInput,
    RiskEvaluationResult,
    RiskTextSegment,
)
from .repository import InternalRiskObservationRepository
from .rules import (
    PersistentRiskRuleCatalogResolver,
    RiskRuleCatalog,
    RiskRuleClosureError,
    RiskRulePolicyBinding,
)


class RiskCompositionError(RuntimeError):
    """Fixed-code failure at the production authority composition boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RiskModelDraftProvider(Protocol):
    """Trusted internal seam for Codex/model observations.

    The provider is injected while constructing the runtime.  It is
    deliberately absent from ``ScopedTurnRiskInput`` and every MCP schema, so
    client text callers cannot smuggle model findings into the risk engine.
    """

    def approved_model_ref(self) -> VersionRef:
        """Return the exact approved model/prompt revision used for drafts."""

    def draft_observations(
        self,
        *,
        turn: ScopedTurnRiskInput,
        catalog: RiskRuleCatalog,
    ) -> tuple[ModelRiskObservationDraft, ...]:
        """Return counselor-only drafts bound to ``turn`` and ``catalog``."""


class ScopedTurnRiskInput(StrictModel):
    """Only worker-scoped turn text and approved context keys; no model drafts."""

    schema_version: Literal["1.0"] = "1.0"
    session_id: Uuid7String
    segments: Annotated[tuple[RiskTextSegment, ...], Field(min_length=1)]
    context_keys: frozenset[SafePolicyKey]

    @field_validator("segments")
    @classmethod
    def _unique_segments(
        cls,
        value: tuple[RiskTextSegment, ...],
    ) -> tuple[RiskTextSegment, ...]:
        identities = tuple((segment.turn_id, segment.content_ref) for segment in value)
        if len(identities) != len(set(identities)):
            raise ValueError("scoped risk turn segments must be unique")
        return value

    def evaluation_input(self) -> RiskEvaluationInput:
        return RiskEvaluationInput(
            session_id=self.session_id,
            segments=self.segments,
            context_keys=self.context_keys,
            model_drafts=(),
        )


def _assert_read_only_global_connection(connection: sqlite3.Connection) -> None:
    if not isinstance(connection, sqlite3.Connection):
        raise RiskCompositionError("RISK_GLOBAL_CONNECTION_REQUIRED")
    if connection.in_transaction:
        raise RiskCompositionError("RISK_GLOBAL_TRANSACTION_OPEN")
    try:
        query_only = connection.execute("PRAGMA query_only").fetchone()
        databases = connection.execute("PRAGMA database_list").fetchall()
    except sqlite3.DatabaseError:
        raise RiskCompositionError("RISK_GLOBAL_CONNECTION_INVALID") from None
    if query_only is None or int(query_only[0]) != 1:
        raise RiskCompositionError("RISK_GLOBAL_CONNECTION_READ_ONLY_REQUIRED")
    if not databases or any(str(row[1]) not in {"main", "temp"} for row in databases):
        raise RiskCompositionError("RISK_GLOBAL_CONNECTION_SCOPE_INVALID")


def _assert_exact_active_binding(
    connection: sqlite3.Connection,
    binding: RiskRulePolicyBinding,
) -> None:
    active = connection.execute(
        "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE' ORDER BY epoch"
    ).fetchall()
    if active != [(binding.runtime_epoch,)]:
        raise RiskCompositionError("RISK_RULE_ACTIVE_EPOCH_MISMATCH")
    rows = connection.execute(
        """
        SELECT r.state, p.state, p.runtime_epoch,
               m.artifact_key, m.artifact_kind, m.source_version,
               m.manifest_sha256, m.state, m.verified,
               e.state, e.applied_commit_version, e.applied_at,
               a.manifest_id
          FROM runtime_epochs AS r
          JOIN active_artifacts AS a
            ON a.epoch = r.epoch AND a.artifact_key = 'risk_rule_policy'
          JOIN artifact_manifests AS m
            ON m.manifest_id = a.manifest_id
           AND m.operation_id = r.operation_id
          JOIN publication_operations AS p
            ON p.operation_id = r.operation_id
          JOIN approval_executions AS e
            ON e.operation_id = p.operation_id
           AND e.request_id = p.approval_request_id
           AND e.descriptor_sha256 = p.descriptor_sha256
         WHERE r.epoch = ?
        """,
        (binding.runtime_epoch,),
    ).fetchall()
    if len(rows) != 1:
        raise RiskCompositionError("RISK_RULE_ACTIVE_CLOSURE_NOT_FOUND")
    row = rows[0]
    if (
        str(row[0]) != "ACTIVE"
        or str(row[1]) != "ACTIVE"
        or int(row[2]) != binding.runtime_epoch
        or str(row[3]) != "risk_rule_policy"
        or str(row[4]) != "risk_rule_policy"
        or int(row[5]) != binding.manifest_ref.version
        or str(row[6]) != binding.manifest_ref.content_sha256
        or str(row[7]) != "ACTIVE"
        or int(row[8]) != 1
        or str(row[9]) != "APPLIED"
        or row[10] is None
        or row[11] is None
        or str(row[12]) != binding.manifest_ref.object_id
    ):
        raise RiskCompositionError("RISK_RULE_ACTIVE_CLOSURE_INVALID")


def evaluate_scoped_turn_risk(
    *,
    global_connection: sqlite3.Connection,
    loaded_policy: LoadedPolicy[RiskRulesPolicy],
    policy_binding: RiskRulePolicyBinding,
    turn: ScopedTurnRiskInput,
    observation_repository: InternalRiskObservationRepository,
    model_draft_provider: RiskModelDraftProvider | None = None,
    clock: Clock | None = None,
    id_factory: IdFactory | None = None,
) -> RiskEvaluationResult:
    """One-call worker seam over a pinned, approved, active global policy."""

    _assert_read_only_global_connection(global_connection)
    if type(observation_repository) is not InternalRiskObservationRepository:
        raise RiskCompositionError("RISK_CLIENT_REPOSITORY_REQUIRED")
    if observation_repository.connection is global_connection:
        raise RiskCompositionError("RISK_AUTHORITY_SCOPE_ALIAS_DENIED")
    try:
        exact_binding = RiskRulePolicyBinding.model_validate(
            policy_binding, strict=True
        )
        exact_turn = ScopedTurnRiskInput.model_validate(turn, strict=True)
    except ValidationError:
        raise RiskCompositionError("RISK_PRODUCTION_INPUT_INVALID") from None

    try:
        # One read snapshot proves that active pointer, approval execution,
        # manifest membership, and both resolver reads are the same closure.
        with transaction(global_connection, immediate=False):
            _assert_exact_active_binding(global_connection, exact_binding)
            resolver = PersistentRiskRuleCatalogResolver(
                global_connection,
                loaded_policy,
                database_scope="global",
            )
            evaluation_input = exact_turn.evaluation_input()
            approved_model_ref: VersionRef | None = None
            if model_draft_provider is not None:
                catalog = resolver.resolve(exact_binding)
                try:
                    approved_model_ref = VersionRef.model_validate(
                        model_draft_provider.approved_model_ref(),
                        strict=True,
                    )
                    supplied = model_draft_provider.draft_observations(
                        turn=exact_turn,
                        catalog=catalog,
                    )
                    if type(supplied) is not tuple or any(
                        type(draft) is not ModelRiskObservationDraft
                        for draft in supplied
                    ):
                        raise TypeError
                    drafts = tuple(
                        ModelRiskObservationDraft.model_validate(
                            draft,
                            strict=True,
                        )
                        for draft in supplied
                    )
                    if any(draft.model_ref != approved_model_ref for draft in drafts):
                        raise ValueError
                    evaluation_input = RiskEvaluationInput(
                        session_id=exact_turn.session_id,
                        segments=exact_turn.segments,
                        context_keys=exact_turn.context_keys,
                        model_drafts=drafts,
                    )
                except Exception:  # noqa: BLE001 - fail closed at provider seam
                    raise RiskCompositionError(
                        "RISK_MODEL_DRAFT_PROVIDER_INVALID"
                    ) from None
            result = RiskEngine(
                resolver,
                policy_binding=exact_binding,
                clock=clock,
                id_factory=id_factory,
                repository=observation_repository,
            ).evaluate(evaluation_input)
    except RiskCompositionError:
        raise
    except RiskRuleClosureError:
        raise RiskCompositionError("RISK_RULE_ACTIVE_CLOSURE_INVALID") from None
    except (RiskEvaluationError, sqlite3.DatabaseError, TypeError, ValueError):
        raise RiskCompositionError("RISK_PRODUCTION_EVALUATION_FAILED") from None

    for record in result.observations:
        source_kinds = {source.source_kind for source in record.sources}
        if not source_kinds or not source_kinds.issubset(
            {"deterministic_rule", "model_observation"}
        ):
            raise RiskCompositionError("RISK_PRODUCTION_OUTPUT_INVALID")
        if "deterministic_rule" in source_kinds and record.confidence != 1.0:
            raise RiskCompositionError("RISK_PRODUCTION_OUTPUT_INVALID")
        if source_kinds == {"model_observation"} and not (
            0.0 < record.confidence < 1.0
        ):
            raise RiskCompositionError("RISK_PRODUCTION_OUTPUT_INVALID")
        if "model_observation" in source_kinds and (
            approved_model_ref is None
            or any(
                source.source_ref != approved_model_ref
                for source in record.sources
                if source.source_kind == "model_observation"
            )
        ):
            raise RiskCompositionError("RISK_PRODUCTION_OUTPUT_INVALID")
    return result


__all__ = [
    "RiskCompositionError",
    "RiskModelDraftProvider",
    "ScopedTurnRiskInput",
    "evaluate_scoped_turn_risk",
]
