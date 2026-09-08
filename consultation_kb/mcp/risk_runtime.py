"""Read-only control-plane runtime for scoped turn risk evaluation.

The runtime never opens a customer database.  Every call discovers one exact
approved risk-policy binding from a fresh read-only global connection, runs
the production composition seam against a disposable in-memory client
repository, and returns detached internal records for the scoped worker to
persist inside its already-open customer authority.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Literal, final

from pydantic import ValidationError

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import NonEmptyStr, Sha256Hex, StrictModel, VersionRef
from consultation_kb.policy.loader import (
    LoadedPolicy,
    PolicyLoadError,
    PolicyLoader,
    RiskRulesPolicy,
)
from consultation_kb.risk.composition import (
    RiskCompositionError,
    RiskModelDraftProvider,
    ScopedTurnRiskInput,
    evaluate_scoped_turn_risk,
)
from consultation_kb.risk.engine import RiskTextSegment
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    InternalRiskObservationRepository,
    RiskEvaluationAuthorityBinding,
)
from consultation_kb.risk.rules import (
    PersistentRiskRuleCatalogResolver,
    RiskRuleClosureError,
    RiskRulePolicyBinding,
)
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.manifests import ManifestError, ManifestRepository
from consultation_kb.vault.content_store import ContentStore, ContentStoreError
from consultation_kb.vault.layout import VaultLayout


class RiskEvaluationRuntimeError(RuntimeError):
    """Content-free failure at the risk control-plane boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


RiskModelDraftProviderFactory = Callable[[Clock], RiskModelDraftProvider]


class _RiskModelDescriptor(StrictModel):
    """Minimal governed payload required behind an approved model reference."""

    schema_version: Literal["1.0"]
    provider_key: NonEmptyStr
    model_key: NonEmptyStr
    prompt_revision_sha256: Sha256Hex


def _assert_required_manifest_membership(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    manifest_ids: frozenset[str],
) -> frozenset[str]:
    row = connection.execute(
        """
        SELECT p.required_manifests_json, p.required_manifest_count,
               p.verified_manifest_count
          FROM runtime_epochs AS r
          JOIN publication_operations AS p
            ON p.operation_id = r.operation_id
         WHERE r.epoch = ?
        """,
        (epoch,),
    ).fetchone()
    if row is None or type(row[0]) is not str:
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_POLICY_INVALID")
    try:
        required = json.loads(row[0])
    except (TypeError, ValueError, json.JSONDecodeError):
        raise RiskEvaluationRuntimeError(
            "RISK_RUNTIME_ACTIVE_POLICY_INVALID"
        ) from None
    if (
        type(required) is not list
        or any(type(item) is not str or not item for item in required)
        or len(required) != len(set(required))
        or int(row[1]) != len(required)
        or int(row[2]) != len(required)
        or not manifest_ids.issubset(set(required))
    ):
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_POLICY_INVALID")
    return frozenset(required)


def _assert_pure_global_reader(connection: sqlite3.Connection) -> None:
    try:
        query_only = connection.execute("PRAGMA query_only").fetchone()
        databases = connection.execute("PRAGMA database_list").fetchall()
    except sqlite3.DatabaseError:
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_GLOBAL_READER_INVALID") from None
    schema_names = tuple(str(row[1]) for row in databases)
    if query_only != (1,) or schema_names.count("main") != 1:
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_GLOBAL_READER_INVALID")
    if any(name not in {"main", "temp"} for name in schema_names):
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_GLOBAL_READER_INVALID")


def _discover_active_binding(
    connection: sqlite3.Connection,
    *,
    provider_model_ref: VersionRef | None,
) -> tuple[RiskRulePolicyBinding, RiskEvaluationAuthorityBinding]:
    """Pin the sole active, applied manifest from one read snapshot."""

    try:
        context = (
            nullcontext(connection)
            if connection.in_transaction
            else transaction(connection, immediate=False)
        )
        with context:
            active_epochs = connection.execute(
                """
                SELECT epoch
                  FROM runtime_epochs
                 WHERE state = 'ACTIVE'
                 ORDER BY epoch
                """
            ).fetchall()
            if len(active_epochs) != 1:
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_EPOCH_INVALID")
            epoch = int(active_epochs[0][0])
            rows = connection.execute(
                """
                SELECT r.epoch, r.state,
                       p.state, p.runtime_epoch,
                       m.manifest_id, m.artifact_key, m.artifact_kind,
                       m.source_version, m.manifest_sha256,
                       m.state, m.verified,
                       e.state, e.applied_commit_version, e.applied_at
                  FROM runtime_epochs AS r
                  JOIN active_artifacts AS a
                    ON a.epoch = r.epoch
                   AND a.artifact_key = 'risk_rule_policy'
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
                (epoch,),
            ).fetchall()
            if len(rows) != 1:
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_POLICY_INVALID")
            row = rows[0]
            if (
                int(row[0]) != epoch
                or str(row[1]) != "ACTIVE"
                or str(row[2]) != "ACTIVE"
                or int(row[3]) != epoch
                or str(row[5]) != "risk_rule_policy"
                or str(row[6]) != "risk_rule_policy"
                or str(row[9]) != "ACTIVE"
                or int(row[10]) != 1
                or str(row[11]) != "APPLIED"
                or row[12] is None
                or row[13] is None
            ):
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_POLICY_INVALID")
            policy_binding = RiskRulePolicyBinding(
                runtime_epoch=epoch,
                manifest_ref=VersionRef(
                    object_id=str(row[4]),
                    version=int(row[7]),
                    content_sha256=str(row[8]),
                ),
            )
            required_manifest_ids = _assert_required_manifest_membership(
                connection,
                epoch=epoch,
                manifest_ids=frozenset({policy_binding.manifest_ref.object_id}),
            )
            if provider_model_ref is None:
                active_model_count = connection.execute(
                    """
                    SELECT count(*)
                      FROM active_artifacts
                     WHERE epoch = ?
                       AND artifact_key = 'risk_model_descriptor'
                    """,
                    (epoch,),
                ).fetchone()
                if active_model_count != (0,) or any(
                    manifest_id[:-37] == "risk_model_manifest"
                    for manifest_id in required_manifest_ids
                ):
                    raise RiskEvaluationRuntimeError(
                        "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
                    )
                return (
                    policy_binding,
                    RiskEvaluationAuthorityBinding(
                        global_runtime_epoch=epoch,
                        risk_policy_manifest_ref=policy_binding.manifest_ref,
                        model_mode="deterministic_only",
                    ),
                )
            model_rows = connection.execute(
                """
                SELECT m.manifest_id, m.source_version, m.manifest_sha256,
                       m.state, m.verified, m.artifact_key, m.artifact_kind,
                       member.object_id, member.source_version,
                       member.object_sha256, member.object_type,
                       member.media_type, member.ordinal,
                       p.state, p.runtime_epoch,
                       e.state, e.applied_commit_version, e.applied_at
                  FROM active_artifacts AS a
                  JOIN artifact_manifests AS m
                    ON m.manifest_id = a.manifest_id
                  JOIN artifact_members AS member
                    ON member.manifest_id = m.manifest_id
                  JOIN runtime_epochs AS r
                    ON r.epoch = a.epoch
                   AND r.operation_id = m.operation_id
                  JOIN publication_operations AS p
                    ON p.operation_id = r.operation_id
                  JOIN approval_executions AS e
                    ON e.operation_id = p.operation_id
                   AND e.request_id = p.approval_request_id
                   AND e.descriptor_sha256 = p.descriptor_sha256
                 WHERE a.epoch = ?
                   AND a.artifact_key = 'risk_model_descriptor'
                """,
                (epoch,),
            ).fetchall()
            if len(model_rows) != 1:
                raise RiskEvaluationRuntimeError(
                    "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
                )
            model_row = model_rows[0]
            if (
                str(model_row[3]) != "ACTIVE"
                or int(model_row[4]) != 1
                or str(model_row[5]) != "risk_model_descriptor"
                or str(model_row[6]) != "risk_model_descriptor"
                or str(model_row[7]) != provider_model_ref.object_id
                or int(model_row[8]) != provider_model_ref.version
                or str(model_row[9]) != provider_model_ref.content_sha256
                or str(model_row[10]) != "risk_model"
                or str(model_row[11])
                != "application/vnd.consultation-kb.risk-model-descriptor+json"
                or int(model_row[12]) != 0
                or str(model_row[13]) != "ACTIVE"
                or int(model_row[14]) != epoch
                or str(model_row[15]) != "APPLIED"
                or model_row[16] is None
                or model_row[17] is None
            ):
                raise RiskEvaluationRuntimeError(
                    "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
                )
            model_manifest_ref = VersionRef(
                object_id=str(model_row[0]),
                version=int(model_row[1]),
                content_sha256=str(model_row[2]),
            )
            _assert_required_manifest_membership(
                connection,
                epoch=epoch,
                manifest_ids=frozenset(
                    {
                        policy_binding.manifest_ref.object_id,
                        model_manifest_ref.object_id,
                    }
                ),
            )
            return (
                policy_binding,
                RiskEvaluationAuthorityBinding(
                    global_runtime_epoch=epoch,
                    risk_policy_manifest_ref=policy_binding.manifest_ref,
                    model_mode="approved_model",
                    risk_model_manifest_ref=model_manifest_ref,
                    approved_model_ref=provider_model_ref,
                ),
            )
    except RiskEvaluationRuntimeError:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError, ValidationError):
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_POLICY_INVALID") from None


def _canonical_records(
    records: tuple[InternalRiskObservationRecord, ...],
    *,
    session_id: str,
    turn_id: str,
    content_ref: VersionRef,
    approved_model_ref: VersionRef | None,
) -> tuple[InternalRiskObservationRecord, ...]:
    exact = tuple(
        InternalRiskObservationRecord.model_validate(record, strict=True)
        for record in records
    )
    identifiers = tuple(record.observation.observation_id for record in exact)
    if len(identifiers) != len(set(identifiers)):
        raise RiskEvaluationRuntimeError("RISK_RUNTIME_OUTPUT_INVALID")
    for record in exact:
        source_kinds = {source.source_kind for source in record.sources}
        if (
            record.session_id != session_id
            or record.status != "open"
            or not source_kinds
            or not source_kinds.issubset({"deterministic_rule", "model_observation"})
            or ("deterministic_rule" in source_kinds and record.confidence != 1.0)
            or (
                source_kinds == {"model_observation"}
                and not 0.0 < record.confidence < 1.0
            )
            or any(
                span.turn_id != turn_id or span.content_ref != content_ref
                for span in record.trigger_spans
            )
            or (
                "model_observation" in source_kinds
                and (
                    approved_model_ref is None
                    or any(
                        source.source_ref != approved_model_ref
                        for source in record.sources
                        if source.source_kind == "model_observation"
                    )
                )
            )
        ):
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_OUTPUT_INVALID")
    return tuple(
        sorted(
            exact,
            key=lambda record: record.observation.observation_id,
        )
    )


@final
class RiskEvaluationRuntime:
    """Evaluate one scoped client turn without opening its persistent store."""

    def __init__(
        self,
        *,
        config: AppConfig,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
        model_draft_provider_factory: RiskModelDraftProviderFactory | None = None,
    ) -> None:
        if type(config) is not AppConfig:
            raise TypeError("RISK_RUNTIME_CONFIG_REQUIRED")
        selected_clock = clock if clock is not None else SystemClock()
        if not callable(getattr(selected_clock, "now", None)):
            raise TypeError("RISK_RUNTIME_CLOCK_REQUIRED")
        if id_factory is not None and type(id_factory) is not IdFactory:
            raise TypeError("RISK_RUNTIME_ID_FACTORY_REQUIRED")
        if model_draft_provider_factory is not None and not callable(
            model_draft_provider_factory
        ):
            raise TypeError("RISK_RUNTIME_MODEL_PROVIDER_FACTORY_REQUIRED")
        try:
            PolicyLoader.from_config(config).load_all().risk_rules
            global_database = VaultLayout.from_config(config).global_db  # type: ignore[attr-defined]
        except (PolicyLoadError, OSError, TypeError, ValueError):
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_POLICY_UNAVAILABLE"
            ) from None
        self._config = config
        self._global_database: Path = global_database.resolve(strict=False)
        self._global_content_store = ContentStore(self._global_database.parent)
        self._clock = selected_clock
        self._ids = id_factory if id_factory is not None else IdFactory(selected_clock)
        try:
            provider = (
                None
                if model_draft_provider_factory is None
                else model_draft_provider_factory(selected_clock)
            )
            approved_model_ref = (
                None
                if provider is None
                else VersionRef.model_validate(
                    provider.approved_model_ref(),
                    strict=True,
                )
            )
        except Exception:  # noqa: BLE001 - fail closed at provider factory seam
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_MODEL_PROVIDER_UNAVAILABLE"
            ) from None
        self._model_draft_provider = provider
        self._constructor_model_ref = approved_model_ref

    def _assert_model_descriptor_closure(
        self,
        connection: sqlite3.Connection,
        authority: RiskEvaluationAuthorityBinding,
    ) -> None:
        model_ref = authority.approved_model_ref
        if model_ref is None:
            return
        manifest_ref = authority.risk_model_manifest_ref
        if manifest_ref is None:
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_ACTIVE_MODEL_INVALID")
        try:
            manifest = ManifestRepository(connection).get_active(
                "risk_model_descriptor",
                epoch=authority.global_runtime_epoch,
            )
            if (
                manifest.artifact_kind != "risk_model_descriptor"
                or manifest.manifest_id[:-37] != "risk_model_manifest"
                or manifest.source_version != model_ref.version
                or manifest.state != "ACTIVE"
                or not manifest.verified
                or VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                )
                != manifest_ref
                or len(manifest.members) != 1
            ):
                raise RiskEvaluationRuntimeError(
                    "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
                )
            member = manifest.members[0]
            payload = self._global_content_store.read_hash_verified(
                model_ref.content_sha256
            )
            if (
                member.ordinal != 0
                or member.object_type != "risk_model"
                or member.object_id != model_ref.object_id
                or member.object_sha256 != model_ref.content_sha256
                or member.source_version != model_ref.version
                or member.media_type
                != "application/vnd.consultation-kb.risk-model-descriptor+json"
                or member.size_bytes != len(payload)
                or member.source_lineage_hashes
            ):
                raise RiskEvaluationRuntimeError(
                    "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
                )
            _RiskModelDescriptor.model_validate_json(payload, strict=True)
        except RiskEvaluationRuntimeError:
            raise
        except (
            ContentStoreError,
            ManifestError,
            OSError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_ACTIVE_MODEL_INVALID"
            ) from None

    def _resolve_authority_closure(
        self,
        connection: sqlite3.Connection,
        loaded_policy: LoadedPolicy[RiskRulesPolicy],
        *,
        policy_error_code: Literal[
            "RISK_RUNTIME_ACTIVE_POLICY_INVALID",
            "RISK_RUNTIME_POLICY_CLOSURE_INVALID",
        ] = "RISK_RUNTIME_ACTIVE_POLICY_INVALID",
    ) -> tuple[RiskRulePolicyBinding, RiskEvaluationAuthorityBinding]:
        """Resolve one complete authority snapshot and reject a mid-read switch."""

        with transaction(connection, immediate=False):
            policy_binding, authority = _discover_active_binding(
                connection,
                provider_model_ref=self._provider_model_ref(),
            )
            try:
                PersistentRiskRuleCatalogResolver(
                    connection,
                    loaded_policy,
                    database_scope="global",
                ).resolve(policy_binding)
            except RiskRuleClosureError:
                raise RiskEvaluationRuntimeError(policy_error_code) from None
            self._assert_model_descriptor_closure(connection, authority)

        # A WAL writer may activate a new epoch while the first read snapshot
        # remains valid.  Re-open the logical snapshot and reject rather than
        # return an authority that changed during closure verification.
        with transaction(connection, immediate=False):
            confirmed_binding, confirmed_authority = _discover_active_binding(
                connection,
                provider_model_ref=self._provider_model_ref(),
            )
            if (
                confirmed_binding != policy_binding
                or confirmed_authority != authority
            ):
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_AUTHORITY_STALE")
        return policy_binding, authority

    def _provider_model_ref(self) -> VersionRef | None:
        provider = self._model_draft_provider
        if provider is None:
            return None
        try:
            current = VersionRef.model_validate(
                provider.approved_model_ref(),
                strict=True,
            )
        except Exception:  # noqa: BLE001 - trusted seam must fail closed
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_MODEL_PROVIDER_UNAVAILABLE"
            ) from None
        if current != self._constructor_model_ref:
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_MODEL_PROVIDER_INVALID"
            )
        return current

    def current_authority(self) -> RiskEvaluationAuthorityBinding:
        """Read one fresh approved policy/model authority closure."""

        try:
            loaded_policy = PolicyLoader.from_config(
                self._config
            ).load_all().risk_rules
        except (PolicyLoadError, OSError, TypeError, ValueError):
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_POLICY_UNAVAILABLE"
            ) from None
        connection: sqlite3.Connection | None = None
        try:
            connection = connect_database(self._global_database, mode="reader")
            _assert_pure_global_reader(connection)
            _policy_binding, authority = self._resolve_authority_closure(
                connection,
                loaded_policy,
            )
            return authority
        finally:
            if connection is not None:
                connection.close()

    def evaluate_turn(
        self,
        *,
        session_id: str,
        turn_id: str,
        content_ref: VersionRef,
        text: str,
        approved_context_keys: frozenset[str],
        authority: RiskEvaluationAuthorityBinding | None = None,
    ) -> tuple[InternalRiskObservationRecord, ...]:
        """Return constrained internal records for scoped-worker persistence."""

        if (
            type(session_id) is not str
            or type(turn_id) is not str
            or type(content_ref) is not VersionRef
            or type(text) is not str
            or type(approved_context_keys) is not frozenset
            or any(type(key) is not str for key in approved_context_keys)
        ):
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_INPUT_INVALID")
        try:
            turn = ScopedTurnRiskInput(
                session_id=session_id,
                segments=(
                    RiskTextSegment(
                        turn_id=turn_id,
                        content_ref=content_ref,
                        text=text,
                        statement_mode="direct",
                    ),
                ),
                context_keys=approved_context_keys,
            )
        except (ValidationError, TypeError, ValueError):
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_INPUT_INVALID") from None

        # Policy files are a mutable control-plane input.  Reload on every call
        # so a long-lived worker cannot keep using a stale no-match cache after
        # an approved policy activation (or silently ignore local tampering).
        try:
            loaded_policy = PolicyLoader.from_config(self._config).load_all().risk_rules
        except (PolicyLoadError, OSError, TypeError, ValueError):
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_POLICY_UNAVAILABLE"
            ) from None
        try:
            expected_authority = (
                None
                if authority is None
                else RiskEvaluationAuthorityBinding.model_validate(
                    authority,
                    strict=True,
                )
            )
        except ValidationError:
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_INPUT_INVALID") from None

        global_connection: sqlite3.Connection | None = None
        client_connection: sqlite3.Connection | None = None
        try:
            global_connection = connect_database(
                self._global_database,
                mode="reader",
            )
            _assert_pure_global_reader(global_connection)
            binding, live_authority = self._resolve_authority_closure(
                global_connection,
                loaded_policy,
                policy_error_code="RISK_RUNTIME_POLICY_CLOSURE_INVALID",
            )
            if expected_authority is not None and live_authority != expected_authority:
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_AUTHORITY_STALE")

            client_connection = sqlite3.connect(":memory:", isolation_level=None)
            client_connection.execute("PRAGMA foreign_keys = ON")
            InternalRiskObservationRepository.install_schema(
                client_connection,
                database_scope="client",
            )
            repository = InternalRiskObservationRepository(
                client_connection,
                database_scope="client",
                clock=self._clock,
            )
            result = evaluate_scoped_turn_risk(
                global_connection=global_connection,
                loaded_policy=loaded_policy,
                policy_binding=binding,
                turn=turn,
                observation_repository=repository,
                model_draft_provider=self._model_draft_provider,
                clock=self._clock,
                id_factory=self._ids,
            )
            observations = _canonical_records(
                result.observations,
                session_id=session_id,
                turn_id=turn_id,
                content_ref=content_ref,
                approved_model_ref=live_authority.approved_model_ref,
            )
            persisted = {
                record.observation.observation_id: record
                for record in result.persisted_visible_observations
            }
            detached = {
                record.observation.observation_id: record for record in observations
            }
            if persisted != detached:
                raise RiskEvaluationRuntimeError("RISK_RUNTIME_OUTPUT_INVALID")
            return observations
        except RiskEvaluationRuntimeError:
            raise
        except RiskCompositionError as failure:
            if self._model_draft_provider is not None and failure.code in {
                "RISK_MODEL_DRAFT_PROVIDER_INVALID",
                "RISK_PRODUCTION_EVALUATION_FAILED",
                "RISK_PRODUCTION_OUTPUT_INVALID",
            }:
                raise RiskEvaluationRuntimeError(
                    "RISK_RUNTIME_MODEL_PROVIDER_INVALID"
                ) from None
            raise RiskEvaluationRuntimeError(
                "RISK_RUNTIME_POLICY_CLOSURE_INVALID"
            ) from None
        except (sqlite3.DatabaseError, OSError, TypeError, ValueError, ValidationError):
            raise RiskEvaluationRuntimeError("RISK_RUNTIME_EVALUATION_FAILED") from None
        finally:
            if client_connection is not None:
                client_connection.close()
            if global_connection is not None:
                global_connection.close()


__all__ = [
    "RiskEvaluationRuntime",
    "RiskEvaluationRuntimeError",
    "RiskModelDraftProviderFactory",
]
