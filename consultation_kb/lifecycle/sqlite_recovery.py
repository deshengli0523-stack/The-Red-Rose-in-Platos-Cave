"""Production SQLite recovery adapters for one explicitly scoped database.

The adapter never discovers client databases.  A global caller supplies the one
global database and a client worker supplies only its already-bound database.
All externally returned identities are path-free SHA-256 references.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, cast

from consultation_kb.archive.publication_proof import (
    CasePublicationProof,
    CasePublicationProofVerifier,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.lifecycle.publish import (
    PublishCoordinator,
    PublicationIntegrityError,
    publication_closure_sha256,
)
from consultation_kb.lifecycle.recovery_policy import RecoveryPolicyRegistry
from consultation_kb.lifecycle.recovery import (
    RecoveryBackend,
    RecoveryCoordinator,
    RecoveryWriter,
)
from consultation_kb.models.recovery import (
    RecoveryApplyReceipt,
    RecoveryDecision,
    RecoveryInventoryItem,
    RecoveryPurpose,
    RecoveryReport,
    RecoveryScan,
)
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore


RecoveryScope = Literal["global", "client"]
_SHA256 = frozenset("0123456789abcdef")
_NON_RUNTIME_KINDS = frozenset({"shared_case", "case_index"})
_DEDICATED_RUNTIME_VALIDATION_KINDS = frozenset(
    {"risk_rule_policy", "risk_model_descriptor"}
)
_METADATA_ONLY_MANIFEST_KINDS = frozenset({"risk_rule_policy"})
_RUNTIME_ACTIVATION_DENIED_KINDS = frozenset(
    {"private_archive", "shared_case", "case_index"}
)
_SAFE_COMPONENT_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_STAGING_FILE_RE = re.compile(r"payload(?:\.stage|\.[0-9a-f]{32}\.tmp)\Z")
_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_SECONDS = 0.025
_DEFAULT_STAGING_TTL = timedelta(hours=24)


class SqliteRecoveryError(RuntimeError):
    """Fixed-code failure from the production recovery adapter."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SqliteRecoveryError("RECOVERY_CLOCK_INVALID")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _valid_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA256


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise SqliteRecoveryError("RECOVERY_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") else datetime.fromisoformat(value)
    except ValueError:
        raise SqliteRecoveryError("RECOVERY_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SqliteRecoveryError("RECOVERY_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


def _stage_purpose(value: str, *, scope: RecoveryScope) -> RecoveryPurpose:
    lowered = value.lower()
    if "private_archive" in lowered:
        return "private_record"
    if "profile" in lowered or "client" in lowered:
        return "profile"
    if "case_index" in lowered or lowered == "index":
        return "index"
    if "case" in lowered:
        return "case"
    if "graph" in lowered:
        return "graph"
    if "vector" in lowered:
        return "vector"
    if "lex" in lowered:
        return "lex"
    if "wiki" in lowered or "knowledge" in lowered or "policy" in lowered:
        return "wiki"
    return "profile" if scope == "client" else "wiki"


def _safe_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return bool(
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not (attributes & 0x400)
    )


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return bool(row is not None and len(row) == 1 and row[0] == 1)


def _purpose(artifact_kind: str, artifact_key: str) -> RecoveryPurpose:
    kind = artifact_kind.lower()
    key = artifact_key.lower()
    if kind == "private_archive" or key == "private_archive":
        return "private_record"
    if kind in {"profile", "fact_snapshot"} or key in {
        "client_profile",
        "client_fact_snapshot",
    }:
        return "profile"
    if kind == "graph" or key.endswith("graph") or key == "graph":
        return "graph"
    if kind in {"lex", "lexical"} or key in {"lex", "lexical"}:
        return "lex"
    if kind == "vector" or key == "vector":
        return "vector"
    if kind == "shared_case":
        return "case"
    if kind == "case_index":
        return "index"
    if kind in {
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "claim",
        "claims",
        "c1_revision",
        "c1_absence",
    } or key in {
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "claims",
        "c1_revision",
    }:
        return "wiki"
    # Governed policy/model artifacts share the global publication epoch and
    # the same recovery semantics as the rest of the knowledge closure.  A
    # normal vault can contain these before any Wiki publication (for example
    # the mandatory risk policy), so treating them as unknown would make a
    # healthy production MCP fail during startup recovery.
    if (
        "policy" in kind
        or "policy" in key
        or kind in {"risk_model_descriptor", "reranker_descriptor"}
        or key in {"risk_model_descriptor", "reranker_descriptor"}
    ):
        return "wiki"
    raise SqliteRecoveryError("RECOVERY_ARTIFACT_PURPOSE_UNSUPPORTED")


def _local_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(os.fspath(path)))
    with _LOCAL_LOCKS_GUARD:
        lock = _LOCAL_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCAL_LOCKS[key] = lock
        return lock


def _lock_descriptor(descriptor: int) -> bool:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        module = importlib.import_module("msvcrt")
        try:
            module.locking(descriptor, int(module.LK_NBLCK), 1)
        except OSError:
            return False
        return True
    module = importlib.import_module("fcntl")
    try:
        module.flock(descriptor, int(module.LOCK_EX | module.LOCK_NB))
    except OSError:
        return False
    return True


def _unlock_descriptor(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        module = importlib.import_module("msvcrt")
        module.locking(descriptor, int(module.LK_UNLCK), 1)
        return
    module = importlib.import_module("fcntl")
    module.flock(descriptor, int(module.LOCK_UN))


@contextmanager
def _purpose_lock(database: Path, purpose: RecoveryPurpose) -> Iterator[None]:
    lock_path = database.with_name(f".{database.name}.recovery.{purpose}.lock")
    with _local_lock(lock_path):
        descriptor: int | None = None
        locked = False
        try:
            descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0),
                0o600,
            )
            if os.fstat(descriptor).st_size == 0:
                if os.write(descriptor, b"\0") != 1:
                    raise OSError
                os.fsync(descriptor)
            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
            while not locked:
                locked = _lock_descriptor(descriptor)
                if not locked:
                    if time.monotonic() >= deadline:
                        raise SqliteRecoveryError("RECOVERY_WRITER_BUSY")
                    time.sleep(_LOCK_RETRY_SECONDS)
            yield
        except SqliteRecoveryError:
            raise
        except OSError:
            raise SqliteRecoveryError("RECOVERY_WRITER_LOCK_FAILED") from None
        finally:
            if descriptor is not None:
                try:
                    if locked:
                        _unlock_descriptor(descriptor)
                finally:
                    os.close(descriptor)


class _ManifestCheck:
    __slots__ = ("manifest", "members_complete", "hash_valid", "tombstoned")

    def __init__(
        self,
        *,
        manifest: ArtifactManifest | None,
        members_complete: bool,
        hash_valid: bool,
        tombstoned: bool,
    ) -> None:
        self.manifest = manifest
        self.members_complete = members_complete
        self.hash_valid = hash_valid
        self.tombstoned = tombstoned


class _OperationEvidence:
    __slots__ = (
        "approval_valid",
        "base_version",
        "bound_authority_version",
        "bound_permission_epoch",
        "bound_tombstone_epoch",
        "complete",
        "hash_valid",
        "tombstoned",
    )

    def __init__(
        self,
        *,
        complete: bool = False,
        base_version: int = 0,
        approval_valid: bool = False,
        hash_valid: bool = False,
        tombstoned: bool = False,
        bound_authority_version: int = 0,
        bound_permission_epoch: int = 0,
        bound_tombstone_epoch: int = 0,
    ) -> None:
        self.complete = complete
        self.base_version = base_version
        self.approval_valid = approval_valid
        self.hash_valid = hash_valid
        self.tombstoned = tombstoned
        self.bound_authority_version = bound_authority_version
        self.bound_permission_epoch = bound_permission_epoch
        self.bound_tombstone_epoch = bound_tombstone_epoch


class SqliteRecoveryBackend(RecoveryBackend):
    """Recovery backend for exactly one caller-supplied SQLite scope."""

    def __init__(
        self,
        *,
        database: Path,
        content_store: ContentStore,
        database_scope: RecoveryScope,
        database_ref_sha256: str,
        clock: Clock | None = None,
        staging_ttl: timedelta = _DEFAULT_STAGING_TTL,
        outbox_ack_proofs: Mapping[str, CasePublicationProof] | None = None,
        outbox_proof_verifier: CasePublicationProofVerifier | None = None,
    ) -> None:
        if not isinstance(database, Path) or not database.is_absolute():
            raise TypeError("RECOVERY_DATABASE_PATH_REQUIRED")
        if type(content_store) is not ContentStore:
            raise TypeError("RECOVERY_CONTENT_STORE_REQUIRED")
        if database_scope not in {"global", "client"}:
            raise ValueError("RECOVERY_DATABASE_SCOPE_INVALID")
        if not _valid_sha256(database_ref_sha256):
            raise ValueError("RECOVERY_DATABASE_REFERENCE_INVALID")
        if (
            not isinstance(staging_ttl, timedelta)
            or staging_ttl <= timedelta(0)
            or staging_ttl > timedelta(days=30)
        ):
            raise ValueError("RECOVERY_STAGING_TTL_INVALID")
        proofs = dict(outbox_ack_proofs or {})
        if proofs and outbox_proof_verifier is None:
            raise ValueError("RECOVERY_OUTBOX_PROOF_VERIFIER_REQUIRED")
        self._database = database
        self._store = content_store
        self._scope = database_scope
        self._database_ref = database_ref_sha256
        self._clock = clock or SystemClock()
        self._staging_ttl = staging_ttl
        self._ack_proofs = {
            key: CasePublicationProof.model_validate(value)
            for key, value in proofs.items()
        }
        self._proof_verifier = outbox_proof_verifier

    @property
    def database_ref_sha256(self) -> str:
        return self._database_ref

    def read_only_inventory(self) -> Sequence[RecoveryInventoryItem]:
        connection = connect_database(self._database, "reader")
        try:
            MigrationRunner.for_scope(connection, self._scope).check()
            items = list(self._staging_inventory(connection))
            items.extend(self._publication_inventory(connection))
            items.extend(self._retired_inventory(connection))
            if self._scope == "global":
                items.extend(self._case_ledger_inventory(connection))
            else:
                items.extend(self._private_archive_inventory(connection))
                items.extend(self._outbox_inventory(connection))
            identities = [(item.purpose, item.manifest_id) for item in items]
            if len(identities) != len(set(identities)):
                raise SqliteRecoveryError("RECOVERY_INVENTORY_DUPLICATE")
            return tuple(sorted(items, key=lambda value: (value.purpose, value.manifest_id)))
        finally:
            connection.close()

    @contextmanager
    def single_writer(
        self, *, database_ref_sha256: str, purpose: RecoveryPurpose
    ) -> Iterator[RecoveryWriter]:
        if database_ref_sha256 != self._database_ref:
            raise SqliteRecoveryError("RECOVERY_DATABASE_REFERENCE_MISMATCH")
        with _purpose_lock(self._database, purpose):
            connection = connect_database(self._database, "writer")
            try:
                MigrationRunner.for_scope(connection, self._scope).check()
                yield _SqliteRecoveryWriter(
                    backend=self,
                    connection=connection,
                    purpose=purpose,
                )
            finally:
                connection.close()

    def _manifest_check(
        self,
        connection: sqlite3.Connection,
        manifest_id: str,
        *,
        verify_content: bool = True,
    ) -> _ManifestCheck:
        try:
            manifest = ManifestRepository(connection).get(manifest_id)
        except Exception:
            return _ManifestCheck(
                manifest=None,
                members_complete=False,
                hash_valid=False,
                tombstoned=False,
            )
        tombstones = TombstoneRepository(connection)
        tombstoned = False
        try:
            for member in manifest.members:
                if verify_content:
                    reference = self._store.reference(
                        content_sha256=member.object_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                    self._store.read_verified(reference)
                if tombstones.has_direct(
                    ObjectIdentity(member.object_type, member.object_id)
                ) or any(
                    tombstones.has_lineage_hash(lineage)
                    for lineage in member.source_lineage_hashes
                ):
                    tombstoned = True
        except Exception:
            return _ManifestCheck(
                manifest=manifest,
                members_complete=True,
                hash_valid=False,
                tombstoned=tombstoned,
            )
        return _ManifestCheck(
            manifest=manifest,
            members_complete=bool(manifest.members),
            hash_valid=True,
            tombstoned=tombstoned,
        )

    def _operation_evidence(
        self, connection: sqlite3.Connection, operation_id: str
    ) -> _OperationEvidence:
        row = connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, required_manifests_json, "
            "required_manifest_count, expected_current_epoch, state "
            "FROM publication_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return _OperationEvidence()
        try:
            required_raw = json.loads(str(row[4]))
            required = tuple(required_raw)
            if (
                type(required_raw) is not list
                or any(type(value) is not str for value in required)
                or required != tuple(sorted(set(required)))
                or int(row[5]) != len(required)
                or not required
            ):
                return _OperationEvidence()
            manifests = tuple(
                ManifestRepository(connection).get(identifier)
                for identifier in required
            )
            if tuple(sorted(value.manifest_id for value in manifests)) != required:
                return _OperationEvidence()
            generic_manifests = tuple(
                value
                for value in manifests
                if value.artifact_kind
                not in _DEDICATED_RUNTIME_VALIDATION_KINDS
            )
            dedicated_manifests = tuple(
                value
                for value in manifests
                if value.artifact_kind
                in _DEDICATED_RUNTIME_VALIDATION_KINDS
            )
            if (
                any(value.operation_id != operation_id for value in manifests)
                or any(
                    value.artifact_key
                    in _DEDICATED_RUNTIME_VALIDATION_KINDS
                    for value in generic_manifests
                )
                or any(
                    self._scope != "global"
                    or value.artifact_key != value.artifact_kind
                    for value in dedicated_manifests
                )
            ):
                return _OperationEvidence()
            # Candidate activation is an all-or-nothing operation.  Dedicated
            # runtimes own the policy/model authority checks, but every
            # required sibling still belongs to the exact content closure that
            # recovery must accept or reject before selecting the candidate.
            checks = tuple(
                self._manifest_check(
                    connection,
                    manifest.manifest_id,
                    verify_content=(
                        manifest.artifact_kind
                        not in _METADATA_ONLY_MANIFEST_KINDS
                    ),
                )
                for manifest in manifests
            )
            hash_valid = all(value.hash_valid for value in checks)
            tombstoned = any(value.tombstoned for value in checks)
            closure_candidates: set[str] = set()
            for closure_manifests in (generic_manifests, manifests):
                try:
                    closure_candidates.add(
                        publication_closure_sha256(
                            purpose=str(row[0]),
                            authority_base_version=int(row[1]),
                            expected_current_epoch=(
                                None if row[6] is None else int(row[6])
                            ),
                            artifacts=closure_manifests,
                        )
                    )
                except PublicationIntegrityError:
                    continue
            if not closure_candidates:
                return _OperationEvidence()
            attestation = connection.execute(
                "SELECT approval_draft_sha256, closure_sha256 "
                "FROM publication_closure_attestations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            execution = connection.execute(
                "SELECT request_id, descriptor_sha256, draft_sha256, "
                "descriptor_base_version, state, applied_commit_version, applied_at "
                "FROM approval_executions WHERE request_id = ?",
                (str(row[2]),),
            ).fetchone()
            binding = connection.execute(
                "SELECT authority_version, permission_epoch, tombstone_epoch, "
                "binding_origin "
                "FROM recovery_operation_authority_bindings "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            base_version = 0 if execution is None else int(execution[3])
            binding_trusted = bool(
                binding is not None
                and (str(binding[3]) == "LIVE" or str(row[7]) == "ACTIVE")
            )
            approval_valid = bool(
                attestation is not None
                and execution is not None
                and tuple(execution[:3]) == (str(row[2]), str(row[3]), str(attestation[0]))
                and base_version + 1 == int(row[1])
                and str(execution[4]) == "APPLIED"
                and type(execution[5]) is int
                and int(execution[5]) > 0
                and execution[6] is not None
                and str(attestation[1]) in closure_candidates
                and binding_trusted
            )
            return _OperationEvidence(
                complete=all(value.members_complete for value in checks),
                base_version=base_version,
                approval_valid=approval_valid,
                hash_valid=hash_valid,
                tombstoned=tombstoned,
                bound_authority_version=0 if binding is None else int(binding[0]),
                bound_permission_epoch=0 if binding is None else int(binding[1]),
                bound_tombstone_epoch=0 if binding is None else int(binding[2]),
            )
        except Exception:
            return _OperationEvidence()

    def _rollback_rebuild_operation_evidence(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        generic: _OperationEvidence,
    ) -> _OperationEvidence | None:
        """Resolve an activated client rebuild through its outer rollback P1."""

        classification = connection.execute(
            "SELECT intent.intent_kind FROM rebuild_stage_bindings AS stage "
            "JOIN rebuild_jobs AS job ON job.job_id = stage.job_id "
            "LEFT JOIN rebuild_source_intents AS intent "
            "ON intent.intent_id = job.source_intent_id "
            "WHERE stage.operation_id = ?",
            (operation_id,),
        ).fetchall()
        if classification != [("rollback",)]:
            return None
        try:
            from consultation_kb.knowledge._canonical import canonical_json_bytes
            from consultation_kb.approvals.models import descriptor_sha256
            from consultation_kb.lifecycle.rebuild import _stage_descriptor_sha256
            from consultation_kb.lifecycle.rollback import (
                ArtifactRollbackPlan,
                FactRollbackPlan,
                RollbackPlanEnvelope,
            )
            from consultation_kb.storage.client_ledger import FactEventRepository

            if self._scope != "client":
                raise ValueError
            stage = connection.execute(
                "SELECT stage.job_id, stage.attempt_count, "
                "stage.approval_request_id, stage.plan_sha256, "
                "stage.scope_sha256, stage.tombstone_epoch, "
                "job.source_intent_id, job.approval_operation_id, "
                "job.approval_request_id, job.plan_sha256, job.scope_sha256, "
                "job.tombstone_epoch, job.purpose, job.builder_dag_sha256, "
                "job.input_authority_versions_sha256, job.policy_sha256, "
                "job.model_descriptor_sha256, job.state, job.attempt_count "
                "FROM rebuild_stage_bindings AS stage "
                "JOIN rebuild_jobs AS job ON job.job_id = stage.job_id "
                "WHERE stage.operation_id = ?",
                (operation_id,),
            ).fetchone()
            operation = connection.execute(
                "SELECT purpose, authority_base_version, approval_request_id, "
                "descriptor_sha256, required_manifests_json, "
                "required_manifest_count, expected_current_epoch, state "
                "FROM publication_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if stage is None or operation is None:
                raise ValueError
            approval_operation_id = str(stage[7])
            outer_row = connection.execute(
                "SELECT object_id, version, content_sha256, size_bytes, "
                "media_type, purpose, operation_id, plan_sha256, "
                "base_version, target_scope_hash FROM lifecycle_plan_objects "
                "WHERE operation_id = ?",
                (approval_operation_id,),
            ).fetchone()
            if outer_row is None:
                raise ValueError
            outer_payload = self._store.read_verified(
                self._store.reference(
                    content_sha256=str(outer_row[2]),
                    media_type=str(outer_row[4]),
                    size_bytes=int(outer_row[3]),
                )
            )
            outer_envelope = RollbackPlanEnvelope.model_validate_json(
                outer_payload,
                strict=True,
            )
            if (
                canonical_json_bytes(outer_envelope.model_dump(mode="json"))
                != outer_payload
            ):
                raise ValueError
            outer_plan = outer_envelope.plan
            if isinstance(outer_plan, FactRollbackPlan):
                source_plan = outer_plan
            elif (
                isinstance(outer_plan, ArtifactRollbackPlan)
                and outer_plan.database_scope == "client"
                and outer_plan.source_rollback_kind == "profile_fact"
            ):
                source_ref = outer_plan.source_plan_ref
                source_row = connection.execute(
                    "SELECT object_id, version, content_sha256, size_bytes, "
                    "media_type, purpose, operation_id, plan_sha256, "
                    "base_version, target_scope_hash "
                    "FROM lifecycle_plan_objects WHERE object_id = ?",
                    (source_ref.object_id,),
                ).fetchone()
                if source_row is None or tuple(source_row[:5]) != (
                    source_ref.object_id,
                    source_ref.version,
                    source_ref.content_sha256,
                    source_ref.size_bytes,
                    source_ref.media_type,
                ):
                    raise ValueError
                source_payload = self._store.read_verified(
                    self._store.reference(
                        content_sha256=str(source_row[2]),
                        media_type=str(source_row[4]),
                        size_bytes=int(source_row[3]),
                    )
                )
                source_envelope = RollbackPlanEnvelope.model_validate_json(
                    source_payload,
                    strict=True,
                )
                if (
                    canonical_json_bytes(
                        source_envelope.model_dump(mode="json")
                    )
                    != source_payload
                    or not isinstance(source_envelope.plan, FactRollbackPlan)
                    or source_envelope.rollback_kind != "profile_fact"
                    or source_envelope.database_scope != "client"
                    or source_envelope.scope_sha256 != str(stage[4])
                    or source_envelope.plan.plan_sha256
                    != outer_plan.source_plan_sha256
                    or source_envelope.plan.base_versions
                    != outer_plan.base_versions
                    or tuple(source_row[5:])
                    != (
                        "rollback",
                        source_envelope.operation_id,
                        source_envelope.plan.plan_sha256,
                        source_envelope.plan.descriptor.base_version,
                        str(stage[4]),
                    )
                ):
                    raise ValueError
                source_plan = source_envelope.plan
            else:
                raise ValueError

            descriptor = outer_plan.descriptor
            attestation = connection.execute(
                "SELECT request_id, descriptor_sha256, plan_object_id, "
                "plan_version, plan_content_sha256, plan_size_bytes, "
                "plan_media_type, purpose, base_version, target_scope_hash "
                "FROM lifecycle_approval_attestations WHERE operation_id = ?",
                (approval_operation_id,),
            ).fetchone()
            execution = connection.execute(
                "SELECT request_id, descriptor_sha256, draft_sha256, "
                "descriptor_base_version, target_scope_hash, state, "
                "applied_commit_version, applied_at FROM approval_executions "
                "WHERE operation_id = ?",
                (approval_operation_id,),
            ).fetchone()
            descriptor_digest = descriptor_sha256(descriptor)
            required_raw = json.loads(str(operation[4]))
            if (
                type(required_raw) is not list
                or any(type(value) is not str for value in required_raw)
            ):
                raise ValueError
            required = tuple(required_raw)
            manifest_rows = connection.execute(
                "SELECT artifact_key, manifest_id FROM artifact_manifests "
                "WHERE operation_id = ? ORDER BY artifact_key",
                (operation_id,),
            ).fetchall()
            manifest_by_purpose = {
                str(row[0]): str(row[1]) for row in manifest_rows
            }
            fact_repository = FactEventRepository(connection)
            stored_event = fact_repository.get_event(
                source_plan.new_event.event_id
            )
            latest_event = fact_repository.get_latest_event(source_plan.fact_id)
            rebuild_plan = source_plan.rebuild_plan
            binding_valid = bool(
                outer_envelope.database_scope == "client"
                and outer_envelope.scope_sha256 == str(stage[4])
                and outer_envelope.operation_id == approval_operation_id
                and tuple(outer_row[1:])
                == (
                    1,
                    str(outer_row[2]),
                    int(outer_row[3]),
                    "application/json",
                    "rollback",
                    approval_operation_id,
                    outer_plan.plan_sha256,
                    descriptor.base_version,
                    str(stage[4]),
                )
                and str(stage[2]) == str(stage[8])
                and str(stage[2]) == str(operation[2])
                and str(stage[3]) == str(stage[9])
                and str(stage[4]) == str(stage[10])
                and int(stage[5]) == int(stage[11])
                and int(stage[1]) == int(stage[18])
                and str(stage[17]) in {"activating", "succeeded"}
                and source_plan.operation_id == str(stage[6])
                and rebuild_plan.source_intent_id == str(stage[6])
                and rebuild_plan.plan_sha256 == str(stage[9])
                and rebuild_plan.scope_sha256 == str(stage[10])
                and rebuild_plan.tombstone_epoch == int(stage[11])
                and rebuild_plan.purpose == "all"
                and str(stage[12]) == "all"
                and rebuild_plan.builder_dag_sha256 == str(stage[13])
                and rebuild_plan.input_authority_versions_sha256
                == str(stage[14])
                and rebuild_plan.policy_sha256
                == (None if stage[15] is None else str(stage[15]))
                and rebuild_plan.model_descriptor_sha256
                == (None if stage[16] is None else str(stage[16]))
                and stored_event == source_plan.new_event
                and latest_event == source_plan.new_event
                and attestation
                == (
                    str(stage[2]),
                    descriptor_digest,
                    str(outer_row[0]),
                    1,
                    str(outer_row[2]),
                    int(outer_row[3]),
                    "application/json",
                    "rollback",
                    descriptor.base_version,
                    str(stage[4]),
                )
                and execution is not None
                and tuple(execution[:6])
                == (
                    str(stage[2]),
                    descriptor_digest,
                    outer_plan.plan_sha256,
                    descriptor.base_version,
                    str(stage[4]),
                    "APPLIED",
                )
                and type(execution[6]) is int
                and int(execution[6]) > 0
                and execution[7] is not None
                and str(operation[0]) == "rebuild"
                and int(operation[1])
                == source_plan.new_event.commit_version
                and int(operation[5]) == len(required)
                and required == tuple(sorted(manifest_by_purpose.values()))
                and str(operation[3])
                == _stage_descriptor_sha256(
                    database_scope="client",
                    scope_sha256=str(stage[4]),
                    job_id=str(stage[0]),
                    plan_sha256=str(stage[3]),
                    tombstone_epoch=int(stage[5]),
                    expected_current_epoch=(
                        None if operation[6] is None else int(operation[6])
                    ),
                    manifest_by_purpose=manifest_by_purpose,
                )
                and str(operation[7]) in {"PREPARED", "VERIFIED", "ACTIVE"}
            )
            return _OperationEvidence(
                complete=generic.complete,
                base_version=descriptor.base_version,
                approval_valid=binding_valid,
                hash_valid=generic.hash_valid,
                tombstoned=generic.tombstoned,
                bound_authority_version=generic.bound_authority_version,
                bound_permission_epoch=generic.bound_permission_epoch,
                bound_tombstone_epoch=generic.bound_tombstone_epoch,
            )
        except Exception:
            return _OperationEvidence()

    def _current_authority(
        self, connection: sqlite3.Connection
    ) -> tuple[int, int, int]:
        if self._scope == "global":
            row = connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if row is None or any(type(value) is not int for value in row):
                raise SqliteRecoveryError("RECOVERY_AUTHORITY_STATE_INVALID")
            return int(row[0]), int(row[1]), int(row[2])
        row = connection.execute(
            "SELECT authority.commit_version, "
            "(SELECT COUNT(*) FROM tombstones) "
            "FROM client_fact_authority AS authority WHERE authority.singleton = 1"
        ).fetchone()
        if row is None or any(type(value) is not int for value in row):
            raise SqliteRecoveryError("RECOVERY_AUTHORITY_STATE_INVALID")
        return int(row[0]), 0, int(row[1])

    def _staging_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        root = self._store._scope_root / ".staging"
        if not root.exists():
            return ()
        if not _safe_directory(root):
            raise SqliteRecoveryError("RECOVERY_STAGING_LAYOUT_INVALID")
        items: list[RecoveryInventoryItem] = []
        try:
            purpose_directories = tuple(sorted(root.iterdir(), key=lambda path: path.name))
            for purpose_directory in purpose_directories:
                if (
                    _SAFE_COMPONENT_RE.fullmatch(purpose_directory.name) is None
                    or not _safe_directory(purpose_directory)
                ):
                    raise SqliteRecoveryError("RECOVERY_STAGING_LAYOUT_INVALID")
                purpose = _stage_purpose(
                    purpose_directory.name,
                    scope=self._scope,
                )
                for manifest_directory in sorted(
                    purpose_directory.iterdir(), key=lambda path: path.name
                ):
                    if (
                        _OBJECT_ID_RE.fullmatch(manifest_directory.name) is None
                        or not _safe_directory(manifest_directory)
                    ):
                        raise SqliteRecoveryError("RECOVERY_STAGING_LAYOUT_INVALID")
                    observations: list[tuple[str, str, int, int]] = []
                    for digest_directory in sorted(
                        manifest_directory.iterdir(), key=lambda path: path.name
                    ):
                        if (
                            not _valid_sha256(digest_directory.name)
                            or not _safe_directory(digest_directory)
                        ):
                            raise SqliteRecoveryError(
                                "RECOVERY_STAGING_LAYOUT_INVALID"
                            )
                        for candidate in sorted(
                            digest_directory.iterdir(), key=lambda path: path.name
                        ):
                            try:
                                status = os.lstat(candidate)
                            except OSError:
                                raise SqliteRecoveryError(
                                    "RECOVERY_STAGING_LAYOUT_INVALID"
                                ) from None
                            attributes = int(
                                getattr(status, "st_file_attributes", 0)
                            )
                            if (
                                _STAGING_FILE_RE.fullmatch(candidate.name) is None
                                or not stat.S_ISREG(status.st_mode)
                                or stat.S_ISLNK(status.st_mode)
                                or attributes & 0x400
                                or int(status.st_nlink) != 1
                            ):
                                raise SqliteRecoveryError(
                                    "RECOVERY_STAGING_LAYOUT_INVALID"
                                )
                            observations.append(
                                (
                                    digest_directory.name,
                                    candidate.name,
                                    int(status.st_size),
                                    int(status.st_mtime_ns),
                                )
                            )
                    if not observations:
                        continue
                    formal = connection.execute(
                        "SELECT 1 FROM artifact_manifests WHERE manifest_id = ?",
                        (manifest_directory.name,),
                    ).fetchone()
                    if formal is not None:
                        continue
                    latest_ns = max(value[3] for value in observations)
                    modified_at = datetime.fromtimestamp(
                        latest_ns / 1_000_000_000,
                        tz=timezone.utc,
                    )
                    items.append(
                        RecoveryInventoryItem(
                            database_ref_sha256=self._database_ref,
                            database_scope=self._scope,
                            purpose=purpose,
                            manifest_id=manifest_directory.name,
                            manifest_sha256=_sha256(
                                {
                                    "manifest_id": manifest_directory.name,
                                    "observations": observations,
                                    "stage_purpose": purpose_directory.name,
                                }
                            ),
                            state="DRAFT",
                            activation_mode="runtime_epoch",
                            formal_intent_present=False,
                            members_complete=True,
                            manifest_hash_valid=True,
                            source_version=1,
                            current_source_version=1,
                            base_version=0,
                            current_base_version=0,
                            approval_intent_valid=False,
                            approval_epoch=0,
                            current_approval_epoch=0,
                            permission_allows_activation=True,
                            permission_epoch=0,
                            current_permission_epoch=0,
                            tombstoned=False,
                            tombstone_epoch=0,
                            current_tombstone_epoch=0,
                            active_pointer_valid=True,
                            staging_expires_at=modified_at + self._staging_ttl,
                            rollback_expires_at=None,
                            retention_required=False,
                            source_ack_pending=False,
                            global_state=None,
                        )
                    )
        except SqliteRecoveryError:
            raise
        except OSError:
            raise SqliteRecoveryError("RECOVERY_STAGING_LAYOUT_INVALID") from None
        return tuple(items)

    def _retired_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        missing = connection.execute(
            "SELECT epoch.epoch FROM runtime_epochs AS epoch "
            "LEFT JOIN recovery_epoch_retention_windows AS retention "
            "ON retention.epoch = epoch.epoch "
            "WHERE epoch.state = 'RETIRED' AND retention.epoch IS NULL LIMIT 1"
        ).fetchone()
        if missing is not None:
            raise SqliteRecoveryError("RECOVERY_RETIRED_RETENTION_MISSING")
        rows = connection.execute(
            "SELECT epoch.epoch, active.artifact_key, manifest.manifest_id, "
            "manifest.operation_id, manifest.artifact_kind, "
            "manifest.source_version, manifest.manifest_sha256, "
            "retention.rollback_expires_at, retention.retention_required "
            "FROM runtime_epochs AS epoch "
            "JOIN recovery_epoch_retention_windows AS retention "
            "ON retention.epoch = epoch.epoch "
            "JOIN active_artifacts AS active ON active.epoch = epoch.epoch "
            "JOIN artifact_manifests AS manifest "
            "ON manifest.manifest_id = active.manifest_id "
            "WHERE epoch.state = 'RETIRED' "
            "ORDER BY epoch.epoch, manifest.manifest_id"
        ).fetchall()
        retired_epochs = connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs WHERE state = 'RETIRED'"
        ).fetchone()
        represented_epochs = {int(row[0]) for row in rows}
        if retired_epochs is None or int(retired_epochs[0]) != len(represented_epochs):
            raise SqliteRecoveryError("RECOVERY_RETIRED_EPOCH_EMPTY")
        items: list[RecoveryInventoryItem] = []
        for row in rows:
            checked = self._manifest_check(connection, str(row[2]))
            evidence = self._operation_evidence(connection, str(row[3]))
            purpose = _purpose(str(row[4]), str(row[1]))
            items.append(
                RecoveryInventoryItem(
                    database_ref_sha256=self._database_ref,
                    database_scope=self._scope,
                    purpose=purpose,
                    manifest_id=str(row[2]),
                    manifest_sha256=str(row[6]),
                    state="RETIRED",
                    activation_mode="runtime_epoch",
                    formal_intent_present=True,
                    members_complete=bool(
                        checked.members_complete and evidence.complete
                    ),
                    manifest_hash_valid=bool(
                        checked.hash_valid and evidence.hash_valid
                    ),
                    source_version=int(str(row[5])),
                    current_source_version=int(str(row[5])),
                    base_version=evidence.base_version,
                    current_base_version=evidence.base_version,
                    approval_intent_valid=evidence.approval_valid,
                    approval_epoch=0,
                    current_approval_epoch=0,
                    permission_allows_activation=not checked.tombstoned,
                    permission_epoch=evidence.bound_permission_epoch,
                    current_permission_epoch=evidence.bound_permission_epoch,
                    tombstoned=checked.tombstoned,
                    tombstone_epoch=evidence.bound_tombstone_epoch,
                    current_tombstone_epoch=evidence.bound_tombstone_epoch,
                    active_pointer_valid=True,
                    staging_expires_at=None,
                    rollback_expires_at=_parse_utc(row[7]),
                    retention_required=bool(row[8]),
                    source_ack_pending=False,
                    global_state=None,
                )
            )
        return tuple(items)

    def _private_archive_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        rows = connection.execute(
            "SELECT manifest.manifest_id, manifest.operation_id, "
            "manifest.artifact_key, manifest.artifact_kind, "
            "manifest.source_version, manifest.manifest_sha256, "
            "manifest.state, manifest.verified, operation.state, "
            "revision.revision, revision.state, purpose.state, "
            "purpose.manifest_id "
            "FROM artifact_manifests AS manifest "
            "JOIN publication_operations AS operation "
            "ON operation.operation_id = manifest.operation_id "
            "LEFT JOIN private_archive_revisions AS revision "
            "ON revision.manifest_id = manifest.manifest_id "
            "LEFT JOIN archive_purpose_states AS purpose "
            "ON purpose.bundle_id = revision.bundle_id "
            "AND purpose.purpose = 'private_archive' "
            "WHERE manifest.artifact_kind = 'private_archive' "
            "AND operation.purpose = 'private_archive_publish' "
            "AND revision.manifest_id IS NOT NULL "
            "AND operation.state = 'ACTIVE' "
            "ORDER BY manifest.manifest_id"
        ).fetchall()
        _, authorization_epoch, tombstone_epoch = self._current_authority(connection)
        items: list[RecoveryInventoryItem] = []
        for row in rows:
            checked = self._manifest_check(connection, str(row[0]))
            evidence = self._operation_evidence(connection, str(row[1]))
            current_revision = int(row[9]) if type(row[9]) is int else 0
            items.append(
                RecoveryInventoryItem(
                    database_ref_sha256=self._database_ref,
                    database_scope="client",
                    purpose="private_record",
                    manifest_id=str(row[0]),
                    manifest_sha256=str(row[5]),
                    state="ACTIVE",
                    activation_mode="verified_ledger",
                    formal_intent_present=True,
                    members_complete=bool(
                        checked.members_complete and evidence.complete
                    ),
                    manifest_hash_valid=bool(
                        checked.hash_valid
                        and evidence.hash_valid
                        and checked.manifest is not None
                        and checked.manifest.manifest_sha256 == str(row[5])
                    ),
                    source_version=int(str(row[4])),
                    current_source_version=current_revision,
                    base_version=evidence.base_version,
                    current_base_version=max(current_revision - 1, 0),
                    approval_intent_valid=evidence.approval_valid,
                    approval_epoch=0,
                    current_approval_epoch=0,
                    permission_allows_activation=not checked.tombstoned,
                    permission_epoch=evidence.bound_permission_epoch,
                    current_permission_epoch=authorization_epoch,
                    tombstoned=checked.tombstoned,
                    tombstone_epoch=evidence.bound_tombstone_epoch,
                    current_tombstone_epoch=tombstone_epoch,
                    active_pointer_valid=bool(
                        str(row[6]) == "ACTIVE"
                        and int(row[7]) == 1
                        and str(row[8]) == "ACTIVE"
                        and str(row[10]) == "ACTIVE"
                        and str(row[11]) == "ACTIVE"
                        and str(row[12]) == str(row[0])
                    ),
                    staging_expires_at=None,
                    rollback_expires_at=None,
                    retention_required=True,
                    source_ack_pending=False,
                    global_state=None,
                )
            )
        return tuple(items)

    def _publication_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        active_epochs = connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE' ORDER BY epoch"
        ).fetchall()
        active_epoch_valid = len(active_epochs) <= 1
        active_epoch = None if not active_epochs else int(active_epochs[0][0])
        active_rows = (
            []
            if active_epoch is None
            else connection.execute(
                "SELECT artifact_key, manifest_id FROM active_artifacts "
                "WHERE epoch = ? ORDER BY artifact_key",
                (active_epoch,),
            ).fetchall()
        )
        active = {str(row[1]): str(row[0]) for row in active_rows}
        rows = connection.execute(
            "SELECT manifest.manifest_id, manifest.operation_id, "
            "manifest.artifact_key, manifest.artifact_kind, "
            "manifest.source_version, manifest.manifest_sha256, manifest.state, "
            "manifest.verified, operation.state, operation.authority_base_version, "
            "operation.expected_current_epoch, operation.purpose "
            "FROM artifact_manifests AS manifest "
            "JOIN publication_operations AS operation "
            "ON operation.operation_id = manifest.operation_id "
            "WHERE operation.state IN ('PREPARED', 'VERIFIED') "
            "OR manifest.manifest_id IN ("
            "SELECT active.manifest_id FROM active_artifacts AS active "
            "JOIN runtime_epochs AS epoch ON epoch.epoch = active.epoch "
            "WHERE epoch.state = 'ACTIVE') "
            "ORDER BY manifest.manifest_id"
        ).fetchall()
        authority_version, authorization_epoch, tombstone_epoch = (
            self._current_authority(connection)
        )
        values: list[RecoveryInventoryItem] = []
        for row in rows:
            manifest_id = str(row[0])
            artifact_key = str(row[2])
            artifact_kind = str(row[3])
            # Risk policy/model manifests deliberately use the checked-in
            # policy version rather than the knowledge catalog version and do
            # not store their bodies in the global CAS.  The dedicated risk
            # runtime validates their exact policy bytes, member hashes,
            # approval, manifest set and active epoch synchronously before the
            # MCP exposes handlers.  Applying generic publication recovery to
            # them would conflate two authority-version domains.
            if artifact_kind in _DEDICATED_RUNTIME_VALIDATION_KINDS:
                continue
            if artifact_kind in _NON_RUNTIME_KINDS:
                if artifact_kind == "case_index":
                    item = self._case_index_item(connection, row)
                    if item is not None:
                        values.append(item)
                continue
            operation_state = str(row[8])
            if operation_state in {"PREPARED", "VERIFIED"}:
                state: Literal["PREPARED", "ACTIVE"] = "PREPARED"
            elif manifest_id in active:
                state = "ACTIVE"
            else:
                continue
            purpose = _purpose(artifact_kind, artifact_key)
            dedicated_private_archive = bool(
                artifact_kind == "private_archive"
                and str(row[11]) == "private_archive_publish"
            )
            checked = self._manifest_check(connection, manifest_id)
            evidence = self._operation_evidence(
                connection, str(row[1])
            )
            rollback_rebuild_evidence = (
                self._rollback_rebuild_operation_evidence(
                    connection,
                    str(row[1]),
                    evidence,
                )
                if str(row[11]) == "rebuild"
                else None
            )
            if rollback_rebuild_evidence is not None:
                evidence = rollback_rebuild_evidence
            manifest = checked.manifest
            hash_valid = bool(
                checked.hash_valid
                and evidence.hash_valid
                and manifest is not None
                and manifest.manifest_sha256 == str(row[5])
                and manifest.source_version == int(str(row[4]))
            )
            active_pointer = True
            if state == "ACTIVE":
                active_pointer = bool(
                    active_epoch_valid
                    and active.get(manifest_id) == artifact_key
                    and str(row[6]) == "ACTIVE"
                    and int(row[7]) == 1
                )
            current_source_version = int(row[9])
            current_base_version = evidence.base_version
            if (
                self._scope == "global"
                or purpose in {"profile", "graph"}
                or (
                    artifact_kind == "private_archive"
                    and not dedicated_private_archive
                )
            ):
                current_source_version = authority_version
                current_base_version = max(authority_version - 1, 0)
            if dedicated_private_archive:
                private = connection.execute(
                    "SELECT revision FROM private_archive_revisions "
                    "WHERE manifest_id = ?",
                    (manifest_id,),
                ).fetchone()
                current_source_version = (
                    0 if private is None or type(private[0]) is not int else int(private[0])
                )
                current_base_version = max(current_source_version - 1, 0)
            values.append(
                RecoveryInventoryItem(
                    database_ref_sha256=self._database_ref,
                    database_scope=self._scope,
                    purpose=purpose,
                    manifest_id=manifest_id,
                    manifest_sha256=str(row[5]),
                    state=state,
                    activation_mode="runtime_epoch",
                    formal_intent_present=True,
                    members_complete=bool(checked.members_complete and evidence.complete),
                    manifest_hash_valid=hash_valid,
                    source_version=int(str(row[4])),
                    current_source_version=current_source_version,
                    base_version=evidence.base_version,
                    current_base_version=current_base_version,
                    approval_intent_valid=bool(
                        evidence.approval_valid
                        and not dedicated_private_archive
                    ),
                    approval_epoch=0,
                    current_approval_epoch=0,
                    permission_allows_activation=not (
                        checked.tombstoned or evidence.tombstoned
                    ),
                    permission_epoch=evidence.bound_permission_epoch,
                    current_permission_epoch=authorization_epoch,
                    tombstoned=checked.tombstoned or evidence.tombstoned,
                    tombstone_epoch=evidence.bound_tombstone_epoch,
                    current_tombstone_epoch=tombstone_epoch,
                    active_pointer_valid=active_pointer,
                    staging_expires_at=None,
                    rollback_expires_at=None,
                    retention_required=True,
                    source_ack_pending=False,
                    global_state=None,
                )
            )
        return tuple(values)

    def _case_index_item(
        self, connection: sqlite3.Connection, row: tuple[object, ...]
    ) -> RecoveryInventoryItem | None:
        manifest_id = str(row[0])
        ledger = connection.execute(
            "SELECT pattern.state, queue.state, queue.catalog_version, "
            "invalidation.queue_id "
            "FROM case_patterns AS pattern "
            "JOIN rebuild_queue AS queue "
            "ON queue.upstream_type = 'case_index' "
            "AND queue.upstream_id = pattern.manifest_id "
            "LEFT JOIN case_index_rebuild_invalidations AS invalidation "
            "ON invalidation.queue_id = queue.queue_id "
            "WHERE pattern.manifest_id = ?",
            (manifest_id,),
        ).fetchone()
        if ledger is None or str(ledger[0]) == "REVOKED":
            return None
        is_active = str(ledger[0]) == "ACTIVE" and str(ledger[1]) == "COMPLETED"
        is_pending = (
            str(ledger[0]) == "PREPARED"
            and str(ledger[1]) in {"PENDING", "CLAIMED"}
        )
        if not is_active and not is_pending:
            raise SqliteRecoveryError("RECOVERY_CASE_INDEX_LEDGER_INVALID")
        checked = self._manifest_check(connection, manifest_id)
        evidence = self._operation_evidence(
            connection, str(row[1])
        )
        authority_version, authorization_epoch, tombstone_epoch = (
            self._current_authority(connection)
        )
        invalidated = ledger[3] is not None
        return RecoveryInventoryItem(
            database_ref_sha256=self._database_ref,
            database_scope="global",
            purpose="index",
            manifest_id=manifest_id,
            manifest_sha256=str(row[5]),
            state="ACTIVE" if is_active else "PREPARED",
            activation_mode="verified_ledger" if is_active else "full_rebuild_only",
            formal_intent_present=True,
            members_complete=bool(checked.members_complete and evidence.complete),
            manifest_hash_valid=bool(
                checked.hash_valid
                and evidence.hash_valid
                and checked.manifest is not None
                and checked.manifest.state == "VERIFIED"
                and checked.manifest.verified
            ),
            source_version=int(str(row[4])),
            current_source_version=authority_version,
            base_version=evidence.base_version,
            current_base_version=max(authority_version - 1, 0),
            approval_intent_valid=evidence.approval_valid,
            approval_epoch=0,
            current_approval_epoch=0,
            permission_allows_activation=not invalidated and not checked.tombstoned,
            permission_epoch=evidence.bound_permission_epoch,
            current_permission_epoch=authorization_epoch,
            tombstoned=bool(invalidated or checked.tombstoned),
            tombstone_epoch=evidence.bound_tombstone_epoch,
            current_tombstone_epoch=tombstone_epoch,
            active_pointer_valid=bool(
                str(row[6]) == "VERIFIED"
                and type(row[7]) is int
                and row[7] == 1
                and str(row[8]) == "VERIFIED"
                and row[10] is None
            ),
            staging_expires_at=None,
            rollback_expires_at=None,
            retention_required=True,
            source_ack_pending=False,
            global_state=None,
        )

    def _case_ledger_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        if not _table_exists(connection, "global_publish_sagas"):
            return ()
        rows = connection.execute(
            "SELECT saga.manifest_id, saga.outbox_payload_sha256, "
            "saga.candidate_version, saga.state, saga.authority_epoch, "
            "saga.case_id, saga.case_version, saga.global_content_sha256, "
            "cases.state, cases.current_version, versions.state, "
            "versions.candidate_version, authorization.expires_at, "
            "authorization.revoked_at, saga.publication_operation_id "
            "FROM global_publish_sagas AS saga "
            "LEFT JOIN cases ON cases.case_id = saga.case_id "
            "LEFT JOIN case_versions AS versions "
            "ON versions.case_id = saga.case_id AND versions.version = saga.case_version "
            "LEFT JOIN case_authorizations AS authorization "
            "ON authorization.case_id = saga.case_id "
            "AND authorization.case_version = saga.case_version "
            "ORDER BY saga.manifest_id"
        ).fetchall()
        _, authorization_epoch, tombstone_epoch = self._current_authority(connection)
        observed_at = self._clock.now()
        items: list[RecoveryInventoryItem] = []
        for row in rows:
            saga_state = str(row[3])
            active = saga_state == "ACTIVE"
            checked = self._manifest_check(connection, str(row[0]))
            evidence = self._operation_evidence(connection, str(row[14]))
            manifest_sha = (
                checked.manifest.manifest_sha256
                if checked.manifest is not None
                else str(row[1])
            )
            coherent = bool(
                active
                and row[8] == "ACTIVE"
                and row[9] == row[6]
                and row[10] == "ACTIVE"
                and checked.manifest is not None
                and checked.manifest.state == "VERIFIED"
                and checked.manifest.verified
            )
            current_case_version = int(row[9]) if type(row[9]) is int else 0
            current_candidate_version = int(row[11]) if type(row[11]) is int else 0
            permission_live = bool(
                row[13] is None
                and (row[12] is None or observed_at < _parse_utc(row[12]))
                and row[8] != "REVOKED"
            )
            bound_permission_epoch = (
                evidence.bound_permission_epoch
                if evidence.complete
                else (0 if row[4] is None else int(row[4]))
            )
            bound_tombstone_epoch = (
                evidence.bound_tombstone_epoch
                if evidence.complete
                else tombstone_epoch
            )
            items.append(
                RecoveryInventoryItem(
                    database_ref_sha256=self._database_ref,
                    database_scope="global",
                    purpose="case",
                    manifest_id=str(row[0]),
                    manifest_sha256=manifest_sha,
                    state="ACTIVE" if active else "PREPARED",
                    activation_mode="verified_ledger" if active else "sealed_replay",
                    formal_intent_present=True,
                    members_complete=checked.members_complete,
                    manifest_hash_valid=checked.hash_valid,
                    source_version=int(row[6]),
                    current_source_version=current_case_version,
                    base_version=int(row[2]),
                    current_base_version=current_candidate_version,
                    approval_intent_valid=bool(active or saga_state == "PREPARED"),
                    approval_epoch=0,
                    current_approval_epoch=0,
                    permission_allows_activation=bool(
                        permission_live and not checked.tombstoned
                    ),
                    permission_epoch=bound_permission_epoch,
                    current_permission_epoch=authorization_epoch,
                    tombstoned=checked.tombstoned or row[8] == "REVOKED",
                    tombstone_epoch=bound_tombstone_epoch,
                    current_tombstone_epoch=tombstone_epoch,
                    active_pointer_valid=coherent if active else True,
                    staging_expires_at=None,
                    rollback_expires_at=None,
                    retention_required=True,
                    source_ack_pending=False,
                    global_state=None,
                )
            )
        return tuple(items)

    def _outbox_inventory(
        self, connection: sqlite3.Connection
    ) -> tuple[RecoveryInventoryItem, ...]:
        if not _table_exists(connection, "outbox_events"):
            return ()
        repository = OutboxRepository(connection)
        rows = connection.execute(
            "SELECT event_id FROM outbox_events "
            "WHERE state IN ('PENDING', 'CLAIMED', 'FAILED') "
            "ORDER BY event_id"
        ).fetchall()
        _, _, tombstone_epoch = self._current_authority(connection)
        items: list[RecoveryInventoryItem] = []
        for (event_id_raw,) in rows:
            event = repository.get(str(event_id_raw))
            payload: CasePublishOutboxPayload | None = None
            hash_valid = False
            try:
                reference = self._store.reference(
                    content_sha256=event.payload.content_sha256,
                    media_type=event.payload.media_type,
                    size_bytes=event.payload.size_bytes,
                )
                body = self._store.read_verified(reference)
                payload = CasePublishOutboxPayload.model_validate_json(body, strict=True)
                hash_valid = payload.idempotency_key == event.idempotency_key
            except Exception:
                payload = None
            approval_valid = False
            source_version = 1
            base_version = 0
            if payload is not None:
                source_version = payload.candidate_ref.version
                base_version = payload.candidate_ref.version
                execution = connection.execute(
                    "SELECT request_id, descriptor_sha256, draft_sha256, "
                    "target_scope_hash, state, applied_commit_version, applied_at "
                    "FROM approval_executions WHERE operation_id = ?",
                    (payload.approval_operation_id,),
                ).fetchone()
                approval_valid = bool(
                    execution is not None
                    and tuple(execution[:4])
                    == (
                        payload.approval_request_id,
                        payload.approval_descriptor_sha256,
                        payload.approval_draft_sha256,
                        payload.approval_target_scope_hash,
                    )
                    and execution[4] == "APPLIED"
                    and type(execution[5]) is int
                    and int(execution[5]) > 0
                    and execution[6] is not None
                )
            proof = self._ack_proofs.get(event.event_id)
            binding = connection.execute(
                "SELECT tombstone_epoch, binding_origin "
                "FROM recovery_outbox_authority_bindings WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            binding_trusted = bool(
                binding is not None and str(binding[1]) == "LIVE"
            )
            proof_valid = bool(
                proof is not None
                and payload is not None
                and self._proof_verifier is not None
                and self._proof_verifier.verify(proof)
                and proof.payload.source_event_id == event.event_id
                and proof.payload.approval_operation_id
                == payload.approval_operation_id
                and proof.payload.approval_request_id == payload.approval_request_id
                and proof.payload.approval_descriptor_sha256
                == payload.approval_descriptor_sha256
                and proof.payload.approval_draft_sha256
                == payload.approval_draft_sha256
                and proof.payload.approval_target_scope_hash
                == payload.approval_target_scope_hash
            )
            items.append(
                RecoveryInventoryItem(
                    database_ref_sha256=self._database_ref,
                    database_scope="client",
                    purpose="outbox",
                    manifest_id=event.event_id,
                    manifest_sha256=event.payload.content_sha256,
                    state="PREPARED",
                    activation_mode="sealed_replay",
                    formal_intent_present=True,
                    members_complete=payload is not None,
                    manifest_hash_valid=hash_valid,
                    source_version=source_version,
                    current_source_version=source_version,
                    base_version=base_version,
                    current_base_version=base_version,
                    approval_intent_valid=approval_valid,
                    approval_epoch=0,
                    current_approval_epoch=0,
                    permission_allows_activation=binding_trusted,
                    permission_epoch=0,
                    current_permission_epoch=0,
                    tombstoned=False,
                    tombstone_epoch=(
                        tombstone_epoch if binding is None else int(binding[0])
                    ),
                    current_tombstone_epoch=tombstone_epoch,
                    active_pointer_valid=True,
                    staging_expires_at=None,
                    rollback_expires_at=None,
                    retention_required=True,
                    source_ack_pending=bool(proof_valid and binding_trusted),
                    global_state=(
                        "ACTIVE" if proof_valid and binding_trusted else None
                    ),
                )
            )
        return tuple(items)

    def _proof_for(self, event_id: str) -> CasePublicationProof:
        proof = self._ack_proofs.get(event_id)
        if proof is None or self._proof_verifier is None:
            raise SqliteRecoveryError("RECOVERY_OUTBOX_PROOF_REQUIRED")
        if not self._proof_verifier.verify(proof):
            raise SqliteRecoveryError("RECOVERY_OUTBOX_PROOF_INVALID")
        return proof


class _SqliteRecoveryWriter(RecoveryWriter):
    def __init__(
        self,
        *,
        backend: SqliteRecoveryBackend,
        connection: sqlite3.Connection,
        purpose: RecoveryPurpose,
    ) -> None:
        self._backend = backend
        self._connection = connection
        self._purpose = purpose

    def apply(self, decision: RecoveryDecision) -> RecoveryApplyReceipt:
        exact = RecoveryDecision.model_validate(decision)
        if (
            exact.database_ref_sha256 != self._backend.database_ref_sha256
            or exact.database_scope != self._backend._scope
            or exact.purpose != self._purpose
        ):
            raise SqliteRecoveryError("RECOVERY_DECISION_SCOPE_MISMATCH")
        replay = self._receipt(exact)
        if replay is not None:
            return replay
        if exact.action == "VERIFY_AND_ACTIVATE":
            self._recover_runtime_publication(exact)
        elif exact.action == "TOMBSTONE_PREPARED":
            self._retire_invalid_prepared(exact)
        elif exact.action == "ACK_SOURCE":
            self._ack_source(exact)
        elif exact.action in {"ENQUEUE_REBUILD", "QUEUE_CLEANUP", "CLEAN_STAGING"}:
            action_type = "rebuild" if exact.action == "ENQUEUE_REBUILD" else "cleanup"
            with transaction(self._connection):
                result = self._insert_journal(exact, outcome=action_type)
                self._connection.execute(
                    "INSERT INTO recovery_required_actions("
                    "decision_sha256, action_type, database_ref_sha256, purpose, "
                    "manifest_id, manifest_sha256, evidence_sha256, state, "
                    "attempt_count, last_error_code, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, NULL, ?, ?)",
                    (
                        exact.decision_sha256,
                        action_type,
                        exact.database_ref_sha256,
                        exact.purpose,
                        exact.manifest_id,
                        exact.manifest_sha256,
                        exact.evidence_sha256,
                        result[1],
                        result[1],
                    ),
                )
        else:
            raise SqliteRecoveryError("RECOVERY_ACTION_UNSUPPORTED")
        receipt = self._receipt(exact)
        if receipt is None:
            raise SqliteRecoveryError("RECOVERY_JOURNAL_MISSING")
        return receipt.model_copy(update={"disposition": "APPLIED"})

    def _receipt(self, decision: RecoveryDecision) -> RecoveryApplyReceipt | None:
        row = self._connection.execute(
            "SELECT after_state, durable_result_sha256 "
            "FROM recovery_decision_journal WHERE decision_sha256 = ?",
            (decision.decision_sha256,),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != decision.after_state:
            raise SqliteRecoveryError("RECOVERY_JOURNAL_CONFLICT")
        return RecoveryApplyReceipt(
            decision_sha256=decision.decision_sha256,
            disposition="REPLAYED",
            after_state=cast(Literal["DRAFT", "PREPARED", "ACTIVE", "RETIRED"], str(row[0])),
            durable_result_sha256=str(row[1]),
        )

    def _insert_journal(
        self, decision: RecoveryDecision, *, outcome: str
    ) -> tuple[str, str]:
        applied_at = _utc_text(self._backend._clock.now())
        durable = _sha256(
            {
                "action": decision.action,
                "after_state": decision.after_state,
                "decision_sha256": decision.decision_sha256,
                "evidence_sha256": decision.evidence_sha256,
                "manifest_id": decision.manifest_id,
                "manifest_sha256": decision.manifest_sha256,
                "outcome": outcome,
            }
        )
        self._connection.execute(
            "INSERT INTO recovery_decision_journal("
            "decision_sha256, evidence_sha256, database_ref_sha256, "
            "database_scope, purpose, manifest_id, manifest_sha256, "
            "before_state, after_state, action, verification_result, "
            "reason_codes_json, durable_result_sha256, applied_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision.decision_sha256,
                decision.evidence_sha256,
                decision.database_ref_sha256,
                decision.database_scope,
                decision.purpose,
                decision.manifest_id,
                decision.manifest_sha256,
                decision.before_state,
                decision.after_state,
                decision.action,
                decision.verification_result,
                json.dumps(
                    list(decision.reason_codes),
                    ensure_ascii=True,
                    separators=(",", ":"),
                ),
                durable,
                applied_at,
            ),
        )
        return durable, applied_at

    def _manifest_operation(self, manifest_id: str) -> tuple[str, str]:
        row = self._connection.execute(
            "SELECT manifest.operation_id, manifest.artifact_kind "
            "FROM artifact_manifests AS manifest WHERE manifest.manifest_id = ?",
            (manifest_id,),
        ).fetchone()
        if row is None:
            raise SqliteRecoveryError("RECOVERY_MANIFEST_NOT_FOUND")
        return str(row[0]), str(row[1])

    def _runtime_operation(self, manifest_id: str) -> str:
        operation_id, artifact_kind = self._manifest_operation(manifest_id)
        if artifact_kind in _RUNTIME_ACTIVATION_DENIED_KINDS:
            raise SqliteRecoveryError("RECOVERY_LEDGER_RUNTIME_ACTIVATION_DENIED")
        return operation_id

    def _required_manifest_ids(self, operation_id: str) -> tuple[str, ...]:
        row = self._connection.execute(
            "SELECT required_manifests_json FROM publication_operations "
            "WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise SqliteRecoveryError("RECOVERY_OPERATION_NOT_FOUND")
        try:
            raw_required = json.loads(str(row[0]))
            required = tuple(raw_required)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVALID") from None
        if (
            type(raw_required) is not list
            or not required
            or any(type(value) is not str for value in required)
            or required != tuple(sorted(set(required)))
        ):
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVALID")
        return required

    def _sibling_decisions(
        self,
        *,
        operation_id: str,
        required: tuple[str, ...],
    ) -> tuple[RecoveryDecision, ...]:
        placeholders = ",".join("?" for _ in required)
        rows = self._connection.execute(
            "SELECT manifest_id, artifact_key, artifact_kind "
            "FROM artifact_manifests WHERE operation_id = ? "
            f"AND manifest_id IN ({placeholders}) ORDER BY manifest_id",
            (operation_id, *required),
        ).fetchall()
        if tuple(str(row[0]) for row in rows) != required:
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVENTORY_CHANGED")
        recoverable_required: list[str] = []
        for manifest_id, artifact_key, artifact_kind in rows:
            kind = str(artifact_kind)
            if kind in _DEDICATED_RUNTIME_VALIDATION_KINDS:
                # These siblings remain part of the exact operation closure
                # verified and activated by PublishCoordinator.  They omit
                # only the generic knowledge-version recovery decision; the
                # dedicated risk runtime revalidates their policy/model
                # authority before MCP handlers become available.
                if self._backend._scope != "global" or str(artifact_key) != kind:
                    raise SqliteRecoveryError(
                        "RECOVERY_OPERATION_INVENTORY_CHANGED"
                    )
                continue
            recoverable_required.append(str(manifest_id))
        inventory = {
            item.manifest_id: item
            for item in self._backend._publication_inventory(self._connection)
            if item.manifest_id in recoverable_required
        }
        if set(inventory) != set(recoverable_required):
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVENTORY_CHANGED")
        policies = RecoveryPolicyRegistry.default()
        observed_at = self._backend._clock.now()
        return tuple(
            policies.decide(inventory[manifest_id], observed_at=observed_at)
            for manifest_id in recoverable_required
        )

    def _recover_runtime_publication(self, decision: RecoveryDecision) -> None:
        operation_id = self._runtime_operation(decision.manifest_id)
        required = self._required_manifest_ids(operation_id)
        sibling_decisions = self._sibling_decisions(
            operation_id=operation_id,
            required=required,
        )
        if (
            decision.decision_sha256
            not in {value.decision_sha256 for value in sibling_decisions}
            or any(value.action != "VERIFY_AND_ACTIVATE" for value in sibling_decisions)
        ):
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVENTORY_CHANGED")
        coordinator = PublishCoordinator(
            self._connection,
            self._backend._store,
            VisibilityGuard(TombstoneRepository(self._connection)),
            clock=self._backend._clock,
        )
        row = self._connection.execute(
            "SELECT state FROM publication_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise SqliteRecoveryError("RECOVERY_OPERATION_NOT_FOUND")
        if str(row[0]) == "PREPARED":
            coordinator.verify(operation_id)
        with transaction(self._connection):
            active = coordinator.activate(operation_id)
            if active.state != "ACTIVE":
                raise SqliteRecoveryError("RECOVERY_ACTIVATION_INCOMPLETE")
            for sibling in sibling_decisions:
                if self._receipt(sibling) is None:
                    self._insert_journal(sibling, outcome="runtime_active")

    def _retire_invalid_prepared(self, decision: RecoveryDecision) -> None:
        operation_id, _ = self._manifest_operation(decision.manifest_id)
        required = self._required_manifest_ids(operation_id)
        sibling_decisions = self._sibling_decisions(
            operation_id=operation_id,
            required=required,
        )
        if (
            decision.decision_sha256
            not in {value.decision_sha256 for value in sibling_decisions}
            or any(value.action != "TOMBSTONE_PREPARED" for value in sibling_decisions)
        ):
            raise SqliteRecoveryError("RECOVERY_OPERATION_INVENTORY_CHANGED")
        with transaction(self._connection):
            self._connection.execute(
                "UPDATE publication_operations SET state = 'FAILED' "
                "WHERE operation_id = ? AND state IN ('PREPARED', 'VERIFIED')",
                (operation_id,),
            )
            state = self._connection.execute(
                "SELECT state FROM publication_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if state != ("FAILED",):
                raise SqliteRecoveryError("RECOVERY_PREPARED_STATE_CHANGED")
            for sibling in sibling_decisions:
                if self._receipt(sibling) is not None:
                    continue
                _, applied_at = self._insert_journal(
                    sibling,
                    outcome="prepared_failed_closed",
                )
                self._connection.execute(
                    "INSERT INTO recovery_prepared_retirements("
                    "manifest_id, operation_id, decision_sha256, manifest_sha256, "
                    "evidence_sha256, retired_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sibling.manifest_id,
                        operation_id,
                        sibling.decision_sha256,
                        sibling.manifest_sha256,
                        sibling.evidence_sha256,
                        applied_at,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO recovery_required_actions("
                    "decision_sha256, action_type, database_ref_sha256, purpose, "
                    "manifest_id, manifest_sha256, evidence_sha256, state, "
                    "attempt_count, last_error_code, created_at, updated_at"
                    ") VALUES (?, 'cleanup', ?, ?, ?, ?, ?, 'PENDING', "
                    "0, NULL, ?, ?)",
                    (
                        sibling.decision_sha256,
                        sibling.database_ref_sha256,
                        sibling.purpose,
                        sibling.manifest_id,
                        sibling.manifest_sha256,
                        sibling.evidence_sha256,
                        applied_at,
                        applied_at,
                    ),
                )

    def _ack_source(self, decision: RecoveryDecision) -> None:
        if self._backend._scope != "client" or decision.purpose != "outbox":
            raise SqliteRecoveryError("RECOVERY_OUTBOX_SCOPE_INVALID")
        with transaction(self._connection):
            matching = tuple(
                item
                for item in self._backend._outbox_inventory(self._connection)
                if item.manifest_id == decision.manifest_id
            )
            if len(matching) != 1:
                raise SqliteRecoveryError("RECOVERY_OUTBOX_INVENTORY_CHANGED")
            current = RecoveryPolicyRegistry.default().decide(
                matching[0],
                observed_at=self._backend._clock.now(),
            )
            if (
                current.action != "ACK_SOURCE"
                or current.decision_sha256 != decision.decision_sha256
            ):
                raise SqliteRecoveryError("RECOVERY_OUTBOX_INVENTORY_CHANGED")
            proof = self._backend._proof_for(decision.manifest_id)
            record = OutboxRepository(self._connection).mark_published_in_transaction(
                decision.manifest_id,
                global_version=proof.payload.published_global_version,
                published_at=self._backend._clock.now(),
                publication_proof=proof,
            )
            if record.state != "PUBLISHED":
                raise SqliteRecoveryError("RECOVERY_OUTBOX_ACK_INCOMPLETE")
            self._insert_journal(decision, outcome="source_acknowledged")


def compose_global_recovery(
    *,
    database: Path,
    content_store: ContentStore,
    database_ref_sha256: str,
    apply: bool,
    clock: Clock | None = None,
) -> RecoveryScan | RecoveryReport:
    """Scan or recover exactly one global database; never discover clients."""

    backend = SqliteRecoveryBackend(
        database=database,
        content_store=content_store,
        database_scope="global",
        database_ref_sha256=database_ref_sha256,
        clock=clock,
    )
    coordinator = RecoveryCoordinator(backend=backend, clock=clock)
    return coordinator.recover() if apply else coordinator.scan()


def global_database_reference(vault_root: Path) -> str:
    """Return the canonical opaque reference for one exact global database."""

    if not isinstance(vault_root, Path) or not vault_root.is_absolute():
        raise TypeError("RECOVERY_VAULT_ROOT_REQUIRED")
    identity = os.path.normcase(os.path.normpath(os.fspath(vault_root)))
    vault_security_id = (
        "vault_"
        + hashlib.sha256(identity.encode("utf-8", errors="strict")).hexdigest()
    )
    return hashlib.sha256(
        b"consultation-kb-database-ref-v1\0"
        + vault_security_id.encode("ascii", errors="strict")
        + b"\0global\0catalog"
    ).hexdigest()


def scoped_database_reference(scope_marker_sha256: str) -> str:
    """Derive a body-free client database reference from its bound scope marker."""

    if not _valid_sha256(scope_marker_sha256):
        raise ValueError("RECOVERY_SCOPE_MARKER_INVALID")
    return hashlib.sha256(
        b"consultation-kb-client-recovery-database-v1\0"
        + scope_marker_sha256.encode("ascii")
    ).hexdigest()


__all__ = [
    "SqliteRecoveryBackend",
    "SqliteRecoveryError",
    "compose_global_recovery",
    "global_database_reference",
    "scoped_database_reference",
]
