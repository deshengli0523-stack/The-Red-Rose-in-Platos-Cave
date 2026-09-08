"""Fixed-vault Doctor probes for retrieval and lifecycle readiness."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

import numpy as np

from consultation_kb.core.config import AppConfig
from consultation_kb.core.doctor import DiagnosticProbe, DoctorCheck
from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationRepository,
    CaseIndexRebuildIdentity,
    CaseIndexRebuildSnapshot,
    CaseIndexReplayDescriptor,
)
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.lifecycle.backup_queue import BackupDestructionQueue
from consultation_kb.lifecycle.cleanup_authority import CleanupAuthorityResolver
from consultation_kb.lifecycle.production_rebuild import (
    load_production_rebuild_config,
)
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.lifecycle.rebuild_registry import BuilderRegistry
from consultation_kb.models.cases import CaseProvenanceRecord
from consultation_kb.models.common import VersionRef
from consultation_kb.retrieval.artifact_contracts import ArtifactBinding
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
)
from consultation_kb.retrieval.embeddings import ModelDescriptor
from consultation_kb.retrieval.lexical_builder import LexicalBuildManifest
from consultation_kb.retrieval.vector_builder import VectorBuildManifest
from consultation_kb.security.scope_identity import global_approval_scope_sha256
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    IntegrityStore,
)
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.vault.content_store import ContentStore


_REPARSE_ATTRIBUTE: Final = 0x400
_LEXICAL_METADATA_KEYS: Final = frozenset(
    {
        "assigned_input_set_sha256",
        "builder_input_sha256",
        "retrieval_input_descriptor_sha256",
        "row_mapping_sha256",
        "schema_version",
        "source_catalog_version",
        "target_runtime_epoch",
        "tokenizer_descriptor",
        "tokenizer_descriptor_id",
    }
)
_VECTOR_METADATA_KEYS: Final = frozenset(
    {
        "assigned_input_set_sha256",
        "builder_input_sha256",
        "model_descriptor_id",
        "retrieval_input_descriptor_sha256",
        "row_mapping_sha256",
        "schema_version",
        "shard_id",
        "source_catalog_version",
        "target_runtime_epoch",
        "vector_filename",
        "vector_sha256",
    }
)


class _DiagnosticFailure(RuntimeError):
    pass


def _is_reparse(status: os.stat_result) -> bool:
    attributes = int(getattr(status, "st_file_attributes", 0))
    return stat.S_ISLNK(status.st_mode) or bool(attributes & _REPARSE_ATTRIBUTE)


def _fixed_global_paths(config: AppConfig) -> tuple[Path, Path] | None:
    """Resolve the one configured global DB/CAS scope without creating it."""

    global_root = config.vault_root / "global"
    database = global_root / "catalog.sqlite3"
    if not os.path.lexists(global_root):
        return None
    try:
        global_status = os.lstat(global_root)
    except OSError:
        raise _DiagnosticFailure from None
    if not stat.S_ISDIR(global_status.st_mode) or _is_reparse(global_status):
        raise _DiagnosticFailure
    if not os.path.lexists(database):
        return None
    try:
        database_status = os.lstat(database)
        vault = config.vault_root.resolve(strict=True)
        resolved_global = global_root.resolve(strict=True)
        resolved_database = database.resolve(strict=True)
    except OSError:
        raise _DiagnosticFailure from None
    if (
        not stat.S_ISREG(database_status.st_mode)
        or _is_reparse(database_status)
        or int(database_status.st_nlink) != 1
        or resolved_global.parent != vault
        or resolved_database.parent != resolved_global
    ):
        raise _DiagnosticFailure
    return resolved_database, resolved_global


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _readonly_sqlite(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{path.resolve(strict=True).as_uri()}?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
    )
    connection.execute("PRAGMA query_only = ON")
    return connection


def _json_object(value: object) -> dict[str, object]:
    if type(value) is not str:
        raise _DiagnosticFailure
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise _DiagnosticFailure from None
    if type(parsed) is not dict or any(type(key) is not str for key in parsed):
        raise _DiagnosticFailure
    return parsed


def _verify_lexical(binding: ArtifactBinding) -> None:
    manifest_path = binding.path_for("lexical_build_manifest")
    index_path = binding.path_for("lexical_index")
    try:
        manifest = LexicalBuildManifest.model_validate_json(
            manifest_path.read_bytes(),
            strict=True,
        )
    except Exception:
        raise _DiagnosticFailure from None
    if _sha256_file(index_path) != manifest.index_sha256:
        raise _DiagnosticFailure
    with closing(_readonly_sqlite(index_path)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise _DiagnosticFailure
        row = connection.execute(
            "SELECT value_json FROM lexical_metadata WHERE key = 'builder'"
        ).fetchone()
        if row is None or len(row) != 1:
            raise _DiagnosticFailure
        metadata = _json_object(row[0])
        if (
            set(metadata) != _LEXICAL_METADATA_KEYS
            or metadata.get("assigned_input_set_sha256")
            != manifest.assigned_input_set_sha256
            or metadata.get("builder_input_sha256")
            != manifest.builder_input_sha256
            or metadata.get("retrieval_input_descriptor_sha256")
            != manifest.retrieval_input_descriptor_sha256
            or metadata.get("row_mapping_sha256") != manifest.row_mapping_sha256
            or metadata.get("schema_version") != manifest.schema_version
            or metadata.get("source_catalog_version")
            != manifest.source_catalog_version
            or metadata.get("target_runtime_epoch")
            != manifest.target_runtime_epoch
            or metadata.get("tokenizer_descriptor_id")
            != manifest.tokenizer_descriptor_id
            or metadata.get("tokenizer_descriptor")
            != manifest.tokenizer_descriptor.model_dump(mode="json")
        ):
            raise _DiagnosticFailure
        document_rows = connection.execute(
            "SELECT row_sha256 FROM lexical_documents ORDER BY row_id"
        ).fetchall()
        if (
            len(document_rows) != manifest.row_count
            or tuple(sorted(str(row[0]) for row in document_rows))
            != manifest.row_content_hashes
        ):
            raise _DiagnosticFailure
        for table in ("lexical_word_fts", "lexical_char_fts"):
            count_row = connection.execute(f"SELECT count(*) FROM {table}").fetchone()
            if count_row != (manifest.row_count,):
                raise _DiagnosticFailure
            # A fixed no-hit MATCH exercises the FTS5 parser and virtual table even
            # when a future valid artifact contains zero rows.
            probe = connection.execute(
                f"SELECT count(*) FROM {table} WHERE {table} MATCH ?",
                ("consultation_doctor_probe_token",),
            ).fetchone()
            if probe is None or len(probe) != 1:
                raise _DiagnosticFailure
            token_row = connection.execute(
                f"SELECT tokens FROM {table} ORDER BY row_id LIMIT 1"
            ).fetchone()
            if token_row is None:
                continue
            if type(token_row[0]) is not str or not str(token_row[0]).split():
                raise _DiagnosticFailure
            token = str(token_row[0]).split()[0]
            hit = connection.execute(
                f"SELECT count(*) FROM {table} WHERE {table} MATCH ?",
                (token,),
            ).fetchone()
            if hit is None or int(hit[0]) <= 0:
                raise _DiagnosticFailure


def _verify_vector(binding: ArtifactBinding) -> None:
    manifest_path = binding.path_for("vector_build_manifest")
    vector_path = binding.path_for("vector_shard")
    metadata_path = binding.path_for("vector_metadata")
    try:
        manifest = VectorBuildManifest.model_validate_json(
            manifest_path.read_bytes(),
            strict=True,
        )
    except Exception:
        raise _DiagnosticFailure from None
    if (
        _sha256_file(vector_path) != manifest.vector_sha256
        or _sha256_file(metadata_path) != manifest.metadata_sha256
    ):
        raise _DiagnosticFailure
    with closing(_readonly_sqlite(metadata_path)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise _DiagnosticFailure
        descriptor_rows = connection.execute(
            "SELECT model_descriptor_id, descriptor_json, descriptor_sha256 "
            "FROM model_descriptors"
        ).fetchall()
        if len(descriptor_rows) != 1:
            raise _DiagnosticFailure
        descriptor_id, descriptor_json, descriptor_sha256 = descriptor_rows[0]
        try:
            descriptor = ModelDescriptor.model_validate_json(
                str(descriptor_json),
                strict=True,
            )
        except Exception:
            raise _DiagnosticFailure from None
        if (
            descriptor != manifest.model_descriptor
            or descriptor.id != manifest.model_descriptor_id
            or descriptor_id != descriptor.id
            or descriptor_sha256 != descriptor.id
        ):
            raise _DiagnosticFailure
        builder_row = connection.execute(
            "SELECT value_json FROM vector_metadata WHERE key = 'builder'"
        ).fetchone()
        if builder_row is None or len(builder_row) != 1:
            raise _DiagnosticFailure
        builder = _json_object(builder_row[0])
        if (
            set(builder) != _VECTOR_METADATA_KEYS
            or builder.get("assigned_input_set_sha256")
            != manifest.assigned_input_set_sha256
            or builder.get("builder_input_sha256")
            != manifest.builder_input_sha256
            or builder.get("model_descriptor_id") != descriptor.id
            or builder.get("retrieval_input_descriptor_sha256")
            != manifest.retrieval_input_descriptor_sha256
            or builder.get("row_mapping_sha256") != manifest.row_mapping_sha256
            or builder.get("schema_version") != manifest.schema_version
            or builder.get("shard_id") != manifest.shard_id
            or builder.get("source_catalog_version")
            != manifest.source_catalog_version
            or builder.get("target_runtime_epoch")
            != manifest.target_runtime_epoch
            or builder.get("vector_filename") != manifest.vector_filename
            or builder.get("vector_sha256") != manifest.vector_sha256
        ):
            raise _DiagnosticFailure
        rows = connection.execute(
            "SELECT row_index, row_sha256, model_descriptor_id, shard_id "
            "FROM vector_rows ORDER BY row_index"
        ).fetchall()
        if (
            len(rows) != manifest.row_count
            or tuple(int(row[0]) for row in rows)
            != tuple(range(manifest.row_count))
            or tuple(sorted(str(row[1]) for row in rows))
            != manifest.row_content_hashes
            or any(str(row[2]) != descriptor.id for row in rows)
            or any(str(row[3]) != manifest.shard_id for row in rows)
        ):
            raise _DiagnosticFailure

    matrix = np.load(vector_path, mmap_mode="r", allow_pickle=False)
    mmap = getattr(matrix, "_mmap", None)
    try:
        if (
            not isinstance(matrix, np.memmap)
            or mmap is None
            or matrix.dtype != np.float32
            or matrix.shape != (manifest.row_count, descriptor.dimension)
            or not np.isfinite(matrix).all()
        ):
            raise _DiagnosticFailure
        norms = np.linalg.norm(matrix, axis=1)
        if np.any(norms == 0.0) or (
            descriptor.normalize_embeddings
            and not np.allclose(norms, np.ones_like(norms), atol=1e-5)
        ):
            raise _DiagnosticFailure
    finally:
        if mmap is not None:
            mmap.close()
    if mmap is None or not mmap.closed:
        raise _DiagnosticFailure


class RetrievalArtifactDiagnosticProbe:
    """Read-only validation of the sole active five-root global closure."""

    name = "retrieval_artifacts"

    def run(self, config: AppConfig) -> DoctorCheck:
        if type(config) is not AppConfig:
            raise TypeError("RETRIEVAL_DIAGNOSTIC_CONFIG_REQUIRED")
        try:
            fixed = _fixed_global_paths(config)
            if fixed is None:
                return DoctorCheck(
                    status="pass",
                    code="retrieval_artifacts_not_applicable",
                    observed_count=0,
                )
            database, global_root = fixed
            with closing(connect_database(database, mode="reader")) as connection:
                current = ActiveRetrievalArtifactDiscovery(
                    connection,
                    ContentStore(global_root),
                ).discover_current_set()
                if current is None:
                    return DoctorCheck(
                        status="pass",
                        code="retrieval_artifacts_not_applicable",
                        observed_count=0,
                    )
                bindings = current.bindings()
                if len(bindings) != 5:
                    raise _DiagnosticFailure
                for binding in bindings:
                    binding.verify_current()
                _verify_lexical(current.lexical)
                _verify_vector(current.vector)
                for binding in bindings:
                    binding.verify_current()
        except Exception:
            return DoctorCheck(status="fail", code="retrieval_artifacts_invalid")
        return DoctorCheck(
            status="pass",
            code="retrieval_artifacts_verified",
            observed_count=5,
        )


_LifecycleScope = Literal["global", "client"]


@dataclass(frozen=True, slots=True)
class _LifecycleDatabase:
    scope: _LifecycleScope
    database: Path
    content_root: Path
    client_id: str | None = None


def _fixed_lifecycle_databases(
    config: AppConfig,
) -> tuple[_LifecycleDatabase, ...]:
    """Return only the global lifecycle database for control-plane probes.

    A global Doctor invocation must not use the client catalog as a directory
    oracle and then open every private client database.  Client lifecycle
    verification is deliberately exposed only by the already-bound scoped
    worker, where the caller has a session handle and no path/client selector.
    """

    fixed = _fixed_global_paths(config)
    if fixed is None:
        return ()
    global_database, global_root = fixed
    return (
        _LifecycleDatabase(
            scope="global",
            database=global_database,
            content_root=global_root,
        ),
    )


def _required_tables(
    connection: sqlite3.Connection,
    names: frozenset[str],
) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    if not names <= {str(row[0]) for row in rows}:
        raise _DiagnosticFailure


def _verify_active_publication_binding(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
) -> None:
    row = connection.execute(
        "SELECT purpose, authority_base_version, expected_current_epoch, "
        "required_manifest_count, verified_manifest_count "
        "FROM publication_operations WHERE operation_id = ? AND state = 'ACTIVE'",
        (operation_id,),
    ).fetchone()
    if row is None:
        raise _DiagnosticFailure
    purpose = str(row[0])
    manifests = ManifestRepository(connection).list_for_operation(operation_id)
    if (
        int(row[3]) != len(manifests)
        or int(row[4]) != len(manifests)
        or any(manifest.state != "ACTIVE" or not manifest.verified for manifest in manifests)
    ):
        raise _DiagnosticFailure
    if purpose == "rebuild":
        binding = connection.execute(
            "SELECT b.plan_sha256, b.scope_sha256, b.tombstone_epoch, j.state "
            "FROM rebuild_stage_bindings AS b "
            "JOIN rebuild_jobs AS j ON j.job_id = b.job_id "
            "WHERE b.operation_id = ?",
            (operation_id,),
        ).fetchone()
        if binding is None or str(binding[3]) not in {"activating", "succeeded"}:
            raise _DiagnosticFailure
        return
    attestation = connection.execute(
        "SELECT approval_draft_sha256, closure_sha256 "
        "FROM publication_closure_attestations WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    execution = connection.execute(
        "SELECT draft_sha256, state FROM approval_executions "
        "WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    if (
        attestation is None
        or execution is None
        or execution[1] != "APPLIED"
        or str(attestation[0]) != str(execution[0])
    ):
        raise _DiagnosticFailure
    closure = publication_closure_sha256(
        purpose=purpose,
        authority_base_version=int(row[1]),
        expected_current_epoch=(None if row[2] is None else int(row[2])),
        artifacts=manifests,
    )
    if str(attestation[1]) != closure:
        raise _DiagnosticFailure


def _verify_active_scope(
    database: _LifecycleDatabase,
    connection: sqlite3.Connection,
) -> int:
    epoch_rows = connection.execute(
        "SELECT epoch, operation_id FROM runtime_epochs "
        "WHERE state = 'ACTIVE' ORDER BY epoch"
    ).fetchall()
    if not epoch_rows:
        if connection.execute("SELECT count(*) FROM active_artifacts").fetchone() != (
            0,
        ):
            raise _DiagnosticFailure
        return 0
    if len(epoch_rows) != 1:
        raise _DiagnosticFailure
    epoch, operation_id = int(epoch_rows[0][0]), str(epoch_rows[0][1])
    rows = connection.execute(
        "SELECT artifact_key, manifest_id FROM active_artifacts "
        "WHERE epoch = ? ORDER BY artifact_key",
        (epoch,),
    ).fetchall()
    if not rows:
        raise _DiagnosticFailure
    repository = ManifestRepository(connection)
    artifacts: list[ActiveArtifact] = []
    source_versions: set[int] = set()
    for artifact_key, manifest_id in rows:
        manifest = repository.get(str(manifest_id))
        source_versions.add(manifest.source_version)
        artifacts.append(
            ActiveArtifact(
                artifact_key=str(artifact_key),
                manifest_ref=VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                ),
            )
        )
    if len(source_versions) != 1:
        raise _DiagnosticFailure
    _verify_active_publication_binding(connection, operation_id=operation_id)
    if database.scope == "global":
        authority = connection.execute(
            "SELECT catalog_version, authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if authority is None:
            raise _DiagnosticFailure
        gate = ActiveIntegrityGate(
            IntegrityStore(
                scope="global",
                connection=connection,
                content_store=ContentStore(database.content_root),
            )
        )
        gate.verify(
            epoch=epoch,
            artifacts=tuple(artifacts),
            source_version=next(iter(source_versions)),
            authority_version=int(authority[0]),
            tombstone_epoch=int(authority[2]),
            authorization_epoch=int(authority[1]),
        )
        return len(artifacts)
    fact_authority = connection.execute(
        "SELECT commit_version, client_id FROM client_fact_authority "
        "WHERE singleton = 1"
    ).fetchone()
    tombstone_count = connection.execute("SELECT count(*) FROM tombstones").fetchone()
    if (
        fact_authority is None
        or tombstone_count is None
        or fact_authority[1] != database.client_id
    ):
        raise _DiagnosticFailure
    gate = ActiveIntegrityGate(
        IntegrityStore(
            scope="client_private",
            connection=connection,
            content_store=ContentStore(database.content_root),
            client_id=database.client_id,
        )
    )
    gate.verify(
        epoch=epoch,
        artifacts=tuple(artifacts),
        source_version=next(iter(source_versions)),
        tombstone_epoch=int(tombstone_count[0]),
    )
    return len(artifacts)


class _LifecycleDiagnosticProbe:
    name: str

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        raise NotImplementedError

    def run(self, config: AppConfig) -> DoctorCheck:
        if type(config) is not AppConfig:
            raise TypeError("LIFECYCLE_DIAGNOSTIC_CONFIG_REQUIRED")
        try:
            databases = _fixed_lifecycle_databases(config)
            if not databases:
                return DoctorCheck(
                    status="pass",
                    code=f"{self.name}_not_applicable",
                    observed_count=0,
                )
            observed = 0
            for database in databases:
                with closing(
                    connect_database(database.database, mode="reader")
                ) as connection:
                    observed += self._run_one(database, connection)
        except Exception:
            return DoctorCheck(status="fail", code=f"{self.name}_invalid")
        return DoctorCheck(
            status="pass",
            code=f"{self.name}_verified",
            observed_count=observed,
        )


def _verified_operation_manifests(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
) -> tuple[ArtifactManifest, ...]:
    row = connection.execute(
        "SELECT purpose, authority_base_version, approval_request_id, "
        "descriptor_sha256, required_manifests_json, "
        "required_manifest_count, verified_manifest_count, "
        "expected_current_epoch, runtime_epoch, activated_at "
        "FROM publication_operations "
        "WHERE operation_id = ? AND state = 'VERIFIED'",
        (operation_id,),
    ).fetchone()
    if row is None:
        raise _DiagnosticFailure
    try:
        required = json.loads(str(row[4]))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise _DiagnosticFailure from None
    repository = ManifestRepository(connection)
    manifests = repository.list_for_operation(operation_id)
    if (
        str(row[0]) != "case_publish"
        or type(row[1]) is not int
        or type(row[2]) is not str
        or not str(row[2])
        or type(row[3]) is not str
        or len(str(row[3])) != 64
        or type(required) is not list
        or required != [manifest.manifest_id for manifest in manifests]
        or len(manifests) != 1
        or int(row[5]) != 1
        or int(row[6]) != 1
        or row[8] is not None
        or row[9] is not None
        or any(
            manifest.state != "VERIFIED"
            or not manifest.verified
            or manifest.source_version != int(row[1])
            for manifest in manifests
        )
    ):
        raise _DiagnosticFailure
    attestation = connection.execute(
        "SELECT approval_draft_sha256, closure_sha256 "
        "FROM publication_closure_attestations WHERE operation_id = ?",
        (operation_id,),
    ).fetchall()
    closure = publication_closure_sha256(
        purpose="case_publish",
        authority_base_version=int(row[1]),
        expected_current_epoch=(None if row[7] is None else int(row[7])),
        artifacts=manifests,
    )
    if (
        len(attestation) != 1
        or type(attestation[0][0]) is not str
        or len(str(attestation[0][0])) != 64
        or str(attestation[0][1]) != closure
    ):
        raise _DiagnosticFailure
    active_count = connection.execute(
        "SELECT COUNT(*) FROM active_artifacts "
        "WHERE manifest_id = ?",
        (manifests[0].manifest_id,),
    ).fetchone()
    if active_count != (0,):
        raise _DiagnosticFailure
    return manifests


def _read_verified_manifest_members(
    database: _LifecycleDatabase,
    manifest: ArtifactManifest,
) -> dict[str, bytes]:
    store = ContentStore(database.content_root)
    payloads: dict[str, bytes] = {}
    for member in manifest.members:
        if member.object_id in payloads:
            raise _DiagnosticFailure
        try:
            payloads[member.object_id] = store.read_verified(
                store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
            )
        except Exception:
            raise _DiagnosticFailure from None
    return payloads


def _verify_shared_case_ledger(
    database: _LifecycleDatabase,
    connection: sqlite3.Connection,
    manifest: ArtifactManifest,
) -> None:
    if manifest.artifact_kind != "shared_case" or len(manifest.members) != 1:
        raise _DiagnosticFailure
    member = manifest.members[0]
    if member.object_type != "case":
        raise _DiagnosticFailure
    rows = connection.execute(
        "SELECT cases.case_id, cases.state, cases.current_version, "
        "version.version, version.global_content_sha256, "
        "version.global_content_media_type, version.global_content_size_bytes, "
        "version.provenance_id, version.provenance_version, version.state, "
        "version.activated_at, version.revoked_at, "
        "version.release_decision_sha256, version.allowed_uses_json, "
        "provenance.closure_json, provenance.closure_sha256, "
        "provenance.artifact_object_id, provenance.artifact_version, "
        "provenance.artifact_sha256, provenance.artifact_kind, "
        "provenance.allowed_uses_json, authorization.allowed_uses_json, "
        "review.decision, review.release_decision_sha256, "
        "review.allowed_uses_json, saga.state, saga.case_id, saga.case_version, "
        "saga.manifest_id, saga.provenance_id, saga.provenance_version, "
        "saga.global_content_sha256, saga.global_content_media_type, "
        "saga.global_content_size_bytes, saga.published_global_version "
        "FROM case_versions AS version "
        "JOIN cases ON cases.case_id = version.case_id "
        "AND cases.current_version = version.version "
        "JOIN case_provenance AS provenance "
        "ON provenance.provenance_id = version.provenance_id "
        "AND provenance.provenance_version = version.provenance_version "
        "JOIN case_authorizations AS authorization "
        "ON authorization.case_id = version.case_id "
        "AND authorization.case_version = version.version "
        "JOIN case_review_decisions AS review "
        "ON review.case_id = version.case_id "
        "AND review.case_version = version.version "
        "JOIN global_publish_sagas AS saga "
        "ON saga.publication_operation_id = ? "
        "WHERE version.manifest_id = ?",
        (manifest.operation_id, manifest.manifest_id),
    ).fetchall()
    if len(rows) != 1:
        raise _DiagnosticFailure
    row = rows[0]
    state_pair = (str(row[1]), str(row[9]))
    if state_pair not in {("ACTIVE", "ACTIVE"), ("REVOKED", "REVOKED")}:
        raise _DiagnosticFailure
    if (
        str(row[0]) != member.object_id
        or int(row[2]) != member.source_version
        or int(row[3]) != member.source_version
        or str(row[4]) != member.object_sha256
        or str(row[5]) != member.media_type
        or int(row[6]) != member.size_bytes
        or str(row[16]) != member.object_id
        or int(row[17]) != member.source_version
        or str(row[18]) != member.object_sha256
        or str(row[19]) != "case"
        or str(row[13]) != str(row[20])
        or str(row[13]) != str(row[21])
        or str(row[13]) != str(row[24])
        or str(row[22]) != "approved"
        or str(row[12]) != str(row[23])
        or str(row[25]) != "ACTIVE"
        or str(row[26]) != member.object_id
        or int(row[27]) != member.source_version
        or str(row[28]) != manifest.manifest_id
        or str(row[29]) != str(row[7])
        or int(row[30]) != int(row[8])
        or str(row[31]) != member.object_sha256
        or str(row[32]) != member.media_type
        or int(row[33]) != member.size_bytes
        or int(row[34]) != member.source_version
        or row[10] is None
        or (state_pair == ("ACTIVE", "ACTIVE") and row[11] is not None)
        or (state_pair == ("REVOKED", "REVOKED") and row[11] is None)
    ):
        raise _DiagnosticFailure
    try:
        provenance = CaseProvenanceRecord.model_validate_json(
            str(row[14]), strict=True
        )
    except ValueError:
        raise _DiagnosticFailure from None
    if (
        provenance.provenance_ref.object_id != str(row[7])
        or provenance.provenance_ref.version != int(row[8])
        or provenance.closure_sha256 != str(row[15])
        or provenance.artifact_ref
        != VersionRef(
            object_id=member.object_id,
            version=member.source_version,
            content_sha256=member.object_sha256,
        )
        or canonical_json_bytes(provenance.model_dump(mode="json")).decode(
            "ascii"
        )
        != str(row[14])
    ):
        raise _DiagnosticFailure
    _read_verified_manifest_members(database, manifest)


def _verify_invalidated_case_index_ledger(
    database: _LifecycleDatabase,
    connection: sqlite3.Connection,
    manifest: ArtifactManifest,
) -> None:
    payloads = _read_verified_manifest_members(database, manifest)
    descriptor_members = tuple(
        member
        for member in manifest.members
        if member.object_type == "case_index_descriptor"
    )
    if len(descriptor_members) != 1:
        raise _DiagnosticFailure
    try:
        descriptor = CaseIndexReplayDescriptor.model_validate_json(
            payloads[descriptor_members[0].object_id], strict=True
        )
    except ValueError:
        raise _DiagnosticFailure from None
    if (
        descriptor.manifest_id != manifest.manifest_id
        or descriptor.artifact_key != manifest.artifact_key
    ):
        raise _DiagnosticFailure
    for replay in descriptor.artifacts:
        rows = connection.execute(
            "SELECT closure_json FROM case_provenance "
            "WHERE provenance_id = ? AND provenance_version = ?",
            (
                replay.provenance_ref.object_id,
                replay.provenance_ref.version,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise _DiagnosticFailure
        try:
            provenance = CaseProvenanceRecord.model_validate_json(
                str(rows[0][0]), strict=True
            )
        except ValueError:
            raise _DiagnosticFailure from None
        if (
            provenance.provenance_ref != replay.provenance_ref
            or provenance.artifact_ref != replay.artifact_ref
            or provenance.artifact_kind != replay.artifact_kind
        ):
            raise _DiagnosticFailure
    if CaseIndexInvalidationDiagnosticProbe()._run_one(database, connection) <= 0:
        raise _DiagnosticFailure


def _verify_case_index_ledger(
    database: _LifecycleDatabase,
    connection: sqlite3.Connection,
    manifest: ArtifactManifest,
) -> None:
    if manifest.artifact_kind != "case_index":
        raise _DiagnosticFailure
    rows = connection.execute(
        "SELECT pattern.state, queue.catalog_version, "
        "queue.required_outputs_json, queue.reason, queue.state, "
        "COUNT(invalidation.queue_id) "
        "FROM case_patterns AS pattern "
        "JOIN rebuild_queue AS queue "
        "ON queue.upstream_type = 'case_index' "
        "AND queue.upstream_id = pattern.manifest_id "
        "LEFT JOIN case_index_rebuild_invalidations AS invalidation "
        "ON invalidation.queue_id = queue.queue_id "
        "WHERE pattern.manifest_id = ? "
        "GROUP BY pattern.pattern_id, pattern.version, queue.queue_id",
        (manifest.manifest_id,),
    ).fetchall()
    if len(rows) != 1:
        raise _DiagnosticFailure
    row = rows[0]
    pattern_state = str(row[0])
    queue_state = str(row[4])
    invalidations = int(row[5])
    if (
        int(row[1]) != manifest.source_version
        or str(row[2]) != '["bm25","graph","vector","wiki"]'
        or str(row[3]) != "case_index_authority_published"
    ):
        raise _DiagnosticFailure
    if pattern_state in {"PREPARED", "ACTIVE"}:
        if (
            invalidations != 0
            or (
                pattern_state == "PREPARED"
                and queue_state not in {"PENDING", "CLAIMED"}
            )
            or (pattern_state == "ACTIVE" and queue_state != "COMPLETED")
        ):
            raise _DiagnosticFailure
        CaseIndexPublicationRepository(
            connection,
            ContentStore(database.content_root),
        ).replay_manifest(
            VersionRef(
                object_id=manifest.manifest_id,
                version=manifest.source_version,
                content_sha256=manifest.manifest_sha256,
            )
        )
        return
    if (
        pattern_state != "REVOKED"
        or queue_state not in {"PENDING", "CLAIMED"}
        or invalidations != 1
    ):
        raise _DiagnosticFailure
    _verify_invalidated_case_index_ledger(database, connection, manifest)


def _verified_nonruntime_ledger(
    database: _LifecycleDatabase,
    connection: sqlite3.Connection,
    *,
    operation_id: str,
) -> None:
    manifests = _verified_operation_manifests(
        connection,
        operation_id=operation_id,
    )
    manifest = manifests[0]
    if manifest.artifact_kind == "shared_case":
        _verify_shared_case_ledger(database, connection, manifest)
        return
    if manifest.artifact_kind == "case_index":
        _verify_case_index_ledger(database, connection, manifest)
        return
    raise _DiagnosticFailure


class RecoveryPendingDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Fail when a crash-recoverable publication/outbox claim is unresolved."""

    name = "recovery_pending"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        rows = connection.execute(
            "SELECT operation_id, state FROM publication_operations "
            "WHERE state IN ('PREPARED', 'VERIFIED') "
            "ORDER BY operation_id"
        ).fetchall()
        for operation_id, state in rows:
            if str(state) != "VERIFIED" or database.scope != "global":
                raise _DiagnosticFailure
            _verified_nonruntime_ledger(
                database,
                connection,
                operation_id=str(operation_id),
            )
        pending = 0
        if database.scope == "client":
            pending += int(
                connection.execute(
                    "SELECT count(*) FROM outbox_events "
                    "WHERE state IN ('CLAIMED', 'FAILED')"
                ).fetchone()[0]
            )
        if pending:
            raise _DiagnosticFailure
        return 0


class ActiveClosureDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Verify active manifests, CAS bytes, epochs, and approval closure."""

    name = "active_closure"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        return _verify_active_scope(database, connection)


class TombstoneEpochDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Verify monotonic deletion authority and the global epoch mirror."""

    name = "tombstone_epoch"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        row = connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        latest = connection.execute(
            "SELECT COALESCE(MAX(tombstone_epoch), 0) FROM deletion_requests"
        ).fetchone()
        if (
            row is None
            or latest is None
            or type(row[0]) is not int
            or type(row[1]) is not int
            or int(row[0]) < 0
            or int(row[1]) < int(latest[0])
        ):
            raise _DiagnosticFailure
        if database.scope == "global":
            mirrored = connection.execute(
                "SELECT tombstone_epoch FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
            if mirrored != (int(row[1]),):
                raise _DiagnosticFailure
        return int(row[1])


class CleanupQueueDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Re-attest every durable cleanup intent without resolving a path."""

    name = "cleanup_queue"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        _required_tables(
            connection,
            frozenset(
                {
                    "deletion_queue_intents",
                    "deletion_intent_authority_proofs",
                }
            ),
        )
        rows = connection.execute(
            "SELECT intent_id, action_type, state FROM deletion_queue_intents "
            "ORDER BY intent_id"
        ).fetchall()
        resolver = CleanupAuthorityResolver(
            connection,
            authority_scope=database.scope,
        )
        pending = 0
        for intent_id, action_type, state in rows:
            if str(state) == "FAILED":
                raise _DiagnosticFailure
            resolver.resolve(
                str(intent_id),
                expected_action_type=str(action_type),  # type: ignore[arg-type]
            )
            if str(state) in {"PENDING", "CLAIMED"}:
                pending += 1
        return pending


class BackupQueueDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Verify the body-free backup queue and surface outstanding records."""

    name = "backup_queue"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        _required_tables(
            connection,
            frozenset(
                {
                    "backup_destruction_queue",
                    "backup_destruction_objects",
                }
            ),
        )
        rows = connection.execute(
            "SELECT backup_id, state FROM backup_destruction_queue "
            "ORDER BY backup_id"
        ).fetchall()
        queue = BackupDestructionQueue(connection)
        pending = 0
        for backup_id, state in rows:
            queue.get(str(backup_id))
            if str(state) == "failed":
                raise _DiagnosticFailure
            if str(state) == "pending":
                pending += 1
        return pending


class CaseIndexInvalidationDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Verify and count case-index intents cancelled by governed security writes."""

    name = "case_index_invalidations"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        if database.scope != "global":
            return 0
        _required_tables(
            connection,
            frozenset(
                {
                    "case_index_rebuild_invalidations",
                    "case_patterns",
                    "rebuild_queue",
                }
            ),
        )
        total = int(
            connection.execute(
                "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT invalidation.authority_request_id, "
            "invalidation.invalidation_set_sha256, "
            "invalidation.base_catalog_version, "
            "invalidation.target_catalog_version, "
            "invalidation.prior_authorization_epoch, "
            "invalidation.authorization_epoch, "
            "invalidation.prior_tombstone_epoch, invalidation.tombstone_epoch, "
            "manifest.manifest_id, manifest.source_version, "
            "manifest.manifest_sha256, operation.operation_id, "
            "operation.descriptor_sha256, pattern.pattern_id, pattern.version, "
            "queue.queue_id, queue.catalog_version, queue.state, pattern.state, "
            "manifest.artifact_kind, manifest.state, manifest.verified, "
            "operation.state, operation.runtime_epoch, "
            "operation.authority_base_version "
            "FROM case_index_rebuild_invalidations AS invalidation "
            "JOIN rebuild_queue AS queue ON queue.queue_id = invalidation.queue_id "
            "JOIN case_patterns AS pattern "
            "  ON pattern.manifest_id = queue.upstream_id "
            "JOIN artifact_manifests AS manifest "
            "  ON manifest.manifest_id = queue.upstream_id "
            "JOIN publication_operations AS operation "
            "  ON operation.operation_id = manifest.operation_id "
            "WHERE queue.upstream_type = 'case_index' "
            "ORDER BY invalidation.authority_request_id, "
            "invalidation.invalidation_set_sha256, manifest.manifest_id"
        ).fetchall()
        if len(rows) != total:
            raise _DiagnosticFailure
        grouped: dict[
            tuple[str, str, int, int, int, int, int, int],
            list[CaseIndexRebuildIdentity],
        ] = {}
        for row in rows:
            key = (
                str(row[0]),
                str(row[1]),
                int(row[2]),
                int(row[3]),
                int(row[4]),
                int(row[5]),
                int(row[6]),
                int(row[7]),
            )
            if (
                not key[0]
                or key[3] != key[2] + 1
                or key[5] < key[4]
                or key[7] < key[6]
                or (key[5] == key[4] and key[7] == key[6])
                or int(row[9]) != key[3]
                or int(row[16]) != key[3]
                or str(row[17]) not in {"PENDING", "CLAIMED"}
                or str(row[18]) != "REVOKED"
                or str(row[19]) != "case_index"
                or str(row[20]) != "VERIFIED"
                or int(row[21]) != 1
                or str(row[22]) != "VERIFIED"
                or row[23] is not None
                or int(row[24]) != key[3]
            ):
                raise _DiagnosticFailure
            grouped.setdefault(key, []).append(
                CaseIndexRebuildIdentity(
                    manifest_ref=VersionRef(
                        object_id=str(row[8]),
                        version=int(row[9]),
                        content_sha256=str(row[10]),
                    ),
                    operation_id=str(row[11]),
                    approval_descriptor_sha256=str(row[12]),
                    pattern_id=str(row[13]),
                    pattern_version=int(row[14]),
                    queue_id=str(row[15]),
                    target_catalog_version=int(row[16]),
                )
            )
        for key, identities in grouped.items():
            snapshot = CaseIndexRebuildSnapshot(
                target_catalog_version=key[3],
                identities=tuple(identities),
            )
            if snapshot.identity_sha256 != key[1]:
                raise _DiagnosticFailure
        return total


class WalCheckpointDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Require each scoped SQLite WAL to be fully checkpointable now."""

    name = "wal_checkpoint"

    def run(self, config: AppConfig) -> DoctorCheck:
        if type(config) is not AppConfig:
            raise TypeError("LIFECYCLE_DIAGNOSTIC_CONFIG_REQUIRED")
        try:
            databases = _fixed_lifecycle_databases(config)
            if not databases:
                return DoctorCheck(
                    status="pass",
                    code="wal_checkpoint_not_applicable",
                    observed_count=0,
                )
            for database in databases:
                with closing(
                    sqlite3.connect(database.database, isolation_level=None)
                ) as connection:
                    connection.execute("PRAGMA busy_timeout = 0")
                    row = connection.execute(
                        "PRAGMA wal_checkpoint(PASSIVE)"
                    ).fetchone()
                    if (
                        row is None
                        or len(row) != 3
                        or int(row[0]) != 0
                        or (int(row[1]) >= 0 and int(row[1]) != int(row[2]))
                    ):
                        raise _DiagnosticFailure
        except Exception:
            return DoctorCheck(status="fail", code="wal_checkpoint_invalid")
        return DoctorCheck(
            status="pass",
            code="wal_checkpoint_verified",
            observed_count=len(databases),
        )


class RebuildCapabilityDiagnosticProbe(_LifecycleDiagnosticProbe):
    """Verify the registered rebuild DAG and durable job schema are usable."""

    name = "rebuild_capability"

    def _run_one(
        self,
        database: _LifecycleDatabase,
        connection: sqlite3.Connection,
    ) -> int:
        _required_tables(
            connection,
            frozenset(
                {
                    "rebuild_jobs",
                    "rebuild_job_journal",
                    "rebuild_stage_bindings",
                }
            ),
        )
        if database.scope != "global":
            raise _DiagnosticFailure
        scope_sha256 = global_approval_scope_sha256(
            database.content_root.parent
        )
        production = load_production_rebuild_config(
            database.content_root,
            database_scope=database.scope,
            scope_sha256=scope_sha256,
        )
        registry = BuilderRegistry.production()
        plan = registry.plan(database_scope=database.scope, purpose="all")
        registry.validate_bindings(
            database_scope=database.scope,
            purpose="all",
            policy_sha256=production.policy_sha256,
            model_descriptor_sha256=production.model_descriptor_sha256,
        )
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if any(
            source.table not in tables
            for descriptor in plan
            for source in descriptor.authority_sources
        ):
            raise _DiagnosticFailure
        failed = connection.execute(
            "SELECT count(*) FROM rebuild_jobs WHERE state = 'failed'"
        ).fetchone()
        if failed is None or int(failed[0]) != 0:
            raise _DiagnosticFailure
        return len(plan)


def lifecycle_diagnostic_probes() -> tuple[DiagnosticProbe, ...]:
    """Return the complete P8 probe set for CLI/MCP composition roots."""

    return (
        RecoveryPendingDiagnosticProbe(),
        ActiveClosureDiagnosticProbe(),
        TombstoneEpochDiagnosticProbe(),
        CleanupQueueDiagnosticProbe(),
        BackupQueueDiagnosticProbe(),
        CaseIndexInvalidationDiagnosticProbe(),
        WalCheckpointDiagnosticProbe(),
        RebuildCapabilityDiagnosticProbe(),
    )


__all__ = [
    "ActiveClosureDiagnosticProbe",
    "BackupQueueDiagnosticProbe",
    "CaseIndexInvalidationDiagnosticProbe",
    "CleanupQueueDiagnosticProbe",
    "RebuildCapabilityDiagnosticProbe",
    "RecoveryPendingDiagnosticProbe",
    "RetrievalArtifactDiagnosticProbe",
    "TombstoneEpochDiagnosticProbe",
    "WalCheckpointDiagnosticProbe",
    "lifecycle_diagnostic_probes",
]
