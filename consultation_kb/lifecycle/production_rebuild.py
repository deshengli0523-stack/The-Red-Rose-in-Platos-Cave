"""Restart-stable production composition for durable rebuild jobs.

The lifecycle coordinator is deliberately generic.  This module binds its
declarations to the same concrete P4 builders used by normal publication and
to the client bitemporal/profile/graph materializers.  Configuration is an
immutable, checksum-bound file under the already-scoped vault root; there is
no model, tokenizer, Graphify, or path fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

import numpy as np
from numpy.typing import NDArray
from pydantic import field_validator, model_validator

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationError,
    CaseIndexPublicationRepository,
    CaseIndexRebuildSnapshot,
)
from consultation_kb.archive.case_indexing import CaseIndexingError
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.graph_serialization import (
    canonical_graph_bytes as canonical_client_graph_bytes,
    graph_payload as client_graph_payload,
)
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.client.temporal_graph import TemporalGraphBuilder
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.graph.graphify_adapter import GraphifyProjectionAdapter
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.knowledge.approval import GovernedWriteExecutor
from consultation_kb.knowledge.claims import ClaimProposalService
from consultation_kb.knowledge.passages import PassageCatalog
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import WikiClaimAuthority, WikiRevisionService
from consultation_kb.lifecycle.publish import ArtifactDraft, ContentDraft
from consultation_kb.lifecycle.rebuild import (
    EMPTY_CASE_INDEX_INTENT_SET_SHA256,
    ArtifactBuilder,
    AuthorityRecord,
    BuildContext,
    BuiltArtifact,
    RebuildCoordinator,
    RebuildCoordinatorError,
    SqliteCasRebuildArtifactStore,
    SqliteRebuildAuthoritySource,
    rebuild_manifest_id,
    rebuild_job_plan_sha256,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.lifecycle.rebuild_registry import (
    PRODUCTION_IMPLEMENTATION_REVISIONS,
    BuilderDescriptor,
    BuilderRegistry,
    DatabaseScope,
)
from consultation_kb.lifecycle.structured_artifact import (
    StructuredArtifactEnvelope,
    StructuredArtifactMember,
)
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.dependencies import DependencyEdge, DependencyType
from consultation_kb.models.evidence import EvidenceLocator
from consultation_kb.models.facts import FactEvent
from consultation_kb.publication.global_knowledge import (
    GlobalKnowledgePublicationPlanner,
    GlobalPublicationBuilders,
    GlobalPublicationPlanningError,
)
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.authority_descriptor import (
    canonical_retrieval_route_policy_bytes,
)
from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    Embedder,
    ModelDescriptor,
)
from consultation_kb.retrieval.filters import assert_case_index_text_safe
from consultation_kb.retrieval.lexical_builder import LexicalIndexBuilder
from consultation_kb.retrieval.model_adapters import SentenceTransformersEmbedder
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexBuilder
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import ObjectIdentity, lineage_hash
from consultation_kb.vault.content_store import ContentStore


CONFIG_FILENAME = "rebuild-production.json"
ALGORITHM_REVISION: Literal["production_rebuild.v1"] = "production_rebuild.v1"
CLIENT_POLICY_SHA256 = canonical_sha256(
    {
        "domain": "consultation_kb.client_rebuild_policy.v1",
        "fact_snapshot": "approved_bitemporal_exact_boundary",
        "profile": "remove_resolved_invalid_duplicate",
        "graph": TemporalGraphBuilder.POLICY_VERSION,
        "private_archive": "exact_approved_replay",
    }
)


class ProductionRebuildError(RebuildCoordinatorError):
    """Fixed-code production composition failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CaseContributorAliasBinding(StrictModel):
    """Persist the exact non-reversible alias used by case retrieval filters."""

    contributor_client_hash: Sha256Hex
    pseudonymous_client_id: ClientId


def _safe_relative(value: str) -> str:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or ":" in normalized
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("production rebuild path must be scoped and relative")
    return normalized


class ProductionRebuildConfig(StrictModel):
    """Checksum-bound configuration reconstructed after process restart."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_revision: Literal["production_rebuild.v1"] = ALGORITHM_REVISION
    database_scope: DatabaseScope
    scope_sha256: Sha256Hex
    policy_sha256: Sha256Hex
    cas_directory: NonEmptyStr
    build_directory: NonEmptyStr
    target_wiki_id: NonEmptyStr | None = None
    graphify_seed: int = 42
    graphify_production: bool = True
    lexical_tokenizer_descriptor_sha256: Sha256Hex | None = None
    wiki_tokenizer_descriptor_sha256: Sha256Hex | None = None
    embedder_kind: Literal[
        "none", "sentence_transformers", "deterministic_test"
    ] = "none"
    test_mode: bool = False
    model_directory: NonEmptyStr | None = None
    model_descriptor: ModelDescriptor | None = None
    model_descriptor_sha256: Sha256Hex | None = None
    deterministic_vocabulary: dict[NonEmptyStr, tuple[float, ...]] | None = None
    case_contributor_aliases: tuple[CaseContributorAliasBinding, ...] = ()
    config_sha256: Sha256Hex

    @field_validator("cas_directory", "build_directory")
    @classmethod
    def _relative_directories(cls, value: str) -> str:
        return _safe_relative(value)

    @field_validator("model_directory")
    @classmethod
    def _relative_model_directory(cls, value: str | None) -> str | None:
        return None if value is None else _safe_relative(value)

    @field_validator("graphify_seed")
    @classmethod
    def _bounded_seed(cls, value: int) -> int:
        if type(value) is not int or not 0 <= value <= (2**63 - 1):
            raise ValueError("Graphify seed is outside the fixed range")
        return value

    @field_validator("case_contributor_aliases")
    @classmethod
    def _canonical_case_aliases(
        cls,
        value: tuple[CaseContributorAliasBinding, ...],
    ) -> tuple[CaseContributorAliasBinding, ...]:
        keys = tuple(item.contributor_client_hash for item in value)
        aliases = tuple(item.pseudonymous_client_id for item in value)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("case contributor alias hashes must be sorted and unique")
        if len(aliases) != len(set(aliases)):
            raise ValueError("case contributor aliases must be unique")
        return value

    @model_validator(mode="after")
    def _closed_configuration(self) -> "ProductionRebuildConfig":
        if self.database_scope == "global":
            if (
                self.policy_sha256
                != hashlib.sha256(
                    canonical_retrieval_route_policy_bytes()
                ).hexdigest()
                or self.lexical_tokenizer_descriptor_sha256 is None
                or self.wiki_tokenizer_descriptor_sha256 is None
                or self.model_descriptor is None
                or self.model_descriptor_sha256 != self.model_descriptor.id
                or self.embedder_kind == "none"
            ):
                raise ValueError("global production rebuild bindings are incomplete")
            if self.embedder_kind == "sentence_transformers":
                if (
                    self.model_directory is None
                    or self.deterministic_vocabulary is not None
                    or self.test_mode
                ):
                    raise ValueError("local model configuration is incomplete")
            elif (
                not self.test_mode
                or self.model_directory is not None
                or not self.deterministic_vocabulary
            ):
                raise ValueError("deterministic embedder is test-only and explicit")
        elif (
            self.policy_sha256 != CLIENT_POLICY_SHA256
            or self.target_wiki_id is not None
            or self.lexical_tokenizer_descriptor_sha256 is not None
            or self.wiki_tokenizer_descriptor_sha256 is not None
            or self.embedder_kind != "none"
            or self.test_mode
            or self.model_directory is not None
            or self.model_descriptor is not None
            or self.model_descriptor_sha256 is not None
            or self.deterministic_vocabulary is not None
            or self.case_contributor_aliases
        ):
            raise ValueError("client production rebuild bindings are invalid")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"config_sha256"})
        )
        if self.config_sha256 != expected:
            raise ValueError("production rebuild configuration hash mismatch")
        return self

    @classmethod
    def create_global(
        cls,
        *,
        scope_sha256: str,
        model_descriptor: ModelDescriptor,
        embedder_kind: Literal["sentence_transformers", "deterministic_test"],
        model_directory: str | None = None,
        deterministic_vocabulary: Mapping[str, tuple[float, ...]] | None = None,
        test_mode: bool = False,
        target_wiki_id: str | None = None,
        cas_directory: str = "objects",
        build_directory: str = ".rebuild-builds",
        graphify_seed: int = 42,
        graphify_production: bool = True,
        case_contributor_aliases: Mapping[str, str] | None = None,
    ) -> "ProductionRebuildConfig":
        lexical = LexicalIndexBuilder()
        wiki = WikiNavigationIndexBuilder()
        values: dict[str, object] = {
            "database_scope": "global",
            "scope_sha256": scope_sha256,
            "policy_sha256": hashlib.sha256(
                canonical_retrieval_route_policy_bytes()
            ).hexdigest(),
            "cas_directory": cas_directory,
            "build_directory": build_directory,
            "target_wiki_id": target_wiki_id,
            "graphify_seed": graphify_seed,
            "graphify_production": graphify_production,
            "lexical_tokenizer_descriptor_sha256": lexical.descriptor.id,
            "wiki_tokenizer_descriptor_sha256": (
                wiki.tokenizer_descriptor.canonical_sha256
            ),
            "embedder_kind": embedder_kind,
            "test_mode": test_mode,
            "model_directory": model_directory,
            "model_descriptor": model_descriptor,
            "model_descriptor_sha256": model_descriptor.id,
            "deterministic_vocabulary": (
                None
                if deterministic_vocabulary is None
                else dict(deterministic_vocabulary)
            ),
            "case_contributor_aliases": tuple(
                CaseContributorAliasBinding(
                    contributor_client_hash=contributor_hash,
                    pseudonymous_client_id=alias,
                )
                for contributor_hash, alias in sorted(
                    (case_contributor_aliases or {}).items()
                )
            ),
        }
        draft = cls.model_construct(
            config_sha256="0" * 64, **cast(Any, values)
        )
        values["config_sha256"] = canonical_sha256(
            draft.model_dump(mode="json", exclude={"config_sha256"})
        )
        return cls.model_validate(values)

    @classmethod
    def create_client(
        cls,
        *,
        scope_sha256: str,
        cas_directory: str = "cas",
        build_directory: str = ".rebuild-builds",
    ) -> "ProductionRebuildConfig":
        values: dict[str, object] = {
            "database_scope": "client",
            "scope_sha256": scope_sha256,
            "policy_sha256": CLIENT_POLICY_SHA256,
            "cas_directory": cas_directory,
            "build_directory": build_directory,
        }
        draft = cls.model_construct(
            config_sha256="0" * 64, **cast(Any, values)
        )
        values["config_sha256"] = canonical_sha256(
            draft.model_dump(mode="json", exclude={"config_sha256"})
        )
        return cls.model_validate(values)

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


def load_production_rebuild_config(
    scope_root: Path,
    *,
    database_scope: DatabaseScope,
    scope_sha256: str,
) -> ProductionRebuildConfig:
    root = scope_root.resolve(strict=False)
    path = root / CONFIG_FILENAME
    try:
        payload = path.read_bytes()
        config = ProductionRebuildConfig.model_validate_json(payload, strict=True)
    except (OSError, ValueError):
        raise ProductionRebuildError("REBUILD_PRODUCTION_CONFIG_INVALID") from None
    if (
        config.database_scope != database_scope
        or config.scope_sha256 != scope_sha256
        or config.canonical_bytes != payload
    ):
        raise ProductionRebuildError("REBUILD_PRODUCTION_CONFIG_MISMATCH")
    return config


def _scoped_path(root: Path, relative: str) -> Path:
    try:
        target = (root / Path(_safe_relative(relative))).resolve(strict=False)
        target.relative_to(root)
    except (OSError, ValueError):
        raise ProductionRebuildError("REBUILD_PRODUCTION_PATH_INVALID") from None
    return target


@dataclass(frozen=True, slots=True)
class _DecodedAuthority:
    table: str
    row: dict[str, object]
    content_objects: dict[str, bytes]


def _sql_value(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"base64"}:
        raw = value["base64"]
        if type(raw) is not str:
            raise ProductionRebuildError("REBUILD_AUTHORITY_RECORD_INVALID")
        try:
            return base64.b64decode(raw, validate=True)
        except ValueError:
            raise ProductionRebuildError(
                "REBUILD_AUTHORITY_RECORD_INVALID"
            ) from None
    return value


def _decode_authority(record: AuthorityRecord) -> _DecodedAuthority:
    try:
        payload = json.loads(record.payload)
        source = payload["source"]
        raw_row = payload["row"]
        raw_objects = payload["content_objects"]
        if (
            payload["domain"] != "consultation_kb.rebuild_authority_record.v1"
            or type(source) is not dict
            or source.get("table") != record.source.table
            or type(raw_row) is not dict
            or type(raw_objects) is not list
        ):
            raise ValueError
        row = {str(key): _sql_value(value) for key, value in raw_row.items()}
        content: dict[str, bytes] = {}
        for item in raw_objects:
            if (
                type(item) is not dict
                or set(item) != {"column", "content_sha256", "payload_base64"}
                or type(item["column"]) is not str
                or type(item["content_sha256"]) is not str
                or type(item["payload_base64"]) is not str
            ):
                raise ValueError
            body = base64.b64decode(item["payload_base64"], validate=True)
            if hashlib.sha256(body).hexdigest() != item["content_sha256"]:
                raise ValueError
            content[str(item["column"])] = body
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ProductionRebuildError("REBUILD_AUTHORITY_RECORD_INVALID") from None
    return _DecodedAuthority(record.source.table, row, content)


def _decoded_by_table(
    records: tuple[AuthorityRecord, ...],
) -> dict[str, tuple[_DecodedAuthority, ...]]:
    grouped: dict[str, list[_DecodedAuthority]] = {}
    for record in records:
        decoded = _decode_authority(record)
        grouped.setdefault(decoded.table, []).append(decoded)
    return {
        table: tuple(values)
        for table, values in sorted(grouped.items())
    }


def _materialize_authority(
    *,
    scope: DatabaseScope,
    records: tuple[AuthorityRecord, ...],
    root: Path,
    manifest_id: str,
) -> tuple[sqlite3.Connection, ContentStore, dict[str, tuple[_DecodedAuthority, ...]]]:
    decoded = _decoded_by_table(records)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        MigrationRunner.for_scope(connection, scope).apply()
        connection.execute("PRAGMA foreign_keys = OFF")
        store = ContentStore(root / "authority-cas")
        for values in decoded.values():
            for item in values:
                for body in item.content_objects.values():
                    store.finalize(
                        store.stage_bytes(
                            body,
                            purpose="rebuild_authority",
                            manifest_id=manifest_id,
                            media_type="application/octet-stream",
                        )
                    )
                columns = tuple(item.row)
                placeholders = ",".join("?" for _ in columns)
                quoted = ",".join(f'"{column}"' for column in columns)
                connection.execute(
                    f'INSERT INTO "{item.table}"({quoted}) VALUES ({placeholders})',
                    tuple(item.row[column] for column in columns),
                )
        return connection, store, decoded
    except Exception:
        connection.close()
        raise


def _authority_semantic_basis(
    context: BuildContext,
    config: ProductionRebuildConfig,
) -> str:
    return canonical_sha256(
        {
            "domain": "consultation_kb.production_rebuild_semantics.v1",
            "algorithm_revision": ALGORITHM_REVISION,
            "database_scope": context.job.database_scope,
            "scope_sha256": context.job.scope_sha256,
            "policy_sha256": context.policy_sha256,
            "model_descriptor_sha256": context.model_descriptor_sha256,
            "configuration_sha256": config.config_sha256,
            "authority": [
                {
                    "source": record.source.key,
                    "object_id": record.object_id,
                    "version": record.version,
                    "content_sha256": record.content_sha256,
                }
                for record in context.authority_records
            ],
        }
    )


def _draft_artifact(
    *,
    context: BuildContext,
    config: ProductionRebuildConfig,
    draft: ArtifactDraft,
    descriptor: BuilderDescriptor | None = None,
) -> BuiltArtifact:
    output_descriptor = context.descriptor if descriptor is None else descriptor
    if draft.artifact_key != output_descriptor.output_purpose:
        raise ProductionRebuildError("REBUILD_PRODUCTION_OUTPUT_MISMATCH")
    if draft.source_version <= 0:
        raise ProductionRebuildError("REBUILD_PRODUCTION_VERSION_MISMATCH")
    if context.job.database_scope == "global" and draft.artifact_kind in {
        "wiki_index",
        "knowledge_registry",
        "graph",
        "lexical",
        "vector",
    }:
        expected_roles = derived_artifact_role_layout(draft.artifact_kind)
        expected_media = derived_artifact_media_type_layout(draft.artifact_kind)
        if (
            tuple(member.object_type for member in draft.members) != expected_roles
            or tuple(member.media_type for member in draft.members) != expected_media
        ):
            raise ProductionRebuildError("REBUILD_PRODUCTION_LAYOUT_INVALID")
    return _structured_draft_artifact(
        context=context,
        config=config,
        draft=draft,
        builder_id=output_descriptor.builder_id,
    )


def _structured_draft_artifact(
    *,
    context: BuildContext,
    config: ProductionRebuildConfig,
    draft: ArtifactDraft,
    builder_id: str,
) -> BuiltArtifact:
    version = draft.source_version
    if version <= 0:
        raise ProductionRebuildError("REBUILD_PRODUCTION_VERSION_MISMATCH")
    basis = _authority_semantic_basis(context, config)
    members = tuple(
        StructuredArtifactMember.from_bytes(
            role=member.object_type,
            object_id=member.object_id,
            media_type=member.media_type,
            payload=member.data,
            source_lineage_hashes=tuple(
                sorted(
                    lineage_hash(identity.object_type, identity.object_id)
                    for identity in member.source_lineage
                )
            ),
        )
        for member in draft.members
    )
    envelope = StructuredArtifactEnvelope(
        artifact_key=draft.artifact_key,
        artifact_kind=draft.artifact_kind,
        source_version=version,
        semantic_basis_sha256=basis,
        members=members,
    )
    return BuiltArtifact.create(
        builder_id=builder_id,
        output_purpose=draft.artifact_key,
        version=version,
        payload=envelope.canonical_bytes,
        semantic_fingerprint_sha256=envelope.semantic_fingerprint_sha256,
        comparison_content_sha256=envelope.comparison_content_sha256,
    )


def _attempt_root(root: Path, context: BuildContext) -> Path:
    value = root / context.job.job_id / f"attempt-{context.job.attempt_count}"
    value.mkdir(parents=True, exist_ok=True)
    return value


def _stage_epochs(
    connection: sqlite3.Connection,
    job_id: str,
) -> tuple[int | None, int, str, int]:
    row = connection.execute(
        "SELECT p.expected_current_epoch, p.operation_id, "
        "p.authority_base_version "
        "FROM publication_operations AS p "
        "JOIN rebuild_stage_bindings AS b ON b.operation_id = p.operation_id "
        "WHERE b.job_id = ? AND p.purpose = 'rebuild' AND p.state = 'PREPARED' "
        "ORDER BY p.created_at DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    if row is None:
        raise ProductionRebuildError("REBUILD_PRODUCTION_STAGE_MISSING")
    expected = None if row[0] is None else int(str(row[0]))
    maximum = int(
        connection.execute(
            "SELECT COALESCE(MAX(epoch), 0) FROM runtime_epochs"
        ).fetchone()[0]
    )
    active = connection.execute(
        "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchall()
    if len(active) > 1 or (None if not active else int(active[0][0])) != expected:
        raise ProductionRebuildError("REBUILD_PRODUCTION_EPOCH_INVALID")
    operation_id = str(row[1])
    authority_base_version = int(str(row[2]))
    if not operation_id or authority_base_version <= 0:
        raise ProductionRebuildError("REBUILD_PRODUCTION_STAGE_MISSING")
    return expected, maximum + 1, operation_id, authority_base_version


def _production_authority_version(
    connection: sqlite3.Connection,
    scope: DatabaseScope,
) -> int:
    if scope == "global":
        row = connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT commit_version FROM client_fact_authority WHERE singleton = 1"
        ).fetchone()
    if row is None or type(row[0]) is not int or int(row[0]) <= 0:
        raise ProductionRebuildError("REBUILD_PRODUCTION_AUTHORITY_VERSION_INVALID")
    return int(row[0])


def _deterministic_ids(context: BuildContext) -> IdFactory:
    seed = int(
        hashlib.sha256(
            f"{context.job.job_id}:{context.job.attempt_count}".encode("ascii")
        ).hexdigest(),
        16,
    ) % (2**74)
    counter = 0

    def random_source() -> int:
        nonlocal counter
        value = (seed + counter) % (2**74)
        counter += 1
        return value

    return IdFactory(FixedClock(context.job.created_at), random_source)


class _PublicationOperationIdFactory(IdFactory):
    """Bind planner-internal manifests to the durable rebuild operation."""

    def __init__(
        self,
        delegate: IdFactory,
        operation_id: str,
        manifest_ids: tuple[str, ...],
    ) -> None:
        self._delegate = delegate
        self._operation_id = operation_id
        self._manifest_ids = manifest_ids
        self._manifest_index = 0

    def uuid7(self) -> str:
        return self._delegate.uuid7()

    def object_id(self, kind: str) -> str:
        if kind == "knowledge_publication":
            return self._operation_id
        if kind == "manifest":
            try:
                value = self._manifest_ids[self._manifest_index]
            except IndexError:
                raise ProductionRebuildError(
                    "REBUILD_GLOBAL_CLOSURE_INCOMPLETE"
                ) from None
            self._manifest_index += 1
            return value
        return self._delegate.object_id(kind)


class _ReadOnlyExecutor:
    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: object,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> str:
        del approval_request_id, descriptor, operation_kind, apply
        raise ProductionRebuildError("REBUILD_READ_ONLY_AUTHORITY")


def _content_for(item: _DecodedAuthority, column: str) -> bytes:
    try:
        return item.content_objects[column]
    except KeyError:
        raise ProductionRebuildError("REBUILD_AUTHORITY_CAS_MISSING") from None


class _GlobalCompiler:
    def __init__(
        self,
        connection: sqlite3.Connection,
        config: ProductionRebuildConfig,
        build_root: Path,
        scope_root: Path,
    ) -> None:
        self._connection = connection
        self._config = config
        self._root = build_root
        self._scope_root = scope_root
        self._cache: dict[tuple[str, int], dict[str, BuiltArtifact]] = {}

    def build(self, context: BuildContext) -> BuiltArtifact:
        self._validate_binding(context)
        key = (context.job.job_id, context.job.attempt_count)
        if key not in self._cache:
            self._cache[key] = self._compile(context)
        try:
            return self._cache[key][context.descriptor.builder_id]
        except KeyError:
            raise ProductionRebuildError("REBUILD_PRODUCTION_OUTPUT_MISSING") from None

    def _validate_binding(self, context: BuildContext) -> None:
        if (
            context.job.database_scope != "global"
            or context.policy_sha256 != self._config.policy_sha256
            or context.model_descriptor_sha256
            != self._config.model_descriptor_sha256
        ):
            raise ProductionRebuildError("REBUILD_PRODUCTION_BINDING_MISMATCH")

    def _embedder(self) -> Embedder:
        descriptor = self._config.model_descriptor
        if descriptor is None:
            raise ProductionRebuildError("REBUILD_MODEL_CONFIG_MISSING")
        if self._config.embedder_kind == "sentence_transformers":
            directory = self._config.model_directory
            if directory is None:
                raise ProductionRebuildError("REBUILD_MODEL_CONFIG_MISSING")
            try:
                return SentenceTransformersEmbedder(
                    _scoped_path(self._scope_root, directory), descriptor
                )
            except Exception:
                raise ProductionRebuildError("REBUILD_MODEL_UNAVAILABLE") from None
        vocabulary = self._config.deterministic_vocabulary
        if not self._config.test_mode or not vocabulary:
            raise ProductionRebuildError("REBUILD_TEST_MODEL_FORBIDDEN")
        try:
            arrays: dict[str, NDArray[np.float32]] = {
                token: np.asarray(vector, dtype=np.float32)
                for token, vector in vocabulary.items()
            }
            return DeterministicFakeEmbedder(descriptor, arrays)
        except Exception:
            raise ProductionRebuildError("REBUILD_MODEL_CONFIG_INVALID") from None

    def _compile(self, context: BuildContext) -> dict[str, BuiltArtifact]:
        work = _attempt_root(self._root, context)
        authority_root = work / "global-authority"
        authority_root.mkdir(exist_ok=True)
        ephemeral, store, _decoded = _materialize_authority(
            scope="global",
            records=context.authority_records,
            root=authority_root,
            manifest_id=context.job.job_id,
        )
        try:
            (
                expected_epoch,
                target_epoch,
                rebuild_operation_id,
                artifact_version,
            ) = _stage_epochs(
                self._connection, context.job.job_id
            )
            catalog = self._connection.execute(
                "SELECT authorization_epoch FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
            if catalog is None:
                raise ProductionRebuildError(
                    "REBUILD_KNOWLEDGE_CATALOG_STATE_MISSING"
                )
            ephemeral.execute(
                "UPDATE knowledge_catalog_state SET catalog_version = ?, "
                "authorization_epoch = ?, tombstone_epoch = ? WHERE singleton = 1",
                (
                    artifact_version,
                    int(str(catalog[0])),
                    context.tombstone_epoch,
                ),
            )
            ids = _deterministic_ids(context)
            for epoch, state, created_at, activated_at in self._connection.execute(
                "SELECT epoch, state, created_at, activated_at FROM runtime_epochs "
                "ORDER BY epoch"
            ):
                ephemeral.execute(
                    "INSERT INTO runtime_epochs(epoch, operation_id, state, "
                    "created_at, activated_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        int(epoch),
                        ids.object_id("ephemeral_publication"),
                        str(state),
                        str(created_at),
                        activated_at,
                    ),
                )
            maximum = int(
                ephemeral.execute(
                    "SELECT COALESCE(MAX(epoch), 0) FROM runtime_epochs"
                ).fetchone()[0]
            )
            if maximum + 1 != target_epoch:
                raise ProductionRebuildError("REBUILD_PRODUCTION_EPOCH_INVALID")

            clock = FixedClock(context.job.created_at)
            read_only = cast(GovernedWriteExecutor, _ReadOnlyExecutor())
            passages = PassageCatalog(
                ephemeral,
                content_store=store,
                approval_executor=read_only,
                id_factory=ids,
                clock=clock,
            )

            def resolve_claim_evidence(
                reference: VersionRef,
            ) -> tuple[str, str | None, str | None, EvidenceLocator]:
                passage = passages.get(reference.object_id, reference.version)

                def optional_text(value: str | None) -> str | None:
                    if value is None:
                        return None
                    return store.read_hash_verified(
                        value.removeprefix("sha256:")
                    ).decode("utf-8", errors="strict")

                return (
                    store.read_hash_verified(reference.content_sha256).decode(
                        "utf-8", errors="strict"
                    ),
                    optional_text(passage.context_before_ref),
                    optional_text(passage.context_after_ref),
                    passage.locator,
                )

            claims = ClaimProposalService(
                review_resolver=ClaimReviewResolver(resolve_claim_evidence),
                id_factory=ids,
                clock=clock,
                connection=ephemeral,
                approval_executor=read_only,
                content_store=store,
            )
            scope_policies = ScopePolicyRepository(
                ephemeral,
                content_store=store,
                approval_executor=read_only,
                clock=clock,
            )
            theories = TheoryRevisionService(
                id_factory=ids,
                clock=clock,
                connection=ephemeral,
                approval_executor=read_only,
                content_store=store,
                scope_policy_repository=scope_policies,
            )

            def claim_authority(reference: VersionRef) -> WikiClaimAuthority:
                claim = claims.get(reference.object_id, reference.version)
                if claim.text_sha256 != reference.content_sha256:
                    raise ProductionRebuildError(
                        "REBUILD_CLAIM_AUTHORITY_MISMATCH"
                    )
                return WikiClaimAuthority(
                    status="approved",
                    source_grade=claim.source_grade,
                    theory_revision_ref=claim.theory_revision_ref,
                )

            def passage_authority(reference: VersionRef) -> EvidenceLocator:
                passage = passages.get(reference.object_id, reference.version)
                if passage.normalized_text_sha256 != reference.content_sha256:
                    raise ProductionRebuildError(
                        "REBUILD_PASSAGE_AUTHORITY_MISMATCH"
                    )
                return passage.locator

            wikis = WikiRevisionService(
                claim_resolver=claim_authority,
                passage_resolver=passage_authority,
                theory_resolver=lambda ref: theories.get_by_ref(ref).status,
                id_factory=ids,
                clock=clock,
                connection=ephemeral,
                approval_executor=read_only,
                content_store=store,
            )
            lexical = LexicalIndexBuilder()
            wiki_builder = WikiNavigationIndexBuilder()
            if (
                lexical.descriptor.id
                != self._config.lexical_tokenizer_descriptor_sha256
                or wiki_builder.tokenizer_descriptor.canonical_sha256
                != self._config.wiki_tokenizer_descriptor_sha256
            ):
                raise ProductionRebuildError(
                    "REBUILD_TOKENIZER_BINDING_MISMATCH"
                )
            descriptor = self._config.model_descriptor
            if descriptor is None:
                raise ProductionRebuildError("REBUILD_MODEL_CONFIG_MISSING")
            builders = GlobalPublicationBuilders(
                embedder=self._embedder(),
                model_descriptor=descriptor,
                lexical=lexical,
                wiki=wiki_builder,
                graphify=GraphifyProjectionAdapter(
                    seed=self._config.graphify_seed,
                    production=self._config.graphify_production,
                ),
            )
            active_wikis = tuple(
                (str(row[0]), int(str(row[1])))
                for row in ephemeral.execute(
                    "SELECT wiki_id, revision FROM wiki_revisions "
                    "WHERE review_status = 'ACTIVE' ORDER BY wiki_id, revision"
                )
            )
            if not active_wikis:
                raise ProductionRebuildError("REBUILD_ACTIVE_WIKI_REQUIRED")
            target_id = self._config.target_wiki_id
            if target_id is None:
                if len(active_wikis) != 1:
                    raise ProductionRebuildError(
                        "REBUILD_TARGET_WIKI_CONFIG_REQUIRED"
                    )
                target = active_wikis[0]
            else:
                matches = tuple(value for value in active_wikis if value[0] == target_id)
                if len(matches) != 1:
                    raise ProductionRebuildError("REBUILD_TARGET_WIKI_INVALID")
                target = matches[0]
            wiki = wikis.get(*target).model_copy(update={"status": "prepared"})
            # The publication planner stages one target Wiki as PREPARED and
            # activates it only after its derived closure is published.  A
            # rebuild starts from the already-approved ACTIVE authority row,
            # so the isolated in-memory replay database must expose that same
            # row through the planner's staging seam.  This mutation and the
            # PREPARED model view exist only in the isolated replay database;
            # the durable authority snapshot remains exact and ACTIVE.
            staged = ephemeral.execute(
                "UPDATE wiki_revisions SET review_status = 'PREPARED' "
                "WHERE wiki_id = ? AND revision = ? "
                "AND review_status = 'ACTIVE'",
                target,
            ).rowcount
            if staged != 1:
                raise ProductionRebuildError("REBUILD_TARGET_WIKI_INVALID")
            has_governed_c1 = any(
                wikis.get(*active_wiki).theory_revision_refs
                for active_wiki in active_wikis
            )
            planned_purposes = (
                "c1_revision",
                "claims",
                "graph",
                "knowledge_registry",
                "lexical",
                "vector",
                "wiki_index",
                "wiki_page",
            )
            manifest_by_purpose = {
                purpose: rebuild_manifest_id(
                    job_id=context.job.job_id,
                    attempt_count=context.job.attempt_count,
                    output_purpose=purpose,
                )
                for purpose in planned_purposes
            }
            planner_manifest_purposes = tuple(
                purpose
                for purpose in planned_purposes
                if purpose != "c1_revision" or has_governed_c1
            )
            planner_ids = _PublicationOperationIdFactory(
                ids,
                rebuild_operation_id,
                tuple(
                    manifest_by_purpose[purpose]
                    for purpose in planner_manifest_purposes
                ),
            )
            planner = GlobalKnowledgePublicationPlanner(
                connection=ephemeral,
                content_store=store,
                approval_service=cast(ApprovalService, None),
                execution_guard=cast(ApprovalExecutionGuard, None),
                claim_service=claims,
                passage_reader=passages,
                theory_service=theories,
                wiki_service=wikis,
                builders=builders,
                build_root=(work / "derived").resolve(),
                id_factory=planner_ids,
                clock=clock,
                lint_error_count=lambda: 0,
            )
            state = planner._build_state(  # noqa: SLF001 - production reuse seam
                wiki=wiki,
                theory=None,
                authority_version=artifact_version,
                expected_epoch=expected_epoch,
            )
            case_assignments = self._case_assignments(
                ephemeral_store=store,
                stage_manifest_id=context.job.job_id,
            )
            if case_assignments:
                assignments = tuple((*state.authority.assignments, *case_assignments))
                descriptor_value = RetrievalInputDescriptor.from_assignments(
                    assignments,
                    route_policy_ref=state.authority.route_policy_ref,
                )
                authority = replace(
                    state.authority,
                    assignments=assignments,
                    descriptor=descriptor_value,
                )
                closure = hashlib.sha256(
                    canonical_json_bytes(
                        authority.snapshot.model_dump(mode="json")
                    )
                ).hexdigest()
                inputs = {
                    kind: DerivedArtifactBuilderInputV2(
                        artifact_kind=kind,
                        authority_closure_sha256=closure,
                        authority_snapshot=authority.snapshot,
                        retrieval_input_descriptor=descriptor_value,
                        target_runtime_epoch=authority.snapshot.target_runtime_epoch,
                    )
                    for kind in cast(
                        tuple[DerivedArtifactKind, ...],
                        (
                            "wiki_index",
                            "knowledge_registry",
                            "graph",
                            "lexical",
                            "vector",
                        ),
                    )
                }
                state = replace(
                    state,
                    authority=authority,
                    builder_inputs=inputs,
                )
            all_drafts = {
                draft.artifact_key: draft
                for draft in planner._build_artifacts(state)  # noqa: SLF001
            }
            if "c1_revision" not in all_drafts:
                if has_governed_c1:
                    raise ProductionRebuildError(
                        "REBUILD_GLOBAL_CLOSURE_INCOMPLETE"
                    )
                all_drafts["c1_revision"] = ArtifactDraft(
                    manifest_id=manifest_by_purpose["c1_revision"],
                    artifact_key="c1_revision",
                    artifact_kind="c1_absence",
                    source_version=artifact_version,
                    members=(
                        ContentDraft(
                            object_type="c1_absence",
                            object_id=ids.object_id("c1_absence"),
                            data=canonical_json_bytes(
                                {
                                    "reason": "no_active_governed_c1",
                                    "schema_version": "c1_absence.v1",
                                    "source_version": artifact_version,
                                }
                            ),
                            source_version=artifact_version,
                            media_type="application/json",
                            source_lineage=(),
                        ),
                    ),
                )
            derived_keys = {
                "wiki_index",
                "knowledge_registry",
                "graph",
                "lexical",
                "vector",
            }
            required_base = {"wiki_page", "claims", "c1_revision"}
            if not derived_keys | required_base <= set(all_drafts):
                raise ProductionRebuildError("REBUILD_GLOBAL_CLOSURE_INCOMPLETE")
            if any(
                all_drafts[purpose].manifest_id
                != manifest_by_purpose[purpose]
                for purpose in planned_purposes
            ):
                raise ProductionRebuildError("REBUILD_GLOBAL_CLOSURE_INCOMPLETE")
            return {
                builder_id: _draft_artifact(
                    context=context,
                    config=self._config,
                    draft=all_drafts[builder_id],
                    descriptor=self._descriptor(builder_id),
                )
                for builder_id in derived_keys | required_base
            }
        except ProductionRebuildError:
            raise
        except (GlobalPublicationPlanningError, CaseIndexingError) as exc:
            code = getattr(exc, "code", None)
            raise ProductionRebuildError(
                code if isinstance(code, str) else "REBUILD_GLOBAL_BUILD_FAILED"
            ) from exc
        except Exception as exc:
            raise ProductionRebuildError("REBUILD_GLOBAL_BUILD_FAILED") from exc
        finally:
            ephemeral.close()

    @staticmethod
    def _descriptor(builder_id: str) -> BuilderDescriptor:
        registry = BuilderRegistry.production()
        return next(
            value
            for value in registry.descriptors
            if value.builder_id == builder_id
        )

    def _case_assignments(
        self,
        *,
        ephemeral_store: ContentStore,
        stage_manifest_id: str,
    ) -> tuple[RetrievalInputAssignment, ...]:
        durable_store = ContentStore(
            _scoped_path(self._scope_root, self._config.cas_directory)
        )
        repository = CaseIndexPublicationRepository(
            self._connection,
            durable_store,
        )
        channels: dict[str, frozenset[DerivedArtifactKind]] = {
            "case": frozenset({"lexical", "vector"}),
            "wiki_section": frozenset({"wiki_index"}),
            "graph_edge": frozenset({"graph"}),
            "lexical_row": frozenset({"lexical"}),
            "vector_row": frozenset({"vector"}),
        }
        assignments: list[RetrievalInputAssignment] = []
        try:
            for bundle in repository.replay_approved():
                for candidate in bundle.candidates:
                    body = bundle.body_for(candidate)
                    if (
                        hashlib.sha256(body).hexdigest()
                        != candidate.content_ref.content_sha256
                    ):
                        raise ValueError
                    reference = ephemeral_store.finalize(
                        ephemeral_store.stage_bytes(
                            body,
                            purpose="case_rebuild",
                            manifest_id=stage_manifest_id,
                            media_type=candidate.metadata.media_type,
                        )
                    )
                    if reference.content_sha256 != candidate.content_ref.content_sha256:
                        raise ValueError
                    assert_case_index_text_safe(
                        candidate,
                        body.decode("utf-8", errors="strict"),
                    )
                    assignments.append(
                        RetrievalInputAssignment.from_candidate(
                            candidate,
                            target_channels=channels[candidate.object_type],
                        )
                    )
        except (CaseIndexPublicationError, CaseIndexingError, KeyError, ValueError):
            raise ProductionRebuildError("REBUILD_CASE_AUTHORITY_INVALID") from None
        return tuple(assignments)


class _ClientCompiler:
    def __init__(
        self,
        connection: sqlite3.Connection,
        config: ProductionRebuildConfig,
    ) -> None:
        self._connection = connection
        self._config = config
        self._cache: dict[tuple[str, int, str], BuiltArtifact] = {}

    def build(self, context: BuildContext) -> BuiltArtifact:
        if (
            context.job.database_scope != "client"
            or context.policy_sha256 != self._config.policy_sha256
            or context.model_descriptor_sha256 is not None
        ):
            raise ProductionRebuildError("REBUILD_PRODUCTION_BINDING_MISMATCH")
        key = (
            context.job.job_id,
            context.job.attempt_count,
            context.descriptor.builder_id,
        )
        if key not in self._cache:
            draft = (
                self._private_archive(context)
                if context.descriptor.builder_id == "private_archive"
                else self._profile_closure(context)[context.descriptor.builder_id]
            )
            self._cache[key] = _draft_artifact(
                context=context,
                config=self._config,
                draft=draft,
            )
        return self._cache[key]

    def _profile_closure(self, context: BuildContext) -> dict[str, ArtifactDraft]:
        decoded = _decoded_by_table(context.authority_records)
        try:
            authority = self._connection.execute(
                "SELECT commit_version, client_id FROM client_fact_authority "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                authority is None
                or int(str(authority[0])) <= 0
                or authority[1] is None
            ):
                raise ProductionRebuildError("REBUILD_CLIENT_AUTHORITY_EMPTY")
            authority_commit_version = int(str(authority[0]))
            authority_client_id = str(authority[1])
            events = tuple(
                FactEvent.from_record(item.row)
                for item in decoded.get("fact_events", ())
            )
            if not events or any(
                event.client_id != authority_client_id for event in events
            ):
                raise ProductionRebuildError("REBUILD_CLIENT_AUTHORITY_INCOMPLETE")
            dependencies = tuple(
                DependencyEdge(
                    edge_id=str(item.row["edge_id"]),
                    dependent_fact_id=str(item.row["dependent_fact_id"]),
                    prerequisite_fact_id=str(item.row["prerequisite_fact_id"]),
                    dependency_type=cast(
                        DependencyType, str(item.row["dependency_type"])
                    ),
                    confidence=float(str(item.row["confidence"])),
                    source_event_id=str(item.row["source_event_id"]),
                    reviewer_id=str(item.row["reviewer_id"]),
                )
                for item in decoded.get("fact_dependencies", ())
            )
            revisions = decoded.get("profile_revisions", ())
            latest = max(
                revisions,
                key=lambda item: (
                    int(str(item.row["source_commit_version"])),
                    int(str(item.row["visible_runtime_epoch"])),
                    str(item.row["created_at"]),
                    str(item.row["revision_id"]),
                ),
                default=None,
            )
            rollback_intent = (
                context.job.source_intent_id is not None
                and self._connection.execute(
                    "SELECT intent_kind FROM rebuild_source_intents "
                    "WHERE intent_id = ?",
                    (context.job.source_intent_id,),
                ).fetchall()
                == [("rollback",)]
            )
            if not rollback_intent and (
                latest is None
                or int(str(latest.row["source_commit_version"]))
                != authority_commit_version
            ):
                raise ProductionRebuildError("REBUILD_CLIENT_PROFILE_AUTHORITY_STALE")
            (
                expected_epoch,
                target_epoch,
                rebuild_operation_id,
                _stage_authority_version,
            ) = _stage_epochs(self._connection, context.job.job_id)
            version = _production_authority_version(
                self._connection,
                "client",
            )
            if rollback_intent:
                # A rollback successor advances fact authority before its
                # replacement profile exists. Build that profile from the
                # exact append-only fact snapshot at the successor boundary.
                boundary = max(event.recorded_at for event in events)
                commit_version = authority_commit_version
            else:
                assert latest is not None
                boundary = _parse_utc(latest.row["created_at"])
                commit_version = int(str(latest.row["source_commit_version"]))
            query = FactQuery(
                effective_at=boundary,
                known_at=boundary,
                fixed_epoch=target_epoch,
            )
            snapshot = BitemporalFactQuery.snapshot_events(
                tuple(
                    event
                    for event in events
                    if event.commit_version <= commit_version
                ),
                query,
                client_commit_version=commit_version,
            )
            snapshot = BitemporalFactQuery.snapshot_events(
                tuple(
                    event
                    for event in snapshot.events
                    if event.privacy_level == "private_client"
                    and event.allows_purpose("next_session_context")
                ),
                query,
                client_commit_version=commit_version,
            )
            merge_members = frozenset(
                str(item.row["member_event_id"])
                for item in decoded.get("fact_merge_members", ())
            )
            materializer = ProfileMaterializer()
            profile = materializer.build(
                snapshot,
                merge_member_event_ids=merge_members,
            )
            graph = TemporalGraphBuilder().build(
                snapshot,
                publication_operation_id=rebuild_operation_id,
                runtime_epoch=target_epoch,
                dependencies=dependencies,
            )
            fact_bytes = canonical_json_bytes(
                {
                    "dependencies": [
                        value.model_dump(mode="json") for value in dependencies
                    ],
                    "schema_version": "client_fact_snapshot.v2",
                    "snapshot": snapshot.model_dump(mode="json"),
                }
            ) + b"\n"
            commitment = canonical_json_bytes(
                {
                    "schema_version": "client_rebuild_review_commitment.v1",
                    "input_authority_versions_sha256": (
                        context.job.input_authority_versions_sha256
                    ),
                    "tombstone_epoch": context.tombstone_epoch,
                }
            ) + b"\n"
            graph_bytes = canonical_client_graph_bytes(
                client_graph_payload(
                    graph.graph,
                    publication_operation_id=rebuild_operation_id,
                    source_client_commit_version=commit_version,
                    runtime_epoch=target_epoch,
                    effective_at=query.effective_at,
                    known_at=query.known_at,
                    builder_policy_version=graph.builder_policy_version,
                )
            )
        except ProductionRebuildError:
            raise
        except Exception as exc:
            raise ProductionRebuildError("REBUILD_CLIENT_BUILD_FAILED") from exc

        ids = _deterministic_ids(context)
        lineage = tuple(
            ObjectIdentity("fact_event", event.event_id)
            for event in sorted(events, key=lambda value: value.event_id)
        )
        return {
            "client_fact_snapshot": ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_fact_snapshot",
                artifact_kind="fact_snapshot",
                source_version=version,
                members=(
                    ContentDraft(
                        object_type="fact_snapshot",
                        object_id=ids.object_id("fact_snapshot"),
                        data=fact_bytes,
                        source_version=version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="mutation_review_commitment",
                        object_id=ids.object_id("mutation_review_commitment"),
                        data=commitment,
                        source_version=version,
                        media_type="application/json",
                        source_lineage=(),
                    ),
                ),
            ),
            "client_profile": ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_profile",
                artifact_kind="profile",
                source_version=version,
                members=(
                    ContentDraft(
                        object_type="profile_json",
                        object_id=ids.object_id("profile_json"),
                        data=materializer.render_json(profile),
                        source_version=version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="profile_markdown",
                        object_id=ids.object_id("profile_markdown"),
                        data=materializer.render_markdown(profile),
                        source_version=version,
                        media_type="text/markdown",
                        source_lineage=lineage,
                    ),
                ),
            ),
            "client_graph": ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_graph",
                artifact_kind="graph",
                source_version=version,
                members=(
                    ContentDraft(
                        object_type="client_graph",
                        object_id=ids.object_id("client_graph"),
                        data=graph_bytes,
                        source_version=version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                ),
            ),
        }

    def _private_archive(self, context: BuildContext) -> ArtifactDraft:
        decoded = _decoded_by_table(context.authority_records)
        revisions = tuple(
            sorted(
                decoded.get("private_archive_revisions", ()),
                key=lambda item: (
                    str(item.row["bundle_id"]),
                    int(str(item.row["revision"])),
                    str(item.row["revision_id"]),
                ),
            )
        )
        (
            expected_epoch,
            _target_epoch,
            _rebuild_operation_id,
            _stage_authority_version,
        ) = _stage_epochs(self._connection, context.job.job_id)
        version = _production_authority_version(
            self._connection,
            "client",
        )
        ids = _deterministic_ids(context)
        members: list[ContentDraft] = []
        for item in revisions:
            body = _content_for(item, "draft_sha256")
            if hashlib.sha256(body).hexdigest() != str(item.row["draft_sha256"]):
                raise ProductionRebuildError("REBUILD_PRIVATE_ARCHIVE_INVALID")
            try:
                parsed = json.loads(body)
            except (UnicodeError, ValueError, json.JSONDecodeError):
                raise ProductionRebuildError("REBUILD_PRIVATE_ARCHIVE_INVALID") from None
            if canonical_json_bytes(parsed) not in {body, body.rstrip(b"\n")}:
                raise ProductionRebuildError("REBUILD_PRIVATE_ARCHIVE_INVALID")
            members.append(
                ContentDraft(
                    object_type="private_archive_draft",
                    object_id=ids.object_id("private_archive_draft"),
                    data=body,
                    source_version=version,
                    media_type="application/json",
                    source_lineage=(
                        ObjectIdentity(
                            "archive_bundle", str(item.row["bundle_id"])
                        ),
                    ),
                )
            )
        if not members:
            members.append(
                ContentDraft(
                    object_type="private_archive_draft",
                    object_id=ids.object_id("private_archive_draft"),
                    data=canonical_json_bytes(
                        {
                            "schema_version": "private_archive_rebuild.v1",
                            "archives": [],
                        }
                    ),
                    source_version=version,
                    media_type="application/json",
                    source_lineage=(),
                )
            )
        return ArtifactDraft(
            manifest_id=ids.object_id("artifact_manifest"),
            artifact_key="private_archive",
            artifact_kind="private_archive",
            source_version=version,
            members=tuple(members),
        )


@dataclass(slots=True)
class _ProductionArtifactBuilder:
    descriptor: BuilderDescriptor
    compile: Callable[[BuildContext], BuiltArtifact]

    def build(self, context: BuildContext) -> BuiltArtifact:
        if context.descriptor != self.descriptor:
            raise RebuildCoordinatorError("REBUILD_BUILDER_DESCRIPTOR_MISMATCH")
        if self.descriptor.implementation_revision_sha256 != (
            PRODUCTION_IMPLEMENTATION_REVISIONS[self.descriptor.builder_id]
        ):
            raise RebuildCoordinatorError(
                "REBUILD_BUILDER_IMPLEMENTATION_CHANGED"
            )
        if context.job.purpose != "all":
            raise ProductionRebuildError(
                "REBUILD_PRODUCTION_FULL_CLOSURE_REQUIRED"
            )
        return self.compile(context)


def _case_index_intent_set_sha256(
    snapshot: CaseIndexRebuildSnapshot,
) -> str:
    if not snapshot.identities:
        return EMPTY_CASE_INDEX_INTENT_SET_SHA256
    return snapshot.identity_sha256


class _ProductionRebuildArtifactStore(SqliteCasRebuildArtifactStore):
    """Add exact case-index batch authority to the atomic global switch."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        content_store: ContentStore,
    ) -> None:
        super().__init__(
            connection,
            database_scope=database_scope,
            scope_sha256=scope_sha256,
            content_store=content_store,
        )
        self._production_scope = database_scope
        self._production_connection = connection
        self._case_repository = (
            CaseIndexPublicationRepository(connection, content_store)
            if database_scope == "global"
            else None
        )
        self._production_jobs = RebuildJobRepository(
            connection,
            database_scope=database_scope,
        )
        self._production_registry = BuilderRegistry.production()

    def current_case_index_intent_set_sha256(self) -> str:
        if self._case_repository is None:
            return EMPTY_CASE_INDEX_INTENT_SET_SHA256
        try:
            return _case_index_intent_set_sha256(
                self._case_repository.pending_rebuild_snapshot()
            )
        except CaseIndexPublicationError as exc:
            raise RebuildCoordinatorError(str(exc)) from None

    def _validated_case_snapshot(self, job_id: str) -> CaseIndexRebuildSnapshot:
        repository = self._case_repository
        if repository is None:
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_INTENT_SET_INVALID"
            )
        try:
            snapshot = repository.pending_rebuild_snapshot()
        except CaseIndexPublicationError as exc:
            raise RebuildCoordinatorError(str(exc)) from None
        job = self._production_jobs.get(job_id)
        if rebuild_job_plan_sha256(
            job,
            registry=self._production_registry,
            case_index_intent_set_sha256=(
                _case_index_intent_set_sha256(snapshot)
            ),
        ) != job.plan_sha256:
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_INTENT_SET_CHANGED"
            )
        return snapshot

    def _publication_authority_version(
        self,
        tombstone_epoch: int,
        *,
        job_id: str,
    ) -> int:
        current = super()._publication_authority_version(  # noqa: SLF001
            tombstone_epoch,
            job_id=job_id,
        )
        if self._production_scope != "global":
            return current
        snapshot = self._validated_case_snapshot(job_id)
        return snapshot.target_catalog_version if snapshot.identities else current

    def _before_manifest_activation(self, operation: Any) -> None:
        if self._production_scope != "global":
            return
        snapshot = self._validated_case_snapshot(str(operation.job_id))
        if not snapshot.identities:
            current = self._production_connection.execute(
                "SELECT catalog_version FROM knowledge_catalog_state "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                current is None
                or int(str(current[0])) != operation.authority_base_version
            ):
                raise RebuildCoordinatorError(
                    "REBUILD_CASE_INDEX_CATALOG_VERSION_CHANGED"
                )
            return
        if operation.authority_base_version != snapshot.target_catalog_version:
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_CATALOG_VERSION_CHANGED"
            )
        try:
            assert self._case_repository is not None
            self._case_repository.transition_rebuild_batch(snapshot)
        except CaseIndexPublicationError as exc:
            raise RebuildCoordinatorError(str(exc)) from None
        changed = self._production_connection.execute(
            "UPDATE knowledge_catalog_state SET catalog_version = ? "
            "WHERE singleton = 1 AND catalog_version = ?",
            (
                snapshot.target_catalog_version,
                snapshot.target_catalog_version - 1,
            ),
        ).rowcount
        if changed != 1:
            raise RebuildCoordinatorError(
                "REBUILD_CASE_INDEX_CATALOG_VERSION_CHANGED"
            )


def _resolve(
    connection: sqlite3.Connection,
    scope_root: Path,
    scope_sha256: str,
    *,
    database_scope: DatabaseScope,
) -> RebuildCoordinator:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("REBUILD_SCOPED_SQLITE_CONNECTION_REQUIRED")
    if not isinstance(scope_root, Path) or not scope_root.is_absolute():
        raise ProductionRebuildError("REBUILD_PRODUCTION_ROOT_INVALID")
    root = scope_root.resolve(strict=False)
    config = load_production_rebuild_config(
        root,
        database_scope=database_scope,
        scope_sha256=scope_sha256,
    )
    store = ContentStore(_scoped_path(root, config.cas_directory))
    registry = BuilderRegistry.production()
    compiler: _GlobalCompiler | _ClientCompiler
    if database_scope == "global":
        compiler = _GlobalCompiler(
            connection,
            config,
            _scoped_path(root, config.build_directory),
            root,
        )
    else:
        compiler = _ClientCompiler(connection, config)
    builders: dict[str, ArtifactBuilder] = {
        descriptor.builder_id: _ProductionArtifactBuilder(
            descriptor=descriptor,
            compile=compiler.build,
        )
        for descriptor in registry.descriptors
        if descriptor.database_scope == database_scope
    }
    artifact_store = _ProductionRebuildArtifactStore(
        connection,
        database_scope=database_scope,
        scope_sha256=scope_sha256,
        content_store=store,
    )
    return RebuildCoordinator(
        registry=registry,
        jobs=RebuildJobRepository(
            connection,
            database_scope=database_scope,
        ),
        authority=SqliteRebuildAuthoritySource(
            connection,
            database_scope=database_scope,
            scope_sha256=scope_sha256,
            content_store=store,
        ),
        artifact_store=artifact_store,
        builders=builders,
        case_index_intent_set_sha256=(
            artifact_store.current_case_index_intent_set_sha256
        ),
    )


def resolve_client_rebuild(
    connection: sqlite3.Connection,
    client_root: Path,
    scope_marker_sha256: str,
) -> RebuildCoordinator:
    """Resolve a client-scoped coordinator from ``client_root`` only."""

    return _resolve(
        connection,
        client_root,
        scope_marker_sha256,
        database_scope="client",
    )


def resolve_global_rebuild(
    connection: sqlite3.Connection,
    global_root: Path,
    scope_sha256: str,
) -> RebuildCoordinator:
    """Resolve the global coordinator from a fixed global vault root."""

    return _resolve(
        connection,
        global_root,
        scope_sha256,
        database_scope="global",
    )


def _parse_utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ProductionRebuildError("REBUILD_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ProductionRebuildError("REBUILD_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "ALGORITHM_REVISION",
    "CaseContributorAliasBinding",
    "CLIENT_POLICY_SHA256",
    "CONFIG_FILENAME",
    "ProductionRebuildConfig",
    "ProductionRebuildError",
    "load_production_rebuild_config",
    "resolve_client_rebuild",
    "resolve_global_rebuild",
]
