"""Artifact-bound P4 read and global-graph adapters for the local MCP.

The adapter opens the global authority database only.  A fixed, empty
in-memory ``client_authority`` schema lets the existing P4 snapshot guard
issue an exact *global-only* snapshot without attaching, probing, or opening
any customer's database.  The current client identity is obtained solely
from the already capability-bound session and is used only by the P4
leave-one-client-out filters.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast, final

from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.core.clock import Clock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.errors import ChannelUnavailableError
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.generation.evidence_registry import GenerationRiskContextBinding
from consultation_kb.generation.production_retrieval import (
    ActiveArtifactGlobalClosureVerifier,
    ActiveC1CandidateSemantics,
    CharacterTokenCounter,
    EmbeddingEvidenceReranker,
    QueryMatchedGraphNodeResolver,
)
from consultation_kb.generation.retrieval_orchestrator import (
    GenerationC1Context,
    GenerationRetrievalDependencies,
    GenerationRetrievalOrchestrator,
    GenerationRetrievalOutcome,
)
from consultation_kb.graph.path_cost import PathCostContext
from consultation_kb.graph.weighted_path import EvidencePath, WeightedPathQuery
from consultation_kb.models.common import (
    NonNegativeInt,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EvidenceChannel,
    RetrievalScope,
)
from consultation_kb.retrieval.artifact_contracts import (
    ArtifactBinding,
    DerivedArtifactBuilderInputV2,
    retrieval_row_id,
)
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactGate,
    ActiveRetrievalArtifactDiscovery,
    ActiveRetrievalArtifactSet,
    DEDICATED_ACTIVE_ARTIFACT_KEYS,
)
from consultation_kb.retrieval.authority_snapshot import (
    AuthoritativeSnapshotRepository,
)
from consultation_kb.retrieval.budget import ContextBudget
from consultation_kb.retrieval.contracts import (
    CandidateRef,
    FilterDecision,
    Retriever,
    candidate_capability_payload,
)
from consultation_kb.retrieval.embeddings import Embedder, ModelDescriptor
from consultation_kb.retrieval.evidence_pack import (
    ActiveArtifactVersionGate,
    RootManifestSet,
)
from consultation_kb.retrieval.filters import (
    CandidateFilter,
    ContributorIdentityHasher,
    LeaveOneOutAuthorityVerifier,
    is_current_client_contributor,
)
from consultation_kb.retrieval.fusion import ReciprocalRankFusion
from consultation_kb.retrieval.global_graph import GlobalGraphRetriever
from consultation_kb.retrieval.global_graph_runtime import GlobalGraphRuntime
from consultation_kb.retrieval.lexical import LexicalRetriever
from consultation_kb.retrieval.loo_authority import (
    SqliteLeaveOneOutAuthorityVerifier,
)
from consultation_kb.retrieval.resolver import (
    EvidenceResolver,
    ScopedManifestContentReader,
)
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.retrieval.vector import ExactVectorRetriever
from consultation_kb.retrieval.vector_builder import VectorBuildManifest
from consultation_kb.retrieval.wiki_index import WikiIndexRetriever
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.vault.layout import VaultLayout
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.security.worker_protocol import (
    GenerationClientBinding,
    PrivateGenerationEvidence,
)
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    ArtifactUnavailable,
    IntegrityStore,
)
from consultation_kb.storage.manifests import ManifestRepository

from .context import BoundTransport, ToolService
from .schemas import (
    PreviewDependencyImpactInput,
    QueryClientGraphInput,
    QueryGlobalGraphInput,
    SearchCasesInput,
    SearchLexicalInput,
    SearchVectorInput,
    SearchWikiInput,
    WeightedPathInput,
)


class RetrievalRuntimeError(RuntimeError):
    """Fixed-code retrieval composition or execution failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RetrievalCapabilityUnavailable(ChannelUnavailableError):
    """A requested channel has no safe production capability yet."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


ACTIVE_INTEGRITY_REBUILD_REQUIRED = (
    "RETRIEVAL_ACTIVE_INTEGRITY_REBUILD_REQUIRED"
)


class GenerationGlobalBinding(StrictModel):
    """Safe global half of the exact binding required to author QueryPlan."""

    global_runtime_epoch: NonNegativeInt
    global_tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt
    authority_policy_ref: VersionRef
    roots: RootManifestSet
    available_routes: tuple[EvidenceChannel, ...]
    created_at: UtcDateTime

    @classmethod
    def from_invocation(
        cls,
        invocation: "_Invocation",
        *,
        available_routes: tuple[EvidenceChannel, ...],
    ) -> "GenerationGlobalBinding":
        snapshot = invocation.snapshot
        if (
            snapshot.client_runtime_epoch != 0
            or snapshot.tombstone_epoch & 0xFFFFFFFF
            or len(available_routes) != len(set(available_routes))
        ):
            raise RetrievalRuntimeError("RETRIEVAL_GLOBAL_BINDING_INVALID")
        return cls(
            global_runtime_epoch=snapshot.global_runtime_epoch,
            global_tombstone_epoch=snapshot.tombstone_epoch,
            authorization_epoch=snapshot.authorization_epoch,
            authority_policy_ref=snapshot.policy_ref,
            roots=invocation.active.roots,
            available_routes=tuple(sorted(available_routes)),
            created_at=snapshot.created_at,
        )


class BoundClientScopeProvider(Protocol):
    """Resolve an internal client identity from one exact live binding."""

    def client_id_for_binding(self, binding: BoundTransport) -> str: ...

    def invoke_scoped_graph(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object: ...


class VectorEmbedderProvider(Protocol):
    """Return the already-installed offline embedder for one exact descriptor."""

    def __call__(self, descriptor: ModelDescriptor) -> Embedder: ...


class GenerationC1Provider(Protocol):
    """Resolve one trusted, policy-vocabulary-bound C1 state for a plan."""

    def is_available(
        self,
        *,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        active_artifacts: ActiveRetrievalArtifactSet,
    ) -> bool: ...

    def resolve(
        self,
        plan: QueryPlan,
        applicability_input: C1ApplicabilityInput,
        *,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        active_artifacts: ActiveRetrievalArtifactSet,
    ) -> GenerationC1Context: ...


class _ScopedRetriever(Protocol):
    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]: ...


class _CaseRetriever:
    """Fuse genuine governed case candidates from lexical and vector indexes."""

    def __init__(self, lexical: Retriever, vector: Retriever) -> None:
        if not callable(getattr(lexical, "search", None)) or not callable(
            getattr(vector, "search", None)
        ):
            raise TypeError("CASE_RETRIEVER_DELEGATE_REQUIRED")
        self._delegates = (("lexical", lexical), ("vector", vector))
        self._artifact_bindings: Mapping[str, object | None] = MappingProxyType(
            {
                name: getattr(delegate, "artifact_binding", None)
                for name, delegate in self._delegates
            }
        )

    @property
    def artifact_bindings(self) -> Mapping[str, object | None]:
        return self._artifact_bindings

    def search(
        self,
        query: str,
        scope: object,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        fetch_limit = min(1000, max(limit, limit * 8))
        ranked: dict[str, tuple[CandidateRef, dict[str, int]]] = {}
        for name, delegate in self._delegates:
            candidates = delegate.search(
                query,
                scope,
                authority_snapshot,
                limit=fetch_limit,
            )
            projected = tuple(
                candidate
                for candidate in candidates
                if candidate.channel == "case"
                and candidate.object_type == "case"
                and candidate.provenance.provenance_scope
                in {"case_derived", "mixed"}
            )
            for rank, candidate in enumerate(projected, start=1):
                key = retrieval_row_id(candidate)
                existing = ranked.get(key)
                if existing is None:
                    ranked[key] = candidate, {name: rank}
                    continue
                selected, ranks = existing
                if candidate_capability_payload(selected) != (
                    candidate_capability_payload(candidate)
                ):
                    raise RetrievalRuntimeError(
                        "CASE_RETRIEVER_CANDIDATE_CONFLICT"
                    )
                ranks[name] = min(ranks.get(name, rank), rank)

        ordered = sorted(
            ranked.items(),
            key=lambda item: (
                -sum(1.0 / (60.0 + rank) for rank in item[1][1].values()),
                min(item[1][1].values()),
                item[0],
            ),
        )
        return tuple(candidate for _key, (candidate, _ranks) in ordered[:limit])


# Minimal client-side graph protocol proposal.  These operations belong in
# ScopedWorkerBroker; no request contains a client ID, database path, or SQL.
CLIENT_GRAPH_WORKER_PROTOCOL_V1: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "query_client_graph": (
            "request_id",
            "session_id",
            "query",
            "as_of",
            "max_depth",
            "limit",
        ),
        "weighted_client_path": (
            "request_id",
            "session_id",
            "source_ref",
            "target_ref",
            "as_of",
            "max_paths",
            "max_hops",
        ),
        "preview_dependency_impact": (
            "request_id",
            "session_id",
            "target_ref",
            "action",
            "as_of",
        ),
    }
)


@dataclass(frozen=True, slots=True)
class _Invocation:
    active: ActiveRetrievalArtifactSet
    scope: RetrievalScope
    snapshot: AuthoritativeFilterSnapshot
    authority: AuthoritativeSnapshotRepository
    authority_connection: sqlite3.Connection


class ActiveGenerationRetrievalDependencyFactory:
    """Assemble P4 generation dependencies from one live active invocation."""

    def __init__(
        self,
        *,
        invocation: _Invocation,
        discovery: ActiveRetrievalArtifactDiscovery,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
        embedder_provider: VectorEmbedderProvider,
        c1_provider: GenerationC1Provider,
    ) -> None:
        self._invocation = invocation
        self._discovery = discovery
        self._global_connection = global_connection
        self._global_store = global_content_store
        self._embedder_provider = embedder_provider
        self._c1_provider = c1_provider

    def build(
        self,
        *,
        plan: QueryPlan,
        c1_applicability_input: C1ApplicabilityInput,
        active_artifacts: object,
        global_connection: sqlite3.Connection,
        global_content_store: ContentStore,
    ) -> GenerationRetrievalDependencies:
        if (
            active_artifacts is not self._invocation.active
            or global_connection is not self._global_connection
            or global_content_store is not self._global_store
        ):
            raise RetrievalRuntimeError("GENERATION_RETRIEVAL_SCOPE_MISMATCH")
        active = self._invocation.active
        try:
            c1 = GenerationC1Context.model_validate(
                self._c1_provider.resolve(
                    plan,
                    c1_applicability_input,
                    global_connection=self._global_connection,
                    global_content_store=self._global_store,
                    active_artifacts=active,
                ),
                strict=True,
            )
            vector_manifest = VectorBuildManifest.model_validate_json(
                active.vector.path_for("vector_build_manifest").read_bytes(),
                strict=True,
            )
            embedder = self._embedder_provider(vector_manifest.model_descriptor)
            if embedder.descriptor != vector_manifest.model_descriptor:
                raise ValueError("GENERATION_EMBEDDER_DESCRIPTOR_MISMATCH")
            wiki = WikiIndexRetriever(active.wiki_index)
            lexical = LexicalRetriever.from_artifact_binding(active.lexical)
            vector = ExactVectorRetriever.from_artifact_binding(
                active.vector,
                embedder=embedder,
            )
            graph_runtime = GlobalGraphRuntime.from_artifact_binding(
                active.graph,
                global_connection=self._global_connection,
            )
            graph = GlobalGraphRetriever(
                graph_runtime.artifact,
                artifact_binding=active.graph,
                edge_authority_resolver=graph_runtime.edge_authority_resolver,
                node_resolver=QueryMatchedGraphNodeResolver(
                    retrievers={
                        "wiki": cast(Retriever, wiki),
                        "lexical": cast(Retriever, lexical),
                    },
                    snapshot=self._invocation.snapshot,
                    graph=graph_runtime.artifact.graph,
                ),
                candidate_catalog=graph_runtime.candidate_catalog,
            )
            descriptor = embedder.descriptor
            descriptor_ref = VersionRef(
                object_id=deterministic_object_id(
                    "reranker_descriptor",
                    descriptor.id,
                ),
                version=1,
                content_sha256=descriptor.id,
            )
            explicit_refs = [
                descriptor_ref,
                c1.decision.scope_policy_ref,
            ]
            if c1.decision.revision is not None:
                explicit_refs.append(c1.decision.revision)
            closure = ActiveArtifactGlobalClosureVerifier(
                active,
                c1_context=c1,
                explicit_refs=tuple(explicit_refs),
            )
        except RetrievalRuntimeError:
            raise
        except Exception:
            raise RetrievalCapabilityUnavailable(
                "GENERATION_RETRIEVAL_DEPENDENCY_INVALID"
            ) from None
        retrievers: dict[str, Retriever] = {
            "wiki": cast(Retriever, wiki),
            "lexical": cast(Retriever, lexical),
            "vector": cast(Retriever, vector),
            "global_graph": cast(Retriever, graph),
            "case": cast(
                Retriever,
                _CaseRetriever(
                    cast(Retriever, lexical),
                    cast(Retriever, vector),
                ),
            ),
        }
        return GenerationRetrievalDependencies(
            global_snapshot_repository=self._invocation.authority,
            artifact_gate=ActiveRetrievalArtifactGate(self._discovery),
            global_retrievers=retrievers,
            global_content_reader=ScopedManifestContentReader(
                self._invocation.authority_connection,
                self._global_store,
                schema="main",
            ),
            semantics_resolver=ActiveC1CandidateSemantics(
                self._invocation.authority_connection,
                c1_context=c1,
            ),
            fusion=ReciprocalRankFusion(),
            reranker=EvidenceReranker(EmbeddingEvidenceReranker(embedder)),
            context_budget=ContextBudget(
                max_tokens=32_000,
                minimum_supporting=1,
                minimum_contradictions=0,
                minimum_alternatives=0,
                minimum_exact_quotes=0,
            ),
            token_counter=CharacterTokenCounter(),
            closure_verifier=closure,
            version_gate=ActiveArtifactVersionGate(
                self._global_connection,
                self._global_store,
            ),
            c1_context=c1,
            reranker_descriptor_ref=descriptor_ref,
            allowed_uses=frozenset({"consultation"}),
            maximum_sensitivity=3,
        )


def _ref(reference: VersionRef) -> dict[str, object]:
    return cast(dict[str, object], reference.model_dump(mode="json"))


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _member_ref(binding: ArtifactBinding, role: str) -> VersionRef:
    identity = binding.verify_current()
    members = tuple(member for member in identity.members if member.role == role)
    if len(members) != 1:
        raise RetrievalRuntimeError("RETRIEVAL_ARTIFACT_MEMBER_INVALID")
    member = members[0]
    return VersionRef(
        object_id=member.object_id,
        version=identity.source_catalog_version,
        content_sha256=member.content_sha256,
    )


def _authority_view(snapshot: AuthoritativeFilterSnapshot) -> dict[str, object]:
    """Project the exact snapshot without exposing its internal allowed set."""

    return {
        "run_id": snapshot.run_id,
        "global_runtime_epoch": snapshot.global_runtime_epoch,
        "client_runtime_epoch": snapshot.client_runtime_epoch,
        "tombstone_epoch": snapshot.tombstone_epoch,
        "authorization_epoch": snapshot.authorization_epoch,
        "policy_ref": _ref(snapshot.policy_ref),
        "created_at": snapshot.created_at,
        "scope": "global_only",
    }


def _safe_provenance(
    candidate: CandidateRef,
    *,
    exclusion_status: str,
) -> dict[str, object]:
    provenance = candidate.provenance
    return {
        "provenance_scope": provenance.provenance_scope,
        "derivation_rule_ref": _ref(provenance.derivation_rule_ref),
        "source_count": len(provenance.source_ids),
        "passage_count": len(provenance.passage_ids),
        "case_count": len(provenance.case_ids),
        "case_contributor_count": len(provenance.case_contributor_client_ids),
        "independent_source_count": len(provenance.source_ids | provenance.case_ids),
        "client_exclusion_status": exclusion_status,
    }


def _loo_replacements(
    candidates: tuple[CandidateRef, ...],
    *,
    current_client_id: str,
    contributor_identity_hasher: ContributorIdentityHasher | None = None,
    leave_one_out_verifier: LeaveOneOutAuthorityVerifier | None = None,
    scope: RetrievalScope | None = None,
    authority_snapshot: AuthoritativeFilterSnapshot | None = None,
) -> frozenset[tuple[str, int, str]]:
    result: set[tuple[str, int, str]] = set()
    for candidate in candidates:
        variant = candidate.metadata.leave_one_out
        if (
            is_current_client_contributor(
                current_client_id,
                candidate,
                contributor_identity_hasher=contributor_identity_hasher,
            )
            is True
            and variant is not None
            and leave_one_out_verifier is not None
            and scope is not None
            and authority_snapshot is not None
        ):
            try:
                exact = leave_one_out_verifier.is_exact_approved_variant(
                    original=candidate,
                    variant=variant,
                    scope=scope,
                    authority_snapshot=authority_snapshot,
                )
            except Exception:
                exact = False
            if exact is True:
                result.add(_ref_key(variant.reference))
    return frozenset(result)


def _decode_body(body: bytes) -> tuple[str | None, str]:
    try:
        return body.decode("utf-8", errors="strict"), "utf-8"
    except UnicodeDecodeError:
        return None, "binary_reference_only"


def _candidate_item(
    candidate: CandidateRef,
    body: bytes,
    *,
    loo_replacements: frozenset[tuple[str, int, str]],
) -> dict[str, object]:
    text, encoding = _decode_body(body)
    metadata = candidate.metadata
    return {
        "reference": _ref(candidate.reference),
        "content_ref": _ref(candidate.content_ref),
        "object_type": candidate.object_type,
        "channel": candidate.channel,
        "score": candidate.score,
        "score_components": tuple(
            component.model_dump(mode="json")
            for component in candidate.score_components
        ),
        "text": text,
        "content_encoding": encoding,
        "source_grade": metadata.source_grade,
        "framework_priority": metadata.framework_priority,
        "empirical_support": metadata.empirical_support,
        "review_status": metadata.review_status,
        "effective_from": metadata.effective_from,
        "effective_to": metadata.effective_to,
        "review_due_at": metadata.review_due_at,
        "sensitivity": metadata.sensitivity,
        "location": candidate.location.model_dump(mode="json"),
        "freshness": candidate.freshness.model_dump(mode="json"),
        "provenance": _safe_provenance(
            candidate,
            exclusion_status=(
                "leave_one_subject_out_applied"
                if _ref_key(candidate.reference) in loo_replacements
                else "no_subject_contribution"
            ),
        ),
    }


def _proof_view(decision: FilterDecision) -> dict[str, object]:
    proof = decision.proof
    return {
        "input_count": proof.input_count,
        "allowed_count": proof.allowed_count,
        "denied_count": proof.denied_count,
        "reasons": dict(proof.reasons),
    }


def _path_item(path: EvidencePath) -> dict[str, object]:
    return {
        "total_cost": path.total_cost,
        "cost_breakdown": dict(path.cost_breakdown),
        "node_refs": tuple(_ref(value) for value in path.node_refs),
        "edge_refs": tuple(_ref(value) for value in path.edge_refs),
        "contains_support": path.contains_support,
        "contains_contradiction": path.contains_contradiction,
        "source_limits": dict(path.source_limits),
        "graph_version": _ref(path.graph_version),
        "steps": tuple(
            {
                "source_node_ref": _ref(step.source_node_ref),
                "target_node_ref": _ref(step.target_node_ref),
                "relation_ref": _ref(step.relation_ref),
                "claim_ref": _ref(step.claim_ref),
                "passage_refs": tuple(_ref(value) for value in step.passage_refs),
                "source_refs": tuple(_ref(value) for value in step.source_refs),
                "relation": step.relation,
                "source_grade": step.source_grade,
                "truth_type": step.truth_type,
                "independent_source_count": step.independent_source_count,
                "restrictions": step.restrictions,
                "cost": {
                    "policy_version": step.cost.policy_version,
                    "components": dict(step.cost.components),
                    "total": step.cost.total,
                },
            }
            for step in path.steps
        ),
    }


def _open_global_authority_connection(path: Path) -> sqlite3.Connection:
    """Open the global DB read-only and attach only a new in-memory schema."""

    exact = path.resolve(strict=True)
    connection = sqlite3.connect(
        f"{exact.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=5.0,
    )
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        # Main remains URI mode=ro.  query_only is temporarily off solely to
        # define two empty tables in the fresh in-memory attachment.
        connection.execute("PRAGMA query_only = OFF")
        connection.execute("ATTACH DATABASE ':memory:' AS client_authority")
        connection.execute(
            "CREATE TABLE client_authority.runtime_epochs("
            "epoch INTEGER PRIMARY KEY, state TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE client_authority.tombstones("
            "target_type TEXT NOT NULL, target_id_hash TEXT NOT NULL, "
            "source_lineage_hash TEXT NOT NULL)"
        )
        connection.execute("PRAGMA query_only = ON")
        return connection
    except BaseException:
        connection.close()
        raise


@final
class ActiveRetrievalRuntime(ToolService):
    """Route MCP reads through one exact active P4 artifact closure."""

    def __init__(
        self,
        *,
        global_database: Path,
        global_connection: sqlite3.Connection,
        content_store: ContentStore,
        client_scopes: BoundClientScopeProvider,
        clock: Clock,
        id_factory: IdFactory,
        embedder_provider: VectorEmbedderProvider | None = None,
        generation_c1_provider: GenerationC1Provider | None = None,
        case_contributor_hash_key: bytes | None = None,
    ) -> None:
        if not isinstance(global_database, Path):
            raise TypeError("RETRIEVAL_GLOBAL_DATABASE_PATH_REQUIRED")
        if not isinstance(global_connection, sqlite3.Connection):
            raise TypeError("RETRIEVAL_GLOBAL_CONNECTION_REQUIRED")
        if type(content_store) is not ContentStore:
            raise TypeError("RETRIEVAL_CONTENT_STORE_REQUIRED")
        if not callable(getattr(client_scopes, "client_id_for_binding", None)):
            raise TypeError("RETRIEVAL_CLIENT_SCOPE_PROVIDER_REQUIRED")
        self._global_database = global_database.resolve(strict=True)
        self._global_connection = global_connection
        self._store = content_store
        self._scopes = client_scopes
        self._clock = clock
        self._ids = id_factory
        self._embedder_provider = embedder_provider
        if generation_c1_provider is not None and (
            not callable(getattr(generation_c1_provider, "resolve", None))
            or not callable(
                getattr(generation_c1_provider, "is_available", None)
            )
        ):
            raise TypeError("GENERATION_C1_PROVIDER_INVALID")
        self._generation_c1_provider = generation_c1_provider
        self._case_contributor_hasher = (
            None
            if case_contributor_hash_key is None
            else CaseContributorHasher(hash_key=case_contributor_hash_key)
        )
        self._discovery = ActiveRetrievalArtifactDiscovery(
            global_connection,
            content_store,
        )
        self._integrity = ActiveIntegrityGate(
            IntegrityStore(
                scope="global",
                connection=global_connection,
                content_store=content_store,
            )
        )
        self._lock = threading.RLock()
        self._closed = False

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def _active_references(
        self,
        active: ActiveRetrievalArtifactSet,
    ) -> tuple[tuple[ActiveArtifact, ...], tuple[ActiveArtifact, ...]]:
        operation = self._global_connection.execute(
            "SELECT operation_id, state FROM runtime_epochs WHERE epoch = ?",
            (active.active_runtime_epoch,),
        ).fetchone()
        if operation is None or str(operation[1]) != "ACTIVE":
            raise ArtifactUnavailable
        operation_id = str(operation[0])
        rows = self._global_connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (active.active_runtime_epoch,),
        ).fetchall()
        repository = ManifestRepository(self._global_connection)
        knowledge: list[ActiveArtifact] = []
        dedicated: list[ActiveArtifact] = []
        for row in rows:
            artifact_key = str(row[0])
            manifest = repository.get(str(row[1]))
            if (
                manifest.operation_id != operation_id
                or manifest.artifact_key != artifact_key
                or manifest.state != "ACTIVE"
                or not manifest.verified
            ):
                raise ArtifactUnavailable
            artifact = ActiveArtifact(
                artifact_key=artifact_key,
                manifest_ref=VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                ),
            )
            if (
                artifact_key in DEDICATED_ACTIVE_ARTIFACT_KEYS
                or manifest.artifact_kind in DEDICATED_ACTIVE_ARTIFACT_KEYS
            ):
                if artifact_key != manifest.artifact_kind:
                    raise ArtifactUnavailable
                dedicated.append(artifact)
            else:
                knowledge.append(artifact)
        expected_roots = {
            binding.identity.artifact_key: binding.identity.root_ref
            for binding in active.bindings()
        }
        actual_roots = {
            artifact.artifact_key: artifact.manifest_ref for artifact in knowledge
        }
        if any(actual_roots.get(key) != value for key, value in expected_roots.items()):
            raise ArtifactUnavailable
        return tuple(knowledge), tuple(dedicated)

    def _verify_active_integrity(
        self,
        active: ActiveRetrievalArtifactSet,
        *,
        authority_version: int,
        tombstone_epoch: int,
        authorization_epoch: int,
    ) -> None:
        try:
            artifacts, dedicated_artifacts = self._active_references(active)
            self._integrity.verify(
                epoch=active.active_runtime_epoch,
                artifacts=artifacts,
                dedicated_artifacts=dedicated_artifacts,
                source_version=active.source_catalog_version,
                authority_version=authority_version,
                tombstone_epoch=tombstone_epoch,
                authorization_epoch=authorization_epoch,
                content_probes=tuple(
                    binding.verify_current for binding in active.bindings()
                ),
            )
        except ArtifactUnavailable:
            raise RetrievalCapabilityUnavailable(
                ACTIVE_INTEGRITY_REBUILD_REQUIRED
            ) from None

    def _current_authority_epochs(
        self,
    ) -> tuple[int, int]:
        try:
            row = self._global_connection.execute(
                "SELECT authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if (
                row is None
                or type(row[0]) is not int
                or row[0] < 0
                or type(row[1]) is not int
                or row[1] < 0
            ):
                raise ValueError
            return int(row[0]), int(row[1])
        except Exception:
            raise RetrievalCapabilityUnavailable(
                ACTIVE_INTEGRITY_REBUILD_REQUIRED
            ) from None

    def verify_startup_integrity(self) -> bool:
        """Verify a configured ACTIVE set before MCP handlers are installed.

        A clean database without an active set may start with retrieval
        unavailable.  Any partially present or corrupt active state is a hard
        startup failure carrying an explicit rebuild-required reason.
        """

        with self._lock:
            if self._closed:
                raise RetrievalCapabilityUnavailable(
                    "RETRIEVAL_RUNTIME_CLOSED"
                )
            try:
                active = self._discovery.discover_current_set()
            except Exception:
                raise RetrievalCapabilityUnavailable(
                    ACTIVE_INTEGRITY_REBUILD_REQUIRED
                ) from None
            if active is None:
                return False
            builder_input = self._builder_input(active)
            authorization_epoch, tombstone_epoch = self._current_authority_epochs()
            self._verify_active_integrity(
                active,
                authority_version=builder_input.authority_catalog_version,
                tombstone_epoch=tombstone_epoch,
                authorization_epoch=authorization_epoch,
            )
            return True

    def _require_binding(self, binding: BoundTransport | None) -> BoundTransport:
        if binding is None:
            raise RetrievalCapabilityUnavailable("RETRIEVAL_SESSION_SCOPE_REQUIRED")
        return binding

    def generation_global_binding(
        self,
        *,
        binding: BoundTransport | None,
    ) -> GenerationGlobalBinding:
        """Freeze and return the public, client-ID-free QueryPlan binding."""

        with self._lock:
            with self._invocation(
                binding,
                allowed_use="consultation",
            ) as invocation:
                return GenerationGlobalBinding.from_invocation(
                    invocation,
                    available_routes=self._generation_available_routes(invocation),
                )

    def _generation_available_routes(
        self,
        invocation: _Invocation,
    ) -> tuple[EvidenceChannel, ...]:
        if (
            self._embedder_provider is None
            or self._generation_c1_provider is None
        ):
            return ()
        try:
            vector_manifest = VectorBuildManifest.model_validate_json(
                invocation.active.vector.path_for(
                    "vector_build_manifest"
                ).read_bytes(),
                strict=True,
            )
            embedder = self._embedder_provider(vector_manifest.model_descriptor)
            if embedder.descriptor != vector_manifest.model_descriptor:
                return ()
            if not self._generation_c1_provider.is_available(
                global_connection=self._global_connection,
                global_content_store=self._store,
                active_artifacts=invocation.active,
            ):
                return ()
        except Exception:
            return ()
        return (
            "profile",
            "client_history",
            "wiki",
            "lexical",
            "vector",
            "global_graph",
            "case",
        )

    def retrieve_generation_plan(
        self,
        plan: QueryPlan,
        client_binding: GenerationClientBinding,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        *,
        binding: BoundTransport | None,
        revalidate_binding: Callable[[], GenerationClientBinding],
        c1_applicability_input: C1ApplicabilityInput | None = None,
        risk_context_binding: GenerationRiskContextBinding | None = None,
    ) -> GenerationRetrievalOutcome:
        exact_binding = self._require_binding(binding)
        if (
            self._embedder_provider is None
            or self._generation_c1_provider is None
        ):
            raise RetrievalCapabilityUnavailable(
                "GENERATION_RETRIEVAL_DEPENDENCY_UNAVAILABLE"
            )
        client_id = self._scopes.client_id_for_binding(exact_binding)
        with self._lock:
            with self._invocation(
                exact_binding,
                allowed_use="consultation",
                effective_at=plan.envelope.created_at,
            ) as invocation:
                if not self._generation_available_routes(invocation):
                    raise RetrievalCapabilityUnavailable(
                        "GENERATION_RETRIEVAL_DEPENDENCY_UNAVAILABLE"
                    )
                factory = ActiveGenerationRetrievalDependencyFactory(
                    invocation=invocation,
                    discovery=self._discovery,
                    global_connection=self._global_connection,
                    global_content_store=self._store,
                    embedder_provider=self._embedder_provider,
                    c1_provider=self._generation_c1_provider,
                )
                orchestrator = GenerationRetrievalOrchestrator(
                    active_artifacts=invocation.active,
                    global_connection=self._global_connection,
                    global_content_store=self._store,
                    dependency_factory=factory,
                    contributor_identity_hasher=self._case_contributor_hasher,
                    leave_one_out_verifier=(
                        None
                        if self._case_contributor_hasher is None
                        else SqliteLeaveOneOutAuthorityVerifier(
                            self._global_connection,
                            contributor_hasher=self._case_contributor_hasher,
                        )
                    ),
                )
                if c1_applicability_input is None:
                    return orchestrator.retrieve(
                        plan,
                        client_id,
                        client_binding,
                        private_evidence,
                        revalidate_binding,
                        risk_context_binding=risk_context_binding,
                    )
                return orchestrator.retrieve(
                    plan,
                    client_id,
                    client_binding,
                    private_evidence,
                    revalidate_binding,
                    c1_applicability_input=c1_applicability_input,
                    risk_context_binding=risk_context_binding,
                )

    @staticmethod
    def _builder_input(active: ActiveRetrievalArtifactSet) -> DerivedArtifactBuilderInputV2:
        try:
            return DerivedArtifactBuilderInputV2.model_validate_json(
                active.lexical.path_for("lexical_builder_input").read_bytes(),
                strict=True,
            )
        except Exception:
            raise RetrievalRuntimeError("RETRIEVAL_BUILDER_INPUT_INVALID") from None

    @contextmanager
    def _invocation(
        self,
        binding: BoundTransport | None,
        *,
        allowed_use: str,
        effective_at: datetime | None = None,
    ) -> Iterator[_Invocation]:
        exact_binding = self._require_binding(binding)
        if self._closed:
            raise RetrievalCapabilityUnavailable("RETRIEVAL_RUNTIME_CLOSED")
        client_id = self._scopes.client_id_for_binding(exact_binding)
        try:
            active = self._discovery.discover_current_set()
        except Exception:
            raise RetrievalCapabilityUnavailable(
                ACTIVE_INTEGRITY_REBUILD_REQUIRED
            ) from None
        if active is None:
            raise RetrievalCapabilityUnavailable("RETRIEVAL_ARTIFACT_UNAVAILABLE")
        builder_input = self._builder_input(active)
        authorization_epoch, tombstone_epoch = self._current_authority_epochs()
        self._verify_active_integrity(
            active,
            authority_version=builder_input.authority_catalog_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
        )
        policy_ref = builder_input.retrieval_input_descriptor.route_policy_ref
        authority_connection = _open_global_authority_connection(
            self._global_database
        )
        authority = AuthoritativeSnapshotRepository(
            authority_connection,
            policy_ref_provider=lambda: policy_ref,
            clock=self._clock,
            id_factory=self._ids,
            global_content_store=self._store,
        )
        at = self._clock.now() if effective_at is None else effective_at
        scope = RetrievalScope(
            current_client_id=client_id,
            allowed_uses=frozenset({allowed_use}),
            maximum_sensitivity=3,
            effective_at=at,
            known_at=self._clock.now(),
        )
        try:
            snapshot = authority.freeze(scope)
            if snapshot.global_runtime_epoch != active.active_runtime_epoch:
                raise RetrievalRuntimeError("RETRIEVAL_AUTHORITY_EPOCH_MISMATCH")
            if snapshot.tombstone_epoch & 0xFFFFFFFF:
                raise RetrievalRuntimeError("RETRIEVAL_AUTHORITY_SCOPE_MISMATCH")
            self._verify_active_integrity(
                active,
                authority_version=builder_input.authority_catalog_version,
                tombstone_epoch=snapshot.tombstone_epoch >> 32,
                authorization_epoch=snapshot.authorization_epoch,
            )
            yield _Invocation(
                active,
                scope,
                snapshot,
                authority,
                authority_connection,
            )
            authority.assert_snapshot_current(snapshot)
            self._verify_active_integrity(
                active,
                authority_version=builder_input.authority_catalog_version,
                tombstone_epoch=snapshot.tombstone_epoch >> 32,
                authorization_epoch=snapshot.authorization_epoch,
            )
        finally:
            authority.close()

    @staticmethod
    def _fetch_limit(limit: int) -> int:
        return min(1000, max(100, limit * 10))

    def _vector(
        self,
        binding: ArtifactBinding,
    ) -> ExactVectorRetriever:
        if self._embedder_provider is None:
            raise RetrievalCapabilityUnavailable("VECTOR_MODEL_UNAVAILABLE")
        try:
            manifest = VectorBuildManifest.model_validate_json(
                binding.path_for("vector_build_manifest").read_bytes(),
                strict=True,
            )
            embedder = self._embedder_provider(manifest.model_descriptor)
            return ExactVectorRetriever.from_artifact_binding(
                binding,
                embedder=embedder,
            )
        except RetrievalCapabilityUnavailable:
            raise
        except Exception:
            raise RetrievalCapabilityUnavailable("VECTOR_MODEL_UNAVAILABLE") from None

    def _search_result(
        self,
        invocation: _Invocation,
        *,
        channel: str,
        artifact: ArtifactBinding,
        candidates: tuple[CandidateRef, ...],
        limit: int,
        candidate_pool_saturated: bool,
        current_client_id: str,
    ) -> dict[str, object]:
        leave_one_out_verifier = (
            None
            if self._case_contributor_hasher is None
            else SqliteLeaveOneOutAuthorityVerifier(
                invocation.authority_connection,
                contributor_hasher=self._case_contributor_hasher,
            )
        )
        replacements = _loo_replacements(
            candidates,
            current_client_id=current_client_id,
            contributor_identity_hasher=self._case_contributor_hasher,
            leave_one_out_verifier=leave_one_out_verifier,
            scope=invocation.scope,
            authority_snapshot=invocation.snapshot,
        )
        decision = CandidateFilter(
            invocation.authority,
            contributor_identity_hasher=self._case_contributor_hasher,
            leave_one_out_verifier=leave_one_out_verifier,
        ).filter(
            invocation.scope,
            candidates,
            invocation.snapshot,
        )
        reader = ScopedManifestContentReader(
            invocation.authority_connection,
            self._store,
            schema="main",
        )
        resolved = EvidenceResolver(invocation.authority, reader).resolve_many(
            decision.allowed
        )
        selected = resolved[:limit]
        return {
            "status": "ok" if selected else "no_matches",
            "channel": channel,
            "authority": _authority_view(invocation.snapshot),
            "artifact_root": _ref(artifact.identity.root_ref),
            "count": len(selected),
            "items": tuple(
                _candidate_item(
                    item.candidate,
                    item.body,
                    loo_replacements=replacements,
                )
                for item in selected
            ),
            "exclusion": _proof_view(decision),
            "candidate_pool_saturated": candidate_pool_saturated,
        }

    def _search(
        self,
        tool_name: str,
        request: SearchWikiInput | SearchLexicalInput | SearchVectorInput,
        *,
        binding: BoundTransport | None,
    ) -> dict[str, object]:
        exact_binding = self._require_binding(binding)
        client_id = self._scopes.client_id_for_binding(exact_binding)
        with self._invocation(binding, allowed_use="consultation") as invocation:
            fetch_limit = self._fetch_limit(request.limit)
            if tool_name == "search_wiki":
                artifact = invocation.active.wiki_index
                retriever: _ScopedRetriever = WikiIndexRetriever(artifact)
                channel = "wiki"
            elif tool_name == "search_lexical":
                artifact = invocation.active.lexical
                retriever = LexicalRetriever.from_artifact_binding(artifact)
                channel = "lexical"
            else:
                artifact = invocation.active.vector
                retriever = self._vector(artifact)
                channel = "vector"
            candidates = retriever.search(
                request.query,
                invocation.scope,
                invocation.snapshot,
                limit=fetch_limit,
            )
            return self._search_result(
                invocation,
                channel=channel,
                artifact=artifact,
                candidates=candidates,
                limit=request.limit,
                candidate_pool_saturated=len(candidates) == fetch_limit,
                current_client_id=client_id,
            )

    def _search_cases(
        self,
        request: SearchCasesInput,
        *,
        binding: BoundTransport | None,
    ) -> dict[str, object]:
        exact_binding = self._require_binding(binding)
        client_id = self._scopes.client_id_for_binding(exact_binding)
        with self._invocation(
            binding,
            allowed_use="answer_support",
        ) as invocation:
            artifact = invocation.active.lexical
            fetch_limit = self._fetch_limit(request.limit)
            candidates = _CaseRetriever(
                cast(
                    Retriever,
                    LexicalRetriever.from_artifact_binding(artifact),
                ),
                cast(Retriever, self._vector(invocation.active.vector)),
            ).search(
                request.query,
                invocation.scope,
                invocation.snapshot,
                limit=fetch_limit,
            )
            return self._search_result(
                invocation,
                channel="cases",
                artifact=artifact,
                candidates=candidates,
                limit=request.limit,
                candidate_pool_saturated=len(candidates) == fetch_limit,
                current_client_id=client_id,
            )

    @staticmethod
    def _graph_query(
        runtime: GlobalGraphRuntime,
        invocation: _Invocation,
        *,
        source: str,
        target: str,
        max_hops: int,
        top_k: int,
    ) -> tuple[EvidencePath, ...]:
        graph_version = _member_ref(runtime.artifact_binding, "global_graph")
        edge_binding = runtime.edge_authority_resolver.resolve(
            runtime.artifact,
            scope=invocation.scope,
            authority_snapshot=invocation.snapshot,
            required_use="consultation",
            graph_root_ref=runtime.artifact_binding.identity.root_ref,
            graph_version=graph_version,
        )
        query = WeightedPathQuery(
            runtime.artifact,
            graph_version=graph_version,
            edge_authority_resolver=runtime.edge_authority_resolver,
        )
        return query.search(
            source,
            target,
            context=PathCostContext(
                effective_at=invocation.scope.effective_at,
                required_use="consultation",
            ),
            authority_snapshot=invocation.snapshot,
            scope=invocation.scope,
            edge_authority_binding=edge_binding,
            max_hops=max_hops,
            top_k=top_k,
            max_expansions=25_000,
            max_candidates=max(100, top_k),
        )

    def _query_global_graph(
        self,
        request: QueryGlobalGraphInput,
        *,
        binding: BoundTransport | None,
    ) -> dict[str, object]:
        with self._invocation(binding, allowed_use="consultation") as invocation:
            fetch_limit = self._fetch_limit(request.limit)
            wiki = WikiIndexRetriever(invocation.active.wiki_index).search(
                request.query,
                invocation.scope,
                invocation.snapshot,
                limit=fetch_limit,
            )
            lexical = LexicalRetriever.from_artifact_binding(
                invocation.active.lexical
            ).search(
                request.query,
                invocation.scope,
                invocation.snapshot,
                limit=fetch_limit,
            )
            ranked: dict[tuple[str, int, str, str, int, str], CandidateRef] = {}
            for candidate in (*wiki, *lexical):
                key = (*_ref_key(candidate.reference), *_ref_key(candidate.content_ref))
                previous = ranked.get(key)
                if previous is None or candidate.score > previous.score:
                    ranked[key] = candidate
            raw = tuple(
                value
                for _key, value in sorted(
                    ranked.items(),
                    key=lambda item: (-item[1].score, item[0]),
                )
            )
            decision = CandidateFilter(
                invocation.authority,
                contributor_identity_hasher=self._case_contributor_hasher,
                leave_one_out_verifier=(
                    None
                    if self._case_contributor_hasher is None
                    else SqliteLeaveOneOutAuthorityVerifier(
                        invocation.authority_connection,
                        contributor_hasher=self._case_contributor_hasher,
                    )
                ),
            ).filter(
                invocation.scope,
                raw,
                invocation.snapshot,
            )
            claim_refs = frozenset(
                _ref_key(candidate.reference) for candidate in decision.allowed
            )
            runtime = GlobalGraphRuntime.from_artifact_binding(
                invocation.active.graph,
                global_connection=self._global_connection,
            )
            pairs = tuple(
                sorted(
                    {
                        (str(source), str(target))
                        for source, target, attributes in runtime.artifact.graph.edges(
                            data=True
                        )
                        if isinstance(attributes.get("claim_ref"), VersionRef)
                        and _ref_key(cast(VersionRef, attributes["claim_ref"]))
                        in claim_refs
                    }
                )
            )
            paths: list[EvidencePath] = []
            seen: set[tuple[str, ...]] = set()
            for source, target in pairs:
                for path in self._graph_query(
                    runtime,
                    invocation,
                    source=source,
                    target=target,
                    max_hops=request.max_depth,
                    top_k=min(20, request.limit),
                ):
                    path_key = tuple(path.edge_ids)
                    if path_key not in seen:
                        seen.add(path_key)
                        paths.append(path)
            paths.sort(key=lambda item: (item.total_cost, item.edge_ids))
            selected = tuple(paths[: request.limit])
            return {
                "status": "ok" if selected else "no_matches",
                "channel": "global_graph",
                "authority": _authority_view(invocation.snapshot),
                "artifact_root": _ref(invocation.active.graph.identity.root_ref),
                "count": len(selected),
                "items": tuple(_path_item(value) for value in selected),
                "exclusion": _proof_view(decision),
                "matched_endpoint_pairs": len(pairs),
                "candidate_pool_saturated": (
                    len(wiki) == fetch_limit or len(lexical) == fetch_limit
                ),
            }

    def _weighted_global_path(
        self,
        request: WeightedPathInput,
        *,
        binding: BoundTransport | None,
    ) -> dict[str, object]:
        requested_hops = request.max_hops
        effective_hops = min(12, requested_hops)
        with self._invocation(
            binding,
            allowed_use="consultation",
            effective_at=request.as_of,
        ) as invocation:
            runtime = GlobalGraphRuntime.from_artifact_binding(
                invocation.active.graph,
                global_connection=self._global_connection,
            )
            paths = self._graph_query(
                runtime,
                invocation,
                source=request.source_ref,
                target=request.target_ref,
                max_hops=effective_hops,
                top_k=request.max_paths,
            )
            return {
                "status": (
                    "partial_runtime_limit"
                    if requested_hops != effective_hops
                    else "ok" if paths else "no_matches"
                ),
                "channel": "global_graph_weighted_path",
                "authority": _authority_view(invocation.snapshot),
                "artifact_root": _ref(invocation.active.graph.identity.root_ref),
                "requested_max_hops": requested_hops,
                "effective_max_hops": effective_hops,
                "count": len(paths),
                "items": tuple(_path_item(value) for value in paths),
            }

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        with self._lock:
            if tool_name in {"search_wiki", "search_lexical", "search_vector"}:
                return self._search(
                    tool_name,
                    cast(
                        SearchWikiInput | SearchLexicalInput | SearchVectorInput,
                        request,
                    ),
                    binding=binding,
                )
            if tool_name == "search_cases":
                return self._search_cases(
                    cast(SearchCasesInput, request),
                    binding=binding,
                )
            if tool_name == "query_global_graph":
                return self._query_global_graph(
                    cast(QueryGlobalGraphInput, request),
                    binding=binding,
                )
            if tool_name == "weighted_path":
                values = cast(WeightedPathInput, request)
                if values.graph_scope == "global":
                    return self._weighted_global_path(values, binding=binding)
                return self._scopes.invoke_scoped_graph(
                    tool_name,
                    values,
                    binding=binding,
                )
            if tool_name == "query_client_graph":
                return self._scopes.invoke_scoped_graph(
                    tool_name,
                    cast(QueryClientGraphInput, request),
                    binding=binding,
                )
            if tool_name == "preview_dependency_impact":
                return self._scopes.invoke_scoped_graph(
                    tool_name,
                    cast(PreviewDependencyImpactInput, request),
                    binding=binding,
                )
            raise RetrievalCapabilityUnavailable("RETRIEVAL_TOOL_UNAVAILABLE")


def build_active_retrieval_runtime(
    *,
    config: AppConfig,
    connection: sqlite3.Connection,
    client_scopes: BoundClientScopeProvider,
    clock: Clock,
    id_factory: IdFactory,
    embedder_provider: VectorEmbedderProvider | None = None,
    generation_c1_provider: GenerationC1Provider | None = None,
    case_contributor_hash_key: bytes | None = None,
) -> ActiveRetrievalRuntime:
    """Build the integrable read/graph service without a client DB handle."""

    if type(config) is not AppConfig:
        raise TypeError("RETRIEVAL_CONFIG_REQUIRED")
    layout = VaultLayout.from_config(config)  # type: ignore[attr-defined]
    return ActiveRetrievalRuntime(
        global_database=layout.global_db,
        global_connection=connection,
        content_store=ContentStore(config.vault_root / "global"),
        client_scopes=client_scopes,
        clock=clock,
        id_factory=id_factory,
        embedder_provider=embedder_provider,
        generation_c1_provider=generation_c1_provider,
        case_contributor_hash_key=case_contributor_hash_key,
    )


__all__ = [
    "ACTIVE_INTEGRITY_REBUILD_REQUIRED",
    "ActiveRetrievalRuntime",
    "ActiveGenerationRetrievalDependencyFactory",
    "BoundClientScopeProvider",
    "CLIENT_GRAPH_WORKER_PROTOCOL_V1",
    "GenerationC1Provider",
    "GenerationGlobalBinding",
    "RetrievalCapabilityUnavailable",
    "RetrievalRuntimeError",
    "VectorEmbedderProvider",
    "build_active_retrieval_runtime",
]
