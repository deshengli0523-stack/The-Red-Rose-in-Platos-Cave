"""Atomic combined activation of approved knowledge artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pydantic import ValidationError
import numpy as np

from consultation_kb.graph.artifact_contracts import (
    GraphBuildClosureError,
    GraphEdgeAuthorityCatalogPayload,
    verify_graph_member_payloads,
)
from consultation_kb.graph.global_builder import claim_relation_sha256
from consultation_kb.lifecycle.publish import PublicationOperation
from consultation_kb.models.common import VersionRef
from consultation_kb.models.theory import TheoryRevision
from consultation_kb.retrieval.artifact_contracts import (
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    DerivedAuthoritySnapshotV2,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
    retrieval_row_id,
)
from consultation_kb.retrieval.artifact_publication import (
    RetrievalArtifactPublicationError,
    validate_builder_manifest_binding,
)
from consultation_kb.retrieval.authority_descriptor import (
    AuthorityDescriptorError,
    AuthorityManifestMember,
    RebuiltPublicationAuthority,
    rebuild_publication_authority,
)
from consultation_kb.retrieval.contracts import CandidateRef, canonical_json_bytes
from consultation_kb.retrieval.embeddings import EmbeddingContractError, validate_matrix
from consultation_kb.retrieval.lexical_builder import LexicalBuildManifest
from consultation_kb.retrieval.vector_builder import VectorBuildManifest
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexPayloadV2
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.vault.content_store import ContentStore, ContentStoreError

from ._canonical import canonical_sha256
from .theory import TheoryGovernanceError, TheoryRevisionService
from .wiki import WikiGovernanceError, WikiRevisionService


class PublicationCoordinator(Protocol):
    def verify(self, operation_id: str) -> PublicationOperation: ...

    def activate(self, operation_id: str) -> PublicationOperation: ...


class KnowledgePublicationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _DerivedManifestView:
    kind: DerivedArtifactKind
    manifest_ref: VersionRef
    members: dict[str, AuthorityManifestMember]
    payloads: dict[str, bytes]
    builder_input: DerivedArtifactBuilderInputV2


_DERIVED_KINDS: tuple[DerivedArtifactKind, ...] = (
    "wiki_index",
    "knowledge_registry",
    "graph",
    "lexical",
    "vector",
)


class KnowledgePublicationService:
    """The sole C1/Wiki activation entry point.

    When supplied a real P1 ``PublishCoordinator`` and its SQLite connection,
    the runtime epoch switch and authority-row status changes share one
    transaction.  The in-memory service projections update only after commit.
    """

    def __init__(
        self,
        *,
        coordinator: PublicationCoordinator,
        theory_service: TheoryRevisionService,
        wiki_service: WikiRevisionService,
        connection: sqlite3.Connection | None = None,
        required_artifact_kinds: Iterable[str] = (
            "wiki_page",
            "wiki_index",
            "knowledge_registry",
            "c1_revision",
            "claims",
            "graph",
            "lexical",
            "vector",
        ),
        lint_error_count: Callable[[], int] | None = None,
        failure_hook: Callable[[str], None] | None = None,
        content_store: ContentStore | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._theories = theory_service
        self._wikis = wiki_service
        self._connection = connection
        self._required = frozenset(required_artifact_kinds)
        self._lint_errors = lint_error_count
        self._failure_hook = failure_hook
        self._content_store = content_store

    def _hook(self, phase: str) -> None:
        if self._failure_hook is not None:
            self._failure_hook(phase)

    def _write_context(self) -> AbstractContextManager[sqlite3.Connection | None]:
        if self._connection is None:
            return nullcontext(None)
        if self._connection.in_transaction:
            return nullcontext(self._connection)
        return transaction(self._connection)

    def _verify_closure(self, operation_id: str) -> PublicationOperation:
        if self._connection is not None and self._lint_errors is None:
            raise KnowledgePublicationError("KNOWLEDGE_LINTER_REQUIRED")
        if self._lint_errors is not None and self._lint_errors() > 0:
            raise KnowledgePublicationError("KNOWLEDGE_LINT_ERRORS")
        operation = self._coordinator.verify(operation_id)
        if operation.state != "VERIFIED":
            raise KnowledgePublicationError("KNOWLEDGE_CLOSURE_NOT_VERIFIED")
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_CLOSURE_KINDS_UNAVAILABLE")
        rows = self._connection.execute(
            "SELECT artifact_kind, COUNT(*) FROM artifact_manifests "
            "WHERE operation_id = ? GROUP BY artifact_kind",
            (operation_id,),
        ).fetchall()
        counts = {str(row[0]): int(row[1]) for row in rows}
        if any(count > 1 for count in counts.values()):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_MANIFEST_CARDINALITY_INVALID"
            )
        if set(counts) != self._required or any(
            count != 1 for count in counts.values()
        ):
            raise KnowledgePublicationError("KNOWLEDGE_CLOSURE_INCOMPLETE")
        return operation

    def _manifest_members(
        self, operation_id: str
    ) -> dict[str, set[tuple[str, str, str]]]:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_BINDING_UNAVAILABLE")
        grouped: dict[str, set[tuple[str, str, str]]] = {}
        for row in self._connection.execute(
            """
            SELECT m.artifact_kind, a.object_type, a.object_id,
                   a.source_version, a.object_sha256
              FROM artifact_manifests AS m
              JOIN artifact_members AS a ON a.manifest_id = m.manifest_id
             WHERE m.operation_id = ?
            """,
            (operation_id,),
        ):
            grouped.setdefault(str(row[0]), set()).add(
                (str(row[1]), str(row[2]), str(row[4]))
            )
        return grouped

    def _governed_authority_refs(
        self,
        *,
        wiki_id: str,
        wiki_revision: int,
    ) -> tuple[tuple[VersionRef, ...], tuple[VersionRef, ...]]:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_BINDING_UNAVAILABLE")
        try:
            target = self._wikis.get(wiki_id, wiki_revision)
        except WikiGovernanceError as error:
            raise KnowledgePublicationError(f"KNOWLEDGE_{error.code}") from None
        active_rows = self._connection.execute(
            "SELECT wiki_id, revision FROM wiki_revisions "
            "WHERE review_status = 'ACTIVE' ORDER BY wiki_id, revision"
        ).fetchall()
        try:
            wikis = {
                str(row[0]): self._wikis.get(str(row[0]), int(row[1]))
                for row in active_rows
                if str(row[0]) != wiki_id
            }
        except WikiGovernanceError as error:
            raise KnowledgePublicationError(f"KNOWLEDGE_{error.code}") from None
        wikis[wiki_id] = target
        wiki_refs = tuple(
            VersionRef(
                object_id=value.wiki_id,
                version=value.revision,
                content_sha256=value.body_sha256,
            )
            for _key, value in sorted(wikis.items())
        )
        semantic_theories = {
            reference.object_id: reference
            for value in wikis.values()
            for reference in value.theory_revision_refs
        }
        if len(semantic_theories) != len(
            {
                (reference.object_id, reference.version, reference.content_sha256)
                for value in wikis.values()
                for reference in value.theory_revision_refs
            }
        ):
            raise KnowledgePublicationError("KNOWLEDGE_THEORY_VERSION_CONFLICT")
        theory_refs: list[VersionRef] = []
        for theory_id, reference in sorted(semantic_theories.items()):
            row = self._connection.execute(
                "SELECT revision_object_ref FROM theory_revisions "
                "WHERE theory_id = ? AND revision = ? "
                "AND status IN ('PREPARED', 'ACTIVE')",
                (theory_id, reference.version),
            ).fetchone()
            if row is None:
                raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_ROW_MISSING")
            theory_refs.append(
                VersionRef(
                    object_id=theory_id,
                    version=reference.version,
                    content_sha256=_content_digest(str(row[0])),
                )
            )
        return wiki_refs, tuple(theory_refs)

    def _verify_authority_binding(
        self,
        operation_id: str,
        *,
        theory_id: str | None,
        theory_revision: int | None,
        wiki_id: str,
        wiki_revision: int,
    ) -> None:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_BINDING_UNAVAILABLE")
        members = self._manifest_members(operation_id)
        wiki_refs, theory_refs = self._governed_authority_refs(
            wiki_id=wiki_id,
            wiki_revision=wiki_revision,
        )
        expected_wiki = {
            ("wiki", reference.object_id, reference.content_sha256)
            for reference in wiki_refs
        }
        if members.get("wiki_page", set()) != expected_wiki:
            raise KnowledgePublicationError("KNOWLEDGE_WIKI_CLOSURE_MISMATCH")

        expected_theory = {
            ("theory", reference.object_id, reference.content_sha256)
            for reference in theory_refs
        }
        if members.get("c1_revision", set()) != expected_theory:
            raise KnowledgePublicationError("KNOWLEDGE_C1_CLOSURE_MISMATCH")
        expected_c1_claims: set[tuple[str, str, str]] = set()
        for reference in theory_refs:
            expected_c1_claims.update(
                ("claim", str(row[0]), str(row[2]))
                for row in self._connection.execute(
                    "SELECT claim_id, version, claim_sha256 FROM claims "
                    "WHERE source_grade = 'C1' AND theory_revision_id = ? "
                    "AND theory_revision = ?",
                    (reference.object_id, reference.version),
                )
            )
        wiki_claims: set[tuple[str, str, str]] = set()
        for reference in wiki_refs:
            wiki_claims.update(
                ("claim", str(row[0]), str(row[2]))
                for row in self._connection.execute(
                    "SELECT DISTINCT c.claim_id, c.version, c.claim_sha256 "
                    "FROM wiki_revision_claims AS wc JOIN claims AS c "
                    "ON c.claim_id = wc.claim_id AND c.version = wc.claim_version "
                    "WHERE wc.wiki_id = ? AND wc.wiki_revision = ?",
                    (reference.object_id, reference.version),
                )
            )
        claim_members = {
            (object_type, object_id, object_sha256)
            for object_type, object_id, object_sha256 in members.get("claims", set())
        }
        expected_claims = wiki_claims | expected_c1_claims
        if claim_members != expected_claims:
            raise KnowledgePublicationError("KNOWLEDGE_CLAIM_CLOSURE_MISMATCH")
        if theory_id is not None and theory_revision is not None:
            invalid_claim_count = self._connection.execute(
                """
                SELECT COUNT(DISTINCT c.claim_id || ':' || c.version)
                  FROM wiki_revision_claims AS wc
                  JOIN claims AS c
                    ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
                 WHERE wc.wiki_id = ? AND wc.wiki_revision = ? AND (
                       c.privacy_scope = 'PRIVATE'
                    OR (c.source_grade = 'C1' AND (
                           c.review_status <> 'REVIEWED'
                        OR c.theory_revision_id <> ?
                        OR c.theory_revision <> ?
                    ))
                    OR (c.source_grade <> 'C1' AND c.review_status <> 'APPROVED')
                 )
                """,
                (wiki_id, wiki_revision, theory_id, theory_revision),
            ).fetchone()
            if invalid_claim_count is None or int(invalid_claim_count[0]) != 0:
                raise KnowledgePublicationError("KNOWLEDGE_CLAIM_NOT_PUBLISHABLE")

    @staticmethod
    def _lineage_hashes(raw: object) -> tuple[str, ...]:
        try:
            parsed = json.loads(str(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise KnowledgePublicationError("KNOWLEDGE_MANIFEST_MEMBER_INVALID") from None
        if (
            type(parsed) is not list
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in parsed
            )
            or parsed != sorted(set(parsed))
            or str(raw)
            != json.dumps(parsed, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        ):
            raise KnowledgePublicationError("KNOWLEDGE_MANIFEST_MEMBER_INVALID")
        return tuple(parsed)

    def _load_manifest(
        self,
        operation: PublicationOperation,
        artifact_kind: str,
    ) -> tuple[VersionRef, tuple[AuthorityManifestMember, ...]]:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_UNAVAILABLE")
        rows = self._connection.execute(
            "SELECT manifest_id, artifact_key, source_version, manifest_sha256, "
            "state, verified FROM artifact_manifests "
            "WHERE operation_id = ? AND artifact_kind = ?",
            (operation.operation_id, artifact_kind),
        ).fetchall()
        if len(rows) != 1:
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_MANIFEST_CARDINALITY_INVALID"
            )
        row = rows[0]
        manifest_id = str(row[0])
        if (
            str(row[1]) != artifact_kind
            or str(row[2]) != str(operation.authority_base_version)
            or str(row[4]) != "VERIFIED"
            or int(row[5]) != 1
        ):
            raise KnowledgePublicationError("KNOWLEDGE_ARTIFACT_VERSION_MISMATCH")
        member_rows = self._connection.execute(
            "SELECT ordinal, object_type, object_id, object_sha256, "
            "source_version, source_lineage_json, media_type, size_bytes "
            "FROM artifact_members WHERE manifest_id = ? ORDER BY ordinal",
            (manifest_id,),
        ).fetchall()
        if tuple(int(member[0]) for member in member_rows) != tuple(
            range(len(member_rows))
        ):
            raise KnowledgePublicationError("KNOWLEDGE_MANIFEST_MEMBER_INVALID")
        authority_members: list[AuthorityManifestMember] = []
        manifest_members: list[ManifestMember] = []
        for member in member_rows:
            source_version = int(str(member[4]))
            lineage_hashes = self._lineage_hashes(member[5])
            authority_member = AuthorityManifestMember(
                object_type=str(member[1]),
                object_id=str(member[2]),
                object_sha256=str(member[3]),
                source_version=source_version,
                source_lineage_hashes=lineage_hashes,
                media_type=str(member[6]),
                size_bytes=int(member[7]),
            )
            try:
                VersionRef(
                    object_id=authority_member.object_id,
                    version=source_version,
                    content_sha256=authority_member.object_sha256,
                )
            except ValueError:
                raise KnowledgePublicationError(
                    "KNOWLEDGE_MANIFEST_MEMBER_INVALID"
                ) from None
            if (
                source_version != operation.authority_base_version
                or authority_member.object_id[:-37] != authority_member.object_type
            ):
                raise KnowledgePublicationError("KNOWLEDGE_ARTIFACT_VERSION_MISMATCH")
            authority_members.append(authority_member)
            manifest_members.append(
                ManifestMember(
                    ordinal=int(member[0]),
                    object_type=authority_member.object_type,
                    object_id=authority_member.object_id,
                    object_sha256=authority_member.object_sha256,
                    source_version=source_version,
                    media_type=authority_member.media_type,
                    size_bytes=authority_member.size_bytes,
                    source_lineage_hashes=lineage_hashes,
                )
            )
        expected_manifest_sha256 = manifest_sha256(
            manifest_id=manifest_id,
            operation_id=operation.operation_id,
            artifact_key=artifact_kind,
            artifact_kind=artifact_kind,
            source_version=operation.authority_base_version,
            members=manifest_members,
        )
        if expected_manifest_sha256 != str(row[3]):
            raise KnowledgePublicationError("KNOWLEDGE_MANIFEST_HASH_MISMATCH")
        return (
            VersionRef(
                object_id=manifest_id,
                version=operation.authority_base_version,
                content_sha256=expected_manifest_sha256,
            ),
            tuple(authority_members),
        )

    def _read_member(self, member: AuthorityManifestMember) -> bytes:
        if self._content_store is None:
            raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_UNAVAILABLE")
        try:
            payload = self._content_store.read_verified(
                self._content_store.reference(
                    content_sha256=member.object_sha256,
                    size_bytes=member.size_bytes,
                    media_type=member.media_type,
                )
            )
        except (ContentStoreError, OSError, TypeError, ValueError):
            raise KnowledgePublicationError("KNOWLEDGE_ARTIFACT_CAS_INVALID") from None
        if hashlib.sha256(payload).hexdigest() != member.object_sha256:
            raise KnowledgePublicationError("KNOWLEDGE_ARTIFACT_CAS_INVALID")
        return payload

    def _load_derived_views(
        self,
        operation: PublicationOperation,
    ) -> dict[DerivedArtifactKind, _DerivedManifestView]:
        views: dict[DerivedArtifactKind, _DerivedManifestView] = {}
        for kind in _DERIVED_KINDS:
            root_ref, members = self._load_manifest(operation, kind)
            roles = tuple(member.object_type for member in members)
            media_types = tuple(member.media_type for member in members)
            if (
                roles != derived_artifact_role_layout(kind)
                or media_types != derived_artifact_media_type_layout(kind)
            ):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_DERIVED_MEMBER_LAYOUT_INVALID"
                )
            payloads = {
                member.object_type: self._read_member(member) for member in members
            }
            for member in members:
                if (
                    member.media_type == "application/json"
                    and member.object_type != "global_graph"
                ):
                    try:
                        decoded = json.loads(payloads[member.object_type])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        raise KnowledgePublicationError(
                            "KNOWLEDGE_DERIVED_MEMBER_PAYLOAD_INVALID"
                        ) from None
                    if payloads[member.object_type] != canonical_json_bytes(decoded):
                        raise KnowledgePublicationError(
                            "KNOWLEDGE_DERIVED_MEMBER_PAYLOAD_INVALID"
                        )
            try:
                builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
                    payloads[f"{kind}_builder_input"], strict=True
                )
            except (ValidationError, ValueError):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_BUILDER_INPUT_INVALID"
                ) from None
            if (
                builder_input.artifact_kind != kind
                or builder_input.source_catalog_version
                != operation.authority_base_version
                or payloads[f"{kind}_builder_input"]
                != canonical_json_bytes(builder_input.model_dump(mode="json"))
            ):
                raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_INVALID")
            views[kind] = _DerivedManifestView(
                kind=kind,
                manifest_ref=root_ref,
                members={member.object_type: member for member in members},
                payloads=payloads,
                builder_input=builder_input,
            )
        return views

    def _validate_generic_projection(
        self,
        view: _DerivedManifestView,
        rebuilt: RebuiltPublicationAuthority,
    ) -> None:
        kind = view.kind
        if kind not in {"wiki_index", "knowledge_registry"}:
            raise KnowledgePublicationError("KNOWLEDGE_DERIVED_ARTIFACT_INVALID")
        manifest_role = f"{kind}_build_manifest"
        try:
            manifest = GenericDerivedBuildManifestV2.model_validate_json(
                view.payloads[manifest_role], strict=True
            )
            manifest.verify_builder_input(view.builder_input)
        except (ValidationError, TypeError, ValueError):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None
        output_roles = derived_artifact_role_layout(kind)[2:]
        if manifest.member_content_sha256 != {
            role: view.members[role].object_sha256 for role in output_roles
        }:
            raise KnowledgePublicationError("KNOWLEDGE_DERIVED_ARTIFACT_INVALID")
        if kind == "knowledge_registry":
            try:
                registry = KnowledgeRegistryPayloadV1.model_validate_json(
                    view.payloads["knowledge_registry"], strict=True
                )
                registry.verify_descriptor(rebuilt.descriptor)
            except (ValidationError, ValueError):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
                ) from None
            if (
                view.payloads["knowledge_registry"]
                != canonical_json_bytes(registry.model_dump(mode="json"))
            ):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
                )
        else:
            try:
                wiki_index = WikiNavigationIndexPayloadV2.model_validate_json(
                    view.payloads["wiki_index"], strict=True
                )
                wiki_authority = rebuilt.snapshot.wiki
                if wiki_authority is None:
                    raise ValueError("WIKI_INDEX_WIKI_AUTHORITY_MISSING")
                wiki_revisions = tuple(
                    self._wikis.get(value.object_id, value.version)
                    for value in rebuilt.wikis
                )
                wiki_index.verify_sources(
                    view.builder_input,
                    wiki_revisions,
                )
            except (ValidationError, ValueError):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
                ) from None
            if view.payloads["wiki_index"] != canonical_json_bytes(
                wiki_index.model_dump(mode="json")
            ):
                raise KnowledgePublicationError(
                    "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
                )

    @staticmethod
    def _open_sqlite_payload(payload: bytes) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        try:
            connection.deserialize(payload)
            connection.execute("PRAGMA query_only = ON")
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise sqlite3.DatabaseError
            return connection
        except (AttributeError, sqlite3.DatabaseError, TypeError, ValueError):
            connection.close()
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None

    @staticmethod
    def _utc_text(value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    @classmethod
    def _validate_lexical(cls, view: _DerivedManifestView) -> None:
        try:
            manifest = LexicalBuildManifest.model_validate_json(
                view.payloads["lexical_build_manifest"], strict=True
            )
            validate_builder_manifest_binding("lexical", view.builder_input, manifest)
        except (
            ValidationError,
            RetrievalArtifactPublicationError,
            TypeError,
            ValueError,
        ):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None
        if (
            manifest.index_sha256 != view.members["lexical_index"].object_sha256
            or manifest.tokenizer_descriptor_id != manifest.tokenizer_descriptor.id
        ):
            raise KnowledgePublicationError("KNOWLEDGE_DERIVED_ARTIFACT_INVALID")
        connection = cls._open_sqlite_payload(view.payloads["lexical_index"])
        try:
            expected_metadata = {
                "assigned_input_set_sha256": (
                    view.builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                        "lexical"
                    )
                ),
                "builder_input_sha256": view.builder_input.canonical_sha256,
                "retrieval_input_descriptor_sha256": (
                    view.builder_input.retrieval_input_descriptor.descriptor_sha256
                ),
                "row_mapping_sha256": (
                    view.builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                        "lexical"
                    )
                ),
                "schema_version": manifest.schema_version,
                "source_catalog_version": view.builder_input.source_catalog_version,
                "target_runtime_epoch": view.builder_input.target_runtime_epoch,
                "tokenizer_descriptor": manifest.tokenizer_descriptor.model_dump(
                    mode="json"
                ),
                "tokenizer_descriptor_id": manifest.tokenizer_descriptor_id,
            }
            if connection.execute(
                "SELECT key, value_json FROM lexical_metadata ORDER BY key"
            ).fetchall() != [
                ("builder", canonical_json_bytes(expected_metadata).decode("utf-8"))
            ]:
                raise ValueError
            rows = connection.execute(
                "SELECT row_id, evidence_id, evidence_version, evidence_sha256, "
                "content_object_id, content_version, content_sha256, "
                "candidate_json, row_sha256 FROM lexical_documents "
                "ORDER BY evidence_id, evidence_version, evidence_sha256, "
                "content_object_id, content_version, content_sha256"
            ).fetchall()
            candidates: list[CandidateRef] = []
            row_hashes: list[str] = []
            expected_fts: list[tuple[str, str]] = []
            for row in rows:
                candidate_json = str(row[7])
                candidate = CandidateRef.model_validate_json(
                    candidate_json, strict=True
                )
                if (
                    candidate_json != candidate.model_dump_json()
                    or str(row[0]) != retrieval_row_id(candidate)
                    or (str(row[1]), int(row[2]), str(row[3]))
                    != (
                        candidate.reference.object_id,
                        candidate.reference.version,
                        candidate.reference.content_sha256,
                    )
                    or (str(row[4]), int(row[5]), str(row[6]))
                    != (
                        candidate.content_ref.object_id,
                        candidate.content_ref.version,
                        candidate.content_ref.content_sha256,
                    )
                ):
                    raise ValueError
                word = connection.execute(
                    "SELECT evidence_id, tokens FROM lexical_word_fts "
                    "WHERE row_id = ?",
                    (str(row[0]),),
                ).fetchall()
                chars = connection.execute(
                    "SELECT evidence_id, tokens FROM lexical_char_fts "
                    "WHERE row_id = ?",
                    (str(row[0]),),
                ).fetchall()
                if len(word) != 1 or len(chars) != 1 or (
                    str(word[0][0]) != candidate.reference.object_id
                    or str(chars[0][0]) != candidate.reference.object_id
                ):
                    raise ValueError
                expected_row_sha256 = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "candidate": candidate.model_dump(mode="json"),
                            "char_tokens": tuple(str(chars[0][1]).split()),
                            "word_tokens": tuple(str(word[0][1]).split()),
                        }
                    )
                ).hexdigest()
                provenance = connection.execute(
                    "SELECT provenance_sha256 FROM lexical_provenance "
                    "WHERE row_id = ?",
                    (str(row[0]),),
                ).fetchall()
                if provenance != [
                    (
                        hashlib.sha256(
                            canonical_json_bytes(
                                candidate.provenance.model_dump(mode="json")
                            )
                        ).hexdigest(),
                    )
                ] or str(row[8]) != expected_row_sha256:
                    raise ValueError
                candidates.append(candidate)
                row_hashes.append(str(row[8]))
                expected_fts.append((str(row[0]), candidate.reference.object_id))
            view.builder_input.retrieval_input_descriptor.verify_candidates(
                "lexical", tuple(candidates)
            )
            if (
                len(rows) != manifest.row_count
                or tuple(sorted(row_hashes)) != manifest.row_content_hashes
                or connection.execute(
                    "SELECT row_id, evidence_id FROM lexical_word_fts "
                    "ORDER BY row_id, evidence_id"
                ).fetchall()
                != sorted(expected_fts)
                or connection.execute(
                    "SELECT row_id, evidence_id FROM lexical_char_fts "
                    "ORDER BY row_id, evidence_id"
                ).fetchall()
                != sorted(expected_fts)
                or int(
                    connection.execute(
                        "SELECT COUNT(*) FROM lexical_provenance"
                    ).fetchone()[0]
                )
                != len(rows)
            ):
                raise ValueError
        except (sqlite3.DatabaseError, TypeError, ValueError):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None
        finally:
            connection.close()

    @classmethod
    def _validate_vector(cls, view: _DerivedManifestView) -> None:
        try:
            manifest = VectorBuildManifest.model_validate_json(
                view.payloads["vector_build_manifest"], strict=True
            )
            validate_builder_manifest_binding("vector", view.builder_input, manifest)
        except (
            ValidationError,
            RetrievalArtifactPublicationError,
            TypeError,
            ValueError,
        ):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None
        if (
            manifest.metadata_sha256
            != view.members["vector_metadata"].object_sha256
            or manifest.vector_sha256 != view.members["vector_shard"].object_sha256
            or manifest.model_descriptor_id != manifest.model_descriptor.id
        ):
            raise KnowledgePublicationError("KNOWLEDGE_DERIVED_ARTIFACT_INVALID")
        connection = cls._open_sqlite_payload(view.payloads["vector_metadata"])
        try:
            descriptor_json = manifest.model_descriptor.model_dump_json()
            if connection.execute(
                "SELECT model_descriptor_id, descriptor_json, descriptor_sha256 "
                "FROM model_descriptors"
            ).fetchall() != [
                (
                    manifest.model_descriptor_id,
                    descriptor_json,
                    manifest.model_descriptor_id,
                )
            ]:
                raise ValueError
            expected_metadata = {
                "assigned_input_set_sha256": (
                    view.builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                        "vector"
                    )
                ),
                "builder_input_sha256": view.builder_input.canonical_sha256,
                "model_descriptor_id": manifest.model_descriptor_id,
                "retrieval_input_descriptor_sha256": (
                    view.builder_input.retrieval_input_descriptor.descriptor_sha256
                ),
                "row_mapping_sha256": (
                    view.builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                        "vector"
                    )
                ),
                "schema_version": manifest.schema_version,
                "shard_id": manifest.shard_id,
                "source_catalog_version": view.builder_input.source_catalog_version,
                "target_runtime_epoch": view.builder_input.target_runtime_epoch,
                "vector_filename": manifest.vector_filename,
                "vector_sha256": manifest.vector_sha256,
            }
            if connection.execute(
                "SELECT key, value_json FROM vector_metadata ORDER BY key"
            ).fetchall() != [
                ("builder", canonical_json_bytes(expected_metadata).decode("utf-8"))
            ]:
                raise ValueError
            rows = connection.execute(
                "SELECT row_id, evidence_id, evidence_version, evidence_sha256, "
                "content_object_id, content_version, shard_id, row_index, "
                "review_status, valid_from, valid_to, sensitivity, "
                "allowed_uses_json, provenance_ref, content_sha256, "
                "model_descriptor_id, candidate_json, row_sha256 "
                "FROM vector_rows ORDER BY row_index"
            ).fetchall()
            candidates: list[CandidateRef] = []
            row_hashes: list[str] = []
            for expected_index, row in enumerate(rows):
                candidate_json = str(row[16])
                candidate = CandidateRef.model_validate_json(
                    candidate_json, strict=True
                )
                metadata = candidate.metadata
                if (
                    candidate_json != candidate.model_dump_json()
                    or str(row[0]) != retrieval_row_id(candidate)
                    or (str(row[1]), int(row[2]), str(row[3]))
                    != (
                        candidate.reference.object_id,
                        candidate.reference.version,
                        candidate.reference.content_sha256,
                    )
                    or (str(row[4]), int(row[5]), str(row[14]))
                    != (
                        candidate.content_ref.object_id,
                        candidate.content_ref.version,
                        candidate.content_ref.content_sha256,
                    )
                    or str(row[6]) != manifest.shard_id
                    or int(row[7]) != expected_index
                    or str(row[8]) != metadata.review_status
                    or row[9] != cls._utc_text(metadata.effective_from)
                    or row[10] != cls._utc_text(metadata.effective_to)
                    or int(row[11]) != metadata.sensitivity
                    or str(row[12])
                    != json.dumps(sorted(metadata.allowed_uses), separators=(",", ":"))
                    or str(row[13]) != metadata.manifest_ref.model_dump_json()
                    or str(row[15]) != manifest.model_descriptor_id
                ):
                    raise ValueError
                expected_row_sha256 = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "candidate": candidate.model_dump(mode="json"),
                            "row_index": expected_index,
                            "shard_id": manifest.shard_id,
                        }
                    )
                ).hexdigest()
                provenance = connection.execute(
                    "SELECT provenance_sha256 FROM vector_provenance "
                    "WHERE row_id = ?",
                    (str(row[0]),),
                ).fetchall()
                if provenance != [
                    (
                        hashlib.sha256(
                            canonical_json_bytes(
                                candidate.provenance.model_dump(mode="json")
                            )
                        ).hexdigest(),
                    )
                ] or str(row[17]) != expected_row_sha256:
                    raise ValueError
                candidates.append(candidate)
                row_hashes.append(str(row[17]))
            view.builder_input.retrieval_input_descriptor.verify_candidates(
                "vector", tuple(candidates)
            )
            expected_shard_id = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "descriptor_id": manifest.model_descriptor_id,
                        "evidence": [
                            {
                                "content_ref": candidate.content_ref.model_dump(
                                    mode="json"
                                ),
                                "reference": candidate.reference.model_dump(
                                    mode="json"
                                ),
                            }
                            for candidate in candidates
                        ],
                        "source_catalog_version": (
                            view.builder_input.source_catalog_version
                        ),
                    }
                )
            ).hexdigest()
            matrix = np.load(
                io.BytesIO(view.payloads["vector_shard"]), allow_pickle=False
            )
            validate_matrix(
                matrix,
                manifest.model_descriptor,
                expected_rows=len(rows),
            )
            if (
                len(rows) != manifest.row_count
                or tuple(sorted(row_hashes)) != manifest.row_content_hashes
                or expected_shard_id != manifest.shard_id
                or int(
                    connection.execute(
                        "SELECT COUNT(*) FROM vector_provenance"
                    ).fetchone()[0]
                )
                != len(rows)
            ):
                raise ValueError
        except (
            EmbeddingContractError,
            OSError,
            sqlite3.DatabaseError,
            TypeError,
            ValueError,
        ):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None
        finally:
            connection.close()

    def _validate_graph(
        self,
        view: _DerivedManifestView,
        rebuilt: RebuiltPublicationAuthority,
    ) -> None:
        try:
            verify_graph_member_payloads(
                view.payloads,
                members=tuple(
                    ArtifactMemberIdentity(
                        role=role,
                        object_id=view.members[role].object_id,
                        content_sha256=view.members[role].object_sha256,
                        media_type=view.members[role].media_type,
                        size_bytes=view.members[role].size_bytes,
                    )
                    for role in derived_artifact_role_layout("graph")
                ),
            )
            graph_payload = json.loads(view.payloads["global_graph"])
            catalog = GraphEdgeAuthorityCatalogPayload.model_validate_json(
                view.payloads["graph_edge_authority_catalog"],
                strict=True,
            )
            self._verify_graph_wiki_relations(
                graph_payload,
                catalog,
                rebuilt,
            )
        except (
            GraphBuildClosureError,
            KeyError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            raise KnowledgePublicationError(
                "KNOWLEDGE_DERIVED_ARTIFACT_INVALID"
            ) from None

    def _verify_graph_wiki_relations(
        self,
        graph_payload: object,
        catalog: GraphEdgeAuthorityCatalogPayload,
        rebuilt: RebuiltPublicationAuthority,
    ) -> None:
        if self._connection is None or not isinstance(graph_payload, dict):
            raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
        raw_nodes = graph_payload.get("nodes")
        raw_edges = graph_payload.get("edges")
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

        node_refs: dict[str, VersionRef] = {}
        for raw_node in raw_nodes:
            if not isinstance(raw_node, dict):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            node_id = raw_node.get("node_id")
            attributes = raw_node.get("attributes")
            if not isinstance(node_id, str) or not isinstance(attributes, dict):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            reference = VersionRef.model_validate(attributes.get("reference"))
            if (
                reference.object_id != node_id
                or attributes.get("version") != reference.version
                or attributes.get("node_type") != node_id.rsplit("_", maxsplit=1)[0]
                or node_id in node_refs
            ):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            node_refs[node_id] = reference

        expected_by_hash = {
            claim_relation_sha256(
                wiki_ref=binding.wiki_ref,
                source_ref=binding.declaration.source_ref,
                target_ref=binding.declaration.target_ref,
                claim_ref=binding.declaration.claim_ref,
                relation=binding.declaration.relation,
                scope=binding.declaration.scope,
                review_status=binding.declaration.review_status,
                effective_from=binding.declaration.effective_from,
                effective_to=binding.declaration.effective_to,
                confidence_override=(
                    None
                    if binding.declaration.confidence_override is None
                    else float(binding.declaration.confidence_override)
                ),
            ): binding
            for binding in rebuilt.graph_relation_bindings
        }
        if len(expected_by_hash) != len(rebuilt.graph_relation_bindings):
            raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

        graph_relation_refs: set[VersionRef] = set()
        expected_node_refs: set[VersionRef] = set()
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, dict):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            attributes = raw_edge.get("attributes")
            source = raw_edge.get("source")
            target = raw_edge.get("target")
            if (
                not isinstance(attributes, dict)
                or not isinstance(source, str)
                or not isinstance(target, str)
            ):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            relation_ref = VersionRef.model_validate(attributes.get("relation_ref"))
            binding = expected_by_hash.pop(
                relation_ref.content_sha256,
                None,
            )
            if binding is None:
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            declaration = binding.declaration
            wiki_ref = binding.wiki_ref
            claim_ref = VersionRef.model_validate(attributes.get("claim_ref"))
            payload_wiki_ref = VersionRef.model_validate(attributes.get("wiki_ref"))
            source_ref = node_refs.get(source)
            target_ref = node_refs.get(target)
            if (
                relation_ref.object_id.rsplit("_", maxsplit=1)[0] != "graph_edge"
                or relation_ref.version
                != rebuilt.snapshot.publication_authority_version
                or raw_edge.get("edge_id") != relation_ref.object_id
                or source_ref != declaration.source_ref
                or target_ref != declaration.target_ref
                or claim_ref != declaration.claim_ref
                or payload_wiki_ref != wiki_ref
                or attributes.get("relation") != declaration.relation
                or attributes.get("relation_scope") != list(declaration.scope)
                or attributes.get("review_status") != "approved"
            ):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
            expected_node_refs.update((declaration.source_ref, declaration.target_ref))
            graph_relation_refs.add(relation_ref)

            claim_row = self._connection.execute(
                "SELECT claim_sha256, effective_from, effective_to, "
                "model_confidence, cognitive_type, review_due_at "
                "FROM claims WHERE claim_id = ? AND version = ?",
                (claim_ref.object_id, claim_ref.version),
            ).fetchone()
            if claim_row is None or str(claim_row[0]) != claim_ref.content_sha256:
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

            def db_time(value: object) -> datetime | None:
                if value is None:
                    return None
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.utcoffset() is None:
                    raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")
                return parsed

            claim_from = db_time(claim_row[1])
            claim_to = db_time(claim_row[2])
            starts = tuple(
                value
                for value in (claim_from, declaration.effective_from)
                if value is not None
            )
            ends = tuple(
                value
                for value in (claim_to, declaration.effective_to)
                if value is not None
            )
            model_confidence = claim_row[3]
            expected_confidence = (
                float(declaration.confidence_override)
                if declaration.confidence_override is not None
                else (
                    float(model_confidence)
                    if model_confidence is not None
                    else 1.0 if str(claim_row[4]) == "explicit" else 0.75
                )
            )
            raw_confidence = attributes.get("confidence")
            if (
                isinstance(raw_confidence, bool)
                or not isinstance(raw_confidence, int | float)
                or float(raw_confidence) != expected_confidence
                or attributes.get("effective_from")
                != self._utc_text(max(starts) if starts else None)
                or attributes.get("effective_to")
                != self._utc_text(min(ends) if ends else None)
                or attributes.get("review_due_at")
                != self._utc_text(db_time(claim_row[5]))
            ):
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

            assigned = tuple(
                assignment
                for assignment in rebuilt.assignments
                if "graph" in assignment.target_channels
                and assignment.authority.reference == claim_ref
            )
            passage_refs = tuple(
                sorted(
                    (
                        VersionRef.model_validate(value)
                        for value in attributes.get("passage_refs", ())
                    ),
                    key=lambda value: (
                        value.object_id,
                        value.version,
                        value.content_sha256,
                    ),
                )
            )
            expected_passages = tuple(
                sorted(
                    (assignment.authority.content_ref for assignment in assigned),
                    key=lambda value: (
                        value.object_id,
                        value.version,
                        value.content_sha256,
                    ),
                )
            )
            if not assigned or passage_refs != expected_passages:
                raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

        catalog_relation_refs = {record.relation_ref for record in catalog.records}
        if (
            expected_by_hash
            or len(raw_edges) != len(rebuilt.graph_relations)
            or set(node_refs.values()) != expected_node_refs
            or catalog_relation_refs != graph_relation_refs
            or any(
                record.authority_ref.version
                != rebuilt.snapshot.publication_authority_version
                for record in catalog.records
            )
        ):
            raise ValueError("GRAPH_WIKI_RELATION_CLOSURE_INVALID")

    def _verify_builder_input_contract(
        self,
        operation: PublicationOperation,
        *,
        theory_id: str | None,
        theory_revision: int | None,
        wiki_id: str,
        wiki_revision: int,
    ) -> RebuiltPublicationAuthority:
        if self._connection is None or self._content_store is None:
            raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_UNAVAILABLE")
        views = self._load_derived_views(operation)
        claims_manifest_ref, claim_members = self._load_manifest(operation, "claims")
        if not claim_members or any(
            member.object_type != "claim" for member in claim_members
        ):
            raise KnowledgePublicationError("KNOWLEDGE_CLAIM_CLOSURE_MISMATCH")
        route_policy_member = views["knowledge_registry"].members[
            "retrieval_route_policy"
        ]
        governed_wiki_refs, governed_theory_refs = self._governed_authority_refs(
            wiki_id=wiki_id,
            wiki_revision=wiki_revision,
        )
        try:
            rebuilt = rebuild_publication_authority(
                self._connection,
                self._content_store,
                publication_authority_version=operation.authority_base_version,
                expected_current_epoch=operation.expected_current_epoch,
                theory_id=theory_id,
                theory_revision=theory_revision,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
                governed_wiki_refs=governed_wiki_refs,
                governed_theory_refs=governed_theory_refs,
                claims_manifest_ref=claims_manifest_ref,
                claim_members=claim_members,
                route_policy_member=route_policy_member,
            )
        except AuthorityDescriptorError as exc:
            raise KnowledgePublicationError(exc.code) from None
        for view in views.values():
            builder = view.builder_input
            if (
                builder.authority_snapshot != rebuilt.snapshot
                or builder.retrieval_input_descriptor != rebuilt.descriptor
                or builder.target_runtime_epoch
                != rebuilt.snapshot.target_runtime_epoch
            ):
                raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_MISMATCH")
        self._validate_generic_projection(views["wiki_index"], rebuilt)
        self._validate_generic_projection(views["knowledge_registry"], rebuilt)
        self._validate_graph(views["graph"], rebuilt)
        self._validate_lexical(views["lexical"])
        self._validate_vector(views["vector"])
        return rebuilt

    def _builder_member_fingerprint(self, operation_id: str) -> str:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_UNAVAILABLE")
        rows = [
            {
                "artifact_kind": str(row[0]),
                "artifact_key": str(row[1]),
                "manifest_id": str(row[2]),
                "manifest_sha256": str(row[3]),
                "manifest_source_version": str(row[4]),
                "manifest_state": str(row[5]),
                "manifest_verified": int(row[6]),
                "ordinal": int(row[7]),
                "object_type": str(row[8]),
                "object_id": str(row[9]),
                "object_sha256": str(row[10]),
                "source_version": str(row[11]),
                "source_lineage_json": str(row[12]),
                "media_type": str(row[13]),
                "size_bytes": int(row[14]),
            }
            for row in self._connection.execute(
                """
                SELECT m.artifact_kind, m.artifact_key, m.manifest_id,
                       m.manifest_sha256, m.source_version, m.state, m.verified,
                       a.ordinal, a.object_type, a.object_id, a.object_sha256,
                       a.source_version, a.source_lineage_json, a.media_type,
                       a.size_bytes
                  FROM artifact_manifests AS m
                  JOIN artifact_members AS a ON a.manifest_id = m.manifest_id
                 WHERE m.operation_id = ?
                   AND m.artifact_kind IN (
                       'wiki_index', 'knowledge_registry', 'graph',
                       'lexical', 'vector'
                   )
                 ORDER BY m.artifact_kind, m.artifact_key, m.manifest_id, a.ordinal
                """,
                (operation_id,),
            )
        ]
        return canonical_sha256(rows)

    def _assert_snapshot_current(self, snapshot: DerivedAuthoritySnapshotV2) -> None:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_CATALOG_SNAPSHOT_UNAVAILABLE")
        row = self._connection.execute(
            """
            SELECT catalog_version, authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone()
        if row != (
            snapshot.catalog_version,
            snapshot.authorization_epoch,
            snapshot.tombstone_epoch,
        ):
            raise KnowledgePublicationError("KNOWLEDGE_CATALOG_SNAPSHOT_STALE")

    def _assert_operation_current(
        self,
        operation: PublicationOperation,
        snapshot: DerivedAuthoritySnapshotV2,
        builder_fingerprint: str,
    ) -> None:
        if self._connection is None:
            raise KnowledgePublicationError("KNOWLEDGE_CATALOG_SNAPSHOT_UNAVAILABLE")
        if self._lint_errors is None or self._lint_errors() > 0:
            raise KnowledgePublicationError("KNOWLEDGE_LINT_ERRORS")
        row = self._connection.execute(
            """
            SELECT state, authority_base_version, expected_current_epoch
              FROM publication_operations WHERE operation_id = ?
            """,
            (operation.operation_id,),
        ).fetchone()
        if row != (
            "VERIFIED",
            snapshot.publication_authority_version,
            snapshot.expected_current_epoch,
        ):
            raise KnowledgePublicationError("KNOWLEDGE_OPERATION_SNAPSHOT_STALE")
        active_rows = self._connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(active_rows) > 1:
            raise KnowledgePublicationError("KNOWLEDGE_OPERATION_SNAPSHOT_STALE")
        active_epoch = None if not active_rows else int(active_rows[0][0])
        maximum_epoch = int(
            self._connection.execute(
                "SELECT COALESCE(MAX(epoch), 0) FROM runtime_epochs"
            ).fetchone()[0]
        )
        if (
            active_epoch != snapshot.expected_current_epoch
            or maximum_epoch != snapshot.maximum_runtime_epoch
            or snapshot.target_runtime_epoch != maximum_epoch + 1
        ):
            raise KnowledgePublicationError("KNOWLEDGE_OPERATION_TARGET_EPOCH_INVALID")
        mismatched = self._connection.execute(
            """
            SELECT COUNT(*) FROM artifact_manifests
             WHERE operation_id = ? AND source_version <> ?
            """,
            (operation.operation_id, str(operation.authority_base_version)),
        ).fetchone()
        if mismatched is None or int(mismatched[0]) != 0:
            raise KnowledgePublicationError("KNOWLEDGE_ARTIFACT_VERSION_MISMATCH")
        if self._builder_member_fingerprint(operation.operation_id) != builder_fingerprint:
            raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_CHANGED")

    def publish_theory_and_wiki(
        self,
        operation_id: str,
        *,
        theory_id: str,
        theory_revision: int,
        wiki_id: str,
        wiki_revision: int,
    ) -> PublicationOperation:
        theory = self._assert_theory_scope_policy(theory_id, theory_revision)
        wiki = self._wikis.get(wiki_id, wiki_revision)
        theory_ref = self._theories.version_ref(theory_id, theory_revision)
        if wiki.theory_revision_refs != (theory_ref,):
            raise KnowledgePublicationError("KNOWLEDGE_WIKI_THEORY_MISMATCH")
        wiki_claim_refs = {
            (reference.object_id, reference.version, reference.content_sha256)
            for section in wiki.sections
            for reference in section.claim_refs
        }
        if not {
            (reference.object_id, reference.version, reference.content_sha256)
            for reference in theory.claim_refs
        }.issubset(wiki_claim_refs):
            raise KnowledgePublicationError("KNOWLEDGE_WIKI_C1_CLAIMS_MISSING")
        operation = self._verify_closure(operation_id)
        with self._write_context():
            self._assert_theory_scope_policy(theory_id, theory_revision)
            self._verify_authority_binding(
                operation_id,
                theory_id=theory_id,
                theory_revision=theory_revision,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            rebuilt = self._verify_builder_input_contract(
                operation,
                theory_id=theory_id,
                theory_revision=theory_revision,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            builder_fingerprint = self._builder_member_fingerprint(operation_id)
            self._assert_snapshot_current(rebuilt.snapshot)
            self._assert_operation_current(
                operation, rebuilt.snapshot, builder_fingerprint
            )
        self._hook("closure_verified")
        with self._write_context() as connection:
            self._assert_snapshot_current(rebuilt.snapshot)
            self._assert_operation_current(
                operation, rebuilt.snapshot, builder_fingerprint
            )
            self._hook("before_authority_rows")
            current = self._verify_builder_input_contract(
                operation,
                theory_id=theory_id,
                theory_revision=theory_revision,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            if current != rebuilt:
                raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_CHANGED")
            self._verify_authority_binding(
                operation_id,
                theory_id=theory_id,
                theory_revision=theory_revision,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            self._assert_theory_scope_policy(theory_id, theory_revision)
            if connection is not None:
                connection.execute(
                    """
                    UPDATE theory_revisions SET status = 'SUPERSEDED'
                     WHERE theory_id = ? AND status = 'ACTIVE' AND revision <> ?
                    """,
                    (theory_id, theory_revision),
                )
                changed_theory = connection.execute(
                    """
                    UPDATE theory_revisions SET status = 'ACTIVE'
                     WHERE theory_id = ? AND revision = ? AND status = 'PREPARED'
                    """,
                    (theory_id, theory_revision),
                ).rowcount
                connection.execute(
                    """
                    UPDATE claims SET review_status = 'REVOKED'
                     WHERE source_grade = 'C1' AND theory_revision_id = ?
                       AND theory_revision <> ? AND review_status = 'APPROVED'
                    """,
                    (theory_id, theory_revision),
                )
                changed_claims = connection.execute(
                    """
                    UPDATE claims SET review_status = 'APPROVED'
                     WHERE source_grade = 'C1' AND theory_revision_id = ?
                       AND theory_revision = ? AND review_status = 'REVIEWED'
                    """,
                    (theory_id, theory_revision),
                ).rowcount
                connection.execute(
                    """
                    UPDATE wiki_revisions SET review_status = 'SUPERSEDED'
                     WHERE wiki_id = ? AND review_status = 'ACTIVE' AND revision <> ?
                    """,
                    (wiki_id, wiki_revision),
                )
                changed_wiki = connection.execute(
                    """
                    UPDATE wiki_revisions SET review_status = 'ACTIVE'
                     WHERE wiki_id = ? AND revision = ? AND review_status = 'PREPARED'
                    """,
                    (wiki_id, wiki_revision),
                ).rowcount
                if (
                    changed_theory != 1
                    or changed_wiki != 1
                    or changed_claims != len(theory.claim_refs)
                ):
                    raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_ROW_CONFLICT")
            self._hook("authority_rows_written")
            active = self._coordinator.activate(operation.operation_id)
            self._hook("epoch_switched")
        self._theories._activate_from_publication(theory_id, theory_revision)
        self._wikis._activate_from_publication(wiki_id, wiki_revision)
        return active

    def _assert_theory_scope_policy(
        self,
        theory_id: str,
        theory_revision: int,
    ) -> TheoryRevision:
        try:
            theory = self._theories.get(theory_id, theory_revision)
            self._theories.assert_scope_policy_authority(theory)
        except (TheoryGovernanceError, ContentStoreError, sqlite3.Error):
            # Publication is an authority boundary.  Convert all resolver,
            # SQLite and CAS failures to a fixed content-free publication code.
            raise KnowledgePublicationError(
                "KNOWLEDGE_THEORY_SCOPE_POLICY_INVALID"
            ) from None
        return theory

    def publish_wiki(
        self,
        operation_id: str,
        *,
        wiki_id: str,
        wiki_revision: int,
    ) -> PublicationOperation:
        wiki = self._wikis.get(wiki_id, wiki_revision)
        for reference in wiki.theory_revision_refs:
            if self._theories.get_by_ref(reference).status != "active":
                raise KnowledgePublicationError(
                    "KNOWLEDGE_COMBINED_PUBLICATION_REQUIRED"
                )
        if self._connection is not None:
            c1_count = self._connection.execute(
                """
                SELECT COUNT(*)
                  FROM wiki_revision_claims AS wc
                  JOIN claims AS c
                    ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
                 WHERE wc.wiki_id = ? AND wc.wiki_revision = ?
                   AND c.source_grade = 'C1' AND c.review_status <> 'APPROVED'
                """,
                (wiki_id, wiki_revision),
            ).fetchone()
            if c1_count is None or int(c1_count[0]) != 0:
                raise KnowledgePublicationError(
                    "KNOWLEDGE_COMBINED_PUBLICATION_REQUIRED"
                )
        operation = self._verify_closure(operation_id)
        with self._write_context():
            self._verify_authority_binding(
                operation_id,
                theory_id=None,
                theory_revision=None,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            rebuilt = self._verify_builder_input_contract(
                operation,
                theory_id=None,
                theory_revision=None,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            builder_fingerprint = self._builder_member_fingerprint(operation_id)
            self._assert_snapshot_current(rebuilt.snapshot)
            self._assert_operation_current(
                operation, rebuilt.snapshot, builder_fingerprint
            )
        with self._write_context() as connection:
            self._assert_snapshot_current(rebuilt.snapshot)
            self._assert_operation_current(
                operation, rebuilt.snapshot, builder_fingerprint
            )
            current = self._verify_builder_input_contract(
                operation,
                theory_id=None,
                theory_revision=None,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            if current != rebuilt:
                raise KnowledgePublicationError("KNOWLEDGE_BUILDER_INPUT_CHANGED")
            self._verify_authority_binding(
                operation_id,
                theory_id=None,
                theory_revision=None,
                wiki_id=wiki_id,
                wiki_revision=wiki_revision,
            )
            if connection is not None:
                connection.execute(
                    """
                    UPDATE wiki_revisions SET review_status = 'SUPERSEDED'
                     WHERE wiki_id = ? AND review_status = 'ACTIVE' AND revision <> ?
                    """,
                    (wiki_id, wiki_revision),
                )
                changed = connection.execute(
                    """
                    UPDATE wiki_revisions SET review_status = 'ACTIVE'
                     WHERE wiki_id = ? AND revision = ? AND review_status = 'PREPARED'
                    """,
                    (wiki_id, wiki_revision),
                ).rowcount
                if changed != 1:
                    raise KnowledgePublicationError("KNOWLEDGE_AUTHORITY_ROW_CONFLICT")
            active = self._coordinator.activate(operation.operation_id)
        self._wikis._activate_from_publication(wiki_id, wiki_revision)
        return active


__all__ = ["KnowledgePublicationError", "KnowledgePublicationService"]


def _content_digest(value: str) -> str:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise KnowledgePublicationError("KNOWLEDGE_CONTENT_REF_INVALID")
    return value[len(prefix) :]
