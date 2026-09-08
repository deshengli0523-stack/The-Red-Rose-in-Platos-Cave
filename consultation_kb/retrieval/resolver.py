"""Late body resolution with live epoch, manifest, hash, and tombstone checks."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Protocol

from consultation_kb.vault.content_store import ContentStore

from .authority_snapshot import candidate_authority_membership
from .contracts import (
    CandidateRef,
    FilterCapabilityBinding,
    ResolvedEvidence,
    canonical_candidate_capability_payloads,
    canonical_json_bytes,
)
from .filters import CandidateAuthorityGuard


class EvidenceResolutionDenied(RuntimeError):
    def __init__(self) -> None:
        super().__init__("EVIDENCE_RESOLUTION_DENIED")


class VerifiedContentReader(Protocol):
    def read_verified(self, candidate: CandidateRef) -> bytes: ...


def _binding_decision_sha256(
    binding: FilterCapabilityBinding,
    candidates: tuple[CandidateRef, ...],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "allowed": canonical_candidate_capability_payloads(candidates),
                "authorization_epoch": binding.authorization_epoch,
                "client_runtime_epoch": binding.client_runtime_epoch,
                "global_runtime_epoch": binding.global_runtime_epoch,
                "policy_ref": binding.policy_ref.model_dump(mode="json"),
                "run_id": binding.run_id,
                "tombstone_epoch": binding.tombstone_epoch,
            }
        )
    ).hexdigest()


class EvidenceResolver:
    """Resolve exactly one complete filter decision, never arbitrary refs."""

    def __init__(
        self,
        authority_guard: CandidateAuthorityGuard,
        content_reader: VerifiedContentReader,
    ) -> None:
        self._authority = authority_guard
        self._reader = content_reader

    def resolve_many(
        self,
        filtered_refs: tuple[CandidateRef, ...],
    ) -> tuple[ResolvedEvidence, ...]:
        if type(filtered_refs) is not tuple:
            raise TypeError("FILTERED_CANDIDATE_TUPLE_REQUIRED")
        if not filtered_refs:
            return ()
        binding = filtered_refs[0].filter_binding
        if binding is None or any(
            candidate.filter_binding != binding for candidate in filtered_refs
        ):
            raise EvidenceResolutionDenied
        if _binding_decision_sha256(binding, filtered_refs) != binding.decision_sha256:
            raise EvidenceResolutionDenied
        try:
            self._authority.assert_binding_current(binding)
            resolved: list[ResolvedEvidence] = []
            for candidate in filtered_refs:
                self._authority.assert_candidate_binding_visible(candidate, binding)
                body = self._reader.read_verified(candidate)
                # A final live check closes the read/tombstone race.  A body
                # that became unauthorized while being read is discarded.
                self._authority.assert_candidate_binding_visible(candidate, binding)
                resolved.append(ResolvedEvidence(candidate=candidate, body=body))
            return tuple(resolved)
        except EvidenceResolutionDenied:
            raise
        except Exception:
            raise EvidenceResolutionDenied from None


class ScopedManifestContentReader:
    """Read a fixed scope's active artifact member or governed catalog body."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        *,
        schema: str,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if type(content_store) is not ContentStore:
            raise TypeError("CONTENT_STORE_REQUIRED")
        if schema not in {"main", "client_authority"}:
            raise ValueError("CONTENT_SCOPE_SCHEMA_INVALID")
        self._connection = connection
        self._store = content_store
        self._schema = schema

    def read_verified(self, candidate: CandidateRef) -> bytes:
        try:
            return self._read_authorized(candidate)
        except EvidenceResolutionDenied:
            raise
        except Exception:
            raise EvidenceResolutionDenied from None

    def _read_authorized(self, candidate: CandidateRef) -> bytes:
        if (
            candidate.provenance.provenance_scope in {"case_derived", "mixed"}
            and candidate.filter_binding is None
        ):
            # Case bodies are never a direct-reader capability.  They require
            # the exact filter decision whose issuing repository performed the
            # current-client/LOO gate.
            raise EvidenceResolutionDenied
        expected_schema = (
            "client_authority"
            if candidate.provenance.provenance_scope == "client_private"
            else "main"
        )
        if expected_schema != self._schema:
            raise EvidenceResolutionDenied
        epoch_rows = self._connection.execute(
            f"SELECT epoch FROM {self._schema}.runtime_epochs "
            "WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(epoch_rows) != 1:
            raise EvidenceResolutionDenied
        membership = candidate_authority_membership(
            self._connection,
            schema=self._schema,
            epoch=int(str(epoch_rows[0][0])),
            candidate=candidate,
            global_content_store=(self._store if self._schema == "main" else None),
        )
        if membership is None:
            raise EvidenceResolutionDenied

        manifest = candidate.metadata.manifest_ref
        member = self._connection.execute(
            f"SELECT member.object_sha256, member.source_version, "
            "member.media_type, member.size_bytes "
            f"FROM {self._schema}.artifact_members AS member "
            "WHERE member.manifest_id = ? AND member.object_id = ? "
            "AND member.object_sha256 = ?",
            (
                manifest.object_id,
                candidate.content_ref.object_id,
                candidate.content_ref.content_sha256,
            ),
        ).fetchone()
        if (
            membership.content_mode == "manifest_member"
            and member is not None
            and self._member_matches(candidate, member)
        ):
            return self._read_digest(
                candidate.content_ref.content_sha256,
                candidate.metadata.media_type,
                candidate.metadata.size_bytes,
            )
        if self._schema != "main" or membership.content_mode != "claim_passage":
            raise EvidenceResolutionDenied
        return self._read_claim_passage_body(candidate)

    @staticmethod
    def _member_matches(
        candidate: CandidateRef,
        row: tuple[object, ...],
    ) -> bool:
        try:
            version = int(str(row[1]))
        except ValueError:
            return False
        return (
            str(row[0]) == candidate.content_ref.content_sha256
            and version == candidate.metadata.manifest_ref.version
            and str(row[2]) == candidate.metadata.media_type
            and int(str(row[3])) == candidate.metadata.size_bytes
        )

    def _read_claim_passage_body(self, candidate: CandidateRef) -> bytes:
        if candidate.object_type != "claim":
            raise EvidenceResolutionDenied
        claim = candidate.reference
        passage = candidate.content_ref
        row = self._connection.execute(
            "SELECT passage.retrieval_content_ref "
            "FROM main.claim_evidence AS edge "
            "JOIN main.passages AS passage "
            "  ON passage.passage_id = edge.passage_id "
            " AND passage.version = edge.passage_version "
            "JOIN main.source_versions AS source_version "
            "  ON source_version.source_id = passage.source_id "
            " AND source_version.version = passage.source_version "
            "JOIN main.sources AS source ON source.source_id = passage.source_id "
            "WHERE edge.claim_id = ? AND edge.claim_version = ? "
            "AND edge.relation = 'SUPPORTS' "
            "AND passage.passage_id = ? AND passage.version = ? "
            "AND passage.normalized_text_sha256 = ? "
            "AND passage.review_status = 'APPROVED' "
            "AND passage.privacy_scope = 'GLOBAL' "
            "AND source_version.status = 'APPROVED' "
            "AND source.current_version = source_version.version",
            (
                claim.object_id,
                claim.version,
                passage.object_id,
                passage.version,
                passage.content_sha256,
            ),
        ).fetchone()
        if row is None or self._digest_ref(str(row[0])) != passage.content_sha256:
            raise EvidenceResolutionDenied
        return self._read_digest(
            passage.content_sha256,
            candidate.metadata.media_type,
            candidate.metadata.size_bytes,
        )

    @staticmethod
    def _digest_ref(value: str) -> str:
        if len(value) != 71 or not value.startswith("sha256:"):
            raise EvidenceResolutionDenied
        digest = value[7:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise EvidenceResolutionDenied
        return digest

    def _read_digest(self, digest: str, media_type: str, size_bytes: int) -> bytes:
        reference = self._store.reference(
            content_sha256=digest,
            media_type=media_type,
            size_bytes=size_bytes,
        )
        payload = self._store.read_verified(reference)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise EvidenceResolutionDenied
        return payload


class ScopeRoutingContentReader:
    """Closed-world router between the two fixed scope-local readers."""

    def __init__(
        self,
        *,
        global_reader: VerifiedContentReader,
        client_reader: VerifiedContentReader,
    ) -> None:
        self._global = global_reader
        self._client = client_reader

    def read_verified(self, candidate: CandidateRef) -> bytes:
        if candidate.provenance.provenance_scope == "client_private":
            return self._client.read_verified(candidate)
        return self._global.read_verified(candidate)


__all__ = [
    "EvidenceResolutionDenied",
    "EvidenceResolver",
    "ScopeRoutingContentReader",
    "ScopedManifestContentReader",
    "VerifiedContentReader",
]
