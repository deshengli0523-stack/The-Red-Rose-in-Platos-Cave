"""Live SQLite verifier for exact leave-one-client-out replacement authority."""

from __future__ import annotations

import json
import sqlite3

from consultation_kb.archive.leave_one_out import LeaveOneOutAuthorityRepository
from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.models.cases import LeaveOneOutVariantAuthority
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)
from consultation_kb.retrieval.contracts import (
    CandidateRef,
    LeaveOneOutVariant,
)


class SqliteLeaveOneOutAuthorityVerifier:
    """Resolve the canonical mapping before a replacement body can be opened."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        contributor_hasher: CaseContributorHasher,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("LOO verifier requires SQLite")
        if not isinstance(contributor_hasher, CaseContributorHasher):
            raise TypeError("LOO verifier requires contributor hasher")
        self._connection = connection
        self._repository = LeaveOneOutAuthorityRepository(connection)
        self._hasher = contributor_hasher

    def is_exact_approved_variant(
        self,
        *,
        original: CandidateRef,
        variant: LeaveOneOutVariant,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> bool:
        try:
            parent = CandidateRef.model_validate(original)
            replacement = LeaveOneOutVariant.model_validate(variant)
            query_scope = RetrievalScope.model_validate(scope)
            snapshot = AuthoritativeFilterSnapshot.model_validate(
                authority_snapshot
            )
            state = self._connection.execute(
                """
                SELECT catalog_version, authorization_epoch, tombstone_epoch
                  FROM knowledge_catalog_state WHERE singleton = 1
                """
            ).fetchone()
            if state is None or (
                int(state[1]) != snapshot.authorization_epoch
                or int(state[2]) != (snapshot.tombstone_epoch >> 32)
            ):
                return False
            runtime = self._connection.execute(
                "SELECT state FROM runtime_epochs WHERE epoch = ?",
                (snapshot.global_runtime_epoch,),
            ).fetchone()
            if runtime is None or str(runtime[0]) != "ACTIVE":
                return False
            excluded_hash = self._hasher.hash_client_id(
                query_scope.current_client_id
            )
            authority = self._repository.resolve_active(
                parent_ref=parent.reference,
                excluded_client_hash=excluded_hash,
            )
            if authority is None:
                return False
            manifest = self._connection.execute(
                """
                SELECT manifest_sha256, state, verified, source_version
                  FROM artifact_manifests WHERE manifest_id = ?
                """,
                (authority.authority_manifest_ref.object_id,),
            ).fetchone()
            if manifest is None or tuple(manifest) != (
                authority.authority_manifest_ref.content_sha256,
                "ACTIVE",
                1,
                str(authority.authority_manifest_ref.version),
            ):
                return False
            active = self._connection.execute(
                """
                SELECT 1 FROM active_artifacts
                 WHERE epoch = ? AND manifest_id = ?
                """,
                (
                    snapshot.global_runtime_epoch,
                    authority.authority_manifest_ref.object_id,
                ),
            ).fetchone()
            if active is None:
                return False
            provenance = self._connection.execute(
                """
                SELECT artifact_object_id, artifact_version, artifact_sha256,
                       artifact_kind, contributor_client_hashes_json,
                       derivation_rule_id, derivation_rule_version,
                       derivation_rule_sha256, source_grade, allowed_uses_json,
                       effective_to
                  FROM case_provenance
                 WHERE provenance_id = ? AND provenance_version = ?
                   AND provenance_sha256 = ?
                """,
                (
                    authority.provenance_ref.object_id,
                    authority.provenance_ref.version,
                    authority.provenance_ref.content_sha256,
                ),
            ).fetchone()
            if provenance is None:
                return False
            contributor_hashes = frozenset(json.loads(str(provenance[4])))
            provenance_uses = frozenset(json.loads(str(provenance[9])))
            if excluded_hash in contributor_hashes:
                return False
            if (
                replacement.reference != authority.variant_ref
                or replacement.content_ref != authority.content_ref
                or replacement.manifest_ref != authority.authority_manifest_ref
                or replacement.review_status != authority.review_status
                or replacement.allowed_uses != authority.allowed_uses
                or replacement.approved_at != authority.approved_at
                or replacement.effective_from != authority.approved_at
                or replacement.effective_to != authority.effective_to
                or replacement.source_grade != authority.source_grade
                or replacement.source_count
                != authority.remaining_independent_source_count
                or replacement.source_count
                < authority.minimum_independent_source_count
                or replacement.provenance.derivation_rule_ref
                != authority.regeneration_rule_ref
                or query_scope.current_client_id
                in replacement.provenance.case_contributor_client_ids
                or tuple(provenance[:4])
                != (
                    replacement.reference.object_id,
                    replacement.reference.version,
                    replacement.reference.content_sha256,
                    replacement.object_type,
                )
                or tuple(provenance[5:8])
                != (
                    authority.regeneration_rule_ref.object_id,
                    authority.regeneration_rule_ref.version,
                    authority.regeneration_rule_ref.content_sha256,
                )
                or str(provenance[8]) != authority.source_grade
                or not authority.allowed_uses.issubset(provenance_uses)
                or (None if provenance[10] is None else str(provenance[10]))
                != (
                    None
                    if authority.effective_to is None
                    else authority.effective_to.isoformat(
                        timespec="microseconds"
                    ).replace("+00:00", "Z")
                )
                or authority.content_ref not in replacement.location.anchor_refs
            ):
                return False
            member = self._connection.execute(
                """
                SELECT media_type, size_bytes FROM artifact_members
                 WHERE manifest_id = ? AND object_id = ?
                   AND object_sha256 = ?
                """,
                (
                    authority.authority_manifest_ref.object_id,
                    authority.content_ref.object_id,
                    authority.content_ref.content_sha256,
                ),
            ).fetchone()
            return member is not None and tuple(member) == (
                replacement.media_type,
                replacement.size_bytes,
            )
        except Exception:
            return False

    def resolve_exact_approved_variant(
        self,
        *,
        original: CandidateRef,
        variant: LeaveOneOutVariant,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
    ) -> LeaveOneOutVariantAuthority | None:
        """Return the exact active mapping only after the full client check."""

        if not self.is_exact_approved_variant(
            original=original,
            variant=variant,
            scope=scope,
            authority_snapshot=authority_snapshot,
        ):
            return None
        try:
            authority = self._repository.resolve_active(
                parent_ref=original.reference,
                excluded_client_hash=self._hasher.hash_client_id(
                    scope.current_client_id
                ),
            )
            if authority is None or (
                authority.variant_ref != variant.reference
                or authority.content_ref != variant.content_ref
                or authority.authority_manifest_ref != variant.manifest_ref
            ):
                return None
            return authority
        except Exception:
            return None

    def is_exact_active_closure(
        self,
        *,
        mapping_ref: VersionRef,
        parent_ref: VersionRef,
        variant_ref: VersionRef,
        authority_manifest_ref: VersionRef,
        provenance_ref: VersionRef,
    ) -> bool:
        """Recheck the exact mapping/manifest/provenance tuple at pack closure."""

        try:
            mapping = VersionRef.model_validate(mapping_ref)
            parent = VersionRef.model_validate(parent_ref)
            variant = VersionRef.model_validate(variant_ref)
            manifest = VersionRef.model_validate(authority_manifest_ref)
            provenance = VersionRef.model_validate(provenance_ref)
            row = self._connection.execute(
                """
                SELECT loo.parent_object_id, loo.parent_version, loo.parent_sha256,
                       loo.variant_object_id, loo.variant_version, loo.variant_sha256,
                       loo.authority_manifest_id, loo.authority_manifest_version,
                       loo.authority_manifest_sha256,
                       loo.provenance_id, loo.provenance_version,
                       cp.provenance_sha256
                  FROM case_leave_one_out_variants AS loo
                  JOIN case_provenance AS cp
                    ON cp.provenance_id = loo.provenance_id
                   AND cp.provenance_version = loo.provenance_version
                 WHERE loo.mapping_id = ? AND loo.mapping_version = ?
                   AND loo.mapping_sha256 = ? AND loo.state = 'ACTIVE'
                """,
                (mapping.object_id, mapping.version, mapping.content_sha256),
            ).fetchone()
            if row is None or tuple(row) != (
                parent.object_id,
                parent.version,
                parent.content_sha256,
                variant.object_id,
                variant.version,
                variant.content_sha256,
                manifest.object_id,
                manifest.version,
                manifest.content_sha256,
                provenance.object_id,
                provenance.version,
                provenance.content_sha256,
            ):
                return False
            active = self._connection.execute(
                """
                SELECT 1
                  FROM artifact_manifests AS manifest
                  JOIN active_artifacts AS active
                    ON active.manifest_id = manifest.manifest_id
                  JOIN runtime_epochs AS runtime
                    ON runtime.epoch = active.epoch AND runtime.state = 'ACTIVE'
                 WHERE manifest.manifest_id = ?
                   AND manifest.manifest_sha256 = ?
                   AND manifest.source_version = ?
                   AND manifest.state = 'ACTIVE' AND manifest.verified = 1
                """,
                (
                    manifest.object_id,
                    manifest.content_sha256,
                    str(manifest.version),
                ),
            ).fetchone()
            return active is not None
        except Exception:
            return False


__all__ = ["SqliteLeaveOneOutAuthorityVerifier"]
