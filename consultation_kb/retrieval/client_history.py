"""Body-free client history retrieval for a pre-scoped worker."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Literal, Protocol, TypeAlias

from pydantic import field_validator

from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    NonNegativeInt,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EvidenceChannel,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
    SourceGrade,
)
from consultation_kb.knowledge.anchors import deterministic_object_id

from .contracts import CandidateMetadata, CandidateRef, ScoreComponent


ClientHistoryQueryCategory: TypeAlias = Literal[
    "continuity",
    "current_profile",
    "relationship_history",
    "unresolved_items",
]


def client_history_derivation_rule_ref() -> VersionRef:
    """Return the source-addressed built-in rule used by the P4 worker stub."""

    return VersionRef(
        object_id=deterministic_object_id(
            "derivation_rule",
            "client-history-candidate-v1",
        ),
        version=1,
        content_sha256=hashlib.sha256(
            b"consultation-kb-client-history-candidate-v1"
        ).hexdigest(),
    )


class ClientHistoryQuery(StrictModel):
    """Public worker request: deliberately no client, path, table, or SQL."""

    request_id: Uuid7String
    session_handle: NonEmptyStr
    query_category: ClientHistoryQueryCategory
    as_of: datetime | None = None
    limit: int = 20

    @field_validator("limit")
    @classmethod
    def _bounded_limit(cls, value: int) -> int:
        if type(value) is not int or not 1 <= value <= 100:
            raise ValueError("client history limit must be between 1 and 100")
        return value


class ClientHistoryResult(StrictModel):
    request_id: Uuid7String
    candidates: tuple[CandidateRef, ...]
    runtime_epoch: NonNegativeInt


class ClientHistoryTransport(Protocol):
    def query_client_history(
        self,
        request: ClientHistoryQuery,
    ) -> ClientHistoryResult: ...


class Uuid7Factory(Protocol):
    def uuid7(self) -> str: ...


class ScopedClientHistoryService:
    """Worker-internal service bound to one already-authorized client DB."""

    _ARTIFACT_KEYS: dict[ClientHistoryQueryCategory, tuple[str, ...]] = {
        "continuity": ("client_profile", "client_fact_snapshot", "client_graph"),
        "current_profile": ("client_profile",),
        "relationship_history": ("client_fact_snapshot", "client_graph"),
        "unresolved_items": ("client_profile", "client_fact_snapshot"),
    }

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        current_client_id: ClientId,
        derivation_rule_ref: VersionRef,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection
        self._client_id = current_client_id
        self._derivation_rule_ref = VersionRef.model_validate(derivation_rule_ref)

    def query(self, request: ClientHistoryQuery) -> ClientHistoryResult:
        if type(request) is not ClientHistoryQuery:
            raise TypeError("CLIENT_HISTORY_QUERY_REQUIRED")
        if request.as_of is None:
            epoch_row = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchone()
        else:
            epoch_row = self._connection.execute(
                "SELECT epoch FROM runtime_epochs "
                "WHERE state IN ('ACTIVE', 'RETIRED') AND activated_at IS NOT NULL "
                "AND julianday(activated_at) <= julianday(?) "
                "ORDER BY julianday(activated_at) DESC, epoch DESC LIMIT 1",
                (request.as_of.isoformat().replace("+00:00", "Z"),),
            ).fetchone()
        if epoch_row is None:
            return ClientHistoryResult(
                request_id=request.request_id,
                candidates=(),
                runtime_epoch=0,
            )
        epoch = int(epoch_row[0])
        artifact_keys = self._ARTIFACT_KEYS[request.query_category]
        placeholders = ",".join("?" for _ in artifact_keys)
        rows = self._connection.execute(
            "SELECT manifest.manifest_id, manifest.manifest_sha256, "
            "manifest.source_version, manifest.created_at, active.artifact_key, "
            "member.object_type, member.object_id, member.object_sha256, "
            "member.source_version, member.source_lineage_json, "
            "member.media_type, member.size_bytes "
            "FROM active_artifacts AS active "
            "JOIN artifact_manifests AS manifest "
            "  ON manifest.manifest_id = active.manifest_id "
            "JOIN artifact_members AS member "
            "  ON member.manifest_id = manifest.manifest_id "
            f"WHERE active.epoch = ? AND active.artifact_key IN ({placeholders}) "
            "AND manifest.state = 'ACTIVE' AND manifest.verified = 1 "
            "AND ((active.artifact_key = 'client_profile' "
            "      AND member.object_type = 'profile_json') "
            "  OR (active.artifact_key = 'client_fact_snapshot' "
            "      AND member.object_type = 'fact_snapshot') "
            "  OR (active.artifact_key = 'client_graph' "
            "      AND member.object_type = 'client_graph')) "
            "ORDER BY active.artifact_key, member.ordinal LIMIT ?",
            (epoch, *artifact_keys, request.limit),
        ).fetchall()
        candidates = tuple(self._candidate(row) for row in rows)
        return ClientHistoryResult(
            request_id=request.request_id,
            candidates=candidates,
            runtime_epoch=epoch,
        )

    def _candidate(self, row: tuple[object, ...]) -> CandidateRef:
        try:
            manifest_version = int(str(row[2]))
            member_version = int(str(row[8]))
            lineage_raw = json.loads(str(row[9]))
            if (
                not isinstance(lineage_raw, list)
                or any(type(item) is not str for item in lineage_raw)
            ):
                raise ValueError
            if lineage_raw != sorted(set(lineage_raw)):
                raise ValueError
            lineage = tuple(lineage_raw)
            channel: EvidenceChannel = (
                "profile" if str(row[4]) == "client_profile" else "client_history"
            )
            source_grade: SourceGrade = "K2" if channel == "profile" else "K1"
            reference = VersionRef(
                object_id=str(row[6]),
                version=member_version,
                content_sha256=str(row[7]),
            )
            manifest_ref = VersionRef(
                object_id=str(row[0]),
                version=manifest_version,
                content_sha256=str(row[1]),
            )
            provenance = Provenance(
                client_ids=frozenset({self._client_id}),
                provenance_scope="client_private",
                private_owner_client_id=self._client_id,
                derivation_rule_ref=self._derivation_rule_ref,
            )
            metadata = CandidateMetadata(
                manifest_ref=manifest_ref,
                review_status="approved",
                allowed_uses=frozenset(
                    {
                        "answer_support",
                        "consultation",
                        "continuity",
                        "next_session_context",
                    }
                ),
                approved_at=_parse_utc(row[3]),
                sensitivity=3,
                source_grade=source_grade,
                source_count=1,
                source_lineage_hashes=lineage,
                media_type=str(row[10]),
                size_bytes=int(str(row[11])),
            )
            return CandidateRef(
                reference=reference,
                content_ref=reference,
                object_type=str(row[5]),
                channel=channel,
                metadata=metadata,
                provenance=provenance,
                location=EvidenceLocator(
                    locator_kind="client_fact",
                    anchor_refs=(reference,),
                    display_locator=f"fact:{reference.object_id}",
                    locator_policy_ref=self._derivation_rule_ref,
                ),
                freshness=EvidenceFreshnessSnapshot(
                    status="current",
                    evaluated_at=_parse_utc(row[3]),
                    source_observed_at=None,
                    last_reviewed_at=_parse_utc(row[3]),
                    review_due_at=None,
                    policy_ref=self._derivation_rule_ref,
                ),
                score=1.0,
                score_components=(
                    ScoreComponent(channel="client_history", rank=1, score=1.0),
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("CLIENT_HISTORY_ARTIFACT_INVALID") from exc


class ClientHistoryRetriever:
    """Control-plane adapter that can neither name nor probe another client."""

    def __init__(
        self,
        transport: ClientHistoryTransport,
        *,
        session_handle: str,
        query_category: ClientHistoryQueryCategory,
        request_id_factory: Uuid7Factory,
    ) -> None:
        self._transport = transport
        self._session_handle = session_handle
        self._query_category = query_category
        self._request_ids = request_id_factory

    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        del query, scope
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("CLIENT_HISTORY_LIMIT_INVALID")
        request_id = self._request_ids.uuid7()
        result = self._transport.query_client_history(
            ClientHistoryQuery(
                request_id=request_id,
                session_handle=self._session_handle,
                query_category=self._query_category,
                # Fetch the closed worker-side candidate surface before the
                # live authority intersection.  Applying the caller's limit
                # here would let a revoked first row crowd out a legal row.
                limit=100,
            )
        )
        if result.request_id != request_id:
            raise RuntimeError("CLIENT_HISTORY_RESPONSE_INVALID")
        # Pre-filter before rank/limit. The deterministic CandidateFilter still
        # runs afterwards and enforces private-owner/use/provenance gates.
        return tuple(
            candidate
            for candidate in result.candidates
            if candidate.reference.object_id in authority_snapshot.allowed_ref_ids
        )[:limit]


__all__ = [
    "ClientHistoryQuery",
    "ClientHistoryQueryCategory",
    "ClientHistoryResult",
    "ClientHistoryRetriever",
    "ClientHistoryTransport",
    "ScopedClientHistoryService",
    "Uuid7Factory",
    "client_history_derivation_rule_ref",
]


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("client history timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("client history timestamp is invalid")
    return parsed
