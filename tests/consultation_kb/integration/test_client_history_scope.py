from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.errors import WorkflowOperationalError
from consultation_kb.core.ids import IdFactory
from consultation_kb.retrieval.client_history import ClientHistoryRetriever
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.retrieval.filters import CandidateFilter, StaticAuthorityGuard
from consultation_kb.security.scoped_worker import (
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    QueryClientHistoryCandidatesRequest,
    QueryClientHistoryCandidatesResponse,
    WorkerProtocolError,
    decode_request,
)
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.retrieval_db_support import (
    activate_epoch,
    add_active_candidate,
    add_manifest_candidate,
    migrate_database,
)
from tests.consultation_kb.retrieval_support import (
    CLIENT_A,
    CLIENT_B,
    NOW,
    candidate,
    private_provenance,
    scope,
    snapshot,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped worker"),
]
REQUEST_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"


@dataclass
class _Validator:
    calls: list[tuple[str, str]] = field(default_factory=list)

    def assert_valid(
        self,
        capability_token: str,
        *,
        required_permission: str,
    ) -> None:
        self.calls.append((capability_token, required_permission))


def _scoped_root(tmp_path: Path):
    root = (tmp_path / "clients" / "opaque-a").resolve()
    root.mkdir(parents=True)
    marker = b"scope-a\n"
    (root / ".scope-id").write_bytes(marker)
    migrate_database(root / "client.sqlite3", "client")
    profile = candidate(
        41,
        text="current profile",
        provenance=private_provenance(41, CLIENT_A),
        channel="profile",
        object_type="profile_json",
        allowed_uses=frozenset(
            {"answer_support", "consultation", "continuity", "next_session_context"}
        ),
    )
    facts = candidate(
        42,
        text="fact snapshot",
        provenance=private_provenance(42, CLIENT_A),
        channel="client_history",
        object_type="fact_snapshot",
        allowed_uses=frozenset(
            {"answer_support", "consultation", "continuity", "next_session_context"}
        ),
    )
    graph = candidate(
        43,
        text="temporal graph",
        provenance=private_provenance(43, CLIENT_A),
        channel="client_history",
        object_type="client_graph",
        allowed_uses=frozenset(
            {"answer_support", "consultation", "continuity", "next_session_context"}
        ),
    )
    connection = sqlite3.connect(root / "client.sqlite3")
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=1,
            index=4001,
            required_manifest_count=3,
        )
        for key, kind, value in (
            ("client_profile", "profile", profile),
            ("client_fact_snapshot", "fact_snapshot", facts),
            ("client_graph", "graph", graph),
        ):
            add_active_candidate(
                connection,
                epoch=1,
                operation_id=operation,
                artifact_key=key,
                artifact_kind=kind,
                candidate=value,
            )
        profile_markdown = candidate(
            44,
            text="duplicate profile rendering",
            provenance=private_provenance(44, CLIENT_A),
            channel="profile",
            object_type="profile_markdown",
        )
        review_commitment = candidate(
            45,
            text="internal review commitment",
            provenance=private_provenance(45, CLIENT_A),
            channel="client_history",
            object_type="mutation_review_commitment",
        )
        add_manifest_candidate(
            connection,
            manifest_id=profile.metadata.manifest_ref.object_id,
            candidate=profile_markdown,
            ordinal=1,
        )
        add_manifest_candidate(
            connection,
            manifest_id=facts.metadata.manifest_ref.object_id,
            candidate=review_commitment,
            ordinal=1,
        )
        bodies = (
            (profile, b"current profile"),
            (facts, b"fact snapshot"),
            (graph, b"temporal graph"),
            (profile_markdown, b"duplicate profile rendering"),
            (review_commitment, b"internal review commitment"),
        )
        store = ContentStore(root / "cas")
        for value, body in bodies:
            stored = store.finalize(
                store.stage_bytes(
                    body,
                    purpose="client_history_fixture",
                    manifest_id=value.metadata.manifest_ref.object_id,
                    media_type=value.metadata.media_type,
                )
            )
            assert stored.content_sha256 == value.reference.content_sha256
            assert stored.size_bytes == value.metadata.size_bytes
        manifest_rows = connection.execute(
            "SELECT manifest_id, operation_id, artifact_key, artifact_kind, "
            "source_version FROM artifact_manifests ORDER BY manifest_id"
        ).fetchall()
        for manifest_row in manifest_rows:
            member_rows = connection.execute(
                "SELECT ordinal, object_type, object_id, object_sha256, "
                "source_version, media_type, size_bytes, source_lineage_json "
                "FROM artifact_members WHERE manifest_id = ? ORDER BY ordinal",
                (manifest_row[0],),
            ).fetchall()
            members = tuple(
                ManifestMember(
                    ordinal=int(member[0]),
                    object_type=str(member[1]),
                    object_id=str(member[2]),
                    object_sha256=str(member[3]),
                    source_version=int(str(member[4])),
                    media_type=str(member[5]),
                    size_bytes=int(member[6]),
                    source_lineage_hashes=tuple(json.loads(str(member[7]))),
                )
                for member in member_rows
            )
            digest = manifest_sha256(
                manifest_id=str(manifest_row[0]),
                operation_id=str(manifest_row[1]),
                artifact_key=str(manifest_row[2]),
                artifact_kind=str(manifest_row[3]),
                source_version=int(str(manifest_row[4])),
                members=members,
            )
            connection.execute(
                "UPDATE artifact_manifests SET manifest_sha256 = ? "
                "WHERE manifest_id = ?",
                (digest, manifest_row[0]),
            )
        connection.execute(
            "UPDATE client_fact_authority "
            "SET commit_version = 1, client_id = ? WHERE singleton = 1",
            (CLIENT_A,),
        )
        connection.commit()
    finally:
        connection.close()
    (tmp_path / "clients" / "opaque-b-canary").write_text(
        "CLIENT_B_PRIVATE_CANARY",
        encoding="ascii",
    )
    return root, marker, (profile, facts, graph)


def test_wire_request_has_only_session_handle_and_query_category() -> None:
    assert set(QueryClientHistoryCandidatesRequest.model_fields) == {
        "schema_version",
        "operation",
        "request_id",
        "session_handle",
        "query_category",
        "as_of",
    }
    for forbidden in ("client_id", "path", "sql", "payload", "limit"):
        with pytest.raises(ValidationError):
            QueryClientHistoryCandidatesRequest.model_validate(
                {
                    "request_id": REQUEST_ID,
                    "session_handle": "session-handle",
                    "query_category": "continuity",
                    forbidden: CLIENT_B,
                }
            )
    raw = json.dumps(
        {
            "operation": "query_client_history_candidates",
            "request_id": REQUEST_ID,
            "schema_version": "1.0",
            "session_handle": "session-handle",
            "query_category": "continuity",
            "path": r"C:\other-client\client.sqlite3",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        decode_request(raw)


def test_real_scoped_worker_returns_only_current_client_body_free_refs(
    tmp_path: Path,
) -> None:
    root, marker, expected = _scoped_root(tmp_path)
    validator = _Validator()
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=CLIENT_A,
        ),
        capability_token="opaque-capability",
        validator=validator,
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )
    broker.start()
    try:
        authority = snapshot(*expected)
        retriever = ClientHistoryRetriever(
            broker,
            session_handle="opaque-capability",
            query_category="continuity",
            request_id_factory=IdFactory(FixedClock(NOW), lambda: 5001),
        )
        returned = retriever.search(
            "ignored by body-free history channel",
            scope(),
            authority,
            limit=10,
        )
    finally:
        broker.close()

    assert {item.reference.object_id for item in returned} == {
        item.reference.object_id for item in expected
    }
    assert all(type(item) is CandidateRef for item in returned)
    assert all(item.provenance.private_owner_client_id == CLIENT_A for item in returned)
    assert all(item.provenance.client_ids == frozenset({CLIENT_A}) for item in returned)
    assert all(item.channel in {"profile", "client_history"} for item in returned)
    assert "body" not in CandidateRef.model_fields
    assert "text" not in CandidateRef.model_fields
    assert "CLIENT_B_PRIVATE_CANARY" not in "".join(
        item.model_dump_json() for item in returned
    )
    assert all(permission == "client_read" for _token, permission in validator.calls)


def test_scoped_history_executes_the_requested_as_of_time(tmp_path: Path) -> None:
    root, marker, _expected = _scoped_root(tmp_path)
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=CLIENT_A,
        ),
        capability_token="opaque-capability",
        validator=_Validator(),
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )
    broker.start()
    try:
        before = broker.call(
            QueryClientHistoryCandidatesRequest(
                request_id=REQUEST_ID,
                session_handle="opaque-capability",
                query_category="continuity",
                as_of=NOW - timedelta(microseconds=1),
            )
        )
        current = broker.call(
            QueryClientHistoryCandidatesRequest(
                request_id="017f22e2-79b0-7cc3-98c4-dc0c0c073990",
                session_handle="opaque-capability",
                query_category="continuity",
                as_of=NOW,
            )
        )
    finally:
        broker.close()

    assert isinstance(before, QueryClientHistoryCandidatesResponse)
    assert before.runtime_epoch == 0 and before.candidates == ()
    assert isinstance(current, QueryClientHistoryCandidatesResponse)
    assert current.runtime_epoch == 1 and len(current.candidates) == 3


def test_private_history_supports_continuity_but_never_case_example(
    tmp_path: Path,
) -> None:
    root, marker, expected = _scoped_root(tmp_path)
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=CLIENT_A,
        ),
        capability_token="opaque-capability",
        validator=_Validator(),
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )
    broker.start()
    try:
        authority = snapshot(*expected)
        returned = ClientHistoryRetriever(
            broker,
            session_handle="opaque-capability",
            query_category="continuity",
            request_id_factory=IdFactory(FixedClock(NOW), lambda: 5002),
        ).search("", scope(), authority, limit=10)
    finally:
        broker.close()

    guard = StaticAuthorityGuard(authority)
    continuity = CandidateFilter(guard).filter(scope(), returned, authority)
    case_example = CandidateFilter(guard).filter(
        scope(use="case_example"),
        returned,
        authority,
    )
    wrong_owner = CandidateFilter(guard).filter(
        scope(client_id=CLIENT_B),
        returned,
        authority,
    )

    assert len(continuity.allowed) == 3
    assert case_example.allowed == ()
    assert case_example.proof.reasons == {"use_denied": 3}
    assert wrong_owner.allowed == ()
    assert wrong_owner.proof.reasons == {"scope_denied": 3}


@pytest.mark.acceptance_id("VER-01")
def test_client_private_query_gate_rejects_corrupt_active_cas_before_results(
    tmp_path: Path,
) -> None:
    root, marker, expected = _scoped_root(tmp_path)
    profile = expected[0]
    ContentStore(root / "cas").reference(
        content_sha256=profile.reference.content_sha256,
        media_type=profile.metadata.media_type,
        size_bytes=profile.metadata.size_bytes,
    ).path.write_bytes(b"tampered profile")
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=CLIENT_A,
        ),
        capability_token="opaque-capability",
        validator=_Validator(),
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )
    broker.start()
    try:
        with pytest.raises(
            WorkflowOperationalError,
            match="^CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED$",
        ):
            broker.call(
                QueryClientHistoryCandidatesRequest(
                    request_id=REQUEST_ID,
                    session_handle="opaque-capability",
                    query_category="continuity",
                )
            )
    finally:
        broker.close()


@pytest.mark.acceptance_id("VER-01")
def test_client_private_query_gate_rejects_retained_candidates_without_active_epoch(
    tmp_path: Path,
) -> None:
    root, marker, _expected = _scoped_root(tmp_path)
    connection = sqlite3.connect(root / "client.sqlite3")
    try:
        connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
        )
        connection.commit()
    finally:
        connection.close()

    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=CLIENT_A,
        ),
        capability_token="opaque-capability",
        validator=_Validator(),
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )
    broker.start()
    try:
        with pytest.raises(
            WorkflowOperationalError,
            match="^CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED$",
        ):
            broker.call(
                QueryClientHistoryCandidatesRequest(
                    request_id=REQUEST_ID,
                    session_handle="opaque-capability",
                    query_category="continuity",
                    as_of=NOW,
                )
            )
    finally:
        broker.close()
