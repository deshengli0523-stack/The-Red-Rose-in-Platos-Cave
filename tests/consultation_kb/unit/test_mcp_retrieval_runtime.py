from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.retrieval_runtime import (
    CLIENT_GRAPH_WORKER_PROTOCOL_V1,
    ActiveRetrievalRuntime,
    _CaseRetriever,
    _candidate_item,
    _loo_replacements,
    _open_global_authority_connection,
    _ref_key,
)
from consultation_kb.mcp.schemas import QueryClientGraphInput, WeightedPathInput
from consultation_kb.retrieval.contracts import CandidateRef, LeaveOneOutVariant
from consultation_kb.retrieval.filters import CandidateFilter, StaticAuthorityGuard
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.retrieval_support import (
    CLIENT_A,
    CLIENT_B,
    NOW,
    candidate,
    case_provenance,
    reference,
    scope,
    snapshot,
)


class _Scopes:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object, BoundTransport | None]] = []

    def client_id_for_binding(self, binding: BoundTransport) -> str:
        del binding
        return CLIENT_A

    def invoke_scoped_graph(
        self,
        tool_name: str,
        request: object,
        *,
        binding: BoundTransport | None,
    ) -> object:
        self.calls.append((tool_name, request, binding))
        return {"channel": "scoped-worker", "tool": tool_name}


def _runtime(
    tmp_path: Path,
) -> tuple[ActiveRetrievalRuntime, sqlite3.Connection, _Scopes]:
    database = tmp_path / "global.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    scopes = _Scopes()
    return (
        ActiveRetrievalRuntime(
            global_database=database,
            global_connection=connection,
            content_store=ContentStore(tmp_path / "global-content"),
            client_scopes=scopes,
            clock=FixedClock(NOW),
            id_factory=IdFactory(FixedClock(NOW), lambda: 17),
        ),
        connection,
        scopes,
    )


def test_client_graph_operations_are_explicit_scoped_worker_capabilities(
    tmp_path: Path,
) -> None:
    runtime, connection, scopes = _runtime(tmp_path)
    binding = BoundTransport("transport-1", "h" * 32)
    try:
        graph = runtime.invoke(
            "query_client_graph",
            QueryClientGraphInput(
                session_handle="h" * 32,
                query="relationship",
                limit=10,
                max_depth=2,
            ),
            binding=binding,
        )
        path = runtime.invoke(
            "weighted_path",
            WeightedPathInput(
                session_handle="h" * 32,
                graph_scope="client",
                source_ref=("fact_019f55c5-5e2c-7e20-bfe3-65480ce3bb0d"),
                target_ref=("fact_019f55c5-5e2c-7e20-bfe3-65480ce3bb0e"),
            ),
            binding=binding,
        )
    finally:
        runtime.close()
        connection.close()

    assert graph == {"channel": "scoped-worker", "tool": "query_client_graph"}
    assert path == {"channel": "scoped-worker", "tool": "weighted_path"}
    assert [(name, call_binding) for name, _request, call_binding in scopes.calls] == [
        ("query_client_graph", binding),
        ("weighted_path", binding),
    ]
    assert set(CLIENT_GRAPH_WORKER_PROTOCOL_V1) == {
        "preview_dependency_impact",
        "query_client_graph",
        "weighted_client_path",
    }
    assert all(
        forbidden not in fields
        for fields in CLIENT_GRAPH_WORKER_PROTOCOL_V1.values()
        for forbidden in ("client_id", "path", "sql")
    )


def test_safe_candidate_projection_marks_leave_one_out_without_client_ids() -> None:
    replacement = candidate(
        31,
        provenance=case_provenance(31, CLIENT_B),
        allowed_uses=frozenset({"consultation"}),
        text="safe replacement",
    )

    rendered = _candidate_item(
        replacement,
        b"safe replacement",
        loo_replacements=frozenset({_ref_key(replacement.reference)}),
    )
    encoded = json.dumps(rendered, ensure_ascii=False, default=str)

    assert rendered["text"] == "safe replacement"
    assert rendered["provenance"]["client_exclusion_status"] == (
        "leave_one_subject_out_applied"
    )
    assert rendered["provenance"]["case_contributor_count"] == 1
    assert CLIENT_A not in encoded
    assert CLIENT_B not in encoded
    assert "case_contributor_client_ids" not in encoded


def test_hmac_leave_one_out_projection_uses_the_current_client_alias() -> None:
    hasher = CaseContributorHasher(hash_key=b"h" * 32)
    current_alias = hasher.pseudonymous_client_id(CLIENT_A)
    other_alias = hasher.pseudonymous_client_id(CLIENT_B)
    original = candidate(
        32,
        provenance=case_provenance(32, current_alias, other_alias),
        allowed_uses=frozenset({"answer_support"}),
        text="original governed case",
    )
    replacement_ref = reference("passage", 33)
    replacement = LeaveOneOutVariant(
        reference=replacement_ref,
        content_ref=replacement_ref,
        object_type=original.object_type,
        manifest_ref=original.metadata.manifest_ref,
        review_status="approved",
        allowed_uses=frozenset({"answer_support"}),
        approved_at=NOW,
        sensitivity=1,
        source_grade="K3",
        source_count=1,
        provenance=case_provenance(33, other_alias),
        location=original.location,
        freshness=original.freshness,
        media_type="text/plain",
        size_bytes=3,
    )
    original = original.model_copy(
        update={
            "metadata": original.metadata.model_copy(
                update={
                    "contributor_identity_scheme": "hmac_alias_v1",
                    "leave_one_out": replacement,
                }
            )
        }
    )

    class _ExactVerifier:
        def __init__(self, approved: bool) -> None:
            self.approved = approved

        def is_exact_approved_variant(self, **kwargs: object) -> bool:
            assert kwargs["original"] == original
            assert kwargs["variant"] == replacement
            return self.approved

    exact_scope = scope(client_id=CLIENT_A, use="answer_support")
    exact_snapshot = snapshot(original)

    replacements = _loo_replacements(
        (original,),
        current_client_id=CLIENT_A,
        contributor_identity_hasher=hasher,
        leave_one_out_verifier=_ExactVerifier(True),  # type: ignore[arg-type]
        scope=exact_scope,
        authority_snapshot=exact_snapshot,
    )

    assert replacements == frozenset({_ref_key(replacement.reference)})
    assert _loo_replacements(
        (original,),
        current_client_id=CLIENT_A,
        contributor_identity_hasher=hasher,
        leave_one_out_verifier=_ExactVerifier(False),  # type: ignore[arg-type]
        scope=exact_scope,
        authority_snapshot=exact_snapshot,
    ) == frozenset()


def test_case_route_keeps_other_subject_case_and_excludes_current_subject() -> None:
    hasher = CaseContributorHasher(hash_key=b"h" * 32)
    current_alias = hasher.pseudonymous_client_id(CLIENT_A)
    other_alias = hasher.pseudonymous_client_id(CLIENT_B)

    def governed_case(index: int, contributor_alias: str) -> CandidateRef:
        value = candidate(
            index,
            provenance=case_provenance(index, contributor_alias),
            channel="case",
            object_type="case",
            allowed_uses=frozenset({"answer_support"}),
            text=f"governed case {index}",
        )
        return value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={"contributor_identity_scheme": "hmac_alias_v1"}
                )
            }
        )

    current_subject_case = governed_case(34, current_alias)
    other_subject_case = governed_case(35, other_alias)
    exact_snapshot = snapshot(current_subject_case, other_subject_case)

    class _Retriever:
        artifact_binding = None

        def search(
            self,
            query: str,
            route_scope: object,
            authority_snapshot: object,
            *,
            limit: int,
        ) -> tuple[CandidateRef, ...]:
            del query, route_scope, authority_snapshot
            return (current_subject_case, other_subject_case)[:limit]

    routed = _CaseRetriever(_Retriever(), _Retriever()).search(
        "relationship pattern",
        scope(use="answer_support"),
        exact_snapshot,
        limit=10,
    )
    decision = CandidateFilter(
        StaticAuthorityGuard(exact_snapshot),
        contributor_identity_hasher=hasher,
    ).filter(
        scope(use="answer_support"),
        routed,
        exact_snapshot,
    )

    assert tuple(item.reference for item in decision.allowed) == (
        other_subject_case.reference,
    )
    assert decision.proof.reasons == {"source_client_excluded": 1}


def test_case_route_includes_a_governed_case_found_only_by_vector() -> None:
    exact_case = candidate(
        36,
        provenance=case_provenance(36, CLIENT_B),
        channel="case",
        object_type="case",
        allowed_uses=frozenset({"answer_support"}),
        text="semantic-only governed case",
    )

    class _Retriever:
        artifact_binding = None

        def __init__(self, values: tuple[CandidateRef, ...]) -> None:
            self._values = values

        def search(
            self,
            query: str,
            route_scope: object,
            authority_snapshot: object,
            *,
            limit: int,
        ) -> tuple[CandidateRef, ...]:
            del query, route_scope, authority_snapshot
            return self._values[:limit]

    exact_snapshot = snapshot(exact_case)
    values = _CaseRetriever(
        _Retriever(()),
        _Retriever((exact_case,)),
    ).search(
        "same meaning with different wording",
        scope(use="answer_support"),
        exact_snapshot,
        limit=10,
    )

    assert values == (exact_case,)


def test_global_authority_reader_never_attaches_a_customer_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "global.sqlite3"
    setup = sqlite3.connect(database)
    setup.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
    setup.commit()
    setup.close()

    connection = _open_global_authority_connection(database)
    try:
        databases = tuple(
            (str(row[1]), str(row[2]))
            for row in connection.execute("PRAGMA database_list").fetchall()
        )
        assert databases[0] == ("main", str(database))
        assert databases[1] == ("client_authority", "")
        assert connection.execute(
            "SELECT count(*) FROM client_authority.runtime_epochs"
        ).fetchone() == (0,)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO main.sentinel(value) VALUES ('x')")
    finally:
        connection.close()
