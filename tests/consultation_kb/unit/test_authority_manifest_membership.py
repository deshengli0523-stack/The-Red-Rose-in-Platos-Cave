from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.retrieval.authority_snapshot import AuthoritativeSnapshotRepository
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.retrieval.filters import CandidateFilter
from consultation_kb.retrieval.resolver import (
    EvidenceResolutionDenied,
    EvidenceResolver,
    ScopedManifestContentReader,
)
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.retrieval_db_support import (
    activate_epoch,
    add_active_candidate,
    migrate_database,
)
from tests.consultation_kb.retrieval_support import (
    CLIENT_B,
    NOW,
    candidate,
    case_provenance,
    reference,
    scope,
)


def _databases(root: Path) -> tuple[Path, Path]:
    global_path = root / "global.sqlite3"
    client_path = root / "client.sqlite3"
    migrate_database(global_path, "global")
    migrate_database(client_path, "client")
    return global_path, client_path


def _claim(index: int, *, text: str) -> CandidateRef:
    return candidate(index, text=text, object_type="claim")


def _with_authority_version(value: CandidateRef, version: int) -> CandidateRef:
    return value.model_copy(
        update={
            "metadata": value.metadata.model_copy(
                update={
                    "manifest_ref": value.metadata.manifest_ref.model_copy(
                        update={"version": version}
                    )
                }
            )
        }
    )


def _insert_claim(connection: sqlite3.Connection, value: CandidateRef) -> None:
    connection.execute(
        "INSERT INTO claims("
        "claim_id, version, claim_object_ref, claim_object_size_bytes, "
        "claim_object_media_type, claim_sha256, cognitive_type, source_grade, "
        "framework_eligibility, empirical_support, model_confidence, "
        "review_status, effective_from, effective_to, review_due_at, "
        "applicability_json, privacy_scope, allowed_uses_json, provenance_json, "
        "theory_revision_id, theory_revision, theory_revision_sha256, created_at"
        ") VALUES (?, ?, ?, ?, 'text/plain', ?, 'explicit', 'T1', "
        "'ELIGIBLE', 'empirically_supported', NULL, 'APPROVED', NULL, NULL, "
        "NULL, '{}', 'GLOBAL', '[\"answer_support\"]', '{}', NULL, NULL, NULL, ?)",
        (
            value.reference.object_id,
            value.reference.version,
            f"sha256:{value.reference.content_sha256}",
            len(b"claim"),
            value.reference.content_sha256,
            NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        ),
    )


def _claim_with_passage(
    index: int,
    *,
    claim_text: str,
    passage_text: str,
) -> tuple[CandidateRef, bytes]:
    value = _claim(index, text=claim_text)
    body = passage_text.encode("utf-8")
    passage_ref = VersionRef(
        object_id=reference("passage", index).object_id,
        version=1,
        content_sha256=hashlib.sha256(body).hexdigest(),
    )
    return (
        value.model_copy(
            update={
                "content_ref": passage_ref,
                "metadata": value.metadata.model_copy(
                    update={"media_type": "text/plain", "size_bytes": len(body)}
                ),
                "location": value.location.model_copy(
                    update={"anchor_refs": (passage_ref,)}
                ),
            }
        ),
        body,
    )


def _insert_passage(
    connection: sqlite3.Connection,
    value: CandidateRef,
    *,
    with_claim_edge: bool,
    relation: str = "SUPPORTS",
) -> None:
    passage = value.content_ref
    source_id = next(iter(value.provenance.source_ids))
    timestamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT INTO sources(source_id, logical_path, logical_path_key, "
        "document_type, current_version, created_at) VALUES (?, ?, ?, 'text', 1, ?)",
        (source_id, f"source/{source_id}.txt", f"source/{source_id}.txt", timestamp),
    )
    connection.execute(
        "INSERT INTO source_versions("
        "source_id, version, content_sha256, content_object_ref, size_bytes, "
        "license, domain, language, sensitivity, source_grade, status, "
        "imported_at, metadata_json, metadata_sha256"
        ") VALUES (?, 1, ?, ?, 0, 'test', 'consultation', 'zh', 'public', "
        "'T1', 'APPROVED', ?, '{}', ?)",
        (source_id, "a" * 64, f"sha256:{'a' * 64}", timestamp, "b" * 64),
    )
    connection.execute(
        "INSERT INTO passages("
        "passage_id, version, source_id, source_version, document_type, "
        "structural_path, locator_json, normalized_text_sha256, raw_content_ref, "
        "retrieval_content_ref, context_before_ref, context_after_ref, "
        "extractor_version, privacy_scope, provenance_json, review_status, created_at"
        ") VALUES (?, ?, ?, 1, 'text', 'section/1', '{}', ?, ?, ?, NULL, NULL, "
        "'test-v1', 'GLOBAL', '{}', 'APPROVED', ?)",
        (
            passage.object_id,
            passage.version,
            source_id,
            passage.content_sha256,
            f"sha256:{passage.content_sha256}",
            f"sha256:{passage.content_sha256}",
            timestamp,
        ),
    )
    if with_claim_edge:
        evidence_role = "COUNTEREVIDENCE" if relation == "CONTRADICTS" else "PRIMARY"
        connection.execute(
            "INSERT INTO claim_evidence("
            "claim_id, claim_version, passage_id, passage_version, relation, "
            "evidence_role) VALUES (?, ?, ?, ?, ?, ?)",
            (
                value.reference.object_id,
                value.reference.version,
                passage.object_id,
                passage.version,
                relation,
                evidence_role,
            ),
        )


def _repository(
    global_path: Path, client_path: Path, *, index: int
) -> AuthoritativeSnapshotRepository:
    return AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: reference("authority_policy", index),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: index),
    )


def test_only_exact_content_authority_membership_grants_candidates(
    tmp_path: Path,
) -> None:
    global_path, client_path = _databases(tmp_path)
    published = _with_authority_version(_claim(101, text="published"), 5)
    unpublished = _claim(102, text="approved but not published")
    unpublished = unpublished.model_copy(
        update={
            "metadata": unpublished.metadata.model_copy(
                update={"manifest_ref": published.metadata.manifest_ref}
            )
        }
    )
    route_root_claim = _with_authority_version(
        _claim(103, text="route root masquerade"), 5
    )
    wrong_authority_root = _with_authority_version(
        _claim(104, text="wrong publication authority"), 6
    )

    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=5,
            index=9100,
            required_manifest_count=3,
        )
        for value in (
            published,
            unpublished,
            route_root_claim,
            wrong_authority_root,
        ):
            _insert_claim(connection, value)
        add_active_candidate(
            connection,
            epoch=5,
            operation_id=operation,
            artifact_key="claims",
            artifact_kind="claims",
            candidate=published,
        )
        add_active_candidate(
            connection,
            epoch=5,
            operation_id=operation,
            artifact_key="lexical",
            artifact_kind="lexical",
            candidate=route_root_claim,
        )
        add_active_candidate(
            connection,
            epoch=5,
            operation_id=operation,
            artifact_key="claims_wrong_authority",
            artifact_kind="claims",
            candidate=wrong_authority_root,
        )
        connection.commit()
    finally:
        connection.close()

    with _repository(global_path, client_path, index=9101) as repository:
        frozen = repository.freeze(scope())

        assert published.reference.object_id in frozen.allowed_ref_ids
        assert route_root_claim.reference.object_id in frozen.allowed_ref_ids
        assert wrong_authority_root.reference.object_id in frozen.allowed_ref_ids
        assert unpublished.reference.object_id not in frozen.allowed_ref_ids
        assert repository.candidate_status(published, frozen) == "visible"
        assert repository.candidate_status(unpublished, frozen) == "unauthorized"
        assert repository.candidate_status(route_root_claim, frozen) == "unauthorized"
        assert (
            repository.candidate_status(wrong_authority_root, frozen)
            == "unauthorized"
        )

        wrong_version = published.model_copy(
            update={
                "reference": published.reference.model_copy(update={"version": 2}),
                "content_ref": published.content_ref.model_copy(update={"version": 2}),
            }
        )
        wrong_hash = published.model_copy(
            update={
                "reference": published.reference.model_copy(
                    update={"content_sha256": "f" * 64}
                ),
                "content_ref": published.content_ref.model_copy(
                    update={"content_sha256": "f" * 64}
                ),
            }
        )
        wrong_manifest_version = published.model_copy(
            update={
                "metadata": published.metadata.model_copy(
                    update={
                        "manifest_ref": published.metadata.manifest_ref.model_copy(
                            update={"version": 2}
                        )
                    }
                )
            }
        )
        wrong_manifest_hash = published.model_copy(
            update={
                "metadata": published.metadata.model_copy(
                    update={
                        "manifest_ref": published.metadata.manifest_ref.model_copy(
                            update={"content_sha256": "e" * 64}
                        )
                    }
                )
            }
        )
        assert repository.candidate_status(wrong_version, frozen) == "unauthorized"
        assert repository.candidate_status(wrong_hash, frozen) == "unauthorized"
        assert (
            repository.candidate_status(wrong_manifest_version, frozen)
            == "unauthorized"
        )
        assert (
            repository.candidate_status(wrong_manifest_hash, frozen)
            == "unauthorized"
        )

    reader_connection = sqlite3.connect(global_path)
    try:
        reader = ScopedManifestContentReader(
            reader_connection,
            ContentStore(tmp_path / "empty-cas"),
            schema="main",
        )
        for denied in (
            unpublished,
            route_root_claim,
            wrong_version,
            wrong_hash,
            wrong_manifest_version,
            wrong_manifest_hash,
            wrong_authority_root,
        ):
            with pytest.raises(
                EvidenceResolutionDenied,
                match="EVIDENCE_RESOLUTION_DENIED",
            ):
                reader.read_verified(denied)
    finally:
        reader_connection.close()


def test_claim_passage_requires_exact_edge_and_resolves_only_legal_body(
    tmp_path: Path,
) -> None:
    global_path, client_path = _databases(tmp_path)
    denied, denied_body = _claim_with_passage(
        201,
        claim_text="unclosed claim",
        passage_text="secret denied passage",
    )
    legal, legal_body = _claim_with_passage(
        202,
        claim_text="closed claim",
        passage_text="governed legal passage",
    )
    denied = _with_authority_version(denied, 7)
    legal = _with_authority_version(legal, 7)
    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=7,
            index=9200,
            required_manifest_count=2,
        )
        for key, value, has_edge in (
            ("claims_denied", denied, False),
            ("claims_legal", legal, True),
        ):
            _insert_claim(connection, value)
            _insert_passage(connection, value, with_claim_edge=has_edge)
            add_active_candidate(
                connection,
                epoch=7,
                operation_id=operation,
                artifact_key=key,
                artifact_kind="claims",
                candidate=value,
            )
        connection.commit()
    finally:
        connection.close()

    store = ContentStore(tmp_path / "cas")
    staged = store.stage_bytes(
        legal_body,
        purpose="authority_test",
        manifest_id=legal.metadata.manifest_ref.object_id,
        media_type="text/plain",
    )
    store.finalize(staged)

    reader_connection = sqlite3.connect(global_path)
    try:
        reader_connection.execute("PRAGMA foreign_keys = ON")
        reader = ScopedManifestContentReader(
            reader_connection,
            store,
            schema="main",
        )
        with _repository(global_path, client_path, index=9201) as repository:
            frozen = repository.freeze(scope())
            assert repository.candidate_status(denied, frozen) == "unauthorized"
            assert repository.candidate_status(legal, frozen) == "visible"
            wrong_passage_version = legal.model_copy(
                update={
                    "content_ref": legal.content_ref.model_copy(
                        update={"version": 2}
                    )
                }
            )
            wrong_passage_hash = legal.model_copy(
                update={
                    "content_ref": legal.content_ref.model_copy(
                        update={"content_sha256": "d" * 64}
                    )
                }
            )
            assert (
                repository.candidate_status(wrong_passage_version, frozen)
                == "unauthorized"
            )
            assert (
                repository.candidate_status(wrong_passage_hash, frozen)
                == "unauthorized"
            )

            decision = CandidateFilter(repository).filter(
                scope(),
                (denied, legal),
                frozen,
            )
            assert decision.proof.reasons == {"not_authorized": 1}
            assert tuple(item.reference for item in decision.allowed) == (
                legal.reference,
            )
            resolved = EvidenceResolver(repository, reader).resolve_many(
                decision.allowed
            )
            assert tuple(item.body for item in resolved) == (legal_body,)

            safe_proof = decision.proof.model_dump_json()
            assert denied.reference.object_id not in safe_proof
            assert denied.content_ref.object_id not in safe_proof
            assert denied_body.decode("utf-8") not in safe_proof
    finally:
        reader_connection.close()


def test_case_candidate_is_closed_until_governed_loo_authority_exists(
    tmp_path: Path,
) -> None:
    global_path, client_path = _databases(tmp_path)
    value = _with_authority_version(_claim(301, text="case-derived"), 11)
    value = value.model_copy(
        update={"provenance": case_provenance(301, CLIENT_B)}
    )
    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=11,
            index=9300,
            required_manifest_count=1,
        )
        _insert_claim(connection, value)
        add_active_candidate(
            connection,
            epoch=11,
            operation_id=operation,
            artifact_key="claims",
            artifact_kind="claims",
            candidate=value,
        )
        connection.commit()
    finally:
        connection.close()

    with _repository(global_path, client_path, index=9301) as repository:
        frozen = repository.freeze(scope())
        assert value.reference.object_id in frozen.allowed_ref_ids
        assert repository.candidate_status(value, frozen) == "unauthorized"


def test_contradicts_only_passage_cannot_be_authorized_or_resolved(
    tmp_path: Path,
) -> None:
    global_path, client_path = _databases(tmp_path)
    contradicted, body = _claim_with_passage(
        351,
        claim_text="claim with counterevidence",
        passage_text="counterevidence is not supporting answer content",
    )
    contradicted = _with_authority_version(contradicted, 12)
    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=12,
            index=9350,
            required_manifest_count=1,
        )
        _insert_claim(connection, contradicted)
        _insert_passage(
            connection,
            contradicted,
            with_claim_edge=True,
            relation="CONTRADICTS",
        )
        add_active_candidate(
            connection,
            epoch=12,
            operation_id=operation,
            artifact_key="claims",
            artifact_kind="claims",
            candidate=contradicted,
        )
        connection.commit()
    finally:
        connection.close()

    store = ContentStore(tmp_path / "contradicts-cas")
    store.finalize(
        store.stage_bytes(
            body,
            purpose="authority_test",
            manifest_id=contradicted.metadata.manifest_ref.object_id,
            media_type="text/plain",
        )
    )
    with _repository(global_path, client_path, index=9351) as repository:
        frozen = repository.freeze(scope())
        assert repository.candidate_status(contradicted, frozen) == "unauthorized"

    reader_connection = sqlite3.connect(global_path)
    try:
        reader = ScopedManifestContentReader(
            reader_connection,
            store,
            schema="main",
        )
        with pytest.raises(EvidenceResolutionDenied):
            reader.read_verified(contradicted)
    finally:
        reader_connection.close()


def test_active_wiki_page_is_a_direct_content_authority_root(tmp_path: Path) -> None:
    global_path, client_path = _databases(tmp_path)
    body = "governed wiki body".encode("utf-8")
    value = _with_authority_version(
        candidate(401, text=body.decode(), object_type="wiki", channel="wiki"),
        9,
    )
    timestamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=9,
            index=9400,
            required_manifest_count=1,
        )
        connection.execute(
            "INSERT INTO wiki_revisions("
            "wiki_id, revision, slug, title, body_object_ref, "
            "body_object_size_bytes, body_object_media_type, body_sha256, "
            "base_revision, diff_kind, diff_object_ref, diff_object_size_bytes, "
            "diff_object_media_type, diff_sha256, review_status, review_due_at, "
            "approval_request_id, created_at"
            ") VALUES (?, ?, 'governed-wiki', 'Governed Wiki', ?, ?, "
            "'text/plain', ?, 0, 'ADD', ?, 0, 'application/json', ?, 'ACTIVE', "
            "NULL, 'approval-wiki', ?)",
            (
                value.reference.object_id,
                value.reference.version,
                f"sha256:{value.reference.content_sha256}",
                len(body),
                value.reference.content_sha256,
                f"sha256:{'c' * 64}",
                "c" * 64,
                timestamp,
            ),
        )
        add_active_candidate(
            connection,
            epoch=9,
            operation_id=operation,
            artifact_key="wiki_page",
            artifact_kind="wiki_page",
            candidate=value,
        )
        connection.commit()
    finally:
        connection.close()

    store = ContentStore(tmp_path / "wiki-cas")
    store.finalize(
        store.stage_bytes(
            body,
            purpose="wiki_authority_test",
            manifest_id=value.metadata.manifest_ref.object_id,
            media_type="text/plain",
        )
    )
    reader_connection = sqlite3.connect(global_path)
    try:
        reader = ScopedManifestContentReader(
            reader_connection,
            store,
            schema="main",
        )
        with _repository(global_path, client_path, index=9401) as repository:
            frozen = repository.freeze(scope())
            decision = CandidateFilter(repository).filter(scope(), (value,), frozen)
            assert tuple(item.body for item in EvidenceResolver(repository, reader).resolve_many(decision.allowed)) == (body,)
    finally:
        reader_connection.close()
