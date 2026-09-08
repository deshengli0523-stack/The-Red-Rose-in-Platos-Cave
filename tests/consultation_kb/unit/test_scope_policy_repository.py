from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.scope_policy import (
    ScopePolicyError,
    ScopePolicyRepository,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyFieldValueMembers,
)
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 1, 0, tzinfo=timezone.utc)


class _DirectApprovalExecutor:
    def __init__(self, connection: sqlite3.Connection, ids: IdFactory) -> None:
        self._connection = connection
        self._ids = ids

    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> str:
        del approval_request_id, descriptor
        with transaction(self._connection):
            apply(self._connection)
        return self._ids.object_id(operation_kind)


def _ids() -> IdFactory:
    values: Iterator[int] = iter(range(1, 10_000))
    return IdFactory(FixedClock(NOW), lambda: next(values))


def _repository(
    tmp_path: Path,
) -> tuple[
    sqlite3.Connection,
    ContentStore,
    IdFactory,
    ScopePolicyRepository,
]:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    ids = _ids()
    store = ContentStore(tmp_path / "global_cas")
    executor = _DirectApprovalExecutor(connection, ids)
    return (
        connection,
        store,
        ids,
        ScopePolicyRepository(
            connection,
            content_store=store,
            approval_executor=executor,
            clock=FixedClock(NOW),
        ),
    )


def _document(
    policy_id: str,
    *,
    version: int,
    evaluator_version: int | None = None,
) -> ScopePolicyDocument:
    return ScopePolicyDocument(
        policy_id=policy_id,
        version=version,
        evaluator_id="deterministic_c1_scope",
        evaluator_version=(version if evaluator_version is None else evaluator_version),
        rule_members=frozenset(
            {
                "adult_population",
                "contraindication_match",
                "domain_match",
                "exclusion_match",
            }
        ),
        context_fields=frozenset(
            {"contraindications", "domain", "exclusions", "population"}
        ),
        field_value_members=(
            ScopePolicyFieldValueMembers(
                context_field="contraindications",
                value_members=frozenset({"medical_diagnosis", "none_observed"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="domain",
                value_members=frozenset(
                    {"career_consultation", "emotional_consultation"}
                ),
            ),
            ScopePolicyFieldValueMembers(
                context_field="exclusions",
                value_members=frozenset({"none_observed", "outside_scope"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="population",
                value_members=frozenset({"adult", "adolescent"}),
            ),
        ),
        missing_field_semantics="insufficient_context",
        known_empty_semantics="present_empty",
    )


def _approval(ids: IdFactory) -> str:
    return ids.object_id("approval_request")


def test_prepare_persists_hash_only_record_and_unapproved_resolution_fails_closed(
    tmp_path: Path,
) -> None:
    connection, _store, ids, repository = _repository(tmp_path)
    try:
        document = _document(ids.object_id("scope_policy"), version=1)
        record = repository.prepare(document, effective_from=NOW)

        assert record.status == "PREPARED"
        assert record.semantic_ref == repository.semantic_ref(document)
        assert record.cas_object_sha256 == record.semantic_ref.content_sha256
        assert repository.load_document(record.semantic_ref) == document
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_NOT_APPROVED"):
            repository.resolve_approved(record.semantic_ref)

        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(scope_policy_versions)")
        }
        assert (
            not {
                "body",
                "document_json",
                "evaluator_id",
                "rule_members",
                "context_fields",
                "field_value_members",
            }
            & columns
        )
        row_text = repr(
            connection.execute("SELECT * FROM scope_policy_versions").fetchone()
        )
        assert "deterministic_c1_scope" not in row_text
        assert "emotional_consultation" not in row_text
        assert str(tmp_path) not in row_text
    finally:
        connection.close()


def test_document_closes_field_vocabulary_and_presence_semantics() -> None:
    ids = _ids()
    document = _document(ids.object_id("scope_policy"), version=1)

    with pytest.raises(ValidationError):
        ScopePolicyDocument.model_validate(
            document.model_copy(
                update={
                    "context_fields": frozenset(
                        {*document.context_fields, "unregistered_field"}
                    )
                }
            ).model_dump(mode="python")
        )
    with pytest.raises(ValidationError):
        ScopePolicyDocument.model_validate(
            {
                **document.model_dump(mode="python"),
                "missing_field_semantics": "treat_as_empty",
            }
        )


def test_approval_is_one_shot_exact_and_effective_interval_is_enforced(
    tmp_path: Path,
) -> None:
    connection, _store, ids, repository = _repository(tmp_path)
    try:
        document = _document(ids.object_id("scope_policy"), version=1)
        record = repository.prepare(
            document,
            effective_from=NOW,
            effective_to=NOW + timedelta(days=30),
        )
        approval_id = _approval(ids)
        approved = repository.approve(
            record.semantic_ref,
            approval_request_id=approval_id,
        )

        assert approved.status == "APPROVED"
        assert approved.approval_request_id == approval_id
        assert repository.resolve_approved(record.semantic_ref, at=NOW) == document
        assert repository.resolve_current(document.policy_id, at=NOW) == (
            approved,
            document,
        )
        with pytest.raises(
            ScopePolicyError, match="SCOPE_POLICY_STATE_TRANSITION_INVALID"
        ):
            repository.approve(record.semantic_ref, approval_request_id=_approval(ids))
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_NOT_EFFECTIVE"):
            repository.resolve_approved(
                record.semantic_ref,
                at=NOW + timedelta(days=30),
            )
    finally:
        connection.close()


def test_approved_row_without_one_shot_binding_is_not_authority(
    tmp_path: Path,
) -> None:
    connection, _store, ids, repository = _repository(tmp_path)
    try:
        document = _document(ids.object_id("scope_policy"), version=1)
        prepared = repository.prepare(document, effective_from=NOW)
        created_at = connection.execute(
            """
            SELECT created_at FROM scope_policy_versions
             WHERE policy_id = ? AND version = ?
            """,
            (document.policy_id, document.version),
        ).fetchone()[0]
        connection.execute(
            """
            UPDATE scope_policy_versions
               SET status = 'APPROVED', approval_request_id = ?,
                   approved_at = ?, updated_at = ?
             WHERE policy_id = ? AND version = ?
            """,
            (
                _approval(ids),
                created_at,
                created_at,
                document.policy_id,
                document.version,
            ),
        )

        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_APPROVAL_CONFLICT"):
            repository.resolve_approved(prepared.semantic_ref)
    finally:
        connection.close()


def test_successor_supersedes_exact_predecessor_and_revoke_is_approval_bound(
    tmp_path: Path,
) -> None:
    connection, _store, ids, repository = _repository(tmp_path)
    try:
        policy_id = ids.object_id("scope_policy")
        first = repository.prepare(_document(policy_id, version=1), effective_from=NOW)
        repository.approve(first.semantic_ref, approval_request_id=_approval(ids))
        second_document = _document(policy_id, version=2)

        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_VERSION_CONFLICT"):
            repository.prepare(second_document, effective_from=NOW)
        second = repository.prepare(
            second_document,
            effective_from=NOW,
            supersedes_ref=first.semantic_ref,
        )
        second_approval = _approval(ids)
        repository.approve(
            second.semantic_ref,
            approval_request_id=second_approval,
        )

        assert repository.get_record(first.semantic_ref).status == "SUPERSEDED"
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_NOT_APPROVED"):
            repository.resolve_approved(first.semantic_ref)
        assert repository.resolve_approved(second.semantic_ref) == second_document

        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_APPROVAL_CONFLICT"):
            repository.revoke(
                second.semantic_ref,
                approval_request_id=second_approval,
            )
        assert repository.get_record(second.semantic_ref).status == "APPROVED"

        revocation_id = _approval(ids)
        revoked = repository.revoke(
            second.semantic_ref,
            approval_request_id=revocation_id,
        )
        assert revoked.status == "REVOKED"
        assert revoked.revocation_approval_request_id == revocation_id
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_NOT_APPROVED"):
            repository.resolve_approved(second.semantic_ref)

        third_document = _document(policy_id, version=3)
        third = repository.prepare(
            third_document,
            effective_from=NOW,
            supersedes_ref=second.semantic_ref,
        )
        assert third.status == "PREPARED"
    finally:
        connection.close()


def test_forged_hash_missing_or_corrupt_cas_and_size_mismatch_fail_closed(
    tmp_path: Path,
) -> None:
    connection, store, ids, repository = _repository(tmp_path)
    try:
        document = _document(ids.object_id("scope_policy"), version=1)
        record = repository.prepare(document, effective_from=NOW)
        approval_id = _approval(ids)
        repository.approve(record.semantic_ref, approval_request_id=approval_id)

        forged_hash = "f" * 64
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE scope_policy_versions
               SET semantic_sha256 = ?, cas_object_ref = ?, cas_object_sha256 = ?
             WHERE policy_id = ? AND version = ?
            """,
            (
                forged_hash,
                f"sha256:{forged_hash}",
                forged_hash,
                document.policy_id,
                document.version,
            ),
        )
        forged_ref = VersionRef(
            object_id=document.policy_id,
            version=document.version,
            content_sha256=forged_hash,
        )
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_CONTENT_INVALID"):
            repository.get_record(forged_ref)

        connection.execute(
            """
            UPDATE scope_policy_versions
               SET semantic_sha256 = ?, cas_object_ref = ?, cas_object_sha256 = ?,
                   cas_object_size_bytes = cas_object_size_bytes + 1
             WHERE policy_id = ? AND version = ?
            """,
            (
                record.semantic_ref.content_sha256,
                record.cas_object_ref,
                record.cas_object_sha256,
                document.policy_id,
                document.version,
            ),
        )
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_CONTENT_INVALID"):
            repository.get_record(record.semantic_ref)

        connection.execute(
            """
            UPDATE scope_policy_versions SET cas_object_size_bytes = ?
             WHERE policy_id = ? AND version = ?
            """,
            (
                record.cas_object_size_bytes,
                document.policy_id,
                document.version,
            ),
        )
        reference = store.reference(
            content_sha256=record.cas_object_sha256,
            size_bytes=record.cas_object_size_bytes,
            media_type=record.cas_object_media_type,
        )
        reference.path.write_bytes(b"corrupt")
        with pytest.raises(ScopePolicyError, match="SCOPE_POLICY_CONTENT_INVALID"):
            repository.get_record(record.semantic_ref)
    finally:
        connection.close()
