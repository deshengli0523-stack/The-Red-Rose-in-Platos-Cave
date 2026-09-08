from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.theory import (
    PrimaryCounselorApprovalRequired,
    TheoryGovernanceError,
    TheoryRevisionService,
)
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.knowledge.publication import KnowledgePublicationError
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyFieldValueMembers,
)
from consultation_kb.models.theory import (
    TheoryRevision,
    TheoryRevisionDraft,
    TheoryScope,
)
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


class _ConnectionApprovalExecutor:
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


def _scope_authority(
    tmp_path: Path,
) -> tuple[
    sqlite3.Connection,
    ContentStore,
    IdFactory,
    _ConnectionApprovalExecutor,
    ScopePolicyRepository,
]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    connection = connect_database(tmp_path / "scope.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    values: Iterator[int] = iter(range(1000, 100_000))
    ids = IdFactory(FixedClock(NOW), lambda: next(values))
    executor = _ConnectionApprovalExecutor(connection, ids)
    store = ContentStore(tmp_path / "scope-cas")
    return (
        connection,
        store,
        ids,
        executor,
        ScopePolicyRepository(
            connection,
            content_store=store,
            approval_executor=executor,
            clock=FixedClock(NOW),
        ),
    )


def _scope_document(policy_id: str, *, version: int = 1) -> ScopePolicyDocument:
    return ScopePolicyDocument(
        policy_id=policy_id,
        version=version,
        evaluator_id="deterministic_c1_scope",
        evaluator_version=version,
        rule_members=frozenset({"domain_match", "population_match"}),
        context_fields=frozenset({"domain", "population"}),
        field_value_members=(
            ScopePolicyFieldValueMembers(
                context_field="domain",
                value_members=frozenset({"emotional_consultation"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="population",
                value_members=frozenset({"adult"}),
            ),
        ),
    )


def _approve_scope_policy(
    repository: ScopePolicyRepository,
    ids: IdFactory,
    *,
    effective_from: datetime,
    effective_to: datetime | None,
) -> VersionRef:
    document = _scope_document(ids.object_id("scope_policy"))
    prepared = repository.prepare(
        document,
        effective_from=effective_from,
        effective_to=effective_to,
    )
    return repository.approve(
        prepared.semantic_ref,
        approval_request_id=ids.object_id("approval_request"),
    ).semantic_ref


def _prepare_theory(
    draft: TheoryRevisionDraft,
    *,
    ids: IdFactory,
    executor: _ConnectionApprovalExecutor,
    repository: ScopePolicyRepository | None,
) -> tuple[TheoryRevisionService, TheoryRevision]:
    service = TheoryRevisionService(
        id_factory=ids,
        clock=FixedClock(NOW),
        approval_executor=executor,
        scope_policy_repository=repository,
    )
    proposal = service.propose(draft, actor="codex")
    revision = service.approve(
        proposal.request_id,
        actor="primary_counselor",
        approval_request_id=ids.object_id("approval_request"),
    )
    return service, revision


def _draft() -> TheoryRevisionDraft:
    counter = iter(range(1, 100))
    ids = IdFactory(FixedClock(NOW), lambda: next(counter))
    source = VersionRef(
        object_id=ids.object_id("source"),
        version=1,
        content_sha256="1" * 64,
    )
    return TheoryRevisionDraft(
        theory_id=ids.object_id("theory"),
        source_ref=source,
        document_sha256=source.content_sha256,
        author="primary counselor",
        declared_version="1.0",
        effective_from=NOW,
        effective_to=NOW + timedelta(days=365),
        scope=TheoryScope(
            domains=frozenset({"emotional_consultation"}),
            populations=frozenset({"adult"}),
            contexts=frozenset({"relationship"}),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset({"medical_diagnosis"}),
        ),
        core_claims=("clarify facts before interpreting patterns",),
        methods=("temporal clarification",),
        contraindications=("not a medical diagnosis",),
        counterexamples=("insufficient facts",),
        passage_refs=(
            VersionRef(
                object_id=ids.object_id("passage"),
                version=1,
                content_sha256="2" * 64,
            ),
        ),
        citation_refs=(source,),
        empirical_support="unassessed",
        scope_policy_ref=VersionRef(
            object_id=ids.object_id("scope_policy"),
            version=1,
            content_sha256="3" * 64,
        ),
    )


@pytest.mark.parametrize(
    "field",
    (
        "core_claims",
        "methods",
        "contraindications",
        "counterexamples",
        "passage_refs",
        "citation_refs",
    ),
)
def test_c1_revision_rejects_missing_governed_content(field: str) -> None:
    payload = _draft().model_dump(mode="json")
    payload[field] = []
    with pytest.raises(ValidationError):
        TheoryRevisionDraft.model_validate(payload)


def test_theory_approval_without_p1_executor_fails_closed() -> None:
    draft = _draft()
    service = TheoryRevisionService(clock=FixedClock(NOW))
    proposal = service.propose(draft, actor="codex")
    with pytest.raises(PrimaryCounselorApprovalRequired):
        service.approve(
            proposal.request_id,
            actor="primary_counselor",
            approval_request_id=IdFactory(FixedClock(NOW), lambda: 50).object_id(
                "approval_request"
            ),
        )


def test_theory_approval_without_scope_policy_authority_fails_closed(
    tmp_path: Path,
) -> None:
    connection, _store, ids, executor, _repository = _scope_authority(tmp_path)
    try:
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_REQUIRED",
        ):
            _prepare_theory(
                _draft(),
                ids=ids,
                executor=executor,
                repository=None,
            )
    finally:
        connection.close()


def test_theory_approval_rejects_prepared_or_mismatched_scope_policy(
    tmp_path: Path,
) -> None:
    connection, _store, ids, executor, repository = _scope_authority(tmp_path)
    try:
        document = _scope_document(ids.object_id("scope_policy"))
        prepared = repository.prepare(document, effective_from=NOW)
        for reference in (
            prepared.semantic_ref,
            prepared.semantic_ref.model_copy(update={"content_sha256": "f" * 64}),
            prepared.semantic_ref.model_copy(update={"version": 2}),
        ):
            draft = _draft().model_copy(update={"scope_policy_ref": reference})
            with pytest.raises(
                TheoryGovernanceError,
                match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
            ):
                _prepare_theory(
                    draft,
                    ids=ids,
                    executor=executor,
                    repository=repository,
                )
    finally:
        connection.close()


def test_theory_approval_rejects_corrupt_or_revoked_scope_policy(
    tmp_path: Path,
) -> None:
    connection, store, ids, executor, repository = _scope_authority(tmp_path)
    try:
        reference = _approve_scope_policy(
            repository,
            ids,
            effective_from=NOW - timedelta(days=1),
            effective_to=NOW + timedelta(days=400),
        )
        record = repository.get_record(reference)
        content_reference = store.reference(
            content_sha256=record.cas_object_sha256,
            size_bytes=record.cas_object_size_bytes,
            media_type=record.cas_object_media_type,
        )
        content_reference.path.write_bytes(b"corrupt")
        draft = _draft().model_copy(update={"scope_policy_ref": reference})
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
        ):
            _prepare_theory(
                draft,
                ids=ids,
                executor=executor,
                repository=repository,
            )
    finally:
        connection.close()

    connection, _store, ids, executor, repository = _scope_authority(
        tmp_path / "revoked"
    )
    try:
        reference = _approve_scope_policy(
            repository,
            ids,
            effective_from=NOW - timedelta(days=1),
            effective_to=NOW + timedelta(days=400),
        )
        repository.revoke(
            reference,
            approval_request_id=ids.object_id("approval_request"),
        )
        draft = _draft().model_copy(update={"scope_policy_ref": reference})
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
        ):
            _prepare_theory(
                draft,
                ids=ids,
                executor=executor,
                repository=repository,
            )
    finally:
        connection.close()


def test_theory_approval_rejects_superseded_scope_policy(tmp_path: Path) -> None:
    connection, _store, ids, executor, repository = _scope_authority(tmp_path)
    try:
        policy_id = ids.object_id("scope_policy")
        first = repository.prepare(
            _scope_document(policy_id),
            effective_from=NOW - timedelta(days=1),
            effective_to=NOW + timedelta(days=400),
        )
        first = repository.approve(
            first.semantic_ref,
            approval_request_id=ids.object_id("approval_request"),
        )
        second = repository.prepare(
            _scope_document(policy_id, version=2),
            effective_from=NOW - timedelta(days=1),
            effective_to=NOW + timedelta(days=400),
            supersedes_ref=first.semantic_ref,
        )
        repository.approve(
            second.semantic_ref,
            approval_request_id=ids.object_id("approval_request"),
        )

        draft = _draft().model_copy(update={"scope_policy_ref": first.semantic_ref})
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
        ):
            _prepare_theory(
                draft,
                ids=ids,
                executor=executor,
                repository=repository,
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("policy_start", "policy_end"),
    (
        (NOW - timedelta(days=2), NOW - timedelta(days=1)),
        (NOW, NOW + timedelta(days=30)),
        (NOW + timedelta(days=1), NOW + timedelta(days=400)),
    ),
)
def test_scope_policy_must_cover_theory_effective_interval(
    tmp_path: Path,
    policy_start: datetime,
    policy_end: datetime,
) -> None:
    connection, _store, ids, executor, repository = _scope_authority(tmp_path)
    try:
        reference = _approve_scope_policy(
            repository,
            ids,
            effective_from=policy_start,
            effective_to=policy_end,
        )
        draft = _draft().model_copy(update={"scope_policy_ref": reference})
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
        ):
            _prepare_theory(
                draft,
                ids=ids,
                executor=executor,
                repository=repository,
            )
    finally:
        connection.close()


def test_approved_scope_policy_survives_resolver_restart_and_revocation_closes_it(
    tmp_path: Path,
) -> None:
    connection, store, ids, executor, repository = _scope_authority(tmp_path)
    try:
        reference = _approve_scope_policy(
            repository,
            ids,
            effective_from=NOW - timedelta(days=1),
            effective_to=NOW + timedelta(days=400),
        )
        draft = _draft().model_copy(update={"scope_policy_ref": reference})
        _service, revision = _prepare_theory(
            draft,
            ids=ids,
            executor=executor,
            repository=repository,
        )

        restarted_repository = ScopePolicyRepository(
            connection,
            content_store=store,
            approval_executor=executor,
            clock=FixedClock(NOW),
        )
        restarted_service = TheoryRevisionService(
            id_factory=ids,
            clock=FixedClock(NOW),
            approval_executor=executor,
            scope_policy_repository=restarted_repository,
        )
        restarted_service.assert_scope_policy_authority(revision)

        restarted_repository.revoke(
            reference,
            approval_request_id=ids.object_id("approval_request"),
        )
        with pytest.raises(
            TheoryGovernanceError,
            match="THEORY_SCOPE_POLICY_AUTHORITY_INVALID",
        ):
            restarted_service.assert_scope_policy_authority(revision)
    finally:
        connection.close()


def test_scope_policy_revoked_after_publication_prepare_blocks_activation(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        policy_ref = knowledge.theory.scope_policy_ref
        harness.scope_policies.revoke(
            policy_ref,
            approval_request_id=harness.confirm(
                harness.scope_policies.preview_revoke(policy_ref)
            ),
        )

        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_THEORY_SCOPE_POLICY_INVALID",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT status FROM theory_revisions WHERE theory_id = ? AND revision = ?",
            (knowledge.theory.theory_id, knowledge.theory.revision),
        ).fetchone() == ("PREPARED",)
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_production_successor_requires_exact_previous_revision_ref(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        current = knowledge.theory
        draft = TheoryRevisionDraft(
            theory_id=current.theory_id,
            source_ref=current.source_ref,
            document_sha256=current.document_sha256,
            author=current.author,
            declared_version="2.0",
            effective_from=current.effective_from,
            effective_to=current.effective_to,
            scope=current.scope,
            core_claims=("second governed interpretation",),
            methods=current.methods,
            contraindications=current.contraindications,
            counterexamples=current.counterexamples,
            passage_refs=current.passage_refs,
            citation_refs=current.citation_refs,
            empirical_support=current.empirical_support,
            scope_policy_ref=current.scope_policy_ref,
            supersedes_ref=knowledge.theory_service.version_ref(
                current.theory_id, current.revision
            ).model_copy(update={"content_sha256": "f" * 64}),
        )
        proposal = knowledge.theory_service.propose(draft, actor="codex")
        descriptor = knowledge.theory_service.preview(proposal.request_id)
        with pytest.raises(
            TheoryGovernanceError, match="THEORY_LINEAGE_AUTHORITY_INVALID"
        ):
            knowledge.theory_service.approve(
                proposal.request_id,
                actor="primary_counselor",
                approval_request_id=harness.confirm(descriptor),
            )
        assert harness.connection.execute(
            "SELECT count(*) FROM theory_revisions WHERE theory_id = ?",
            (current.theory_id,),
        ).fetchone() == (1,)
    finally:
        harness.close()
