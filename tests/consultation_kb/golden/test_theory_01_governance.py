from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.theory import (
    PrimaryCounselorApprovalRequired,
    TheoryActivationForbidden,
    TheoryRevisionService,
)
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyFieldValueMembers,
)
from consultation_kb.models.theory import TheoryRevisionDraft, TheoryScope
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


pytestmark = [pytest.mark.golden, pytest.mark.acceptance_id("THEORY-01")]
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


def _service(
    tmp_path: Path,
) -> tuple[TheoryRevisionService, TheoryRevisionDraft, sqlite3.Connection]:
    counter = iter(range(1, 100))
    ids = IdFactory(FixedClock(NOW), lambda: next(counter))
    connection = connect_database(tmp_path / "scope.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    executor = _ConnectionApprovalExecutor(connection, ids)
    repository = ScopePolicyRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope-cas"),
        approval_executor=executor,
        clock=FixedClock(NOW),
    )
    policy = ScopePolicyDocument(
        policy_id=ids.object_id("scope_policy"),
        version=1,
        evaluator_id="deterministic_c1_scope",
        evaluator_version=1,
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
    prepared_policy = repository.prepare(
        policy,
        effective_from=NOW,
        effective_to=NOW + timedelta(days=365),
    )
    approved_policy = repository.approve(
        prepared_policy.semantic_ref,
        approval_request_id=ids.object_id("approval_request"),
    )
    source_id = ids.object_id("source")
    passage_id = ids.object_id("passage")
    draft = TheoryRevisionDraft(
        theory_id=ids.object_id("theory"),
        source_ref=VersionRef(
            object_id=source_id,
            version=1,
            content_sha256="1" * 64,
        ),
        document_sha256="1" * 64,
        author="主咨询师",
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
        core_claims=("先澄清事实，再解释关系模式。",),
        methods=("时序澄清",),
        contraindications=("不可替代医学诊断",),
        counterexamples=("事实不足时不作确定判断",),
        passage_refs=(
            VersionRef(object_id=passage_id, version=1, content_sha256="2" * 64),
        ),
        citation_refs=(
            VersionRef(object_id=source_id, version=1, content_sha256="1" * 64),
        ),
        empirical_support="unassessed",
        scope_policy_ref=approved_policy.semantic_ref,
    )
    return (
        TheoryRevisionService(
            id_factory=ids,
            clock=FixedClock(NOW),
            approval_executor=executor,
            scope_policy_repository=repository,
        ),
        draft,
        connection,
    )


def test_only_primary_counselor_can_prepare_c1(tmp_path: Path) -> None:
    service, draft, connection = _service(tmp_path)
    try:
        request = service.propose(draft, actor="codex")

        with pytest.raises(PrimaryCounselorApprovalRequired):
            service.approve(request.request_id, actor="codex")

        prepared = service.approve(
            request.request_id,
            actor="primary_counselor",
            approval_request_id=service.id_factory.object_id("approval_request"),
        )
        assert prepared.source_grade == "C1"
        assert prepared.status == "prepared"
        assert prepared.claim_refs
        assert service.get_active(prepared.theory_id) is None
    finally:
        connection.close()


def test_theory_service_has_no_direct_activation_path(tmp_path: Path) -> None:
    service, draft, connection = _service(tmp_path)
    try:
        request = service.propose(draft, actor="codex")
        prepared = service.approve(
            request.request_id,
            actor="primary_counselor",
            approval_request_id=service.id_factory.object_id("approval_request"),
        )

        with pytest.raises(TheoryActivationForbidden):
            service.activate(prepared.theory_id, prepared.revision)
    finally:
        connection.close()
