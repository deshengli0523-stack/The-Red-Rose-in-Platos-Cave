from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.provenance import (
    ProvenanceClosure,
    ProvenanceEdge,
    ProvenanceError,
    ProvenancePolicyManifest,
    ProvenanceRepository,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import Provenance
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(300, 2000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, value: int) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=f"{value:064x}",
    )


def test_case_closure_inherits_all_cases_and_contributors() -> None:
    ids = _ids()
    rule = _ref(ids, "policy", 1)
    closure = ProvenanceClosure(
        ProvenancePolicyManifest(
            manifest_ref=_ref(ids, "policy_manifest", 2), rule_members=(rule,)
        )
    )
    clients = [f"client_{letter * 12}" for letter in "abc"]
    values = []
    for index, client_id in enumerate(clients, 1):
        values.append(
            Provenance(
                case_ids=frozenset({ids.object_id("case")}),
                client_ids=frozenset({client_id}),
                provenance_scope="case_derived",
                case_contributor_client_ids=frozenset({client_id}),
                derivation_rule_ref=rule,
            )
        )

    result = closure.compute(values, derivation_rule_ref=rule)
    assert result.provenance_scope == "case_derived"
    assert result.client_ids == frozenset(clients)
    assert len(result.case_ids) == 3


def test_private_provenance_cannot_escape_to_global() -> None:
    ids = _ids()
    rule = _ref(ids, "policy", 1)
    closure = ProvenanceClosure(
        ProvenancePolicyManifest(
            manifest_ref=_ref(ids, "policy_manifest", 2), rule_members=(rule,)
        )
    )
    private = Provenance(
        client_ids=frozenset({"client_" + "a" * 12}),
        provenance_scope="client_private",
        private_owner_client_id="client_" + "a" * 12,
        derivation_rule_ref=rule,
    )
    with pytest.raises(ProvenanceError, match="PRIVATE_PROVENANCE_CANNOT_ESCAPE"):
        closure.compute(
            (private,), derivation_rule_ref=rule, target_scope="global_source"
        )


def test_derived_from_cycle_is_rejected() -> None:
    ids = _ids()
    rule = _ref(ids, "policy", 1)
    first = _ref(ids, "claim", 2)
    second = _ref(ids, "claim", 3)
    edges = (
        ProvenanceEdge(
            source_ref=first,
            target_ref=second,
            relation="DERIVED_FROM",
            derivation_rule_ref=rule,
        ),
        ProvenanceEdge(
            source_ref=second,
            target_ref=first,
            relation="DERIVED_FROM",
            derivation_rule_ref=rule,
        ),
    )
    with pytest.raises(ProvenanceError, match="PROVENANCE_CYCLE"):
        ProvenanceClosure.assert_acyclic(edges)


def test_unapproved_derivation_rule_is_rejected() -> None:
    ids = _ids()
    approved = _ref(ids, "policy", 1)
    other = _ref(ids, "policy", 2)
    closure = ProvenanceClosure(
        ProvenancePolicyManifest(
            manifest_ref=_ref(ids, "policy_manifest", 3), rule_members=(approved,)
        )
    )
    source = Provenance(
        source_ids=frozenset({ids.object_id("source")}),
        provenance_scope="global_source",
        derivation_rule_ref=approved,
    )
    with pytest.raises(ProvenanceError, match="DERIVATION_RULE_NOT_APPROVED"):
        closure.compute((source,), derivation_rule_ref=other)


def test_provenance_repository_resolves_exact_versions_and_rejects_cycle(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    ids = _ids()
    first_id = ids.object_id("artifact")
    second_id = ids.object_id("artifact")
    for artifact_id, digest in ((first_id, "a" * 64), (second_id, "b" * 64)):
        connection.execute(
            """
            INSERT INTO artifact_versions(
                artifact_id, version, artifact_kind, source_catalog_version,
                metadata_sha256, manifest_id, state, created_at
            ) VALUES (?, 1, 'graph', 0, ?, NULL, 'CURRENT', ?)
            """,
            (artifact_id, digest, "2026-07-18T08:00:00.000000Z"),
        )
    rule = _ref(ids, "policy", 91)
    repository = ProvenanceRepository(
        connection,
        policy_manifest=ProvenancePolicyManifest(
            manifest_ref=_ref(ids, "policy_manifest", 92), rule_members=(rule,)
        ),
        allowed_relations={"DERIVED_FROM"},
    )
    first = VersionRef(object_id=first_id, version=1, content_sha256="a" * 64)
    second = VersionRef(object_id=second_id, version=1, content_sha256="b" * 64)
    lineage = Provenance(
        source_ids=frozenset({ids.object_id("source")}),
        provenance_scope="global_source",
        derivation_rule_ref=rule,
    )
    repository.add(
        ProvenanceEdge(
            source_ref=first,
            target_ref=second,
            relation="DERIVED_FROM",
            derivation_rule_ref=rule,
        ),
        source_type="artifact",
        target_type="artifact",
        target_provenance=lineage,
    )
    with pytest.raises(ProvenanceError, match="PROVENANCE_CYCLE"):
        repository.add(
            ProvenanceEdge(
                source_ref=second,
                target_ref=first,
                relation="DERIVED_FROM",
                derivation_rule_ref=rule,
            ),
            source_type="artifact",
            target_type="artifact",
            target_provenance=lineage,
        )
    with pytest.raises(ProvenanceError, match="PROVENANCE_OBJECT_VERSION_NOT_FOUND"):
        repository.add(
            ProvenanceEdge(
                source_ref=first.model_copy(update={"version": 2}),
                target_ref=second,
                relation="DERIVED_FROM",
                derivation_rule_ref=rule,
            ),
            source_type="artifact",
            target_type="artifact",
            target_provenance=lineage,
        )
    connection.close()
