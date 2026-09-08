from __future__ import annotations

import sqlite3
from pathlib import Path

from consultation_kb.lifecycle.rebuild import SqliteRebuildAuthoritySource
from consultation_kb.lifecycle.rebuild_registry import AuthoritySourceSpec
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore


SCOPE_SHA256 = "a" * 64


def _base_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE deletion_authority_state(
            singleton INTEGER PRIMARY KEY,
            tombstone_epoch INTEGER NOT NULL
        );
        INSERT INTO deletion_authority_state(singleton, tombstone_epoch)
        VALUES (1, 1);
        CREATE TABLE tombstones(
            target_type TEXT NOT NULL,
            target_id_hash TEXT NOT NULL,
            source_lineage_hash TEXT NOT NULL
        );
        """
    )
    return connection


def _records(
    connection: sqlite3.Connection,
    *,
    scope: str,
    tables: tuple[str, ...],
    store: ContentStore,
) -> dict[str, int]:
    sources = tuple(
        AuthoritySourceSpec(database_scope=scope, table=table)  # type: ignore[arg-type]
        for table in tables
    )
    authority = SqliteRebuildAuthoritySource(
        connection,
        database_scope=scope,  # type: ignore[arg-type]
        scope_sha256=SCOPE_SHA256,
        content_store=store,
    )
    inventory = authority.inventory(
        database_scope=scope,  # type: ignore[arg-type]
        scope_sha256=SCOPE_SHA256,
        sources=sources,
    )
    return {
        key: len(value)
        for key, value in authority.read_exact(inventory).items()
    }


def test_global_parent_tombstones_remove_every_linked_authority_row(
    tmp_path: Path,
) -> None:
    connection = _base_connection()
    store = ContentStore(tmp_path / "global-cas")
    artifact = store.finalize(
        store.stage_bytes(
            b"case provenance artifact",
            purpose="authority_test",
            manifest_id="manifest_019f55c5-5e2c-7e20-bfe3-65480ce3bb0d",
            media_type="application/octet-stream",
        )
    )
    try:
        connection.executescript(
            """
            CREATE TABLE claims(
                claim_id TEXT, version INTEGER, review_status TEXT
            );
            CREATE TABLE passages(
                passage_id TEXT, version INTEGER, review_status TEXT
            );
            CREATE TABLE claim_evidence(
                claim_id TEXT, claim_version INTEGER,
                passage_id TEXT, passage_version INTEGER, relation TEXT
            );
            CREATE TABLE wiki_revisions(
                wiki_id TEXT, revision INTEGER, review_status TEXT
            );
            CREATE TABLE wiki_revision_claims(
                wiki_id TEXT, wiki_revision INTEGER, section_key TEXT,
                claim_id TEXT, claim_version INTEGER
            );
            CREATE TABLE theory_revisions(
                theory_id TEXT, revision INTEGER, status TEXT
            );
            CREATE TABLE theory_revision_passages(
                theory_id TEXT, theory_revision INTEGER,
                passage_id TEXT, passage_version INTEGER
            );
            CREATE TABLE case_versions(
                case_id TEXT, version INTEGER, state TEXT,
                provenance_id TEXT, provenance_version INTEGER
            );
            CREATE TABLE case_authorizations(
                case_id TEXT, case_version INTEGER,
                authorization_id TEXT, authorization_version INTEGER,
                reuse_authorized INTEGER, revoked_at TEXT
            );
            CREATE TABLE case_review_decisions(
                case_id TEXT, case_version INTEGER, review_version INTEGER,
                release_policy_version INTEGER, decision TEXT
            );
            CREATE TABLE case_provenance(
                provenance_id TEXT, provenance_version INTEGER,
                artifact_version INTEGER, derivation_rule_version INTEGER,
                artifact_sha256 TEXT
            );

            INSERT INTO claims VALUES ('claim-1', 1, 'APPROVED');
            INSERT INTO passages VALUES ('passage-1', 1, 'APPROVED');
            INSERT INTO claim_evidence
            VALUES ('claim-1', 1, 'passage-1', 1, 'supports');
            INSERT INTO wiki_revisions VALUES ('wiki-1', 1, 'ACTIVE');
            INSERT INTO wiki_revision_claims
            VALUES ('wiki-1', 1, 'section-1', 'claim-1', 1);
            INSERT INTO theory_revisions VALUES ('theory-1', 1, 'ACTIVE');
            INSERT INTO theory_revision_passages
            VALUES ('theory-1', 1, 'passage-1', 1);

            INSERT INTO case_versions
            VALUES ('case-1', 1, 'ACTIVE', 'provenance-1', 1);
            INSERT INTO case_authorizations
            VALUES ('case-1', 1, 'authorization-1', 1, 1, NULL);
            INSERT INTO case_review_decisions
            VALUES ('case-1', 1, 1, 1, 'approved');
            """
        )
        connection.execute(
            "INSERT INTO case_provenance VALUES (?, ?, ?, ?, ?)",
            ("provenance-1", 1, 1, 1, artifact.content_sha256),
        )
        for object_type, object_id in (
            ("claim", "claim-1"),
            ("passage", "passage-1"),
            ("case", "case-1"),
        ):
            connection.execute(
                "INSERT INTO tombstones VALUES (?, ?, ?)",
                (
                    object_type,
                    target_hash(object_type, object_id),
                    lineage_hash(object_type, object_id),
                ),
            )

        tables = (
            "claim_evidence",
            "wiki_revision_claims",
            "theory_revision_passages",
            "case_authorizations",
            "case_review_decisions",
            "case_provenance",
        )
        assert _records(
            connection,
            scope="global",
            tables=tables,
            store=store,
        ) == {f"global.{table}": 0 for table in tables}
    finally:
        connection.close()


def test_fact_parent_tombstone_removes_every_linked_authority_row(
    tmp_path: Path,
) -> None:
    connection = _base_connection()
    store = ContentStore(tmp_path / "client-cas")
    try:
        connection.executescript(
            """
            CREATE TABLE fact_events(
                event_id TEXT, review_status TEXT, validity_status TEXT
            );
            CREATE TABLE fact_evidence(
                event_id TEXT, evidence_id TEXT
            );
            CREATE TABLE fact_dependencies(
                edge_id TEXT, source_event_id TEXT,
                created_commit_version INTEGER
            );
            CREATE TABLE fact_merge_members(
                projection_event_id TEXT, member_event_id TEXT,
                ordinal INTEGER
            );

            INSERT INTO fact_events VALUES ('event-1', 'approved', 'active');
            INSERT INTO fact_events VALUES ('event-2', 'approved', 'active');
            INSERT INTO fact_evidence VALUES ('event-1', 'evidence-1');
            INSERT INTO fact_dependencies VALUES ('edge-1', 'event-1', 1);
            INSERT INTO fact_merge_members VALUES ('event-1', 'event-2', 0);
            """
        )
        connection.execute(
            "INSERT INTO tombstones VALUES (?, ?, ?)",
            (
                "fact_event",
                target_hash("fact_event", "event-1"),
                lineage_hash("fact_event", "event-1"),
            ),
        )

        tables = (
            "fact_evidence",
            "fact_dependencies",
            "fact_merge_members",
        )
        assert _records(
            connection,
            scope="client",
            tables=tables,
            store=store,
        ) == {f"client.{table}": 0 for table in tables}
    finally:
        connection.close()
