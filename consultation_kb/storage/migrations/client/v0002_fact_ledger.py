"""Client bitemporal fact ledger and derived-profile schema."""

from __future__ import annotations

import sqlite3


VERSION = 2
NAME = "client_bitemporal_fact_ledger"


_STATEMENTS = (
    """
    CREATE TABLE client_fact_authority (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        commit_version INTEGER NOT NULL CHECK(commit_version >= 0),
        client_id TEXT UNIQUE CHECK(
            client_id IS NULL
            OR (length(client_id) = 19 AND client_id GLOB 'client_[a-z0-9]*')
        )
    )
    """,
    "INSERT INTO client_fact_authority(singleton, commit_version, client_id) "
    "VALUES (1, 0, NULL)",
    """
    CREATE TABLE fact_events (
        event_id TEXT PRIMARY KEY CHECK(length(event_id) > 0),
        fact_id TEXT NOT NULL CHECK(length(fact_id) > 0),
        client_id TEXT NOT NULL CHECK(
            length(client_id) = 19 AND client_id GLOB 'client_[a-z0-9]*'
        ),
        event_version INTEGER NOT NULL CHECK(event_version > 0),
        mutation_type TEXT NOT NULL CHECK(
            mutation_type IN ('ADD','CONFIRM','CORRECT','SUPERSEDE','RESOLVE','MERGE')
        ),
        canonical_key TEXT NOT NULL CHECK(length(canonical_key) > 0),
        subject TEXT NOT NULL CHECK(length(subject) > 0),
        predicate TEXT NOT NULL CHECK(length(predicate) > 0),
        object_json TEXT NOT NULL CHECK(json_valid(object_json)),
        cognitive_type TEXT NOT NULL CHECK(cognitive_type IN (
            'external_fact','client_statement','consultant_observation',
            'interpretation','hypothesis','recommendation'
        )),
        source_kind TEXT NOT NULL CHECK(source_kind IN (
            'controlled_import','session_statement','session_observation','session_derived'
        )),
        source_session_id TEXT,
        source_turn_id TEXT,
        source_ref TEXT,
        effective_from TEXT NOT NULL,
        effective_to TEXT,
        time_precision TEXT NOT NULL CHECK(time_precision IN (
            'instant','minute','hour','day','month','year','unknown'
        )),
        timezone_name TEXT NOT NULL CHECK(length(timezone_name) > 0),
        recorded_at TEXT NOT NULL,
        approved_at TEXT NOT NULL,
        reported_at TEXT,
        observed_at TEXT,
        transaction_id TEXT NOT NULL CHECK(length(transaction_id) > 0),
        commit_version INTEGER NOT NULL CHECK(commit_version > 0),
        publication_operation_id TEXT NOT NULL CHECK(length(publication_operation_id) > 0),
        visible_runtime_epoch INTEGER NOT NULL CHECK(visible_runtime_epoch > 0),
        review_status TEXT NOT NULL CHECK(
            review_status IN ('proposed','reviewed','approved','rejected')
        ),
        validity_status TEXT NOT NULL CHECK(
            validity_status IN ('active','superseded','invalidated','historical')
        ),
        resolution_status TEXT NOT NULL CHECK(
            resolution_status IN ('open','resolved','not_applicable')
        ),
        epistemic_status TEXT NOT NULL CHECK(
            epistemic_status IN ('asserted','uncertain','disputed')
        ),
        fact_confidence REAL NOT NULL CHECK(fact_confidence BETWEEN 0.0 AND 1.0),
        model_confidence REAL CHECK(
            model_confidence IS NULL OR model_confidence BETWEEN 0.0 AND 1.0
        ),
        reviewer_id TEXT NOT NULL CHECK(length(reviewer_id) > 0),
        review_reason TEXT NOT NULL CHECK(length(review_reason) > 0),
        review_source TEXT NOT NULL CHECK(length(review_source) > 0),
        privacy_level TEXT NOT NULL CHECK(
            privacy_level IN ('private_client','private_session')
        ),
        allowed_purposes_json TEXT NOT NULL CHECK(json_valid(allowed_purposes_json)),
        applicability_json TEXT NOT NULL CHECK(json_valid(applicability_json)),
        source_anchor_json TEXT NOT NULL CHECK(json_valid(source_anchor_json)),
        supersedes_event_id TEXT REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        previous_event_id TEXT REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        replacement_event_id TEXT REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        source_event_ids_json TEXT NOT NULL CHECK(json_valid(source_event_ids_json)),
        relation_type TEXT CHECK(relation_type IS NULL OR relation_type IN (
            'ABOUT_ENTITY','DEPENDS_ON','DERIVED_FROM','SUPPORTS','CONTRADICTS',
            'SUPERSEDES','RESOLVED_BY','CURRENT_RELATIONSHIP','HISTORICAL_RELATIONSHIP'
        )),
        UNIQUE(fact_id, event_version),
        CHECK(effective_to IS NULL OR effective_to > effective_from),
        CHECK(approved_at >= recorded_at),
        CHECK(
            (source_kind = 'controlled_import'
             AND source_ref IS NOT NULL
             AND source_session_id IS NULL AND source_turn_id IS NULL
             AND reported_at IS NULL AND observed_at IS NULL
             AND cognitive_type NOT IN ('client_statement','consultant_observation'))
            OR
            (source_kind = 'session_statement'
             AND cognitive_type = 'client_statement'
             AND source_ref IS NULL
             AND source_session_id IS NOT NULL AND source_turn_id IS NOT NULL
             AND reported_at IS NOT NULL AND observed_at IS NULL)
            OR
            (source_kind = 'session_observation'
             AND cognitive_type = 'consultant_observation'
             AND source_ref IS NULL
             AND source_session_id IS NOT NULL AND source_turn_id IS NOT NULL
             AND reported_at IS NULL AND observed_at IS NOT NULL)
            OR
            (source_kind = 'session_derived'
             AND cognitive_type IN ('external_fact','interpretation','hypothesis','recommendation')
             AND source_ref IS NULL
             AND source_session_id IS NOT NULL AND source_turn_id IS NOT NULL
             AND ((reported_at IS NOT NULL AND observed_at IS NULL)
                  OR (reported_at IS NULL AND observed_at IS NOT NULL)))
        )
    )
    """,
    "CREATE INDEX idx_fact_events_canonical_key ON fact_events(canonical_key)",
    "CREATE INDEX idx_fact_events_fact_time ON fact_events(fact_id, approved_at, recorded_at, event_version)",
    "CREATE INDEX idx_fact_events_effective ON fact_events(effective_from, effective_to)",
    "CREATE INDEX idx_fact_events_runtime ON fact_events(visible_runtime_epoch, commit_version)",
    """
    CREATE TRIGGER fact_events_no_update
    BEFORE UPDATE ON fact_events
    BEGIN
        SELECT RAISE(ABORT, 'fact_events are append-only');
    END
    """,
    """
    CREATE TRIGGER fact_events_no_delete
    BEFORE DELETE ON fact_events
    BEGIN
        SELECT RAISE(ABORT, 'fact_events are append-only');
    END
    """,
    """
    CREATE TABLE fact_evidence (
        event_id TEXT NOT NULL REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        evidence_id TEXT NOT NULL CHECK(length(evidence_id) > 0),
        source_kind TEXT NOT NULL CHECK(length(source_kind) > 0),
        source_ref TEXT NOT NULL CHECK(length(source_ref) > 0),
        supports INTEGER NOT NULL CHECK(supports IN (0,1)),
        evidence_confidence REAL NOT NULL CHECK(evidence_confidence BETWEEN 0.0 AND 1.0),
        PRIMARY KEY(event_id, evidence_id)
    )
    """,
    """
    CREATE TABLE fact_dependencies (
        edge_id TEXT PRIMARY KEY CHECK(length(edge_id) > 0),
        dependent_fact_id TEXT NOT NULL CHECK(length(dependent_fact_id) > 0),
        prerequisite_fact_id TEXT NOT NULL CHECK(length(prerequisite_fact_id) > 0),
        dependency_type TEXT NOT NULL CHECK(dependency_type IN (
            'direct_deterministic','direct_conditional','indirect_inferred'
        )),
        confidence REAL NOT NULL CHECK(confidence BETWEEN 0.0 AND 1.0),
        source_event_id TEXT NOT NULL REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        reviewer_id TEXT NOT NULL CHECK(length(reviewer_id) > 0),
        created_commit_version INTEGER NOT NULL CHECK(created_commit_version > 0),
        UNIQUE(dependent_fact_id, prerequisite_fact_id, dependency_type, source_event_id)
    )
    """,
    "CREATE INDEX idx_fact_dependencies_prerequisite ON fact_dependencies(prerequisite_fact_id)",
    """
    CREATE TRIGGER fact_dependencies_no_update
    BEFORE UPDATE ON fact_dependencies
    BEGIN
        SELECT RAISE(ABORT, 'fact_dependencies are append-only');
    END
    """,
    """
    CREATE TRIGGER fact_dependencies_no_delete
    BEFORE DELETE ON fact_dependencies
    BEGIN
        SELECT RAISE(ABORT, 'fact_dependencies are append-only');
    END
    """,
    """
    CREATE TABLE fact_merge_members (
        projection_event_id TEXT NOT NULL REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        member_event_id TEXT NOT NULL REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        member_session_id TEXT,
        member_turn_id TEXT,
        member_recorded_at TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        PRIMARY KEY(projection_event_id, member_event_id),
        UNIQUE(projection_event_id, ordinal)
    )
    """,
    """
    CREATE TABLE profile_revisions (
        revision_id TEXT PRIMARY KEY CHECK(length(revision_id) > 0),
        publication_operation_id TEXT NOT NULL CHECK(length(publication_operation_id) > 0),
        source_commit_version INTEGER NOT NULL CHECK(source_commit_version > 0),
        visible_runtime_epoch INTEGER NOT NULL CHECK(visible_runtime_epoch > 0),
        profile_sha256 TEXT NOT NULL CHECK(length(profile_sha256) = 64),
        json_object_id TEXT NOT NULL CHECK(length(json_object_id) > 0),
        markdown_object_id TEXT NOT NULL CHECK(length(markdown_object_id) > 0),
        created_at TEXT NOT NULL,
        UNIQUE(source_commit_version, visible_runtime_epoch)
    )
    """,
    """
    CREATE TABLE profile_members (
        revision_id TEXT NOT NULL REFERENCES profile_revisions(revision_id) ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        section TEXT NOT NULL CHECK(length(section) > 0),
        fact_id TEXT NOT NULL CHECK(length(fact_id) > 0),
        event_id TEXT NOT NULL REFERENCES fact_events(event_id) ON DELETE RESTRICT,
        PRIMARY KEY(revision_id, ordinal),
        UNIQUE(revision_id, event_id)
    )
    """,
    """
    CREATE TABLE session_fact_events (
        session_event_id TEXT PRIMARY KEY CHECK(length(session_event_id) > 0),
        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
        turn_id TEXT NOT NULL CHECK(length(turn_id) > 0),
        event_kind TEXT NOT NULL CHECK(event_kind IN (
            'ADD','CONFIRM','CORRECT','SUPERSEDE','RESOLVE','MERGE',
            'POSSIBLY_INVALID','GOAL','ISSUE','PREFERENCE','CONSTRAINT','HYPOTHESIS','CONFLICT'
        )),
        event_json TEXT NOT NULL CHECK(json_valid(event_json)),
        recorded_at TEXT NOT NULL,
        UNIQUE(session_id, turn_id, session_event_id)
    )
    """,
    """
    CREATE TABLE review_diff_objects (
        object_id TEXT PRIMARY KEY CHECK(length(object_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        content_sha256 TEXT NOT NULL CHECK(
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
        media_type TEXT NOT NULL CHECK(length(media_type) > 0),
        draft_event_id TEXT NOT NULL
            REFERENCES session_fact_events(session_event_id) ON DELETE RESTRICT,
        operation_id TEXT NOT NULL CHECK(length(operation_id) > 0),
        preview_sha256 TEXT NOT NULL CHECK(
            length(preview_sha256) = 64
            AND preview_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        base_commit_version INTEGER NOT NULL CHECK(base_commit_version >= 0),
        expected_runtime_epoch INTEGER NOT NULL CHECK(expected_runtime_epoch > 0),
        purpose TEXT NOT NULL CHECK(purpose = 'profile_update_review'),
        created_at TEXT NOT NULL,
        UNIQUE(draft_event_id, operation_id),
        UNIQUE(content_sha256, object_id, version)
    )
    """,
    """
    CREATE TRIGGER review_diff_objects_no_update
    BEFORE UPDATE ON review_diff_objects
    BEGIN
        SELECT RAISE(ABORT, 'review diff objects are append-only');
    END
    """,
    """
    CREATE TRIGGER review_diff_objects_no_delete
    BEFORE DELETE ON review_diff_objects
    BEGIN
        SELECT RAISE(ABORT, 'review diff objects are append-only');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the append-only client fact ledger in the runner transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
