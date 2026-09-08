"""Append-only consultation sessions, turns, and governed content references."""

from __future__ import annotations

import sqlite3


VERSION = 3
NAME = "consultation_sessions"


_STATEMENTS = (
    """
    ALTER TABLE sessions ADD COLUMN client_id TEXT CHECK(
        client_id IS NULL
        OR (length(client_id) = 19 AND client_id GLOB 'client_[a-z0-9]*')
    )
    """,
    "ALTER TABLE sessions ADD COLUMN client_snapshot_version INTEGER NOT NULL DEFAULT 0 CHECK(client_snapshot_version >= 0)",
    "ALTER TABLE sessions ADD COLUMN client_snapshot_canonical_sha256 TEXT CHECK(client_snapshot_canonical_sha256 IS NULL OR (length(client_snapshot_canonical_sha256) = 64 AND client_snapshot_canonical_sha256 NOT GLOB '*[^0-9a-f]*'))",
    "ALTER TABLE sessions ADD COLUMN client_snapshot_object_id TEXT",
    "ALTER TABLE sessions ADD COLUMN client_snapshot_sha256 TEXT CHECK(client_snapshot_sha256 IS NULL OR (length(client_snapshot_sha256) = 64 AND client_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'))",
    "ALTER TABLE sessions ADD COLUMN client_snapshot_media_type TEXT",
    "ALTER TABLE sessions ADD COLUMN client_snapshot_size_bytes INTEGER CHECK(client_snapshot_size_bytes IS NULL OR client_snapshot_size_bytes >= 0)",
    "ALTER TABLE sessions ADD COLUMN capability_epoch INTEGER NOT NULL DEFAULT 1 CHECK(capability_epoch > 0)",
    "ALTER TABLE sessions ADD COLUMN last_closed_turn_ordinal INTEGER NOT NULL DEFAULT 0 CHECK(last_closed_turn_ordinal >= 0)",
    "ALTER TABLE sessions ADD COLUMN archive_state TEXT NOT NULL DEFAULT 'NOT_STARTED' CHECK(archive_state IN ('NOT_STARTED','DRAFT','INCOMPLETE','READY','ARCHIVED'))",
    "ALTER TABLE sessions ADD COLUMN updated_at TEXT",
    """
    CREATE TRIGGER sessions_binding_immutable
    BEFORE UPDATE OF client_id, client_scope_hash, client_snapshot_version,
        client_snapshot_canonical_sha256, client_snapshot_object_id,
        client_snapshot_sha256, client_snapshot_media_type,
        client_snapshot_size_bytes, started_at
    ON sessions
    BEGIN
        SELECT RAISE(ABORT, 'session binding is immutable');
    END
    """,
    """
    CREATE TABLE turns (
        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
        turn_id TEXT NOT NULL CHECK(length(turn_id) > 0),
        ordinal INTEGER NOT NULL CHECK(ordinal > 0),
        client_message_object_id TEXT NOT NULL CHECK(length(client_message_object_id) > 0),
        client_message_sha256 TEXT NOT NULL CHECK(
            length(client_message_sha256) = 64
            AND client_message_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        client_message_media_type TEXT NOT NULL CHECK(length(client_message_media_type) > 0),
        client_message_size_bytes INTEGER NOT NULL CHECK(client_message_size_bytes > 0),
        state TEXT NOT NULL CHECK(state IN (
            'client_turn_received','generation_in_progress','candidates_generated',
            'awaiting_actual_reply','actual_reply_recorded',
            'external_reply_unknown','turn_closed'
        )),
        active_run_id TEXT,
        received_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        closed_at TEXT,
        PRIMARY KEY(session_id, turn_id),
        UNIQUE(session_id, ordinal),
        CHECK(
            (state = 'turn_closed' AND closed_at IS NOT NULL)
            OR (state != 'turn_closed' AND closed_at IS NULL)
        )
    )
    """,
    "CREATE INDEX idx_turns_session_state ON turns(session_id, state, ordinal)",
    """
    CREATE TRIGGER turns_insert_guard
    BEFORE INSERT ON turns
    BEGIN
        SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM sessions
            WHERE session_id = NEW.session_id
              AND state = 'OPEN'
              AND client_id IS NOT NULL
              AND client_snapshot_object_id IS NOT NULL
              AND client_snapshot_sha256 IS NOT NULL
        ) THEN RAISE(ABORT, 'session is not appendable') END;
        SELECT CASE WHEN NEW.ordinal != COALESCE((
            SELECT MAX(ordinal) + 1 FROM turns WHERE session_id = NEW.session_id
        ), 1) THEN RAISE(ABORT, 'turn ordinal is not contiguous') END;
        SELECT CASE WHEN EXISTS(
            SELECT 1 FROM turns
            WHERE session_id = NEW.session_id AND state != 'turn_closed'
        ) THEN RAISE(ABORT, 'previous turn is not closed') END;
    END
    """,
    """
    CREATE TRIGGER turns_binding_immutable
    BEFORE UPDATE OF session_id, turn_id, ordinal, client_message_object_id,
        client_message_sha256, client_message_media_type,
        client_message_size_bytes, received_at
    ON turns
    BEGIN
        SELECT RAISE(ABORT, 'turn binding is immutable');
    END
    """,
    """
    CREATE TRIGGER turns_state_transition_guard
    BEFORE UPDATE OF state ON turns
    WHEN NOT (
        (OLD.state = 'client_turn_received' AND NEW.state = 'generation_in_progress')
        OR (OLD.state = 'generation_in_progress' AND NEW.state = 'candidates_generated')
        OR (OLD.state = 'candidates_generated' AND NEW.state = 'awaiting_actual_reply')
        OR (OLD.state = 'awaiting_actual_reply' AND NEW.state = 'actual_reply_recorded')
        OR (OLD.state = 'awaiting_actual_reply' AND NEW.state = 'external_reply_unknown')
        OR (OLD.state = 'actual_reply_recorded' AND NEW.state = 'turn_closed')
        OR (OLD.state = 'external_reply_unknown' AND NEW.state = 'turn_closed')
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid turn state transition');
    END
    """,
    """
    CREATE TABLE candidate_sets (
        candidate_set_id TEXT PRIMARY KEY CHECK(length(candidate_set_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        run_id TEXT NOT NULL CHECK(length(run_id) > 0),
        idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) > 0),
        set_sha256 TEXT NOT NULL CHECK(
            length(set_sha256) = 64 AND set_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        candidate_count INTEGER NOT NULL CHECK(candidate_count BETWEEN 2 AND 4),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        UNIQUE(session_id, turn_id),
        UNIQUE(session_id, idempotency_key),
        UNIQUE(candidate_set_id, session_id, turn_id)
    )
    """,
    """
    CREATE TABLE candidate_replies (
        candidate_id TEXT PRIMARY KEY CHECK(length(candidate_id) > 0),
        candidate_set_id TEXT NOT NULL
            REFERENCES candidate_sets(candidate_set_id) ON DELETE RESTRICT,
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 4),
        label TEXT NOT NULL CHECK(length(label) > 0),
        candidate_object_id TEXT NOT NULL CHECK(length(candidate_object_id) > 0),
        candidate_sha256 TEXT NOT NULL CHECK(
            length(candidate_sha256) = 64
            AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        candidate_media_type TEXT NOT NULL CHECK(length(candidate_media_type) > 0),
        candidate_size_bytes INTEGER NOT NULL CHECK(candidate_size_bytes > 0),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        FOREIGN KEY(candidate_set_id, session_id, turn_id)
            REFERENCES candidate_sets(candidate_set_id, session_id, turn_id)
            ON DELETE RESTRICT,
        UNIQUE(candidate_set_id, ordinal),
        UNIQUE(session_id, turn_id, candidate_id)
    )
    """,
    """
    CREATE TRIGGER candidate_sets_no_update
    BEFORE UPDATE ON candidate_sets BEGIN
        SELECT RAISE(ABORT, 'candidate sets are append-only');
    END
    """,
    """
    CREATE TRIGGER candidate_replies_no_update
    BEFORE UPDATE ON candidate_replies BEGIN
        SELECT RAISE(ABORT, 'candidate replies are append-only');
    END
    """,
    """
    CREATE TABLE actual_replies (
        actual_reply_id TEXT PRIMARY KEY CHECK(length(actual_reply_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) > 0),
        operation_sha256 TEXT NOT NULL CHECK(
            length(operation_sha256) = 64
            AND operation_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_type TEXT NOT NULL CHECK(source_type IN (
            'adopted','edited','external_unknown'
        )),
        candidate_id TEXT REFERENCES candidate_replies(candidate_id) ON DELETE RESTRICT,
        reply_object_id TEXT,
        reply_sha256 TEXT CHECK(reply_sha256 IS NULL OR (
            length(reply_sha256) = 64 AND reply_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
        reply_media_type TEXT,
        reply_size_bytes INTEGER CHECK(reply_size_bytes IS NULL OR reply_size_bytes > 0),
        diff_object_id TEXT,
        diff_sha256 TEXT CHECK(diff_sha256 IS NULL OR (
            length(diff_sha256) = 64 AND diff_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
        diff_media_type TEXT,
        diff_size_bytes INTEGER CHECK(diff_size_bytes IS NULL OR diff_size_bytes > 0),
        sent_at TEXT,
        confirmed_at TEXT,
        evidence_gap INTEGER NOT NULL CHECK(evidence_gap IN (0, 1)),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        UNIQUE(session_id, turn_id),
        UNIQUE(session_id, idempotency_key),
        CHECK(
            (source_type = 'adopted'
             AND candidate_id IS NOT NULL
             AND reply_object_id IS NOT NULL AND reply_sha256 IS NOT NULL
             AND reply_media_type IS NOT NULL AND reply_size_bytes IS NOT NULL
             AND diff_object_id IS NULL AND diff_sha256 IS NULL
             AND diff_media_type IS NULL AND diff_size_bytes IS NULL
             AND sent_at IS NOT NULL AND confirmed_at IS NULL AND evidence_gap = 0)
            OR
            (source_type = 'edited'
             AND candidate_id IS NOT NULL
             AND reply_object_id IS NOT NULL AND reply_sha256 IS NOT NULL
             AND reply_media_type IS NOT NULL AND reply_size_bytes IS NOT NULL
             AND diff_object_id IS NOT NULL AND diff_sha256 IS NOT NULL
             AND diff_media_type IS NOT NULL AND diff_size_bytes IS NOT NULL
             AND sent_at IS NOT NULL AND confirmed_at IS NULL AND evidence_gap = 0)
            OR
            (source_type = 'external_unknown'
             AND candidate_id IS NULL
             AND reply_object_id IS NULL AND reply_sha256 IS NULL
             AND reply_media_type IS NULL AND reply_size_bytes IS NULL
             AND diff_object_id IS NULL AND diff_sha256 IS NULL
             AND diff_media_type IS NULL AND diff_size_bytes IS NULL
             AND sent_at IS NULL AND confirmed_at IS NOT NULL AND evidence_gap = 1)
        )
    )
    """,
    """
    CREATE TRIGGER actual_replies_insert_guard
    BEFORE INSERT ON actual_replies
    BEGIN
        SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM turns
            WHERE session_id = NEW.session_id AND turn_id = NEW.turn_id
              AND state = 'awaiting_actual_reply'
        ) THEN RAISE(ABORT, 'turn is not awaiting actual reply') END;
        SELECT CASE WHEN NEW.candidate_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM candidate_replies
            WHERE candidate_id = NEW.candidate_id
              AND session_id = NEW.session_id AND turn_id = NEW.turn_id
        ) THEN RAISE(ABORT, 'candidate does not belong to turn') END;
        SELECT CASE WHEN NEW.source_type = 'adopted' AND NOT EXISTS(
            SELECT 1 FROM candidate_replies
            WHERE candidate_id = NEW.candidate_id
              AND candidate_object_id = NEW.reply_object_id
              AND candidate_sha256 = NEW.reply_sha256
              AND candidate_media_type = NEW.reply_media_type
              AND candidate_size_bytes = NEW.reply_size_bytes
        ) THEN RAISE(ABORT, 'adopted reply must exactly match candidate') END;
    END
    """,
    """
    CREATE TRIGGER actual_replies_no_update
    BEFORE UPDATE ON actual_replies BEGIN
        SELECT RAISE(ABORT, 'actual replies are append-only');
    END
    """,
    "ALTER TABLE session_fact_events ADD COLUMN cognitive_type TEXT CHECK(cognitive_type IS NULL OR cognitive_type IN ('external_fact','client_statement','consultant_observation','interpretation','hypothesis','recommendation'))",
    "ALTER TABLE session_fact_events ADD COLUMN content_object_id TEXT",
    "ALTER TABLE session_fact_events ADD COLUMN content_sha256 TEXT CHECK(content_sha256 IS NULL OR (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'))",
    "ALTER TABLE session_fact_events ADD COLUMN content_media_type TEXT",
    "ALTER TABLE session_fact_events ADD COLUMN content_size_bytes INTEGER CHECK(content_size_bytes IS NULL OR content_size_bytes > 0)",
    "ALTER TABLE session_fact_events ADD COLUMN target_fact_id TEXT",
    "ALTER TABLE session_fact_events ADD COLUMN target_fact_version INTEGER CHECK(target_fact_version IS NULL OR target_fact_version > 0)",
    "ALTER TABLE session_fact_events ADD COLUMN idempotency_key_sha256 TEXT CHECK(idempotency_key_sha256 IS NULL OR (length(idempotency_key_sha256) = 64 AND idempotency_key_sha256 NOT GLOB '*[^0-9a-f]*'))",
    "ALTER TABLE session_fact_events ADD COLUMN operation_sha256 TEXT CHECK(operation_sha256 IS NULL OR (length(operation_sha256) = 64 AND operation_sha256 NOT GLOB '*[^0-9a-f]*'))",
    "CREATE UNIQUE INDEX idx_session_fact_events_idempotency ON session_fact_events(session_id, idempotency_key_sha256) WHERE idempotency_key_sha256 IS NOT NULL",
    """
    CREATE TRIGGER session_fact_events_no_update
    BEFORE UPDATE ON session_fact_events BEGIN
        SELECT RAISE(ABORT, 'session fact events are append-only');
    END
    """,
    """
    CREATE TRIGGER session_fact_events_no_delete
    BEFORE DELETE ON session_fact_events BEGIN
        SELECT RAISE(ABORT, 'session fact events are append-only');
    END
    """,
    """
    CREATE TABLE generation_stage_artifacts (
        stage_artifact_id TEXT PRIMARY KEY CHECK(length(stage_artifact_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        run_id TEXT NOT NULL CHECK(length(run_id) > 0),
        stage TEXT NOT NULL CHECK(stage IN (
            'query_plan','conceptualization','theory_comparison','reply_drafts',
            'evidence_audit','consistency_risk_review','final_bundle'
        )),
        artifact_object_id TEXT NOT NULL CHECK(length(artifact_object_id) > 0),
        artifact_sha256 TEXT NOT NULL CHECK(
            length(artifact_sha256) = 64
            AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_media_type TEXT NOT NULL CHECK(length(artifact_media_type) > 0),
        artifact_size_bytes INTEGER NOT NULL CHECK(artifact_size_bytes > 0),
        parent_sha256s_json TEXT NOT NULL CHECK(json_valid(parent_sha256s_json)),
        status TEXT NOT NULL DEFAULT 'ACTIVE'
            CHECK(status IN ('ACTIVE','DISCARDED')),
        discarded_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        UNIQUE(session_id, turn_id, run_id, stage),
        CHECK(
            (status = 'ACTIVE' AND discarded_at IS NULL)
            OR (status = 'DISCARDED' AND discarded_at IS NOT NULL)
        )
    )
    """,
    "CREATE INDEX idx_generation_stage_active ON generation_stage_artifacts(session_id, turn_id, run_id, status)",
    """
    CREATE TABLE risk_observations (
        observation_id TEXT PRIMARY KEY CHECK(length(observation_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        category TEXT NOT NULL CHECK(length(category) > 0),
        level TEXT NOT NULL CHECK(level IN ('general','high')),
        rule_object_id TEXT NOT NULL CHECK(length(rule_object_id) > 0),
        rule_sha256 TEXT NOT NULL CHECK(
            length(rule_sha256) = 64 AND rule_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        observation_object_id TEXT NOT NULL CHECK(length(observation_object_id) > 0),
        observation_sha256 TEXT NOT NULL CHECK(
            length(observation_sha256) = 64
            AND observation_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        detected_at TEXT NOT NULL,
        client_facing_visibility TEXT NOT NULL DEFAULT 'never'
            CHECK(client_facing_visibility = 'never'),
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_checkpoints (
        checkpoint_id TEXT PRIMARY KEY CHECK(length(checkpoint_id) > 0),
        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
        checkpoint_sequence INTEGER NOT NULL CHECK(checkpoint_sequence > 0),
        turn_id TEXT,
        from_state TEXT,
        to_state TEXT NOT NULL CHECK(length(to_state) > 0),
        payload_sha256 TEXT NOT NULL CHECK(
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        event_kind TEXT NOT NULL CHECK(length(event_kind) > 0),
        created_at TEXT NOT NULL,
        UNIQUE(session_id, checkpoint_sequence),
        UNIQUE(session_id, turn_id, to_state, payload_sha256)
    )
    """,
    "CREATE INDEX idx_session_checkpoints_order ON session_checkpoints(session_id, checkpoint_sequence)",
    """
    CREATE TRIGGER session_checkpoints_no_update
    BEFORE UPDATE ON session_checkpoints BEGIN
        SELECT RAISE(ABORT, 'session checkpoints are append-only');
    END
    """,
    """
    CREATE TRIGGER session_checkpoints_no_delete
    BEFORE DELETE ON session_checkpoints BEGIN
        SELECT RAISE(ABORT, 'session checkpoints are append-only');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Extend an already migrated client scope without copying any body."""

    for statement in _STATEMENTS:
        connection.execute(statement)
