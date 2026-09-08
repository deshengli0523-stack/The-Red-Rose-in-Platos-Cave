"""Client-local archive bundles, independent purpose state, and outbox staging."""

from __future__ import annotations

import sqlite3


VERSION = 5
NAME = "client_archive_bundles"


_STATEMENTS = (
    """
    CREATE TRIGGER actual_replies_no_delete
    BEFORE DELETE ON actual_replies BEGIN
        SELECT RAISE(ABORT, 'actual replies are append-only');
    END
    """,
    """
    CREATE TRIGGER review_decisions_no_update
    BEFORE UPDATE ON review_decisions BEGIN
        SELECT RAISE(ABORT, 'review decisions are append-only');
    END
    """,
    """
    CREATE TRIGGER review_decisions_no_delete
    BEFORE DELETE ON review_decisions BEGIN
        SELECT RAISE(ABORT, 'review decisions cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER approval_executions_update_guard
    BEFORE UPDATE ON approval_executions BEGIN
        SELECT CASE WHEN NOT (
            OLD.state = 'CLAIMED'
            AND NEW.state = 'APPLIED'
            AND NEW.operation_id = OLD.operation_id
            AND NEW.request_id = OLD.request_id
            AND NEW.descriptor_sha256 = OLD.descriptor_sha256
            AND NEW.draft_sha256 = OLD.draft_sha256
            AND NEW.descriptor_base_version = OLD.descriptor_base_version
            AND NEW.target_scope_hash = OLD.target_scope_hash
            AND NEW.nonce_sha256 = OLD.nonce_sha256
            AND OLD.applied_commit_version IS NULL
            AND OLD.applied_at IS NULL
            AND NEW.applied_commit_version IS NOT NULL
            AND NEW.applied_at IS NOT NULL
        ) THEN RAISE(ABORT, 'approval execution transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER approval_executions_insert_guard
    BEFORE INSERT ON approval_executions
    WHEN NEW.state != 'CLAIMED' BEGIN
        SELECT RAISE(ABORT, 'approval execution must begin claimed');
    END
    """,
    """
    CREATE TRIGGER approval_executions_no_delete
    BEFORE DELETE ON approval_executions BEGIN
        SELECT RAISE(ABORT, 'approval executions cannot be deleted');
    END
    """,
    """
    CREATE TABLE archive_bundles (
        bundle_id TEXT PRIMARY KEY CHECK(length(bundle_id) > 0),
        session_id TEXT NOT NULL UNIQUE
            REFERENCES sessions(session_id) ON DELETE RESTRICT,
        actual_transcript_object_id TEXT NOT NULL UNIQUE
            CHECK(length(actual_transcript_object_id) > 0),
        actual_transcript_version INTEGER NOT NULL DEFAULT 1
            CHECK(actual_transcript_version > 0),
        actual_transcript_sha256 TEXT NOT NULL CHECK(
            length(actual_transcript_sha256) = 64
            AND actual_transcript_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        actual_transcript_media_type TEXT NOT NULL
            CHECK(actual_transcript_media_type = 'application/json'),
        actual_transcript_size_bytes INTEGER NOT NULL
            CHECK(actual_transcript_size_bytes > 0),
        incomplete_evidence INTEGER NOT NULL CHECK(incomplete_evidence IN (0, 1)),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        UNIQUE(
            bundle_id,
            actual_transcript_object_id,
            actual_transcript_sha256
        )
    )
    """,
    """
    CREATE TRIGGER archive_bundles_no_update
    BEFORE UPDATE ON archive_bundles BEGIN
        SELECT RAISE(ABORT, 'archive bundles are immutable');
    END
    """,
    """
    CREATE TRIGGER archive_bundles_no_delete
    BEFORE DELETE ON archive_bundles BEGIN
        SELECT RAISE(ABORT, 'archive bundles cannot be deleted');
    END
    """,
    """
    CREATE TABLE archive_purpose_states (
        bundle_id TEXT NOT NULL
            REFERENCES archive_bundles(bundle_id) ON DELETE RESTRICT,
        purpose TEXT NOT NULL CHECK(
            purpose IN ('private_archive', 'profile_diff', 'shared_case')
        ),
        state TEXT NOT NULL CHECK(
            state IN (
                'DRAFT', 'PREPARED', 'ACTIVE', 'REJECTED',
                'NO_CHANGE', 'PRIVATE_ONLY'
            )
        ),
        manifest_id TEXT
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        review_decision_id TEXT
            REFERENCES review_decisions(decision_id) ON DELETE RESTRICT,
        updated_at TEXT NOT NULL CHECK(length(updated_at) > 0),
        PRIMARY KEY(bundle_id, purpose),
        CHECK(
            (purpose = 'private_archive'
             AND state IN ('DRAFT', 'PREPARED', 'ACTIVE', 'REJECTED'))
            OR
            (purpose = 'profile_diff'
             AND state IN ('DRAFT', 'PREPARED', 'ACTIVE', 'REJECTED', 'NO_CHANGE'))
            OR
            (purpose = 'shared_case'
             AND state IN ('DRAFT', 'PREPARED', 'ACTIVE', 'REJECTED', 'PRIVATE_ONLY'))
        ),
        CHECK(
            (state = 'DRAFT'
             AND manifest_id IS NULL AND review_decision_id IS NULL)
            OR
            (state = 'PREPARED'
             AND manifest_id IS NULL AND review_decision_id IS NOT NULL)
            OR
            (state = 'ACTIVE'
             AND manifest_id IS NOT NULL AND review_decision_id IS NOT NULL)
            OR
            (state IN ('REJECTED', 'NO_CHANGE', 'PRIVATE_ONLY')
             AND manifest_id IS NULL AND review_decision_id IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX idx_archive_purpose_state
        ON archive_purpose_states(purpose, state, bundle_id)
    """,
    """
    CREATE TRIGGER archive_purpose_states_no_delete
    BEFORE DELETE ON archive_purpose_states BEGIN
        SELECT RAISE(ABORT, 'archive purpose states cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER archive_purpose_states_update_guard
    BEFORE UPDATE ON archive_purpose_states BEGIN
        SELECT CASE WHEN
            NEW.bundle_id != OLD.bundle_id
            OR NEW.purpose != OLD.purpose
            OR NOT (
                (NEW.state = OLD.state
                 AND NEW.manifest_id IS OLD.manifest_id
                 AND NEW.review_decision_id IS OLD.review_decision_id)
                OR
                (OLD.state = 'DRAFT'
                 AND NEW.state IN (
                    'PREPARED', 'REJECTED', 'NO_CHANGE', 'PRIVATE_ONLY'
                 ))
                OR
                (OLD.state = 'PREPARED'
                 AND NEW.state IN ('ACTIVE', 'REJECTED', 'PRIVATE_ONLY'))
            )
        THEN RAISE(ABORT, 'archive purpose state transition invalid') END;
    END
    """,
    """
    CREATE TABLE private_archive_revisions (
        revision_id TEXT PRIMARY KEY CHECK(length(revision_id) > 0),
        bundle_id TEXT NOT NULL
            REFERENCES archive_bundles(bundle_id) ON DELETE RESTRICT,
        revision INTEGER NOT NULL CHECK(revision > 0),
        draft_object_id TEXT NOT NULL CHECK(length(draft_object_id) > 0),
        draft_sha256 TEXT NOT NULL CHECK(
            length(draft_sha256) = 64
            AND draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        draft_media_type TEXT NOT NULL CHECK(draft_media_type = 'application/json'),
        draft_size_bytes INTEGER NOT NULL CHECK(draft_size_bytes > 0),
        actual_transcript_object_id TEXT NOT NULL,
        actual_transcript_sha256 TEXT NOT NULL CHECK(
            length(actual_transcript_sha256) = 64
            AND actual_transcript_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        review_decision_id TEXT NOT NULL
            REFERENCES review_decisions(decision_id) ON DELETE RESTRICT,
        manifest_id TEXT
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'REJECTED')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        FOREIGN KEY(
            bundle_id,
            actual_transcript_object_id,
            actual_transcript_sha256
        ) REFERENCES archive_bundles(
            bundle_id,
            actual_transcript_object_id,
            actual_transcript_sha256
        ) ON DELETE RESTRICT,
        UNIQUE(bundle_id, revision),
        UNIQUE(bundle_id, draft_sha256),
        CHECK(
            (state = 'ACTIVE' AND manifest_id IS NOT NULL)
            OR (state IN ('PREPARED', 'REJECTED') AND manifest_id IS NULL)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX idx_private_archive_one_active
        ON private_archive_revisions(bundle_id) WHERE state = 'ACTIVE'
    """,
    """
    CREATE TRIGGER private_archive_revisions_update_guard
    BEFORE UPDATE ON private_archive_revisions BEGIN
        SELECT CASE WHEN
            OLD.state != 'PREPARED'
            OR NEW.state != 'ACTIVE'
            OR NEW.manifest_id IS NULL
            OR NEW.revision_id != OLD.revision_id
            OR NEW.bundle_id != OLD.bundle_id
            OR NEW.revision != OLD.revision
            OR NEW.draft_object_id != OLD.draft_object_id
            OR NEW.draft_sha256 != OLD.draft_sha256
            OR NEW.draft_media_type != OLD.draft_media_type
            OR NEW.draft_size_bytes != OLD.draft_size_bytes
            OR NEW.actual_transcript_object_id != OLD.actual_transcript_object_id
            OR NEW.actual_transcript_sha256 != OLD.actual_transcript_sha256
            OR NEW.review_decision_id != OLD.review_decision_id
            OR NEW.created_at != OLD.created_at
        THEN RAISE(ABORT, 'private archive revision transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER private_archive_revisions_no_delete
    BEFORE DELETE ON private_archive_revisions BEGIN
        SELECT RAISE(ABORT, 'private archive revisions cannot be deleted');
    END
    """,
    """
    CREATE TABLE profile_diff_drafts (
        draft_id TEXT PRIMARY KEY CHECK(length(draft_id) > 0),
        bundle_id TEXT NOT NULL
            REFERENCES archive_bundles(bundle_id) ON DELETE RESTRICT,
        revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
        base_profile_version INTEGER NOT NULL CHECK(base_profile_version >= 0),
        base_profile_sha256 TEXT NOT NULL CHECK(
            length(base_profile_sha256) = 64
            AND base_profile_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        draft_object_id TEXT NOT NULL CHECK(length(draft_object_id) > 0),
        draft_sha256 TEXT NOT NULL CHECK(
            length(draft_sha256) = 64
            AND draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        draft_media_type TEXT NOT NULL CHECK(draft_media_type = 'application/json'),
        draft_size_bytes INTEGER NOT NULL CHECK(draft_size_bytes > 0),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        UNIQUE(bundle_id, revision),
        UNIQUE(bundle_id, draft_sha256)
    )
    """,
    """
    CREATE TRIGGER profile_diff_drafts_no_update
    BEFORE UPDATE ON profile_diff_drafts BEGIN
        SELECT RAISE(ABORT, 'profile diff drafts are append-only');
    END
    """,
    """
    CREATE TRIGGER profile_diff_drafts_no_delete
    BEFORE DELETE ON profile_diff_drafts BEGIN
        SELECT RAISE(ABORT, 'profile diff drafts cannot be deleted');
    END
    """,
    """
    CREATE TABLE shared_case_candidates (
        candidate_id TEXT PRIMARY KEY CHECK(length(candidate_id) > 0),
        bundle_id TEXT NOT NULL
            REFERENCES archive_bundles(bundle_id) ON DELETE RESTRICT,
        version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
        candidate_object_id TEXT NOT NULL CHECK(length(candidate_object_id) > 0),
        candidate_sha256 TEXT NOT NULL CHECK(
            length(candidate_sha256) = 64
            AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        candidate_media_type TEXT NOT NULL
            CHECK(candidate_media_type = 'application/json'),
        candidate_size_bytes INTEGER NOT NULL CHECK(candidate_size_bytes > 0),
        source_record_sha256 TEXT NOT NULL CHECK(
            length(source_record_sha256) = 64
            AND source_record_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        incomplete_evidence INTEGER NOT NULL CHECK(incomplete_evidence IN (0, 1)),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        UNIQUE(bundle_id, version),
        UNIQUE(bundle_id, candidate_sha256)
    )
    """,
    """
    CREATE TRIGGER shared_case_candidates_no_update
    BEFORE UPDATE ON shared_case_candidates BEGIN
        SELECT RAISE(ABORT, 'shared case candidates are append-only');
    END
    """,
    """
    CREATE TRIGGER shared_case_candidates_no_delete
    BEFORE DELETE ON shared_case_candidates BEGIN
        SELECT RAISE(ABORT, 'shared case candidates cannot be deleted');
    END
    """,
    """
    CREATE TABLE outbox_events (
        event_id TEXT PRIMARY KEY CHECK(length(event_id) > 0),
        bundle_id TEXT NOT NULL
            REFERENCES archive_bundles(bundle_id) ON DELETE RESTRICT,
        event_type TEXT NOT NULL CHECK(event_type = 'shared_case_publish'),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) > 0),
        payload_object_id TEXT NOT NULL CHECK(length(payload_object_id) > 0),
        payload_sha256 TEXT NOT NULL CHECK(
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        payload_media_type TEXT NOT NULL CHECK(payload_media_type = 'application/json'),
        payload_size_bytes INTEGER NOT NULL CHECK(payload_size_bytes > 0),
        state TEXT NOT NULL DEFAULT 'PENDING' CHECK(
            state IN ('PENDING', 'CLAIMED', 'PUBLISHED', 'FAILED')
        ),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        published_global_version INTEGER CHECK(
            published_global_version IS NULL OR published_global_version > 0
        ),
        last_error_code TEXT CHECK(
            last_error_code IS NULL OR length(last_error_code) > 0
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        updated_at TEXT NOT NULL CHECK(
            updated_at GLOB '????-??-??T??:??:??*Z'
            OR updated_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(
            (state = 'PUBLISHED' AND published_global_version IS NOT NULL)
            OR (state != 'PUBLISHED' AND published_global_version IS NULL)
        ),
        CHECK(
            (state = 'FAILED' AND last_error_code IS NOT NULL)
            OR (state != 'FAILED' AND last_error_code IS NULL)
        )
    )
    """,
    """
    CREATE INDEX idx_outbox_events_pending
        ON outbox_events(state, created_at, event_id)
    """,
    """
    CREATE TRIGGER outbox_events_update_guard
    BEFORE UPDATE ON outbox_events BEGIN
        SELECT CASE WHEN
            NEW.event_id != OLD.event_id
            OR NEW.bundle_id != OLD.bundle_id
            OR NEW.event_type != OLD.event_type
            OR NEW.idempotency_key != OLD.idempotency_key
            OR NEW.payload_object_id != OLD.payload_object_id
            OR NEW.payload_sha256 != OLD.payload_sha256
            OR NEW.payload_media_type != OLD.payload_media_type
            OR NEW.payload_size_bytes != OLD.payload_size_bytes
            OR NEW.created_at != OLD.created_at
            OR NEW.updated_at < OLD.updated_at
            OR NOT (
                (OLD.state IN ('PENDING', 'FAILED')
                 AND NEW.state = 'CLAIMED'
                 AND NEW.attempt_count = OLD.attempt_count + 1)
                OR
                (OLD.state IN ('PENDING', 'CLAIMED', 'FAILED')
                 AND NEW.state = 'FAILED'
                 AND NEW.attempt_count = OLD.attempt_count)
                OR
                (OLD.state IN ('PENDING', 'CLAIMED', 'FAILED')
                 AND NEW.state = 'PUBLISHED'
                 AND NEW.attempt_count = OLD.attempt_count)
            )
        THEN RAISE(ABORT, 'outbox event transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER outbox_events_no_delete
    BEFORE DELETE ON outbox_events BEGIN
        SELECT RAISE(ABORT, 'outbox events cannot be deleted');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
