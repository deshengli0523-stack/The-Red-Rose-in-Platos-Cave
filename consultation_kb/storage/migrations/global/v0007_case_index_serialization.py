"""Serialize case-index rebuilds with global catalog authority changes."""

from __future__ import annotations

import sqlite3


VERSION = 7
NAME = "case_index_serialization"


_STATEMENTS = (
    """
    CREATE TABLE case_index_rebuild_invalidations (
        queue_id TEXT PRIMARY KEY
            REFERENCES rebuild_queue(queue_id) ON DELETE RESTRICT,
        authority_request_id TEXT NOT NULL CHECK(length(authority_request_id) > 0),
        invalidation_set_sha256 TEXT NOT NULL CHECK(
            length(invalidation_set_sha256) = 64
            AND invalidation_set_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        reason_code TEXT NOT NULL CHECK(length(reason_code) > 0),
        base_catalog_version INTEGER NOT NULL CHECK(base_catalog_version >= 0),
        target_catalog_version INTEGER NOT NULL CHECK(
            target_catalog_version = base_catalog_version + 1
        ),
        prior_authorization_epoch INTEGER NOT NULL CHECK(
            prior_authorization_epoch >= 0
        ),
        authorization_epoch INTEGER NOT NULL CHECK(
            authorization_epoch >= prior_authorization_epoch
        ),
        prior_tombstone_epoch INTEGER NOT NULL CHECK(prior_tombstone_epoch >= 0),
        tombstone_epoch INTEGER NOT NULL CHECK(
            tombstone_epoch >= prior_tombstone_epoch
        ),
        invalidated_at TEXT NOT NULL CHECK(
            invalidated_at GLOB '????-??-??T??:??:??*Z'
            OR invalidated_at GLOB '????-??-??T??:??:??*+00:00'
        ) CHECK(julianday(invalidated_at) IS NOT NULL),
        CHECK(
            authorization_epoch > prior_authorization_epoch
            OR tombstone_epoch > prior_tombstone_epoch
        )
    )
    """,
    """
    CREATE TRIGGER case_index_rebuild_invalidations_no_update
    BEFORE UPDATE ON case_index_rebuild_invalidations BEGIN
        SELECT RAISE(ABORT, 'case index rebuild invalidation is append only');
    END
    """,
    """
    CREATE TRIGGER case_index_rebuild_invalidations_no_delete
    BEFORE DELETE ON case_index_rebuild_invalidations BEGIN
        SELECT RAISE(ABORT, 'case index rebuild invalidation is append only');
    END
    """,
    """
    CREATE TRIGGER case_index_rebuild_invalidations_no_replace
    BEFORE INSERT ON case_index_rebuild_invalidations
    WHEN EXISTS(
        SELECT 1 FROM case_index_rebuild_invalidations
         WHERE queue_id = NEW.queue_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'case index rebuild invalidation is append only');
    END
    """,
    """
    CREATE TRIGGER case_index_security_epoch_pending_guard
    BEFORE UPDATE OF authorization_epoch, tombstone_epoch ON knowledge_catalog_state
    WHEN (NEW.authorization_epoch > OLD.authorization_epoch
          OR NEW.tombstone_epoch > OLD.tombstone_epoch)
         AND EXISTS(
             SELECT 1
               FROM rebuild_queue AS queue
               JOIN case_patterns AS pattern
                 ON pattern.manifest_id = queue.upstream_id
              WHERE queue.upstream_type = 'case_index'
                AND queue.catalog_version = OLD.catalog_version + 1
                AND queue.state IN ('PENDING', 'CLAIMED')
                AND pattern.state = 'PREPARED'
         )
    BEGIN
        SELECT RAISE(ABORT, 'pending case index security invalidation required');
    END
    """,
    """
    CREATE TRIGGER knowledge_catalog_pending_case_index_guard
    BEFORE UPDATE OF catalog_version ON knowledge_catalog_state
    WHEN NEW.catalog_version != OLD.catalog_version
         AND EXISTS(
             SELECT 1
               FROM rebuild_queue AS queue
               JOIN case_patterns AS pattern
                 ON pattern.manifest_id = queue.upstream_id
              WHERE queue.upstream_type = 'case_index'
                AND queue.catalog_version = OLD.catalog_version + 1
                AND queue.state IN ('PENDING', 'CLAIMED')
                AND pattern.state = 'PREPARED'
         )
    BEGIN
        SELECT RAISE(ABORT, 'pending case index rebuild');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Install global case-index serialization in the runner transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
