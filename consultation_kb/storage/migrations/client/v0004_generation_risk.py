"""Append-only generation revisions and counselor-only risk lifecycle."""

from __future__ import annotations

import sqlite3


VERSION = 4
NAME = "generation_revisions_and_internal_risk"


_STATEMENTS = (
    """
    CREATE TABLE turn_risk_evaluations (
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        evaluation_revision INTEGER NOT NULL CHECK(evaluation_revision > 0),
        client_message_sha256 TEXT NOT NULL CHECK(
            length(client_message_sha256) = 64
            AND client_message_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        authority_sha256 TEXT NOT NULL CHECK(
            length(authority_sha256) = 64
            AND authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        risk_global_runtime_epoch INTEGER NOT NULL CHECK(
            risk_global_runtime_epoch > 0
        ),
        risk_policy_manifest_object_id TEXT NOT NULL CHECK(
            length(risk_policy_manifest_object_id) > 0
        ),
        risk_policy_manifest_version INTEGER NOT NULL CHECK(
            risk_policy_manifest_version > 0
        ),
        risk_policy_manifest_sha256 TEXT NOT NULL CHECK(
            length(risk_policy_manifest_sha256) = 64
            AND risk_policy_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        risk_model_mode TEXT NOT NULL CHECK(
            risk_model_mode IN ('deterministic_only','approved_model')
        ),
        risk_model_manifest_object_id TEXT,
        risk_model_manifest_version INTEGER CHECK(
            risk_model_manifest_version IS NULL
            OR risk_model_manifest_version > 0
        ),
        risk_model_manifest_sha256 TEXT CHECK(
            risk_model_manifest_sha256 IS NULL OR (
                length(risk_model_manifest_sha256) = 64
                AND risk_model_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        approved_model_object_id TEXT,
        approved_model_version INTEGER CHECK(
            approved_model_version IS NULL OR approved_model_version > 0
        ),
        approved_model_sha256 TEXT CHECK(
            approved_model_sha256 IS NULL OR (
                length(approved_model_sha256) = 64
                AND approved_model_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        status TEXT NOT NULL CHECK(status IN ('pending','completed')),
        observation_set_sha256 TEXT CHECK(
            observation_set_sha256 IS NULL OR (
                length(observation_set_sha256) = 64
                AND observation_set_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        observation_count INTEGER CHECK(
            observation_count IS NULL OR observation_count >= 0
        ),
        completed_at TEXT,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        PRIMARY KEY(session_id, turn_id, evaluation_revision),
        UNIQUE(session_id, turn_id, authority_sha256),
        CHECK(
            (risk_model_mode = 'deterministic_only'
             AND risk_model_manifest_object_id IS NULL
             AND risk_model_manifest_version IS NULL
             AND risk_model_manifest_sha256 IS NULL
             AND approved_model_object_id IS NULL
             AND approved_model_version IS NULL
             AND approved_model_sha256 IS NULL)
            OR
            (risk_model_mode = 'approved_model'
             AND risk_model_manifest_object_id IS NOT NULL
             AND risk_model_manifest_version IS NOT NULL
             AND risk_model_manifest_sha256 IS NOT NULL
             AND approved_model_object_id IS NOT NULL
             AND approved_model_version IS NOT NULL
             AND approved_model_sha256 IS NOT NULL)
        ),
        CHECK(
            (status = 'pending'
             AND observation_set_sha256 IS NULL
             AND observation_count IS NULL
             AND completed_at IS NULL)
            OR
            (status = 'completed'
             AND observation_set_sha256 IS NOT NULL
             AND observation_count IS NOT NULL
             AND completed_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE TRIGGER turn_risk_evaluations_insert_guard
    BEFORE INSERT ON turn_risk_evaluations
    BEGIN
        SELECT CASE WHEN NEW.evaluation_revision != COALESCE((
            SELECT MAX(evaluation_revision) FROM turn_risk_evaluations
             WHERE session_id = NEW.session_id AND turn_id = NEW.turn_id
        ), 0) + 1
        THEN RAISE(ABORT, 'turn risk evaluation revision invalid') END;
    END
    """,
    """
    CREATE TRIGGER turn_risk_evaluations_update_guard
    BEFORE UPDATE ON turn_risk_evaluations
    BEGIN
        SELECT CASE WHEN
            NEW.session_id != OLD.session_id
            OR NEW.turn_id != OLD.turn_id
            OR NEW.evaluation_revision != OLD.evaluation_revision
            OR NEW.client_message_sha256 != OLD.client_message_sha256
            OR NEW.authority_sha256 != OLD.authority_sha256
            OR NEW.risk_global_runtime_epoch != OLD.risk_global_runtime_epoch
            OR NEW.risk_policy_manifest_object_id
               != OLD.risk_policy_manifest_object_id
            OR NEW.risk_policy_manifest_version
               != OLD.risk_policy_manifest_version
            OR NEW.risk_policy_manifest_sha256
               != OLD.risk_policy_manifest_sha256
            OR NEW.risk_model_mode != OLD.risk_model_mode
            OR NEW.risk_model_manifest_object_id
               IS NOT OLD.risk_model_manifest_object_id
            OR NEW.risk_model_manifest_version
               IS NOT OLD.risk_model_manifest_version
            OR NEW.risk_model_manifest_sha256
               IS NOT OLD.risk_model_manifest_sha256
            OR NEW.approved_model_object_id IS NOT OLD.approved_model_object_id
            OR NEW.approved_model_version IS NOT OLD.approved_model_version
            OR NEW.approved_model_sha256 IS NOT OLD.approved_model_sha256
            OR OLD.status != 'pending'
            OR NEW.status != 'completed'
            OR NEW.observation_count != (
                SELECT COUNT(*)
                  FROM turn_risk_evaluation_observations AS member
                 WHERE member.session_id = OLD.session_id
                   AND member.turn_id = OLD.turn_id
                   AND member.evaluation_revision = OLD.evaluation_revision
            )
        THEN RAISE(ABORT, 'turn risk evaluation transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER turn_risk_evaluations_no_delete
    BEFORE DELETE ON turn_risk_evaluations BEGIN
        SELECT RAISE(ABORT, 'turn risk evaluations cannot be deleted');
    END
    """,
    """
    CREATE TABLE generation_stage_revisions (
        stage_revision_id TEXT PRIMARY KEY CHECK(length(stage_revision_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        run_id TEXT NOT NULL CHECK(length(run_id) > 0),
        stage TEXT NOT NULL CHECK(stage IN (
            'query_plan','conceptualization','theory_comparison','reply_drafts',
            'evidence_audit','consistency_risk_review','final_bundle'
        )),
        revision INTEGER NOT NULL CHECK(revision > 0),
        idempotency_key_sha256 TEXT NOT NULL CHECK(
            length(idempotency_key_sha256) = 64
            AND idempotency_key_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_object_id TEXT NOT NULL CHECK(length(artifact_object_id) > 0),
        artifact_sha256 TEXT NOT NULL CHECK(
            length(artifact_sha256) = 64
            AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_media_type TEXT NOT NULL CHECK(length(artifact_media_type) > 0),
        artifact_size_bytes INTEGER NOT NULL CHECK(artifact_size_bytes > 0),
        parent_sha256s_json TEXT NOT NULL CHECK(json_valid(parent_sha256s_json)),
        revision_reason_object_id TEXT,
        revision_reason_sha256 TEXT CHECK(
            revision_reason_sha256 IS NULL OR (
                length(revision_reason_sha256) = 64
                AND revision_reason_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        revision_reason_media_type TEXT,
        revision_reason_size_bytes INTEGER CHECK(
            revision_reason_size_bytes IS NULL OR revision_reason_size_bytes > 0
        ),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        UNIQUE(session_id, turn_id, run_id, stage, revision),
        UNIQUE(session_id, turn_id, run_id, stage, idempotency_key_sha256),
        UNIQUE(session_id, turn_id, run_id, stage, artifact_sha256),
        CHECK(
            (revision = 1
             AND revision_reason_object_id IS NULL
             AND revision_reason_sha256 IS NULL
             AND revision_reason_media_type IS NULL
             AND revision_reason_size_bytes IS NULL)
            OR
            (revision > 1
             AND revision_reason_object_id IS NOT NULL
             AND revision_reason_sha256 IS NOT NULL
             AND revision_reason_media_type IS NOT NULL
             AND revision_reason_size_bytes IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX idx_generation_stage_revision_latest
        ON generation_stage_revisions(
            session_id, turn_id, run_id, stage, revision DESC
        )
    """,
    """
    CREATE TRIGGER generation_stage_revisions_insert_guard
    BEFORE INSERT ON generation_stage_revisions
    BEGIN
        SELECT CASE WHEN NEW.revision != COALESCE((
            SELECT MAX(revision) FROM generation_stage_revisions
             WHERE session_id = NEW.session_id
               AND turn_id = NEW.turn_id
               AND run_id = NEW.run_id
               AND stage = NEW.stage
        ), 0) + 1
        THEN RAISE(ABORT, 'generation revision is not the next sequence') END;
    END
    """,
    """
    CREATE TRIGGER generation_stage_revisions_no_update
    BEFORE UPDATE ON generation_stage_revisions BEGIN
        SELECT RAISE(ABORT, 'generation revisions are append-only');
    END
    """,
    """
    CREATE TRIGGER generation_stage_revisions_no_delete
    BEFORE DELETE ON generation_stage_revisions BEGIN
        SELECT RAISE(ABORT, 'generation revisions are append-only');
    END
    """,
    """
    CREATE TABLE generation_evidence_objects (
        object_id TEXT NOT NULL CHECK(length(object_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        run_id TEXT NOT NULL CHECK(length(run_id) > 0),
        object_type TEXT NOT NULL CHECK(
            object_type IN ('authority_snapshot','exclusion_proof','provenance')
        ),
        content_sha256 TEXT NOT NULL CHECK(
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        media_type TEXT NOT NULL CHECK(media_type = 'application/json'),
        size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        PRIMARY KEY(session_id, turn_id, run_id, object_id),
        UNIQUE(session_id, turn_id, run_id, object_type, content_sha256)
    )
    """,
    """
    CREATE TRIGGER generation_evidence_objects_no_update
    BEFORE UPDATE ON generation_evidence_objects BEGIN
        SELECT RAISE(ABORT, 'generation evidence objects are append-only');
    END
    """,
    """
    CREATE TRIGGER generation_evidence_objects_no_delete
    BEFORE DELETE ON generation_evidence_objects BEGIN
        SELECT RAISE(ABORT, 'generation evidence objects are append-only');
    END
    """,
    """
    CREATE TABLE generation_evidence_packs (
        evidence_pack_id TEXT PRIMARY KEY CHECK(length(evidence_pack_id) > 0),
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        run_id TEXT NOT NULL CHECK(length(run_id) > 0),
        query_plan_sha256 TEXT NOT NULL CHECK(
            length(query_plan_sha256) = 64
            AND query_plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        pack_object_id TEXT NOT NULL UNIQUE CHECK(length(pack_object_id) > 0),
        pack_sha256 TEXT NOT NULL CHECK(
            length(pack_sha256) = 64
            AND pack_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        pack_media_type TEXT NOT NULL CHECK(pack_media_type = 'application/json'),
        pack_size_bytes INTEGER NOT NULL CHECK(pack_size_bytes > 0),
        context_object_id TEXT NOT NULL CHECK(length(context_object_id) > 0),
        context_sha256 TEXT NOT NULL CHECK(
            length(context_sha256) = 64
            AND context_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        context_media_type TEXT NOT NULL CHECK(
            context_media_type = 'application/json'
        ),
        context_size_bytes INTEGER NOT NULL CHECK(context_size_bytes > 0),
        authority_snapshot_object_id TEXT NOT NULL,
        exclusion_proof_object_id TEXT NOT NULL,
        retrieval_metadata_json TEXT NOT NULL CHECK(json_valid(retrieval_metadata_json)),
        created_at TEXT NOT NULL,
        FOREIGN KEY(session_id, turn_id)
            REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
        FOREIGN KEY(session_id, turn_id, run_id, authority_snapshot_object_id)
            REFERENCES generation_evidence_objects(
                session_id, turn_id, run_id, object_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY(session_id, turn_id, run_id, exclusion_proof_object_id)
            REFERENCES generation_evidence_objects(
                session_id, turn_id, run_id, object_id
            ) ON DELETE RESTRICT,
        UNIQUE(session_id, turn_id, run_id, query_plan_sha256),
        UNIQUE(session_id, turn_id, run_id, pack_sha256)
    )
    """,
    """
    CREATE INDEX idx_generation_evidence_pack_lookup
        ON generation_evidence_packs(
            session_id, turn_id, run_id, query_plan_sha256, pack_sha256
        )
    """,
    """
    CREATE TRIGGER generation_evidence_packs_no_update
    BEFORE UPDATE ON generation_evidence_packs BEGIN
        SELECT RAISE(ABORT, 'generation evidence packs are append-only');
    END
    """,
    """
    CREATE TRIGGER generation_evidence_packs_no_delete
    BEFORE DELETE ON generation_evidence_packs BEGIN
        SELECT RAISE(ABORT, 'generation evidence packs are append-only');
    END
    """,
    """
    CREATE TABLE internal_risk_observations (
        observation_id TEXT PRIMARY KEY CHECK(length(observation_id) > 0),
        session_id TEXT NOT NULL
            REFERENCES sessions(session_id) ON DELETE RESTRICT,
        immutable_record_json TEXT NOT NULL CHECK(json_valid(immutable_record_json)),
        status TEXT NOT NULL CHECK(status IN ('open','acknowledged','closed')),
        acknowledged_at TEXT,
        counselor_disposition TEXT,
        rejection_reason TEXT,
        closed_at TEXT,
        close_decision TEXT,
        close_reason TEXT,
        CHECK(
            (status = 'open'
             AND acknowledged_at IS NULL
             AND counselor_disposition IS NULL
             AND rejection_reason IS NULL
             AND closed_at IS NULL
             AND close_decision IS NULL
             AND close_reason IS NULL)
            OR
            (status = 'acknowledged'
             AND acknowledged_at IS NOT NULL
             AND (counselor_disposition IS NOT NULL OR rejection_reason IS NOT NULL)
             AND closed_at IS NULL
             AND close_decision IS NULL
             AND close_reason IS NULL)
            OR
            (status = 'closed'
             AND acknowledged_at IS NOT NULL
             AND (counselor_disposition IS NOT NULL OR rejection_reason IS NOT NULL)
             AND closed_at IS NOT NULL
             AND close_decision IS NOT NULL
             AND close_reason IS NOT NULL)
        ),
        UNIQUE(session_id, observation_id)
    )
    """,
    """
    CREATE TABLE turn_risk_evaluation_observations (
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        evaluation_revision INTEGER NOT NULL CHECK(evaluation_revision > 0),
        observation_id TEXT NOT NULL CHECK(length(observation_id) > 0),
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        record_snapshot_json TEXT NOT NULL CHECK(
            json_valid(record_snapshot_json)
        ),
        record_snapshot_sha256 TEXT NOT NULL CHECK(
            length(record_snapshot_sha256) = 64
            AND record_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(
            session_id, turn_id, evaluation_revision, observation_id
        ),
        UNIQUE(session_id, turn_id, evaluation_revision, ordinal),
        FOREIGN KEY(session_id, turn_id, evaluation_revision)
            REFERENCES turn_risk_evaluations(
                session_id, turn_id, evaluation_revision
            ) ON DELETE RESTRICT,
        FOREIGN KEY(session_id, observation_id)
            REFERENCES internal_risk_observations(session_id, observation_id)
            ON DELETE RESTRICT
    )
    """,
    """
    CREATE TRIGGER turn_risk_evaluation_observations_insert_guard
    BEFORE INSERT ON turn_risk_evaluation_observations
    BEGIN
        SELECT CASE WHEN
            json_valid(NEW.record_snapshot_json) != 1
            OR json_type(NEW.record_snapshot_json, '$.session_id') IS NOT 'text'
            OR json_extract(NEW.record_snapshot_json, '$.session_id')
               IS NOT NEW.session_id
            OR json_type(
                NEW.record_snapshot_json, '$.observation.observation_id'
            ) IS NOT 'text'
            OR json_extract(
                NEW.record_snapshot_json, '$.observation.observation_id'
            ) IS NOT NEW.observation_id
            OR json_type(
                NEW.record_snapshot_json, '$.observation.trigger_turn_ids'
            ) IS NOT 'array'
            OR COALESCE(json_array_length(
                NEW.record_snapshot_json, '$.observation.trigger_turn_ids'
            ), 0) != 1
            OR json_extract(
                NEW.record_snapshot_json, '$.observation.trigger_turn_ids[0]'
            ) IS NOT NEW.turn_id
            OR json_type(
                NEW.record_snapshot_json, '$.trigger_spans'
            ) IS NOT 'array'
            OR COALESCE(json_array_length(
                NEW.record_snapshot_json, '$.trigger_spans'
            ), 0) < 1
            OR json_type(
                NEW.record_snapshot_json, '$.sources'
            ) IS NOT 'array'
            OR COALESCE(json_array_length(
                NEW.record_snapshot_json, '$.sources'
            ), 0) < 1
            OR EXISTS (
                SELECT 1
                  FROM json_tree(NEW.record_snapshot_json) AS node
                 WHERE node.key IS NOT NULL
                 GROUP BY node.parent, node.key
                HAVING COUNT(*) > 1
            )
        THEN RAISE(ABORT, 'turn risk evaluation member snapshot invalid') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
              FROM turn_risk_evaluations AS evaluation
              JOIN turns AS turn
                ON turn.session_id = evaluation.session_id
               AND turn.turn_id = evaluation.turn_id
             WHERE evaluation.session_id = NEW.session_id
               AND evaluation.turn_id = NEW.turn_id
               AND evaluation.evaluation_revision = NEW.evaluation_revision
               AND evaluation.status = 'pending'
               AND evaluation.client_message_sha256
                   = turn.client_message_sha256
               AND NOT EXISTS (
                    SELECT 1
                      FROM json_each(
                        NEW.record_snapshot_json, '$.trigger_spans'
                      ) AS span
                     WHERE json_extract(span.value, '$.turn_id')
                               IS NOT NEW.turn_id
                        OR json_extract(
                            span.value, '$.content_ref.object_id'
                        ) IS NOT turn.client_message_object_id
                        OR json_extract(
                            span.value, '$.content_ref.content_sha256'
                        ) IS NOT turn.client_message_sha256
               )
               AND NOT EXISTS (
                    SELECT 1
                      FROM json_each(
                        NEW.record_snapshot_json, '$.sources'
                      ) AS source
                     WHERE json_extract(source.value, '$.source_kind')
                               = 'model_observation'
                       AND (
                            evaluation.risk_model_mode = 'deterministic_only'
                            OR json_extract(
                                source.value, '$.source_ref.object_id'
                            ) IS NOT evaluation.approved_model_object_id
                            OR json_extract(
                                source.value, '$.source_ref.version'
                            ) IS NOT evaluation.approved_model_version
                            OR json_extract(
                                source.value, '$.source_ref.content_sha256'
                            ) IS NOT evaluation.approved_model_sha256
                       )
               )
        ) OR NEW.ordinal != (
            SELECT COUNT(*) FROM turn_risk_evaluation_observations AS member
             WHERE member.session_id = NEW.session_id
               AND member.turn_id = NEW.turn_id
               AND member.evaluation_revision = NEW.evaluation_revision
        )
        THEN RAISE(ABORT, 'turn risk evaluation member invalid') END;
    END
    """,
    """
    CREATE TRIGGER turn_risk_evaluation_observations_no_update
    BEFORE UPDATE ON turn_risk_evaluation_observations BEGIN
        SELECT RAISE(ABORT, 'turn risk evaluation members are append-only');
    END
    """,
    """
    CREATE TRIGGER turn_risk_evaluation_observations_no_delete
    BEFORE DELETE ON turn_risk_evaluation_observations BEGIN
        SELECT RAISE(ABORT, 'turn risk evaluation members are append-only');
    END
    """,
    """
    CREATE INDEX idx_internal_risk_visible
        ON internal_risk_observations(session_id, status, observation_id)
    """,
    """
    CREATE TRIGGER internal_risk_observations_update_guard
    BEFORE UPDATE ON internal_risk_observations
    BEGIN
        SELECT CASE WHEN
            NEW.observation_id != OLD.observation_id
            OR NEW.session_id != OLD.session_id
            OR NEW.immutable_record_json != OLD.immutable_record_json
        THEN RAISE(ABORT, 'risk observation immutable fields changed') END;
        SELECT CASE WHEN NOT (
            (OLD.status = 'open' AND NEW.status = 'acknowledged')
            OR (OLD.status = 'acknowledged' AND NEW.status = 'closed')
        ) THEN RAISE(ABORT, 'risk lifecycle transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER internal_risk_observations_no_delete
    BEFORE DELETE ON internal_risk_observations BEGIN
        SELECT RAISE(ABORT, 'risk observations cannot be deleted');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
