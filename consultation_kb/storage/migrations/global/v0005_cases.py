"""Global shared-case catalog, governed lineage, and publish-saga schema."""

from __future__ import annotations

import sqlite3


VERSION = 5
NAME = "global_shared_cases"


_STATEMENTS = (
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
    CREATE TABLE cases (
        case_id TEXT PRIMARY KEY CHECK(length(case_id) > 0),
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'REVOKED')),
        current_version INTEGER CHECK(current_version IS NULL OR current_version > 0),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        updated_at TEXT NOT NULL CHECK(length(updated_at) > 0),
        CHECK(
            (state = 'PREPARED' AND current_version IS NULL)
            OR (state IN ('ACTIVE', 'REVOKED') AND current_version IS NOT NULL)
        ),
        CHECK(updated_at >= created_at),
        FOREIGN KEY(case_id, current_version)
            REFERENCES case_versions(case_id, version) ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_cases_state ON cases(state, case_id)",
    """
    CREATE TABLE case_versions (
        case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
        version INTEGER NOT NULL CHECK(version > 0),
        candidate_id TEXT NOT NULL CHECK(length(candidate_id) > 0),
        candidate_version INTEGER NOT NULL CHECK(candidate_version > 0),
        candidate_sha256 TEXT NOT NULL CHECK(
            length(candidate_sha256) = 64
            AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        global_content_ref TEXT NOT NULL CHECK(
            global_content_ref = 'sha256:' || global_content_sha256
        ),
        global_content_sha256 TEXT NOT NULL CHECK(
            length(global_content_sha256) = 64
            AND global_content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        global_content_media_type TEXT NOT NULL CHECK(
            global_content_media_type = 'application/json'
        ),
        global_content_size_bytes INTEGER NOT NULL CHECK(
            global_content_size_bytes > 0
        ),
        manifest_id TEXT NOT NULL UNIQUE
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        release_decision_sha256 TEXT NOT NULL CHECK(
            length(release_decision_sha256) = 64
            AND release_decision_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        source_grade TEXT NOT NULL CHECK(source_grade IN ('K1', 'K2', 'K3', 'K4')),
        provenance_id TEXT NOT NULL CHECK(length(provenance_id) > 0),
        provenance_version INTEGER NOT NULL CHECK(provenance_version > 0),
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'REVOKED')),
        prepared_at TEXT NOT NULL CHECK(length(prepared_at) > 0),
        activated_at TEXT,
        revoked_at TEXT,
        PRIMARY KEY(case_id, version),
        UNIQUE(candidate_id, candidate_version),
        UNIQUE(candidate_sha256),
        FOREIGN KEY(provenance_id, provenance_version)
            REFERENCES case_provenance(provenance_id, provenance_version)
            ON DELETE RESTRICT,
        CHECK(
            (state = 'PREPARED' AND activated_at IS NULL AND revoked_at IS NULL)
            OR (state = 'ACTIVE' AND activated_at IS NOT NULL AND revoked_at IS NULL)
            OR (state = 'REVOKED' AND activated_at IS NOT NULL AND revoked_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX idx_case_versions_one_active
    ON case_versions(case_id) WHERE state = 'ACTIVE'
    """,
    """
    CREATE INDEX idx_case_versions_visibility
    ON case_versions(state, manifest_id, case_id, version)
    """,
    """
    CREATE TABLE case_authorizations (
        case_id TEXT NOT NULL,
        case_version INTEGER NOT NULL CHECK(case_version > 0),
        authorization_id TEXT NOT NULL CHECK(length(authorization_id) > 0),
        authorization_version INTEGER NOT NULL CHECK(authorization_version > 0),
        authorization_sha256 TEXT NOT NULL CHECK(
            length(authorization_sha256) = 64
            AND authorization_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        contributor_client_hash TEXT NOT NULL CHECK(
            length(contributor_client_hash) = 64
            AND contributor_client_hash NOT GLOB '*[^0-9a-f]*'
        ),
        reuse_authorized INTEGER NOT NULL CHECK(reuse_authorized = 1),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        valid_from TEXT NOT NULL CHECK(length(valid_from) > 0),
        expires_at TEXT,
        revoked_at TEXT,
        terms_sha256 TEXT NOT NULL CHECK(
            length(terms_sha256) = 64
            AND terms_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(case_id, case_version),
        UNIQUE(authorization_id, authorization_version),
        FOREIGN KEY(case_id, case_version)
            REFERENCES case_versions(case_id, version) ON DELETE RESTRICT,
        CHECK(expires_at IS NULL OR expires_at > valid_from),
        CHECK(revoked_at IS NULL OR revoked_at >= valid_from)
    )
    """,
    """
    CREATE TABLE case_review_decisions (
        case_id TEXT NOT NULL,
        case_version INTEGER NOT NULL CHECK(case_version > 0),
        review_id TEXT NOT NULL CHECK(length(review_id) > 0),
        review_version INTEGER NOT NULL CHECK(review_version > 0),
        review_sha256 TEXT NOT NULL CHECK(
            length(review_sha256) = 64
            AND review_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        candidate_sha256 TEXT NOT NULL CHECK(
            length(candidate_sha256) = 64
            AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        decision TEXT NOT NULL CHECK(decision = 'approved'),
        checked_categories_json TEXT NOT NULL CHECK(
            length(checked_categories_json) > 2
        ),
        residual_risk TEXT NOT NULL CHECK(residual_risk IN ('low', 'medium')),
        rare_combination_disposition TEXT NOT NULL CHECK(
            rare_combination_disposition IN ('not_present', 'mitigated')
        ),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        reviewer_attestation_sha256 TEXT NOT NULL CHECK(
            length(reviewer_attestation_sha256) = 64
            AND reviewer_attestation_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        release_policy_id TEXT NOT NULL CHECK(length(release_policy_id) > 0),
        release_policy_version INTEGER NOT NULL CHECK(release_policy_version > 0),
        release_policy_sha256 TEXT NOT NULL CHECK(
            length(release_policy_sha256) = 64
            AND release_policy_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        release_decision_sha256 TEXT NOT NULL CHECK(
            length(release_decision_sha256) = 64
            AND release_decision_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        reviewed_at TEXT NOT NULL CHECK(length(reviewed_at) > 0),
        evaluated_at TEXT NOT NULL CHECK(length(evaluated_at) > 0),
        PRIMARY KEY(case_id, case_version),
        UNIQUE(review_id, review_version),
        FOREIGN KEY(case_id, case_version)
            REFERENCES case_versions(case_id, version) ON DELETE RESTRICT,
        CHECK(evaluated_at >= reviewed_at)
    )
    """,
    """
    CREATE TABLE case_provenance (
        provenance_id TEXT NOT NULL CHECK(length(provenance_id) > 0),
        provenance_version INTEGER NOT NULL CHECK(provenance_version > 0),
        provenance_sha256 TEXT NOT NULL CHECK(
            length(provenance_sha256) = 64
            AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_object_id TEXT NOT NULL CHECK(length(artifact_object_id) > 0),
        artifact_version INTEGER NOT NULL CHECK(artifact_version > 0),
        artifact_sha256 TEXT NOT NULL CHECK(
            length(artifact_sha256) = 64
            AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_kind TEXT NOT NULL CHECK(
            artifact_kind IN (
                'case', 'case_pattern', 'claim', 'wiki_section',
                'graph_edge', 'lexical_row', 'vector_row'
            )
        ),
        contributor_client_hashes_json TEXT NOT NULL CHECK(
            length(contributor_client_hashes_json) > 2
        ),
        independent_source_count INTEGER NOT NULL CHECK(
            independent_source_count >= 0
        ),
        derivation_rule_id TEXT NOT NULL CHECK(length(derivation_rule_id) > 0),
        derivation_rule_version INTEGER NOT NULL CHECK(derivation_rule_version > 0),
        derivation_rule_sha256 TEXT NOT NULL CHECK(
            length(derivation_rule_sha256) = 64
            AND derivation_rule_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        policy_manifest_id TEXT NOT NULL CHECK(length(policy_manifest_id) > 0),
        policy_manifest_version INTEGER NOT NULL CHECK(policy_manifest_version > 0),
        policy_manifest_sha256 TEXT NOT NULL CHECK(
            length(policy_manifest_sha256) = 64
            AND policy_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_grade TEXT NOT NULL CHECK(length(source_grade) > 0),
        provenance_scope TEXT NOT NULL CHECK(
            provenance_scope IN ('global_source', 'case_derived', 'mixed')
        ),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        effective_to TEXT,
        closure_json TEXT NOT NULL CHECK(length(closure_json) > 2),
        closure_sha256 TEXT NOT NULL CHECK(
            length(closure_sha256) = 64
            AND closure_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(provenance_id, provenance_version),
        UNIQUE(artifact_object_id, artifact_version, artifact_sha256),
        CHECK(provenance_sha256 = closure_sha256)
    )
    """,
    """
    CREATE TABLE case_patterns (
        pattern_id TEXT NOT NULL CHECK(length(pattern_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        global_content_ref TEXT NOT NULL CHECK(
            global_content_ref = 'sha256:' || global_content_sha256
        ),
        global_content_sha256 TEXT NOT NULL CHECK(
            length(global_content_sha256) = 64
            AND global_content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        global_content_size_bytes INTEGER NOT NULL CHECK(
            global_content_size_bytes > 0
        ),
        manifest_id TEXT NOT NULL
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        provenance_id TEXT NOT NULL,
        provenance_version INTEGER NOT NULL CHECK(provenance_version > 0),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'REVOKED')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(pattern_id, version),
        FOREIGN KEY(provenance_id, provenance_version)
            REFERENCES case_provenance(provenance_id, provenance_version)
            ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE case_regeneration_proofs (
        proof_id TEXT NOT NULL CHECK(length(proof_id) > 0),
        proof_version INTEGER NOT NULL CHECK(proof_version > 0),
        proof_sha256 TEXT NOT NULL CHECK(
            length(proof_sha256) = 64
            AND proof_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        request_sha256 TEXT NOT NULL CHECK(
            length(request_sha256) = 64
            AND request_sha256 NOT GLOB '*[^0-9a-f]*'
            AND request_sha256 = proof_sha256
        ),
        parent_ref_json TEXT NOT NULL CHECK(length(parent_ref_json) > 2),
        variant_ref_json TEXT NOT NULL CHECK(length(variant_ref_json) > 2),
        content_ref_json TEXT NOT NULL CHECK(length(content_ref_json) > 2),
        regeneration_rule_ref_json TEXT NOT NULL CHECK(
            length(regeneration_rule_ref_json) > 2
        ),
        input_case_refs_json TEXT NOT NULL CHECK(length(input_case_refs_json) > 1),
        input_independent_source_refs_json TEXT NOT NULL CHECK(
            length(input_independent_source_refs_json) > 1
        ),
        rendered_text_sha256 TEXT NOT NULL CHECK(
            length(rendered_text_sha256) = 64
            AND rendered_text_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(proof_id, proof_version)
    )
    """,
    """
    CREATE TABLE case_leave_one_out_variants (
        mapping_id TEXT NOT NULL CHECK(length(mapping_id) > 0),
        mapping_version INTEGER NOT NULL CHECK(mapping_version > 0),
        mapping_sha256 TEXT NOT NULL CHECK(
            length(mapping_sha256) = 64
            AND mapping_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        parent_object_id TEXT NOT NULL CHECK(length(parent_object_id) > 0),
        parent_version INTEGER NOT NULL CHECK(parent_version > 0),
        parent_sha256 TEXT NOT NULL CHECK(
            length(parent_sha256) = 64
            AND parent_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        excluded_client_hash TEXT NOT NULL CHECK(
            length(excluded_client_hash) = 64
            AND excluded_client_hash NOT GLOB '*[^0-9a-f]*'
        ),
        variant_object_id TEXT NOT NULL CHECK(length(variant_object_id) > 0),
        variant_version INTEGER NOT NULL CHECK(variant_version > 0),
        variant_sha256 TEXT NOT NULL CHECK(
            length(variant_sha256) = 64
            AND variant_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        content_object_id TEXT NOT NULL CHECK(length(content_object_id) > 0),
        content_version INTEGER NOT NULL CHECK(content_version > 0),
        content_sha256 TEXT NOT NULL CHECK(
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        authority_manifest_id TEXT NOT NULL
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        authority_manifest_version INTEGER NOT NULL CHECK(
            authority_manifest_version > 0
        ),
        authority_manifest_sha256 TEXT NOT NULL CHECK(
            length(authority_manifest_sha256) = 64
            AND authority_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        provenance_id TEXT NOT NULL,
        provenance_version INTEGER NOT NULL CHECK(provenance_version > 0),
        approval_id TEXT NOT NULL CHECK(length(approval_id) > 0),
        approval_version INTEGER NOT NULL CHECK(approval_version > 0),
        approval_sha256 TEXT NOT NULL CHECK(
            length(approval_sha256) = 64
            AND approval_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        approval_descriptor_sha256 TEXT NOT NULL CHECK(
            length(approval_descriptor_sha256) = 64
            AND approval_descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        draft_id TEXT NOT NULL CHECK(length(draft_id) > 0),
        draft_version INTEGER NOT NULL CHECK(draft_version > 0),
        draft_sha256 TEXT NOT NULL CHECK(
            length(draft_sha256) = 64
            AND draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        regeneration_rule_id TEXT NOT NULL CHECK(
            length(regeneration_rule_id) > 0
        ),
        regeneration_rule_version INTEGER NOT NULL CHECK(
            regeneration_rule_version > 0
        ),
        regeneration_rule_sha256 TEXT NOT NULL CHECK(
            length(regeneration_rule_sha256) = 64
            AND regeneration_rule_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        regeneration_request_sha256 TEXT NOT NULL CHECK(
            length(regeneration_request_sha256) = 64
            AND regeneration_request_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        regeneration_proof_id TEXT NOT NULL CHECK(
            length(regeneration_proof_id) > 0
        ),
        regeneration_proof_version INTEGER NOT NULL CHECK(
            regeneration_proof_version > 0
        ),
        regeneration_proof_sha256 TEXT NOT NULL CHECK(
            length(regeneration_proof_sha256) = 64
            AND regeneration_proof_sha256 NOT GLOB '*[^0-9a-f]*'
            AND regeneration_proof_sha256 = regeneration_request_sha256
        ),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 2),
        source_grade TEXT NOT NULL CHECK(length(source_grade) > 0),
        remaining_independent_source_count INTEGER NOT NULL CHECK(
            remaining_independent_source_count >= 0
        ),
        minimum_independent_source_count INTEGER NOT NULL CHECK(
            minimum_independent_source_count > 0
        ),
        review_status TEXT NOT NULL CHECK(review_status = 'approved'),
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'REVOKED')),
        approved_at TEXT NOT NULL CHECK(length(approved_at) > 0),
        effective_to TEXT,
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(mapping_id, mapping_version),
        UNIQUE(parent_object_id, parent_version, parent_sha256, excluded_client_hash),
        UNIQUE(variant_object_id, variant_version),
        FOREIGN KEY(provenance_id, provenance_version)
            REFERENCES case_provenance(provenance_id, provenance_version)
            ON DELETE RESTRICT,
        FOREIGN KEY(approval_id)
            REFERENCES approval_executions(operation_id)
            ON DELETE RESTRICT,
        FOREIGN KEY(regeneration_proof_id, regeneration_proof_version)
            REFERENCES case_regeneration_proofs(proof_id, proof_version)
            ON DELETE RESTRICT,
        CHECK(approval_version > 0),
        CHECK(effective_to IS NULL OR effective_to > approved_at),
        CHECK(
            state != 'ACTIVE'
            OR remaining_independent_source_count >= minimum_independent_source_count
        )
    )
    """,
    """
    CREATE INDEX idx_loo_exact_active
    ON case_leave_one_out_variants(
        parent_object_id, parent_version, parent_sha256,
        excluded_client_hash, state
    )
    """,
    """
    CREATE TABLE global_publish_sagas (
        saga_id TEXT PRIMARY KEY CHECK(length(saga_id) > 0),
        source_event_id TEXT NOT NULL UNIQUE CHECK(length(source_event_id) > 0),
        idempotency_key_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(idempotency_key_sha256) = 64
            AND idempotency_key_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        outbox_payload_sha256 TEXT NOT NULL CHECK(
            length(outbox_payload_sha256) = 64
            AND outbox_payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        case_id TEXT NOT NULL CHECK(length(case_id) > 0),
        case_version INTEGER NOT NULL CHECK(case_version > 0),
        candidate_id TEXT NOT NULL CHECK(length(candidate_id) > 0),
        candidate_version INTEGER NOT NULL CHECK(candidate_version > 0),
        candidate_sha256 TEXT NOT NULL CHECK(
            length(candidate_sha256) = 64
            AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        publication_operation_id TEXT NOT NULL UNIQUE
            CHECK(length(publication_operation_id) > 0),
        manifest_id TEXT NOT NULL UNIQUE CHECK(length(manifest_id) > 0),
        provenance_id TEXT NOT NULL UNIQUE CHECK(length(provenance_id) > 0),
        provenance_version INTEGER NOT NULL CHECK(provenance_version > 0),
        global_content_sha256 TEXT CHECK(
            global_content_sha256 IS NULL
            OR (
                length(global_content_sha256) = 64
                AND global_content_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        global_content_media_type TEXT,
        global_content_size_bytes INTEGER CHECK(
            global_content_size_bytes IS NULL OR global_content_size_bytes > 0
        ),
        state TEXT NOT NULL CHECK(
            state IN ('RECEIVED', 'COPIED', 'PREPARED', 'ACTIVE')
        ),
        authority_epoch INTEGER CHECK(
            authority_epoch IS NULL OR authority_epoch >= 0
        ),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        published_global_version INTEGER CHECK(
            published_global_version IS NULL OR published_global_version > 0
        ),
        last_error_code TEXT,
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        updated_at TEXT NOT NULL CHECK(length(updated_at) > 0),
        UNIQUE(candidate_id, candidate_version),
        CHECK(
            (state = 'RECEIVED'
             AND global_content_sha256 IS NULL
             AND global_content_media_type IS NULL
             AND global_content_size_bytes IS NULL)
            OR
            (state IN ('COPIED', 'PREPARED', 'ACTIVE')
             AND global_content_sha256 IS NOT NULL
             AND global_content_media_type = 'application/json'
             AND global_content_size_bytes IS NOT NULL)
        ),
        CHECK(
            (state = 'ACTIVE' AND published_global_version = case_version)
            OR (state != 'ACTIVE' AND published_global_version IS NULL)
        ),
        CHECK(
            (state IN ('RECEIVED', 'COPIED') AND authority_epoch IS NULL)
            OR (state IN ('PREPARED', 'ACTIVE') AND authority_epoch IS NOT NULL)
        ),
        CHECK(updated_at >= created_at)
    )
    """,
    "CREATE INDEX idx_global_publish_saga_state ON global_publish_sagas(state)",
    """
    CREATE TRIGGER case_versions_update_guard
    BEFORE UPDATE ON case_versions BEGIN
        SELECT CASE WHEN
            NEW.case_id != OLD.case_id
            OR NEW.version != OLD.version
            OR NEW.candidate_id != OLD.candidate_id
            OR NEW.candidate_version != OLD.candidate_version
            OR NEW.candidate_sha256 != OLD.candidate_sha256
            OR NEW.global_content_ref != OLD.global_content_ref
            OR NEW.global_content_sha256 != OLD.global_content_sha256
            OR NEW.global_content_media_type != OLD.global_content_media_type
            OR NEW.global_content_size_bytes != OLD.global_content_size_bytes
            OR NEW.manifest_id != OLD.manifest_id
            OR NEW.release_decision_sha256 != OLD.release_decision_sha256
            OR NEW.allowed_uses_json != OLD.allowed_uses_json
            OR NEW.source_grade != OLD.source_grade
            OR NEW.provenance_id != OLD.provenance_id
            OR NEW.provenance_version != OLD.provenance_version
            OR NOT (
                (OLD.state = 'PREPARED' AND NEW.state = 'ACTIVE'
                 AND NEW.activated_at IS NOT NULL AND NEW.revoked_at IS NULL)
                OR
                (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED'
                 AND NEW.activated_at = OLD.activated_at
                 AND NEW.revoked_at IS NOT NULL)
            )
        THEN RAISE(ABORT, 'case version transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER cases_update_guard
    BEFORE UPDATE ON cases BEGIN
        SELECT CASE WHEN
            NEW.case_id != OLD.case_id
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (OLD.state = 'PREPARED' AND NEW.state = 'ACTIVE'
                 AND OLD.current_version IS NULL
                 AND NEW.current_version IS NOT NULL)
                OR
                (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED'
                 AND NEW.current_version = OLD.current_version)
            )
        THEN RAISE(ABORT, 'case transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER cases_no_delete
    BEFORE DELETE ON cases BEGIN
        SELECT RAISE(ABORT, 'case history is immutable');
    END
    """,
    """
    CREATE TRIGGER case_versions_no_delete
    BEFORE DELETE ON case_versions BEGIN
        SELECT RAISE(ABORT, 'case version history is immutable');
    END
    """,
    """
    CREATE TRIGGER case_authorizations_update_guard
    BEFORE UPDATE ON case_authorizations BEGIN
        SELECT RAISE(ABORT, 'case authorizations are immutable');
    END
    """,
    """
    CREATE TRIGGER case_governance_no_delete
    BEFORE DELETE ON case_authorizations BEGIN
        SELECT RAISE(ABORT, 'case authorization history is immutable');
    END
    """,
    """
    CREATE TRIGGER case_reviews_no_update
    BEFORE UPDATE ON case_review_decisions BEGIN
        SELECT RAISE(ABORT, 'case review decisions are immutable');
    END
    """,
    """
    CREATE TRIGGER case_reviews_no_delete
    BEFORE DELETE ON case_review_decisions BEGIN
        SELECT RAISE(ABORT, 'case review decisions are immutable');
    END
    """,
    """
    CREATE TRIGGER case_provenance_no_update
    BEFORE UPDATE ON case_provenance BEGIN
        SELECT RAISE(ABORT, 'case provenance is immutable');
    END
    """,
    """
    CREATE TRIGGER case_provenance_no_delete
    BEFORE DELETE ON case_provenance BEGIN
        SELECT RAISE(ABORT, 'case provenance is immutable');
    END
    """,
    """
    CREATE TRIGGER case_patterns_update_guard
    BEFORE UPDATE ON case_patterns BEGIN
        SELECT CASE WHEN
            NEW.pattern_id != OLD.pattern_id
            OR NEW.version != OLD.version
            OR NEW.global_content_ref != OLD.global_content_ref
            OR NEW.global_content_sha256 != OLD.global_content_sha256
            OR NEW.global_content_size_bytes != OLD.global_content_size_bytes
            OR NEW.manifest_id != OLD.manifest_id
            OR NEW.provenance_id != OLD.provenance_id
            OR NEW.provenance_version != OLD.provenance_version
            OR NEW.allowed_uses_json != OLD.allowed_uses_json
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (OLD.state = 'PREPARED' AND NEW.state IN ('ACTIVE', 'REVOKED'))
                OR (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED')
            )
        THEN RAISE(ABORT, 'case pattern transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER case_patterns_no_delete
    BEFORE DELETE ON case_patterns BEGIN
        SELECT RAISE(ABORT, 'case pattern history is immutable');
    END
    """,
    """
    CREATE TRIGGER case_leave_one_out_variants_update_guard
    BEFORE UPDATE ON case_leave_one_out_variants BEGIN
        SELECT CASE WHEN
            NEW.mapping_id != OLD.mapping_id
            OR NEW.mapping_version != OLD.mapping_version
            OR NEW.mapping_sha256 != OLD.mapping_sha256
            OR NEW.parent_object_id != OLD.parent_object_id
            OR NEW.parent_version != OLD.parent_version
            OR NEW.parent_sha256 != OLD.parent_sha256
            OR NEW.excluded_client_hash != OLD.excluded_client_hash
            OR NEW.variant_object_id != OLD.variant_object_id
            OR NEW.variant_version != OLD.variant_version
            OR NEW.variant_sha256 != OLD.variant_sha256
            OR NEW.content_object_id != OLD.content_object_id
            OR NEW.content_version != OLD.content_version
            OR NEW.content_sha256 != OLD.content_sha256
            OR NEW.authority_manifest_id != OLD.authority_manifest_id
            OR NEW.authority_manifest_version != OLD.authority_manifest_version
            OR NEW.authority_manifest_sha256 != OLD.authority_manifest_sha256
            OR NEW.provenance_id != OLD.provenance_id
            OR NEW.provenance_version != OLD.provenance_version
            OR NEW.approval_id != OLD.approval_id
            OR NEW.approval_version != OLD.approval_version
            OR NEW.approval_sha256 != OLD.approval_sha256
            OR NEW.approval_descriptor_sha256 != OLD.approval_descriptor_sha256
            OR NEW.draft_id != OLD.draft_id
            OR NEW.draft_version != OLD.draft_version
            OR NEW.draft_sha256 != OLD.draft_sha256
            OR NEW.regeneration_rule_id != OLD.regeneration_rule_id
            OR NEW.regeneration_rule_version != OLD.regeneration_rule_version
            OR NEW.regeneration_rule_sha256 != OLD.regeneration_rule_sha256
            OR NEW.regeneration_request_sha256 != OLD.regeneration_request_sha256
            OR NEW.regeneration_proof_id != OLD.regeneration_proof_id
            OR NEW.regeneration_proof_version != OLD.regeneration_proof_version
            OR NEW.regeneration_proof_sha256 != OLD.regeneration_proof_sha256
            OR NEW.allowed_uses_json != OLD.allowed_uses_json
            OR NEW.source_grade != OLD.source_grade
            OR NEW.remaining_independent_source_count
                != OLD.remaining_independent_source_count
            OR NEW.minimum_independent_source_count
                != OLD.minimum_independent_source_count
            OR NEW.review_status != OLD.review_status
            OR NEW.approved_at != OLD.approved_at
            OR NEW.effective_to IS NOT OLD.effective_to
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (OLD.state = 'PREPARED' AND NEW.state IN ('ACTIVE', 'REVOKED'))
                OR (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED')
            )
        THEN RAISE(ABORT, 'leave-one-out transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER case_leave_one_out_variants_no_delete
    BEFORE DELETE ON case_leave_one_out_variants BEGIN
        SELECT RAISE(ABORT, 'leave-one-out history is immutable');
    END
    """,
    """
    CREATE TRIGGER case_regeneration_proofs_no_update
    BEFORE UPDATE ON case_regeneration_proofs BEGIN
        SELECT RAISE(ABORT, 'case regeneration proofs are immutable');
    END
    """,
    """
    CREATE TRIGGER case_regeneration_proofs_no_delete
    BEFORE DELETE ON case_regeneration_proofs BEGIN
        SELECT RAISE(ABORT, 'case regeneration proofs are immutable');
    END
    """,
    """
    CREATE TRIGGER global_publish_sagas_update_guard
    BEFORE UPDATE ON global_publish_sagas BEGIN
        SELECT CASE WHEN
            NEW.saga_id != OLD.saga_id
            OR NEW.source_event_id != OLD.source_event_id
            OR NEW.idempotency_key_sha256 != OLD.idempotency_key_sha256
            OR NEW.outbox_payload_sha256 != OLD.outbox_payload_sha256
            OR NEW.case_id != OLD.case_id
            OR NEW.case_version != OLD.case_version
            OR NEW.candidate_id != OLD.candidate_id
            OR NEW.candidate_version != OLD.candidate_version
            OR NEW.candidate_sha256 != OLD.candidate_sha256
            OR NEW.publication_operation_id != OLD.publication_operation_id
            OR NEW.manifest_id != OLD.manifest_id
            OR NEW.provenance_id != OLD.provenance_id
            OR NEW.provenance_version != OLD.provenance_version
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (NEW.state = OLD.state
                 AND NEW.global_content_sha256 IS OLD.global_content_sha256
                 AND NEW.global_content_media_type IS OLD.global_content_media_type
                 AND NEW.global_content_size_bytes IS OLD.global_content_size_bytes
                 AND NEW.authority_epoch IS OLD.authority_epoch
                 AND NEW.published_global_version IS OLD.published_global_version)
                OR
                (OLD.state = 'RECEIVED' AND NEW.state = 'COPIED'
                 AND OLD.global_content_sha256 IS NULL
                 AND NEW.global_content_sha256 IS NOT NULL
                 AND NEW.global_content_media_type = 'application/json'
                 AND NEW.global_content_size_bytes IS NOT NULL
                 AND NEW.authority_epoch IS NULL
                 AND NEW.published_global_version IS NULL)
                OR
                (OLD.state = 'COPIED' AND NEW.state = 'PREPARED'
                 AND NEW.global_content_sha256 = OLD.global_content_sha256
                 AND NEW.global_content_media_type = OLD.global_content_media_type
                 AND NEW.global_content_size_bytes = OLD.global_content_size_bytes
                 AND OLD.authority_epoch IS NULL
                 AND NEW.authority_epoch IS NOT NULL
                 AND NEW.published_global_version IS NULL)
                OR
                (OLD.state = 'PREPARED' AND NEW.state = 'ACTIVE'
                 AND NEW.global_content_sha256 = OLD.global_content_sha256
                 AND NEW.global_content_media_type = OLD.global_content_media_type
                 AND NEW.global_content_size_bytes = OLD.global_content_size_bytes
                 AND NEW.authority_epoch >= OLD.authority_epoch
                 AND NEW.published_global_version = NEW.case_version)
            )
        THEN RAISE(ABORT, 'global case publish saga transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER global_publish_sagas_no_delete
    BEFORE DELETE ON global_publish_sagas BEGIN
        SELECT RAISE(ABORT, 'global case publish saga is immutable');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
