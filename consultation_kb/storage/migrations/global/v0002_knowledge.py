"""Global governed-knowledge catalog schema.

The knowledge catalog is deliberately metadata-heavy.  Large source, passage,
claim and Wiki bodies live in the scope-local content store; these tables keep
only immutable object references, hashes and governance state.
"""

from __future__ import annotations

import sqlite3


VERSION = 2
NAME = "governed_knowledge_catalog"


_STATEMENTS = (
    """
    CREATE TABLE sources (
        source_id TEXT PRIMARY KEY CHECK(length(source_id) > 0),
        logical_path TEXT NOT NULL UNIQUE CHECK(length(logical_path) > 0),
        logical_path_key TEXT NOT NULL UNIQUE CHECK(length(logical_path_key) > 0),
        document_type TEXT NOT NULL CHECK(length(document_type) > 0),
        current_version INTEGER NOT NULL CHECK(current_version > 0),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0)
    )
    """,
    """
    CREATE TABLE source_versions (
        source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
        version INTEGER NOT NULL CHECK(version > 0),
        content_sha256 TEXT NOT NULL CHECK(
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        content_object_ref TEXT NOT NULL CHECK(length(content_object_ref) > 0),
        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
        license TEXT NOT NULL CHECK(length(license) > 0),
        domain TEXT NOT NULL CHECK(length(domain) > 0),
        language TEXT NOT NULL CHECK(length(language) > 0),
        sensitivity TEXT NOT NULL CHECK(length(sensitivity) > 0),
        source_grade TEXT NOT NULL CHECK(length(source_grade) > 0),
        status TEXT NOT NULL CHECK(status IN ('DRAFT', 'REVIEWED', 'APPROVED', 'REJECTED', 'REVOKED')),
        imported_at TEXT NOT NULL CHECK(length(imported_at) > 0),
        metadata_json TEXT NOT NULL CHECK(length(metadata_json) > 0),
        metadata_sha256 TEXT NOT NULL CHECK(
            length(metadata_sha256) = 64
            AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(source_id, version)
    )
    """,
    "CREATE INDEX idx_source_versions_hash ON source_versions(content_sha256)",
    "CREATE INDEX idx_source_versions_state ON source_versions(status)",
    """
    CREATE TABLE passages (
        passage_id TEXT NOT NULL CHECK(length(passage_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        source_id TEXT NOT NULL,
        source_version INTEGER NOT NULL,
        document_type TEXT NOT NULL CHECK(length(document_type) > 0),
        structural_path TEXT NOT NULL CHECK(length(structural_path) > 0),
        locator_json TEXT NOT NULL CHECK(length(locator_json) > 0),
        normalized_text_sha256 TEXT NOT NULL CHECK(
            length(normalized_text_sha256) = 64
            AND normalized_text_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        raw_content_ref TEXT NOT NULL CHECK(length(raw_content_ref) > 0),
        retrieval_content_ref TEXT NOT NULL CHECK(length(retrieval_content_ref) > 0),
        context_before_ref TEXT,
        context_after_ref TEXT,
        extractor_version TEXT NOT NULL CHECK(length(extractor_version) > 0),
        privacy_scope TEXT NOT NULL CHECK(privacy_scope IN ('GLOBAL', 'PRIVATE', 'CASE')),
        provenance_json TEXT NOT NULL CHECK(length(provenance_json) > 0),
        review_status TEXT NOT NULL CHECK(review_status IN ('DRAFT', 'REVIEWED', 'APPROVED', 'REJECTED', 'REVOKED')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(passage_id, version),
        FOREIGN KEY(source_id, source_version)
            REFERENCES source_versions(source_id, version) ON DELETE RESTRICT,
        UNIQUE(source_id, source_version, structural_path, normalized_text_sha256)
    )
    """,
    "CREATE INDEX idx_passages_source ON passages(source_id, source_version)",
    "CREATE INDEX idx_passages_status ON passages(review_status)",
    """
    CREATE TABLE claims (
        claim_id TEXT NOT NULL CHECK(length(claim_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        claim_object_ref TEXT NOT NULL CHECK(length(claim_object_ref) > 0),
        claim_object_size_bytes INTEGER NOT NULL CHECK(claim_object_size_bytes >= 0),
        claim_object_media_type TEXT NOT NULL CHECK(length(claim_object_media_type) > 0),
        claim_sha256 TEXT NOT NULL CHECK(
            length(claim_sha256) = 64
            AND claim_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        cognitive_type TEXT NOT NULL CHECK(cognitive_type IN (
            'explicit', 'paraphrase', 'counselor_judgment',
            'model_inference', 'cross_theory_analogy'
        )),
        source_grade TEXT NOT NULL CHECK(length(source_grade) > 0),
        framework_eligibility TEXT NOT NULL CHECK(framework_eligibility IN ('ELIGIBLE', 'INELIGIBLE', 'CONDITIONAL')),
        empirical_support TEXT NOT NULL CHECK(length(empirical_support) > 0),
        model_confidence REAL CHECK(model_confidence IS NULL OR (model_confidence >= 0 AND model_confidence <= 1)),
        review_status TEXT NOT NULL CHECK(review_status IN ('DRAFT', 'REVIEWED', 'APPROVED', 'REJECTED', 'REVOKED')),
        effective_from TEXT,
        effective_to TEXT,
        review_due_at TEXT,
        applicability_json TEXT NOT NULL CHECK(length(applicability_json) > 0),
        privacy_scope TEXT NOT NULL CHECK(privacy_scope IN ('GLOBAL', 'PRIVATE', 'CASE', 'MIXED')),
        allowed_uses_json TEXT NOT NULL CHECK(length(allowed_uses_json) > 0),
        provenance_json TEXT NOT NULL CHECK(length(provenance_json) > 0),
        theory_revision_id TEXT,
        theory_revision INTEGER,
        theory_revision_sha256 TEXT CHECK(
            theory_revision_sha256 IS NULL OR (
                length(theory_revision_sha256) = 64
                AND theory_revision_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(claim_id, version),
        FOREIGN KEY(theory_revision_id, theory_revision)
            REFERENCES theory_revisions(theory_id, revision) ON DELETE RESTRICT,
        CHECK(
            (source_grade = 'C1' AND theory_revision_id IS NOT NULL
                AND theory_revision IS NOT NULL AND theory_revision > 0
                AND theory_revision_sha256 IS NOT NULL)
            OR
            (source_grade <> 'C1' AND theory_revision_id IS NULL
                AND theory_revision IS NULL AND theory_revision_sha256 IS NULL)
        ),
        CHECK(effective_to IS NULL OR effective_from IS NULL OR effective_to > effective_from)
    )
    """,
    "CREATE INDEX idx_claims_status_grade ON claims(review_status, source_grade)",
    """
    CREATE TABLE claim_evidence (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        passage_id TEXT NOT NULL,
        passage_version INTEGER NOT NULL,
        relation TEXT NOT NULL CHECK(relation IN ('SUPPORTS', 'CONTRADICTS')),
        evidence_role TEXT NOT NULL CHECK(evidence_role IN ('PRIMARY', 'CORROBORATING', 'COUNTEREVIDENCE')),
        PRIMARY KEY(claim_id, claim_version, passage_id, passage_version, relation),
        FOREIGN KEY(claim_id, claim_version)
            REFERENCES claims(claim_id, version) ON DELETE RESTRICT,
        FOREIGN KEY(passage_id, passage_version)
            REFERENCES passages(passage_id, version) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE theory_revisions (
        theory_id TEXT NOT NULL CHECK(length(theory_id) > 0),
        revision INTEGER NOT NULL CHECK(revision > 0),
        source_id TEXT NOT NULL,
        source_version INTEGER NOT NULL,
        document_sha256 TEXT NOT NULL CHECK(length(document_sha256) = 64),
        revision_sha256 TEXT NOT NULL CHECK(
            length(revision_sha256) = 64
            AND revision_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        revision_object_ref TEXT NOT NULL CHECK(length(revision_object_ref) > 0),
        revision_object_size_bytes INTEGER NOT NULL CHECK(revision_object_size_bytes >= 0),
        revision_object_media_type TEXT NOT NULL CHECK(length(revision_object_media_type) > 0),
        author TEXT NOT NULL CHECK(length(author) > 0),
        declared_version TEXT NOT NULL CHECK(length(declared_version) > 0),
        source_grade TEXT NOT NULL CHECK(source_grade = 'C1'),
        empirical_support TEXT NOT NULL CHECK(length(empirical_support) > 0),
        status TEXT NOT NULL CHECK(status IN ('DRAFT', 'PREPARED', 'ACTIVE', 'SUPERSEDED', 'REVOKED', 'EXPIRED')),
        approval_request_id TEXT,
        approved_at TEXT,
        effective_from TEXT NOT NULL CHECK(length(effective_from) > 0),
        effective_to TEXT,
        applicability_json TEXT NOT NULL CHECK(length(applicability_json) > 0),
        core_claims_json TEXT NOT NULL CHECK(length(core_claims_json) > 0),
        methods_json TEXT NOT NULL CHECK(length(methods_json) > 0),
        contraindications_json TEXT NOT NULL CHECK(length(contraindications_json) > 0),
        counterexamples_json TEXT NOT NULL CHECK(length(counterexamples_json) > 0),
        citations_json TEXT NOT NULL CHECK(length(citations_json) > 0),
        scope_policy_ref_json TEXT NOT NULL CHECK(length(scope_policy_ref_json) > 0),
        supersedes_revision INTEGER,
        revokes_revision INTEGER,
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(theory_id, revision),
        FOREIGN KEY(source_id, source_version)
            REFERENCES source_versions(source_id, version) ON DELETE RESTRICT,
        FOREIGN KEY(theory_id, supersedes_revision)
            REFERENCES theory_revisions(theory_id, revision) ON DELETE RESTRICT,
        FOREIGN KEY(theory_id, revokes_revision)
            REFERENCES theory_revisions(theory_id, revision) ON DELETE RESTRICT,
        CHECK(effective_to IS NULL OR effective_to > effective_from),
        CHECK(status = 'DRAFT' OR (approval_request_id IS NOT NULL AND approved_at IS NOT NULL))
    )
    """,
    """
    CREATE UNIQUE INDEX idx_theory_one_active
    ON theory_revisions(theory_id) WHERE status = 'ACTIVE'
    """,
    """
    CREATE TABLE theory_revision_passages (
        theory_id TEXT NOT NULL,
        theory_revision INTEGER NOT NULL,
        passage_id TEXT NOT NULL,
        passage_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        PRIMARY KEY(theory_id, theory_revision, passage_id, passage_version),
        UNIQUE(theory_id, theory_revision, ordinal),
        FOREIGN KEY(theory_id, theory_revision)
            REFERENCES theory_revisions(theory_id, revision) ON DELETE RESTRICT,
        FOREIGN KEY(passage_id, passage_version)
            REFERENCES passages(passage_id, version) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE entity_aliases (
        entity_id TEXT NOT NULL CHECK(length(entity_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        alias TEXT NOT NULL CHECK(length(alias) > 0),
        language TEXT NOT NULL CHECK(length(language) > 0),
        meaning_scope TEXT NOT NULL CHECK(length(meaning_scope) > 0),
        review_status TEXT NOT NULL CHECK(review_status IN ('DRAFT', 'APPROVED', 'REJECTED', 'REVOKED')),
        PRIMARY KEY(entity_id, version, alias, language, meaning_scope)
    )
    """,
    """
    CREATE TABLE review_decisions (
        decision_id TEXT PRIMARY KEY CHECK(length(decision_id) > 0),
        object_type TEXT NOT NULL CHECK(length(object_type) > 0),
        object_id TEXT NOT NULL CHECK(length(object_id) > 0),
        object_version INTEGER NOT NULL CHECK(object_version > 0),
        decision TEXT NOT NULL CHECK(decision IN ('APPROVE', 'REJECT', 'REVOKE', 'REQUEST_CHANGES')),
        diff_sha256 TEXT NOT NULL CHECK(length(diff_sha256) = 64),
        approver_role TEXT NOT NULL CHECK(length(approver_role) > 0),
        approval_request_id TEXT,
        decided_at TEXT NOT NULL CHECK(length(decided_at) > 0)
    )
    """,
    """
    CREATE TABLE wiki_revisions (
        wiki_id TEXT NOT NULL CHECK(length(wiki_id) > 0),
        revision INTEGER NOT NULL CHECK(revision > 0),
        slug TEXT NOT NULL CHECK(length(slug) > 0),
        title TEXT NOT NULL CHECK(length(title) > 0),
        body_object_ref TEXT NOT NULL CHECK(length(body_object_ref) > 0),
        body_object_size_bytes INTEGER NOT NULL CHECK(body_object_size_bytes >= 0),
        body_object_media_type TEXT NOT NULL CHECK(length(body_object_media_type) > 0),
        body_sha256 TEXT NOT NULL CHECK(length(body_sha256) = 64),
        base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
        diff_kind TEXT NOT NULL CHECK(diff_kind IN ('ADD', 'CORRECT', 'PARALLEL_DISAGREEMENT', 'SUPERSEDE', 'EXPIRE')),
        diff_object_ref TEXT NOT NULL CHECK(length(diff_object_ref) > 0),
        diff_object_size_bytes INTEGER NOT NULL CHECK(diff_object_size_bytes >= 0),
        diff_object_media_type TEXT NOT NULL CHECK(length(diff_object_media_type) > 0),
        diff_sha256 TEXT NOT NULL CHECK(length(diff_sha256) = 64),
        review_status TEXT NOT NULL CHECK(review_status IN ('DRAFT', 'PREPARED', 'ACTIVE', 'SUPERSEDED', 'REVOKED')),
        review_due_at TEXT,
        approval_request_id TEXT,
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(wiki_id, revision),
        UNIQUE(slug, revision),
        CHECK(review_status = 'DRAFT' OR approval_request_id IS NOT NULL)
    )
    """,
    """
    CREATE UNIQUE INDEX idx_wiki_one_active
    ON wiki_revisions(wiki_id) WHERE review_status = 'ACTIVE'
    """,
    """
    CREATE TABLE wiki_revision_claims (
        wiki_id TEXT NOT NULL,
        wiki_revision INTEGER NOT NULL,
        section_key TEXT NOT NULL CHECK(length(section_key) > 0),
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        stance TEXT NOT NULL CHECK(stance IN ('SUPPORT', 'OPPOSE', 'CONTEXT')),
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        PRIMARY KEY(wiki_id, wiki_revision, section_key, claim_id, claim_version),
        FOREIGN KEY(wiki_id, wiki_revision)
            REFERENCES wiki_revisions(wiki_id, revision) ON DELETE RESTRICT,
        FOREIGN KEY(claim_id, claim_version)
            REFERENCES claims(claim_id, version) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE artifact_versions (
        artifact_id TEXT NOT NULL CHECK(length(artifact_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        artifact_kind TEXT NOT NULL CHECK(length(artifact_kind) > 0),
        source_catalog_version INTEGER NOT NULL CHECK(source_catalog_version >= 0),
        metadata_sha256 TEXT NOT NULL CHECK(length(metadata_sha256) = 64),
        manifest_id TEXT,
        state TEXT NOT NULL CHECK(state IN ('CURRENT', 'STALE', 'REBUILD_QUEUED', 'RETIRED')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(artifact_id, version)
    )
    """,
    """
    CREATE TABLE artifact_dependencies (
        upstream_type TEXT NOT NULL CHECK(length(upstream_type) > 0),
        upstream_id TEXT NOT NULL CHECK(length(upstream_id) > 0),
        upstream_version INTEGER NOT NULL CHECK(upstream_version > 0),
        downstream_artifact_id TEXT NOT NULL,
        downstream_artifact_version INTEGER NOT NULL,
        dependency_kind TEXT NOT NULL CHECK(length(dependency_kind) > 0),
        PRIMARY KEY(upstream_type, upstream_id, upstream_version, downstream_artifact_id, downstream_artifact_version),
        FOREIGN KEY(downstream_artifact_id, downstream_artifact_version)
            REFERENCES artifact_versions(artifact_id, version) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE provenance_edges (
        from_type TEXT NOT NULL CHECK(length(from_type) > 0),
        from_id TEXT NOT NULL CHECK(length(from_id) > 0),
        from_version INTEGER NOT NULL CHECK(from_version > 0),
        relation TEXT NOT NULL CHECK(length(relation) > 0),
        to_type TEXT NOT NULL CHECK(length(to_type) > 0),
        to_id TEXT NOT NULL CHECK(length(to_id) > 0),
        to_version INTEGER NOT NULL CHECK(to_version > 0),
        derivation_rule_ref_json TEXT NOT NULL CHECK(length(derivation_rule_ref_json) > 0),
        source_client_ids_json TEXT NOT NULL DEFAULT '[]' CHECK(length(source_client_ids_json) > 0),
        source_case_ids_json TEXT NOT NULL DEFAULT '[]' CHECK(length(source_case_ids_json) > 0),
        PRIMARY KEY(from_type, from_id, from_version, relation, to_type, to_id, to_version),
        CHECK(NOT (from_type = to_type AND from_id = to_id AND from_version = to_version))
    )
    """,
    """
    CREATE TABLE rebuild_queue (
        queue_id TEXT PRIMARY KEY CHECK(length(queue_id) > 0),
        upstream_type TEXT NOT NULL CHECK(length(upstream_type) > 0),
        upstream_id TEXT NOT NULL CHECK(length(upstream_id) > 0),
        catalog_version INTEGER NOT NULL CHECK(catalog_version >= 0),
        required_outputs_json TEXT NOT NULL CHECK(length(required_outputs_json) > 0),
        reason TEXT NOT NULL CHECK(length(reason) > 0),
        state TEXT NOT NULL CHECK(state IN ('PENDING', 'CLAIMED', 'COMPLETED')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        UNIQUE(upstream_type, upstream_id, catalog_version)
    )
    """,
    """
    CREATE TABLE security_invalidation_events (
        upstream_type TEXT NOT NULL CHECK(length(upstream_type) > 0),
        upstream_id TEXT NOT NULL CHECK(length(upstream_id) > 0),
        catalog_version INTEGER NOT NULL CHECK(catalog_version >= 0),
        event_kind TEXT NOT NULL CHECK(event_kind IN ('AUTHORIZATION', 'TOMBSTONE')),
        created_at TEXT NOT NULL CHECK(length(created_at) > 0),
        PRIMARY KEY(upstream_type, upstream_id, catalog_version, event_kind)
    )
    """,
    """
    CREATE TABLE knowledge_catalog_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        catalog_version INTEGER NOT NULL CHECK(catalog_version >= 0),
        authorization_epoch INTEGER NOT NULL CHECK(authorization_epoch >= 0),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0)
    )
    """,
    "INSERT INTO knowledge_catalog_state(singleton, catalog_version, authorization_epoch, tombstone_epoch) VALUES (1, 0, 0, 0)",
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the complete knowledge schema inside the migration transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
