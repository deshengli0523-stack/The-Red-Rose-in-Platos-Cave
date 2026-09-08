"""Schema for one staged immutable lexical SQLite artifact."""

from __future__ import annotations

import sqlite3


SCHEMA_VERSION = "consultation_lexical_v2"


def create(connection: sqlite3.Connection) -> None:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("SQLITE_CONNECTION_REQUIRED")
    connection.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE lexical_metadata(
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL CHECK(json_valid(value_json))
        );
        CREATE TABLE lexical_documents(
            row_id TEXT PRIMARY KEY CHECK(length(row_id) = 64),
            evidence_id TEXT NOT NULL,
            evidence_version INTEGER NOT NULL CHECK(evidence_version > 0),
            evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
            content_object_id TEXT NOT NULL,
            content_version INTEGER NOT NULL CHECK(content_version > 0),
            content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
            candidate_json TEXT NOT NULL CHECK(json_valid(candidate_json)),
            row_sha256 TEXT NOT NULL CHECK(length(row_sha256) = 64),
            UNIQUE(
                evidence_id,
                evidence_version,
                evidence_sha256,
                content_object_id,
                content_version,
                content_sha256
            )
        );
        CREATE TABLE lexical_provenance(
            row_id TEXT PRIMARY KEY
                REFERENCES lexical_documents(row_id) ON DELETE RESTRICT,
            provenance_sha256 TEXT NOT NULL CHECK(length(provenance_sha256) = 64)
        );
        CREATE VIRTUAL TABLE lexical_word_fts USING fts5(
            row_id UNINDEXED,
            evidence_id UNINDEXED,
            tokens,
            tokenize = 'unicode61 remove_diacritics 0'
        );
        CREATE VIRTUAL TABLE lexical_char_fts USING fts5(
            row_id UNINDEXED,
            evidence_id UNINDEXED,
            tokens,
            tokenize = 'unicode61 remove_diacritics 0'
        );
        """
    )


__all__ = ["SCHEMA_VERSION", "create"]
