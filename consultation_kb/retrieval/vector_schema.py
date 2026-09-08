"""Metadata schema for one exact NumPy vector shard."""

from __future__ import annotations

import sqlite3


SCHEMA_VERSION = "consultation_exact_vector_v2"


def create(connection: sqlite3.Connection) -> None:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("SQLITE_CONNECTION_REQUIRED")
    connection.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE vector_metadata(
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL CHECK(json_valid(value_json))
        );
        CREATE TABLE model_descriptors(
            model_descriptor_id TEXT PRIMARY KEY CHECK(length(model_descriptor_id) = 64),
            descriptor_json TEXT NOT NULL CHECK(json_valid(descriptor_json)),
            descriptor_sha256 TEXT NOT NULL CHECK(length(descriptor_sha256) = 64)
        );
        CREATE TABLE vector_rows(
            row_id TEXT PRIMARY KEY CHECK(length(row_id) = 64),
            evidence_id TEXT NOT NULL,
            evidence_version INTEGER NOT NULL CHECK(evidence_version > 0),
            evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
            content_object_id TEXT NOT NULL,
            content_version INTEGER NOT NULL CHECK(content_version > 0),
            shard_id TEXT NOT NULL,
            row_index INTEGER NOT NULL UNIQUE CHECK(row_index >= 0),
            review_status TEXT NOT NULL,
            valid_from TEXT,
            valid_to TEXT,
            sensitivity INTEGER NOT NULL CHECK(sensitivity >= 0),
            allowed_uses_json TEXT NOT NULL CHECK(json_valid(allowed_uses_json)),
            provenance_ref TEXT NOT NULL CHECK(json_valid(provenance_ref)),
            content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
            model_descriptor_id TEXT NOT NULL
                REFERENCES model_descriptors(model_descriptor_id) ON DELETE RESTRICT,
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
        CREATE TABLE vector_provenance(
            row_id TEXT PRIMARY KEY
                REFERENCES vector_rows(row_id) ON DELETE RESTRICT,
            provenance_sha256 TEXT NOT NULL CHECK(length(provenance_sha256) = 64)
        );
        """
    )


__all__ = ["SCHEMA_VERSION", "create"]
