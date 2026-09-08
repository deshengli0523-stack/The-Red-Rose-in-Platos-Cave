"""Immutable exact-vector shard builder."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

import numpy as np
from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    Sha256Hex,
    StrictModel,
)

from .artifact_contracts import DerivedArtifactBuilderInputV2, retrieval_row_id
from .contracts import CandidateRef, canonical_json_bytes
from .embeddings import Embedder, ModelDescriptor, validate_matrix
from .filters import assert_case_index_text_safe
from .vector_schema import SCHEMA_VERSION, create


class VectorBuildError(RuntimeError):
    def __init__(self, code: str = "VECTOR_BUILD_INVALID") -> None:
        super().__init__(code)


class VectorDocument(StrictModel):
    candidate: CandidateRef
    text: NonEmptyStr

    @model_validator(mode="after")
    def _case_text_boundary(self) -> "VectorDocument":
        assert_case_index_text_safe(self.candidate, self.text)
        return self


class VectorBuildManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    shard_id: Sha256Hex
    model_descriptor: ModelDescriptor
    model_descriptor_id: Sha256Hex
    builder_input_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    source_catalog_version: NonNegativeInt
    target_runtime_epoch: PositiveInt
    vector_filename: Literal["vectors.npy"] = "vectors.npy"
    metadata_filename: Literal["vector-meta.sqlite3"] = "vector-meta.sqlite3"
    vector_sha256: Sha256Hex
    metadata_sha256: Sha256Hex
    row_mapping_sha256: Sha256Hex
    row_content_hashes: tuple[Sha256Hex, ...]
    row_count: NonNegativeInt

    @field_validator("row_content_hashes")
    @classmethod
    def _canonical_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("vector row hashes must be unique")
        return tuple(sorted(value))


class ExactVectorIndexBuilder:
    def __init__(self, embedder: Embedder) -> None:
        self._embedder = embedder

    def build(
        self,
        documents: tuple[VectorDocument, ...],
        output_directory: Path,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> VectorBuildManifest:
        if type(documents) is not tuple or not documents:
            raise VectorBuildError("VECTOR_DOCUMENTS_REQUIRED")
        if not isinstance(output_directory, Path):
            raise TypeError("VECTOR_OUTPUT_PATH_REQUIRED")
        if (
            type(builder_input) is not DerivedArtifactBuilderInputV2
            or builder_input.artifact_kind != "vector"
        ):
            raise VectorBuildError
        source_catalog_version = builder_input.source_catalog_version
        target = output_directory.resolve(strict=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise VectorBuildError("VECTOR_IMMUTABLE_TARGET_EXISTS")
        staging = target.with_name(f".{target.name}.{secrets.token_hex(12)}.stage")
        staging.mkdir()
        connection: sqlite3.Connection | None = None
        try:
            ordered = tuple(
                sorted(
                    documents,
                    key=lambda item: (
                        item.candidate.reference.object_id,
                        item.candidate.reference.version,
                        item.candidate.reference.content_sha256,
                        item.candidate.content_ref.object_id,
                        item.candidate.content_ref.version,
                        item.candidate.content_ref.content_sha256,
                    ),
                )
            )
            try:
                builder_input.retrieval_input_descriptor.verify_candidates(
                    "vector",
                    tuple(document.candidate for document in ordered),
                )
            except (TypeError, ValueError):
                raise VectorBuildError("VECTOR_INPUT_SET_MISMATCH") from None
            ids = [retrieval_row_id(item.candidate) for item in ordered]
            if len(ids) != len(set(ids)) or any(
                item.candidate.filter_binding is not None
                or item.candidate.metadata.review_status != "approved"
                or hashlib.sha256(item.text.encode("utf-8")).hexdigest()
                != item.candidate.content_ref.content_sha256
                or len(item.text.encode("utf-8"))
                != item.candidate.metadata.size_bytes
                for item in ordered
            ):
                raise VectorBuildError
            descriptor = self._embedder.descriptor
            matrix = validate_matrix(
                self._embedder.encode_documents([item.text for item in ordered]),
                descriptor,
                expected_rows=len(ordered),
            )
            shard_id = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "descriptor_id": descriptor.id,
                        "evidence": [
                            {
                                "content_ref": item.candidate.content_ref.model_dump(
                                    mode="json"
                                ),
                                "reference": item.candidate.reference.model_dump(
                                    mode="json"
                                ),
                            }
                            for item in ordered
                        ],
                        "source_catalog_version": source_catalog_version,
                    }
                )
            ).hexdigest()
            vector_path = staging / "vectors.npy"
            with vector_path.open("xb") as stream:
                np.save(stream, matrix, allow_pickle=False)
                stream.flush()
                os.fsync(stream.fileno())
            vector_sha256 = hashlib.sha256(vector_path.read_bytes()).hexdigest()

            metadata_path = staging / "vector-meta.sqlite3"
            connection = sqlite3.connect(metadata_path, isolation_level=None)
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            create(connection)
            connection.execute("BEGIN IMMEDIATE")
            descriptor_json = descriptor.model_dump_json()
            connection.execute(
                "INSERT INTO model_descriptors("
                "model_descriptor_id, descriptor_json, descriptor_sha256) "
                "VALUES (?, ?, ?)",
                (descriptor.id, descriptor_json, descriptor.id),
            )
            connection.execute(
                "INSERT INTO vector_metadata(key, value_json) VALUES (?, ?)",
                (
                    "builder",
                    json.dumps(
                        {
                            "assigned_input_set_sha256": builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                                "vector"
                            ),
                            "builder_input_sha256": builder_input.canonical_sha256,
                            "model_descriptor_id": descriptor.id,
                            "retrieval_input_descriptor_sha256": builder_input.retrieval_input_descriptor.descriptor_sha256,
                            "row_mapping_sha256": builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                                "vector"
                            ),
                            "schema_version": SCHEMA_VERSION,
                            "shard_id": shard_id,
                            "source_catalog_version": source_catalog_version,
                            "target_runtime_epoch": builder_input.target_runtime_epoch,
                            "vector_filename": vector_path.name,
                            "vector_sha256": vector_sha256,
                        },
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            row_hashes: list[str] = []
            for row_index, document in enumerate(ordered):
                candidate = document.candidate
                row_id = retrieval_row_id(candidate)
                candidate_json = candidate.model_dump_json()
                row_sha256 = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "candidate": candidate.model_dump(mode="json"),
                            "row_index": row_index,
                            "shard_id": shard_id,
                        }
                    )
                ).hexdigest()
                provenance_sha256 = hashlib.sha256(
                    canonical_json_bytes(candidate.provenance.model_dump(mode="json"))
                ).hexdigest()
                metadata = candidate.metadata
                connection.execute(
                    "INSERT INTO vector_rows("
                    "row_id, evidence_id, evidence_version, evidence_sha256, "
                    "content_object_id, content_version, shard_id, row_index, "
                    "review_status, valid_from, valid_to, sensitivity, "
                    "allowed_uses_json, provenance_ref, content_sha256, "
                    "model_descriptor_id, candidate_json, row_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row_id,
                        candidate.reference.object_id,
                        candidate.reference.version,
                        candidate.reference.content_sha256,
                        candidate.content_ref.object_id,
                        candidate.content_ref.version,
                        shard_id,
                        row_index,
                        metadata.review_status,
                        _utc(metadata.effective_from),
                        _utc(metadata.effective_to),
                        metadata.sensitivity,
                        json.dumps(sorted(metadata.allowed_uses), separators=(",", ":")),
                        metadata.manifest_ref.model_dump_json(),
                        candidate.content_ref.content_sha256,
                        descriptor.id,
                        candidate_json,
                        row_sha256,
                    ),
                )
                connection.execute(
                    "INSERT INTO vector_provenance(row_id, provenance_sha256) "
                    "VALUES (?, ?)",
                    (row_id, provenance_sha256),
                )
                row_hashes.append(row_sha256)
            connection.execute("COMMIT")
            connection.execute("PRAGMA optimize")
            connection.close()
            connection = None
            metadata_sha256 = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
            manifest = VectorBuildManifest(
                shard_id=shard_id,
                model_descriptor=descriptor,
                model_descriptor_id=descriptor.id,
                builder_input_sha256=builder_input.canonical_sha256,
                retrieval_input_descriptor_sha256=(
                    builder_input.retrieval_input_descriptor.descriptor_sha256
                ),
                assigned_input_set_sha256=(
                    builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                        "vector"
                    )
                ),
                source_catalog_version=source_catalog_version,
                target_runtime_epoch=builder_input.target_runtime_epoch,
                vector_sha256=vector_sha256,
                metadata_sha256=metadata_sha256,
                row_mapping_sha256=(
                    builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                        "vector"
                    )
                ),
                row_content_hashes=tuple(row_hashes),
                row_count=len(ordered),
            )
            manifest_path = staging / "vector-manifest.json"
            with manifest_path.open("xb") as stream:
                payload = manifest.model_dump_json(indent=2).encode("utf-8")
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(staging, target)
            return manifest
        except VectorBuildError:
            raise
        except Exception as exc:
            raise VectorBuildError from exc
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
            if staging.exists():
                shutil.rmtree(staging)


def _utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "ExactVectorIndexBuilder",
    "VectorBuildError",
    "VectorBuildManifest",
    "VectorDocument",
]
