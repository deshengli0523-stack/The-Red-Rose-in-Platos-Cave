"""Exact NumPy retrieval after live allowed-subset intersection."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import cast

import numpy as np
from numpy.typing import NDArray
from pydantic import ValidationError

from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)

from .artifact_contracts import ArtifactBinding, retrieval_row_id
from .contracts import CandidateRef, ScoreComponent
from .embeddings import (
    Embedder,
    EmbeddingContractError,
    ModelDescriptor,
    validate_matrix,
    validate_vector,
)
from .vector_builder import VectorBuildManifest


MatrixLoader = Callable[[Path], NDArray[np.float32]]


class ExactVectorIndexError(RuntimeError):
    def __init__(self, code: str = "VECTOR_INDEX_INVALID") -> None:
        super().__init__(code)


def _default_matrix_loader(path: Path) -> NDArray[np.float32]:
    value = np.load(path, mmap_mode="r", allow_pickle=False)
    return cast(NDArray[np.float32], value)


class ExactVectorRetriever:
    def __init__(
        self,
        artifact_binding: ArtifactBinding,
        *,
        embedder: Embedder,
        matrix_loader: MatrixLoader | None = None,
    ) -> None:
        if type(artifact_binding) is not ArtifactBinding:
            raise TypeError("VECTOR_ARTIFACT_BINDING_REQUIRED")
        if artifact_binding.identity.artifact_key != "vector":
            raise ExactVectorIndexError("ARTIFACT_VERSION_MISMATCH")
        self._initialize(
            metadata_path=artifact_binding.path_for("vector_metadata"),
            vector_path=artifact_binding.path_for("vector_shard"),
            manifest_path=artifact_binding.path_for("vector_build_manifest"),
            artifact_binding=artifact_binding,
            embedder=embedder,
            matrix_loader=matrix_loader,
        )
        self._verify_artifact_binding()

    def _initialize(
        self,
        *,
        metadata_path: Path,
        vector_path: Path,
        manifest_path: Path,
        artifact_binding: ArtifactBinding | None,
        embedder: Embedder,
        matrix_loader: MatrixLoader | None,
    ) -> None:
        paths = (metadata_path, vector_path, manifest_path)
        if any(not isinstance(path, Path) for path in paths):
            raise TypeError("VECTOR_INDEX_PATH_REQUIRED")
        resolved = tuple(path.resolve(strict=True) for path in paths)
        if not all(path.is_file() for path in resolved):
            raise ExactVectorIndexError
        self._metadata_path, self._vector_path, self._manifest_path = resolved
        self._artifact_binding = artifact_binding
        self._embedder = embedder
        self._matrix_loader = matrix_loader or _default_matrix_loader

    @classmethod
    def from_artifact_binding(
        cls,
        artifact_binding: ArtifactBinding,
        *,
        embedder: Embedder,
        matrix_loader: MatrixLoader | None = None,
    ) -> "ExactVectorRetriever":
        return cls(
            artifact_binding,
            embedder=embedder,
            matrix_loader=matrix_loader,
        )

    @classmethod
    def _from_unbound_directory_for_test(
        cls,
        index_directory: Path,
        *,
        embedder: Embedder,
        matrix_loader: MatrixLoader | None = None,
    ) -> "ExactVectorRetriever":
        if not isinstance(index_directory, Path):
            raise TypeError("VECTOR_INDEX_PATH_REQUIRED")
        directory = index_directory.resolve(strict=True)
        instance = cls.__new__(cls)
        instance._initialize(
            metadata_path=directory / "vector-meta.sqlite3",
            vector_path=directory / "vectors.npy",
            manifest_path=directory / "vector-manifest.json",
            artifact_binding=None,
            embedder=embedder,
            matrix_loader=matrix_loader,
        )
        return instance

    @property
    def artifact_binding(self) -> ArtifactBinding | None:
        return self._artifact_binding

    def _verify_artifact_binding(self) -> None:
        if self._artifact_binding is None:
            return
        try:
            self._artifact_binding.verify_current()
        except Exception:
            raise ExactVectorIndexError("ARTIFACT_VERSION_MISMATCH") from None

    def search(
        self,
        query: str,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        del scope
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("VECTOR_LIMIT_INVALID")
        self._verify_artifact_binding()
        try:
            return self._search(query, authority_snapshot, limit=limit)
        finally:
            self._verify_artifact_binding()

    def _search(
        self,
        query: str,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        try:
            manifest = VectorBuildManifest.model_validate_json(
                self._manifest_path.read_text(encoding="utf-8"),
                strict=True,
            )
            descriptor = self._embedder.descriptor
            if manifest.model_descriptor_id != descriptor.id:
                raise ExactVectorIndexError("VECTOR_MODEL_DESCRIPTOR_MISMATCH")
            if hashlib.sha256(self._metadata_path.read_bytes()).hexdigest() != (
                manifest.metadata_sha256
            ):
                raise ExactVectorIndexError("VECTOR_METADATA_HASH_MISMATCH")
            rows = self._allowed_rows(authority_snapshot, descriptor)
            if not rows:
                return ()
            # Only after the metadata intersection is known do we touch the
            # vector shard or invoke the query model.
            if hashlib.sha256(self._vector_path.read_bytes()).hexdigest() != (
                manifest.vector_sha256
            ):
                raise ExactVectorIndexError("VECTOR_SHARD_HASH_MISMATCH")
            query_vector = validate_vector(
                self._embedder.encode_query(query),
                descriptor,
            )
            matrix = self._matrix_loader(self._vector_path)
            if (
                not isinstance(matrix, np.ndarray)
                or matrix.dtype != np.float32
                or matrix.ndim != 2
                or matrix.shape[1] != descriptor.dimension
                or matrix.shape[0] != manifest.row_count
            ):
                raise ExactVectorIndexError
            row_indices = np.asarray([row[0] for row in rows], dtype=np.intp)
            allowed_matrix = validate_matrix(
                np.asarray(matrix[row_indices], dtype=np.float32),
                descriptor,
                expected_rows=len(rows),
            )
            scores = allowed_matrix @ query_vector
            ranked = sorted(
                zip(rows, scores.tolist(), strict=True),
                key=lambda item: (-float(item[1]), item[0][1],),
            )[:limit]
            return tuple(
                candidate.model_copy(
                    update={
                        "score": float(score),
                        "score_components": (
                            ScoreComponent(
                                channel="vector_exact",
                                rank=rank,
                                score=float(score),
                            ),
                        ),
                    }
                )
                for rank, ((_row_index, _row_id, candidate), score) in enumerate(
                    ranked,
                    start=1,
                )
            )
        except ExactVectorIndexError:
            raise
        except (
            OSError,
            sqlite3.Error,
            ValidationError,
            EmbeddingContractError,
            TypeError,
            ValueError,
        ):
            raise ExactVectorIndexError from None

    def _allowed_rows(
        self,
        authority_snapshot: AuthoritativeFilterSnapshot,
        descriptor: ModelDescriptor,
    ) -> tuple[tuple[int, str, CandidateRef], ...]:
        connection = sqlite3.connect(
            f"{self._metadata_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=5.0,
        )
        try:
            connection.execute("PRAGMA query_only = OFF")
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute(
                "CREATE TEMP TABLE allowed_refs("
                "evidence_id TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            connection.executemany(
                "INSERT INTO allowed_refs(evidence_id) VALUES (?)",
                ((identifier,) for identifier in authority_snapshot.allowed_ref_ids),
            )
            descriptor_row = connection.execute(
                "SELECT descriptor_json, descriptor_sha256 "
                "FROM model_descriptors WHERE model_descriptor_id = ?",
                (descriptor.id,),
            ).fetchone()
            if descriptor_row is None or str(descriptor_row[1]) != descriptor.id:
                raise ExactVectorIndexError("VECTOR_MODEL_DESCRIPTOR_MISMATCH")
            stored_descriptor = ModelDescriptor.model_validate_json(
                str(descriptor_row[0]), strict=True
            )
            if stored_descriptor != descriptor:
                raise ExactVectorIndexError("VECTOR_MODEL_DESCRIPTOR_MISMATCH")
            rows = connection.execute(
                "SELECT vector.row_index, vector.row_id, vector.evidence_id, "
                "vector.evidence_version, vector.evidence_sha256, "
                "vector.content_object_id, vector.content_version, "
                "vector.content_sha256, vector.candidate_json "
                "FROM vector_rows AS vector "
                "JOIN temp.allowed_refs AS allowed "
                "  ON allowed.evidence_id = vector.evidence_id "
                "WHERE vector.model_descriptor_id = ? "
                "ORDER BY vector.row_index",
                (descriptor.id,),
            ).fetchall()
            result: list[tuple[int, str, CandidateRef]] = []
            for row in rows:
                candidate = CandidateRef.model_validate_json(str(row[8]), strict=True)
                if (
                    candidate.reference.object_id != str(row[2])
                    or candidate.reference.version != int(row[3])
                    or candidate.reference.content_sha256 != str(row[4])
                    or candidate.content_ref.object_id != str(row[5])
                    or candidate.content_ref.version != int(row[6])
                    or candidate.content_ref.content_sha256 != str(row[7])
                    or retrieval_row_id(candidate) != str(row[1])
                    or candidate.filter_binding is not None
                ):
                    raise ExactVectorIndexError
                result.append((int(row[0]), str(row[1]), candidate))
            return tuple(result)
        finally:
            connection.close()


__all__ = ["ExactVectorIndexError", "ExactVectorRetriever", "MatrixLoader"]
