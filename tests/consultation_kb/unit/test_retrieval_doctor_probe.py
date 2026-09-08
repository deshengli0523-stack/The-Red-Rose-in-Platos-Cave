from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.operations.doctor_probes import RetrievalArtifactDiagnosticProbe
from consultation_kb.retrieval.embeddings import DeterministicFakeEmbedder
from consultation_kb.retrieval.evidence_pack import ArtifactVersionMismatch
from consultation_kb.retrieval.lexical_builder import (
    LexicalDocument,
    LexicalIndexBuilder,
)
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorDocument,
)
from tests.consultation_kb.retrieval_support import (
    candidate,
    derived_builder_input,
    model_descriptor,
)


class _Binding:
    def __init__(self, paths: dict[str, Path] | None = None) -> None:
        self._paths = {} if paths is None else paths
        self.verify_count = 0

    def path_for(self, role: str) -> Path:
        return self._paths[role]

    def verify_current(self) -> object:
        self.verify_count += 1
        return object()


class _ActiveSet:
    def __init__(
        self,
        *,
        lexical: _Binding,
        vector: _Binding,
    ) -> None:
        self.wiki_index = _Binding()
        self.knowledge_registry = _Binding()
        self.lexical = lexical
        self.vector = vector
        self.graph = _Binding()

    def bindings(self) -> tuple[_Binding, ...]:
        return (
            self.wiki_index,
            self.knowledge_registry,
            self.lexical,
            self.vector,
            self.graph,
        )


def _config(tmp_path: Path) -> AppConfig:
    repo = tmp_path / "repo"
    vault = tmp_path / "vault"
    repo.mkdir()
    (repo / ".git").mkdir()
    vault.mkdir()
    return AppConfig.from_values(repo, vault)


def _fixed_database(config: AppConfig) -> Path:
    global_root = config.vault_root / "global"
    global_root.mkdir()
    database = global_root / "catalog.sqlite3"
    sqlite3.connect(database).close()
    return database


def _artifacts(tmp_path: Path) -> tuple[AppConfig, _ActiveSet]:
    config = _config(tmp_path)
    _fixed_database(config)
    build_root = tmp_path / "build"
    build_root.mkdir()
    text = "active exact text"
    value = candidate(1201, text=text)

    lexical_path = build_root / "lexical.sqlite3"
    lexical_manifest = LexicalIndexBuilder().build(
        (LexicalDocument(candidate=value, text=text),),
        lexical_path,
        builder_input=derived_builder_input(
            "lexical", value, source_catalog_version=9
        ),
    )
    lexical_manifest_path = build_root / "lexical-manifest.json"
    lexical_manifest_path.write_text(
        lexical_manifest.model_dump_json(),
        encoding="utf-8",
    )

    descriptor = model_descriptor(query_prompt="", document_prompt="")
    embedder = DeterministicFakeEmbedder(
        descriptor,
        {text: np.asarray([1.0, 0.0], dtype=np.float32)},
    )
    vector_directory = build_root / "vector"
    vector_value = value.model_copy(update={"channel": "vector"})
    ExactVectorIndexBuilder(embedder).build(
        (VectorDocument(candidate=vector_value, text=text),),
        vector_directory,
        builder_input=derived_builder_input(
            "vector", vector_value, source_catalog_version=9
        ),
    )
    return config, _ActiveSet(
        lexical=_Binding(
            {
                "lexical_build_manifest": lexical_manifest_path,
                "lexical_index": lexical_path,
            }
        ),
        vector=_Binding(
            {
                "vector_build_manifest": vector_directory
                / "vector-manifest.json",
                "vector_metadata": vector_directory / "vector-meta.sqlite3",
                "vector_shard": vector_directory / "vectors.npy",
            }
        ),
    )


def _install_discovery(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: AppConfig,
    result: _ActiveSet | BaseException,
) -> None:
    expected_database = config.vault_root / "global" / "catalog.sqlite3"
    expected_scope = config.vault_root / "global"

    class _Discovery:
        def __init__(self, connection: sqlite3.Connection, store: object) -> None:
            database = Path(
                str(connection.execute("PRAGMA database_list").fetchone()[2])
            )
            assert database.resolve() == expected_database.resolve()
            assert getattr(store, "_scope_root") == expected_scope

        def discover_current_set(self) -> _ActiveSet | None:
            if isinstance(result, BaseException):
                raise result
            return result

    monkeypatch.setattr(
        "consultation_kb.operations.doctor_probes.ActiveRetrievalArtifactDiscovery",
        _Discovery,
    )


def test_retrieval_doctor_uses_fixed_vault_discovery_and_verifies_all_five_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, active = _artifacts(tmp_path)
    _install_discovery(monkeypatch, config=config, result=active)
    loaded: list[np.memmap] = []
    original = np.load

    def tracking_load(*args, **kwargs):  # type: ignore[no-untyped-def]
        matrix = original(*args, **kwargs)
        assert isinstance(matrix, np.memmap)
        loaded.append(matrix)
        return matrix

    monkeypatch.setattr("consultation_kb.operations.doctor_probes.np.load", tracking_load)

    result = RetrievalArtifactDiagnosticProbe().run(config)

    assert result.status == "pass"
    assert result.code == "retrieval_artifacts_verified"
    assert result.observed_count == 5
    assert [binding.verify_count for binding in active.bindings()] == [2] * 5
    assert len(loaded) == 1
    assert loaded[0]._mmap.closed is True  # type: ignore[union-attr]


def test_retrieval_doctor_reports_not_applicable_without_fixed_global_database(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    before = tuple(config.vault_root.rglob("*"))

    result = RetrievalArtifactDiagnosticProbe().run(config)

    assert result.status == "pass"
    assert result.code == "retrieval_artifacts_not_applicable"
    assert result.observed_count == 0
    assert tuple(config.vault_root.rglob("*")) == before


def test_retrieval_doctor_fails_closed_on_partial_or_mixed_active_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _fixed_database(config)
    _install_discovery(
        monkeypatch,
        config=config,
        result=ArtifactVersionMismatch(),
    )

    result = RetrievalArtifactDiagnosticProbe().run(config)

    assert result.status == "fail"
    assert result.code == "retrieval_artifacts_invalid"


def test_retrieval_doctor_rejects_runtime_vector_dimension_drift_and_closes_mmap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, active = _artifacts(tmp_path)
    _install_discovery(monkeypatch, config=config, result=active)
    wrong_matrix = tmp_path / "wrong-dimension.bin"
    np.asarray([[1.0, 0.0, 0.0]], dtype=np.float32).tofile(wrong_matrix)
    loaded: list[np.memmap] = []

    def wrong_load(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        matrix = np.memmap(
            wrong_matrix,
            dtype=np.float32,
            mode="r",
            shape=(1, 3),
        )
        loaded.append(matrix)
        return matrix

    monkeypatch.setattr("consultation_kb.operations.doctor_probes.np.load", wrong_load)

    result = RetrievalArtifactDiagnosticProbe().run(config)

    assert result.status == "fail"
    assert result.code == "retrieval_artifacts_invalid"
    assert loaded[0]._mmap.closed is True  # type: ignore[union-attr]


def test_retrieval_doctor_rejects_vector_cas_byte_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, active = _artifacts(tmp_path)
    _install_discovery(monkeypatch, config=config, result=active)
    vector_path = active.vector.path_for("vector_shard")
    vector_path.write_bytes(vector_path.read_bytes() + b"tamper")

    result = RetrievalArtifactDiagnosticProbe().run(config)

    assert result.status == "fail"
    assert result.code == "retrieval_artifacts_invalid"


def test_retrieval_doctor_does_not_accept_external_artifact_paths() -> None:
    with pytest.raises(TypeError):
        RetrievalArtifactDiagnosticProbe(object())  # type: ignore[call-arg]
