from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import consultation_kb.models.importer as importer_module
import consultation_kb.models.model_lock as model_lock_module
from consultation_kb.models.importer import (
    LocalRepositorySnapshot,
    ModelImportError,
    ModelImporter,
)
from consultation_kb.models.model_lock import (
    ModelLockError,
    RuntimeLibraryVersions,
    load_runtime_model_manifest,
    load_tracked_model_spec,
    write_runtime_model_manifest_atomic,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"
REVISION = "a" * 40
VERSIONS = RuntimeLibraryVersions(
    sentence_transformers_version="5.6.0",
    transformers_version="4.57.0",
    tokenizer_version="0.22.0",
)


def _snapshot(tmp_path: Path) -> LocalRepositorySnapshot:
    source = tmp_path / "fake-repository"
    (source / "weights").mkdir(parents=True)
    (source / "config.json").write_text('{"model_type":"fake"}', encoding="utf-8")
    (source / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted for this synthetic fixture.",
        encoding="utf-8",
    )
    (source / "tokenizer.json").write_text('{"version":"1.0"}', encoding="utf-8")
    (source / "weights" / "model.safetensors").write_bytes(b"fake weights")
    return LocalRepositorySnapshot(
        directory=source,
        repo="BAAI/bge-m3",
        revision=REVISION,
        license_id="mit",
    )


def _importer(tmp_path: Path) -> tuple[ModelImporter, Path, Path]:
    artifact_root = (tmp_path / "vault" / "models").resolve()
    manifest_path = (
        tmp_path / "repository-state" / ".consultation-models" / "runtime-manifest.json"
    ).resolve()
    importer = ModelImporter(
        artifact_root=artifact_root,
        runtime_manifest_path=manifest_path,
        candidates=load_tracked_model_spec(TRACKED_MODELS),
    )
    return importer, artifact_root, manifest_path


def test_fake_local_repository_import_is_byte_complete_and_idempotent(
    tmp_path: Path,
) -> None:
    importer, artifact_root, manifest_path = _importer(tmp_path)
    snapshot = _snapshot(tmp_path)

    first = importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)
    second = importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert first == second
    assert len(first.models) == 1
    record = first.models[0]
    assert record.revision == REVISION
    assert record.repo == snapshot.repo
    assert record.license_id == "mit"
    assert record.descriptor.model_files == record.files
    assert record.descriptor_sha256 == record.descriptor.id
    assert {item.relative_path for item in record.files} == {
        "LICENSE",
        "config.json",
        "tokenizer.json",
        "weights/model.safetensors",
    }
    assert record.load_policy.local_files_only is True
    assert record.load_policy.trust_remote_code is False
    assert not list(artifact_root.glob(".model-import-*"))
    assert (
        load_runtime_model_manifest(
            manifest_path,
            candidates=load_tracked_model_spec(TRACKED_MODELS),
            artifact_root=artifact_root,
        )
        == first
    )
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert raw["models"][0]["load_policy"] == {
        "hf_hub_offline": "1",
        "local_files_only": True,
        "transformers_offline": "1",
        "trust_remote_code": False,
    }


@pytest.mark.parametrize(
    ("replacement", "expected_code"),
    (
        ({"repo": "BAAI/bge-small-zh-v1.5"}, "MODEL_IMPORT_IDENTITY_MISMATCH"),
        ({"license_id": "apache-2.0"}, "MODEL_IMPORT_IDENTITY_MISMATCH"),
        ({"revision": "main"}, "MODEL_IMPORT_REVISION_INVALID"),
        ({"revision": "A" * 40}, "MODEL_IMPORT_REVISION_INVALID"),
    ),
)
def test_fake_import_rejects_unpinned_or_mismatched_identity(
    tmp_path: Path,
    replacement: dict[str, str],
    expected_code: str,
) -> None:
    importer, _artifact_root, manifest_path = _importer(tmp_path)
    snapshot = replace(_snapshot(tmp_path), **replacement)

    with pytest.raises(ModelImportError) as caught:
        importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert caught.value.code == expected_code
    assert not manifest_path.exists()


def test_runtime_load_rejects_directory_file_drift(tmp_path: Path) -> None:
    importer, artifact_root, manifest_path = _importer(tmp_path)
    manifest = importer.import_snapshot(
        "bge_m3", _snapshot(tmp_path), versions=VERSIONS
    )
    target = artifact_root / Path(manifest.models[0].artifact_relpath)
    (target / "unexpected.bin").write_bytes(b"drift")

    with pytest.raises(ModelLockError) as caught:
        load_runtime_model_manifest(
            manifest_path,
            candidates=load_tracked_model_spec(TRACKED_MODELS),
            artifact_root=artifact_root,
        )

    assert caught.value.code == "MODEL_ARTIFACT_FILES_MISMATCH"


def test_fake_import_rejects_missing_or_mismatched_license_material(
    tmp_path: Path,
) -> None:
    importer, _artifact_root, manifest_path = _importer(tmp_path)
    snapshot = _snapshot(tmp_path)
    (snapshot.directory / "LICENSE").write_text(
        "Apache License\nVersion 2.0",
        encoding="utf-8",
    )

    with pytest.raises(ModelImportError) as caught:
        importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert caught.value.code == "MODEL_IMPORT_LICENSE_MISMATCH"
    assert not manifest_path.exists()


def test_import_rechecks_materialized_license_after_source_toctou(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer, _artifact_root, manifest_path = _importer(tmp_path)
    snapshot = _snapshot(tmp_path)
    original_verify = importer_module._verify_license_material
    source_verified = False

    def mutate_after_source_license_check(
        root: Path,
        *,
        repo: str,
        revision: str,
        expected_license: str,
    ) -> None:
        nonlocal source_verified
        original_verify(
            root,
            repo=repo,
            revision=revision,
            expected_license=expected_license,
        )
        if root == snapshot.directory.resolve() and not source_verified:
            source_verified = True
            (root / "LICENSE").write_text(
                "Apache License\nVersion 2.0\nMutated after initial verification.",
                encoding="utf-8",
            )

    monkeypatch.setattr(
        importer_module,
        "_verify_license_material",
        mutate_after_source_license_check,
    )

    with pytest.raises(ModelImportError) as caught:
        importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert source_verified is True
    assert caught.value.code == "MODEL_IMPORT_LICENSE_MISMATCH"
    assert not manifest_path.exists()


def test_import_rechecks_destination_tree_before_manifest_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer, _artifact_root, manifest_path = _importer(tmp_path)
    snapshot = _snapshot(tmp_path)
    original_materialize = importer._materialize

    def drift_after_materialize(
        source: Path,
        destination: Path,
        files: tuple[object, ...],
    ) -> None:
        original_materialize(source, destination, files)  # type: ignore[arg-type]
        (destination / "post-copy-drift.bin").write_bytes(b"drift")

    monkeypatch.setattr(importer, "_materialize", drift_after_materialize)

    with pytest.raises(ModelImportError) as caught:
        importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert caught.value.code == "MODEL_IMPORT_COPY_MISMATCH"
    assert not manifest_path.exists()


def test_runtime_load_rejects_descriptor_drift(tmp_path: Path) -> None:
    importer, artifact_root, manifest_path = _importer(tmp_path)
    importer.import_snapshot("bge_m3", _snapshot(tmp_path), versions=VERSIONS)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["models"][0]["descriptor"]["query_prompt"] = "drift"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ModelLockError) as caught:
        load_runtime_model_manifest(
            manifest_path,
            candidates=load_tracked_model_spec(TRACKED_MODELS),
            artifact_root=artifact_root,
        )

    assert caught.value.code == "MODEL_RUNTIME_MANIFEST_INVALID"


@pytest.mark.parametrize("drift", ("revision", "file_hash", "credential"))
def test_runtime_load_rejects_unpinned_incomplete_or_sensitive_manifest(
    tmp_path: Path,
    drift: str,
) -> None:
    importer, artifact_root, manifest_path = _importer(tmp_path)
    importer.import_snapshot("bge_m3", _snapshot(tmp_path), versions=VERSIONS)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if drift == "revision":
        raw["models"][0]["revision"] = "main"
    elif drift == "file_hash":
        raw["models"][0]["files"][0]["sha256"] = "0" * 63
    else:
        raw["api_key"] = "not-allowed"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ModelLockError) as caught:
        load_runtime_model_manifest(
            manifest_path,
            candidates=load_tracked_model_spec(TRACKED_MODELS),
            artifact_root=artifact_root,
        )

    assert caught.value.code == "MODEL_RUNTIME_MANIFEST_INVALID"


def test_runtime_load_rejects_license_binding_drift(tmp_path: Path) -> None:
    importer, artifact_root, manifest_path = _importer(tmp_path)
    importer.import_snapshot("bge_m3", _snapshot(tmp_path), versions=VERSIONS)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["models"][0]["license_id"] = "apache-2.0"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ModelLockError) as caught:
        load_runtime_model_manifest(
            manifest_path,
            candidates=load_tracked_model_spec(TRACKED_MODELS),
            artifact_root=artifact_root,
        )

    assert caught.value.code == "MODEL_CANDIDATE_BINDING_MISMATCH"


def test_runtime_manifest_replace_is_atomic_and_keeps_previous_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer, _artifact_root, manifest_path = _importer(tmp_path)
    manifest = importer.import_snapshot(
        "bge_m3", _snapshot(tmp_path), versions=VERSIONS
    )
    previous = manifest_path.read_bytes()

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(model_lock_module.os, "replace", fail_replace)
    with pytest.raises(ModelLockError) as caught:
        write_runtime_model_manifest_atomic(manifest_path, manifest)

    assert caught.value.code == "MODEL_RUNTIME_MANIFEST_WRITE_FAILED"
    assert manifest_path.read_bytes() == previous
    assert not list(manifest_path.parent.glob(".runtime-manifest.json.*.tmp"))


def test_importer_rejects_nonignored_runtime_manifest_path(tmp_path: Path) -> None:
    with pytest.raises(ModelImportError) as caught:
        ModelImporter(
            artifact_root=(tmp_path / "models").resolve(),
            runtime_manifest_path=(tmp_path / "runtime-manifest.json").resolve(),
            candidates=load_tracked_model_spec(TRACKED_MODELS),
        )

    assert caught.value.code == "MODEL_RUNTIME_MANIFEST_PATH_INVALID"
