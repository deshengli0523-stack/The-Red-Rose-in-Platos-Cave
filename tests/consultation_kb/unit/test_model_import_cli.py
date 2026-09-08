from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from consultation_kb import cli
import consultation_kb.models.importer as importer_module
import consultation_kb.models.huggingface_resolver as resolver_module
from consultation_kb.models.importer import LocalRepositorySnapshot
from consultation_kb.models.model_lock import (
    load_runtime_model_manifest,
    load_tracked_model_spec,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"
REVISION = "1" * 40


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    (repository / "models").mkdir()
    shutil.copyfile(TRACKED_MODELS, repository / "models" / TRACKED_MODELS.name)
    return repository.resolve()


def _snapshot(tmp_path: Path) -> Path:
    snapshot = tmp_path / "snapshot"
    (snapshot / "weights").mkdir(parents=True)
    (snapshot / "config.json").write_text("{}", encoding="utf-8")
    (snapshot / "tokenizer.json").write_text("{}", encoding="utf-8")
    (snapshot / "weights" / "model.safetensors").write_bytes(b"synthetic")
    (snapshot / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted for this synthetic fixture.",
        encoding="utf-8",
    )
    return snapshot.resolve()


def _install_fake_version_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    versions = {
        "sentence-transformers": "5.6.0",
        "transformers": "4.57.0",
        "tokenizers": "0.22.0",
    }
    monkeypatch.setattr(importer_module.metadata, "version", versions.__getitem__)


def test_models_import_cli_registers_verified_local_snapshot_without_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    snapshot = _snapshot(tmp_path)
    vault = (tmp_path / "vault").resolve()
    _install_fake_version_probe(monkeypatch)

    exit_code = cli.main(
        (
            "models-import",
            "--repo",
            "BAAI/bge-m3",
            "--source",
            str(snapshot),
            "--revision",
            REVISION,
            "--license",
            "mit",
            "--repo-root",
            str(repository),
            "--vault-root",
            str(vault),
            "--json",
        )
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload == {
        "descriptor_sha256": payload["descriptor_sha256"],
        "model_id": "bge_m3",
        "ok": True,
        "registered_model_count": 1,
        "repo": "BAAI/bge-m3",
        "revision": REVISION,
        "role": "embedding",
        "runtime_manifest_sha256": payload["runtime_manifest_sha256"],
    }
    assert len(payload["descriptor_sha256"]) == 64
    assert len(payload["runtime_manifest_sha256"]) == 64
    assert str(repository) not in captured.out
    assert str(snapshot) not in captured.out
    assert str(vault) not in captured.out

    candidates = load_tracked_model_spec(repository / "models" / TRACKED_MODELS.name)
    manifest = load_runtime_model_manifest(
        repository / ".consultation-models" / "runtime-manifest.json",
        candidates=candidates,
        artifact_root=vault / "models",
    )
    assert manifest.models[0].load_policy.local_files_only is True
    assert manifest.models[0].load_policy.trust_remote_code is False


@pytest.mark.parametrize("revision", ("main", "A" * 40, "1" * 39))
def test_models_import_cli_rejects_unpinned_revision_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    revision: str,
) -> None:
    repository = _repository(tmp_path)
    snapshot = _snapshot(tmp_path)
    vault = (tmp_path / "vault").resolve()
    _install_fake_version_probe(monkeypatch)

    assert (
        cli.main(
            (
                "models-import",
                "--repo",
                "BAAI/bge-m3",
                "--source",
                str(snapshot),
                "--revision",
                revision,
                "--license",
                "mit",
                "--repo-root",
                str(repository),
                "--vault-root",
                str(vault),
                "--json",
            )
        )
        == 2
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "code": "MODEL_IMPORT_REVISION_INVALID",
        "ok": False,
    }
    assert captured.err == (
        "consultation-kb models-import: MODEL_IMPORT_REVISION_INVALID\n"
    )
    assert not (repository / ".consultation-models").exists()
    assert not vault.exists()


def test_models_import_resolve_main_uses_explicit_resolver_without_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    snapshot = _snapshot(tmp_path)
    vault = (tmp_path / "vault").resolve()
    calls: list[tuple[str, str]] = []
    _install_fake_version_probe(monkeypatch)

    class _FakeResolver:
        def __init__(
            self,
            *,
            candidates: object,
            temporary_root: Path,
        ) -> None:
            del candidates
            calls.append(("init", "tracked"))
            temporary_root.resolve().relative_to(vault / "models")
            assert temporary_root.name == ".huggingface-staging"

        @contextmanager
        def resolve_main(self, repo: str) -> Iterator[LocalRepositorySnapshot]:
            calls.append(("resolve_main", repo))
            yield LocalRepositorySnapshot(
                directory=snapshot,
                repo=repo,
                revision=REVISION,
                license_id="mit",
            )

    monkeypatch.setattr(
        resolver_module,
        "HuggingFaceSnapshotResolver",
        _FakeResolver,
    )

    assert (
        cli.main(
            (
                "models-import",
                "--repo",
                "BAAI/bge-m3",
                "--resolve-main",
                "--repo-root",
                str(repository),
                "--vault-root",
                str(vault),
                "--json",
            )
        )
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert captured.err == ""
    assert payload["ok"] is True
    assert payload["model_id"] == "bge_m3"
    assert payload["revision"] == REVISION
    assert calls == [
        ("init", "tracked"),
        ("resolve_main", "BAAI/bge-m3"),
    ]
    assert str(repository) not in captured.out
    assert str(snapshot) not in captured.out
    assert str(vault) not in captured.out
    assert "synthetic" not in captured.out


def test_models_import_resolve_main_propagates_fixed_body_free_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    vault = (tmp_path / "vault").resolve()
    _install_fake_version_probe(monkeypatch)

    class _FailingResolver:
        def __init__(
            self,
            *,
            candidates: object,
            temporary_root: Path,
        ) -> None:
            del candidates, temporary_root

        @contextmanager
        def resolve_main(self, repo: str) -> Iterator[LocalRepositorySnapshot]:
            del repo
            raise resolver_module.HuggingFaceResolverError(
                "HF_RESOLVER_METADATA_FAILED"
            )
            yield  # pragma: no cover

    monkeypatch.setattr(
        resolver_module,
        "HuggingFaceSnapshotResolver",
        _FailingResolver,
    )

    assert (
        cli.main(
            (
                "models-import",
                "--repo",
                "BAAI/bge-m3",
                "--resolve-main",
                "--repo-root",
                str(repository),
                "--vault-root",
                str(vault),
                "--json",
            )
        )
        == 2
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "code": "HF_RESOLVER_METADATA_FAILED",
        "ok": False,
    }
    assert captured.err == (
        "consultation-kb models-import: HF_RESOLVER_METADATA_FAILED\n"
    )
    assert str(repository) not in captured.out + captured.err
    assert str(vault) not in captured.out + captured.err


def test_models_import_rejects_mixed_resolver_and_local_snapshot_mode(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    snapshot = _snapshot(tmp_path)

    assert (
        cli.main(
            (
                "models-import",
                "--repo",
                "BAAI/bge-m3",
                "--resolve-main",
                "--source",
                str(snapshot),
                "--repo-root",
                str(repository),
                "--vault-root",
                str((tmp_path / "vault").resolve()),
                "--json",
            )
        )
        == 2
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "code": "MODEL_IMPORT_MODE_CONFLICT",
        "ok": False,
    }
    assert captured.err == (
        "consultation-kb models-import: MODEL_IMPORT_MODE_CONFLICT\n"
    )
