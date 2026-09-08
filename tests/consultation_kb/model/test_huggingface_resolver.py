from __future__ import annotations

import builtins
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from consultation_kb.models.huggingface_resolver import (
    HubModelMetadata,
    HuggingFaceResolverError,
    HuggingFaceSnapshotResolver,
)
from consultation_kb.models import huggingface_resolver as resolver_module
from consultation_kb.models.importer import (
    ModelImportError,
    ModelImporter,
)
from consultation_kb.models.model_lock import (
    LICENSE_ATTESTATION_FILENAME,
    RuntimeLibraryVersions,
    load_model_license_attestation,
    load_tracked_model_spec,
)


pytestmark = pytest.mark.model

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"
VERSIONS = RuntimeLibraryVersions(
    sentence_transformers_version="5.6.0",
    transformers_version="4.57.0",
    tokenizer_version="0.22.0",
)
OFFICIAL_CURRENT = (
    (
        "BAAI/bge-m3",
        "5617a9f61b028005a4858fdac845db406aefb181",
        "mit",
    ),
    (
        "BAAI/bge-small-zh-v1.5",
        "7999e1d3359715c523056ef9478215996d62a620",
        "mit",
    ),
    (
        "BAAI/bge-reranker-v2-m3",
        "953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e",
        "apache-2.0",
    ),
    (
        "BAAI/bge-reranker-base",
        "2cfc18c9415c912f9d8155881c133215df768a70",
        "mit",
    ),
)


@dataclass
class _FakeHub:
    repo: str
    revision: str
    license_id: str
    returned_repo: str | None = None
    returned_revision: str | None = None
    returned_license: str | None = None
    wrong_download_path: Path | None = None
    omit_expected_weight: bool = False
    add_alternative_weight: bool = False
    calls: list[tuple[str, str, str]] = field(default_factory=list)
    download_ignore_patterns: list[tuple[str, ...]] = field(default_factory=list)

    def model_info(self, *, repo: str, revision: str) -> HubModelMetadata:
        self.calls.append(("model_info", repo, revision))
        return HubModelMetadata(
            repo=self.repo if self.returned_repo is None else self.returned_repo,
            revision=(
                self.revision
                if self.returned_revision is None
                else self.returned_revision
            ),
            license_id=(
                self.license_id
                if self.returned_license is None
                else self.returned_license
            ),
        )

    def snapshot_download(
        self,
        *,
        repo: str,
        revision: str,
        local_dir: Path,
        ignore_patterns: tuple[str, ...],
    ) -> Path:
        self.calls.append(("snapshot_download", repo, revision))
        self.download_ignore_patterns.append(ignore_patterns)
        local_dir.mkdir(parents=True)
        (local_dir / "config.json").write_text("{}", encoding="utf-8")
        (local_dir / "tokenizer.json").write_text("{}", encoding="utf-8")
        expected_weight = (
            "pytorch_model.bin" if repo == "BAAI/bge-m3" else "model.safetensors"
        )
        if not self.omit_expected_weight:
            (local_dir / expected_weight).write_bytes(b"synthetic")
        if self.add_alternative_weight:
            alternative = (
                "model.safetensors"
                if expected_weight == "pytorch_model.bin"
                else "pytorch_model.bin"
            )
            (local_dir / alternative).write_bytes(b"duplicate")
        (local_dir / ".cache" / "huggingface").mkdir(parents=True)
        (local_dir / ".cache" / "huggingface" / "download.json").write_text(
            "{}",
            encoding="utf-8",
        )
        return (
            local_dir if self.wrong_download_path is None else self.wrong_download_path
        )


def _resolver(tmp_path: Path, hub: _FakeHub) -> HuggingFaceSnapshotResolver:
    temporary_root = tmp_path / "resolver-temp"
    temporary_root.mkdir()
    return HuggingFaceSnapshotResolver(
        candidates=load_tracked_model_spec(TRACKED_MODELS),
        adapter=hub,
        temporary_root=temporary_root,
    )


def test_default_adapter_disables_xet_before_import_and_keeps_cache_in_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HF_HUB_DISABLE_XET", "0")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "0")
    observed_environment: list[tuple[str | None, str | None]] = []
    download_calls: list[dict[str, object]] = []

    class _FakeApi:
        def __init__(self, **_kwargs: object) -> None:
            pass

    def fake_snapshot_download(**kwargs: object) -> str:
        download_calls.append(kwargs)
        return str(kwargs["local_dir"])

    fake_module = SimpleNamespace(
        HfApi=_FakeApi,
        snapshot_download=fake_snapshot_download,
    )
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "huggingface_hub":
            observed_environment.append(
                (
                    os.environ.get("HF_HUB_DISABLE_XET"),
                    os.environ.get("HF_HUB_DISABLE_TELEMETRY"),
                )
            )
            return fake_module
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    adapter = resolver_module._DefaultHuggingFaceHubAdapter()
    staging = tmp_path / "vault" / "models" / ".huggingface-staging" / "run"
    staging.mkdir(parents=True)
    payload = staging / "snapshot"

    returned = adapter.snapshot_download(
        repo="BAAI/bge-m3",
        revision=OFFICIAL_CURRENT[0][1],
        local_dir=payload,
        ignore_patterns=("onnx/**", "openvino/**"),
    )

    assert observed_environment == [("1", "1")]
    assert returned == payload
    assert len(download_calls) == 1
    assert download_calls[0]["local_dir"] == os.fspath(payload)
    assert download_calls[0]["cache_dir"] == os.fspath(staging / ".hub-cache")
    assert (
        Path(str(download_calls[0]["cache_dir"]))
        .resolve()
        .is_relative_to(staging.resolve())
    )


@pytest.mark.parametrize(("repo", "revision", "license_id"), OFFICIAL_CURRENT)
def test_explicit_fake_hub_resolves_pinned_snapshot_and_seals_card_license(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repo: str,
    revision: str,
    license_id: str,
) -> None:
    hub = _FakeHub(repo=repo, revision=revision, license_id=license_id)
    resolver = _resolver(tmp_path, hub)
    original_import = builtins.__import__

    def reject_hub_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "huggingface_hub" or name.startswith("huggingface_hub."):
            raise AssertionError("fake-adapter flow imported huggingface_hub")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_hub_import)
    resolved_directory: Path | None = None
    with resolver.resolve_main(repo) as snapshot:
        resolved_directory = snapshot.directory
        assert snapshot.repo == repo
        assert snapshot.revision == revision
        assert snapshot.license_id == license_id
        assert snapshot.expected_files is not None
        file_names = {item.relative_path for item in snapshot.expected_files}
        assert LICENSE_ATTESTATION_FILENAME in file_names
        assert "LICENSE" not in file_names
        assert not (snapshot.directory / ".cache").exists()
        expected_ignore = ("onnx/**", "openvino/**")
        if repo != "BAAI/bge-m3":
            expected_ignore += ("pytorch_model.bin",)
        assert hub.download_ignore_patterns == [expected_ignore]
        attestation = load_model_license_attestation(
            snapshot.directory / LICENSE_ATTESTATION_FILENAME
        )
        assert (attestation.repo, attestation.revision, attestation.license_id) == (
            repo,
            revision,
            license_id,
        )

        candidates = load_tracked_model_spec(TRACKED_MODELS)
        candidate = candidates.candidate_for_repo(repo)
        importer = ModelImporter(
            artifact_root=(tmp_path / "vault" / "models").resolve(),
            runtime_manifest_path=(
                tmp_path / "state" / ".consultation-models" / "runtime-manifest.json"
            ).resolve(),
            candidates=candidates,
        )
        manifest = importer.import_snapshot(
            candidate.model_id,
            snapshot,
            versions=VERSIONS,
        )
        record = next(
            item for item in manifest.models if item.model_id == candidate.model_id
        )
        assert record.revision == revision
        assert record.license_id == license_id
        assert LICENSE_ATTESTATION_FILENAME in {
            item.relative_path for item in record.files
        }

    assert resolved_directory is not None
    assert not resolved_directory.exists()
    assert hub.calls == [
        ("model_info", repo, "main"),
        ("snapshot_download", repo, revision),
    ]


@pytest.mark.parametrize(
    ("replacement", "expected_code"),
    (
        ({"returned_repo": "BAAI/bge-small-zh-v1.5"}, "HF_RESOLVER_IDENTITY_MISMATCH"),
        ({"returned_revision": "main"}, "HF_RESOLVER_METADATA_INVALID"),
        ({"returned_revision": "A" * 40}, "HF_RESOLVER_METADATA_INVALID"),
        ({"returned_license": "apache-2.0"}, "HF_RESOLVER_IDENTITY_MISMATCH"),
    ),
)
def test_resolver_rejects_unpinned_or_mismatched_model_card_before_download(
    tmp_path: Path,
    replacement: dict[str, str],
    expected_code: str,
) -> None:
    repo, revision, license_id = OFFICIAL_CURRENT[0]
    hub = _FakeHub(repo=repo, revision=revision, license_id=license_id, **replacement)
    resolver = _resolver(tmp_path, hub)

    with pytest.raises(HuggingFaceResolverError) as caught:
        with resolver.resolve_main(repo):
            pytest.fail("invalid metadata must not yield a snapshot")

    assert caught.value.code == expected_code
    assert [call[0] for call in hub.calls] == ["model_info"]
    assert not list((tmp_path / "resolver-temp").iterdir())


def test_resolved_file_drift_is_rejected_before_import(tmp_path: Path) -> None:
    repo, revision, license_id = OFFICIAL_CURRENT[0]
    hub = _FakeHub(repo=repo, revision=revision, license_id=license_id)
    resolver = _resolver(tmp_path, hub)

    with resolver.resolve_main(repo) as snapshot:
        (snapshot.directory / "config.json").write_text(
            '{"drift":true}',
            encoding="utf-8",
        )
        candidates = load_tracked_model_spec(TRACKED_MODELS)
        importer = ModelImporter(
            artifact_root=(tmp_path / "vault" / "models").resolve(),
            runtime_manifest_path=(
                tmp_path / "state" / ".consultation-models" / "runtime-manifest.json"
            ).resolve(),
            candidates=candidates,
        )
        with pytest.raises(ModelImportError) as caught:
            importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert caught.value.code == "MODEL_IMPORT_SNAPSHOT_DRIFT"


def test_resolver_rejects_adapter_returning_a_different_directory(
    tmp_path: Path,
) -> None:
    repo, revision, license_id = OFFICIAL_CURRENT[0]
    outside = tmp_path / "outside"
    outside.mkdir()
    hub = _FakeHub(
        repo=repo,
        revision=revision,
        license_id=license_id,
        wrong_download_path=outside,
    )
    resolver = _resolver(tmp_path, hub)

    with pytest.raises(HuggingFaceResolverError) as caught:
        with resolver.resolve_main(repo):
            pytest.fail("wrong download path must not yield a snapshot")

    assert caught.value.code == "HF_RESOLVER_DOWNLOAD_PATH_INVALID"
    assert outside.exists()
    assert not list((tmp_path / "resolver-temp").iterdir())


def test_importer_rejects_tampered_card_license_attestation(tmp_path: Path) -> None:
    repo, revision, license_id = OFFICIAL_CURRENT[0]
    hub = _FakeHub(repo=repo, revision=revision, license_id=license_id)
    resolver = _resolver(tmp_path, hub)

    with resolver.resolve_main(repo) as snapshot:
        target = snapshot.directory / LICENSE_ATTESTATION_FILENAME
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["license_id"] = "apache-2.0"
        target.write_text(json.dumps(payload), encoding="utf-8")
        candidates = load_tracked_model_spec(TRACKED_MODELS)
        importer = ModelImporter(
            artifact_root=(tmp_path / "vault" / "models").resolve(),
            runtime_manifest_path=(
                tmp_path / "state" / ".consultation-models" / "runtime-manifest.json"
            ).resolve(),
            candidates=candidates,
        )
        with pytest.raises(ModelImportError) as caught:
            importer.import_snapshot("bge_m3", snapshot, versions=VERSIONS)

    assert caught.value.code == "MODEL_IMPORT_LICENSE_ATTESTATION_INVALID"


@pytest.mark.parametrize(
    ("repo", "revision", "license_id"),
    OFFICIAL_CURRENT,
)
@pytest.mark.parametrize(
    "fault",
    ("missing_expected", "alternative_weight"),
)
def test_resolver_rejects_incomplete_or_duplicate_weight_layout(
    tmp_path: Path,
    repo: str,
    revision: str,
    license_id: str,
    fault: str,
) -> None:
    hub = _FakeHub(
        repo=repo,
        revision=revision,
        license_id=license_id,
        omit_expected_weight=fault == "missing_expected",
        add_alternative_weight=fault == "alternative_weight",
    )
    resolver = _resolver(tmp_path, hub)

    with pytest.raises(HuggingFaceResolverError) as caught:
        with resolver.resolve_main(repo):
            pytest.fail("invalid weight layout must not yield a snapshot")

    assert caught.value.code == "HF_RESOLVER_WEIGHT_LAYOUT_INVALID"
    assert not list((tmp_path / "resolver-temp").iterdir())
