"""Explicit local-snapshot import into the offline model runtime authority."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from pydantic import ValidationError

from consultation_kb.models.model_lock import (
    LICENSE_ATTESTATION_FILENAME,
    ModelLockError,
    RUNTIME_MANIFEST_SCHEMA_VERSION,
    RuntimeLibraryVersions,
    RuntimeModelManifest,
    RuntimeModelRecord,
    TrackedModelSpec,
    hash_model_tree,
    load_model_license_attestation,
    load_runtime_model_manifest,
    model_tree_sha256,
    verify_runtime_manifest,
    write_runtime_model_manifest_atomic,
)
from consultation_kb.retrieval.embeddings import ModelFileHash


class ModelImportError(RuntimeError):
    """A fixed-code local model import rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_LICENSE_MARKERS: dict[str, tuple[bytes, ...]] = {
    "mit": (b"mit license", b"permission is hereby granted"),
    "apache-2.0": (b"apache license", b"version 2.0"),
}
_LICENSE_NAMES = frozenset({"license", "license.md", "license.txt"})


def detect_runtime_library_versions() -> RuntimeLibraryVersions:
    """Read exact active-environment versions without importing ML runtimes."""

    try:
        return RuntimeLibraryVersions(
            sentence_transformers_version=metadata.version("sentence-transformers"),
            transformers_version=metadata.version("transformers"),
            tokenizer_version=metadata.version("tokenizers"),
        )
    except (metadata.PackageNotFoundError, ValidationError, ValueError):
        raise ModelImportError("MODEL_IMPORT_RUNTIME_DEPENDENCY_MISSING") from None


def _is_link_or_reparse(path: Path) -> bool:
    status = os.lstat(path)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(status, "st_file_attributes", 0))
    return stat.S_ISLNK(status.st_mode) or bool(attributes & reparse_flag)


def _verify_license_material(
    root: Path,
    *,
    repo: str,
    revision: str,
    expected_license: str,
) -> None:
    markers = _LICENSE_MARKERS.get(expected_license)
    if markers is None:
        raise ModelImportError("MODEL_IMPORT_LICENSE_UNSUPPORTED")
    traditional_verified = False
    try:
        candidates: list[Path] = []
        for path in root.iterdir():
            if path.name.lower() not in _LICENSE_NAMES:
                continue
            if _is_link_or_reparse(path) or not path.is_file():
                raise ModelImportError("MODEL_IMPORT_LICENSE_INVALID")
            candidates.append(path)
        for path in candidates:
            if path.stat().st_size > 1024 * 1024:
                raise ModelImportError("MODEL_IMPORT_LICENSE_INVALID")
            payload = path.read_bytes().lower()
            detected = {
                license_id
                for license_id, license_markers in _LICENSE_MARKERS.items()
                if all(marker in payload for marker in license_markers)
            }
            if detected and expected_license not in detected:
                raise ModelImportError("MODEL_IMPORT_LICENSE_MISMATCH")
            traditional_verified = traditional_verified or expected_license in detected
    except ModelImportError:
        raise
    except OSError:
        raise ModelImportError("MODEL_IMPORT_LICENSE_UNREADABLE") from None

    attestation_path = root / LICENSE_ATTESTATION_FILENAME
    attestation_present = os.path.lexists(attestation_path)
    if attestation_present:
        try:
            attestation = load_model_license_attestation(attestation_path)
        except ModelLockError:
            raise ModelImportError("MODEL_IMPORT_LICENSE_ATTESTATION_INVALID") from None
        if (
            attestation.repo != repo
            or attestation.revision != revision
            or attestation.license_id != expected_license
        ):
            raise ModelImportError("MODEL_IMPORT_LICENSE_ATTESTATION_MISMATCH")
    if not traditional_verified and not attestation_present:
        raise ModelImportError("MODEL_IMPORT_LICENSE_MISSING")


@dataclass(frozen=True, slots=True)
class LocalRepositorySnapshot:
    """Already-resolved local repository material supplied by an ops adapter."""

    directory: Path
    repo: str
    revision: str
    license_id: str
    expected_files: tuple[ModelFileHash, ...] | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.directory, Path)
            or type(self.repo) is not str
            or type(self.revision) is not str
            or type(self.license_id) is not str
            or (
                self.expected_files is not None
                and (
                    type(self.expected_files) is not tuple
                    or any(
                        not isinstance(item, ModelFileHash)
                        for item in self.expected_files
                    )
                )
            )
        ):
            raise TypeError("MODEL_IMPORT_SNAPSHOT_INVALID")


class ModelImporter:
    """Import a materialized snapshot; this class has no network capability."""

    def __init__(
        self,
        *,
        artifact_root: Path,
        runtime_manifest_path: Path,
        candidates: TrackedModelSpec,
    ) -> None:
        if not isinstance(artifact_root, Path) or not isinstance(
            runtime_manifest_path, Path
        ):
            raise TypeError("MODEL_IMPORT_PATH_REQUIRED")
        if not artifact_root.is_absolute() or not runtime_manifest_path.is_absolute():
            raise ModelImportError("MODEL_IMPORT_ABSOLUTE_ROOT_REQUIRED")
        self._artifact_root = artifact_root.resolve(strict=False)
        self._manifest_path = runtime_manifest_path.resolve(strict=False)
        if (
            self._manifest_path.name != "runtime-manifest.json"
            or self._manifest_path.parent.name != ".consultation-models"
        ):
            raise ModelImportError("MODEL_RUNTIME_MANIFEST_PATH_INVALID")
        self._candidates = TrackedModelSpec.model_validate(candidates)

    @property
    def artifact_root(self) -> Path:
        return self._artifact_root

    @property
    def runtime_manifest_path(self) -> Path:
        return self._manifest_path

    def import_snapshot(
        self,
        model_id: str,
        snapshot: LocalRepositorySnapshot,
        *,
        versions: RuntimeLibraryVersions,
    ) -> RuntimeModelManifest:
        """Verify, materialize, register, and re-verify one local snapshot."""

        if not isinstance(snapshot, LocalRepositorySnapshot):
            raise TypeError("MODEL_IMPORT_SNAPSHOT_REQUIRED")
        try:
            candidate = self._candidates.candidate(model_id)
            exact_versions = RuntimeLibraryVersions.model_validate(
                versions,
                strict=True,
            )
        except ModelLockError as error:
            raise ModelImportError(error.code) from None
        except (ValidationError, ValueError, TypeError):
            raise ModelImportError("MODEL_IMPORT_VERSIONS_INVALID") from None
        if (
            snapshot.repo != candidate.repo
            or snapshot.license_id != candidate.expected_license
        ):
            raise ModelImportError("MODEL_IMPORT_IDENTITY_MISMATCH")
        if len(snapshot.revision) != 40 or any(
            char not in "0123456789abcdef" for char in snapshot.revision
        ):
            raise ModelImportError("MODEL_IMPORT_REVISION_INVALID")
        try:
            source = snapshot.directory.resolve(strict=True)
        except OSError:
            raise ModelImportError("MODEL_IMPORT_SNAPSHOT_MISSING") from None
        try:
            source_is_link = _is_link_or_reparse(snapshot.directory)
        except OSError:
            raise ModelImportError("MODEL_IMPORT_SNAPSHOT_INVALID") from None
        if source_is_link or not source.is_dir():
            raise ModelImportError("MODEL_IMPORT_SNAPSHOT_INVALID")
        _verify_license_material(
            source,
            repo=candidate.repo,
            revision=snapshot.revision,
            expected_license=candidate.expected_license,
        )
        try:
            files = hash_model_tree(source)
        except ModelLockError as error:
            raise ModelImportError(error.code) from None
        if snapshot.expected_files is not None and files != snapshot.expected_files:
            raise ModelImportError("MODEL_IMPORT_SNAPSHOT_DRIFT")
        tokenizer = next(
            (
                item
                for item in files
                if item.relative_path == candidate.tokenizer_relpath
            ),
            None,
        )
        if tokenizer is None:
            raise ModelImportError("MODEL_IMPORT_TOKENIZER_MISSING")
        try:
            descriptor = candidate.descriptor(
                revision=snapshot.revision,
                files=files,
                tokenizer_sha256=tokenizer.sha256,
                versions=exact_versions,
            )
            record = RuntimeModelRecord(
                model_id=candidate.model_id,
                role=candidate.role,
                repo=candidate.repo,
                revision=snapshot.revision,
                license_id=snapshot.license_id,
                artifact_relpath=candidate.artifact_relpath,
                files=files,
                artifact_tree_sha256=model_tree_sha256(files),
                descriptor=descriptor,
                descriptor_sha256=descriptor.id,
                load_policy=candidate.load_policy,
            )
        except (ValueError, ModelLockError):
            raise ModelImportError("MODEL_IMPORT_DESCRIPTOR_INVALID") from None

        self._artifact_root.mkdir(parents=True, exist_ok=True)
        try:
            artifact_root_is_link = _is_link_or_reparse(self._artifact_root)
        except OSError:
            raise ModelImportError("MODEL_IMPORT_ARTIFACT_ROOT_INVALID") from None
        if artifact_root_is_link or not self._artifact_root.is_dir():
            raise ModelImportError("MODEL_IMPORT_ARTIFACT_ROOT_INVALID")
        destination = self._destination(candidate.artifact_relpath)
        self._materialize(source, destination, files)
        _verify_license_material(
            destination,
            repo=candidate.repo,
            revision=snapshot.revision,
            expected_license=candidate.expected_license,
        )
        try:
            if hash_model_tree(destination) != record.files:
                raise ModelImportError("MODEL_IMPORT_COPY_MISMATCH")
        except ModelImportError:
            raise
        except ModelLockError:
            raise ModelImportError("MODEL_IMPORT_COPY_MISMATCH") from None

        models: dict[str, RuntimeModelRecord] = {}
        if self._manifest_path.exists():
            try:
                current = load_runtime_model_manifest(
                    self._manifest_path,
                    candidates=self._candidates,
                    artifact_root=self._artifact_root,
                )
            except ModelLockError as error:
                raise ModelImportError(error.code) from None
            models.update((item.model_id, item) for item in current.models)
        models[record.model_id] = record
        try:
            manifest = RuntimeModelManifest(
                schema_version=RUNTIME_MANIFEST_SCHEMA_VERSION,
                candidate_spec_sha256=self._candidates.canonical_sha256,
                models=tuple(models.values()),
            )
            verify_runtime_manifest(
                manifest,
                candidates=self._candidates,
                artifact_root=self._artifact_root,
            )
            write_runtime_model_manifest_atomic(self._manifest_path, manifest)
            return load_runtime_model_manifest(
                self._manifest_path,
                candidates=self._candidates,
                artifact_root=self._artifact_root,
            )
        except ModelLockError as error:
            raise ModelImportError(error.code) from None

    def _destination(self, artifact_relpath: str) -> Path:
        candidate = self._artifact_root / Path(artifact_relpath)
        current = self._artifact_root
        try:
            for part in Path(artifact_relpath).parts:
                current /= part
                if os.path.lexists(current) and _is_link_or_reparse(current):
                    raise ModelImportError("MODEL_IMPORT_ARTIFACT_PATH_INVALID")
        except ModelImportError:
            raise
        except OSError:
            raise ModelImportError("MODEL_IMPORT_ARTIFACT_PATH_INVALID") from None
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self._artifact_root)
        except ValueError:
            raise ModelImportError("MODEL_IMPORT_ARTIFACT_PATH_INVALID") from None
        return resolved

    def _materialize(
        self,
        source: Path,
        destination: Path,
        files: tuple[ModelFileHash, ...],
    ) -> None:
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise ModelImportError("MODEL_IMPORT_ARTIFACT_CONFLICT")
            try:
                if hash_model_tree(destination) != files:
                    raise ModelImportError("MODEL_IMPORT_ARTIFACT_CONFLICT")
            except ModelLockError as error:
                raise ModelImportError(error.code) from None
            return

        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=".model-import-", dir=self._artifact_root)
        )
        payload = staging / "payload"
        try:
            payload.mkdir()
            for expected in files:
                source_file = source / Path(expected.relative_path)
                target_file = payload / Path(expected.relative_path)
                target_file.parent.mkdir(parents=True, exist_ok=True)
                with (
                    source_file.open("rb") as source_stream,
                    target_file.open("xb") as target_stream,
                ):
                    shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
                    target_stream.flush()
                    os.fsync(target_stream.fileno())
            if hash_model_tree(payload) != files:
                raise ModelImportError("MODEL_IMPORT_COPY_MISMATCH")
            try:
                os.replace(payload, destination)
            except OSError:
                if destination.is_dir() and hash_model_tree(destination) == files:
                    return
                raise
        except ModelImportError:
            raise
        except (OSError, ModelLockError):
            raise ModelImportError("MODEL_IMPORT_WRITE_FAILED") from None
        finally:
            self._remove_staging(staging)

    def _remove_staging(self, staging: Path) -> None:
        try:
            resolved = staging.resolve(strict=False)
            if resolved.parent == self._artifact_root and resolved.name.startswith(
                ".model-import-"
            ):
                shutil.rmtree(resolved, ignore_errors=True)
        except OSError:
            pass


__all__ = [
    "LocalRepositorySnapshot",
    "ModelImportError",
    "ModelImporter",
    "detect_runtime_library_versions",
]
