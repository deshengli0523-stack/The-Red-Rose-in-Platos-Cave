"""Explicit Hugging Face resolver for pinned, locally importable snapshots.

Importing this module has no network or Hugging Face dependency side effect.
The optional dependency is imported only when ``resolve_main`` is explicitly
entered without an injected adapter.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.importer import LocalRepositorySnapshot
from consultation_kb.models.model_lock import (
    LICENSE_ATTESTATION_FILENAME,
    ModelLockError,
    TrackedModelSpec,
    build_model_license_attestation,
    hash_model_tree,
)


OFFICIAL_HUGGING_FACE_ENDPOINT = "https://huggingface.co"
_BASE_IGNORE_PATTERNS = ("onnx/**", "openvino/**")
_EXPECTED_WEIGHT_BY_REPO = {
    "BAAI/bge-m3": "pytorch_model.bin",
    "BAAI/bge-small-zh-v1.5": "model.safetensors",
    "BAAI/bge-reranker-v2-m3": "model.safetensors",
    "BAAI/bge-reranker-base": "model.safetensors",
}
_ALTERNATIVE_WEIGHT_NAMES = frozenset(
    {
        "flax_model.msgpack",
        "model.safetensors",
        "pytorch_model.bin",
        "rust_model.ot",
        "tf_model.h5",
    }
)
_PYTORCH_SHARD_RE = re.compile(r"pytorch_model-\d{5}-of-\d{5}\.bin\Z")
_SAFETENSORS_SHARD_RE = re.compile(r"model-\d{5}-of-\d{5}\.safetensors\Z")


class HuggingFaceResolverError(RuntimeError):
    """A fixed-code failure at the explicit public-model network boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HubModelMetadata:
    """Exact public model-card identity returned by a hub adapter."""

    repo: str
    revision: str
    license_id: str

    def __post_init__(self) -> None:
        if (
            type(self.repo) is not str
            or type(self.revision) is not str
            or type(self.license_id) is not str
        ):
            raise TypeError("HF_RESOLVER_METADATA_INVALID")


class HuggingFaceHubAdapter(Protocol):
    def model_info(self, *, repo: str, revision: str) -> HubModelMetadata: ...

    def snapshot_download(
        self,
        *,
        repo: str,
        revision: str,
        local_dir: Path,
        ignore_patterns: tuple[str, ...],
    ) -> Path: ...


def _card_license(card_data: object) -> str:
    value: object = None
    if isinstance(card_data, Mapping):
        value = card_data.get("license")
    else:
        try:
            value = getattr(card_data, "license")
        except Exception:
            value = None
        if value is None:
            try:
                converted = card_data.to_dict()  # type: ignore[attr-defined]
            except Exception:
                converted = None
            if isinstance(converted, Mapping):
                value = converted.get("license")
    if type(value) is not str or not value:
        raise HuggingFaceResolverError("HF_RESOLVER_LICENSE_MISSING")
    return value


class _DefaultHuggingFaceHubAdapter:
    """Lazy wrapper around the public, unauthenticated Hugging Face API."""

    def __init__(self) -> None:
        # These flags are read while ``huggingface_hub`` is imported.  The
        # resolver is an explicit one-shot network boundary, so force the
        # predictable HTTP implementation before importing the optional
        # dependency instead of allowing hf-xet or telemetry side effects.
        os.environ["HF_HUB_DISABLE_XET"] = "1"
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        try:
            from huggingface_hub import HfApi, snapshot_download  # type: ignore[import-not-found,unused-ignore]
        except ImportError:
            raise HuggingFaceResolverError("HF_RESOLVER_DEPENDENCY_MISSING") from None
        self._api: Any = HfApi(
            endpoint=OFFICIAL_HUGGING_FACE_ENDPOINT,
            token=False,
        )
        self._snapshot_download: Any = snapshot_download

    def model_info(self, *, repo: str, revision: str) -> HubModelMetadata:
        info: Any = self._api.model_info(
            repo_id=repo,
            revision=revision,
            files_metadata=False,
            token=False,
        )
        return HubModelMetadata(
            repo=info.id,
            revision=info.sha,
            license_id=_card_license(info.card_data),
        )

    def snapshot_download(
        self,
        *,
        repo: str,
        revision: str,
        local_dir: Path,
        ignore_patterns: tuple[str, ...],
    ) -> Path:
        cache_dir = local_dir.parent / ".hub-cache"
        result: object = self._snapshot_download(
            repo_id=repo,
            revision=revision,
            local_dir=os.fspath(local_dir),
            cache_dir=os.fspath(cache_dir),
            local_files_only=False,
            token=False,
            endpoint=OFFICIAL_HUGGING_FACE_ENDPOINT,
            ignore_patterns=list(ignore_patterns),
        )
        if type(result) is not str:
            raise HuggingFaceResolverError("HF_RESOLVER_DOWNLOAD_PATH_INVALID")
        return Path(result)


def _is_link_or_reparse(path: Path) -> bool:
    status = os.lstat(path)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(status, "st_file_attributes", 0))
    return stat.S_ISLNK(status.st_mode) or bool(attributes & reparse_flag)


def _plain_directory(path: Path) -> bool:
    try:
        return path.is_dir() and not _is_link_or_reparse(path)
    except OSError:
        return False


def _ignore_patterns(repo: str) -> tuple[str, ...]:
    if repo not in _EXPECTED_WEIGHT_BY_REPO:
        raise HuggingFaceResolverError("MODEL_CANDIDATE_NOT_FOUND")
    if repo == "BAAI/bge-m3":
        return _BASE_IGNORE_PATTERNS
    return (*_BASE_IGNORE_PATTERNS, "pytorch_model.bin")


def _is_alternative_weight(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    return (
        name in _ALTERNATIVE_WEIGHT_NAMES
        or _PYTORCH_SHARD_RE.fullmatch(name) is not None
        or _SAFETENSORS_SHARD_RE.fullmatch(name) is not None
        or name.endswith((".onnx", ".onnx_data"))
        or normalized.startswith(("onnx/", "openvino/"))
    )


def _verify_weight_layout(
    repo: str,
    relative_paths: tuple[str, ...],
) -> None:
    expected = _EXPECTED_WEIGHT_BY_REPO.get(repo)
    if expected is None:
        raise HuggingFaceResolverError("MODEL_CANDIDATE_NOT_FOUND")
    observed = {path for path in relative_paths if _is_alternative_weight(path)}
    if observed != {expected}:
        raise HuggingFaceResolverError("HF_RESOLVER_WEIGHT_LAYOUT_INVALID")


class HuggingFaceSnapshotResolver:
    """Resolve mutable ``main`` once, then download only the resulting commit."""

    def __init__(
        self,
        *,
        candidates: TrackedModelSpec,
        adapter: HuggingFaceHubAdapter | None = None,
        temporary_root: Path | None = None,
    ) -> None:
        try:
            self._candidates = TrackedModelSpec.model_validate(candidates, strict=True)
        except (TypeError, ValidationError, ValueError):
            raise HuggingFaceResolverError("HF_RESOLVER_CANDIDATES_INVALID") from None
        if temporary_root is not None and not isinstance(temporary_root, Path):
            raise TypeError("HF_RESOLVER_TEMPORARY_ROOT_REQUIRED")
        self._adapter = adapter
        self._temporary_root = (
            None if temporary_root is None else temporary_root.resolve(strict=False)
        )

    def _hub(self) -> HuggingFaceHubAdapter:
        if self._adapter is None:
            self._adapter = _DefaultHuggingFaceHubAdapter()
        return self._adapter

    def _create_staging(self) -> tuple[Path, Path]:
        parent = self._temporary_root
        if parent is not None and not _plain_directory(parent):
            raise HuggingFaceResolverError("HF_RESOLVER_TEMPORARY_ROOT_INVALID")
        try:
            staging = Path(
                tempfile.mkdtemp(prefix=".consultation-hf-", dir=parent)
            ).resolve(strict=True)
        except OSError:
            raise HuggingFaceResolverError("HF_RESOLVER_STAGING_FAILED") from None
        if not _plain_directory(staging):
            raise HuggingFaceResolverError("HF_RESOLVER_STAGING_INVALID")
        return staging, staging.parent.resolve(strict=True)

    @staticmethod
    def _remove_hub_local_metadata(payload: Path) -> None:
        cache = payload / ".cache"
        if not os.path.lexists(cache):
            return
        try:
            resolved = cache.resolve(strict=True)
            resolved.relative_to(payload)
            if _is_link_or_reparse(cache) or not resolved.is_dir():
                raise OSError
            shutil.rmtree(resolved)
        except OSError:
            raise HuggingFaceResolverError("HF_RESOLVER_CACHE_INVALID") from None

    @staticmethod
    def _write_attestation(
        payload: Path, *, repo: str, revision: str, license_id: str
    ) -> None:
        target = payload / LICENSE_ATTESTATION_FILENAME
        if os.path.lexists(target):
            raise HuggingFaceResolverError("HF_RESOLVER_ATTESTATION_CONFLICT")
        try:
            attestation = build_model_license_attestation(
                repo=repo,
                revision=revision,
                license_id=license_id,
            )
            serialized = (
                canonical_json_bytes(attestation.model_dump(mode="json")) + b"\n"
            )
            with target.open("xb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, ModelLockError, ValidationError, ValueError):
            raise HuggingFaceResolverError(
                "HF_RESOLVER_ATTESTATION_WRITE_FAILED"
            ) from None

    @staticmethod
    def _cleanup_staging(staging: Path, expected_parent: Path) -> None:
        if not os.path.lexists(staging):
            return
        if staging.parent != expected_parent or not staging.name.startswith(
            ".consultation-hf-"
        ):
            raise HuggingFaceResolverError("HF_RESOLVER_CLEANUP_SCOPE_INVALID")
        try:
            if _is_link_or_reparse(staging):
                staging.unlink()
            else:
                shutil.rmtree(staging)
        except OSError:
            raise HuggingFaceResolverError("HF_RESOLVER_CLEANUP_FAILED") from None

    @contextmanager
    def resolve_main(self, repo: str) -> Iterator[LocalRepositorySnapshot]:
        """Resolve and materialize one tracked repo for an immediate import."""

        try:
            candidate = self._candidates.candidate_for_repo(repo)
        except ModelLockError as error:
            raise HuggingFaceResolverError(error.code) from None
        staging, staging_parent = self._create_staging()
        payload = staging / "snapshot"
        try:
            hub = self._hub()
            try:
                metadata = hub.model_info(repo=candidate.repo, revision="main")
            except HuggingFaceResolverError:
                raise
            except Exception:
                raise HuggingFaceResolverError("HF_RESOLVER_METADATA_FAILED") from None
            if not isinstance(metadata, HubModelMetadata):
                raise HuggingFaceResolverError("HF_RESOLVER_METADATA_INVALID")
            try:
                attestation = build_model_license_attestation(
                    repo=metadata.repo,
                    revision=metadata.revision,
                    license_id=metadata.license_id,
                )
            except (ValidationError, ValueError):
                raise HuggingFaceResolverError("HF_RESOLVER_METADATA_INVALID") from None
            if (
                metadata.repo != candidate.repo
                or metadata.license_id != candidate.expected_license
            ):
                raise HuggingFaceResolverError("HF_RESOLVER_IDENTITY_MISMATCH")

            try:
                downloaded = hub.snapshot_download(
                    repo=candidate.repo,
                    revision=attestation.revision,
                    local_dir=payload,
                    ignore_patterns=_ignore_patterns(candidate.repo),
                )
            except HuggingFaceResolverError:
                raise
            except Exception:
                raise HuggingFaceResolverError("HF_RESOLVER_DOWNLOAD_FAILED") from None
            if not isinstance(downloaded, Path):
                raise HuggingFaceResolverError("HF_RESOLVER_DOWNLOAD_PATH_INVALID")
            try:
                exact_payload = payload.resolve(strict=True)
                exact_downloaded = downloaded.resolve(strict=True)
            except OSError:
                raise HuggingFaceResolverError(
                    "HF_RESOLVER_DOWNLOAD_PATH_INVALID"
                ) from None
            if (
                exact_downloaded != exact_payload
                or exact_payload.parent != staging
                or not _plain_directory(payload)
            ):
                raise HuggingFaceResolverError("HF_RESOLVER_DOWNLOAD_PATH_INVALID")
            try:
                downloaded_files = hash_model_tree(exact_payload)
            except ModelLockError as error:
                raise HuggingFaceResolverError(error.code) from None
            _verify_weight_layout(
                candidate.repo,
                tuple(item.relative_path for item in downloaded_files),
            )
            self._remove_hub_local_metadata(exact_payload)
            self._write_attestation(
                exact_payload,
                repo=attestation.repo,
                revision=attestation.revision,
                license_id=attestation.license_id,
            )
            try:
                expected_files = hash_model_tree(exact_payload)
            except ModelLockError as error:
                raise HuggingFaceResolverError(error.code) from None
            yield LocalRepositorySnapshot(
                directory=exact_payload,
                repo=attestation.repo,
                revision=attestation.revision,
                license_id=attestation.license_id,
                expected_files=expected_files,
            )
        finally:
            self._cleanup_staging(staging, staging_parent)


__all__ = [
    "HubModelMetadata",
    "HuggingFaceHubAdapter",
    "HuggingFaceResolverError",
    "HuggingFaceSnapshotResolver",
    "OFFICIAL_HUGGING_FACE_ENDPOINT",
]
