"""Tracked model candidates and verified offline runtime model manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TypeAlias

from pydantic import ValidationError, field_validator, model_validator

from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.common import (
    NonEmptyStr,
    PositiveInt,
    Sha256Hex,
    StrictModel,
)
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash


CANDIDATE_SPEC_SCHEMA_VERSION: Final[Literal["consultation_model_candidates.v1"]] = (
    "consultation_model_candidates.v1"
)
RUNTIME_MANIFEST_SCHEMA_VERSION: Final[Literal["consultation_model_runtime.v1"]] = (
    "consultation_model_runtime.v1"
)
RUNTIME_MANIFEST_RELPATH: Final = ".consultation-models/runtime-manifest.json"
LICENSE_ATTESTATION_FILENAME: Final = ".consultation-license-attestation.json"
MAX_MODEL_MANIFEST_BYTES: Final = 4 * 1024 * 1024

ModelRole: TypeAlias = Literal["embedding", "reranker"]

_MODEL_ID_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_REPO_RE = re.compile(r"BAAI/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_LICENSE_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}\Z")
_DRIVE_PATH_RE = re.compile(r"[A-Za-z]:")
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)(?:https?|ssh)://[^\s]*[?&#](?:api[_-]?key|access[_-]?token|token)="
)
_URL_USERINFO_RE = re.compile(r"(?i)(?:https?|ssh)://[^\s/@]+:[^\s/@]+@")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s]+")
_HF_TOKEN_RE = re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")
_API_TOKEN_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "bearer_token",
        "hf_token",
        "token",
    }
)
_EXPECTED_MODEL_BINDINGS: Final = {
    ("embedding", "BAAI/bge-m3"): ("bge_m3", "embedding/bge-m3"),
    ("embedding", "BAAI/bge-small-zh-v1.5"): (
        "bge_small_zh_v1_5",
        "embedding/bge-small-zh-v1.5",
    ),
    ("reranker", "BAAI/bge-reranker-v2-m3"): (
        "bge_reranker_v2_m3",
        "reranker/bge-reranker-v2-m3",
    ),
    ("reranker", "BAAI/bge-reranker-base"): (
        "bge_reranker_base",
        "reranker/bge-reranker-base",
    ),
}
_EMBEDDING_ADAPTER: Final = (
    "consultation_kb.retrieval.model_adapters.SentenceTransformersEmbedder"
)
_RERANKER_ADAPTER: Final = (
    "consultation_kb.retrieval.model_adapters.SentenceTransformersCrossEncoderReranker"
)


class ModelLockError(ValueError):
    """A fixed-code model lock or runtime verification rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _safe_relative_path(value: str) -> str:
    if type(value) is not str:
        raise ValueError("model artifact path must be an exact string")
    if (
        not value
        or len(value) > 512
        or "\\" in value
        or "\x00" in value
        or value.startswith(("/", "~"))
        or value.startswith("//")
        or _DRIVE_PATH_RE.match(value) is not None
        or ":" in value
    ):
        raise ValueError("model artifact path must be portable and relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("model artifact path must be non-traversing")
    return value


def _validate_model_id(value: str) -> str:
    if _MODEL_ID_RE.fullmatch(value) is None or len(value) > 96:
        raise ValueError("model_id must use canonical lower-snake form")
    return value


def _validate_repo(value: str) -> str:
    if _REPO_RE.fullmatch(value) is None:
        raise ValueError("model repo must be an exact BAAI repository identifier")
    return value


def _validate_revision(value: str) -> str:
    if _REVISION_RE.fullmatch(value) is None:
        raise ValueError("runtime model revision must be a 40-hex commit")
    return value


def _validate_license(value: str) -> str:
    if _LICENSE_RE.fullmatch(value) is None:
        raise ValueError("model license must be a canonical SPDX-like identifier")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    """Reject symlinks and Windows junction/reparse entries uniformly."""

    status = os.lstat(path)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(status, "st_file_attributes", 0))
    return stat.S_ISLNK(status.st_mode) or bool(attributes & reparse_flag)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _reject_sensitive_material(value: object) -> None:
    if isinstance(value, Mapping):
        for key, member in value.items():
            if type(key) is not str or _normalized_key(key) in _SECRET_KEYS:
                raise ValueError("model registry must not contain credentials")
            _reject_sensitive_material(member)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for member in value:
            _reject_sensitive_material(member)
        return
    if type(value) is str and any(
        pattern.search(value) is not None
        for pattern in (
            _URL_CREDENTIAL_RE,
            _URL_USERINFO_RE,
            _BEARER_RE,
            _HF_TOKEN_RE,
            _API_TOKEN_RE,
        )
    ):
        raise ValueError("model registry must not contain credentials")


def _canonical_files(
    value: tuple[ModelFileHash, ...],
) -> tuple[ModelFileHash, ...]:
    if not value:
        raise ValueError("runtime model files must be nonempty")
    paths = [item.relative_path for item in value]
    if len(paths) != len(set(paths)):
        raise ValueError("runtime model file paths must be unique")
    for path in paths:
        _safe_relative_path(path)
    return tuple(sorted(value, key=lambda item: item.relative_path))


def model_tree_sha256(files: tuple[ModelFileHash, ...]) -> str:
    """Hash the complete ordered path/hash authority for one model tree."""

    exact = _canonical_files(files)
    return hashlib.sha256(
        canonical_json_bytes([item.model_dump(mode="json") for item in exact])
    ).hexdigest()


def _license_authority_sha256(
    *,
    repo: str,
    revision: str,
    license_id: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "license_id": license_id,
                "repo": repo,
                "resolved_from": "main",
                "revision": revision,
                "source": "huggingface_model_card",
            }
        )
    ).hexdigest()


class OfflineLoadPolicy(StrictModel):
    """The only permitted production loading policy for model artifacts."""

    local_files_only: Literal[True]
    trust_remote_code: Literal[False]
    hf_hub_offline: Literal["1"]
    transformers_offline: Literal["1"]


class ModelEncodingSpec(StrictModel):
    """Tracked P4 encoding semantics that do not depend on downloaded bytes."""

    adapter_class: NonEmptyStr
    adapter_version: NonEmptyStr
    query_prompt: str
    document_prompt: str
    pooling: Literal["cls", "mean", "max", "last_token", "model_defined"]
    normalize_embeddings: bool
    max_sequence_length: PositiveInt
    truncation: Literal["longest_first", "only_first", "do_not_truncate"]
    dtype: Literal["float32"]
    precision: Literal["float32"]
    dimension: PositiveInt
    score_function: Literal["cosine", "dot"]

    @model_validator(mode="after")
    def _valid_score_semantics(self) -> "ModelEncodingSpec":
        if self.score_function == "cosine" and not self.normalize_embeddings:
            raise ValueError("cosine encoding requires normalized embeddings")
        return self


class RuntimeLibraryVersions(StrictModel):
    """Exact installed library versions included in a runtime descriptor."""

    sentence_transformers_version: NonEmptyStr
    transformers_version: NonEmptyStr
    tokenizer_version: NonEmptyStr


class ModelLicenseAttestation(StrictModel):
    """Pinned model-card license authority sealed into the model file tree."""

    schema_version: Literal["consultation_model_license_attestation.v1"] = (
        "consultation_model_license_attestation.v1"
    )
    source: Literal["huggingface_model_card"] = "huggingface_model_card"
    resolved_from: Literal["main"] = "main"
    repo: NonEmptyStr
    revision: NonEmptyStr
    license_id: NonEmptyStr
    card_authority_sha256: Sha256Hex

    @field_validator("repo")
    @classmethod
    def _repo(cls, value: str) -> str:
        return _validate_repo(value)

    @field_validator("revision")
    @classmethod
    def _revision(cls, value: str) -> str:
        return _validate_revision(value)

    @field_validator("license_id")
    @classmethod
    def _license(cls, value: str) -> str:
        return _validate_license(value)

    @model_validator(mode="after")
    def _authority_binding(self) -> "ModelLicenseAttestation":
        expected = _license_authority_sha256(
            repo=self.repo,
            revision=self.revision,
            license_id=self.license_id,
        )
        if self.card_authority_sha256 != expected:
            raise ValueError("model-card license authority hash is invalid")
        _reject_sensitive_material(self.model_dump(mode="json"))
        return self


def build_model_license_attestation(
    *,
    repo: str,
    revision: str,
    license_id: str,
) -> ModelLicenseAttestation:
    """Build the canonical attestation for one resolved public model card."""

    exact_repo = _validate_repo(repo)
    exact_revision = _validate_revision(revision)
    exact_license = _validate_license(license_id)
    return ModelLicenseAttestation(
        repo=exact_repo,
        revision=exact_revision,
        license_id=exact_license,
        card_authority_sha256=_license_authority_sha256(
            repo=exact_repo,
            revision=exact_revision,
            license_id=exact_license,
        ),
    )


class ModelCandidateSpec(StrictModel):
    """One tracked candidate without a mutable or machine-local revision."""

    model_id: NonEmptyStr
    role: ModelRole
    repo: NonEmptyStr
    expected_license: NonEmptyStr
    artifact_relpath: NonEmptyStr
    tokenizer_relpath: NonEmptyStr
    encoding: ModelEncodingSpec
    load_policy: OfflineLoadPolicy

    @field_validator("model_id")
    @classmethod
    def _model_id(cls, value: str) -> str:
        return _validate_model_id(value)

    @field_validator("repo")
    @classmethod
    def _repo(cls, value: str) -> str:
        return _validate_repo(value)

    @field_validator("expected_license")
    @classmethod
    def _license(cls, value: str) -> str:
        return _validate_license(value)

    @field_validator("artifact_relpath", "tokenizer_relpath")
    @classmethod
    def _relative_path(cls, value: str) -> str:
        return _safe_relative_path(value)

    @model_validator(mode="after")
    def _role_contract(self) -> "ModelCandidateSpec":
        encoding = self.encoding
        if self.role == "embedding":
            if (
                encoding.dimension <= 1
                or not encoding.normalize_embeddings
                or encoding.score_function != "cosine"
                or encoding.adapter_class != _EMBEDDING_ADAPTER
            ):
                raise ValueError("embedding candidate encoding contract is invalid")
        elif (
            encoding.dimension != 1
            or encoding.normalize_embeddings
            or encoding.pooling != "model_defined"
            or encoding.score_function != "dot"
            or encoding.adapter_class != _RERANKER_ADAPTER
        ):
            raise ValueError("reranker candidate encoding contract is invalid")
        if (
            encoding.adapter_version != "1"
            or self.tokenizer_relpath != "tokenizer.json"
        ):
            raise ValueError("model adapter binding is invalid")
        _reject_sensitive_material(self.model_dump(mode="json"))
        return self

    def descriptor(
        self,
        *,
        revision: str,
        files: tuple[ModelFileHash, ...],
        tokenizer_sha256: str,
        versions: RuntimeLibraryVersions,
    ) -> ModelDescriptor:
        exact_files = _canonical_files(files)
        return ModelDescriptor(
            repo=self.repo,
            revision=_validate_revision(revision),
            model_files=exact_files,
            adapter_class=self.encoding.adapter_class,
            adapter_version=self.encoding.adapter_version,
            sentence_transformers_version=versions.sentence_transformers_version,
            transformers_version=versions.transformers_version,
            tokenizer_version=versions.tokenizer_version,
            tokenizer_sha256=Sha256Hex(tokenizer_sha256),
            query_prompt=self.encoding.query_prompt,
            document_prompt=self.encoding.document_prompt,
            pooling=self.encoding.pooling,
            normalize_embeddings=self.encoding.normalize_embeddings,
            max_sequence_length=self.encoding.max_sequence_length,
            truncation=self.encoding.truncation,
            dtype=self.encoding.dtype,
            precision=self.encoding.precision,
            dimension=self.encoding.dimension,
            score_function=self.encoding.score_function,
        )

    def matches_descriptor(self, descriptor: ModelDescriptor) -> bool:
        encoding = self.encoding
        return (
            descriptor.repo == self.repo
            and descriptor.adapter_class == encoding.adapter_class
            and descriptor.adapter_version == encoding.adapter_version
            and descriptor.query_prompt == encoding.query_prompt
            and descriptor.document_prompt == encoding.document_prompt
            and descriptor.pooling == encoding.pooling
            and descriptor.normalize_embeddings == encoding.normalize_embeddings
            and descriptor.max_sequence_length == encoding.max_sequence_length
            and descriptor.truncation == encoding.truncation
            and descriptor.dtype == encoding.dtype
            and descriptor.precision == encoding.precision
            and descriptor.dimension == encoding.dimension
            and descriptor.score_function == encoding.score_function
        )


class TrackedModelSpec(StrictModel):
    """Repository-tracked four-candidate model benchmark authority."""

    schema_version: Literal["consultation_model_candidates.v1"]
    candidates: tuple[ModelCandidateSpec, ...]

    @field_validator("candidates")
    @classmethod
    def _canonical_candidates(
        cls, value: tuple[ModelCandidateSpec, ...]
    ) -> tuple[ModelCandidateSpec, ...]:
        identities = [(item.model_id, item.role, item.repo) for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("model candidates must be nonempty and unique")
        model_ids = [item.model_id for item in value]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("model candidate ids must be unique")
        return tuple(sorted(value, key=lambda item: item.model_id))

    @model_validator(mode="after")
    def _official_candidate_set(self) -> "TrackedModelSpec":
        actual = {
            (item.role, item.repo): (item.model_id, item.artifact_relpath)
            for item in self.candidates
        }
        if actual != _EXPECTED_MODEL_BINDINGS:
            raise ValueError("tracked model candidate set is incomplete")
        _reject_sensitive_material(self.model_dump(mode="json"))
        return self

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json"))
        ).hexdigest()

    def candidate(self, model_id: str) -> ModelCandidateSpec:
        for candidate in self.candidates:
            if candidate.model_id == model_id:
                return candidate
        raise ModelLockError("MODEL_CANDIDATE_NOT_FOUND")

    def candidate_for_repo(self, repo: str) -> ModelCandidateSpec:
        """Resolve one tracked repository without accepting arbitrary repos."""

        for candidate in self.candidates:
            if candidate.repo == repo:
                return candidate
        raise ModelLockError("MODEL_CANDIDATE_NOT_FOUND")


class RuntimeModelRecord(StrictModel):
    """One imported, byte-complete and fixed-revision local model."""

    model_id: NonEmptyStr
    role: ModelRole
    repo: NonEmptyStr
    revision: NonEmptyStr
    license_id: NonEmptyStr
    artifact_relpath: NonEmptyStr
    files: tuple[ModelFileHash, ...]
    artifact_tree_sha256: Sha256Hex
    descriptor: ModelDescriptor
    descriptor_sha256: Sha256Hex
    load_policy: OfflineLoadPolicy

    @field_validator("model_id")
    @classmethod
    def _model_id(cls, value: str) -> str:
        return _validate_model_id(value)

    @field_validator("repo")
    @classmethod
    def _repo(cls, value: str) -> str:
        return _validate_repo(value)

    @field_validator("revision")
    @classmethod
    def _revision(cls, value: str) -> str:
        return _validate_revision(value)

    @field_validator("license_id")
    @classmethod
    def _license(cls, value: str) -> str:
        return _validate_license(value)

    @field_validator("artifact_relpath")
    @classmethod
    def _artifact_path(cls, value: str) -> str:
        return _safe_relative_path(value)

    @field_validator("files")
    @classmethod
    def _files(cls, value: tuple[ModelFileHash, ...]) -> tuple[ModelFileHash, ...]:
        return _canonical_files(value)

    @model_validator(mode="after")
    def _descriptor_binding(self) -> "RuntimeModelRecord":
        if (
            self.descriptor.repo != self.repo
            or self.descriptor.revision != self.revision
            or self.descriptor.model_files != self.files
            or self.descriptor.id != self.descriptor_sha256
            or model_tree_sha256(self.files) != self.artifact_tree_sha256
        ):
            raise ValueError("runtime model descriptor binding is invalid")
        _reject_sensitive_material(self.model_dump(mode="json"))
        return self


class RuntimeModelManifest(StrictModel):
    """Ignored local runtime registry; never a source of network fallbacks."""

    schema_version: Literal["consultation_model_runtime.v1"]
    candidate_spec_sha256: Sha256Hex
    models: tuple[RuntimeModelRecord, ...]

    @field_validator("models")
    @classmethod
    def _canonical_models(
        cls, value: tuple[RuntimeModelRecord, ...]
    ) -> tuple[RuntimeModelRecord, ...]:
        model_ids = [item.model_id for item in value]
        paths = [item.artifact_relpath for item in value]
        if (
            not value
            or len(model_ids) != len(set(model_ids))
            or len(paths) != len(set(paths))
        ):
            raise ValueError("runtime models must be nonempty and uniquely bound")
        return tuple(sorted(value, key=lambda item: item.model_id))

    @model_validator(mode="after")
    def _contains_no_credentials(self) -> "RuntimeModelManifest":
        _reject_sensitive_material(self.model_dump(mode="json"))
        return self

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json"))
        ).hexdigest()


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _read_json(path: Path) -> object:
    if not isinstance(path, Path):
        raise TypeError("model registry path must be a Path")
    try:
        if _is_link_or_reparse(path) or not path.is_file():
            raise ValueError
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_MODEL_MANIFEST_BYTES or b"\x00" in raw:
            raise ValueError
        parsed: object = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_no_duplicate_object,
        )
        _reject_sensitive_material(parsed)
        return parsed
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise ModelLockError("MODEL_REGISTRY_INVALID") from None


def load_tracked_model_spec(path: Path) -> TrackedModelSpec:
    """Load the tracked four-candidate authority with no path or secret fallback."""

    try:
        return TrackedModelSpec.model_validate_json(
            canonical_json_bytes(_read_json(path)),
            strict=True,
        )
    except (ValidationError, ValueError):
        raise ModelLockError("MODEL_CANDIDATE_SPEC_INVALID") from None


def load_model_license_attestation(path: Path) -> ModelLicenseAttestation:
    """Load one exact, path-safe, credential-free model-card attestation."""

    try:
        return ModelLicenseAttestation.model_validate_json(
            canonical_json_bytes(_read_json(path)),
            strict=True,
        )
    except (ModelLockError, ValidationError, ValueError):
        raise ModelLockError("MODEL_LICENSE_ATTESTATION_INVALID") from None


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_UNREADABLE") from None
    return digest.hexdigest()


def hash_model_tree(root: Path) -> tuple[ModelFileHash, ...]:
    """Hash every regular file and reject links or special entries."""

    if not isinstance(root, Path):
        raise TypeError("model root must be a Path")
    try:
        exact_root = root.resolve(strict=True)
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_MISSING") from None
    try:
        root_is_link = _is_link_or_reparse(root)
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_UNREADABLE") from None
    if root_is_link or not exact_root.is_dir():
        raise ModelLockError("MODEL_ARTIFACT_INVALID")
    files: list[ModelFileHash] = []
    try:
        for directory, dirnames, filenames in os.walk(exact_root, followlinks=False):
            current = Path(directory)
            for name in dirnames:
                child = current / name
                if _is_link_or_reparse(child):
                    raise ModelLockError("MODEL_ARTIFACT_LINK_FORBIDDEN")
            for name in filenames:
                child = current / name
                if _is_link_or_reparse(child) or not child.is_file():
                    raise ModelLockError("MODEL_ARTIFACT_LINK_FORBIDDEN")
                relative = child.relative_to(exact_root).as_posix()
                files.append(
                    ModelFileHash(
                        relative_path=_safe_relative_path(relative),
                        sha256=_hash_file(child),
                    )
                )
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_UNREADABLE") from None
    try:
        return _canonical_files(tuple(files))
    except (ValidationError, ValueError):
        raise ModelLockError("MODEL_ARTIFACT_INVALID") from None


def verify_runtime_manifest(
    manifest: RuntimeModelManifest,
    *,
    candidates: TrackedModelSpec,
    artifact_root: Path,
) -> RuntimeModelManifest:
    """Verify tracked semantics and every file in every imported artifact tree."""

    exact = RuntimeModelManifest.model_validate(manifest)
    if exact.candidate_spec_sha256 != candidates.canonical_sha256:
        raise ModelLockError("MODEL_CANDIDATE_BINDING_MISMATCH")
    try:
        root = artifact_root.resolve(strict=True)
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_ROOT_MISSING") from None
    try:
        root_is_link = _is_link_or_reparse(artifact_root)
    except OSError:
        raise ModelLockError("MODEL_ARTIFACT_ROOT_INVALID") from None
    if root_is_link or not root.is_dir():
        raise ModelLockError("MODEL_ARTIFACT_ROOT_INVALID")
    for record in exact.models:
        candidate = candidates.candidate(record.model_id)
        if (
            record.role != candidate.role
            or record.repo != candidate.repo
            or record.license_id != candidate.expected_license
            or record.artifact_relpath != candidate.artifact_relpath
            or record.load_policy != candidate.load_policy
            or not candidate.matches_descriptor(record.descriptor)
        ):
            raise ModelLockError("MODEL_CANDIDATE_BINDING_MISMATCH")
        target = root / Path(record.artifact_relpath)
        try:
            current = root
            for part in Path(record.artifact_relpath).parts:
                current /= part
                if _is_link_or_reparse(current):
                    raise ValueError
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            raise ModelLockError("MODEL_ARTIFACT_PATH_INVALID") from None
        if hash_model_tree(resolved) != record.files:
            raise ModelLockError("MODEL_ARTIFACT_FILES_MISMATCH")
        tokenizer = next(
            (
                item
                for item in record.files
                if item.relative_path == candidate.tokenizer_relpath
            ),
            None,
        )
        if tokenizer is None or tokenizer.sha256 != record.descriptor.tokenizer_sha256:
            raise ModelLockError("MODEL_TOKENIZER_BINDING_MISMATCH")
    return exact


def load_runtime_model_manifest(
    path: Path,
    *,
    candidates: TrackedModelSpec,
    artifact_root: Path,
) -> RuntimeModelManifest:
    """Load and byte-verify an ignored runtime manifest without any fallback."""

    try:
        manifest = RuntimeModelManifest.model_validate_json(
            canonical_json_bytes(_read_json(path)),
            strict=True,
        )
    except (ValidationError, ValueError):
        raise ModelLockError("MODEL_RUNTIME_MANIFEST_INVALID") from None
    return verify_runtime_manifest(
        manifest,
        candidates=candidates,
        artifact_root=artifact_root,
    )


def write_runtime_model_manifest_atomic(
    path: Path,
    manifest: RuntimeModelManifest,
) -> None:
    """Atomically replace only the ignored runtime-manifest location."""

    if (
        not isinstance(path, Path)
        or path.name != "runtime-manifest.json"
        or path.parent.name != ".consultation-models"
    ):
        raise ModelLockError("MODEL_RUNTIME_MANIFEST_PATH_INVALID")
    exact = RuntimeModelManifest.model_validate(manifest)
    payload = canonical_json_bytes(exact.model_dump(mode="json")) + b"\n"
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if _is_link_or_reparse(path.parent):
            raise OSError
        if os.path.lexists(path) and _is_link_or_reparse(path):
            raise OSError
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".runtime-manifest.json.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError:
        raise ModelLockError("MODEL_RUNTIME_MANIFEST_WRITE_FAILED") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = [
    "CANDIDATE_SPEC_SCHEMA_VERSION",
    "LICENSE_ATTESTATION_FILENAME",
    "MAX_MODEL_MANIFEST_BYTES",
    "ModelCandidateSpec",
    "ModelEncodingSpec",
    "ModelLockError",
    "ModelLicenseAttestation",
    "ModelRole",
    "OfflineLoadPolicy",
    "RUNTIME_MANIFEST_RELPATH",
    "RUNTIME_MANIFEST_SCHEMA_VERSION",
    "RuntimeLibraryVersions",
    "RuntimeModelManifest",
    "RuntimeModelRecord",
    "TrackedModelSpec",
    "build_model_license_attestation",
    "hash_model_tree",
    "load_runtime_model_manifest",
    "load_model_license_attestation",
    "load_tracked_model_spec",
    "model_tree_sha256",
    "verify_runtime_manifest",
    "write_runtime_model_manifest_atomic",
]
