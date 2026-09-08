"""Hash-only exact and semantic equivalence reports for rebuilds."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

import numpy as np
import numpy.typing as npt
from pydantic import model_validator

from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.models.common import (
    FiniteFloat,
    NonNegativeInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)


VECTOR_ABSOLUTE_TOLERANCE = 1e-6
ComparisonMode: TypeAlias = Literal["exact", "vector"]


class EquivalenceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArtifactFingerprint(StrictModel):
    """Body-free fingerprint captured before or after a rebuild."""

    artifact_key: SafePolicyKey
    version: NonNegativeInt
    content_sha256: Sha256Hex
    semantic_fingerprint_sha256: Sha256Hex

    @property
    def fingerprint_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class EquivalenceItem(StrictModel):
    artifact_key: SafePolicyKey
    comparison_mode: ComparisonMode
    before_version: NonNegativeInt | None
    after_version: NonNegativeInt | None
    before_fingerprint_sha256: Sha256Hex | None
    after_fingerprint_sha256: Sha256Hex | None
    equivalent: bool
    reason_codes: tuple[SafePolicyKey, ...]
    numeric_atol: FiniteFloat | None = None

    @model_validator(mode="after")
    def _validate_item(self) -> "EquivalenceItem":
        if not self.reason_codes or len(set(self.reason_codes)) != len(
            self.reason_codes
        ):
            raise ValueError("equivalence reasons must be non-empty and unique")
        if self.comparison_mode == "vector":
            if self.numeric_atol != VECTOR_ABSOLUTE_TOLERANCE:
                raise ValueError("vector comparison must use the fixed tolerance")
        elif self.numeric_atol is not None:
            raise ValueError("exact comparison cannot carry a numeric tolerance")
        if (self.before_version is None) != (
            self.before_fingerprint_sha256 is None
        ):
            raise ValueError("before version and fingerprint must appear together")
        if (self.after_version is None) != (self.after_fingerprint_sha256 is None):
            raise ValueError("after version and fingerprint must appear together")
        if self.equivalent and (
            self.before_version is None or self.after_version is None
        ):
            raise ValueError("equivalent artifacts require both sides")
        return self

    @property
    def activation_eligible(self) -> bool:
        if self.equivalent:
            return True
        if self.before_version is None:
            return (
                self.after_version is not None
                and self.reason_codes == ("initial_build",)
            )
        if self.after_version is None:
            return False
        return (
            self.after_version > self.before_version
            and "missing_output" not in self.reason_codes
            and "unversioned_content_change" not in self.reason_codes
        )


class EquivalenceReport(StrictModel):
    """Content-free report safe for durable job metadata and audit logs."""

    items: tuple[EquivalenceItem, ...]
    equivalent: bool
    activation_eligible: bool
    report_sha256: Sha256Hex

    @model_validator(mode="after")
    def _validate_report(self) -> "EquivalenceReport":
        keys = tuple(item.artifact_key for item in self.items)
        if not keys or keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("equivalence items must be non-empty, sorted, and unique")
        if self.equivalent != all(item.equivalent for item in self.items):
            raise ValueError("report equivalent flag does not match its items")
        if self.activation_eligible != all(
            item.activation_eligible for item in self.items
        ):
            raise ValueError("report activation flag does not match its items")
        if self.report_sha256 != _report_sha256(self.items):
            raise ValueError("equivalence report hash mismatch")
        return self


def _report_sha256(items: tuple[EquivalenceItem, ...]) -> str:
    return hashlib.sha256(_report_bytes(items)).hexdigest()


def _report_bytes(items: tuple[EquivalenceItem, ...]) -> bytes:
    return canonical_json_bytes(
        {
            "domain": "consultation_kb.rebuild_equivalence.v1",
            "items": [item.model_dump(mode="json") for item in items],
        }
    )


def equivalence_report_bytes(report: EquivalenceReport) -> bytes:
    """Return the exact content-addressed, body-free audit payload."""

    exact = EquivalenceReport.model_validate(report)
    payload = _report_bytes(exact.items)
    if hashlib.sha256(payload).hexdigest() != exact.report_sha256:
        raise EquivalenceError("REBUILD_EQUIVALENCE_REPORT_HASH_MISMATCH")
    return payload


def make_equivalence_report(
    items: tuple[EquivalenceItem, ...],
) -> EquivalenceReport:
    ordered = tuple(sorted(items, key=lambda item: item.artifact_key))
    return EquivalenceReport(
        items=ordered,
        equivalent=all(item.equivalent for item in ordered),
        activation_eligible=all(item.activation_eligible for item in ordered),
        report_sha256=_report_sha256(ordered),
    )


def compare_artifact_sets(
    before: tuple[ArtifactFingerprint, ...],
    after: tuple[ArtifactFingerprint, ...],
) -> EquivalenceReport:
    """Compare exact/profile/wiki/graph/FTS/case fingerprints by stable key."""

    before_by_key = _unique_fingerprints(before)
    after_by_key = _unique_fingerprints(after)
    items: list[EquivalenceItem] = []
    for key in sorted(set(before_by_key) | set(after_by_key)):
        old = before_by_key.get(key)
        new = after_by_key.get(key)
        if old is None:
            if new is None:  # pragma: no cover - the key comes from the union
                raise AssertionError("unreachable empty equivalence key")
            items.append(
                EquivalenceItem(
                    artifact_key=key,
                    comparison_mode="exact",
                    before_version=None,
                    after_version=new.version,
                    before_fingerprint_sha256=None,
                    after_fingerprint_sha256=new.fingerprint_sha256,
                    equivalent=False,
                    reason_codes=("initial_build",),
                )
            )
            continue
        if new is None:
            items.append(
                EquivalenceItem(
                    artifact_key=key,
                    comparison_mode="exact",
                    before_version=old.version,
                    after_version=None,
                    before_fingerprint_sha256=old.fingerprint_sha256,
                    after_fingerprint_sha256=None,
                    equivalent=False,
                    reason_codes=("missing_output",),
                )
            )
            continue
        content_equivalent = (
            old.content_sha256 == new.content_sha256
            and old.semantic_fingerprint_sha256
            == new.semantic_fingerprint_sha256
        )
        reasons: list[str] = []
        if content_equivalent:
            reasons.append(
                "exact_match"
                if new.version == old.version
                else "content_equivalent_new_version"
            )
        else:
            if new.version != old.version:
                reasons.append("version_changed")
            if new.content_sha256 != old.content_sha256:
                reasons.append("content_hash_changed")
            if (
                new.semantic_fingerprint_sha256
                != old.semantic_fingerprint_sha256
            ):
                reasons.append("semantic_fingerprint_changed")
            if new.version == old.version:
                reasons.append("unversioned_content_change")
        items.append(
            EquivalenceItem(
                artifact_key=key,
                comparison_mode="exact",
                before_version=old.version,
                after_version=new.version,
                before_fingerprint_sha256=old.fingerprint_sha256,
                after_fingerprint_sha256=new.fingerprint_sha256,
                equivalent=content_equivalent,
                reason_codes=tuple(reasons),
            )
        )
    return make_equivalence_report(tuple(items))


def _unique_fingerprints(
    values: tuple[ArtifactFingerprint, ...],
) -> dict[str, ArtifactFingerprint]:
    result: dict[str, ArtifactFingerprint] = {}
    for raw in values:
        value = ArtifactFingerprint.model_validate(raw)
        if value.artifact_key in result:
            raise EquivalenceError("REBUILD_EQUIVALENCE_DUPLICATE_ARTIFACT")
        result[value.artifact_key] = value
    return result


@dataclass(frozen=True)
class VectorSnapshot:
    """Transient vector data used for comparison; never embedded in the report."""

    artifact_key: str
    version: int
    model_descriptor_sha256: str
    file_sha256s: tuple[str, ...]
    embeddings: npt.NDArray[np.floating[Any]]
    top_k_rankings: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        ArtifactFingerprint(
            artifact_key=self.artifact_key,
            version=self.version,
            content_sha256=self.model_descriptor_sha256,
            semantic_fingerprint_sha256=self.model_descriptor_sha256,
        )
        if not self.file_sha256s or any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in self.file_sha256s
        ):
            raise ValueError("vector file hashes must be canonical sha256 values")
        array = np.array(self.embeddings, copy=True)
        if array.ndim != 2 or not np.issubdtype(array.dtype, np.floating):
            raise ValueError("vector embeddings must be a two-dimensional float array")
        if not np.isfinite(array).all():
            raise ValueError("vector embeddings must be finite")
        if not self.top_k_rankings or any(
            not ranking
            or any(type(item) is not str or not item for item in ranking)
            for ranking in self.top_k_rankings
        ):
            raise ValueError("vector rankings must be non-empty")
        if tuple(sorted(self.file_sha256s)) != self.file_sha256s or len(
            set(self.file_sha256s)
        ) != len(self.file_sha256s):
            raise ValueError("vector file hashes must be sorted and unique")
        array.setflags(write=False)
        object.__setattr__(self, "embeddings", array)

    @property
    def fingerprint_sha256(self) -> str:
        array = np.ascontiguousarray(self.embeddings)
        numeric_sha256 = hashlib.sha256(
            canonical_sha256(
                {"shape": list(array.shape), "dtype": str(array.dtype)}
            ).encode("ascii")
            + array.tobytes(order="C")
        ).hexdigest()
        return canonical_sha256(
            {
                "artifact_key": self.artifact_key,
                "version": self.version,
                "model_descriptor_sha256": self.model_descriptor_sha256,
                "file_sha256s": list(self.file_sha256s),
                "numeric_sha256": numeric_sha256,
                "ranking_sha256": canonical_sha256(self.top_k_rankings),
            }
        )


def compare_vector_snapshots(
    before: VectorSnapshot,
    after: VectorSnapshot,
) -> EquivalenceReport:
    old = before
    new = after
    if old.artifact_key != new.artifact_key:
        raise EquivalenceError("REBUILD_VECTOR_ARTIFACT_KEY_MISMATCH")
    same_shape = old.embeddings.shape == new.embeddings.shape
    numeric_equal = same_shape and bool(
        np.allclose(
            old.embeddings,
            new.embeddings,
            rtol=0.0,
            atol=VECTOR_ABSOLUTE_TOLERANCE,
            equal_nan=False,
        )
    )
    model_equal = old.model_descriptor_sha256 == new.model_descriptor_sha256
    files_equal = old.file_sha256s == new.file_sha256s
    ranking_equal = old.top_k_rankings == new.top_k_rankings
    version_equal = old.version == new.version
    content_equivalent = (
        numeric_equal
        and model_equal
        and files_equal
        and ranking_equal
    )
    reasons: list[str] = []
    if content_equivalent:
        if version_equal and old.fingerprint_sha256 == new.fingerprint_sha256:
            reasons.append("exact_match")
        elif not version_equal:
            reasons.append("content_equivalent_new_version")
        else:
            reasons.append("numeric_within_tolerance")
    else:
        if not version_equal:
            reasons.append("version_changed")
        if not model_equal:
            reasons.append("model_descriptor_changed")
        if not files_equal:
            reasons.append("file_hash_changed")
        if not same_shape:
            reasons.append("embedding_shape_changed")
        elif not numeric_equal:
            reasons.append("embedding_values_changed")
        if not ranking_equal:
            reasons.append("top_k_ranking_changed")
    item = EquivalenceItem(
        artifact_key=old.artifact_key,
        comparison_mode="vector",
        before_version=old.version,
        after_version=new.version,
        before_fingerprint_sha256=old.fingerprint_sha256,
        after_fingerprint_sha256=new.fingerprint_sha256,
        equivalent=content_equivalent,
        reason_codes=tuple(reasons),
        numeric_atol=VECTOR_ABSOLUTE_TOLERANCE,
    )
    return make_equivalence_report((item,))


__all__ = [
    "VECTOR_ABSOLUTE_TOLERANCE",
    "ArtifactFingerprint",
    "ComparisonMode",
    "EquivalenceError",
    "EquivalenceItem",
    "EquivalenceReport",
    "VectorSnapshot",
    "compare_artifact_sets",
    "compare_vector_snapshots",
    "equivalence_report_bytes",
    "make_equivalence_report",
]
