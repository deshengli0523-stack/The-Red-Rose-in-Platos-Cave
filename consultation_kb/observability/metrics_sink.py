"""Append-only shared metrics containing only numbers, enums, hashes, and refs."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Final, Literal, TypeAlias, cast

from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
)
from consultation_kb.observability.audit import (
    ObservabilityCorruptionError,
    ObservabilityStoreError,
    _append_line,
    _canonical_json_line,
    _exclusive_store_lock,
    _load_records,
)


MetricName: TypeAlias = Literal[
    "archive_completion",
    "candidate_count",
    "degraded_component_count",
    "evaluation_score",
    "filter_denied_count",
    "retrieval_latency_ms",
    "retry_count",
    "run_latency_ms",
    "selected_evidence_count",
]
MetricUnit: TypeAlias = Literal["bytes", "count", "milliseconds", "ratio", "score"]
MetricDimensionName: TypeAlias = Literal[
    "degraded_component",
    "evaluation_split",
    "route",
    "run_kind",
    "run_phase",
    "status",
]
MetricDimensionValue: TypeAlias = Literal[
    "actual_reply",
    "approval",
    "archive",
    "cancelled",
    "case",
    "client_history",
    "consultation_reply",
    "dedicated_venv",
    "degraded",
    "dev",
    "evaluation",
    "failed",
    "final_candidate",
    "generation",
    "generation_stage",
    "global_graph",
    "lexical",
    "model",
    "policy",
    "profile",
    "query",
    "reranker",
    "retrieval",
    "risk",
    "storage",
    "succeeded",
    "test",
    "train",
    "canary",
    "vector",
    "wiki",
]


_DIMENSION_VALUES: Final[dict[MetricDimensionName, frozenset[str]]] = {
    "degraded_component": frozenset(
        {
            "approval",
            "archive",
            "case",
            "generation",
            "global_graph",
            "lexical",
            "model",
            "policy",
            "reranker",
            "retrieval",
            "risk",
            "storage",
            "vector",
            "wiki",
        }
    ),
    "evaluation_split": frozenset({"train", "dev", "test", "canary"}),
    "route": frozenset(
        {"profile", "client_history", "wiki", "lexical", "vector", "global_graph", "case"}
    ),
    "run_kind": frozenset({"consultation_reply", "archive", "evaluation"}),
    "run_phase": frozenset(
        {
            "query",
            "retrieval",
            "generation_stage",
            "final_candidate",
            "actual_reply",
            "archive",
            "evaluation",
        }
    ),
    "status": frozenset({"succeeded", "failed", "degraded", "cancelled"}),
}
_METRIC_UNITS: Final[dict[MetricName, MetricUnit]] = {
    "archive_completion": "count",
    "candidate_count": "count",
    "degraded_component_count": "count",
    "evaluation_score": "score",
    "filter_denied_count": "count",
    "retrieval_latency_ms": "milliseconds",
    "retry_count": "count",
    "run_latency_ms": "milliseconds",
    "selected_evidence_count": "count",
}


class MetricDimension(StrictModel):
    name: MetricDimensionName
    value: MetricDimensionValue

    @model_validator(mode="after")
    def _registered_pair(self) -> "MetricDimension":
        if self.value not in _DIMENSION_VALUES[self.name]:
            raise ValueError("metric dimension value is not registered for its name")
        return self


class MetricPointV1(StrictModel):
    """One shared aggregate point with no arbitrary label or prose channel."""

    schema_version: Literal["1.0"] = "1.0"
    metric_id: ObjectId
    run_id: Uuid7String
    root_run_id: Uuid7String
    parent_run_id: Uuid7String | None
    occurred_at: UtcDateTime
    scope_bucket_sha256: Sha256Hex
    name: MetricName
    value: int | float
    unit: MetricUnit
    dimensions: tuple[MetricDimension, ...]

    @field_validator("value", mode="before")
    @classmethod
    def _exact_number(cls, value: Any) -> int | float:
        if type(value) not in {int, float}:
            raise ValueError("metric value must be an exact integer or float")
        return cast(int | float, value)

    @field_validator("dimensions")
    @classmethod
    def _canonical_dimensions(
        cls,
        value: tuple[MetricDimension, ...],
    ) -> tuple[MetricDimension, ...]:
        names = tuple(item.name for item in value)
        if len(names) != len(set(names)):
            raise ValueError("metric dimensions must use unique names")
        return tuple(sorted(value, key=lambda item: item.name))

    @model_validator(mode="after")
    def _metric_contract(self) -> "MetricPointV1":
        numeric = float(self.value)
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError("metric value must be finite and non-negative")
        if self.unit != _METRIC_UNITS[self.name]:
            raise ValueError("metric unit does not match metric registry")
        if self.unit == "count" and type(self.value) is not int:
            raise ValueError("count metrics require exact integers")
        if self.unit in {"ratio", "score"} and numeric > 1:
            raise ValueError("ratio and score metrics must be between zero and one")
        if self.parent_run_id is None:
            if self.root_run_id != self.run_id:
                raise ValueError("root metric point must identify its run as root")
        elif self.parent_run_id == self.run_id:
            raise ValueError("child metric point must identify a distinct parent")
        return self


MetricPoint: TypeAlias = MetricPointV1
_METRIC_MODELS: Final[dict[str, type[MetricPointV1]]] = {"1.0": MetricPointV1}


class MetricsSink:
    """Locked canonical shared aggregate store; client detail belongs elsewhere."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("metrics path must be pathlib.Path")
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def emit(self, point: MetricPoint) -> None:
        validated = MetricPointV1.model_validate(point)
        with _exclusive_store_lock(self._path):
            existing = self._load_unlocked()
            if any(item.metric_id == validated.metric_id for item in existing):
                raise ObservabilityStoreError("metric ID is already present")
            _append_line(self._path, _canonical_json_line(validated))

    def load(self) -> tuple[MetricPointV1, ...]:
        with _exclusive_store_lock(self._path):
            return self._load_unlocked()

    def _load_unlocked(self) -> tuple[MetricPointV1, ...]:
        records = _load_records(self._path, _METRIC_MODELS)
        metric_ids = tuple(record.metric_id for record in records)
        if len(metric_ids) != len(set(metric_ids)):
            raise ObservabilityCorruptionError("metrics stream contains a duplicate metric ID")
        return records


__all__ = [
    "MetricDimension",
    "MetricDimensionName",
    "MetricDimensionValue",
    "MetricName",
    "MetricPoint",
    "MetricPointV1",
    "MetricUnit",
    "MetricsSink",
]
