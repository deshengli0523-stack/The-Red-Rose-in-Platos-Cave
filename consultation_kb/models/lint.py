"""Structured knowledge lint and invalidation contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import field_serializer

from .common import NonEmptyStr, ObjectId, PositiveInt, SafePolicyKey, StrictModel, UtcDateTime


LintSeverity = Literal["error", "warning", "info"]


class LintFinding(StrictModel):
    object_id: ObjectId
    object_version: PositiveInt
    rule: SafePolicyKey
    severity: LintSeverity
    summary: NonEmptyStr


class LintReport(StrictModel):
    catalog_version: int
    findings: tuple[LintFinding, ...]

    @property
    def has_errors(self) -> bool:
        return any(item.severity == "error" for item in self.findings)


class RebuildRequest(StrictModel):
    queue_id: ObjectId
    upstream_type: SafePolicyKey
    upstream_id: ObjectId
    catalog_version: int
    required_outputs: frozenset[Literal["wiki", "graph", "bm25", "vector"]]
    reason: SafePolicyKey
    created_at: UtcDateTime

    @field_serializer("required_outputs")
    def _serialize_outputs(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


__all__ = ["LintFinding", "LintReport", "LintSeverity", "RebuildRequest"]
