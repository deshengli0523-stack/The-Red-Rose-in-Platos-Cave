"""Read-only catalog and manifest lint for governed knowledge."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

from consultation_kb.models.lint import LintFinding, LintReport, LintSeverity

from .anchors import deterministic_object_id


_EMPIRICAL = {
    "unassessed",
    "case_supported",
    "observation_supported",
    "empirically_supported",
    "guideline_consistent",
    "conflicting",
}
_RELATIONSHIPS = {
    "CITES",
    "SUPPORTS",
    "CONTRADICTS",
    "INTERPRETS",
    "DERIVED_FROM",
    "APPLIES_TO",
    "NOT_APPLICABLE_TO",
    "ANALOGOUS_TO",
    "DISTINCT_FROM",
    "CONTRAINDICATED_FOR",
    "REQUIRES_REFERRAL",
    "EXEMPLIFIED_BY",
    "SUPERSEDES",
}


class KnowledgeLinter:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        now: datetime | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("knowledge linter requires sqlite3.Connection")
        self._connection = connection
        self._now = now or datetime.now(timezone.utc)

    def _finding(
        self,
        object_id: object,
        version: object,
        rule: str,
        severity: LintSeverity,
        summary: str,
    ) -> LintFinding:
        candidate = str(object_id)
        if "_" not in candidate:
            candidate = deterministic_object_id("lint_object", rule, candidate)
        try:
            value_version = int(str(version))
        except (TypeError, ValueError):
            value_version = 1
        if value_version < 1:
            value_version = 1
        try:
            return LintFinding(
                object_id=candidate,
                object_version=value_version,
                rule=rule,
                severity=severity,
                summary=summary,
            )
        except ValueError:
            return LintFinding(
                object_id=deterministic_object_id("lint_object", rule, candidate),
                object_version=value_version,
                rule=rule,
                severity=severity,
                summary=summary,
            )

    def run(self, catalog_version: int | None = None) -> LintReport:
        row = self._connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int:
            raise ValueError("current catalog version is unavailable")
        current_catalog_version = int(row[0])
        if catalog_version is not None and catalog_version != current_catalog_version:
            raise ValueError("catalog version does not match the current catalog")
        catalog_version = current_catalog_version
        findings: list[LintFinding] = []

        for row in self._connection.execute(
            """
            SELECT c.claim_id, c.version
              FROM claims AS c
             WHERE c.review_status = 'APPROVED'
               AND NOT EXISTS (
                    SELECT 1 FROM claim_evidence AS e
                     WHERE e.claim_id = c.claim_id AND e.claim_version = c.version
               )
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "unsourced_claim", "error", "正式主张缺少原始 Passage 证据")
            )

        for row in self._connection.execute(
            """
            SELECT w.wiki_id, w.revision
              FROM wiki_revisions AS w
             WHERE w.review_status IN ('PREPARED', 'ACTIVE')
               AND EXISTS (
                    SELECT 1 FROM wiki_revision_claims AS wc
                    JOIN claims AS c
                      ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
                   WHERE wc.wiki_id = w.wiki_id AND wc.wiki_revision = w.revision
                     AND c.review_due_at IS NOT NULL AND c.review_due_at <= ?
               )
            """,
            (_utc(self._now),),
        ):
            findings.append(
                self._finding(row[0], row[1], "stale_wiki", "warning", "Wiki 引用的主张已经到达复核日期")
            )

        for row in self._connection.execute(
            """
            SELECT c.claim_id, c.version
              FROM claims AS c
             WHERE c.review_status = 'APPROVED'
               AND c.empirical_support = 'conflicting'
               AND NOT EXISTS (
                    SELECT 1 FROM wiki_revision_claims AS wc
                     WHERE wc.claim_id = c.claim_id AND wc.claim_version = c.version
                       AND wc.stance = 'OPPOSE'
               )
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "unexplained_conflict", "warning", "冲突证据尚未在 Wiki 中并列说明")
            )

        for row in self._connection.execute(
            """
            SELECT w.wiki_id, w.revision
              FROM wiki_revisions AS w
             WHERE w.review_status IN ('PREPARED', 'ACTIVE')
               AND NOT EXISTS (
                    SELECT 1 FROM wiki_revision_claims AS wc
                     WHERE wc.wiki_id = w.wiki_id AND wc.wiki_revision = w.revision
               )
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "orphan_wiki_page", "warning", "Wiki 页面没有正式主张入口")
            )

        findings.extend(self._cycle_findings())

        for row in self._connection.execute(
            """
            SELECT c.claim_id, c.version
              FROM claims AS c
             WHERE c.cognitive_type = 'explicit'
               AND EXISTS (
                    SELECT 1 FROM provenance_edges AS p
                     WHERE p.to_id = c.claim_id AND p.to_version = c.version
                       AND p.relation = 'MODEL_INFERENCE'
               )
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "inference_marked_explicit", "warning", "模型推断被标为原文明示")
            )

        for row in self._connection.execute(
            """
            SELECT c.claim_id, c.version
              FROM claims AS c
              LEFT JOIN theory_revisions AS t
                ON t.theory_id = c.theory_revision_id
               AND t.revision = c.theory_revision
               AND t.revision_sha256 = c.theory_revision_sha256
             WHERE c.source_grade = 'C1'
               AND (c.theory_revision_id IS NULL OR t.theory_id IS NULL
                    OR t.approval_request_id IS NULL
                    OR t.status NOT IN ('PREPARED', 'ACTIVE'))
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "invalid_c1_authority", "error", "C1 缺少主咨询师批准的理论修订")
            )

        for row in self._connection.execute(
            """
            SELECT DISTINCT t.theory_id, t.revision
              FROM theory_revisions AS t
              JOIN claims AS c
                ON c.theory_revision_id = t.theory_id
               AND c.theory_revision = t.revision
               AND c.theory_revision_sha256 = t.revision_sha256
             WHERE (t.status = 'ACTIVE' AND c.review_status <> 'APPROVED')
                OR (t.status IN ('REVOKED', 'SUPERSEDED', 'EXPIRED')
                    AND c.review_status = 'APPROVED')
            """
        ):
            findings.append(
                self._finding(row[0], row[1], "revoked_c1_active", "error", "废止或被取代的 C1 仍处于 active")
            )

        for row in self._connection.execute(
            """
            SELECT DISTINCT w.wiki_id, w.revision
              FROM wiki_revisions AS w
              JOIN wiki_revision_claims AS wc
                ON wc.wiki_id = w.wiki_id AND wc.wiki_revision = w.revision
              JOIN claims AS c
                ON c.claim_id = wc.claim_id AND c.version = wc.claim_version
              LEFT JOIN theory_revisions AS t
                ON t.theory_id = c.theory_revision_id
               AND t.revision = c.theory_revision
               AND t.revision_sha256 = c.theory_revision_sha256
             WHERE w.review_status = 'ACTIVE' AND (
                   c.review_status <> 'APPROVED'
                OR c.privacy_scope = 'PRIVATE'
                OR (c.source_grade = 'C1' AND (
                       t.status <> 'ACTIVE' OR t.theory_id IS NULL
                ))
             )
            """
        ):
            findings.append(
                self._finding(
                    row[0],
                    row[1],
                    "active_wiki_authority_invalid",
                    "error",
                    "Active Wiki 引用了不可用、私有或非 active 的权威主张",
                )
            )

        for row in self._connection.execute(
            """
            SELECT claim_id, version FROM claims
             WHERE claim_object_ref <> 'sha256:' || claim_sha256
            UNION ALL
            SELECT wiki_id, revision FROM wiki_revisions
             WHERE body_object_ref <> 'sha256:' || body_sha256
                OR diff_object_ref <> 'sha256:' || diff_sha256
            """
        ):
            findings.append(
                self._finding(
                    row[0], row[1], "invalid_content_ref", "error", "正文引用与内容哈希不一致"
                )
            )

        for row in self._connection.execute(
            """
            SELECT DISTINCT w.wiki_id, w.revision
              FROM wiki_revisions AS w
              JOIN wiki_revision_claims AS wc
                ON wc.wiki_id = w.wiki_id AND wc.wiki_revision = w.revision
              JOIN claim_evidence AS ce
                ON ce.claim_id = wc.claim_id AND ce.claim_version = wc.claim_version
              JOIN passages AS p
                ON p.passage_id = ce.passage_id AND p.version = ce.passage_version
             WHERE w.review_status = 'ACTIVE' AND p.privacy_scope = 'PRIVATE'
            """
        ):
            findings.append(
                self._finding(
                    row[0], row[1], "active_wiki_private_evidence", "error", "Active Wiki 引用了私有 Passage"
                )
            )

        for row in self._connection.execute(
            """
            SELECT claim_id, version FROM claims
             WHERE source_grade = 'C1' AND empirical_support NOT IN (?, ?, ?, ?, ?, ?)
            """,
            tuple(sorted(_EMPIRICAL)),
        ):
            findings.append(
                self._finding(row[0], row[1], "c1_empirical_conflation", "error", "C1 框架权威与外部实证状态被混写")
            )

        for row in self._connection.execute(
            """
            SELECT source_id, version, metadata_json FROM source_versions
             WHERE source_grade IN ('L1', 'L2', 'L3')
            """
        ):
            try:
                due = json.loads(str(row[2])).get("review_due_at")
                if due is not None and str(due) <= _utc(self._now):
                    findings.append(
                        self._finding(row[0], row[1], "stale_time_sensitive_source", "warning", "时效资料已经超过复核日期")
                    )
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                findings.append(
                    self._finding(row[0], row[1], "stale_time_sensitive_source", "warning", "时效资料的复核元数据无效")
                )

        for row in self._connection.execute(
            "SELECT claim_id, version, provenance_json FROM claims WHERE source_grade = 'K3'"
        ):
            try:
                case_ids = json.loads(str(row[2])).get("case_ids", [])
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                case_ids = []
            if len(case_ids) < 2:
                findings.append(
                    self._finding(row[0], row[1], "single_case_pattern", "warning", "案例模式不足两个独立案例")
                )

        for row in self._connection.execute(
            """
            SELECT to_id, to_version, relation, derivation_rule_ref_json
              FROM provenance_edges WHERE relation IN (
                'CITES','SUPPORTS','CONTRADICTS','INTERPRETS','DERIVED_FROM',
                'APPLIES_TO','NOT_APPLICABLE_TO','ANALOGOUS_TO','DISTINCT_FROM',
                'CONTRAINDICATED_FOR','REQUIRES_REFERRAL','EXEMPLIFIED_BY','SUPERSEDES'
              )
            """
        ):
            try:
                metadata = json.loads(str(row[3]))
            except (TypeError, ValueError, json.JSONDecodeError):
                metadata = {}
            if not isinstance(metadata, dict) or not {
                "object_id",
                "version",
                "content_sha256",
            }.issubset(metadata):
                findings.append(
                    self._finding(row[0], row[1], "relationship_metadata_incomplete", "warning", "关系缺少批准的范围、来源或审核元数据")
                )

        for row in self._connection.execute(
            """
            SELECT artifact_id, version FROM artifact_versions
             WHERE state = 'CURRENT' AND source_catalog_version <> ?
            """,
            (catalog_version,),
        ):
            findings.append(
                self._finding(row[0], row[1], "artifact_metadata_mismatch", "error", "派生工件与目录版本不一致")
            )

        return LintReport(
            catalog_version=catalog_version,
            findings=tuple(
                sorted(
                    findings,
                    key=lambda item: (
                        item.severity,
                        item.rule,
                        item.object_id,
                        item.object_version,
                    ),
                )
            ),
        )

    def _cycle_findings(self) -> tuple[LintFinding, ...]:
        rows = self._connection.execute(
            """
            SELECT from_id, from_version, to_id, to_version
              FROM provenance_edges WHERE relation = 'DERIVED_FROM'
            """
        ).fetchall()
        graph: dict[tuple[str, int], set[tuple[str, int]]] = defaultdict(set)
        for row in rows:
            graph[(str(row[0]), int(row[1]))].add((str(row[2]), int(row[3])))
        visiting: list[tuple[str, int]] = []
        visited: set[tuple[str, int]] = set()
        cyclic: set[tuple[str, int]] = set()

        def visit(node: tuple[str, int]) -> None:
            if node in visiting:
                cyclic.update(visiting[visiting.index(node) :])
                return
            if node in visited:
                return
            visiting.append(node)
            for child in sorted(graph.get(node, set())):
                visit(child)
            visiting.pop()
            visited.add(node)

        for node in sorted(graph):
            visit(node)
        return tuple(
            self._finding(node[0], node[1], "cyclic_evidence", "error", "派生证据形成循环")
            for node in sorted(cyclic)
        )


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = ["KnowledgeLinter"]
