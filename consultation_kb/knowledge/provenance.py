"""Deterministic provenance closure and cycle prevention."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from contextlib import nullcontext
import json
import sqlite3

from pydantic import field_validator, model_validator

from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.evidence import Provenance, ProvenanceScope
from consultation_kb.storage.connection import transaction


class ProvenanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _ref_key(value: VersionRef) -> tuple[str, int, str]:
    return value.object_id, value.version, value.content_sha256


class ProvenancePolicyManifest(StrictModel):
    manifest_ref: VersionRef
    rule_members: tuple[VersionRef, ...]

    @field_validator("rule_members")
    @classmethod
    def _canonical_rules(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        keys = [_ref_key(item) for item in value]
        if not value or len(keys) != len(set(keys)):
            raise ValueError("provenance policy members must be non-empty and unique")
        return tuple(sorted(value, key=_ref_key))


class ProvenanceEdge(StrictModel):
    source_ref: VersionRef
    target_ref: VersionRef
    relation: str
    derivation_rule_ref: VersionRef

    @model_validator(mode="after")
    def _no_self_loop(self) -> "ProvenanceEdge":
        if _ref_key(self.source_ref) == _ref_key(self.target_ref):
            raise ValueError("provenance self-loop is forbidden")
        return self


class ProvenanceClosure:
    def __init__(self, policy_manifest: ProvenancePolicyManifest) -> None:
        self._manifest = ProvenancePolicyManifest.model_validate(policy_manifest)
        self._approved_rules = frozenset(_ref_key(item) for item in self._manifest.rule_members)

    @staticmethod
    def assert_acyclic(edges: Iterable[ProvenanceEdge]) -> None:
        graph: dict[tuple[str, int, str], set[tuple[str, int, str]]] = defaultdict(set)
        nodes: set[tuple[str, int, str]] = set()
        for edge in edges:
            validated = ProvenanceEdge.model_validate(edge)
            source = _ref_key(validated.source_ref)
            target = _ref_key(validated.target_ref)
            graph[source].add(target)
            nodes.update((source, target))

        visiting: set[tuple[str, int, str]] = set()
        visited: set[tuple[str, int, str]] = set()

        def visit(node: tuple[str, int, str]) -> None:
            if node in visiting:
                raise ProvenanceError("PROVENANCE_CYCLE")
            if node in visited:
                return
            visiting.add(node)
            for child in sorted(graph.get(node, set())):
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for node in sorted(nodes):
            visit(node)

    def compute(
        self,
        inputs: Iterable[Provenance],
        *,
        derivation_rule_ref: VersionRef,
        target_scope: ProvenanceScope | None = None,
    ) -> Provenance:
        values = tuple(Provenance.model_validate(value) for value in inputs)
        if not values:
            raise ProvenanceError("PROVENANCE_INPUT_REQUIRED")
        rule = VersionRef.model_validate(derivation_rule_ref)
        if _ref_key(rule) not in self._approved_rules:
            raise ProvenanceError("DERIVATION_RULE_NOT_APPROVED")

        source_ids = frozenset().union(*(item.source_ids for item in values))
        passage_ids = frozenset().union(*(item.passage_ids for item in values))
        case_ids = frozenset().union(*(item.case_ids for item in values))
        client_ids = frozenset().union(*(item.client_ids for item in values))
        contributors = frozenset().union(
            *(item.case_contributor_client_ids for item in values)
        )
        owners = frozenset(
            item.private_owner_client_id
            for item in values
            if item.private_owner_client_id is not None
        )

        if target_scope is None:
            if source_ids and case_ids:
                scope: ProvenanceScope = "mixed"
            elif source_ids:
                scope = "global_source"
            elif case_ids:
                scope = "case_derived"
            else:
                scope = "client_private"
        else:
            scope = target_scope

        owner: str | None = None
        if scope == "client_private":
            if len(owners) != 1 or source_ids or case_ids or contributors:
                raise ProvenanceError("PRIVATE_PROVENANCE_SCOPE_VIOLATION")
            owner = next(iter(owners))
            client_ids = frozenset({owner})
        elif owners:
            # Raw private material cannot silently become global/case knowledge.
            raise ProvenanceError("PRIVATE_PROVENANCE_CANNOT_ESCAPE")

        if scope in {"case_derived", "mixed"}:
            if not contributors or client_ids != contributors:
                raise ProvenanceError("CASE_CONTRIBUTOR_CLOSURE_MISMATCH")

        try:
            return Provenance(
                source_ids=source_ids,
                passage_ids=passage_ids,
                case_ids=case_ids,
                client_ids=client_ids,
                provenance_scope=scope,
                private_owner_client_id=owner,
                case_contributor_client_ids=contributors,
                derivation_rule_ref=rule,
            )
        except ValueError as exc:
            raise ProvenanceError("PROVENANCE_SCOPE_MATRIX_INVALID") from exc


class ProvenanceRepository:
    """Write exact, policy-bound lineage edges after resolving both versions."""

    _HASH_QUERIES = {
        "source": "SELECT content_sha256 FROM source_versions WHERE source_id = ? AND version = ?",
        "passage": "SELECT normalized_text_sha256 FROM passages WHERE passage_id = ? AND version = ?",
        "claim": "SELECT claim_sha256 FROM claims WHERE claim_id = ? AND version = ?",
        "theory": "SELECT revision_sha256 FROM theory_revisions WHERE theory_id = ? AND revision = ?",
        "wiki": "SELECT body_sha256 FROM wiki_revisions WHERE wiki_id = ? AND revision = ?",
        "artifact": "SELECT metadata_sha256 FROM artifact_versions WHERE artifact_id = ? AND version = ?",
    }

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        policy_manifest: ProvenancePolicyManifest,
        allowed_relations: Iterable[str],
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("provenance repository requires sqlite3.Connection")
        self._connection = connection
        self._policy = ProvenancePolicyManifest.model_validate(policy_manifest)
        self._closure = ProvenanceClosure(self._policy)
        self._allowed_relations = frozenset(allowed_relations)
        if not self._allowed_relations or any(
            type(item) is not str or not item for item in self._allowed_relations
        ):
            raise ProvenanceError("PROVENANCE_RELATION_POLICY_INVALID")

    def add(
        self,
        edge: ProvenanceEdge,
        *,
        source_type: str,
        target_type: str,
        target_provenance: Provenance,
    ) -> ProvenanceEdge:
        validated = ProvenanceEdge.model_validate(edge)
        lineage = Provenance.model_validate(target_provenance)
        if validated.relation not in self._allowed_relations:
            raise ProvenanceError("PROVENANCE_RELATION_NOT_APPROVED")
        if validated.derivation_rule_ref != lineage.derivation_rule_ref:
            raise ProvenanceError("PROVENANCE_DERIVATION_RULE_MISMATCH")
        approved = {_ref_key(item) for item in self._policy.rule_members}
        if _ref_key(validated.derivation_rule_ref) not in approved:
            raise ProvenanceError("DERIVATION_RULE_NOT_APPROVED")
        self._assert_exact_ref(source_type, validated.source_ref)
        self._assert_exact_ref(target_type, validated.target_ref)
        self._assert_target_provenance(target_type, validated.target_ref, lineage)
        existing = self._load_edges()
        self._closure.assert_acyclic((*existing, validated))
        context = (
            nullcontext(self._connection)
            if self._connection.in_transaction
            else transaction(self._connection)
        )
        try:
            with context:
                self._connection.execute(
                    """
                    INSERT INTO provenance_edges(
                        from_type, from_id, from_version, relation,
                        to_type, to_id, to_version, derivation_rule_ref_json,
                        source_client_ids_json, source_case_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_type,
                        validated.source_ref.object_id,
                        validated.source_ref.version,
                        validated.relation,
                        target_type,
                        validated.target_ref.object_id,
                        validated.target_ref.version,
                        validated.derivation_rule_ref.model_dump_json(),
                        json.dumps(sorted(lineage.client_ids), separators=(",", ":")),
                        json.dumps(sorted(lineage.case_ids), separators=(",", ":")),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ProvenanceError("PROVENANCE_EDGE_CONFLICT") from exc
        return validated

    def _assert_exact_ref(self, object_type: str, reference: VersionRef) -> None:
        query = self._HASH_QUERIES.get(object_type)
        if query is None:
            raise ProvenanceError("PROVENANCE_OBJECT_TYPE_INVALID")
        row = self._connection.execute(
            query, (reference.object_id, reference.version)
        ).fetchone()
        if row is None:
            raise ProvenanceError("PROVENANCE_OBJECT_VERSION_NOT_FOUND")
        if str(row[0]) != reference.content_sha256:
            raise ProvenanceError("PROVENANCE_OBJECT_HASH_MISMATCH")

    def _load_edges(self) -> tuple[ProvenanceEdge, ...]:
        values: list[ProvenanceEdge] = []
        rows = self._connection.execute(
            """
            SELECT from_type, from_id, from_version, relation,
                   to_type, to_id, to_version, derivation_rule_ref_json
              FROM provenance_edges
            """
        ).fetchall()
        for row in rows:
            source = self._resolved_ref(str(row[0]), str(row[1]), int(row[2]))
            target = self._resolved_ref(str(row[4]), str(row[5]), int(row[6]))
            try:
                rule = VersionRef.model_validate_json(str(row[7]))
                if (
                    str(row[3]) not in self._allowed_relations
                    or _ref_key(rule)
                    not in {_ref_key(item) for item in self._policy.rule_members}
                ):
                    raise ProvenanceError("PROVENANCE_EDGE_POLICY_MISMATCH")
                values.append(
                    ProvenanceEdge(
                        source_ref=source,
                        target_ref=target,
                        relation=str(row[3]),
                        derivation_rule_ref=rule,
                    )
                )
            except ValueError:
                raise ProvenanceError("PROVENANCE_EDGE_CORRUPT") from None
        return tuple(values)

    def _assert_target_provenance(
        self,
        object_type: str,
        reference: VersionRef,
        expected: Provenance,
    ) -> None:
        query = {
            "passage": "SELECT provenance_json FROM passages WHERE passage_id = ? AND version = ?",
            "claim": "SELECT provenance_json FROM claims WHERE claim_id = ? AND version = ?",
        }.get(object_type)
        if query is None:
            return
        row = self._connection.execute(
            query, (reference.object_id, reference.version)
        ).fetchone()
        if row is None:
            raise ProvenanceError("PROVENANCE_OBJECT_VERSION_NOT_FOUND")
        try:
            actual = Provenance.model_validate_json(str(row[0]))
        except ValueError:
            raise ProvenanceError("PROVENANCE_TARGET_CLOSURE_INVALID") from None
        if actual != expected:
            raise ProvenanceError("PROVENANCE_TARGET_CLOSURE_MISMATCH")

    def _resolved_ref(self, object_type: str, object_id: str, version: int) -> VersionRef:
        query = self._HASH_QUERIES.get(object_type)
        if query is None:
            raise ProvenanceError("PROVENANCE_OBJECT_TYPE_INVALID")
        row = self._connection.execute(query, (object_id, version)).fetchone()
        if row is None:
            raise ProvenanceError("PROVENANCE_OBJECT_VERSION_NOT_FOUND")
        return VersionRef(
            object_id=object_id,
            version=version,
            content_sha256=str(row[0]),
        )


__all__ = [
    "ProvenanceClosure",
    "ProvenanceEdge",
    "ProvenanceError",
    "ProvenancePolicyManifest",
    "ProvenanceRepository",
]
