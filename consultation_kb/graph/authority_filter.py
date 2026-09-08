"""Live authority prefilter for immutable global-graph artifacts."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pydantic import model_validator

from consultation_kb.graph.global_builder import (
    GlobalGraphArtifact,
    verify_global_graph_artifact,
)
from consultation_kb.models.common import (
    ClientId,
    NonNegativeInt,
    PositiveInt,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    ProvenanceScope,
    RetrievalScope,
)


class GraphAuthoritySnapshotError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GraphAuthorityBinding:
    run_id: str
    global_runtime_epoch: int
    client_runtime_epoch: int
    tombstone_epoch: int
    authorization_epoch: int
    policy_ref: VersionRef
    created_at: datetime
    artifact_sha256: str
    graph_root_ref: VersionRef
    graph_version: VersionRef
    required_use: str
    scope_sha256: str
    allowed_relation_refs: tuple[VersionRef, ...]
    authority_record_refs: tuple[VersionRef, ...]
    decision_sha256: str


class GraphLeaveOneOutGrant(StrictModel):
    """Internal grant selecting one exact replacement for one contributor."""

    excluded_client_id: ClientId
    replacement_relation_ref: VersionRef

    @model_validator(mode="after")
    def _validate_ref(self) -> "GraphLeaveOneOutGrant":
        if _object_kind(self.replacement_relation_ref) != "graph_edge":
            raise ValueError("leave-one-out replacement must be a graph edge")
        return self


class GraphEdgeAuthorityRecord(StrictModel):
    """Metadata-only provenance authority; never returned by graph queries."""

    authority_ref: VersionRef
    relation_ref: VersionRef
    runtime_epoch: NonNegativeInt
    provenance_scope: ProvenanceScope
    independent_source_count: PositiveInt
    minimum_leave_one_out_sources: PositiveInt = 1
    contributor_client_ids: frozenset[ClientId] = frozenset()
    leave_one_out_grants: tuple[GraphLeaveOneOutGrant, ...] = ()
    leave_one_out_parent_ref: VersionRef | None = None
    excluded_client_ids: frozenset[ClientId] = frozenset()

    @model_validator(mode="after")
    def _validate_record(self) -> "GraphEdgeAuthorityRecord":
        if _object_kind(self.authority_ref) != "graph_edge_authority":
            raise ValueError("graph edge authority reference has invalid kind")
        if _object_kind(self.relation_ref) != "graph_edge":
            raise ValueError("graph edge authority must bind a graph edge")
        if self.provenance_scope == "client_private":
            raise ValueError("client-private edges cannot enter the global graph")
        if self.provenance_scope == "global_source":
            if self.contributor_client_ids:
                raise ValueError("global-source edge cannot have case contributors")
        elif self.provenance_scope in {"case_derived", "mixed"}:
            if not self.contributor_client_ids:
                raise ValueError("case-derived edge requires contributors")
        grant_keys = tuple(
            (
                grant.excluded_client_id,
                grant.replacement_relation_ref.object_id,
                grant.replacement_relation_ref.version,
                grant.replacement_relation_ref.content_sha256,
            )
            for grant in self.leave_one_out_grants
        )
        if grant_keys != tuple(sorted(set(grant_keys))):
            raise ValueError("leave-one-out grants must be unique and canonical")
        if any(
            grant.excluded_client_id not in self.contributor_client_ids
            or grant.replacement_relation_ref == self.relation_ref
            for grant in self.leave_one_out_grants
        ):
            raise ValueError("leave-one-out grant is not bound to a contributor")
        if self.leave_one_out_parent_ref is None:
            if self.excluded_client_ids:
                raise ValueError("primary edge cannot declare excluded clients")
        else:
            if (
                _object_kind(self.leave_one_out_parent_ref) != "graph_edge"
                or not self.excluded_client_ids
                or self.leave_one_out_grants
                or self.excluded_client_ids & self.contributor_client_ids
            ):
                raise ValueError("leave-one-out replacement metadata is invalid")
        expected = graph_edge_authority_sha256(
            relation_ref=self.relation_ref,
            runtime_epoch=self.runtime_epoch,
            provenance_scope=self.provenance_scope,
            independent_source_count=self.independent_source_count,
            minimum_leave_one_out_sources=self.minimum_leave_one_out_sources,
            contributor_client_ids=self.contributor_client_ids,
            leave_one_out_grants=self.leave_one_out_grants,
            leave_one_out_parent_ref=self.leave_one_out_parent_ref,
            excluded_client_ids=self.excluded_client_ids,
        )
        if self.authority_ref.content_sha256 != expected:
            raise ValueError("graph edge authority reference hash is not canonical")
        return self


@dataclass(frozen=True, slots=True)
class FrozenGraphEdgeAuthorityCatalog:
    runtime_epoch: int
    records: tuple[GraphEdgeAuthorityRecord, ...]


class GraphEdgeAuthorityCatalog(Protocol):
    """Freeze one epoch in a single metadata-only transactional read."""

    def snapshot(self, runtime_epoch: int) -> FrozenGraphEdgeAuthorityCatalog: ...


class StaticGraphEdgeAuthorityCatalog:
    """Immutable in-memory catalog used by composition roots and tests."""

    def __init__(
        self,
        records: tuple[GraphEdgeAuthorityRecord, ...],
        *,
        runtime_epoch: int,
    ) -> None:
        if type(runtime_epoch) is not int or runtime_epoch < 0:
            raise ValueError("graph edge authority epoch is invalid")
        values: dict[tuple[str, int, str], GraphEdgeAuthorityRecord] = {}
        stable_ids: set[str] = set()
        for raw_record in records:
            record = GraphEdgeAuthorityRecord.model_validate(raw_record)
            key = _ref_key(record.relation_ref)
            if (
                record.runtime_epoch != runtime_epoch
                or key in values
                or record.relation_ref.object_id in stable_ids
            ):
                raise ValueError("graph edge authority records must be exact and unique")
            values[key] = record
            stable_ids.add(record.relation_ref.object_id)
        self._snapshot = FrozenGraphEdgeAuthorityCatalog(
            runtime_epoch=runtime_epoch,
            records=tuple(value for _key, value in sorted(values.items())),
        )

    def snapshot(self, runtime_epoch: int) -> FrozenGraphEdgeAuthorityCatalog:
        if runtime_epoch != self._snapshot.runtime_epoch:
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_EPOCH_MISMATCH"
            )
        return self._snapshot


def _object_kind(reference: VersionRef) -> str:
    return reference.object_id.rsplit("_", maxsplit=1)[0]


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _ref_payload(reference: VersionRef) -> dict[str, object]:
    return reference.model_dump(mode="json")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def graph_edge_authority_sha256(
    *,
    relation_ref: VersionRef,
    runtime_epoch: int,
    provenance_scope: ProvenanceScope,
    independent_source_count: int,
    minimum_leave_one_out_sources: int,
    contributor_client_ids: frozenset[str],
    leave_one_out_grants: tuple[GraphLeaveOneOutGrant, ...],
    leave_one_out_parent_ref: VersionRef | None,
    excluded_client_ids: frozenset[str],
) -> str:
    """Hash the complete acyclic edge-authority metadata contract."""

    return _canonical_sha256(
        {
            "contributor_client_ids": sorted(contributor_client_ids),
            "excluded_client_ids": sorted(excluded_client_ids),
            "independent_source_count": independent_source_count,
            "leave_one_out_grants": [
                grant.model_dump(mode="json") for grant in leave_one_out_grants
            ],
            "leave_one_out_parent_ref": (
                None
                if leave_one_out_parent_ref is None
                else _ref_payload(leave_one_out_parent_ref)
            ),
            "minimum_leave_one_out_sources": minimum_leave_one_out_sources,
            "provenance_scope": provenance_scope,
            "relation_ref": _ref_payload(relation_ref),
            "runtime_epoch": runtime_epoch,
        }
    )


def _validate_snapshot(
    artifact: GlobalGraphArtifact,
    snapshot: AuthoritativeFilterSnapshot,
) -> None:
    """Validate that a live snapshot is not older than the derived graph."""

    verify_global_graph_artifact(artifact)
    if (
        snapshot.global_runtime_epoch != artifact.source_runtime_epoch
        or snapshot.created_at < artifact.effective_at
    ):
        raise GraphAuthoritySnapshotError("GLOBAL_GRAPH_AUTHORITY_SNAPSHOT_STALE")


class GraphEdgeAuthorityResolver:
    """Issue and revalidate client-safe, exact edge-selection capabilities."""

    MAX_ISSUED_BINDINGS = 256

    def __init__(self, catalog: GraphEdgeAuthorityCatalog) -> None:
        self._catalog = catalog
        self._issued: OrderedDict[str, GraphAuthorityBinding] = OrderedDict()

    def resolve(
        self,
        artifact: GlobalGraphArtifact,
        *,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        required_use: str,
        graph_root_ref: VersionRef,
        graph_version: VersionRef,
    ) -> GraphAuthorityBinding:
        binding = self._compute(
            artifact,
            scope=scope,
            authority_snapshot=authority_snapshot,
            required_use=required_use,
            graph_root_ref=graph_root_ref,
            graph_version=graph_version,
        )
        self._issued.pop(binding.run_id, None)
        self._issued[binding.run_id] = binding
        while len(self._issued) > self.MAX_ISSUED_BINDINGS:
            self._issued.popitem(last=False)
        return binding

    def assert_binding_current(
        self,
        binding: GraphAuthorityBinding,
        artifact: GlobalGraphArtifact,
        *,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        required_use: str,
        graph_root_ref: VersionRef,
        graph_version: VersionRef,
    ) -> None:
        if not isinstance(binding, GraphAuthorityBinding):
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_REQUIRED"
            )
        issued = self._issued.get(binding.run_id)
        if issued != binding:
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_INVALID"
            )
        expected = self._compute(
            artifact,
            scope=scope,
            authority_snapshot=authority_snapshot,
            required_use=required_use,
            graph_root_ref=graph_root_ref,
            graph_version=graph_version,
        )
        if expected != binding:
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_STALE"
            )

    @staticmethod
    def relation_allowed(
        attributes: Mapping[str, object], binding: GraphAuthorityBinding
    ) -> bool:
        relation_ref = attributes.get("relation_ref")
        return isinstance(relation_ref, VersionRef) and relation_ref in frozenset(
            binding.allowed_relation_refs
        )

    def _compute(
        self,
        artifact: GlobalGraphArtifact,
        *,
        scope: RetrievalScope,
        authority_snapshot: AuthoritativeFilterSnapshot,
        required_use: str,
        graph_root_ref: VersionRef,
        graph_version: VersionRef,
    ) -> GraphAuthorityBinding:
        _validate_snapshot(artifact, authority_snapshot)
        exact_root = VersionRef.model_validate(graph_root_ref)
        exact_graph_version = VersionRef.model_validate(graph_version)
        if (
            _object_kind(exact_graph_version) != "global_graph"
            or exact_graph_version.content_sha256 != artifact.canonical_sha256
            or exact_graph_version.version != artifact.source_catalog_version
            or exact_root == exact_graph_version
            or exact_root.version != artifact.source_catalog_version
        ):
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_DERIVED_ROOT_BINDING_INVALID"
            )
        if (
            not required_use
            or required_use not in scope.allowed_uses
            or scope.effective_at != authority_snapshot.created_at
            or scope.known_at != authority_snapshot.created_at
        ):
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_SCOPE_MISMATCH"
            )

        frozen_catalog = self._catalog.snapshot(artifact.source_runtime_epoch)
        if frozen_catalog.runtime_epoch != artifact.source_runtime_epoch:
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_EPOCH_MISMATCH"
            )
        records: dict[tuple[str, int, str], GraphEdgeAuthorityRecord] = {}
        stable_record_ids: set[str] = set()
        for raw_record in frozen_catalog.records:
            record = GraphEdgeAuthorityRecord.model_validate(raw_record)
            key = _ref_key(record.relation_ref)
            if (
                record.runtime_epoch != artifact.source_runtime_epoch
                or key in records
                or record.relation_ref.object_id in stable_record_ids
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
                )
            records[key] = record
            stable_record_ids.add(record.relation_ref.object_id)

        edges: dict[
            tuple[str, int, str],
            tuple[str, str, Mapping[str, object], GraphEdgeAuthorityRecord],
        ] = {}
        stable_edge_ids: set[str] = set()
        for _source, _target, key, attributes in artifact.graph.edges(
            keys=True, data=True
        ):
            relation_ref = attributes.get("relation_ref")
            if (
                not isinstance(relation_ref, VersionRef)
                or relation_ref.object_id != str(key)
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
                )
            edge_key = _ref_key(relation_ref)
            if (
                edge_key in edges
                or relation_ref.object_id in stable_edge_ids
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
                )
            edge_record = records.get(edge_key)
            provenance_scope = attributes.get("provenance_scope")
            contributor_count = attributes.get("case_contributor_count")
            relation_scope = attributes.get("relation_scope")
            allowed_uses = attributes.get("allowed_uses")
            if edge_record is None:
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_MISSING"
                )
            if (
                edge_record.relation_ref != relation_ref
                or edge_record.provenance_scope != provenance_scope
                or edge_record.authority_ref.object_id
                not in authority_snapshot.allowed_ref_ids
                or edge_record.relation_ref.object_id
                not in authority_snapshot.allowed_ref_ids
                or type(contributor_count) is not int
                or contributor_count != len(edge_record.contributor_client_ids)
                or attributes.get("independent_source_count")
                != edge_record.independent_source_count
                or not isinstance(relation_scope, tuple)
                or not relation_scope
                or relation_scope != tuple(sorted(set(relation_scope)))
                or not isinstance(allowed_uses, tuple)
                or required_use not in allowed_uses
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
                )
            edges[edge_key] = (
                str(_source),
                str(_target),
                attributes,
                edge_record,
            )
            stable_edge_ids.add(relation_ref.object_id)

        if set(records) != set(edges):
            raise GraphAuthoritySnapshotError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
            )

        # Validate the complete LOO graph independently of the current client,
        # so a dormant malformed grant can never be activated by a later query.
        replacement_parents: dict[
            tuple[str, int, str], tuple[str, int, str]
        ] = {}
        for parent_key, (
            parent_source,
            parent_target,
            parent_attributes,
            parent,
        ) in edges.items():
            if parent.leave_one_out_parent_ref is not None:
                continue
            for grant in parent.leave_one_out_grants:
                replacement_key = _ref_key(grant.replacement_relation_ref)
                replacement = edges.get(replacement_key)
                if replacement is None or replacement_key in replacement_parents:
                    raise GraphAuthoritySnapshotError(
                        "GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID"
                    )
                (
                    replacement_source,
                    replacement_target,
                    replacement_attributes,
                    replacement_record,
                ) = replacement
                if (
                    parent.provenance_scope
                    not in {"case_derived", "mixed"}
                    or replacement_record.leave_one_out_parent_ref
                    != parent.relation_ref
                    or replacement_record.excluded_client_ids
                    != frozenset({grant.excluded_client_id})
                    or grant.excluded_client_id
                    in replacement_record.contributor_client_ids
                    or replacement_record.provenance_scope == "client_private"
                    or replacement_record.independent_source_count
                    < parent.minimum_leave_one_out_sources
                    or replacement_attributes.get("independent_source_count")
                    != replacement_record.independent_source_count
                    or replacement_source != parent_source
                    or replacement_target != parent_target
                    or replacement_attributes.get("relation")
                    != parent_attributes.get("relation")
                    or replacement_attributes.get("relation_scope")
                    != parent_attributes.get("relation_scope")
                    or replacement_attributes.get("allowed_uses")
                    != parent_attributes.get("allowed_uses")
                    or replacement_attributes.get("privacy_scope")
                    != parent_attributes.get("privacy_scope")
                ):
                    raise GraphAuthoritySnapshotError(
                        "GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID"
                    )
                replacement_parents[replacement_key] = parent_key
        for replacement_key, (
            _source,
            _target,
            _attributes,
            replacement_record_value,
        ) in edges.items():
            if replacement_record_value.leave_one_out_parent_ref is not None and (
                replacement_key not in replacement_parents
                or _ref_key(replacement_record_value.leave_one_out_parent_ref)
                != replacement_parents[replacement_key]
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID"
                )

        selected_replacements: set[tuple[str, int, str]] = set()
        for _source, _target, edge_attributes, record in edges.values():
            if (
                record.leave_one_out_parent_ref is not None
                or scope.current_client_id not in record.contributor_client_ids
                or not edge_visible_in_snapshot(
                    edge_attributes,
                    authority_snapshot,
                    required_use=required_use,
                    effective_at=scope.effective_at,
                    known_at=scope.known_at,
                )
            ):
                continue
            grants = tuple(
                grant
                for grant in record.leave_one_out_grants
                if grant.excluded_client_id == scope.current_client_id
            )
            if len(grants) > 1:
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_AUTHORITY_CLOSURE_INVALID"
                )
            if not grants:
                continue
            replacement_key = _ref_key(grants[0].replacement_relation_ref)
            replacement = edges.get(replacement_key)
            if replacement is None:
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID"
                )
            (
                _replacement_source,
                _replacement_target,
                replacement_attributes,
                replacement_record,
            ) = replacement
            if (
                replacement_record.leave_one_out_parent_ref != record.relation_ref
                or scope.current_client_id
                not in replacement_record.excluded_client_ids
                or scope.current_client_id
                in replacement_record.contributor_client_ids
                or not edge_visible_in_snapshot(
                    replacement_attributes,
                    authority_snapshot,
                    required_use=required_use,
                    effective_at=scope.effective_at,
                    known_at=scope.known_at,
                )
            ):
                raise GraphAuthoritySnapshotError(
                    "GLOBAL_GRAPH_EDGE_LOO_CLOSURE_INVALID"
                )
            selected_replacements.add(replacement_key)

        allowed: list[VersionRef] = []
        actions: list[dict[str, object]] = []
        authority_refs: list[VersionRef] = []
        for key, (
            _source,
            _target,
            edge_attributes,
            record,
        ) in sorted(edges.items()):
            live = edge_visible_in_snapshot(
                edge_attributes,
                authority_snapshot,
                required_use=required_use,
                effective_at=scope.effective_at,
                known_at=scope.known_at,
            )
            selected = False
            action = "denied"
            if live and record.leave_one_out_parent_ref is not None:
                selected = key in selected_replacements
                action = "leave_one_out" if selected else "loo_not_selected"
            elif live and record.provenance_scope == "global_source":
                selected = True
                action = "global_source"
            elif live and record.provenance_scope in {"case_derived", "mixed"}:
                selected = scope.current_client_id not in record.contributor_client_ids
                action = "other_client_case" if selected else "self_case_excluded"
            if selected:
                allowed.append(record.relation_ref)
            authority_refs.append(record.authority_ref)
            actions.append(
                {
                    "action": action,
                    "authority_ref": _ref_payload(record.authority_ref),
                    "relation_ref": _ref_payload(record.relation_ref),
                }
            )

        allowed_refs = tuple(sorted(allowed, key=_ref_key))
        record_refs = tuple(sorted(authority_refs, key=_ref_key))
        scope_sha256 = _canonical_sha256(scope.model_dump(mode="json"))
        decision_sha256 = _canonical_sha256(
            {
                "actions": actions,
                "allowed_relation_refs": [
                    _ref_payload(value) for value in allowed_refs
                ],
                "artifact_sha256": artifact.canonical_sha256,
                "graph_root_ref": _ref_payload(exact_root),
                "graph_version": _ref_payload(exact_graph_version),
                "authorization_epoch": authority_snapshot.authorization_epoch,
                "client_runtime_epoch": authority_snapshot.client_runtime_epoch,
                "global_runtime_epoch": authority_snapshot.global_runtime_epoch,
                "policy_ref": _ref_payload(authority_snapshot.policy_ref),
                "required_use": required_use,
                "run_id": authority_snapshot.run_id,
                "scope_sha256": scope_sha256,
                "tombstone_epoch": authority_snapshot.tombstone_epoch,
            }
        )
        return GraphAuthorityBinding(
            run_id=authority_snapshot.run_id,
            global_runtime_epoch=authority_snapshot.global_runtime_epoch,
            client_runtime_epoch=authority_snapshot.client_runtime_epoch,
            tombstone_epoch=authority_snapshot.tombstone_epoch,
            authorization_epoch=authority_snapshot.authorization_epoch,
            policy_ref=authority_snapshot.policy_ref,
            created_at=authority_snapshot.created_at,
            artifact_sha256=artifact.canonical_sha256,
            graph_root_ref=exact_root,
            graph_version=exact_graph_version,
            required_use=required_use,
            scope_sha256=scope_sha256,
            allowed_relation_refs=allowed_refs,
            authority_record_refs=record_refs,
            decision_sha256=decision_sha256,
        )


def edge_visible_in_snapshot(
    attributes: Mapping[str, object],
    snapshot: AuthoritativeFilterSnapshot,
    *,
    required_use: str,
    effective_at: datetime | None = None,
    known_at: datetime | None = None,
) -> bool:
    """Apply current revocation/authorization gates before topology or rank."""

    if (
        attributes.get("review_status") != "approved"
        or attributes.get("passage_review_status") != "approved"
        or attributes.get("authorized") is not True
        or attributes.get("tombstoned") is not False
    ):
        return False
    allowed_uses = attributes.get("allowed_uses")
    if not isinstance(allowed_uses, tuple | list | set | frozenset):
        return False
    if required_use not in allowed_uses:
        return False

    relation_ref = attributes.get("relation_ref")
    claim_ref = attributes.get("claim_ref")
    wiki_ref = attributes.get("wiki_ref")
    passage_refs = attributes.get("passage_refs")
    theory_ref = attributes.get("theory_ref")
    if (
        not isinstance(relation_ref, VersionRef)
        or not isinstance(claim_ref, VersionRef)
        or not isinstance(wiki_ref, VersionRef)
        or not isinstance(passage_refs, tuple)
        or not passage_refs
        or any(not isinstance(value, VersionRef) for value in passage_refs)
        or (theory_ref is not None and not isinstance(theory_ref, VersionRef))
    ):
        return False
    authority_refs = (relation_ref, claim_ref, wiki_ref, *passage_refs)
    if isinstance(theory_ref, VersionRef):
        authority_refs = (*authority_refs, theory_ref)
    if any(
        reference.object_id not in snapshot.allowed_ref_ids
        for reference in authority_refs
    ):
        return False

    effective_from = attributes.get("effective_from")
    effective_to = attributes.get("effective_to")
    review_due_at = attributes.get("review_due_at")
    if effective_from is not None and not isinstance(effective_from, datetime):
        return False
    if effective_to is not None and not isinstance(effective_to, datetime):
        return False
    if review_due_at is not None and not isinstance(review_due_at, datetime):
        return False
    effective_time = effective_at or snapshot.created_at
    known_time = known_at or snapshot.created_at
    if isinstance(effective_from, datetime) and effective_from > effective_time:
        return False
    if isinstance(effective_to, datetime) and effective_time >= effective_to:
        return False
    if isinstance(review_due_at, datetime) and review_due_at <= known_time:
        return False
    if attributes.get("source_grade") == "C1" and not isinstance(
        theory_ref, VersionRef
    ):
        return False
    return True


__all__ = [
    "GraphAuthorityBinding",
    "GraphEdgeAuthorityCatalog",
    "GraphEdgeAuthorityRecord",
    "GraphEdgeAuthorityResolver",
    "GraphAuthoritySnapshotError",
    "GraphLeaveOneOutGrant",
    "StaticGraphEdgeAuthorityCatalog",
    "edge_visible_in_snapshot",
    "graph_edge_authority_sha256",
]
