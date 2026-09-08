"""Fixed rebuild-builder DAG and authority-source allowlist.

The registry deliberately stores declarations only.  Builders never receive a
database connection; the coordinator reads the exact allowlisted authority
records and passes those records into each builder.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, TypeAlias

from pydantic import model_validator

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import (
    NonNegativeInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)


DatabaseScope: TypeAlias = Literal["global", "client"]
BindingRequirement: TypeAlias = Literal["none", "required"]
AuthoritySelection: TypeAlias = Literal[
    "approved_not_tombstoned",
    "active_approved_not_tombstoned",
]


def _implementation_revision(builder_id: str, revision: str) -> str:
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_builder_implementation.v1",
            "builder_id": builder_id,
            "revision": revision,
        }
    )


PRODUCTION_IMPLEMENTATION_REVISIONS: dict[str, str] = {
    builder_id: _implementation_revision(builder_id, "production_v1")
    for builder_id in (
        "c1_revision",
        "claims",
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "graph",
        "lexical",
        "vector",
        "client_fact_snapshot",
        "client_profile",
        "client_graph",
        "private_archive",
    )
}


GLOBAL_AUTHORITY_TABLES: frozenset[str] = frozenset(
    {
        "sources",
        "source_versions",
        "passages",
        "claims",
        "claim_evidence",
        "theory_revisions",
        "theory_revision_passages",
        "scope_policy_approval_bindings",
        "scope_policy_versions",
        "review_decisions",
        "wiki_revisions",
        "wiki_revision_claims",
        "cases",
        "case_versions",
        "case_authorizations",
        "case_review_decisions",
        "case_provenance",
        "case_patterns",
        "case_regeneration_proofs",
        "case_leave_one_out_variants",
    }
)
CLIENT_AUTHORITY_TABLES: frozenset[str] = frozenset(
    {
        "sessions",
        "turns",
        "actual_replies",
        "review_decisions",
        "fact_events",
        "fact_evidence",
        "fact_dependencies",
        "fact_merge_members",
        "profile_revisions",
        "profile_members",
        "archive_bundles",
        "archive_purpose_states",
        "private_archive_revisions",
    }
)
AUTHORITY_TABLE_ALLOWLIST: dict[DatabaseScope, frozenset[str]] = {
    "global": GLOBAL_AUTHORITY_TABLES,
    "client": CLIENT_AUTHORITY_TABLES,
}


class BuilderRegistryError(RuntimeError):
    """Fixed-code registry declaration or planning error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuthoritySourceSpec(StrictModel):
    """One database table approved as a rebuild authority source."""

    database_scope: DatabaseScope
    table: SafePolicyKey

    @property
    def key(self) -> str:
        return f"{self.database_scope}.{self.table}"


class BuilderDescriptor(StrictModel):
    """Body-free declaration of one deterministic artifact builder."""

    builder_id: SafePolicyKey
    database_scope: DatabaseScope
    output_purpose: SafePolicyKey
    implementation_revision_sha256: Sha256Hex
    dependencies: tuple[SafePolicyKey, ...]
    authority_sources: tuple[AuthoritySourceSpec, ...]
    policy_binding: BindingRequirement
    model_binding: BindingRequirement
    authority_selection: AuthoritySelection = "approved_not_tombstoned"
    order: NonNegativeInt = 0

    @model_validator(mode="after")
    def _validate_unique_inputs(self) -> "BuilderDescriptor":
        if self.builder_id in self.dependencies:
            raise ValueError("builder cannot depend on itself")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("builder dependencies must be unique")
        source_keys = tuple(source.key for source in self.authority_sources)
        if not source_keys or len(set(source_keys)) != len(source_keys):
            raise ValueError("builder authority sources must be non-empty and unique")
        return self


def _source(scope: DatabaseScope, table: str) -> AuthoritySourceSpec:
    return AuthoritySourceSpec(database_scope=scope, table=table)


def _default_descriptors() -> tuple[BuilderDescriptor, ...]:
    global_knowledge = tuple(
        _source("global", table)
        for table in (
            "sources",
            "source_versions",
            "passages",
            "claims",
            "claim_evidence",
            "theory_revisions",
            "theory_revision_passages",
            "scope_policy_approval_bindings",
            "scope_policy_versions",
            "review_decisions",
            "wiki_revisions",
            "wiki_revision_claims",
        )
    )
    case_authority = tuple(
        _source("global", table)
        for table in (
            "cases",
            "case_versions",
            "case_authorizations",
            "case_review_decisions",
            "case_provenance",
            "case_patterns",
            "case_regeneration_proofs",
            "case_leave_one_out_variants",
        )
    )
    fact_authority = tuple(
        _source("client", table)
        for table in (
            "fact_events",
            "fact_evidence",
            "fact_dependencies",
            "fact_merge_members",
        )
    )
    private_archive_authority = tuple(
        _source("client", table)
        for table in (
            "archive_bundles",
            "archive_purpose_states",
            "private_archive_revisions",
        )
    )
    approved_profile_audit_authority = (
        *fact_authority,
        _source("client", "profile_revisions"),
        _source("client", "profile_members"),
        _source("client", "review_decisions"),
        _source("client", "archive_purpose_states"),
    )
    global_rebuild_authority = (*global_knowledge, *case_authority)
    return (
        BuilderDescriptor(
            builder_id="wiki_index",
            database_scope="global",
            output_purpose="wiki_index",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["wiki_index"]
            ),
            dependencies=(),
            authority_sources=global_rebuild_authority,
            policy_binding="required",
            model_binding="none",
            order=0,
        ),
        BuilderDescriptor(
            builder_id="knowledge_registry",
            database_scope="global",
            output_purpose="knowledge_registry",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["knowledge_registry"]
            ),
            dependencies=("wiki_index",),
            authority_sources=global_rebuild_authority,
            policy_binding="required",
            model_binding="none",
            order=10,
        ),
        BuilderDescriptor(
            builder_id="graph",
            database_scope="global",
            output_purpose="graph",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["graph"]
            ),
            dependencies=("wiki_index", "knowledge_registry"),
            authority_sources=global_rebuild_authority,
            policy_binding="required",
            model_binding="none",
            order=20,
        ),
        BuilderDescriptor(
            builder_id="lexical",
            database_scope="global",
            output_purpose="lexical",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["lexical"]
            ),
            dependencies=("knowledge_registry",),
            authority_sources=global_rebuild_authority,
            policy_binding="required",
            model_binding="none",
            order=30,
        ),
        BuilderDescriptor(
            builder_id="vector",
            database_scope="global",
            output_purpose="vector",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["vector"]
            ),
            dependencies=("knowledge_registry",),
            authority_sources=global_rebuild_authority,
            policy_binding="required",
            model_binding="required",
            order=40,
        ),
        BuilderDescriptor(
            builder_id="client_fact_snapshot",
            database_scope="client",
            output_purpose="client_fact_snapshot",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["client_fact_snapshot"]
            ),
            dependencies=(),
            authority_sources=approved_profile_audit_authority,
            policy_binding="required",
            model_binding="none",
            order=0,
        ),
        BuilderDescriptor(
            builder_id="client_profile",
            database_scope="client",
            output_purpose="client_profile",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["client_profile"]
            ),
            dependencies=("client_fact_snapshot",),
            authority_sources=approved_profile_audit_authority,
            policy_binding="required",
            model_binding="none",
            order=10,
        ),
        BuilderDescriptor(
            builder_id="client_graph",
            database_scope="client",
            output_purpose="client_graph",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["client_graph"]
            ),
            dependencies=("client_fact_snapshot",),
            authority_sources=approved_profile_audit_authority,
            policy_binding="required",
            model_binding="none",
            order=20,
        ),
        BuilderDescriptor(
            builder_id="private_archive",
            database_scope="client",
            output_purpose="private_archive",
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS["private_archive"]
            ),
            dependencies=(),
            authority_sources=private_archive_authority,
            policy_binding="required",
            model_binding="none",
            authority_selection="active_approved_not_tombstoned",
            order=30,
        ),
    )


def _production_descriptors() -> tuple[BuilderDescriptor, ...]:
    defaults = _default_descriptors()
    global_sources = next(
        value.authority_sources
        for value in defaults
        if value.builder_id == "wiki_index"
    )
    bases = tuple(
        BuilderDescriptor(
            builder_id=builder_id,
            database_scope="global",
            output_purpose=builder_id,
            implementation_revision_sha256=(
                PRODUCTION_IMPLEMENTATION_REVISIONS[builder_id]
            ),
            dependencies=(),
            authority_sources=global_sources,
            policy_binding="required",
            model_binding="none",
            order=order,
        )
        for order, builder_id in enumerate(
            ("c1_revision", "claims", "wiki_page")
        )
    )
    adjusted: list[BuilderDescriptor] = []
    for descriptor in defaults:
        if descriptor.database_scope != "global":
            adjusted.append(descriptor)
        elif descriptor.builder_id == "wiki_index":
            adjusted.append(
                descriptor.model_copy(
                    update={
                        "dependencies": (
                            "c1_revision",
                            "claims",
                            "wiki_page",
                        ),
                        "order": 10,
                    }
                )
            )
        else:
            adjusted.append(
                descriptor.model_copy(update={"order": descriptor.order + 20})
            )
    return (*bases, *adjusted)


class BuilderRegistry:
    """Validated immutable builder declarations with deterministic planning."""

    def __init__(self, descriptors: Iterable[BuilderDescriptor]) -> None:
        checked = tuple(
            BuilderDescriptor.model_validate(descriptor) for descriptor in descriptors
        )
        if not checked:
            raise BuilderRegistryError("REBUILD_BUILDER_REGISTRY_EMPTY")
        ids = tuple(item.builder_id for item in checked)
        outputs = tuple(
            (item.database_scope, item.output_purpose) for item in checked
        )
        if len(set(ids)) != len(ids):
            raise BuilderRegistryError("REBUILD_BUILDER_ID_DUPLICATE")
        if len(set(outputs)) != len(outputs):
            raise BuilderRegistryError("REBUILD_OUTPUT_PURPOSE_DUPLICATE")
        by_id = {item.builder_id: item for item in checked}
        for descriptor in checked:
            for source in descriptor.authority_sources:
                if (
                    source.database_scope != descriptor.database_scope
                    or source.table
                    not in AUTHORITY_TABLE_ALLOWLIST[source.database_scope]
                ):
                    raise BuilderRegistryError(
                        "REBUILD_AUTHORITY_SOURCE_FORBIDDEN"
                    )
            for dependency_id in descriptor.dependencies:
                dependency = by_id.get(dependency_id)
                if dependency is None:
                    raise BuilderRegistryError("REBUILD_DEPENDENCY_MISSING")
                if dependency.database_scope != descriptor.database_scope:
                    raise BuilderRegistryError(
                        "REBUILD_CROSS_SCOPE_DEPENDENCY"
                    )
        self._descriptors = tuple(sorted(checked, key=lambda item: item.builder_id))
        self._by_id = by_id
        # Validate the entire graph now, not only when a purpose is requested.
        self._topological(frozenset(ids))

    @classmethod
    def default(cls) -> "BuilderRegistry":
        return cls(_default_descriptors())

    @classmethod
    def production(cls) -> "BuilderRegistry":
        return cls(_production_descriptors())

    @property
    def descriptors(self) -> tuple[BuilderDescriptor, ...]:
        return self._descriptors

    def _topological(
        self, selected: frozenset[str]
    ) -> tuple[BuilderDescriptor, ...]:
        remaining = set(selected)
        emitted: list[BuilderDescriptor] = []
        emitted_ids: set[str] = set()
        while remaining:
            ready = [
                self._by_id[builder_id]
                for builder_id in remaining
                if set(self._by_id[builder_id].dependencies) <= emitted_ids
            ]
            if not ready:
                raise BuilderRegistryError("REBUILD_BUILDER_DAG_CYCLE")
            ready.sort(key=lambda item: (item.order, item.builder_id))
            for descriptor in ready:
                emitted.append(descriptor)
                emitted_ids.add(descriptor.builder_id)
                remaining.remove(descriptor.builder_id)
        return tuple(emitted)

    def plan(
        self, *, database_scope: DatabaseScope, purpose: str
    ) -> tuple[BuilderDescriptor, ...]:
        if purpose == "all":
            selected = {
                descriptor.builder_id
                for descriptor in self._descriptors
                if descriptor.database_scope == database_scope
            }
        else:
            targets = [
                descriptor
                for descriptor in self._descriptors
                if descriptor.database_scope == database_scope
                and descriptor.output_purpose == purpose
            ]
            if len(targets) != 1:
                raise BuilderRegistryError("REBUILD_PURPOSE_UNKNOWN")
            selected = {targets[0].builder_id}
            pending = [targets[0]]
            while pending:
                descriptor = pending.pop()
                for dependency_id in descriptor.dependencies:
                    if dependency_id not in selected:
                        selected.add(dependency_id)
                        pending.append(self._by_id[dependency_id])
        if not selected:
            raise BuilderRegistryError("REBUILD_PURPOSE_UNKNOWN")
        return self._topological(frozenset(selected))

    def dag_sha256(self, *, database_scope: DatabaseScope, purpose: str) -> str:
        plan = self.plan(database_scope=database_scope, purpose=purpose)
        return canonical_sha256(
            [
                {
                    "builder_id": descriptor.builder_id,
                    "database_scope": descriptor.database_scope,
                    "output_purpose": descriptor.output_purpose,
                    "implementation_revision_sha256": (
                        descriptor.implementation_revision_sha256
                    ),
                    "dependencies": list(descriptor.dependencies),
                    "authority_sources": [
                        source.model_dump(mode="json")
                        for source in descriptor.authority_sources
                    ],
                    "policy_binding": descriptor.policy_binding,
                    "model_binding": descriptor.model_binding,
                    "authority_selection": descriptor.authority_selection,
                    "order": descriptor.order,
                }
                for descriptor in plan
            ]
        )

    def validate_bindings(
        self,
        *,
        database_scope: DatabaseScope,
        purpose: str,
        policy_sha256: Sha256Hex | None,
        model_descriptor_sha256: Sha256Hex | None,
    ) -> None:
        plan = self.plan(database_scope=database_scope, purpose=purpose)
        if policy_sha256 is None and any(
            descriptor.policy_binding == "required" for descriptor in plan
        ):
            raise BuilderRegistryError("REBUILD_POLICY_BINDING_REQUIRED")
        if model_descriptor_sha256 is None and any(
            descriptor.model_binding == "required" for descriptor in plan
        ):
            raise BuilderRegistryError("REBUILD_MODEL_BINDING_REQUIRED")


__all__ = [
    "AUTHORITY_TABLE_ALLOWLIST",
    "CLIENT_AUTHORITY_TABLES",
    "GLOBAL_AUTHORITY_TABLES",
    "AuthoritySourceSpec",
    "AuthoritySelection",
    "BindingRequirement",
    "BuilderDescriptor",
    "BuilderRegistry",
    "BuilderRegistryError",
    "DatabaseScope",
    "PRODUCTION_IMPLEMENTATION_REVISIONS",
]
