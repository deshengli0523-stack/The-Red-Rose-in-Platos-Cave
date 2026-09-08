"""Version-closed deterministic risk rules.

The P0 policy loader owns parsing and canonicalization.  This module binds the
loaded policy and every member to immutable ``VersionRef`` objects before the
runtime is allowed to evaluate a rule.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import nullcontext
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    SafePolicyKey,
    StrictModel,
    VersionRef,
)
from consultation_kb.policy.loader import (
    LoadedPolicy,
    RiskRulesPolicy,
    risk_rule_member_identities,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import ManifestError, ManifestRepository


_ARTIFACT_KEY = "risk_rule_policy"
_ARTIFACT_KIND = "risk_rule_policy"
_POLICY_MEDIA_TYPE = "application/vnd.consultation-kb.risk-policy+json"
_RULE_MEDIA_TYPE = "application/vnd.consultation-kb.risk-rule+json"


class RiskRuleClosureError(RuntimeError):
    """Raised when a rule is not an exact member of its loaded policy."""

    def __init__(self, code: str = "RISK_RULE_CLOSURE_INVALID") -> None:
        super().__init__(code)


class MaterializedRiskRule(StrictModel):
    """One immutable rule plus its owning immutable policy reference."""

    schema_version: Literal["1.0"] = "1.0"
    policy_ref: VersionRef
    rule_ref: VersionRef
    rule_id: SafePolicyKey
    category: SafePolicyKey
    level: Literal["general", "high"]
    pattern_type: Literal["literal"]
    pattern: NonEmptyStr
    negation_window_tokens: Annotated[int, Field(strict=True, ge=0, le=32)]
    required_context: tuple[SafePolicyKey, ...]
    suggested_questions: Annotated[
        tuple[NonEmptyStr, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]

    @field_validator("required_context", "suggested_questions")
    @classmethod
    def _unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("risk rule tuple values must be unique")
        return value

    @model_validator(mode="after")
    def _version_closure(self) -> "MaterializedRiskRule":
        if self.policy_ref.version != 1 or self.rule_ref.version != 1:
            raise ValueError("risk rule and policy versions must be exact v1 refs")
        return self


class RiskRuleCatalog(StrictModel):
    """A complete, immutable policy closure used by ``RiskEngine``."""

    schema_version: Literal["1.0"] = "1.0"
    policy_ref: VersionRef
    rules: Annotated[
        tuple[MaterializedRiskRule, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]

    @model_validator(mode="after")
    def _closed_catalog(self) -> "RiskRuleCatalog":
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("risk rule IDs must be unique")
        if len({rule.rule_ref for rule in self.rules}) != len(self.rules):
            raise ValueError("risk rule refs must be unique")
        if any(rule.policy_ref != self.policy_ref for rule in self.rules):
            raise ValueError("every risk rule must bind to the catalog policy ref")
        return self

    @classmethod
    def from_loaded_policy(
        cls,
        loaded: LoadedPolicy[RiskRulesPolicy],
        *,
        policy_ref: VersionRef,
        rule_refs: Mapping[str, VersionRef],
    ) -> "RiskRuleCatalog":
        """Verify hashes and materialize an already-published policy closure."""

        if (
            policy_ref.version != loaded.policy_version
            or policy_ref.content_sha256 != loaded.content_sha256
        ):
            raise RiskRuleClosureError
        identities = risk_rule_member_identities(loaded)
        if set(rule_refs) != {identity.rule_id for identity in identities}:
            raise RiskRuleClosureError

        rules_by_id = {rule.rule_id: rule for rule in loaded.document.rules}
        materialized: list[MaterializedRiskRule] = []
        for identity in identities:
            reference = rule_refs[identity.rule_id]
            if (
                reference.version != identity.version
                or reference.content_sha256 != identity.content_sha256
            ):
                raise RiskRuleClosureError
            rule = rules_by_id[identity.rule_id]
            materialized.append(
                MaterializedRiskRule(
                    policy_ref=policy_ref,
                    rule_ref=reference,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    level=rule.level,
                    pattern_type=rule.pattern_type,
                    pattern=rule.pattern,
                    negation_window_tokens=rule.negation_window_tokens,
                    required_context=rule.required_context,
                    suggested_questions=rule.suggested_questions,
                )
            )
        return cls(policy_ref=policy_ref, rules=tuple(materialized))

    def get_by_ref(self, reference: VersionRef) -> MaterializedRiskRule:
        for rule in self.rules:
            if rule.rule_ref == reference:
                return rule
        raise RiskRuleClosureError("RISK_RULE_REF_NOT_IN_POLICY")


class RiskRulePolicyBinding(StrictModel):
    """Explicit immutable pointer; resolution never follows an implicit latest."""

    schema_version: Literal["1.0"] = "1.0"
    runtime_epoch: Annotated[int, Field(strict=True, ge=1)]
    manifest_ref: VersionRef

    @model_validator(mode="after")
    def _risk_manifest_ref(self) -> "RiskRulePolicyBinding":
        if (
            self.manifest_ref.object_id[:-37] != "risk_rule_policy_manifest"
            or self.manifest_ref.version != 1
        ):
            raise ValueError("risk rule binding requires an exact v1 manifest ref")
        return self


class PersistentRiskRuleCatalogResolver:
    """Resolve an approved whole/member closure from one pinned global epoch."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        loaded_policy: LoadedPolicy[RiskRulesPolicy],
        *,
        database_scope: Literal["global"],
    ) -> None:
        if database_scope != "global":
            raise ValueError("RISK_RULE_RESOLVER_REQUIRES_GLOBAL_DATABASE")
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        try:
            identities = risk_rule_member_identities(loaded_policy)
        except Exception:
            raise RiskRuleClosureError from None
        self._connection = connection
        self._loaded = loaded_policy
        self._identities = identities
        self._manifests = ManifestRepository(connection)

    @staticmethod
    def _manifest_ref(manifest: object) -> VersionRef:
        return VersionRef(
            object_id=manifest.manifest_id,  # type: ignore[attr-defined]
            version=manifest.source_version,  # type: ignore[attr-defined]
            content_sha256=manifest.manifest_sha256,  # type: ignore[attr-defined]
        )

    def _assert_persistent_approval(self, binding: RiskRulePolicyBinding) -> None:
        row = self._connection.execute(
            """
            SELECT r.state, p.state, p.runtime_epoch,
                   m.state, m.verified,
                   e.state, e.applied_commit_version, e.applied_at,
                   a.manifest_id
              FROM runtime_epochs AS r
              JOIN active_artifacts AS a
                ON a.epoch = r.epoch AND a.artifact_key = ?
              JOIN artifact_manifests AS m
                ON m.manifest_id = a.manifest_id
               AND m.operation_id = r.operation_id
              JOIN publication_operations AS p
                ON p.operation_id = r.operation_id
              JOIN approval_executions AS e
                ON e.operation_id = p.operation_id
               AND e.request_id = p.approval_request_id
               AND e.descriptor_sha256 = p.descriptor_sha256
             WHERE r.epoch = ?
            """,
            (_ARTIFACT_KEY, binding.runtime_epoch),
        ).fetchall()
        if len(row) != 1:
            raise RiskRuleClosureError("RISK_RULE_APPROVAL_NOT_FOUND")
        values = row[0]
        if (
            str(values[0]) not in {"ACTIVE", "RETIRED"}
            or str(values[1]) != "ACTIVE"
            or int(values[2]) != binding.runtime_epoch
            or str(values[3]) != "ACTIVE"
            or int(values[4]) != 1
            or str(values[5]) != "APPLIED"
            or values[6] is None
            or values[7] is None
            or str(values[8]) != binding.manifest_ref.object_id
        ):
            raise RiskRuleClosureError("RISK_RULE_APPROVAL_INVALID")

    def resolve(self, binding: RiskRulePolicyBinding) -> RiskRuleCatalog:
        """Resolve only the named epoch+manifest and recheck every member hash."""

        exact = RiskRulePolicyBinding.model_validate(binding)
        context = (
            nullcontext(self._connection)
            if self._connection.in_transaction
            else transaction(self._connection, immediate=False)
        )
        try:
            with context:
                self._assert_persistent_approval(exact)
                manifest = self._manifests.get_active(
                    _ARTIFACT_KEY,
                    epoch=exact.runtime_epoch,
                )
                if (
                    manifest.artifact_kind != _ARTIFACT_KIND
                    or manifest.source_version != self._loaded.policy_version
                    or manifest.state != "ACTIVE"
                    or not manifest.verified
                    or self._manifest_ref(manifest) != exact.manifest_ref
                ):
                    raise RiskRuleClosureError

                members = manifest.members
                if len(members) != len(self._identities) + 1:
                    raise RiskRuleClosureError
                whole = members[0]
                if (
                    whole.ordinal != 0
                    or whole.object_type != "risk_policy"
                    or whole.source_version != self._loaded.policy_version
                    or whole.object_sha256 != self._loaded.content_sha256
                    or whole.media_type != _POLICY_MEDIA_TYPE
                    or whole.size_bytes != len(self._loaded.canonical_bytes)
                ):
                    raise RiskRuleClosureError

                rule_refs: dict[str, VersionRef] = {}
                for identity, member in zip(self._identities, members[1:], strict=True):
                    if (
                        member.ordinal != identity.member_ordinal + 1
                        or member.object_type != "risk_rule"
                        or member.source_version != identity.version
                        or member.object_sha256 != identity.content_sha256
                        or member.media_type != _RULE_MEDIA_TYPE
                        or member.size_bytes != len(identity.canonical_bytes)
                    ):
                        raise RiskRuleClosureError
                    rule_refs[identity.rule_id] = VersionRef(
                        object_id=member.object_id,
                        version=member.source_version,
                        content_sha256=member.object_sha256,
                    )

                return RiskRuleCatalog.from_loaded_policy(
                    self._loaded,
                    policy_ref=VersionRef(
                        object_id=whole.object_id,
                        version=whole.source_version,
                        content_sha256=whole.object_sha256,
                    ),
                    rule_refs=rule_refs,
                )
        except RiskRuleClosureError:
            raise
        except (ManifestError, sqlite3.DatabaseError, TypeError, ValueError):
            raise RiskRuleClosureError from None


__all__ = [
    "MaterializedRiskRule",
    "PersistentRiskRuleCatalogResolver",
    "RiskRuleCatalog",
    "RiskRuleClosureError",
    "RiskRulePolicyBinding",
]
