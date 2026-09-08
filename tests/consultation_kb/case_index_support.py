from __future__ import annotations

from consultation_kb.archive.provenance import (
    CaseContributionAuthority,
    IndependentEvidenceAuthority,
    SourceAuthorityState,
)
from consultation_kb.archive.case_indexing import CaseIndexRootAuthority
from consultation_kb.models.cases import (
    CaseContribution,
    version_ref_key,
)
from consultation_kb.models.common import VersionRef


class StaticCaseSourceAuthority:
    """Exact, body-free source authority used by case-index acceptance tests."""

    def __init__(self) -> None:
        self._cases: dict[
            tuple[
                tuple[str, int, str],
                tuple[str, int, str],
                tuple[str, int, str],
            ],
            CaseContributionAuthority,
        ] = {}

    def authorize_case(
        self,
        contribution: CaseContribution,
        *,
        state: SourceAuthorityState = "active",
    ) -> None:
        value = CaseContribution.model_validate(contribution)
        self._cases[self._case_key(value)] = CaseContributionAuthority(value, state)

    def resolve_case_contribution(
        self,
        *,
        case_ref: VersionRef,
        source_provenance_ref: VersionRef,
        authorization_ref: VersionRef,
    ) -> CaseContributionAuthority | None:
        return self._cases.get(
            (
                version_ref_key(case_ref),
                version_ref_key(source_provenance_ref),
                version_ref_key(authorization_ref),
            )
        )

    def resolve_independent_evidence(
        self,
        *,
        evidence_ref: VersionRef,
        source_provenance_ref: VersionRef,
    ) -> IndependentEvidenceAuthority | None:
        del evidence_ref, source_provenance_ref
        return None

    @staticmethod
    def _case_key(
        value: CaseContribution,
    ) -> tuple[
        tuple[str, int, str],
        tuple[str, int, str],
        tuple[str, int, str],
    ]:
        return (
            version_ref_key(value.case_ref),
            version_ref_key(value.source_provenance_ref),
            version_ref_key(value.authorization_ref),
        )


class StaticCaseIndexAuthority:
    """Exact catalog authority keyed by case and manifest refs."""

    def __init__(self) -> None:
        self._records: dict[
            tuple[tuple[str, int, str], tuple[str, int, str]],
            CaseIndexRootAuthority,
        ] = {}

    def authorize(self, value: CaseIndexRootAuthority) -> None:
        exact = CaseIndexRootAuthority.model_validate(value)
        self._records[
            (
                version_ref_key(exact.case_ref),
                version_ref_key(exact.authority_manifest_ref),
            )
        ] = exact

    def resolve_case_index_authority(
        self,
        *,
        case_ref: VersionRef,
        authority_manifest_ref: VersionRef,
    ) -> CaseIndexRootAuthority | None:
        return self._records.get(
            (
                version_ref_key(case_ref),
                version_ref_key(authority_manifest_ref),
            )
        )


__all__ = ["StaticCaseIndexAuthority", "StaticCaseSourceAuthority"]
