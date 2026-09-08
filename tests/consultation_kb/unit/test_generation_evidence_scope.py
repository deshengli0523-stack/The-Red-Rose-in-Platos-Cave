from __future__ import annotations

import pytest

from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.models.common import VersionRef

from tests.consultation_kb.unit.p6_quality_support import pack, ref


def test_bound_evidence_ids_join_candidates_and_current_turn_facts() -> None:
    current_report = ref("temporary_fact", 51)
    evidence_pack = pack(temporary_fact_refs=(current_report,))

    assert bound_evidence_ids(evidence_pack) == {
        evidence_pack.supporting[0].evidence_id,
        current_report.object_id,
    }


def test_temporary_fact_cannot_alias_a_retrieval_evidence_id() -> None:
    baseline = pack()
    collision = VersionRef(
        object_id=baseline.supporting[0].evidence_id,
        version=1,
        content_sha256="f" * 64,
    )
    evidence_pack = baseline.model_copy(
        update={"temporary_fact_refs": (collision,)}
    )

    with pytest.raises(ValueError, match="GENERATION_EVIDENCE_ID_COLLISION"):
        bound_evidence_ids(evidence_pack)
