"""Shared generation-stage view of evidence bound by one EvidencePack."""

from __future__ import annotations

from consultation_kb.models.evidence import EvidencePack


def bound_evidence_ids(evidence_pack: EvidencePack) -> frozenset[str]:
    """Return candidate and current-turn temporary-fact IDs as one closed set.

    Retrieval candidates carry rich provenance and contradiction metadata.
    Temporary facts are separately hash-bound session objects, but they are
    still valid support for faithful reports about the current client turn.
    Keeping this projection in one helper prevents generation stages from
    silently disagreeing about whether current-turn evidence exists.
    """

    pack = EvidencePack.model_validate(evidence_pack, strict=True)
    candidate_ids = {
        item.evidence_id for item in (*pack.supporting, *pack.contradicting)
    }
    temporary_ids = {item.object_id for item in pack.temporary_fact_refs}
    if candidate_ids & temporary_ids:
        raise ValueError("GENERATION_EVIDENCE_ID_COLLISION")
    return frozenset(candidate_ids | temporary_ids)


__all__ = ["bound_evidence_ids"]
