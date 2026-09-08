from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = [pytest.mark.golden, pytest.mark.acceptance_id("FACT-01")]
UTC = timezone.utc


def test_fact_01_preserves_uncertainty_and_deterministic_history_hash() -> None:
    repository = _repository()
    repository.append_batch(base_commit_version=0, events=(_event(),))
    service = BitemporalFactQuery(repository)
    uncertain_query = FactQuery(
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        fixed_epoch=1,
        review_statuses=frozenset({"approved"}),
        validity_statuses=frozenset({"active"}),
        resolution_statuses=frozenset({"open"}),
        epistemic_statuses=frozenset({"uncertain"}),
    )
    first = service.snapshot(uncertain_query)
    second = service.snapshot(uncertain_query)

    assert first.event_ids == ("event-1",)
    assert first.canonical_sha256 == second.canonical_sha256
    asserted = uncertain_query.model_copy(
        update={"epistemic_statuses": frozenset({"asserted"})}
    )
    assert service.execute(asserted) == ()
