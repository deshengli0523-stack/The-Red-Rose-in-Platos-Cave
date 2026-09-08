from __future__ import annotations

from pathlib import Path

import pytest

from tests.consultation_kb.fault.test_manifest_process_crash import (
    _run_publication_cycle,
)


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]


@pytest.mark.parametrize(
    ("component", "fault_point"),
    (
        ("fact", "after_stage_write"),
        ("profile", "after_prepared_tx"),
        ("graph", "after_active_tx"),
    ),
)
def test_client_publication_crash_keeps_fact_profile_graph_atomic(
    tmp_path: Path,
    component: str,
    fault_point: str,
) -> None:
    _run_publication_cycle(
        tmp_path,
        scenario="client",
        component=component,
        fault_point=fault_point,
    )
