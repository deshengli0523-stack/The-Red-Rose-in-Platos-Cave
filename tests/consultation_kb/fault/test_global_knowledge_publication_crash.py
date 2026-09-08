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
        ("c1", "after_file_fsync"),
        ("wiki", "before_prepared_tx"),
        ("graph", "after_verify"),
        ("lexical", "before_active_tx"),
        ("vector", "before_cleanup"),
    ),
)
def test_global_publication_crash_keeps_every_knowledge_root_atomic(
    tmp_path: Path,
    component: str,
    fault_point: str,
) -> None:
    _run_publication_cycle(
        tmp_path,
        scenario="global",
        component=component,
        fault_point=fault_point,
    )
