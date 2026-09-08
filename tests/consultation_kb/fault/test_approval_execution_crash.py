from __future__ import annotations

from pathlib import Path

import pytest

from tests.consultation_kb.fault.test_manifest_process_crash import (
    _run_approval_cycle,
)


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]


@pytest.mark.parametrize(
    "fault_point",
    (
        "after_approval_claim",
        "before_target_commit",
        "after_target_commit_before_ack",
    ),
)
def test_approval_crash_recovers_exact_target_once(
    tmp_path: Path,
    fault_point: str,
) -> None:
    _run_approval_cycle(tmp_path, fault_point=fault_point)
