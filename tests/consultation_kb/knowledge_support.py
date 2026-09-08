from __future__ import annotations

import sqlite3
from collections.abc import Callable

from consultation_kb.core.ids import IdFactory
from consultation_kb.models.manifests import DraftDescriptor


class DirectTestApprovalExecutor:
    """Test-only executor; integration tests use the real P1 adapter."""

    def __init__(self, id_factory: IdFactory) -> None:
        self._ids = id_factory
        self._connection = sqlite3.connect(":memory:", isolation_level=None)

    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> str:
        if not approval_request_id.startswith("approval_request_"):
            raise ValueError("test approval request malformed")
        DraftDescriptor.model_validate(descriptor)
        apply(self._connection)
        return self._ids.object_id(operation_kind)
