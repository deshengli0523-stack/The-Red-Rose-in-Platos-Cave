"""P1-bound execution adapter for knowledge authority writes."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Protocol

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.store import ApprovalService, ApprovalUsed
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ObjectId
from consultation_kb.models.manifests import DraftDescriptor


class GovernedWriteExecutor(Protocol):
    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> ObjectId: ...


class P1GovernedWriteExecutor:
    """Consume one confirmed P1 approval in exactly one target transaction."""

    def __init__(
        self,
        *,
        approval_service: ApprovalService,
        execution_guard: ApprovalExecutionGuard,
        id_factory: IdFactory,
    ) -> None:
        self._approvals = approval_service
        self._guard = execution_guard
        self._ids = id_factory

    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> ObjectId:
        validated = DraftDescriptor.model_validate(descriptor)
        operation_id = self._approvals.bound_operation_id(
            approval_request_id,
            validated,
        ) or self._ids.object_id(operation_kind)
        try:
            ticket = self._approvals.issue_for_execution(
                approval_request_id,
                validated,
                operation_id=operation_id,
            )
        except ApprovalUsed:
            # A concurrent writer may have durably bound the receipt after the
            # lookup above.  Re-read and retry only that exact binding.
            recovered = self._approvals.bound_operation_id(
                approval_request_id,
                validated,
            )
            if recovered is None:
                raise
            operation_id = recovered
            ticket = self._approvals.issue_for_execution(
                approval_request_id,
                validated,
                operation_id=recovered,
            )
        proof = self._guard.apply_in_transaction(ticket, validated, apply)
        self._approvals.acknowledge(proof)
        return operation_id


__all__ = ["GovernedWriteExecutor", "P1GovernedWriteExecutor"]
