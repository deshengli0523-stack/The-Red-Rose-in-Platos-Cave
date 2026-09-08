"""Structural errors plus the only controlled client-visible construction path.

``ToolError`` alone cannot prove arbitrary prose semantically safe. Future
outward handlers must use :func:`client_visible_error` or
:func:`map_exception_to_client_error`, which expose only closed templates.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from consultation_kb.models.common import (
    FrozenSafeDetails,
    NonEmptyStr,
    StrictModel,
)


class ToolError(StrictModel):
    """Strict structural error; not an independent client-safety certificate."""

    code: NonEmptyStr
    message: NonEmptyStr
    retryable: bool = False
    safe_details: FrozenSafeDetails = Field(
        default_factory=lambda: FrozenSafeDetails({}),
        json_schema_extra={"default": {}},
    )


class ClientVisibleErrorCode(str, Enum):
    """Closed codes supported by the Task 3 client-visible boundary."""

    SCOPE_DENIED = "SCOPE_DENIED"
    PREVIOUS_TURN_NOT_CLOSED = "PREVIOUS_TURN_NOT_CLOSED"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class WorkflowErrorCode(str, Enum):
    """Closed counselor-facing workflow failures with no reflected content."""

    QUERY_PLAN_CORRECTION_REQUIRED = "QUERY_PLAN_CORRECTION_REQUIRED"
    GENERATION_STAGE_ORDER_INVALID = "GENERATION_STAGE_ORDER_INVALID"
    GENERATION_PARENT_MISMATCH = "GENERATION_PARENT_MISMATCH"
    QUALITY_RETRY_EXHAUSTED = "QUALITY_RETRY_EXHAUSTED"
    GENERATION_BINDING_MISMATCH = "GENERATION_BINDING_MISMATCH"
    GENERATION_STAGE_CONFLICT = "GENERATION_STAGE_CONFLICT"
    GENERATION_STAGE_IDEMPOTENCY_CONFLICT = (
        "GENERATION_STAGE_IDEMPOTENCY_CONFLICT"
    )
    GENERATION_STAGE_REVISION_REASON_REQUIRED = (
        "GENERATION_STAGE_REVISION_REASON_REQUIRED"
    )
    GENERATION_STAGE_REVISION_CLOSED = "GENERATION_STAGE_REVISION_CLOSED"
    CLIENT_REPLY_RISK_LEAKAGE = "CLIENT_REPLY_RISK_LEAKAGE"
    RISK_OBSERVATION_UNAVAILABLE = "RISK_OBSERVATION_UNAVAILABLE"
    RISK_LIFECYCLE_CONFLICT = "RISK_LIFECYCLE_CONFLICT"
    RISK_EVALUATION_INCOMPLETE = "RISK_EVALUATION_INCOMPLETE"
    CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED = (
        "CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED"
    )
    REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE = (
        "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
    )
    REBUILD_JOB_NOT_FOUND = "REBUILD_JOB_NOT_FOUND"
    REBUILD_JOB_STATE_CONFLICT = "REBUILD_JOB_STATE_CONFLICT"
    REBUILD_CANCELLATION_AFTER_ACTIVATION = (
        "REBUILD_CANCELLATION_AFTER_ACTIVATION"
    )
    REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN = (
        "REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN"
    )
    LIFECYCLE_APPROVAL_REQUIRED = "LIFECYCLE_APPROVAL_REQUIRED"
    LIFECYCLE_PLAN_MISMATCH = "LIFECYCLE_PLAN_MISMATCH"


class ScopedObjectNotFoundError(LookupError):
    """Internal absence signal; its message is never emitted to a client."""


class ScopedObjectAccessDeniedError(PermissionError):
    """Internal authorization signal; its message is never emitted to a client."""


class PreviousTurnNotClosedError(RuntimeError):
    """Safe operational signal: a new turn must wait for the current turn."""


class ChannelUnavailableError(RuntimeError):
    """Safe operational signal: an optional/runtime channel is unavailable."""


class WorkflowOperationalError(RuntimeError):
    """One closed P6 correction/failure code safe for the counselor tool."""

    def __init__(self, code: str | WorkflowErrorCode) -> None:
        try:
            self.code = WorkflowErrorCode(code)
        except ValueError:
            raise TypeError("workflow error code is not in the closed set") from None
        super().__init__(self.code.value)


def client_visible_error(code: ClientVisibleErrorCode) -> ToolError:
    """Build one of the closed, caller-content-free client-visible templates."""

    if type(code) is not ClientVisibleErrorCode:
        raise TypeError("client-visible errors require ClientVisibleErrorCode")
    if code is ClientVisibleErrorCode.SCOPE_DENIED:
        return ToolError(
            code=code.value,
            message="The requested resource is unavailable.",
        )
    if code is ClientVisibleErrorCode.PREVIOUS_TURN_NOT_CLOSED:
        return ToolError(
            code=code.value,
            message="Close the current turn before starting another turn.",
        )
    if code is ClientVisibleErrorCode.CHANNEL_UNAVAILABLE:
        return ToolError(
            code=code.value,
            message="The requested channel is currently unavailable.",
            retryable=True,
        )
    if code is ClientVisibleErrorCode.INTERNAL_ERROR:
        return ToolError(
            code=code.value,
            message="The request could not be completed.",
        )
    raise AssertionError("unhandled closed client-visible error code")


def workflow_visible_error(code: WorkflowErrorCode) -> ToolError:
    """Render one closed workflow correction without caller-controlled prose."""

    messages: dict[WorkflowErrorCode, tuple[str, bool]] = {
        WorkflowErrorCode.QUERY_PLAN_CORRECTION_REQUIRED: (
            "Revise the query plan to satisfy required routes and evidence checks.",
            True,
        ),
        WorkflowErrorCode.GENERATION_STAGE_ORDER_INVALID: (
            "Submit the next required generation stage in order.",
            True,
        ),
        WorkflowErrorCode.GENERATION_PARENT_MISMATCH: (
            "Regenerate the stage against the exact active parent artifacts.",
            True,
        ),
        WorkflowErrorCode.QUALITY_RETRY_EXHAUSTED: (
            "Automated quality retries are exhausted; counselor judgment is required.",
            False,
        ),
        WorkflowErrorCode.GENERATION_BINDING_MISMATCH: (
            "The generation artifact does not match the bound turn and run.",
            False,
        ),
        WorkflowErrorCode.GENERATION_STAGE_CONFLICT: (
            "The generation stage conflicts with the current saved state.",
            True,
        ),
        WorkflowErrorCode.GENERATION_STAGE_IDEMPOTENCY_CONFLICT: (
            "The idempotency key is already bound to different stage content.",
            False,
        ),
        WorkflowErrorCode.GENERATION_STAGE_REVISION_REASON_REQUIRED: (
            "Provide an explicit revision reason for changed stage content.",
            True,
        ),
        WorkflowErrorCode.GENERATION_STAGE_REVISION_CLOSED: (
            "This generation stage can no longer be revised.",
            False,
        ),
        WorkflowErrorCode.CLIENT_REPLY_RISK_LEAKAGE: (
            "Regenerate the client reply without internal risk metadata or labels.",
            True,
        ),
        WorkflowErrorCode.RISK_OBSERVATION_UNAVAILABLE: (
            "The risk observation is unavailable in this consultation scope.",
            False,
        ),
        WorkflowErrorCode.RISK_LIFECYCLE_CONFLICT: (
            "The requested risk lifecycle transition conflicts with saved state.",
            False,
        ),
        WorkflowErrorCode.RISK_EVALUATION_INCOMPLETE: (
            "Complete the durable turn risk evaluation before generation.",
            True,
        ),
        WorkflowErrorCode.CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED: (
            "The active client knowledge artifacts require a verified rebuild.",
            False,
        ),
        WorkflowErrorCode.REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE: (
            "The required production rebuild builders are unavailable.",
            False,
        ),
        WorkflowErrorCode.REBUILD_JOB_NOT_FOUND: (
            "The rebuild job is unavailable in this bound scope.",
            False,
        ),
        WorkflowErrorCode.REBUILD_JOB_STATE_CONFLICT: (
            "The rebuild job no longer permits this state transition.",
            True,
        ),
        WorkflowErrorCode.REBUILD_CANCELLATION_AFTER_ACTIVATION: (
            "The rebuild can no longer be cancelled after activation begins.",
            False,
        ),
        WorkflowErrorCode.REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN: (
            "A rebuild required by a source deletion cannot be cancelled.",
            False,
        ),
        WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED: (
            "This lifecycle operation requires an exact current approval.",
            False,
        ),
        WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH: (
            "The lifecycle request no longer matches its approved plan and base versions.",
            False,
        ),
    }
    message, retryable = messages[code]
    return ToolError(code=code.value, message=message, retryable=retryable)


def map_exception_to_client_error(error: BaseException) -> ToolError:
    """Map internal failures without echoing bodies, paths, IDs, or existence."""

    if not isinstance(error, BaseException):
        raise TypeError("error mapping requires an exception instance")
    if isinstance(error, (ScopedObjectNotFoundError, ScopedObjectAccessDeniedError)):
        return client_visible_error(ClientVisibleErrorCode.SCOPE_DENIED)
    if isinstance(error, PreviousTurnNotClosedError):
        return client_visible_error(ClientVisibleErrorCode.PREVIOUS_TURN_NOT_CLOSED)
    if isinstance(error, ChannelUnavailableError):
        return client_visible_error(ClientVisibleErrorCode.CHANNEL_UNAVAILABLE)
    if isinstance(error, WorkflowOperationalError):
        return workflow_visible_error(error.code)
    return client_visible_error(ClientVisibleErrorCode.INTERNAL_ERROR)
