"""Draft and approval contract models."""

from __future__ import annotations

from typing import Literal

from pydantic import GetJsonSchemaHandler, model_validator
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from .common import (
    ClientId,
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
)


DraftPurpose = Literal[
    "create_client",
    "profile_update",
    "private_archive_publish",
    "case_publish",
    "passage_approve",
    "claim_approve",
    "claim_revoke",
    "theory_approve",
    "theory_revoke",
    "wiki_publish",
    "rebuild",
    "rollback",
    "delete",
]


class DraftDescriptor(StrictModel):
    purpose: DraftPurpose
    target_id: NonEmptyStr
    client_id: ClientId | None = None
    base_version: NonNegativeInt
    draft_sha256: Sha256Hex
    session_id: Uuid7String | None = None


class ApprovalReceipt(StrictModel):
    request_id: ObjectId
    descriptor_sha256: Sha256Hex
    approver_role: Literal["primary_counselor"]
    approved_at: UtcDateTime
    expires_at: UtcDateTime
    nonce: NonEmptyStr
    provider_id: NonEmptyStr
    signature: NonEmptyStr

    @model_validator(mode="after")
    def _validate_expiry(self) -> "ApprovalReceipt":
        if self.expires_at <= self.approved_at:
            raise ValueError("expires_at must be later than approved_at")
        return self


class ApprovalExecution(StrictModel):
    operation_id: ObjectId
    request_id: ObjectId
    descriptor_sha256: Sha256Hex
    target_scope_hash: Sha256Hex
    state: Literal["issued", "claimed", "applied", "acknowledged"]
    applied_commit_version: PositiveInt | None = None

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        rendered["oneOf"] = [
            {
                "properties": {
                    "state": {"enum": ["issued", "claimed"]},
                    "applied_commit_version": {"type": "null"},
                }
            },
            {
                "properties": {
                    "state": {"enum": ["applied", "acknowledged"]},
                    "applied_commit_version": {"not": {"type": "null"}},
                },
                "required": ["applied_commit_version"],
            },
        ]
        return rendered

    @model_validator(mode="after")
    def _validate_state(self) -> "ApprovalExecution":
        pending = self.state in {"issued", "claimed"}
        if pending and self.applied_commit_version is not None:
            raise ValueError("unapplied approval execution must not have a commit version")
        if not pending and self.applied_commit_version is None:
            raise ValueError("applied approval execution requires a commit version")
        return self
