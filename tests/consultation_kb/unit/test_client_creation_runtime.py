from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.approvals.store import ApprovalRequired, ApprovalService
from consultation_kb.core.clock import Clock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.errors import (
    ChannelUnavailableError,
    ScopedObjectAccessDeniedError,
    map_exception_to_client_error,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.client_creation_runtime import (
    ClientCreationRuntime,
    ClientCreationRuntimeError,
    build_production_client_creation_runtime,
    vault_security_id,
)
from consultation_kb.security.dpapi import SecretProtector
from consultation_kb.storage.catalog import DuplicateClientAlias
from consultation_kb.vault.content_store import ContentStore


CLIENT_ID = "client_" + "a1b2c3d4e5f6"
REQUEST_ID = "approval_request_01800000-0000-7000-8000-000000000001"
IDEMPOTENCY_KEY = "client-preview:0001"


@dataclass(frozen=True, slots=True)
class Request:
    action: str
    alias: str | None = None
    idempotency_key: str | None = None
    approval_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class Preview:
    request_id: str = REQUEST_ID
    client_id: str = CLIENT_ID


@dataclass(frozen=True, slots=True)
class Record:
    client_id: str = CLIENT_ID
    state: str = "ACTIVE"


class FakeCreationService:
    def __init__(self) -> None:
        self.preview_calls: list[tuple[str, str]] = []
        self.commit_requests: list[str] = []
        self.preview_error: BaseException | None = None
        self.commit_error: BaseException | None = None

    def preview(self, *, alias: str, idempotency_key: str) -> Preview:
        self.preview_calls.append((alias, idempotency_key))
        if self.preview_error is not None:
            raise self.preview_error
        return Preview()

    def commit(self, request_id: str) -> Record:
        self.commit_requests.append(request_id)
        if self.commit_error is not None:
            raise self.commit_error
        return Record()


class MalformedCreationService:
    def preview(self, *, alias: str, idempotency_key: str) -> object:
        del alias, idempotency_key
        return type(
            "MalformedPreview",
            (),
            {"client_id": 7, "request_id": REQUEST_ID},
        )()

    def commit(self, request_id: str) -> object:
        del request_id
        return type(
            "MalformedRecord",
            (),
            {"client_id": object(), "state": "ACTIVE"},
        )()


def test_preview_returns_only_opaque_client_and_approval_ids() -> None:
    alias = "Private Human Alias"
    service = FakeCreationService()
    runtime = ClientCreationRuntime(service)

    result = runtime.invoke(
        "create_client",
        Request(
            action="preview",
            alias=alias,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        binding=None,
    )

    assert service.preview_calls == [(alias, IDEMPOTENCY_KEY)]
    assert result.model_dump(mode="json") == {
        "status": "approval_required",
        "client_id": CLIENT_ID,
        "approval_request_id": REQUEST_ID,
    }
    encoded = result.model_dump_json()
    assert alias not in encoded
    assert "directory" not in encoded
    assert "path" not in encoded
    assert "sha256" not in encoded


def test_commit_accepts_only_the_approval_request_and_returns_active_id() -> None:
    service = FakeCreationService()
    runtime = ClientCreationRuntime(service)

    result = runtime.invoke(
        "create_client",
        Request(action="commit", approval_request_id=REQUEST_ID),
        binding=None,
    )

    assert service.commit_requests == [REQUEST_ID]
    assert result.model_dump(mode="json") == {
        "status": "active",
        "client_id": CLIENT_ID,
    }


@pytest.mark.parametrize(
    "command",
    (
        Request(
            action="preview",
            alias="Private Alias",
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        Request(action="commit", approval_request_id=REQUEST_ID),
    ),
)
def test_malformed_service_result_fails_closed_without_casting(command: Request) -> None:
    with pytest.raises(
        ClientCreationRuntimeError,
        match="CLIENT_CREATION_FAILED",
    ):
        ClientCreationRuntime(MalformedCreationService()).invoke(
            "create_client",
            command,
            binding=None,
        )


@pytest.mark.parametrize(
    "command",
    (
        Request(action="preview"),
        Request(action="preview", alias="Private Alias"),
        Request(
            action="preview",
            alias="Private Alias",
            idempotency_key=IDEMPOTENCY_KEY,
            approval_request_id=REQUEST_ID,
        ),
        Request(action="commit"),
        Request(
            action="commit",
            alias="Private Alias",
            approval_request_id=REQUEST_ID,
        ),
        Request(
            action="commit",
            idempotency_key=IDEMPOTENCY_KEY,
            approval_request_id=REQUEST_ID,
        ),
        Request(action="other", alias="Private Alias"),
    ),
)
def test_preview_and_commit_fields_are_mutually_exclusive(command: Request) -> None:
    service = FakeCreationService()

    with pytest.raises(
        ClientCreationRuntimeError,
        match="CLIENT_CREATION_REQUEST_INVALID",
    ):
        ClientCreationRuntime(service).invoke(
            "create_client",
            command,
            binding=None,
        )

    assert service.preview_calls == []
    assert service.commit_requests == []


@pytest.mark.parametrize(
    "domain_error",
    (
        DuplicateClientAlias(),
        ApprovalRequired("private approval detail"),
    ),
)
def test_alias_existence_and_approval_state_share_closed_scope_denial(
    domain_error: BaseException,
) -> None:
    alias = "Existence Must Stay Private"
    service = FakeCreationService()
    service.preview_error = domain_error

    with pytest.raises(ScopedObjectAccessDeniedError) as denied:
        ClientCreationRuntime(service).invoke(
            "create_client",
            Request(
                action="preview",
                alias=alias,
                idempotency_key=IDEMPOTENCY_KEY,
            ),
            binding=None,
        )

    outward = map_exception_to_client_error(denied.value).model_dump_json()
    assert '"code":"SCOPE_DENIED"' in outward
    assert alias not in outward
    assert "duplicate" not in outward.lower()
    assert "approval" not in outward.lower()
    assert "exist" not in outward.lower()


def test_missing_protected_authorities_fail_as_channel_unavailable() -> None:
    with pytest.raises(ChannelUnavailableError) as unavailable:
        build_production_client_creation_runtime(
            config=cast(AppConfig, object()),
            connection=cast(sqlite3.Connection, object()),
            approval_service=cast(ApprovalService, object()),
            execution_guard=cast(ApprovalExecutionGuard, object()),
            protector=cast(SecretProtector, object()),
            protected_secret_store=cast(ProtectedProviderSecretStore, object()),
            content_store=cast(ContentStore, object()),
            vault_id="vault_" + "0" * 64,
            clock=cast(Clock, object()),
            id_factory=cast(IdFactory, object()),
        )

    outward = map_exception_to_client_error(unavailable.value)
    assert outward.code == "CHANNEL_UNAVAILABLE"
    assert outward.safe_details == {}


def test_vault_security_id_normalizes_equivalent_path_spellings(
    tmp_path: Path,
) -> None:
    vault = (tmp_path / "VaultRoot").resolve()
    vault.mkdir()
    with_parent_segment = vault / "child" / os.pardir

    assert vault_security_id(with_parent_segment) == vault_security_id(vault)
    if os.name == "nt":
        assert vault_security_id(Path(str(vault).swapcase())) == vault_security_id(vault)
