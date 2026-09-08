"""Governed two-stage client creation for the local MCP control process.

The public adapter intentionally exposes only the newly allocated opaque client
identifier and the one-shot approval request identifier.  The human-readable
alias remains inside the DPAPI-protected identity map owned by
``ClientCreationService``; it is never copied into the global CAS review diff.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path
from typing import Final, Literal, Protocol, final

from pydantic import ValidationError

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    ProtectedProviderSecretStore,
    ProviderSecretUnavailable,
)
from consultation_kb.approvals.store import (
    ApprovalError,
    ApprovalExpired,
    ApprovalMismatch,
    ApprovalProviderRejected,
    ApprovalRequired,
    ApprovalService,
    ApprovalUnavailable,
    ApprovalUsed,
)
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.clock import Clock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.errors import (
    ChannelUnavailableError,
    ScopedObjectAccessDeniedError,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ClientId, ObjectId, StrictModel, VersionRef
from consultation_kb.security.dpapi import SecretProtector
from consultation_kb.security.ntfs_acl import AclPolicy, AclPolicyViolation
from consultation_kb.storage.catalog import (
    ClientCatalog,
    ClientCatalogError,
    ClientCreationFailed,
    ClientCreationService,
    DuplicateClientAlias,
    IdentityMapEraseResult,
)
from consultation_kb.vault.content_store import ContentStore, ContentStoreError
from consultation_kb.vault.layout import VaultLayout

from .context import BoundTransport


_ALIAS_LOOKUP_KEY_DOMAIN: Final = b"consultation-kb/client-alias-lookup/v1"
_DIFF_DESCRIPTION: Final = "Create a new empty consultation client scope."
_DIFF_MEDIA_TYPE: Final = "application/json"
_DIFF_PURPOSE: Final = "client_creation_diff"


class ClientCreationRuntimeError(RuntimeError):
    """Content-free failure at the MCP-to-client-catalog boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ClientCreationPreviewResult(StrictModel):
    """Safe result returned before the counselor confirms the review diff."""

    status: Literal["approval_required"] = "approval_required"
    client_id: ClientId
    approval_request_id: ObjectId


class ClientCreationCommitResult(StrictModel):
    """Safe result returned only after the approved scope is active."""

    status: Literal["active"] = "active"
    client_id: ClientId


class _ClientCreationPort(Protocol):
    def preview(self, *, alias: str, idempotency_key: str) -> object: ...

    def commit(self, request_id: str) -> object: ...

    def has_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
    ) -> bool: ...

    def erase_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
        allow_absent: bool = False,
    ) -> IdentityMapEraseResult: ...


def _request_field(request: object, name: str) -> object:
    try:
        return getattr(request, name)
    except Exception:
        raise ClientCreationRuntimeError("CLIENT_CREATION_REQUEST_INVALID") from None


def _optional_request_field(request: object, name: str) -> object:
    try:
        return getattr(request, name, None)
    except Exception:
        raise ClientCreationRuntimeError("CLIENT_CREATION_REQUEST_INVALID") from None


def _string_result_field(result: object, name: str) -> str:
    value = _request_field(result, name)
    if type(value) is not str or not value:
        raise ClientCreationRuntimeError("CLIENT_CREATION_FAILED")
    return value


def _domain_error(error: BaseException) -> BaseException:
    # Approval state, alias duplication, and target existence all cross the same
    # closed outward boundary.  No internal code may reveal which condition held.
    if isinstance(
        error,
        (
            DuplicateClientAlias,
            ApprovalRequired,
            ApprovalExpired,
            ApprovalUsed,
            ApprovalMismatch,
            ApprovalProviderRejected,
            ApprovalUnavailable,
        ),
    ):
        return ScopedObjectAccessDeniedError()
    if isinstance(error, (ClientCreationFailed, ClientCatalogError, ApprovalError)):
        return ClientCreationRuntimeError("CLIENT_CREATION_FAILED")
    return ClientCreationRuntimeError("CLIENT_CREATION_FAILED")


@final
class ClientCreationRuntime:
    """One strict MCP tool with mutually exclusive preview and commit actions."""

    def __init__(self, service: _ClientCreationPort) -> None:
        if service is None:
            raise TypeError("client creation runtime requires a service")
        self._service = service

    @property
    def lifecycle_identity_registry(self) -> _ClientCreationPort:
        """Internal exact identity-map authority for whole-client cleanup."""

        return self._service

    def invoke(
        self,
        tool_name: str,
        request: object,
        *,
        binding: BoundTransport | None,
    ) -> ClientCreationPreviewResult | ClientCreationCommitResult:
        if tool_name != "create_client":
            raise ClientCreationRuntimeError("CLIENT_CREATION_TOOL_UNSUPPORTED")
        if binding is not None:
            raise ClientCreationRuntimeError("GLOBAL_TOOL_BINDING_FORBIDDEN")

        action = _request_field(request, "action")
        alias = _optional_request_field(request, "alias")
        idempotency_key = _optional_request_field(request, "idempotency_key")
        approval_request_id = _optional_request_field(
            request,
            "approval_request_id",
        )
        if action == "preview":
            if (
                type(alias) is not str
                or not alias
                or type(idempotency_key) is not str
                or not idempotency_key
                or approval_request_id is not None
            ):
                raise ClientCreationRuntimeError("CLIENT_CREATION_REQUEST_INVALID")
            try:
                preview = self._service.preview(
                    alias=alias,
                    idempotency_key=idempotency_key,
                )
                return ClientCreationPreviewResult(
                    client_id=_string_result_field(preview, "client_id"),
                    approval_request_id=_string_result_field(preview, "request_id"),
                )
            except ClientCreationRuntimeError:
                raise
            except (ClientCatalogError, ApprovalError, ValidationError) as error:
                raise _domain_error(error) from None
            except Exception:
                raise ClientCreationRuntimeError("CLIENT_CREATION_FAILED") from None

        if action == "commit":
            if (
                alias is not None
                or idempotency_key is not None
                or type(approval_request_id) is not str
                or not approval_request_id
            ):
                raise ClientCreationRuntimeError("CLIENT_CREATION_REQUEST_INVALID")
            try:
                record = self._service.commit(approval_request_id)
                if _request_field(record, "state") != "ACTIVE":
                    raise ClientCreationRuntimeError("CLIENT_CREATION_FAILED")
                return ClientCreationCommitResult(
                    client_id=_string_result_field(record, "client_id")
                )
            except ClientCreationRuntimeError:
                raise
            except (ClientCatalogError, ApprovalError, ValidationError) as error:
                raise _domain_error(error) from None
            except Exception:
                raise ClientCreationRuntimeError("CLIENT_CREATION_FAILED") from None

        raise ClientCreationRuntimeError("CLIENT_CREATION_REQUEST_INVALID")


@final
class _DeidentifiedCreationDiffFactory:
    """Write an alias-free creation summary to the fixed global CAS."""

    def __init__(self, store: ContentStore, id_factory: IdFactory) -> None:
        if type(store) is not ContentStore or type(id_factory) is not IdFactory:
            raise TypeError("client creation diff requires production authorities")
        self._store = store
        self._ids = id_factory

    def __call__(self, alias: str, client_id: str) -> VersionRef:
        # The alias is intentionally consumed only by ClientCreationService's
        # encrypted identity map.  The review diff is safe to retain globally.
        del alias
        object_id = self._ids.object_id("client_creation_diff")
        payload = json.dumps(
            {
                "client_id": client_id,
                "description": _DIFF_DESCRIPTION,
                "operation": "create_client",
                "schema_version": 1,
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        stored = self._store.finalize(
            self._store.stage_bytes(
                payload,
                purpose=_DIFF_PURPOSE,
                manifest_id=object_id,
                media_type=_DIFF_MEDIA_TYPE,
            )
        )
        return VersionRef(
            object_id=object_id,
            version=1,
            content_sha256=stored.content_sha256,
        )


def _alias_lookup_secret(store: ProtectedProviderSecretStore) -> bytes:
    root_secret = store.load()
    if type(root_secret) is not bytes or len(root_secret) != 32:
        raise ProviderSecretUnavailable("provider secret is unavailable")
    return hmac.new(
        root_secret,
        _ALIAS_LOOKUP_KEY_DOMAIN,
        hashlib.sha256,
    ).digest()


def vault_security_id(vault_root: Path) -> str:
    """Return the single canonical vault protection context identifier."""

    if not isinstance(vault_root, Path) or not vault_root.is_absolute():
        raise ValueError("vault security ID requires an absolute pathlib.Path")
    identity = os.path.normcase(os.path.normpath(os.fspath(vault_root)))
    digest = hashlib.sha256(identity.encode("utf-8", errors="strict")).hexdigest()
    return f"vault_{digest}"


def build_production_client_creation_runtime(
    *,
    config: AppConfig,
    connection: sqlite3.Connection,
    approval_service: ApprovalService,
    execution_guard: ApprovalExecutionGuard,
    protector: SecretProtector,
    protected_secret_store: ProtectedProviderSecretStore,
    content_store: ContentStore,
    vault_id: str,
    clock: Clock,
    id_factory: IdFactory,
) -> ClientCreationRuntime:
    """Compose client creation only when all protected authorities are live.

    The caller supplies the exact global approval service, execution guard and
    CAS already owned by the MCP process.  This function never constructs a
    second approval authority and never falls back to an unprotected key or a
    permissive filesystem policy.
    """

    try:
        if (
            type(config) is not AppConfig
            or not isinstance(connection, sqlite3.Connection)
            or not isinstance(approval_service, ApprovalService)
            or not isinstance(execution_guard, ApprovalExecutionGuard)
            or type(protected_secret_store) is not ProtectedProviderSecretStore
            or type(content_store) is not ContentStore
            or type(id_factory) is not IdFactory
        ):
            raise TypeError
        layout = VaultLayout.from_config(config)  # type: ignore[attr-defined]
        if vault_id != vault_security_id(config.vault_root):
            raise ValueError
        acl_policy = AclPolicy()
        protected_directories = (
            layout.clients_root,
            layout.identity_map.parent,
            layout.global_db.parent,
            config.vault_root / "security",
        )
        for protected_directory in protected_directories:
            acl_policy.verify(protected_directory)
        alias_secret = _alias_lookup_secret(protected_secret_store)
        creation = ClientCreationService(
            catalog=ClientCatalog(connection),
            approval_service=approval_service,
            execution_guard=execution_guard,
            protector=protector,
            acl_policy=acl_policy,
            clock=clock,
            id_factory=id_factory,
            client_id_factory=ClientIdFactory(),
            clients_root=layout.clients_root,
            identity_map_path=layout.identity_map,
            vault_id=vault_id,
            alias_lookup_secret=alias_secret,
            diff_ref_factory=_DeidentifiedCreationDiffFactory(
                content_store,
                id_factory,
            ),
        )
        return ClientCreationRuntime(creation)
    except ClientCreationRuntimeError:
        raise
    except (
        AclPolicyViolation,
        ProviderSecretUnavailable,
        ClientCatalogError,
        ContentStoreError,
        OSError,
        TypeError,
        ValueError,
    ):
        raise ChannelUnavailableError() from None
    except Exception:
        raise ChannelUnavailableError() from None


__all__ = [
    "ClientCreationCommitResult",
    "ClientCreationPreviewResult",
    "ClientCreationRuntime",
    "ClientCreationRuntimeError",
    "build_production_client_creation_runtime",
    "vault_security_id",
]
