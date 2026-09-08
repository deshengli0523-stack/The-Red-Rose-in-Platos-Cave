"""Resolve validated capabilities into exact internal client scope descriptors."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, NoReturn, SupportsIndex, final

from consultation_kb.models.common import SessionScope
from consultation_kb.security.capability import (
    CapabilityDenied,
    CapabilityService,
)
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.catalog import ClientCatalog, ClientCatalogError


class ScopeBrokerDenied(PermissionError):
    def __init__(self) -> None:
        super().__init__("SCOPE_DENIED")


def _stream_sha256(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        if type(chunk) is not bytes:
            raise ScopeBrokerDenied
        digest.update(chunk)
    return digest.hexdigest()


@final
@dataclass(frozen=True, slots=True, repr=False)
class ScopedSession:
    session_scope: SessionScope
    client_id: str
    client_root: Path
    client_database: Path
    global_database: Path
    scope_marker_sha256: str
    global_descriptor_sha256: str
    capability_id: str
    capability_epoch: int

    def __repr__(self) -> str:
        return "<ScopedSession redacted>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("SCOPED_SESSION_SERIALIZATION_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("SCOPED_SESSION_SERIALIZATION_FORBIDDEN")


@final
class ScopeBroker:
    def __init__(
        self,
        *,
        capability_service: CapabilityService,
        catalog: ClientCatalog,
        clients_root: Path,
        global_database: Path,
    ) -> None:
        self._capability_service = capability_service
        self._catalog = catalog
        self._clients_root = Path(clients_root)
        self._global_database = Path(global_database)

    def authorize(
        self,
        token: str,
        *,
        session_id: str,
        client_id: str,
        required_permissions: Iterable[str],
    ) -> ScopedSession:
        try:
            binding = self._capability_service.validate_binding(
                token,
                session_id=session_id,
                client_id=client_id,
                required_permissions=required_permissions,
            )
            record = self._catalog.require_active(binding.client_id)
            root = self._clients_root
            if not root.is_absolute() or ".." in root.parts:
                raise ScopeBrokerDenied
            client_root = root / binding.client_id
            client_database = client_root / "client.sqlite3"
            global_database = self._global_database
            if not global_database.is_absolute() or ".." in global_database.parts:
                raise ScopeBrokerDenied
            expected_marker = f"{record.directory_object_id}\n".encode("ascii")
            relative_marker = Path(binding.client_id) / ".scope-id"
            relative_database = Path(binding.client_id) / "client.sqlite3"
            client_guard = PathGuard(root)
            with client_guard.pin_scoped_directory(Path(binding.client_id)):
                with client_guard.open_scoped(
                    relative_marker,
                    mode="rb",
                ) as marker:
                    marker_bytes = marker.read(4097)
                    if not hmac.compare_digest(marker_bytes, expected_marker):
                        raise ScopeBrokerDenied
                    scope_marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
                    with client_guard.open_scoped(
                        relative_database,
                        mode="rb",
                    ) as database:
                        database.read(0)
                        with PathGuard(global_database.parent).open_scoped(
                            global_database.name,
                            mode="rb",
                        ) as global_handle:
                            global_descriptor_sha256 = _stream_sha256(
                                global_handle
                            )
            return ScopedSession(
                session_scope=binding.session_scope,
                client_id=binding.client_id,
                client_root=client_root,
                client_database=client_database,
                global_database=global_database,
                scope_marker_sha256=scope_marker_sha256,
                global_descriptor_sha256=global_descriptor_sha256,
                capability_id=binding.capability_id,
                capability_epoch=binding.capability_epoch,
            )
        except (
            CapabilityDenied,
            ClientCatalogError,
            OSError,
            ScopePathDenied,
            UnicodeError,
            ValueError,
        ):
            raise ScopeBrokerDenied from None


__all__ = ["ScopeBroker", "ScopeBrokerDenied", "ScopedSession"]
