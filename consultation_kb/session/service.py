"""Control-plane begin/resume service with permanent transport binding."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from pydantic import Field

from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    Sha256Hex,
    StrictModel,
    Uuid7String,
)
from consultation_kb.session.context import ClientContextSnapshot
from consultation_kb.session.repository import SessionConflict, SessionRepository


class SessionServiceError(RuntimeError):
    """Base fixed-code control-plane session error."""


class TaskScopeAlreadyBound(SessionServiceError):
    def __init__(self) -> None:
        super().__init__("TASK_SCOPE_ALREADY_BOUND")


class ClientUnavailable(SessionServiceError):
    def __init__(self) -> None:
        super().__init__("CLIENT_UNAVAILABLE")


class CapabilityGrant(StrictModel):
    session_handle: NonEmptyStr
    capability_epoch: int = Field(strict=True, gt=0)


class SessionStart(StrictModel):
    session_handle: NonEmptyStr
    session_id: Uuid7String
    capability_epoch: int = Field(strict=True, gt=0)
    snapshot: ClientContextSnapshot


class ClientContextSource(Protocol):
    def build(self, client_id: str) -> ClientContextSnapshot: ...


class SessionCapabilityPort(Protocol):
    def issue(self, *, client_id: str, session_id: str) -> CapabilityGrant: ...

    def renew(
        self,
        *,
        client_id: str,
        session_id: str,
        previous_epoch: int,
    ) -> CapabilityGrant: ...

    def revoke(self, session_handle: str) -> int: ...


@dataclass(frozen=True, slots=True)
class TransportBinding:
    client_id: str
    session_id: str


class TransportBindingRegistry:
    def __init__(self) -> None:
        self._bindings: dict[str, TransportBinding] = {}
        self._lock = threading.Lock()

    def lookup(self, transport_session_id: str) -> TransportBinding | None:
        if type(transport_session_id) is not str or not transport_session_id:
            raise ValueError("transport_session_id must be nonempty")
        with self._lock:
            return self._bindings.get(transport_session_id)

    def bind(
        self,
        *,
        transport_session_id: str,
        client_id: str,
        session_id: str,
    ) -> None:
        if type(transport_session_id) is not str or not transport_session_id:
            raise ValueError("transport_session_id must be nonempty")
        proposed = TransportBinding(client_id=client_id, session_id=session_id)
        with self._lock:
            existing = self._bindings.get(transport_session_id)
            if existing is not None and existing != proposed:
                raise TaskScopeAlreadyBound
            self._bindings[transport_session_id] = proposed


class SessionService:
    def __init__(
        self,
        repository: SessionRepository,
        *,
        context_source: ClientContextSource,
        capability_port: SessionCapabilityPort,
        transport_bindings: TransportBindingRegistry,
        clock: Clock,
        id_factory: IdFactory,
        bound_client_id: ClientId,
        client_scope_hash: Sha256Hex,
    ) -> None:
        self._repository = repository
        self._context_source = context_source
        self._capability_port = capability_port
        self._transport_bindings = transport_bindings
        self._clock = clock
        self._id_factory = id_factory
        self._bound_client_id = bound_client_id
        self._client_scope_hash = client_scope_hash
        self._handles: dict[str, str] = {}

    def _require_client(self, client_id: str) -> None:
        if client_id != self._bound_client_id:
            raise ClientUnavailable

    def begin(
        self,
        client_id: str,
        *,
        transport_session_id: str,
    ) -> SessionStart:
        self._require_client(client_id)
        existing = self._transport_bindings.lookup(transport_session_id)
        if existing is not None:
            if existing.client_id != client_id:
                raise TaskScopeAlreadyBound
            return self.resume(
                client_id,
                existing.session_id,
                transport_session_id=transport_session_id,
            )
        snapshot = self._context_source.build(client_id)
        if snapshot.client_id != client_id:
            raise ClientUnavailable
        session_id = self._id_factory.uuid7()
        grant = self._capability_port.issue(client_id=client_id, session_id=session_id)
        try:
            self._repository.create_session(
                session_id=session_id,
                client_id=client_id,
                client_scope_hash=self._client_scope_hash,
                snapshot_version=snapshot.profile_version,
                snapshot_canonical_sha256=snapshot.canonical_sha256,
                snapshot_bytes=snapshot.canonical_bytes(),
                capability_epoch=grant.capability_epoch,
            )
        except Exception:
            self._capability_port.revoke(grant.session_handle)
            raise
        self._transport_bindings.bind(
            transport_session_id=transport_session_id,
            client_id=client_id,
            session_id=session_id,
        )
        self._handles[grant.session_handle] = session_id
        return SessionStart(
            session_handle=grant.session_handle,
            session_id=session_id,
            capability_epoch=grant.capability_epoch,
            snapshot=snapshot,
        )

    def resume(
        self,
        client_id: str,
        session_id: str,
        *,
        transport_session_id: str,
    ) -> SessionStart:
        self._require_client(client_id)
        binding = self._transport_bindings.lookup(transport_session_id)
        if binding is not None and binding != TransportBinding(client_id, session_id):
            raise TaskScopeAlreadyBound
        record = self._repository.get_session(session_id)
        if record.client_id != client_id or record.client_scope_hash != self._client_scope_hash:
            raise ClientUnavailable
        snapshot = self.load_fixed_context(session_id)
        grant = self._capability_port.renew(
            client_id=client_id,
            session_id=session_id,
            previous_epoch=record.capability_epoch,
        )
        self._repository.set_capability_epoch(
            session_id,
            expected_epoch=record.capability_epoch,
            new_epoch=grant.capability_epoch,
        )
        self._transport_bindings.bind(
            transport_session_id=transport_session_id,
            client_id=client_id,
            session_id=session_id,
        )
        self._handles[grant.session_handle] = session_id
        return SessionStart(
            session_handle=grant.session_handle,
            session_id=session_id,
            capability_epoch=grant.capability_epoch,
            snapshot=snapshot,
        )

    def close_capability(self, session_handle: str) -> int:
        new_epoch = self._capability_port.revoke(session_handle)
        session_id = self._handles.pop(session_handle, None)
        if session_id is not None:
            record = self._repository.get_session(session_id)
            if new_epoch > record.capability_epoch:
                self._repository.set_capability_epoch(
                    session_id,
                    expected_epoch=record.capability_epoch,
                    new_epoch=new_epoch,
                )
        return new_epoch

    def load_fixed_context(self, session_id: str) -> ClientContextSnapshot:
        record = self._repository.get_session(session_id)
        try:
            snapshot = ClientContextSnapshot.model_validate_json(
                self._repository.read_snapshot(session_id)
            )
        except Exception:
            raise SessionConflict("SESSION_SNAPSHOT_INVALID") from None
        if (
            snapshot.client_id != record.client_id
            or snapshot.profile_version != record.client_snapshot_version
            or snapshot.canonical_sha256
            != record.client_snapshot_canonical_sha256
        ):
            raise SessionConflict("SESSION_SNAPSHOT_INVALID")
        return snapshot


__all__ = [
    "CapabilityGrant",
    "ClientContextSource",
    "ClientUnavailable",
    "SessionCapabilityPort",
    "SessionService",
    "SessionServiceError",
    "SessionStart",
    "TaskScopeAlreadyBound",
    "TransportBinding",
    "TransportBindingRegistry",
]
