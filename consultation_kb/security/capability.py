"""One-time opaque session capabilities bound to exact clients."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast, final

from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import (
    ClientId,
    Permission,
    SessionScope,
    Uuid7String,
)
from consultation_kb.storage.catalog import ClientCatalog, ClientCatalogError
from consultation_kb.storage.connection import transaction


_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_PERMISSIONS = frozenset(
    {"client_read", "session_append", "draft_write", "formal_write"}
)
_CLIENT_ADAPTER = TypeAdapter(ClientId)
_SESSION_ADAPTER = TypeAdapter(Uuid7String)


class CapabilityDenied(PermissionError):
    def __init__(self) -> None:
        super().__init__("CAPABILITY_DENIED")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CapabilityDenied
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise CapabilityDenied
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CapabilityDenied from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise CapabilityDenied
    return parsed


def _validate_client_id(value: object) -> str:
    try:
        return _CLIENT_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise CapabilityDenied from None


def _validate_session_id(value: object) -> str:
    try:
        return _SESSION_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise CapabilityDenied from None


def _permissions(values: Iterable[str]) -> frozenset[Permission]:
    if isinstance(values, str):
        raise CapabilityDenied
    try:
        collected = frozenset(values)
    except (TypeError, ValueError):
        raise CapabilityDenied from None
    if (
        not collected
        or any(type(value) is not str for value in collected)
        or not collected <= _ALLOWED_PERMISSIONS
    ):
        raise CapabilityDenied
    return cast(frozenset[Permission], collected)


def _permissions_json(values: frozenset[Permission]) -> str:
    return json.dumps(
        sorted(values),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _parse_permissions(value: object) -> frozenset[Permission]:
    if type(value) is not str:
        raise CapabilityDenied
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        raise CapabilityDenied from None
    if type(parsed) is not list:
        raise CapabilityDenied
    permissions = _permissions(parsed)
    if value != _permissions_json(permissions):
        raise CapabilityDenied
    return permissions


def _token_hash(token: object) -> str:
    if type(token) is not str or _TOKEN_RE.fullmatch(token) is None:
        raise CapabilityDenied
    try:
        raw = base64.urlsafe_b64decode(f"{token}=")
    except (ValueError, TypeError):
        raise CapabilityDenied from None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != token:
        raise CapabilityDenied
    return hashlib.sha256(token.encode("ascii")).hexdigest()


@final
@dataclass(frozen=True, slots=True, repr=False)
class CapabilityBinding:
    capability_id: str
    client_id: str
    capability_epoch: int
    session_scope: SessionScope

    def __repr__(self) -> str:
        return "<CapabilityBinding redacted>"


@final
class CapabilityService:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        catalog: ClientCatalog,
        clock: Clock,
        id_factory: IdFactory,
        token_source: Callable[[int], bytes] = secrets.token_bytes,
        ttl: timedelta = timedelta(minutes=30),
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("capability service requires sqlite3.Connection")
        if not isinstance(catalog, ClientCatalog) or not catalog.uses_connection(
            connection
        ):
            raise TypeError("capability catalog connection mismatch")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise ValueError("capability TTL must be positive")
        self._connection = connection
        self._catalog = catalog
        self._clock = clock
        self._id_factory = id_factory
        self._token_source = token_source
        self._ttl = ttl

    def issue(
        self,
        *,
        client_id: str,
        session_id: str,
        permissions: Iterable[str],
    ) -> str:
        validated_client = _validate_client_id(client_id)
        validated_session = _validate_session_id(session_id)
        granted = _permissions(permissions)
        now = self._clock.now()
        expires_at = now + self._ttl
        try:
            raw_token = self._token_source(32)
        except Exception:
            raise CapabilityDenied from None
        if type(raw_token) is not bytes or len(raw_token) != 32:
            raise CapabilityDenied
        token = base64.urlsafe_b64encode(raw_token).rstrip(b"=").decode("ascii")
        token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        capability_id = self._id_factory.object_id("capability")
        try:
            with transaction(self._connection):
                self._catalog.require_active(validated_client)
                self._connection.execute(
                    """
                    INSERT INTO capabilities(
                        capability_id, token_sha256, session_id, client_id,
                        permissions_json, issued_at, expires_at, revoked_at,
                        state, capability_epoch
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'ACTIVE', 1)
                    """,
                    (
                        capability_id,
                        token_sha256,
                        validated_session,
                        validated_client,
                        _permissions_json(granted),
                        _utc_text(now),
                        _utc_text(expires_at),
                    ),
                )
        except (sqlite3.IntegrityError, ClientCatalogError):
            raise CapabilityDenied from None
        return token

    def validate_binding(
        self,
        token: str,
        *,
        session_id: str,
        client_id: str,
        required_permissions: Iterable[str],
    ) -> CapabilityBinding:
        computed_hash = _token_hash(token)
        expected_session = _validate_session_id(session_id)
        expected_client = _validate_client_id(client_id)
        required = _permissions(required_permissions)
        row = self._connection.execute(
            """
            SELECT capability_id, token_sha256, session_id, client_id,
                   permissions_json, expires_at, revoked_at, state,
                   capability_epoch
              FROM capabilities WHERE token_sha256 = ?
            """,
            (computed_hash,),
        ).fetchone()
        if row is None:
            hmac.compare_digest(computed_hash, "0" * 64)
            raise CapabilityDenied
        if (
            len(row) != 9
            or type(row[0]) is not str
            or type(row[1]) is not str
            or _SHA256_RE.fullmatch(row[1]) is None
            or not hmac.compare_digest(computed_hash, row[1])
            or row[2] != expected_session
            or row[3] != expected_client
            or row[6] is not None
            or row[7] != "ACTIVE"
            or type(row[8]) is not int
            or row[8] <= 0
        ):
            raise CapabilityDenied
        granted = _parse_permissions(row[4])
        if not required <= granted or self._clock.now() >= _parse_utc(row[5]):
            raise CapabilityDenied
        try:
            self._catalog.require_active(expected_client)
            scope = SessionScope(
                session_handle=row[0],
                session_id=expected_session,
                permissions=granted,
                expires_at=_parse_utc(row[5]),
            )
        except (ClientCatalogError, ValidationError):
            raise CapabilityDenied from None
        return CapabilityBinding(
            capability_id=row[0],
            client_id=expected_client,
            capability_epoch=row[8],
            session_scope=scope,
        )

    def renew(
        self,
        *,
        client_id: str,
        session_id: str,
        previous_epoch: int,
    ) -> str:
        """Atomically rotate one session capability with strict CAS semantics.

        A retry using an already-consumed ``previous_epoch`` is a conflict and
        is denied.  The caller must reconcile the current session epoch before
        attempting another renewal; token material is never recoverable from
        the stored hash.
        """

        validated_client = _validate_client_id(client_id)
        validated_session = _validate_session_id(session_id)
        if type(previous_epoch) is not int or previous_epoch <= 0:
            raise CapabilityDenied
        now = self._clock.now()
        expires_at = now + self._ttl
        try:
            raw_token = self._token_source(32)
        except Exception:
            raise CapabilityDenied from None
        if type(raw_token) is not bytes or len(raw_token) != 32:
            raise CapabilityDenied
        token = base64.urlsafe_b64encode(raw_token).rstrip(b"=").decode("ascii")
        token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        try:
            with transaction(self._connection):
                self._catalog.require_active(validated_client)
                updated = self._connection.execute(
                    """
                    UPDATE capabilities
                       SET token_sha256 = ?, issued_at = ?, expires_at = ?,
                           revoked_at = NULL, state = 'ACTIVE',
                           capability_epoch = capability_epoch + 1
                     WHERE client_id = ? AND session_id = ?
                       AND capability_epoch = ? AND token_sha256 <> ?
                    """,
                    (
                        token_sha256,
                        _utc_text(now),
                        _utc_text(expires_at),
                        validated_client,
                        validated_session,
                        previous_epoch,
                        token_sha256,
                    ),
                )
                if updated.rowcount != 1:
                    raise CapabilityDenied
        except (sqlite3.IntegrityError, ClientCatalogError):
            raise CapabilityDenied from None
        return token

    def current_epoch(self, *, client_id: str, session_id: str) -> int:
        """Return the exact persisted epoch for an existing session binding.

        Resume needs the latest compare-and-swap value even when the prior
        capability has expired or been revoked.  This lookup intentionally
        returns no other capability material and fails uniformly for unknown,
        malformed, or retired client bindings.
        """

        validated_client = _validate_client_id(client_id)
        validated_session = _validate_session_id(session_id)
        try:
            self._catalog.require_active(validated_client)
            row = self._connection.execute(
                """
                SELECT capability_epoch
                  FROM capabilities
                 WHERE client_id = ? AND session_id = ?
                """,
                (validated_client, validated_session),
            ).fetchone()
        except ClientCatalogError:
            raise CapabilityDenied from None
        if row is None or len(row) != 1 or type(row[0]) is not int or row[0] <= 0:
            raise CapabilityDenied
        return row[0]

    def validate(
        self,
        token: str,
        *,
        session_id: str,
        client_id: str,
        required_permissions: Iterable[str],
    ) -> SessionScope:
        return self.validate_binding(
            token,
            session_id=session_id,
            client_id=client_id,
            required_permissions=required_permissions,
        ).session_scope

    def revoke(self, token: str) -> int:
        computed_hash = _token_hash(token)
        now = self._clock.now()
        with transaction(self._connection):
            row = self._connection.execute(
                """
                SELECT token_sha256, state, capability_epoch
                  FROM capabilities WHERE token_sha256 = ?
                """,
                (computed_hash,),
            ).fetchone()
            if (
                row is None
                or len(row) != 3
                or type(row[0]) is not str
                or not hmac.compare_digest(computed_hash, row[0])
                or type(row[2]) is not int
                or row[2] <= 0
            ):
                raise CapabilityDenied
            if row[1] == "REVOKED":
                return row[2]
            if row[1] != "ACTIVE":
                raise CapabilityDenied
            next_epoch = row[2] + 1
            updated = self._connection.execute(
                """
                UPDATE capabilities
                   SET state = 'REVOKED', revoked_at = ?, capability_epoch = ?
                 WHERE token_sha256 = ? AND state = 'ACTIVE'
                """,
                (_utc_text(now), next_epoch, computed_hash),
            )
            if updated.rowcount != 1:
                raise CapabilityDenied
            return next_epoch

    def assert_active_epoch(self, capability_id: str, epoch: int) -> None:
        if type(capability_id) is not str or type(epoch) is not int or epoch <= 0:
            raise CapabilityDenied
        row = self._connection.execute(
            """
            SELECT state, capability_epoch, expires_at, client_id
              FROM capabilities WHERE capability_id = ?
            """,
            (capability_id,),
        ).fetchone()
        try:
            if (
                row is None
                or len(row) != 4
                or row[0] != "ACTIVE"
                or row[1] != epoch
                or self._clock.now() >= _parse_utc(row[2])
            ):
                raise CapabilityDenied
            self._catalog.require_active(_validate_client_id(row[3]))
        except ClientCatalogError:
            raise CapabilityDenied


__all__ = [
    "CapabilityBinding",
    "CapabilityDenied",
    "CapabilityService",
]
