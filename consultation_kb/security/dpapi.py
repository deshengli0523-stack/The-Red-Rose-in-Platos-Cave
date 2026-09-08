"""Current-user Windows DPAPI protection with explicit context binding."""

from __future__ import annotations

import hashlib
import importlib
import sys
import unicodedata
from typing import Any, Protocol, final


_PLATFORM = sys.platform
_UI_FORBIDDEN = 0x1
_LOCAL_MACHINE = 0x4
_MAX_SECRET_BYTES = 1_048_576
_MAX_PURPOSE_CHARS = 128
_MAX_VAULT_ID_CHARS = 256


class UnsupportedSecurityPlatform(RuntimeError):
    """Raised when a production security primitive is unavailable."""

    def __init__(self) -> None:
        super().__init__("SECURITY_PLATFORM_UNSUPPORTED")


class InvalidSecretContext(ValueError):
    """Raised for invalid secret bytes or context labels."""

    def __init__(self) -> None:
        super().__init__("SECRET_CONTEXT_INVALID")


class SecretProtectionFailed(RuntimeError):
    """Raised when DPAPI cannot protect a secret."""

    def __init__(self) -> None:
        super().__init__("SECRET_PROTECTION_FAILED")


class SecretDecryptionFailed(RuntimeError):
    """Raised when a protected blob cannot be decrypted in this context."""

    def __init__(self) -> None:
        super().__init__("SECRET_DECRYPTION_FAILED")


class SecretProtector(Protocol):
    """Opaque secret protection bound to a vault and purpose."""

    def protect(self, data: bytes, *, purpose: str, vault_id: str) -> bytes: ...

    def unprotect(self, blob: bytes, *, purpose: str, vault_id: str) -> bytes: ...


class DpapiBackend(Protocol):
    """Injectable DPAPI boundary used by platform-independent unit tests."""

    def protect(
        self,
        data: bytes,
        *,
        description: str,
        entropy: bytes,
        flags: int,
    ) -> bytes: ...

    def unprotect(
        self,
        blob: bytes,
        *,
        entropy: bytes,
        flags: int,
    ) -> tuple[str, bytes]: ...


@final
class _WindowsDpapiBackend:
    __slots__ = ("_win32crypt",)

    def __init__(self) -> None:
        if _PLATFORM != "win32":
            raise UnsupportedSecurityPlatform
        self._win32crypt: Any = importlib.import_module("win32crypt")

    def protect(
        self,
        data: bytes,
        *,
        description: str,
        entropy: bytes,
        flags: int,
    ) -> bytes:
        result = self._win32crypt.CryptProtectData(
            data,
            description,
            entropy,
            None,
            None,
            flags,
        )
        if type(result) is not bytes:
            raise SecretProtectionFailed
        return result

    def unprotect(
        self,
        blob: bytes,
        *,
        entropy: bytes,
        flags: int,
    ) -> tuple[str, bytes]:
        result = self._win32crypt.CryptUnprotectData(
            blob,
            entropy,
            None,
            None,
            flags,
        )
        if (
            type(result) is not tuple
            or len(result) != 2
            or type(result[0]) is not str
            or type(result[1]) is not bytes
        ):
            raise SecretDecryptionFailed
        return result[0], result[1]


def _validate_label(value: object, *, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise InvalidSecretContext
    if value != value.strip() or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise InvalidSecretContext
    return value


def _validate_bytes(value: object) -> bytes:
    if type(value) is not bytes or not value or len(value) > _MAX_SECRET_BYTES:
        raise InvalidSecretContext
    return value


def _context(purpose: object, vault_id: object) -> tuple[str, str, bytes]:
    validated_purpose = _validate_label(purpose, maximum=_MAX_PURPOSE_CHARS)
    validated_vault_id = _validate_label(vault_id, maximum=_MAX_VAULT_ID_CHARS)
    purpose_bytes = validated_purpose.encode("utf-8")
    vault_bytes = validated_vault_id.encode("utf-8")
    material = b"consultation-kb/dpapi/v1\x00" + b"".join(
        (
            len(vault_bytes).to_bytes(4, "big"),
            vault_bytes,
            len(purpose_bytes).to_bytes(4, "big"),
            purpose_bytes,
        )
    )
    return (
        validated_purpose,
        validated_vault_id,
        hashlib.sha256(material).digest(),
    )


@final
class WindowsDpapiProtector:
    """Use current-user DPAPI; never uses machine scope or plaintext fallback."""

    __slots__ = ("_backend",)

    def __init__(self, *, backend: DpapiBackend | None = None) -> None:
        self._backend = _WindowsDpapiBackend() if backend is None else backend

    def protect(self, data: bytes, *, purpose: str, vault_id: str) -> bytes:
        plaintext = _validate_bytes(data)
        validated_purpose, _, entropy = _context(purpose, vault_id)
        flags = _UI_FORBIDDEN
        if flags & _LOCAL_MACHINE:
            raise SecretProtectionFailed
        try:
            protected = self._backend.protect(
                plaintext,
                description=f"consultation-kb:{validated_purpose}",
                entropy=entropy,
                flags=flags,
            )
        except (InvalidSecretContext, SecretProtectionFailed):
            raise
        except Exception:
            raise SecretProtectionFailed from None
        if type(protected) is not bytes or not protected or protected == plaintext:
            raise SecretProtectionFailed
        return protected

    def unprotect(self, blob: bytes, *, purpose: str, vault_id: str) -> bytes:
        protected = _validate_bytes(blob)
        validated_purpose, _, entropy = _context(purpose, vault_id)
        try:
            description, plaintext = self._backend.unprotect(
                protected,
                entropy=entropy,
                flags=_UI_FORBIDDEN,
            )
        except InvalidSecretContext:
            raise
        except Exception:
            raise SecretDecryptionFailed from None
        if (
            description != f"consultation-kb:{validated_purpose}"
            or type(plaintext) is not bytes
            or not plaintext
        ):
            raise SecretDecryptionFailed
        return plaintext


def create_secret_protector() -> SecretProtector:
    """Create the production protector, failing closed off Windows."""

    if _PLATFORM != "win32":
        raise UnsupportedSecurityPlatform
    return WindowsDpapiProtector()
