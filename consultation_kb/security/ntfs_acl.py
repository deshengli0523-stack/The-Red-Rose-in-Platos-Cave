"""Explicit NTFS DACL application and strict verification."""

from __future__ import annotations

import importlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, final

from consultation_kb.security.dpapi import UnsupportedSecurityPlatform


FULL_CONTROL_MASK = 2_032_127
DIRECTORY_INHERIT_FLAGS = 0x1 | 0x2
_REPARSE_ATTRIBUTE = 0x400
_PLATFORM = sys.platform


class AclPolicyViolation(RuntimeError):
    """Raised when a directory ACL does not exactly match policy."""

    def __init__(self) -> None:
        super().__init__("ACL_POLICY_VIOLATION")


@final
@dataclass(frozen=True, slots=True)
class AclEntry:
    sid: str
    access_mask: int
    ace_flags: int
    allow: bool


@final
@dataclass(frozen=True, slots=True)
class AclSnapshot:
    owner_sid: str
    inheritance_protected: bool
    entries: tuple[AclEntry, ...]


@final
@dataclass(frozen=True, slots=True)
class AclVerification:
    allowed_principal_count: int


class AclBackend(Protocol):
    """Injectable ACL provider for deterministic policy tests."""

    def current_user_sid(self) -> str: ...

    def system_sid(self) -> str: ...

    def resolve_principal(self, principal: str) -> str: ...

    def read(self, path: Path) -> AclSnapshot: ...

    def apply(
        self,
        path: Path,
        *,
        owner_sid: str,
        allowed_sids: tuple[str, ...],
    ) -> None: ...


@final
class _WindowsAclBackend:
    __slots__ = (
        "_ntsecuritycon",
        "_win32api",
        "_win32con",
        "_win32security",
    )

    def __init__(self) -> None:
        if _PLATFORM != "win32":
            raise UnsupportedSecurityPlatform
        self._ntsecuritycon: Any = importlib.import_module("ntsecuritycon")
        self._win32api: Any = importlib.import_module("win32api")
        self._win32con: Any = importlib.import_module("win32con")
        self._win32security: Any = importlib.import_module("win32security")

    def _sid_string(self, sid: object) -> str:
        result = self._win32security.ConvertSidToStringSid(sid)
        if type(result) is not str or not result:
            raise AclPolicyViolation
        return result

    def current_user_sid(self) -> str:
        token = self._win32security.OpenProcessToken(
            self._win32api.GetCurrentProcess(),
            self._win32con.TOKEN_QUERY,
        )
        sid, _attributes = self._win32security.GetTokenInformation(
            token,
            self._win32security.TokenUser,
        )
        return self._sid_string(sid)

    def system_sid(self) -> str:
        sid = self._win32security.CreateWellKnownSid(
            self._win32security.WinLocalSystemSid,
            None,
        )
        return self._sid_string(sid)

    def resolve_principal(self, principal: str) -> str:
        try:
            if principal.upper().startswith("S-"):
                sid = self._win32security.ConvertStringSidToSid(principal)
            else:
                sid, _domain, _kind = self._win32security.LookupAccountName(
                    None,
                    principal,
                )
            return self._sid_string(sid)
        except Exception:
            raise AclPolicyViolation from None

    def read(self, path: Path) -> AclSnapshot:
        self._validate_target(path)
        try:
            security = self._win32security.GetNamedSecurityInfo(
                str(path),
                self._win32security.SE_FILE_OBJECT,
                self._win32security.OWNER_SECURITY_INFORMATION
                | self._win32security.DACL_SECURITY_INFORMATION,
            )
            owner_sid = self._sid_string(security.GetSecurityDescriptorOwner())
            control, _revision = security.GetSecurityDescriptorControl()
            dacl = security.GetSecurityDescriptorDacl()
            if dacl is None:
                raise AclPolicyViolation
            entries: list[AclEntry] = []
            for index in range(dacl.GetAceCount()):
                header, mask, sid = dacl.GetAce(index)
                ace_type, ace_flags = header
                entries.append(
                    AclEntry(
                        sid=self._sid_string(sid),
                        access_mask=int(mask),
                        ace_flags=int(ace_flags),
                        allow=(
                            int(ace_type)
                            == self._win32security.ACCESS_ALLOWED_ACE_TYPE
                        ),
                    )
                )
            return AclSnapshot(
                owner_sid=owner_sid,
                inheritance_protected=bool(
                    int(control) & self._win32security.SE_DACL_PROTECTED
                ),
                entries=tuple(entries),
            )
        except AclPolicyViolation:
            raise AclPolicyViolation from None
        except Exception:
            raise AclPolicyViolation from None

    def apply(
        self,
        path: Path,
        *,
        owner_sid: str,
        allowed_sids: tuple[str, ...],
    ) -> None:
        self._validate_target(path)
        try:
            owner = self._win32security.ConvertStringSidToSid(owner_sid)
            dacl = self._win32security.ACL()
            for sid_string in allowed_sids:
                sid = self._win32security.ConvertStringSidToSid(sid_string)
                dacl.AddAccessAllowedAceEx(
                    self._win32security.ACL_REVISION_DS,
                    DIRECTORY_INHERIT_FLAGS,
                    self._ntsecuritycon.FILE_ALL_ACCESS,
                    sid,
                )
            self._win32security.SetNamedSecurityInfo(
                str(path),
                self._win32security.SE_FILE_OBJECT,
                self._win32security.OWNER_SECURITY_INFORMATION
                | self._win32security.DACL_SECURITY_INFORMATION
                | self._win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                None,
                dacl,
                None,
            )
        except Exception:
            raise AclPolicyViolation from None

    @staticmethod
    def _validate_target(path: Path) -> None:
        try:
            status = os.lstat(path)
            attributes = int(getattr(status, "st_file_attributes", 0))
        except Exception:
            raise AclPolicyViolation from None
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or attributes & _REPARSE_ATTRIBUTE
        ):
            raise AclPolicyViolation


def _valid_sid(value: object) -> str:
    if type(value) is not str or not value or not value.upper().startswith("S-"):
        raise AclPolicyViolation
    return value.upper()


@final
class AclPolicy:
    """Verify exact protected DACLs; mutation occurs only through ``apply``."""

    __slots__ = ("_allowed_sids", "_backend", "_owner_sid")

    def __init__(
        self,
        *,
        backup_principals: tuple[str, ...] = (),
        backend: AclBackend | None = None,
    ) -> None:
        selected_backend = _WindowsAclBackend() if backend is None else backend
        try:
            owner_sid = _valid_sid(selected_backend.current_user_sid())
            system_sid = _valid_sid(selected_backend.system_sid())
            backup_sids = tuple(
                _valid_sid(selected_backend.resolve_principal(principal))
                for principal in backup_principals
            )
        except AclPolicyViolation:
            raise AclPolicyViolation from None
        except Exception:
            raise AclPolicyViolation from None
        self._backend = selected_backend
        self._owner_sid = owner_sid
        self._allowed_sids = tuple(sorted({owner_sid, system_sid, *backup_sids}))

    def _expected_entries(self) -> tuple[AclEntry, ...]:
        return tuple(
            AclEntry(
                sid=sid,
                access_mask=FULL_CONTROL_MASK,
                ace_flags=DIRECTORY_INHERIT_FLAGS,
                allow=True,
            )
            for sid in self._allowed_sids
        )

    def verify(self, path: Path) -> AclVerification:
        try:
            snapshot = self._backend.read(Path(path))
            if type(snapshot) is not AclSnapshot:
                raise AclPolicyViolation
            normalized: list[AclEntry] = []
            for entry in snapshot.entries:
                if (
                    type(entry) is not AclEntry
                    or type(entry.access_mask) is not int
                    or type(entry.ace_flags) is not int
                    or type(entry.allow) is not bool
                ):
                    raise AclPolicyViolation
                normalized.append(
                    AclEntry(
                        sid=_valid_sid(entry.sid),
                        access_mask=entry.access_mask,
                        ace_flags=entry.ace_flags,
                        allow=entry.allow,
                    )
                )
            normalized_entries = tuple(
                sorted(
                    normalized,
                    key=lambda item: (
                        item.sid,
                        item.access_mask,
                        item.ace_flags,
                        item.allow,
                    ),
                )
            )
            if (
                _valid_sid(snapshot.owner_sid) != self._owner_sid
                or snapshot.inheritance_protected is not True
                or normalized_entries != self._expected_entries()
            ):
                raise AclPolicyViolation
            return AclVerification(allowed_principal_count=len(self._allowed_sids))
        except AclPolicyViolation:
            raise AclPolicyViolation from None
        except Exception:
            raise AclPolicyViolation from None

    def apply(self, path: Path) -> AclVerification:
        """Explicitly replace the target DACL, then verify the result."""

        try:
            self._backend.apply(
                Path(path),
                owner_sid=self._owner_sid,
                allowed_sids=self._allowed_sids,
            )
        except AclPolicyViolation:
            raise AclPolicyViolation from None
        except Exception:
            raise AclPolicyViolation from None
        return self.verify(path)
