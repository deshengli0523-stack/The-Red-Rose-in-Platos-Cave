"""Open existing client files through a same-handle final-path authority check."""

from __future__ import annotations

import importlib
import ntpath
import os
import stat
import sys
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any, BinaryIO, Protocol, cast, final

from consultation_kb.security.dpapi import UnsupportedSecurityPlatform


_PLATFORM = sys.platform
_REPARSE_ATTRIBUTE = 0x400
_DIRECTORY_ATTRIBUTE = 0x10
_OPEN_REPARSE_POINT = 0x00200000
_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_READ_ATTRIBUTES = 0x80
_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)
_ALLOWED_MODES = frozenset({"rb", "r+b", "rb+"})


class ScopePathDenied(PermissionError):
    """Opaque path denial that does not reveal the rejected location."""

    def __init__(self) -> None:
        super().__init__("SCOPE_PATH_DENIED")


@final
class PathInspection:
    __slots__ = ("is_directory", "is_regular", "is_reparse", "link_count")

    def __init__(
        self,
        *,
        is_directory: bool,
        is_regular: bool,
        is_reparse: bool,
        link_count: int,
    ) -> None:
        self.is_directory = is_directory
        self.is_regular = is_regular
        self.is_reparse = is_reparse
        self.link_count = link_count


class OpenedPath(Protocol):
    final_path: str
    attributes: int
    link_count: int
    is_directory: bool

    def into_file(self, mode: str) -> BinaryIO: ...

    def close(self) -> None: ...


class FinalPathProvider(Protocol):
    """Injectable open/final-path provider for privilege-independent tests."""

    def inspect(self, path: Path) -> PathInspection: ...

    def open_path(
        self,
        path: Path,
        *,
        mode: str,
        directory: bool,
        pin: bool = False,
    ) -> OpenedPath: ...


@final
class _WindowsOpenedPath:
    __slots__ = (
        "_handle",
        "_transferred",
        "attributes",
        "final_path",
        "is_directory",
        "link_count",
    )

    def __init__(
        self,
        handle: Any,
        *,
        final_path: str,
        attributes: int,
        link_count: int,
    ) -> None:
        self._handle = handle
        self._transferred = False
        self.final_path = final_path
        self.attributes = attributes
        self.link_count = link_count
        self.is_directory = bool(attributes & _DIRECTORY_ATTRIBUTE)

    def into_file(self, mode: str) -> BinaryIO:
        if self._transferred or mode not in _ALLOWED_MODES or self.is_directory:
            raise ScopePathDenied
        raw_handle: int | None = None
        descriptor: int | None = None
        try:
            raw_handle = int(self._handle.Detach())
            self._transferred = True
            os_flags = int(getattr(os, "O_BINARY", 0)) | (
                os.O_RDONLY if mode == "rb" else os.O_RDWR
            )
            msvcrt_module: Any = importlib.import_module("msvcrt")
            descriptor = int(msvcrt_module.open_osfhandle(raw_handle, os_flags))
            raw_handle = None
            result = cast(BinaryIO, os.fdopen(descriptor, mode))
            descriptor = None
            return result
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            elif raw_handle is not None:
                try:
                    importlib.import_module("win32api").CloseHandle(raw_handle)
                except Exception:
                    pass
            raise ScopePathDenied from None

    def close(self) -> None:
        if self._transferred:
            return
        try:
            self._handle.Close()
        except Exception:
            raise ScopePathDenied from None


@final
class _WindowsFinalPathProvider:
    __slots__ = ("_win32con", "_win32file")

    def __init__(self) -> None:
        if _PLATFORM != "win32":
            raise UnsupportedSecurityPlatform
        self._win32con: Any = importlib.import_module("win32con")
        self._win32file: Any = importlib.import_module("win32file")

    def inspect(self, path: Path) -> PathInspection:
        try:
            status = os.lstat(path)
            attributes = int(getattr(status, "st_file_attributes", 0))
            link_count = int(status.st_nlink)
        except Exception:
            raise ScopePathDenied from None
        return PathInspection(
            is_directory=stat.S_ISDIR(status.st_mode),
            is_regular=stat.S_ISREG(status.st_mode),
            is_reparse=stat.S_ISLNK(status.st_mode)
            or bool(attributes & _REPARSE_ATTRIBUTE),
            link_count=link_count,
        )

    def open_path(
        self,
        path: Path,
        *,
        mode: str,
        directory: bool,
        pin: bool = False,
    ) -> OpenedPath:
        if mode not in _ALLOWED_MODES or type(pin) is not bool:
            raise ScopePathDenied
        desired_access = _FILE_READ_ATTRIBUTES
        if directory and pin:
            desired_access |= int(self._win32con.DELETE)
        if not directory:
            desired_access = self._win32con.GENERIC_READ
            if mode != "rb":
                desired_access |= self._win32con.GENERIC_WRITE
        flags = _OPEN_REPARSE_POINT
        flags |= _BACKUP_SEMANTICS if directory else _FILE_ATTRIBUTE_NORMAL
        handle: Any = None
        try:
            share_mode = self._win32con.FILE_SHARE_READ | self._win32con.FILE_SHARE_WRITE
            if directory and not pin:
                share_mode |= self._win32con.FILE_SHARE_DELETE
            handle = self._win32file.CreateFile(
                _extended_windows_open_path(path),
                desired_access,
                share_mode,
                None,
                self._win32con.OPEN_EXISTING,
                flags,
                None,
            )
            final_path = self._win32file.GetFinalPathNameByHandle(handle, 0)
            information = self._win32file.GetFileInformationByHandle(handle)
            attributes = int(information[0])
            link_count = int(information[7])
            if type(final_path) is not str or not final_path or link_count < 1:
                raise ScopePathDenied
            return _WindowsOpenedPath(
                handle,
                final_path=final_path,
                attributes=attributes,
                link_count=link_count,
            )
        except ScopePathDenied:
            if handle is not None:
                handle.Close()
            raise
        except Exception:
            if handle is not None:
                try:
                    handle.Close()
                except Exception:
                    pass
            raise ScopePathDenied from None


def _raw_relative_parts(candidate: object) -> tuple[str, ...]:
    if not isinstance(candidate, (str, os.PathLike)):
        raise ScopePathDenied
    try:
        raw = os.fspath(candidate)
    except (TypeError, ValueError, OSError):
        raise ScopePathDenied from None
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ScopePathDenied
    pure = PureWindowsPath(raw)
    if pure.drive or pure.root or pure.anchor or pure.is_absolute():
        raise ScopePathDenied
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ScopePathDenied
    for part in parts:
        if (
            part != part.rstrip(" .")
            or ":" in part
            or any(ord(character) < 32 for character in part)
            or part.partition(".")[0].upper() in _RESERVED_NAMES
        ):
            raise ScopePathDenied
    return parts


def _lexically_within(root: Path, target: Path) -> bool:
    try:
        normalized_root = os.path.normcase(os.path.normpath(str(root)))
        normalized_target = os.path.normcase(os.path.normpath(str(target)))
        return os.path.commonpath((normalized_root, normalized_target)) == normalized_root
    except (OSError, ValueError):
        return False


def _authority_prefixes(path: Path) -> tuple[Path, ...]:
    try:
        if not path.is_absolute() or not path.anchor:
            raise ScopePathDenied
        parts = path.parts
        if not parts or os.path.normcase(parts[0]) != os.path.normcase(path.anchor):
            raise ScopePathDenied
        current = Path(path.anchor)
        prefixes = [current]
        for part in parts[1:]:
            if part in {"", ".", ".."}:
                raise ScopePathDenied
            current = current / part
            prefixes.append(current)
        return tuple(prefixes)
    except ScopePathDenied:
        raise ScopePathDenied from None
    except Exception:
        raise ScopePathDenied from None


def _normalize_final_path(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ScopePathDenied
    normalized = value.replace("/", "\\")
    upper = normalized.upper()
    if upper.startswith("\\\\?\\UNC\\"):
        normalized = "\\\\" + normalized[8:]
    elif upper.startswith("\\\\?\\"):
        normalized = normalized[4:]
    elif upper.startswith("\\??\\"):
        normalized = normalized[4:]
    try:
        return ntpath.normcase(ntpath.normpath(normalized))
    except (OSError, ValueError):
        raise ScopePathDenied from None


def _extended_windows_open_path(path: Path) -> str:
    try:
        raw = str(path).replace("/", "\\")
        if not raw or "\x00" in raw:
            raise ScopePathDenied
        upper = raw.upper()
        if upper.startswith(("\\\\?\\", "\\??\\", "\\\\.\\")):
            raise ScopePathDenied
        normalized = ntpath.normpath(raw)
        drive, tail = ntpath.splitdrive(normalized)
        if drive.startswith("\\\\"):
            unc_parts = tuple(part for part in drive[2:].split("\\") if part)
            if len(unc_parts) != 2 or not tail.startswith("\\"):
                raise ScopePathDenied
            return "\\\\?\\UNC\\" + normalized[2:]
        if (
            len(drive) != 2
            or drive[0] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or drive[1] != ":"
            or not tail.startswith("\\")
        ):
            raise ScopePathDenied
        return "\\\\?\\" + normalized
    except ScopePathDenied:
        raise ScopePathDenied from None
    except Exception:
        raise ScopePathDenied from None


def _final_within(root: object, target: object) -> bool:
    normalized_root = _normalize_final_path(root)
    normalized_target = _normalize_final_path(target)
    try:
        return (
            normalized_target != normalized_root
            and ntpath.commonpath((normalized_root, normalized_target))
            == normalized_root
        )
    except (OSError, ValueError):
        return False


def _final_equal(first: object, second: object) -> bool:
    return _normalize_final_path(first) == _normalize_final_path(second)


@final
class PathGuard:
    """Fail-closed scoped opener retaining the exact verified file handle."""

    __slots__ = ("_provider", "_root")

    def __init__(
        self,
        root: Path,
        *,
        provider: FinalPathProvider | None = None,
    ) -> None:
        if type(root) is not Path:
            root = Path(root)
        self._root = root
        self._provider = _WindowsFinalPathProvider() if provider is None else provider

    def _resolved_root(self) -> Path:
        try:
            raw_root = self._root
            if not raw_root.is_absolute() or ".." in raw_root.parts:
                raise ScopePathDenied
            for prefix in _authority_prefixes(raw_root):
                inspection = self._provider.inspect(prefix)
                if not inspection.is_directory or inspection.is_reparse:
                    raise ScopePathDenied
            root = raw_root.resolve(strict=True)
            resolved_inspection = self._provider.inspect(root)
            if (
                not resolved_inspection.is_directory
                or resolved_inspection.is_reparse
            ):
                raise ScopePathDenied
            return root
        except ScopePathDenied:
            raise ScopePathDenied from None
        except Exception:
            raise ScopePathDenied from None

    def _open_root_handle(self, root: Path, *, pin: bool) -> OpenedPath:
        handle: OpenedPath | None = None
        try:
            handle = self._provider.open_path(
                root,
                mode="rb",
                directory=True,
                pin=pin,
            )
            if (
                not handle.is_directory
                or handle.attributes & _REPARSE_ATTRIBUTE
                or not _final_equal(handle.final_path, str(root))
            ):
                raise ScopePathDenied
            return handle
        except ScopePathDenied:
            if handle is not None:
                handle.close()
            raise ScopePathDenied from None
        except Exception:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            raise ScopePathDenied from None

    @contextmanager
    def pin_root(self) -> Iterator[None]:
        """Hold the verified root directory open without delete sharing."""

        root = self._resolved_root()
        handle = self._open_root_handle(root, pin=True)
        try:
            yield
        finally:
            handle.close()

    @contextmanager
    def pin_scoped_directory(self, candidate: object) -> Iterator[None]:
        """Hold one verified descendant directory and its root open."""

        parts = _raw_relative_parts(candidate)
        root = self._resolved_root()
        root_handle: OpenedPath | None = None
        target_handle: OpenedPath | None = None
        try:
            current = root
            for part in parts:
                current = current / part
                inspection = self._provider.inspect(current)
                if not inspection.is_directory or inspection.is_reparse:
                    raise ScopePathDenied
            target = current.resolve(strict=True)
            if not _lexically_within(root, target):
                raise ScopePathDenied
            root_handle = self._open_root_handle(root, pin=True)
            target_handle = self._provider.open_path(
                target,
                mode="rb",
                directory=True,
                pin=True,
            )
            if (
                not target_handle.is_directory
                or target_handle.attributes & _REPARSE_ATTRIBUTE
                or not _final_within(
                    root_handle.final_path,
                    target_handle.final_path,
                )
            ):
                raise ScopePathDenied
        except ScopePathDenied:
            if target_handle is not None:
                target_handle.close()
            if root_handle is not None:
                root_handle.close()
            raise ScopePathDenied from None
        except Exception:
            if target_handle is not None:
                try:
                    target_handle.close()
                except Exception:
                    pass
            if root_handle is not None:
                try:
                    root_handle.close()
                except Exception:
                    pass
            raise ScopePathDenied from None
        try:
            yield
        finally:
            target_handle.close()
            root_handle.close()

    @contextmanager
    def pin_scoped_directories(
        self,
        candidates: Iterable[object],
        *,
        create_missing: bool = False,
    ) -> Iterator[None]:
        """Pin multiple directory chains under one verified root handle.

        Every unique intermediate component is opened with delete access and
        without delete sharing before the next component is processed. This
        lets a caller create a directory chain without leaving already-created
        ancestors replaceable, while avoiding incompatible duplicate root
        handles when two destination chains must be held simultaneously.
        """

        if type(create_missing) is not bool or isinstance(
            candidates,
            (str, bytes, os.PathLike),
        ):
            raise ScopePathDenied
        try:
            parsed = tuple(_raw_relative_parts(candidate) for candidate in candidates)
        except ScopePathDenied:
            raise ScopePathDenied from None
        except Exception:
            raise ScopePathDenied from None
        if (
            not parsed
            or len(parsed) > 64
            or sum(len(parts) for parts in parsed) > 256
        ):
            raise ScopePathDenied

        handles = ExitStack()
        try:
            root = self._resolved_root()
            root_handle = self._open_root_handle(root, pin=True)
            handles.callback(root_handle.close)
            pinned: set[tuple[str, ...]] = set()
            for parts in parsed:
                current = root
                normalized_prefix: list[str] = []
                for part in parts:
                    current /= part
                    normalized_prefix.append(os.path.normcase(part))
                    key = tuple(normalized_prefix)
                    if key in pinned:
                        continue
                    if create_missing:
                        try:
                            current.mkdir(exist_ok=True)
                        except OSError:
                            raise ScopePathDenied from None
                    inspection = self._provider.inspect(current)
                    if not inspection.is_directory or inspection.is_reparse:
                        raise ScopePathDenied
                    target = current.resolve(strict=True)
                    if not _lexically_within(root, target):
                        raise ScopePathDenied
                    target_handle = self._provider.open_path(
                        target,
                        mode="rb",
                        directory=True,
                        pin=True,
                    )
                    handles.callback(target_handle.close)
                    if (
                        not target_handle.is_directory
                        or target_handle.attributes & _REPARSE_ATTRIBUTE
                        or not _final_equal(target_handle.final_path, str(target))
                        or not _final_within(
                            root_handle.final_path,
                            target_handle.final_path,
                        )
                    ):
                        raise ScopePathDenied
                    pinned.add(key)
        except Exception:
            try:
                handles.close()
            except Exception:
                pass
            raise ScopePathDenied from None
        try:
            yield
        finally:
            handles.close()

    def open_scoped(self, candidate: object, *, mode: str = "rb") -> BinaryIO:
        if type(mode) is not str or mode not in _ALLOWED_MODES:
            raise ScopePathDenied
        parts = _raw_relative_parts(candidate)
        root_handle: OpenedPath | None = None
        target_handle: OpenedPath | None = None
        transferred = False
        try:
            root = self._resolved_root()

            current = root
            for index, part in enumerate(parts):
                current = current / part
                inspection = self._provider.inspect(current)
                is_last = index == len(parts) - 1
                if inspection.is_reparse:
                    raise ScopePathDenied
                if is_last:
                    if not inspection.is_regular or inspection.link_count != 1:
                        raise ScopePathDenied
                elif not inspection.is_directory:
                    raise ScopePathDenied

            target = current.resolve(strict=True)
            if not _lexically_within(root, target):
                raise ScopePathDenied

            root_handle = self._open_root_handle(root, pin=False)
            target_handle = self._provider.open_path(
                target,
                mode=mode,
                directory=False,
                pin=False,
            )
            if (
                target_handle.is_directory
                or target_handle.attributes & _REPARSE_ATTRIBUTE
                or target_handle.link_count != 1
                or not _final_within(root_handle.final_path, target_handle.final_path)
            ):
                raise ScopePathDenied
            result = target_handle.into_file(mode)
            transferred = True
            return result
        except ScopePathDenied:
            raise ScopePathDenied from None
        except Exception:
            raise ScopePathDenied from None
        finally:
            if root_handle is not None:
                root_handle.close()
            if target_handle is not None and not transferred:
                target_handle.close()
