"""Windows child-process start boundary for an active STDIO server.

CPython's Windows ``spawn`` launcher copies the process standard-input handle.
If the MCP transport already has a blocking read outstanding on that handle,
the child interpreter can stall before it reaches ``spawn_main``.  Existing
``sys.stdin`` objects retain their original OS handle, so changing only the
process-level handle during ``CreateProcess`` leaves the live MCP reader
untouched while giving the child an independent, readable end-of-file stream.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Final, Protocol


_KERNEL32: Any = None
if os.name == "nt":  # pragma: win32 cover
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.GetStdHandle.argtypes = (wintypes.DWORD,)
    _KERNEL32.GetStdHandle.restype = wintypes.HANDLE
    _KERNEL32.SetStdHandle.argtypes = (wintypes.DWORD, wintypes.HANDLE)
    _KERNEL32.SetStdHandle.restype = wintypes.BOOL
else:  # pragma: no cover - Windows worker boundary
    ctypes = None  # type: ignore[assignment]
    msvcrt = None  # type: ignore[assignment]


_STD_INPUT_HANDLE: Final[int] = (1 << 32) - 10
_PROCESS_START_LOCK = threading.Lock()


class StartableProcess(Protocol):
    """Minimal process surface used by the scoped worker broker."""

    def start(self) -> None: ...


def _raise_last_windows_error() -> None:
    assert ctypes is not None
    error = ctypes.get_last_error()
    raise OSError(error, "WINDOWS_PROCESS_START_FAILED")


def start_process_with_isolated_standard_input(process: StartableProcess) -> None:
    """Start one child without inheriting the MCP transport's active stdin.

    The Win32 standard-handle table is process-global, so all worker starts are
    serialized.  The original handle is restored on every exit path and the
    temporary NUL handle remains alive until ``CreateProcess`` has returned.
    Other platforms call ``start`` directly without taking the Windows lock.
    """

    if os.name != "nt":  # pragma: no cover - Windows worker boundary
        process.start()
        return

    assert msvcrt is not None
    assert _KERNEL32 is not None
    with _PROCESS_START_LOCK:
        null_fd = os.open(
            os.devnull,
            os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
        )
        try:
            null_handle = msvcrt.get_osfhandle(null_fd)
            os.set_handle_inheritable(null_handle, True)
            original_handle = _KERNEL32.GetStdHandle(_STD_INPUT_HANDLE)
            if not _KERNEL32.SetStdHandle(
                _STD_INPUT_HANDLE,
                null_handle,
            ):
                _raise_last_windows_error()
            try:
                process.start()
            finally:
                if not _KERNEL32.SetStdHandle(
                    _STD_INPUT_HANDLE,
                    original_handle,
                ):
                    _raise_last_windows_error()
        finally:
            os.close(null_fd)


__all__ = ["StartableProcess", "start_process_with_isolated_standard_input"]
