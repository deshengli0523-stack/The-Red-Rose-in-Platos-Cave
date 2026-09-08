from __future__ import annotations

import ctypes
import sys
import threading
import time
from typing import cast

import pytest

from consultation_kb.security import windows_process_start
from consultation_kb.security.windows_process_start import (
    start_process_with_isolated_standard_input,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows standard-handle boundary",
)
_STD_INPUT_HANDLE = (1 << 32) - 10


def _current_standard_input_handle() -> int | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetStdHandle.argtypes = (ctypes.c_uint32,)
    kernel32.GetStdHandle.restype = ctypes.c_void_p
    return cast(int | None, kernel32.GetStdHandle(_STD_INPUT_HANDLE))


class _StartFailure(RuntimeError):
    pass


class _FailingProcess:
    def __init__(self, original_handle: int | None) -> None:
        self.original_handle = original_handle
        self.observed_handle: int | None = None

    def start(self) -> None:
        self.observed_handle = _current_standard_input_handle()
        raise _StartFailure


def test_start_failure_restores_exact_standard_input_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _current_standard_input_handle()
    process = _FailingProcess(original)
    closed_descriptors: list[int] = []
    real_close = windows_process_start.os.close  # type: ignore[attr-defined]

    def observe_close(descriptor: int) -> None:
        closed_descriptors.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(
        windows_process_start.os,  # type: ignore[attr-defined]
        "close",
        observe_close,
    )

    with pytest.raises(_StartFailure):
        start_process_with_isolated_standard_input(process)

    assert process.observed_handle not in {None, original}
    assert _current_standard_input_handle() == original
    assert len(closed_descriptors) == 1


def test_concurrent_process_starts_are_serialized() -> None:
    guard = threading.Lock()
    barrier = threading.Barrier(3)
    active = 0
    maximum_active = 0
    observed_handles: list[int | None] = []

    class _ObservedProcess:
        def start(self) -> None:
            nonlocal active, maximum_active
            with guard:
                active += 1
                maximum_active = max(maximum_active, active)
                observed_handles.append(_current_standard_input_handle())
            time.sleep(0.05)
            with guard:
                active -= 1

    failures: list[BaseException] = []

    def run() -> None:
        try:
            barrier.wait(timeout=5.0)
            start_process_with_isolated_standard_input(_ObservedProcess())
        except BaseException as error:
            failures.append(error)

    threads = tuple(threading.Thread(target=run) for _ in range(2))
    for thread in threads:
        thread.start()
    barrier.wait(timeout=5.0)
    for thread in threads:
        thread.join(timeout=5.0)

    assert failures == []
    assert all(not thread.is_alive() for thread in threads)
    assert maximum_active == 1
    assert len(observed_handles) == 2
    assert all(handle is not None for handle in observed_handles)
