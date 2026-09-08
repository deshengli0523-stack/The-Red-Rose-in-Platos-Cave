from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest

from consultation_kb.security.dpapi import SecretDecryptionFailed, WindowsDpapiProtector
from consultation_kb.security.ntfs_acl import AclPolicy
from consultation_kb.security.path_guard import (
    FinalPathProvider,
    OpenedPath,
    PathGuard,
    PathInspection,
    ScopePathDenied,
)


pytestmark = pytest.mark.integration


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_dpapi_current_user_round_trip_and_entropy_binding() -> None:
    protector = WindowsDpapiProtector()
    blob = protector.protect(
        b"local-review-secret",
        purpose="review-agent-secret",
        vault_id="synthetic-vault",
    )

    assert blob != b"local-review-secret"
    assert protector.unprotect(
        blob,
        purpose="review-agent-secret",
        vault_id="synthetic-vault",
    ) == b"local-review-secret"
    with pytest.raises(SecretDecryptionFailed, match="SECRET_DECRYPTION_FAILED"):
        protector.unprotect(
            blob,
            purpose="identity-map",
            vault_id="synthetic-vault",
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_retains_verified_handle_and_rejects_hardlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "client"
    root.mkdir()
    target = root / "client.sqlite3"
    target.write_bytes(b"verified")

    with PathGuard(root).open_scoped("client.sqlite3", mode="rb") as opened:
        assert opened.read() == b"verified"

    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"other-client")
    hardlink = root / "hardlink.sqlite3"
    os.link(outside, hardlink)
    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root).open_scoped("hardlink.sqlite3", mode="rb")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_pins_directories_against_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "client"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "marker.bin").write_bytes(b"pinned")
    replacement = tmp_path / "replacement"

    with PathGuard(root).pin_root():
        with PathGuard(root).open_scoped("nested/marker.bin", mode="rb") as opened:
            assert opened.read() == b"pinned"
        with pytest.raises(OSError):
            root.rename(replacement)
    assert root.is_dir()

    with PathGuard(root).pin_scoped_directory("nested"):
        with pytest.raises(OSError):
            nested.rename(replacement)
    assert nested.is_dir()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_pins_created_multi_directory_chains(
    tmp_path: Path,
) -> None:
    root = tmp_path / "client"
    root.mkdir()
    first_relative = Path(".staging") / "purpose" / "manifest" / "digest"
    second_relative = Path("objects") / "ab" / "cd"

    with PathGuard(root).pin_scoped_directories(
        (first_relative, second_relative),
        create_missing=True,
    ):
        pinned_paths = (
            root,
            root / ".staging",
            root / ".staging" / "purpose",
            root / ".staging" / "purpose" / "manifest",
            root / first_relative,
            root / "objects",
            root / "objects" / "ab",
            root / second_relative,
        )
        assert all(path.is_dir() for path in pinned_paths)
        for index, path in enumerate(pinned_paths):
            replacement = path.parent / f"replacement-{index}"
            with pytest.raises(OSError):
                path.rename(replacement)


class _SwapCreatedDirectoryBeforeOpen:
    def __init__(
        self,
        delegate: FinalPathProvider,
        *,
        target: Path,
        parked: Path,
        replacement: Path,
    ) -> None:
        self._delegate = delegate
        self._target = target
        self._parked = parked
        self._replacement = replacement
        self.swapped = False

    def inspect(self, path: Path) -> PathInspection:
        return self._delegate.inspect(path)

    def open_path(
        self,
        path: Path,
        *,
        mode: str,
        directory: bool,
        pin: bool = False,
    ) -> OpenedPath:
        if directory and pin and path == self._target and not self.swapped:
            path.rename(self._parked)
            self._replacement.rename(path)
            self.swapped = True
        return self._delegate.open_path(
            path,
            mode=mode,
            directory=directory,
            pin=pin,
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_rejects_created_directory_swap_before_pin(
    tmp_path: Path,
) -> None:
    root = tmp_path / "client"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    replacement = tmp_path / "replacement-junction"
    result = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(replacement),
            str(outside),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")

    target = root / "new-chain"
    parked = root / "parked-original"
    delegate = PathGuard(root)._provider
    provider = _SwapCreatedDirectoryBeforeOpen(
        delegate,
        target=target,
        parked=parked,
        replacement=replacement,
    )
    try:
        with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
            with PathGuard(root, provider=provider).pin_scoped_directories(
                ("new-chain",),
                create_missing=True,
            ):
                pytest.fail("swapped directory was pinned")
        assert provider.swapped
    finally:
        if target.exists():
            target.rmdir()
        if parked.exists():
            parked.rename(target)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_reads_long_path_from_same_verified_handle(
    tmp_path: Path,
) -> None:
    root = tmp_path / "client"
    root.mkdir()
    first = "a" * 90
    second = "b" * 90
    nested = root / first / second
    nested.mkdir(parents=True)
    target = nested / "payload.bin"
    target.write_bytes(b"verified-long-path")
    relative = Path(first) / second / target.name

    assert len(str(target)) > 260
    with PathGuard(root).open_scoped(relative, mode="rb") as opened:
        assert opened.read() == b"verified-long-path"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_rejects_created_link_attack_types(
    tmp_path: Path,
    record_property: Callable[[str, object], None],
) -> None:
    root = tmp_path / "client"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"other-client")
    unavailable: list[str] = []

    symlink = root / "symlink"
    try:
        os.symlink(outside, symlink, target_is_directory=True)
    except OSError:
        unavailable.append("symlink")
    else:
        with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
            PathGuard(root).open_scoped("symlink/secret.bin", mode="rb")

    junction = root / "junction"
    result = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(outside),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        unavailable.append("junction")
    else:
        with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
            PathGuard(root).open_scoped("junction/secret.bin", mode="rb")

    assert set(unavailable) <= {"symlink", "junction"}
    record_property("unavailable_attack_types", ",".join(sorted(unavailable)))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_path_guard_rejects_plain_root_below_junction_ancestor(
    tmp_path: Path,
) -> None:
    actual_parent = tmp_path / "actual-parent"
    actual_root = actual_parent / "client"
    actual_root.mkdir(parents=True)
    (actual_root / "client.sqlite3").write_bytes(b"other-authority")
    junction = tmp_path / "ancestor-junction"
    result = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(actual_parent),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")
    try:
        aliased_root = junction / "client"
        assert not aliased_root.is_symlink()

        with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
            PathGuard(aliased_root).open_scoped("client.sqlite3", mode="rb")
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security integration")
def test_windows_acl_apply_then_verify_on_synthetic_directory(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.mkdir()
    policy = AclPolicy()

    report = policy.apply(protected)

    assert report.allowed_principal_count == 2
    assert policy.verify(protected) == report
