from __future__ import annotations

import io
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import pytest

from consultation_kb.security import ntfs_acl as ntfs_acl_module
from consultation_kb.security import path_guard as path_guard_module
from consultation_kb.security.dpapi import UnsupportedSecurityPlatform
from consultation_kb.security.ntfs_acl import (
    DIRECTORY_INHERIT_FLAGS,
    FULL_CONTROL_MASK,
    AclEntry,
    AclPolicy,
    AclPolicyViolation,
    AclSnapshot,
)
from consultation_kb.security.path_guard import (
    FinalPathProvider,
    OpenedPath,
    PathInspection,
    PathGuard,
    ScopePathDenied,
)


@dataclass
class _FakeOpenedPath:
    final_path: str
    attributes: int = 0
    link_count: int = 1
    is_directory: bool = False
    stream: BinaryIO = field(default_factory=lambda: io.BytesIO(b"verified-handle"))
    closed: bool = False
    transferred: bool = False

    def into_file(self, mode: str) -> BinaryIO:
        assert mode in {"rb", "r+b", "rb+"}
        self.transferred = True
        return self.stream

    def close(self) -> None:
        self.closed = True


class _FakeFinalPathProvider(FinalPathProvider):
    def __init__(self, root: Path, target: Path) -> None:
        self.root = root
        self.target = target
        self.root_handle = _FakeOpenedPath(
            final_path=str(root.resolve()),
            is_directory=True,
        )
        self.directory_handle = _FakeOpenedPath(
            final_path=str(target.parent.resolve()),
            is_directory=True,
        )
        self.target_handle = _FakeOpenedPath(final_path=str(target.resolve()))
        self.inspection_overrides: dict[Path, PathInspection] = {}
        self.opened: list[tuple[Path, str, bool, bool]] = []

    def inspect(self, path: Path) -> PathInspection:
        resolved = Path(path)
        if resolved in self.inspection_overrides:
            return self.inspection_overrides[resolved]
        status = os.lstat(resolved)
        return PathInspection(
            is_directory=stat.S_ISDIR(status.st_mode),
            is_regular=stat.S_ISREG(status.st_mode),
            is_reparse=stat.S_ISLNK(status.st_mode),
            link_count=status.st_nlink,
        )

    def open_path(
        self,
        path: Path,
        *,
        mode: str,
        directory: bool,
        pin: bool = False,
    ) -> OpenedPath:
        path = Path(path)
        self.opened.append((path, mode, directory, pin))
        if directory:
            if path == self.root.resolve():
                return self.root_handle
            return self.directory_handle
        return self.target_handle


@pytest.fixture
def guarded_file(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "client"
    target = root / "nested" / "client.sqlite3"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"database")
    return root, target


@pytest.mark.parametrize(
    "candidate",
    [
        r"C:\outside\client.sqlite3",
        r"C:outside\client.sqlite3",
        r"\\server\share\x",
        r"\rooted\x",
        r"..\client_beta\client.sqlite3",
        r"sub\..\..\x",
        r"/outside/x",
        r"\\?\C:\outside\x",
    ],
)
def test_path_guard_rejects_non_pure_relative_paths(
    guarded_file: tuple[Path, Path],
    candidate: str,
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=provider).open_scoped(candidate, mode="rb")

    assert provider.opened == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (r"C:\vault\client", r"\\?\C:\vault\client"),
        (
            r"\\server\share\vault\client",
            r"\\?\UNC\server\share\vault\client",
        ),
    ],
)
def test_windows_open_path_uses_only_canonical_extended_namespaces(
    raw: str,
    expected: str,
) -> None:
    assert path_guard_module._extended_windows_open_path(Path(raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [r"relative\client", r"\\?\C:\vault\client", r"\\.\C:\vault\client"],
)
def test_windows_open_path_rejects_relative_or_existing_device_namespace(
    raw: str,
) -> None:
    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        path_guard_module._extended_windows_open_path(Path(raw))


@pytest.mark.parametrize(
    "candidate",
    [
        "nested/client.sqlite3:stream",
        "nested/client.sqlite3.",
        "nested/client.sqlite3 ",
        "nested/NUL",
        "nested/COM1.txt",
        "",
        ".",
    ],
)
def test_path_guard_rejects_ambiguous_windows_names(
    guarded_file: tuple[Path, Path],
    candidate: str,
) -> None:
    root, target = guarded_file

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=_FakeFinalPathProvider(root, target)).open_scoped(
            candidate,
            mode="rb",
        )


def test_path_guard_rejects_intermediate_reparse_component(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.inspection_overrides[target.parent] = PathInspection(
        is_directory=True,
        is_regular=False,
        is_reparse=True,
        link_count=1,
    )

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=provider).open_scoped(
            "nested/client.sqlite3",
            mode="rb",
        )

    assert provider.opened == []


def test_path_guard_rejects_reparse_root_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alias_root = tmp_path / "client-alias"
    alias_root.mkdir()
    actual_root = tmp_path / "client-actual"
    actual_target = actual_root / "client.sqlite3"
    actual_root.mkdir()
    actual_target.write_bytes(b"other-scope")
    provider = _FakeFinalPathProvider(actual_root, actual_target)
    provider.inspection_overrides[alias_root] = PathInspection(
        is_directory=True,
        is_regular=False,
        is_reparse=True,
        link_count=1,
    )
    real_resolve = Path.resolve

    def injected_resolve(path: Path, strict: bool = False) -> Path:
        if path == alias_root:
            return actual_root
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", injected_resolve)

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(alias_root, provider=provider).open_scoped(
            "client.sqlite3",
            mode="rb",
        )

    assert provider.opened == []


def test_path_guard_rejects_reparse_ancestor_of_plain_root(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.inspection_overrides[root.parent] = PathInspection(
        is_directory=True,
        is_regular=False,
        is_reparse=True,
        link_count=1,
    )

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=provider).open_scoped(
            "nested/client.sqlite3",
            mode="rb",
        )

    assert provider.opened == []


def test_path_guard_rejects_final_handle_outside_scope(
    guarded_file: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.target_handle.final_path = str(tmp_path / "client-lookalike" / target.name)

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=provider).open_scoped(
            "nested/client.sqlite3",
            mode="rb",
        )

    assert provider.root_handle.closed
    assert provider.target_handle.closed


def test_path_guard_rejects_short_name_final_path_escape(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.root_handle.final_path = r"\\?\C:\vault\client_alpha"
    provider.target_handle.final_path = r"\\?\C:\vault\CLIENT~2\client.sqlite3"

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        PathGuard(root, provider=provider).open_scoped(
            "nested/client.sqlite3",
            mode="rb",
        )


def test_path_guard_compares_final_paths_case_insensitively(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.root_handle.final_path = str(root.resolve()).upper()
    provider.target_handle.final_path = str(target.resolve()).lower()

    opened = PathGuard(root, provider=provider).open_scoped(
        "nested/client.sqlite3",
        mode="rb",
    )

    assert opened is provider.target_handle.stream


def test_path_guard_rejects_opened_reparse_or_hardlink_race(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    for attributes, link_count in ((0x400, 1), (0, 2)):
        provider = _FakeFinalPathProvider(root, target)
        provider.target_handle.attributes = attributes
        provider.target_handle.link_count = link_count

        with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
            PathGuard(root, provider=provider).open_scoped(
                "nested/client.sqlite3",
                mode="rb",
            )

        assert provider.target_handle.closed


def test_path_guard_returns_the_same_verified_handle(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)

    opened = PathGuard(root, provider=provider).open_scoped(
        "nested/client.sqlite3",
        mode="rb",
    )

    assert opened is provider.target_handle.stream
    assert provider.target_handle.transferred
    assert not provider.target_handle.closed
    assert provider.root_handle.closed
    assert opened.read() == b"verified-handle"


def test_path_guard_pins_verified_root_for_context_lifetime(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)

    with PathGuard(root, provider=provider).pin_root():
        assert not provider.root_handle.closed

    assert provider.root_handle.closed
    assert provider.opened == [(root.resolve(), "rb", True, True)]


def test_path_guard_pins_verified_scoped_directory_and_root(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)

    with PathGuard(root, provider=provider).pin_scoped_directory("nested"):
        assert not provider.root_handle.closed
        assert not provider.directory_handle.closed

    assert provider.root_handle.closed
    assert provider.directory_handle.closed


def test_path_guard_allows_same_handle_file_open_while_root_is_pinned(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)

    with PathGuard(root, provider=provider).pin_root():
        opened = PathGuard(root, provider=provider).open_scoped(
            "nested/client.sqlite3",
            mode="rb",
        )

    assert opened is provider.target_handle.stream


def test_path_guard_rejects_swapped_scoped_directory_final_handle(
    guarded_file: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    root, target = guarded_file
    provider = _FakeFinalPathProvider(root, target)
    provider.directory_handle.final_path = str(tmp_path / "other-scope")

    with pytest.raises(ScopePathDenied, match="SCOPE_PATH_DENIED"):
        with PathGuard(root, provider=provider).pin_scoped_directory("nested"):
            pytest.fail("untrusted directory was pinned")

    assert provider.root_handle.closed
    assert provider.directory_handle.closed


def test_path_guard_does_not_chain_raw_path_errors(
    guarded_file: tuple[Path, Path],
) -> None:
    root, target = guarded_file

    with pytest.raises(ScopePathDenied) as denied:
        PathGuard(root, provider=_FakeFinalPathProvider(root, target)).open_scoped(
            "nested/missing-client-name.sqlite3",
            mode="rb",
        )

    assert str(denied.value) == "SCOPE_PATH_DENIED"
    assert denied.value.__cause__ is None


class _FakeAclBackend:
    def __init__(self) -> None:
        self.snapshot = AclSnapshot(
            owner_sid="S-1-5-21-current",
            inheritance_protected=True,
            entries=(
                AclEntry(
                    sid="S-1-5-18",
                    access_mask=FULL_CONTROL_MASK,
                    ace_flags=DIRECTORY_INHERIT_FLAGS,
                    allow=True,
                ),
                AclEntry(
                    sid="S-1-5-21-current",
                    access_mask=FULL_CONTROL_MASK,
                    ace_flags=DIRECTORY_INHERIT_FLAGS,
                    allow=True,
                ),
            ),
        )
        self.apply_calls = 0
        self.read_error: Exception | None = None

    def current_user_sid(self) -> str:
        return "S-1-5-21-current"

    def system_sid(self) -> str:
        return "S-1-5-18"

    def resolve_principal(self, principal: str) -> str:
        return {"backup": "S-1-5-21-backup"}.get(principal, principal)

    def read(self, path: Path) -> AclSnapshot:
        del path
        if self.read_error is not None:
            raise self.read_error
        return self.snapshot

    def apply(
        self,
        path: Path,
        *,
        owner_sid: str,
        allowed_sids: tuple[str, ...],
    ) -> None:
        del path
        self.apply_calls += 1
        self.snapshot = AclSnapshot(
            owner_sid=owner_sid,
            inheritance_protected=True,
            entries=tuple(
                AclEntry(
                    sid=sid,
                    access_mask=FULL_CONTROL_MASK,
                    ace_flags=DIRECTORY_INHERIT_FLAGS,
                    allow=True,
                )
                for sid in allowed_sids
            ),
        )


def test_acl_verify_is_read_only_and_accepts_exact_policy(tmp_path: Path) -> None:
    backend = _FakeAclBackend()
    policy = AclPolicy(backend=backend)

    report = policy.verify(tmp_path)

    assert report.allowed_principal_count == 2
    assert backend.apply_calls == 0


@pytest.mark.parametrize("violation", ["owner", "inheritance", "extra", "mask"])
def test_acl_verify_fails_closed_for_policy_drift(
    tmp_path: Path,
    violation: str,
) -> None:
    backend = _FakeAclBackend()
    snapshot = backend.snapshot
    if violation == "owner":
        backend.snapshot = AclSnapshot(
            owner_sid="S-1-5-21-other",
            inheritance_protected=True,
            entries=snapshot.entries,
        )
    elif violation == "inheritance":
        backend.snapshot = AclSnapshot(
            owner_sid=snapshot.owner_sid,
            inheritance_protected=False,
            entries=snapshot.entries,
        )
    elif violation == "extra":
        backend.snapshot = AclSnapshot(
            owner_sid=snapshot.owner_sid,
            inheritance_protected=True,
            entries=snapshot.entries
            + (
                AclEntry(
                    sid="S-1-5-21-other",
                    access_mask=FULL_CONTROL_MASK,
                    ace_flags=DIRECTORY_INHERIT_FLAGS,
                    allow=True,
                ),
            ),
        )
    else:
        first, second = snapshot.entries
        backend.snapshot = AclSnapshot(
            owner_sid=snapshot.owner_sid,
            inheritance_protected=True,
            entries=(
                first,
                AclEntry(
                    sid=second.sid,
                    access_mask=1,
                    ace_flags=second.ace_flags,
                    allow=True,
                ),
            ),
        )

    with pytest.raises(AclPolicyViolation, match="ACL_POLICY_VIOLATION"):
        AclPolicy(backend=backend).verify(tmp_path)

    assert backend.apply_calls == 0


def test_acl_apply_is_explicit_and_verifies_result(tmp_path: Path) -> None:
    backend = _FakeAclBackend()
    backend.snapshot = AclSnapshot(
        owner_sid="wrong",
        inheritance_protected=False,
        entries=(),
    )
    policy = AclPolicy(backup_principals=("backup",), backend=backend)

    report = policy.apply(tmp_path)

    assert backend.apply_calls == 1
    assert report.allowed_principal_count == 3


def test_acl_violation_does_not_chain_provider_path_details(tmp_path: Path) -> None:
    backend = _FakeAclBackend()
    backend.read_error = OSError(f"sensitive path: {tmp_path}")

    with pytest.raises(AclPolicyViolation) as denied:
        AclPolicy(backend=backend).verify(tmp_path)

    assert str(denied.value) == "ACL_POLICY_VIOLATION"
    assert denied.value.__cause__ is None


def test_acl_verify_rejects_malformed_backend_snapshot(tmp_path: Path) -> None:
    backend = _FakeAclBackend()
    backend.snapshot = object()  # type: ignore[assignment]

    with pytest.raises(AclPolicyViolation, match="ACL_POLICY_VIOLATION"):
        AclPolicy(backend=backend).verify(tmp_path)


def test_default_windows_security_backends_fail_closed_off_windows(
    guarded_file: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _target = guarded_file
    monkeypatch.setattr(path_guard_module, "_PLATFORM", "linux")
    monkeypatch.setattr(ntfs_acl_module, "_PLATFORM", "linux")

    with pytest.raises(UnsupportedSecurityPlatform):
        PathGuard(root)
    with pytest.raises(UnsupportedSecurityPlatform):
        AclPolicy()
