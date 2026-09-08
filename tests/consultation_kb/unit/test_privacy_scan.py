from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import re
import stat
import subprocess
import threading
import types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import consultation_kb.evaluation.privacy_scan as privacy_scan_module
from consultation_kb.evaluation.privacy_scan import (
    DEFAULT_SCAN_LIMITS,
    SCAN_CARRY_BYTES,
    SCAN_CHUNK_BYTES,
    PrivacyHit,
    PrivacyScanError,
    PrivacyScanOutcome,
    PrivacyScanReport,
    PrivacyScanner,
    ScanLimits,
    ScanResolutionHandle,
)


_CANARY_DEFINITION = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "consultation_kb"
    / "canaries.json"
)
_LIMIT_FIELDS = (
    "max_input_paths",
    "max_roots",
    "max_tree_entries",
    "max_files",
    "max_depth",
    "max_native_relative_bytes",
    "max_file_bytes",
    "max_total_bytes",
    "max_hits",
    "max_catalog_bytes",
    "max_markers",
    "max_marker_bytes",
)
_DEFAULT_LIMIT_VALUES = (
    100_000,
    50_000,
    500_000,
    100_000,
    64,
    32_768,
    1_073_741_824,
    8_589_934_592,
    10_000,
    65_536,
    256,
    128,
)
_HARD_LIMIT_VALUES = (
    1_000_000,
    100_000,
    2_000_000,
    1_000_000,
    256,
    32_768,
    8_589_934_592,
    68_719_476_736,
    100_000,
    65_536,
    256,
    128,
)


def _scanner(
    *,
    hash_key: bytes | None = bytes(range(32)),
    limits: ScanLimits = DEFAULT_SCAN_LIMITS,
    profile: object = "repo_tracked",
) -> PrivacyScanner:
    return PrivacyScanner.default(
        profile=profile,  # type: ignore[arg-type]
        canary_definition_path=_CANARY_DEFINITION,
        hash_key=hash_key,
        limits=limits,
    )


def _catalog_bytes(
    markers: object,
    *,
    schema_version: object = "1.0",
    synthetic_only: object = True,
    rule_id: object = "known_canary",
    key_order: tuple[str, ...] = (
        "schema_version",
        "synthetic_only",
        "rule_id",
        "markers",
    ),
    extra_pairs: tuple[tuple[str, object], ...] = (),
) -> bytes:
    values = {
        "schema_version": schema_version,
        "synthetic_only": synthetic_only,
        "rule_id": rule_id,
        "markers": markers,
    }
    document = {key: values[key] for key in key_order}
    for key, value in extra_pairs:
        document[key] = value
    return (
        json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
        + b"\n"
    )


def _write_catalog(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def _git_tracked_worktree_bytes(
    repo_root: Path,
) -> tuple[tuple[str, bytes], ...]:
    try:
        root_status = repo_root.lstat()
    except OSError:
        raise AssertionError("repository root is unavailable") from None
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or stat.S_ISLNK(root_status.st_mode)
        or int(getattr(root_status, "st_file_attributes", 0)) & reparse_flag
    ):
        raise AssertionError("repository root is not a plain directory")

    completed = subprocess.run(
        ("git", "ls-files", "--cached", "--full-name", "-z"),
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.stdout and not completed.stdout.endswith(b"\0"):
        raise AssertionError("git tracked-path output is not NUL-terminated")
    raw_paths = (
        completed.stdout.split(b"\0")[:-1] if completed.stdout else []
    )
    if any(not item for item in raw_paths):
        raise AssertionError("git tracked-path output contains an empty path")
    try:
        decoded_paths = tuple(item.decode("utf-8") for item in raw_paths)
    except UnicodeDecodeError:
        raise AssertionError("git tracked path is not UTF-8") from None
    if len(decoded_paths) != len(set(decoded_paths)):
        raise AssertionError("git tracked-path output contains a duplicate")

    relative_paths = tuple(
        sorted(decoded_paths, key=lambda item: item.encode("utf-8"))
    )
    tracked_bytes: list[tuple[str, bytes]] = []
    for relative_path in relative_paths:
        path_parts = relative_path.split("/")
        if (
            not relative_path
            or relative_path.startswith("/")
            or "\\" in relative_path
            or any(":" in path_part for path_part in path_parts)
            or any(part in {"", ".", ".."} for part in path_parts)
            or relative_path == ".git"
            or relative_path.startswith(".git/")
        ):
            raise AssertionError(f"unsafe tracked path: {relative_path}")

        worktree_candidate = repo_root.joinpath(*path_parts)
        try:
            worktree_candidate.relative_to(repo_root)
        except ValueError:
            raise AssertionError(
                f"unsafe tracked path: {relative_path}"
            ) from None

        worktree_path = repo_root
        for index, path_part in enumerate(path_parts):
            worktree_path = worktree_path / path_part
            try:
                path_status = worktree_path.lstat()
            except FileNotFoundError:
                raise AssertionError(
                    f"tracked path is missing: {relative_path}"
                ) from None
            except OSError:
                raise AssertionError(
                    f"tracked path is unreadable: {relative_path}"
                ) from None
            if (
                stat.S_ISLNK(path_status.st_mode)
                or int(getattr(path_status, "st_file_attributes", 0))
                & reparse_flag
            ):
                raise AssertionError(
                    f"tracked path contains a link: {relative_path}"
                )
            if index < len(path_parts) - 1:
                if not stat.S_ISDIR(path_status.st_mode):
                    raise AssertionError(
                        f"tracked path parent is not a directory: {relative_path}"
                    )
            elif not stat.S_ISREG(path_status.st_mode):
                raise AssertionError(
                    f"tracked path is not a regular file: {relative_path}"
                )
        try:
            content = worktree_path.read_bytes()
        except OSError:
            raise AssertionError(
                f"tracked path is unreadable: {relative_path}"
            ) from None
        tracked_bytes.append((relative_path, content))
    return tuple(tracked_bytes)


class TestTrackedPrivacyGate:
    def test_only_definition_contains_complete_canaries(
        self,
        repo_root: Path,
    ) -> None:
        definition_path = "tests/fixtures/consultation_kb/canaries.json"
        try:
            document = json.loads(_CANARY_DEFINITION.read_bytes())
        except (OSError, UnicodeError, json.JSONDecodeError):
            pytest.fail("canary definition could not be loaded")
        if type(document) is not dict:
            pytest.fail("canary definition is not an object")
        raw_markers = document.get("markers")
        if type(raw_markers) is not list or len(raw_markers) != 2:
            count = len(raw_markers) if type(raw_markers) is list else 0
            pytest.fail(f"canary definition marker count: {count}")
        if any(type(marker) is not str for marker in raw_markers):
            pytest.fail("canary definition contains a non-string marker")
        markers = tuple(marker.encode("utf-8") for marker in raw_markers)
        if len(set(markers)) != 2:
            pytest.fail("canary definition markers are not distinct")

        tracked = _git_tracked_worktree_bytes(repo_root)
        definition_entries = tuple(
            content for path, content in tracked if path == definition_path
        )
        if len(definition_entries) != 1:
            pytest.fail(
                f"canary definition tracked path count: {len(definition_entries)}"
            )
        definition_bytes = definition_entries[0]
        definition_issues = tuple(
            (f"CANARY-{index}", definition_bytes.count(marker))
            for index, marker in enumerate(markers, start=1)
            if definition_bytes.count(marker) != 1
        )
        assert definition_issues == (), (
            f"canary definition occurrence issues: {definition_issues!r}"
        )

        offenders = tuple(
            (f"CANARY-{index}", path, content.count(marker))
            for index, marker in enumerate(markers, start=1)
            for path, content in tracked
            if path != definition_path and content.count(marker)
        )
        assert offenders == (), f"tracked canary offenders: {offenders!r}"

    def test_no_static_stable_client_identifier_in_tracked_bytes(
        self,
        repo_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        unsafe_relative_path = "safe/C:escape/payload.txt"
        (tmp_path / "safe").mkdir()
        completed = subprocess.CompletedProcess(
            args=("git", "ls-files", "--cached", "--full-name", "-z"),
            returncode=0,
            stdout=unsafe_relative_path.encode("utf-8") + b"\0",
            stderr=b"",
        )
        with monkeypatch.context() as patch:
            patch.setattr(
                subprocess,
                "run",
                lambda *args, **kwargs: completed,
            )
            with pytest.raises(AssertionError) as captured:
                _git_tracked_worktree_bytes(tmp_path)
        assert captured.value.args == (
            f"unsafe tracked path: {unsafe_relative_path}",
        )

        stable_client = re.compile(rb"client_[a-z0-9]{12}", re.IGNORECASE)
        offenders = tuple(
            (path, len(stable_client.findall(content)))
            for path, content in _git_tracked_worktree_bytes(repo_root)
            if stable_client.search(content) is not None
        )
        assert offenders == (), (
            f"tracked stable-client offenders: {offenders!r}"
        )

    def test_canonical_policies_have_no_repo_tracked_hits(
        self,
        repo_root: Path,
    ) -> None:
        policy_paths = tuple(
            repo_root / "policies" / name
            for name in (
                "evidence-levels.yaml",
                "relation-types.yaml",
                "retention.yaml",
                "risk-rules.yaml",
            )
        )
        outcome = _scanner(profile="repo_tracked").scan_paths(policy_paths)
        assert outcome.report.hits == ()
        assert outcome.report.hit_count == 0


class TestScannerPublicContract:
    def test_scan_17_exact_key_contract(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        generated_key = bytes(reversed(range(32)))
        generated_calls: list[int] = []

        def generated_key_once(length: int) -> bytes:
            generated_calls.append(length)
            return generated_key

        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            generated_key_once,
        )

        default_key_scanner = _scanner(hash_key=None)
        assert repr(default_key_scanner) == "<PrivacyScanner redacted>"
        assert generated_calls == [32]

        injected_key_scanner = _scanner(hash_key=bytes(range(32)))
        assert repr(injected_key_scanner) == "<PrivacyScanner redacted>"
        assert generated_calls == [32]

        invalid_keys: tuple[object, ...] = (
            b"",
            bytes(31),
            bytes(33),
            bytearray(32),
            memoryview(bytes(32)),
        )
        for invalid_key in invalid_keys:
            with pytest.raises(PrivacyScanError) as captured:
                PrivacyScanner.default(
                    profile="repo_tracked",
                    canary_definition_path=_CANARY_DEFINITION,
                    hash_key=invalid_key,  # type: ignore[arg-type]
                )
            assert captured.value.code == "SCAN_KEY_INVALID"
            assert captured.value.location_ref is None
            assert captured.value.args == ("SCAN_KEY_INVALID",)
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None

        def raising_key(length: int) -> bytes:
            assert length == 32
            raise RuntimeError("TOKEN_BYTES_ORACLE")

        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            raising_key,
        )
        with pytest.raises(PrivacyScanError) as captured:
            _scanner(hash_key=None)
        assert captured.value.code == "SCAN_KEY_INVALID"
        assert captured.value.args == ("SCAN_KEY_INVALID",)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        assert "TOKEN_BYTES_ORACLE" not in str(captured.value)
        assert "TOKEN_BYTES_ORACLE" not in repr(captured.value)

        for generated_invalid in (b"", bytearray(32), memoryview(bytes(32))):
            monkeypatch.setattr(
                privacy_scan_module.secrets,
                "token_bytes",
                lambda length, value=generated_invalid: value,
            )
            with pytest.raises(PrivacyScanError) as captured:
                _scanner(hash_key=None)
            assert captured.value.code == "SCAN_KEY_INVALID"
            assert captured.value.args == ("SCAN_KEY_INVALID",)
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None

        signature = inspect.signature(PrivacyScanner.default)
        assert signature.parameters["profile"].default is inspect.Parameter.empty
        assert (
            signature.parameters["canary_definition_path"].default
            is inspect.Parameter.empty
        )
        with pytest.raises(TypeError):
            PrivacyScanner.default(canary_definition_path=_CANARY_DEFINITION)
        with pytest.raises(TypeError):
            PrivacyScanner.default(profile="repo_tracked")

    def test_scan_27_default_and_hard_limits(self) -> None:
        assert SCAN_CHUNK_BYTES == 65_536
        assert SCAN_CARRY_BYTES == 512
        assert tuple(field.name for field in fields(ScanLimits)) == _LIMIT_FIELDS
        assert tuple(
            getattr(DEFAULT_SCAN_LIMITS, field_name)
            for field_name in _LIMIT_FIELDS
        ) == _DEFAULT_LIMIT_VALUES

        with pytest.raises(FrozenInstanceError):
            DEFAULT_SCAN_LIMITS.max_hits = 1  # type: ignore[misc]
        assert not hasattr(DEFAULT_SCAN_LIMITS, "__dict__")

        hard_limits = ScanLimits(**dict(zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES)))
        assert isinstance(_scanner(limits=hard_limits), PrivacyScanner)

        for field_name, hard_value in zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES):
            invalid_limits = replace(hard_limits, **{field_name: hard_value + 1})
            with pytest.raises(PrivacyScanError) as captured:
                _scanner(limits=invalid_limits)
            assert captured.value.code == "SCAN_LIMIT_CONFIGURATION_INVALID"
            assert captured.value.location_ref is None
            assert captured.value.args == ("SCAN_LIMIT_CONFIGURATION_INVALID",)

        assert isinstance(
            _scanner(
                limits=replace(
                    DEFAULT_SCAN_LIMITS,
                    max_input_paths=1,
                    max_roots=1,
                    max_tree_entries=1,
                    max_files=1,
                    max_depth=1,
                    max_native_relative_bytes=1,
                    max_file_bytes=1,
                    max_total_bytes=1,
                    max_hits=1,
                )
            ),
            PrivacyScanner,
        )

    def test_scan_29_invalid_limit_configuration(self) -> None:
        for field_name in _LIMIT_FIELDS:
            for invalid_value in (True, False, 0, -1, 1.0, "1"):
                invalid_limits = replace(
                    DEFAULT_SCAN_LIMITS,
                    **{field_name: invalid_value},
                )
                with pytest.raises(PrivacyScanError) as captured:
                    _scanner(limits=invalid_limits)
                assert captured.value.code == "SCAN_LIMIT_CONFIGURATION_INVALID"
                assert captured.value.location_ref is None
                assert captured.value.args == (
                    "SCAN_LIMIT_CONFIGURATION_INVALID",
                )

        with pytest.raises(PrivacyScanError) as captured:
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=bytes(range(32)),
                limits=object(),  # type: ignore[arg-type]
            )
        assert captured.value.code == "SCAN_LIMIT_CONFIGURATION_INVALID"

        for invalid_profile in (None, "", "REPO_TRACKED", "unknown", 1, True):
            with pytest.raises(PrivacyScanError) as captured:
                _scanner(profile=invalid_profile)
            assert captured.value.code == "SCAN_PROFILE_INVALID"
            assert captured.value.location_ref is None
            assert captured.value.args == ("SCAN_PROFILE_INVALID",)

        class RaisingEquality:
            def __eq__(self, other: object) -> bool:
                del other
                raise RuntimeError("PROFILE_EQUALITY_ORACLE")

        with pytest.raises(PrivacyScanError) as captured:
            _scanner(profile=RaisingEquality())
        assert captured.value.code == "SCAN_PROFILE_INVALID"
        assert captured.value.args == ("SCAN_PROFILE_INVALID",)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    def test_scan_31_public_redaction_surface(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        initializer_oracles: list[str] = []
        subclass_hook_oracles: list[str] = []
        unchecked_subclass_states: list[tuple[object, ...]] = []

        class NonCooperativeFirst:
            def __init_subclass__(cls, **kwargs: object) -> None:
                del cls, kwargs
                subclass_hook_oracles.append("NONCOOPERATIVE_HOOK_ORACLE")

        def define_statement_subclass() -> type[PrivacyScanner]:
            class StatementSubclassOracle(PrivacyScanner):
                def __init__(self) -> None:
                    initializer_oracles.append("STATEMENT_INIT_ORACLE")

            return StatementSubclassOracle

        def dynamic_body(namespace: dict[str, object]) -> None:
            def dynamic_initializer(self: PrivacyScanner) -> None:
                del self
                initializer_oracles.append("DYNAMIC_INIT_ORACLE")

            namespace["__init__"] = dynamic_initializer

        def define_dynamic_subclass() -> type:
            return types.new_class(
                "DynamicSubclassOracle",
                (PrivacyScanner,),
                exec_body=dynamic_body,
            )

        def record_unchecked_state(value: PrivacyScanner) -> None:
            unchecked_subclass_states.append(
                (
                    object.__getattribute__(value, "_PrivacyScanner__profile"),
                    object.__getattribute__(value, "_PrivacyScanner__limits"),
                    object.__getattribute__(value, "_PrivacyScanner__scan_key"),
                    object.__getattribute__(
                        value,
                        "_PrivacyScanner__catalog_binding",
                    ),
                )
            )

        def define_statement_multiple_subclass() -> type[PrivacyScanner]:
            class StatementMultipleSubclassOracle(
                NonCooperativeFirst,
                PrivacyScanner,
            ):
                __slots__ = ()

                def __new__(cls) -> StatementMultipleSubclassOracle:
                    initializer_oracles.append("STATEMENT_MULTI_NEW_ORACLE")
                    return object.__new__(cls)

                def __init__(self) -> None:
                    initializer_oracles.append("STATEMENT_MULTI_INIT_ORACLE")
                    object.__setattr__(
                        self,
                        "_PrivacyScanner__profile",
                        "invalid",
                    )
                    object.__setattr__(
                        self,
                        "_PrivacyScanner__limits",
                        object(),
                    )
                    object.__setattr__(self, "_PrivacyScanner__scan_key", b"")
                    object.__setattr__(
                        self,
                        "_PrivacyScanner__catalog_binding",
                        object(),
                    )

            record_unchecked_state(StatementMultipleSubclassOracle())
            return StatementMultipleSubclassOracle

        def multiple_dynamic_body(namespace: dict[str, object]) -> None:
            namespace["__slots__"] = ()

            def dynamic_new(cls: type[PrivacyScanner]) -> PrivacyScanner:
                initializer_oracles.append("DYNAMIC_MULTI_NEW_ORACLE")
                return object.__new__(cls)

            def dynamic_initializer(self: PrivacyScanner) -> None:
                initializer_oracles.append("DYNAMIC_MULTI_INIT_ORACLE")
                object.__setattr__(
                    self,
                    "_PrivacyScanner__profile",
                    "invalid",
                )
                object.__setattr__(self, "_PrivacyScanner__limits", object())
                object.__setattr__(self, "_PrivacyScanner__scan_key", b"")
                object.__setattr__(
                    self,
                    "_PrivacyScanner__catalog_binding",
                    object(),
                )

            namespace["__new__"] = dynamic_new
            namespace["__init__"] = dynamic_initializer

        def define_dynamic_multiple_subclass() -> type:
            subclass = types.new_class(
                "DynamicMultipleSubclassOracle",
                (NonCooperativeFirst, PrivacyScanner),
                exec_body=multiple_dynamic_body,
            )
            record_unchecked_state(subclass())
            return subclass

        subclass_errors: list[Exception] = []
        for define_subclass in (
            define_statement_subclass,
            define_dynamic_subclass,
            define_statement_multiple_subclass,
            define_dynamic_multiple_subclass,
        ):
            try:
                define_subclass()
            except Exception as error:
                subclass_errors.append(error)

        assert (
            len(subclass_errors),
            initializer_oracles,
            subclass_hook_oracles,
            unchecked_subclass_states,
        ) == (4, [], [], [])
        for error in subclass_errors:
            assert type(error) is TypeError
            assert error.args == ("SCAN_SCANNER_FROZEN",)
            assert str(error) == "SCAN_SCANNER_FROZEN"
            assert error.__cause__ is None
            assert error.__context__ is None
            public_error = f"{error!s} {error!r} {error.args!r}"
            for oracle in (
                "StatementSubclassOracle",
                "DynamicSubclassOracle",
                "STATEMENT_INIT_ORACLE",
                "DYNAMIC_INIT_ORACLE",
                "StatementMultipleSubclassOracle",
                "DynamicMultipleSubclassOracle",
                "STATEMENT_MULTI_NEW_ORACLE",
                "STATEMENT_MULTI_INIT_ORACLE",
                "DYNAMIC_MULTI_NEW_ORACLE",
                "DYNAMIC_MULTI_INIT_ORACLE",
                "NONCOOPERATIVE_HOOK_ORACLE",
            ):
                assert oracle not in public_error

        initial_key = bytes(range(32))
        replacement_key = bytes(reversed(range(32)))
        origin_scanners = (
            PrivacyScanner(
                profile="repo_tracked",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=initial_key,
            ),
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=initial_key,
            ),
        )
        real_catalog_binding = privacy_scan_module._catalog_binding
        real_token_bytes = privacy_scan_module.secrets.token_bytes

        def bound_state(value: PrivacyScanner) -> tuple[object, ...]:
            return (
                object.__getattribute__(value, "_PrivacyScanner__profile"),
                object.__getattribute__(value, "_PrivacyScanner__limits"),
                object.__getattribute__(value, "_PrivacyScanner__scan_key"),
                object.__getattribute__(
                    value,
                    "_PrivacyScanner__catalog_binding",
                ),
            )

        def state_is_unchanged(
            value: PrivacyScanner,
            original: tuple[object, ...],
        ) -> bool:
            current = bound_state(value)
            return (
                current[0] == original[0]
                and current[1] is original[1]
                and current[2] == original[2]
                and current[3] is original[3]
            )

        one_shot_errors: list[Exception | None] = []
        one_shot_observations: list[tuple[object, ...]] = []
        for scanner_origin in origin_scanners:
            original_state = bound_state(scanner_origin)
            catalog_calls: list[str] = []
            entropy_calls: list[int] = []

            def catalog_binding_spy(
                path: Path,
                limits: ScanLimits,
            ) -> object:
                catalog_calls.append("catalog")
                return real_catalog_binding(path, limits)

            def token_bytes_spy(length: int) -> bytes:
                entropy_calls.append(length)
                return replacement_key

            monkeypatch.setattr(
                privacy_scan_module,
                "_catalog_binding",
                catalog_binding_spy,
            )
            monkeypatch.setattr(
                privacy_scan_module.secrets,
                "token_bytes",
                token_bytes_spy,
            )
            caught: Exception | None = None
            try:
                PrivacyScanner.__init__(
                    scanner_origin,
                    profile="shared_derivative",
                    canary_definition_path=_CANARY_DEFINITION,
                    hash_key=None,
                    limits=replace(DEFAULT_SCAN_LIMITS, max_hits=1),
                )
            except Exception as error:
                caught = error
            one_shot_errors.append(caught)
            one_shot_observations.append(
                (
                    type(caught) if caught is not None else None,
                    caught.args if caught is not None else None,
                    len(catalog_calls),
                    tuple(entropy_calls),
                    state_is_unchanged(scanner_origin, original_state),
                )
            )

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            real_catalog_binding,
        )
        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            real_token_bytes,
        )

        concurrent_scanner = PrivacyScanner.__new__(PrivacyScanner)
        catalog_entered = threading.Event()
        catalog_release = threading.Event()
        catalog_count_lock = threading.Lock()
        concurrent_catalog_calls = 0
        concurrent_entropy_calls: list[int] = []
        first_init_errors: list[Exception] = []

        def blocking_catalog_binding(
            path: Path,
            limits: ScanLimits,
        ) -> object:
            nonlocal concurrent_catalog_calls
            with catalog_count_lock:
                concurrent_catalog_calls += 1
                ordinal = concurrent_catalog_calls
            if ordinal == 1:
                catalog_entered.set()
                if not catalog_release.wait(timeout=5):
                    raise AssertionError("CATALOG_RELEASE_TIMEOUT")
            return real_catalog_binding(path, limits)

        def concurrent_token_bytes(length: int) -> bytes:
            concurrent_entropy_calls.append(length)
            return replacement_key

        def initialize_first() -> None:
            try:
                PrivacyScanner.__init__(
                    concurrent_scanner,
                    profile="repo_tracked",
                    canary_definition_path=_CANARY_DEFINITION,
                    hash_key=initial_key,
                )
            except Exception as error:
                first_init_errors.append(error)

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            blocking_catalog_binding,
        )
        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            concurrent_token_bytes,
        )
        first_initializer = threading.Thread(target=initialize_first)
        first_initializer.start()
        assert catalog_entered.wait(timeout=5)
        concurrent_error: Exception | None = None
        try:
            PrivacyScanner.__init__(
                concurrent_scanner,
                profile="shared_derivative",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=None,
                limits=replace(DEFAULT_SCAN_LIMITS, max_hits=1),
            )
        except Exception as error:
            concurrent_error = error
        finally:
            catalog_release.set()
        first_initializer.join(timeout=5)
        assert not first_initializer.is_alive()
        assert first_init_errors == []

        catalog_calls_before_invalid = concurrent_catalog_calls
        entropy_calls_before_invalid = tuple(concurrent_entropy_calls)
        invalid_reinit_error: Exception | None = None
        try:
            PrivacyScanner.__init__(
                concurrent_scanner,
                profile=object(),  # type: ignore[arg-type]
                canary_definition_path=Path("CALLER_PATH_ORACLE"),
                hash_key=None,
                limits=object(),  # type: ignore[arg-type]
            )
        except Exception as error:
            invalid_reinit_error = error

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            real_catalog_binding,
        )
        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            real_token_bytes,
        )
        contended_scanner = PrivacyScanner(
            profile="repo_tracked",
            canary_definition_path=_CANARY_DEFINITION,
            hash_key=initial_key,
        )
        contended_original_state = bound_state(contended_scanner)
        contended_lock = object.__getattribute__(
            contended_scanner,
            "_PrivacyScanner__initialization_lock",
        )
        contended_started = threading.Event()
        contended_finished = threading.Event()
        contended_errors: list[Exception] = []
        contended_catalog_calls: list[str] = []
        contended_entropy_calls: list[int] = []

        def contended_catalog_binding(
            path: Path,
            limits: ScanLimits,
        ) -> object:
            contended_catalog_calls.append("catalog")
            return real_catalog_binding(path, limits)

        def contended_token_bytes(length: int) -> bytes:
            contended_entropy_calls.append(length)
            return replacement_key

        def retry_while_initialization_lock_is_held() -> None:
            contended_started.set()
            try:
                PrivacyScanner.__init__(
                    contended_scanner,
                    profile="shared_derivative",
                    canary_definition_path=_CANARY_DEFINITION,
                    hash_key=None,
                    limits=replace(DEFAULT_SCAN_LIMITS, max_hits=1),
                )
            except Exception as error:
                contended_errors.append(error)
            finally:
                contended_finished.set()

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            contended_catalog_binding,
        )
        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            contended_token_bytes,
        )
        assert contended_lock.acquire(blocking=False)
        contended_retry = threading.Thread(
            target=retry_while_initialization_lock_is_held
        )
        completed_while_lock_held = False
        try:
            contended_retry.start()
            assert contended_started.wait(timeout=5)
            completed_while_lock_held = contended_finished.wait(timeout=1)
        finally:
            contended_lock.release()
        contended_retry.join(timeout=5)
        assert not contended_retry.is_alive()

        completion_scanner = PrivacyScanner.__new__(PrivacyScanner)
        completion_lock = object.__getattribute__(
            completion_scanner,
            "_PrivacyScanner__initialization_lock",
        )
        completion_catalog_ready = threading.Event()
        completion_catalog_release = threading.Event()
        completion_finished = threading.Event()
        completion_errors: list[Exception] = []

        def catalog_before_contended_completion(
            path: Path,
            limits: ScanLimits,
        ) -> object:
            binding = real_catalog_binding(path, limits)
            completion_catalog_ready.set()
            if not completion_catalog_release.wait(timeout=5):
                raise AssertionError("COMPLETION_RELEASE_TIMEOUT")
            return binding

        def initialize_through_contended_completion() -> None:
            try:
                PrivacyScanner.__init__(
                    completion_scanner,
                    profile="repo_tracked",
                    canary_definition_path=_CANARY_DEFINITION,
                    hash_key=initial_key,
                )
            except Exception as error:
                completion_errors.append(error)
            finally:
                completion_finished.set()

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            catalog_before_contended_completion,
        )
        completion_initializer = threading.Thread(
            target=initialize_through_contended_completion
        )
        completion_initializer.start()
        assert completion_catalog_ready.wait(timeout=5)
        assert completion_lock.acquire(blocking=False)
        completion_finished_while_lock_held = False
        try:
            completion_catalog_release.set()
            completion_finished_while_lock_held = completion_finished.wait(
                timeout=1
            )
        finally:
            completion_lock.release()
        completion_initializer.join(timeout=5)
        assert not completion_initializer.is_alive()

        completion_retry_catalog_calls: list[str] = []

        def completion_retry_catalog(
            path: Path,
            limits: ScanLimits,
        ) -> object:
            completion_retry_catalog_calls.append("catalog")
            return real_catalog_binding(path, limits)

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            completion_retry_catalog,
        )
        completion_retry_error: Exception | None = None
        try:
            PrivacyScanner.__init__(
                completion_scanner,
                profile="repo_tracked",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=initial_key,
            )
        except Exception as error:
            completion_retry_error = error

        bypass_catalog_calls: list[str] = []
        bypass_entropy_calls: list[int] = []

        def bypass_catalog_binding(
            path: Path,
            limits: ScanLimits,
        ) -> object:
            bypass_catalog_calls.append("catalog")
            return real_catalog_binding(path, limits)

        def bypass_token_bytes(length: int) -> bytes:
            bypass_entropy_calls.append(length)
            return replacement_key

        monkeypatch.setattr(
            privacy_scan_module,
            "_catalog_binding",
            bypass_catalog_binding,
        )
        monkeypatch.setattr(
            privacy_scan_module.secrets,
            "token_bytes",
            bypass_token_bytes,
        )
        bypassed_scanner = object.__new__(PrivacyScanner)
        bypass_error: Exception | None = None
        try:
            PrivacyScanner.__init__(
                bypassed_scanner,
                profile="repo_tracked",
                canary_definition_path=_CANARY_DEFINITION,
                hash_key=None,
            )
        except Exception as error:
            bypass_error = error

        allocation_error: Exception | None = None
        try:
            PrivacyScanner.__new__(object)  # type: ignore[arg-type]
        except Exception as error:
            allocation_error = error

        frozen_observation = (
            TypeError,
            ("SCAN_SCANNER_FROZEN",),
            0,
            (),
            True,
        )
        assert one_shot_observations == [
            frozen_observation,
            frozen_observation,
        ]
        assert (
            type(concurrent_error) if concurrent_error is not None else None,
            concurrent_error.args if concurrent_error is not None else None,
            concurrent_catalog_calls,
            tuple(concurrent_entropy_calls),
        ) == (TypeError, ("SCAN_SCANNER_FROZEN",), 1, ())
        assert (
            type(invalid_reinit_error)
            if invalid_reinit_error is not None
            else None,
            invalid_reinit_error.args
            if invalid_reinit_error is not None
            else None,
            concurrent_catalog_calls == catalog_calls_before_invalid,
            tuple(concurrent_entropy_calls) == entropy_calls_before_invalid,
        ) == (TypeError, ("SCAN_SCANNER_FROZEN",), True, True)
        assert (
            completed_while_lock_held,
            type(contended_errors[0]) if len(contended_errors) == 1 else None,
            contended_errors[0].args if len(contended_errors) == 1 else None,
            len(contended_catalog_calls),
            tuple(contended_entropy_calls),
            state_is_unchanged(contended_scanner, contended_original_state),
        ) == (
            True,
            TypeError,
            ("SCAN_SCANNER_FROZEN",),
            0,
            (),
            True,
        )
        assert (
            completion_finished_while_lock_held,
            type(completion_errors[0]) if len(completion_errors) == 1 else None,
            completion_errors[0].args if len(completion_errors) == 1 else None,
            type(completion_retry_error)
            if completion_retry_error is not None
            else None,
            completion_retry_error.args
            if completion_retry_error is not None
            else None,
            len(completion_retry_catalog_calls),
        ) == (
            True,
            TypeError,
            ("SCAN_SCANNER_FROZEN",),
            TypeError,
            ("SCAN_SCANNER_FROZEN",),
            0,
        )
        assert (
            type(bypass_error) if bypass_error is not None else None,
            bypass_error.args if bypass_error is not None else None,
            len(bypass_catalog_calls),
            tuple(bypass_entropy_calls),
        ) == (TypeError, ("SCAN_SCANNER_FROZEN",), 0, ())
        assert (
            type(allocation_error) if allocation_error is not None else None,
            allocation_error.args if allocation_error is not None else None,
        ) == (TypeError, ("SCAN_SCANNER_FROZEN",))
        for error in (
            *one_shot_errors,
            concurrent_error,
            invalid_reinit_error,
            *contended_errors,
            *completion_errors,
            completion_retry_error,
            bypass_error,
            allocation_error,
        ):
            assert error is not None
            assert str(error) == "SCAN_SCANNER_FROZEN"
            assert error.__cause__ is None
            assert error.__context__ is None
            assert "CALLER_PATH_ORACLE" not in repr(error)

        scanner = _scanner()
        assert repr(scanner) == "<PrivacyScanner redacted>"
        assert not hasattr(scanner, "__dict__")
        assert not hasattr(scanner, "hash_key")
        assert not hasattr(scanner, "scan_key")
        assert "scan_key" not in dir(scanner)
        assert "catalog_binding" not in dir(scanner)
        assert "generation" not in dir(scanner)
        assert "mapping" not in dir(scanner)

        for operation in (
            lambda: copy.copy(scanner),
            lambda: copy.deepcopy(scanner),
            lambda: pickle.dumps(scanner),
        ):
            with pytest.raises(TypeError) as captured:
                operation()
            assert captured.value.args == ("SCAN_SERIALIZATION_FORBIDDEN",)

        hit = PrivacyHit(
            location_ref="root_0001/pth1_" + "a" * 64,
            rule_id="email_address",
            line_number=3,
            hit_hash="b" * 64,
        )
        report = PrivacyScanReport(hits=(hit, hit))
        assert report == PrivacyScanReport(hits=(hit, hit))
        assert report.hit_count == 2
        assert tuple(field.name for field in fields(PrivacyHit)) == (
            "location_ref",
            "rule_id",
            "line_number",
            "hit_hash",
        )
        assert tuple(field.name for field in fields(PrivacyScanReport)) == ("hits",)
        assert not hasattr(hit, "path")
        assert not hasattr(report, "path")

        handle = object.__new__(ScanResolutionHandle)
        assert repr(handle) == "<ScanResolutionHandle redacted>"
        assert not hasattr(handle, "__dict__")
        assert handle == handle
        assert handle != object.__new__(ScanResolutionHandle)

        outcome = PrivacyScanOutcome(report=report, resolution_handle=handle)
        same_values = PrivacyScanOutcome(report=report, resolution_handle=handle)
        assert repr(outcome) == "<PrivacyScanOutcome redacted>"
        assert outcome != same_values
        assert tuple(field.name for field in fields(PrivacyScanOutcome)) == (
            "report",
            "resolution_handle",
        )

        for value in (handle, outcome):
            for operation in (
                lambda value=value: copy.copy(value),
                lambda value=value: copy.deepcopy(value),
                lambda value=value: pickle.dumps(value),
            ):
                with pytest.raises(TypeError) as captured:
                    operation()
                _assert_slice7_safe_error(
                    captured.value,
                    "SCAN_SERIALIZATION_FORBIDDEN",
                    sensitive=(value,),
                )

        error = PrivacyScanError("SCAN_LOCATION_UNAVAILABLE")
        assert error.code == "SCAN_LOCATION_UNAVAILABLE"
        assert error.location_ref is None
        assert error.args == ("SCAN_LOCATION_UNAVAILABLE",)
        assert str(error) == "SCAN_LOCATION_UNAVAILABLE"
        assert repr(error) == "<PrivacyScanError redacted>"

        opaque_ref = "root_0001/pth1_" + "c" * 64
        located_error = PrivacyScanError(
            "SCAN_LOCATION_UNAVAILABLE",
            location_ref=opaque_ref,
        )
        assert located_error.location_ref == opaque_ref
        assert located_error.args == ("SCAN_LOCATION_UNAVAILABLE",)
        assert str(located_error) == "SCAN_LOCATION_UNAVAILABLE"
        assert repr(located_error) == "<PrivacyScanError redacted>"
        assert opaque_ref not in str(located_error)
        assert opaque_ref not in repr(located_error)


class TestScannerInputValidation:
    def test_scan_09_links_reparse_and_root_escape(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = _scanner()
        root = tmp_path / "plain.bin"
        root.write_bytes(b"plain")
        alternate = tmp_path / "alternate.bin"
        alternate.write_bytes(b"alternate")
        real_lstat = privacy_scan_module._LSTAT
        real_realpath = privacy_scan_module._REALPATH

        def assert_code(path: Path, expected: str) -> None:
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths([path])
            assert captured.value.code == expected
            assert captured.value.args == (expected,)
            assert captured.value.location_ref is None
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None
            public = f"{captured.value!s} {captured.value!r}"
            assert os.fspath(path) not in public

        link = tmp_path / "link-oracle"
        link_status = SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o777,
            st_dev=1,
            st_ino=2,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=3,
            st_ctime_ns=4,
            st_file_attributes=0,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_LSTAT",
            lambda path: link_status if Path(path) == link else real_lstat(path),
        )
        assert_code(link, "SCAN_LINK_OR_REPARSE")

        reparse = tmp_path / "reparse-oracle"
        reparse_status = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1,
            st_ino=5,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=6,
            st_ctime_ns=7,
            st_file_attributes=privacy_scan_module._REPARSE_ATTRIBUTE,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_LSTAT",
            lambda path: (
                reparse_status if Path(path) == reparse else real_lstat(path)
            ),
        )
        assert_code(reparse, "SCAN_LINK_OR_REPARSE")

        monkeypatch.setattr(privacy_scan_module, "_LSTAT", real_lstat)
        monkeypatch.setattr(
            privacy_scan_module,
            "_REALPATH",
            lambda path: (
                os.fspath(alternate)
                if Path(path) == root
                else real_realpath(path)
            ),
        )
        assert_code(root, "SCAN_ROOT_ESCAPE")

    def test_relative_missing_special_and_namespace_inputs_fail_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = _scanner(limits=replace(DEFAULT_SCAN_LIMITS, max_input_paths=2))
        valid = tmp_path / "valid.bin"
        valid.write_bytes(b"valid")

        def assert_code(paths: object, expected: str) -> None:
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths(paths)  # type: ignore[arg-type]
            assert captured.value.code == expected
            assert captured.value.args == (expected,)
            assert captured.value.location_ref is None
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None
            public = f"{captured.value!s} {captured.value!r}"
            assert "CALLER_ORACLE" not in public
            assert os.fspath(tmp_path) not in public

        assert_code([Path("CALLER_ORACLE")], "SCAN_PATH_NOT_ABSOLUTE")
        assert_code(
            [Path("C:CALLER_ORACLE")],
            "SCAN_PATH_NAMESPACE_UNSUPPORTED",
        )
        assert_code([tmp_path / "CALLER_ORACLE"], "SCAN_PATH_NOT_FOUND")
        assert_code([Path("//server/share/CALLER_ORACLE")], "SCAN_PATH_NAMESPACE_UNSUPPORTED")
        assert_code("CALLER_ORACLE", "SCAN_INPUT_INVALID")
        assert_code(b"CALLER_ORACLE", "SCAN_INPUT_INVALID")
        assert_code(object(), "SCAN_INPUT_INVALID")
        assert_code([object()], "SCAN_INPUT_INVALID")

        concrete_path_type = type(Path())
        monkeypatch.chdir(tmp_path)
        relative_fspath_calls: list[str] = []
        relative_virtual_calls: list[str] = []

        class RelativePathPretendingAbsolute(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                frozen = super().__fspath__()
                relative_fspath_calls.append(frozen)
                return frozen

            def is_absolute(self) -> bool:
                relative_virtual_calls.append("is_absolute")
                return True

            def resolve(self, *args: object, **kwargs: object) -> Path:
                del args, kwargs
                relative_virtual_calls.append("resolve")
                raise AssertionError("CALLER_ORACLE_VIRTUAL_PATH")

        relative_subtype = RelativePathPretendingAbsolute(valid.name)
        boundary_calls: list[str] = []
        real_lstat_for_subtype = privacy_scan_module._LSTAT
        real_realpath_for_subtype = privacy_scan_module._REALPATH

        def subtype_lstat(path: object) -> object:
            if os.fspath(path) == valid.name:
                boundary_calls.append("lstat")
            return real_lstat_for_subtype(path)

        def subtype_realpath(path: str) -> str:
            if path == valid.name:
                boundary_calls.append("realpath")
            return real_realpath_for_subtype(path)

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_LSTAT", subtype_lstat)
            patch.setattr(privacy_scan_module, "_REALPATH", subtype_realpath)
            assert_code([relative_subtype], "SCAN_PATH_NOT_ABSOLUTE")
        assert relative_fspath_calls == [valid.name]
        assert relative_virtual_calls == []
        assert boundary_calls == []

        absolute_fspath_calls: list[str] = []
        absolute_virtual_calls: list[str] = []

        class AbsolutePathSubtype(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                frozen = super().__fspath__()
                absolute_fspath_calls.append(frozen)
                return frozen

            def is_absolute(self) -> bool:
                absolute_virtual_calls.append("is_absolute")
                raise AssertionError("CALLER_ORACLE_VIRTUAL_PATH")

            def resolve(self, *args: object, **kwargs: object) -> Path:
                del args, kwargs
                absolute_virtual_calls.append("resolve")
                raise AssertionError("CALLER_ORACLE_VIRTUAL_PATH")

        absolute_subtype = AbsolutePathSubtype(os.fspath(valid))
        absolute_outcome = scanner.scan_paths([absolute_subtype])
        assert absolute_outcome.report.hit_count == 0
        assert absolute_fspath_calls == [os.fspath(valid)]
        assert absolute_virtual_calls == []

        class NonExactPathText(str):
            pass

        nonexact_calls = 0

        class NonExactTextPath(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                nonlocal nonexact_calls
                nonexact_calls += 1
                return NonExactPathText(os.fspath(valid))

        assert_code([NonExactTextPath("unused")], "SCAN_INPUT_INVALID")
        assert nonexact_calls == 1

        raising_calls = 0

        class RaisingFspathPath(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                nonlocal raising_calls
                raising_calls += 1
                raise RuntimeError("CALLER_ORACLE_FSPATH")

        assert_code([RaisingFspathPath("unused")], "SCAN_INPUT_INVALID")
        assert raising_calls == 1

        del_path = tmp_path / "payload\x7f.bin"
        del_path.write_bytes(b"plain")
        assert_code([del_path], "SCAN_PATH_UNSUPPORTED")

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_PLATFORM_NAME", "nt")
            for namespace in (
                r"\Device\HarddiskVolume1\payload",
                r"\GLOBAL??\C:\payload",
                r"\DosDevices\C:\payload",
                r"\??\C:\payload",
            ):
                assert_code(
                    [Path(namespace)],
                    "SCAN_PATH_NAMESPACE_UNSUPPORTED",
                )
            assert_code(
                [Path(r"\ordinary\payload")],
                "SCAN_PATH_NOT_ABSOLUTE",
            )

        posix_fspath_calls: list[str] = []

        class PosixTextPath(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                frozen = "/??/ordinary/payload"
                posix_fspath_calls.append(frozen)
                return frozen

            def is_absolute(self) -> bool:
                raise AssertionError("POSIX_VIRTUAL_PATH")

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_PLATFORM_NAME", "posix")
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                lambda _binding, _limits: None,
            )
            assert_code(
                [PosixTextPath("unused")],
                "SCAN_PATH_NOT_FOUND",
            )
        assert posix_fspath_calls == ["/??/ordinary/payload"]

        special = tmp_path / "CALLER_ORACLE-special"
        special_status = SimpleNamespace(
            st_mode=stat.S_IFIFO | 0o600,
            st_dev=1,
            st_ino=9,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=10,
            st_ctime_ns=11,
            st_file_attributes=0,
        )
        real_lstat = privacy_scan_module._LSTAT
        monkeypatch.setattr(
            privacy_scan_module,
            "_LSTAT",
            lambda path: (
                special_status if Path(path) == special else real_lstat(path)
            ),
        )
        assert_code([special], "SCAN_PATH_UNSUPPORTED")
        monkeypatch.setattr(privacy_scan_module, "_LSTAT", real_lstat)

        class Sentinel:
            fspath_calls = 0

            def __fspath__(self) -> str:
                self.fspath_calls += 1
                raise AssertionError("CALLER_ORACLE_SENTINEL_INSPECTED")

        sentinel = Sentinel()

        class LyingSequence(Sequence[Path]):
            def __init__(self) -> None:
                self.fetches: list[int] = []
                self.len_calls = 0

            def __len__(self) -> int:
                self.len_calls += 1
                return 0

            def __getitem__(self, index: int) -> Path:
                self.fetches.append(index)
                values: tuple[object, ...] = (valid, valid, sentinel)
                if index >= len(values):
                    raise IndexError
                return values[index]  # type: ignore[return-value]

        sequence = LyingSequence()
        assert_code(sequence, "SCAN_LIMIT_INPUT_PATHS")
        assert sequence.fetches == [0, 1, 2]
        assert sequence.len_calls == 0
        assert sentinel.fspath_calls == 0

        class RaisingSequence(Sequence[Path]):
            def __len__(self) -> int:
                return 1

            def __getitem__(self, index: int) -> Path:
                del index
                raise RuntimeError("CALLER_ORACLE_INDEX")

        assert_code(RaisingSequence(), "SCAN_INPUT_INVALID")
        empty = scanner.scan_paths([])
        assert empty.report == PrivacyScanReport(hits=())
        assert type(empty.resolution_handle) is ScanResolutionHandle

        with pytest.raises(PrivacyScanError) as captured:
            PrivacyScanner.scan_paths(object(), [])  # type: ignore[arg-type]
        assert captured.value.code == "SCAN_INPUT_INVALID"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None


class TestScannerEmptyGeneration:
    def test_scan_42_empty_scan_checks_catalog_and_commits_fresh_handle(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = _scanner()
        real_check = privacy_scan_module._scan_catalog_check
        checks: list[int] = []

        def checked(binding: object, limits: ScanLimits) -> None:
            checks.append(len(checks) + 1)
            real_check(binding, limits)

        monkeypatch.setattr(privacy_scan_module, "_scan_catalog_check", checked)
        outcome = scanner.scan_paths([])
        assert outcome.report == PrivacyScanReport(hits=())
        assert outcome.report.hit_count == 0
        assert type(outcome.resolution_handle) is ScanResolutionHandle
        assert checks == [1, 2]
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert generation.handle is outcome.resolution_handle
        assert dict(generation.mapping) == {}

        with pytest.raises(PrivacyScanError) as captured:
            scanner.resolve_location(
                outcome.resolution_handle,
                "root_0001/pth1_" + "0" * 64,
            )
        assert captured.value.code == "SCAN_LOCATION_UNAVAILABLE"
        assert captured.value.args == ("SCAN_LOCATION_UNAVAILABLE",)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

        catalog_entered = threading.Event()
        catalog_release = threading.Event()
        worker_errors: list[Exception] = []
        worker_outcomes: list[PrivacyScanOutcome] = []

        def blocking_check(binding: object, limits: ScanLimits) -> None:
            catalog_entered.set()
            if not catalog_release.wait(timeout=5):
                raise AssertionError("CATALOG_RELEASE_TIMEOUT")
            real_check(binding, limits)

        def run_scan() -> None:
            try:
                worker_outcomes.append(scanner.scan_paths([]))
            except Exception as error:
                worker_errors.append(error)

        monkeypatch.setattr(
            privacy_scan_module,
            "_scan_catalog_check",
            blocking_check,
        )
        worker = threading.Thread(target=run_scan)
        worker.start()
        assert catalog_entered.wait(timeout=5)
        losing_errors: list[PrivacyScanError] = []
        for operation in (lambda: scanner.scan_paths([]), scanner.close):
            with pytest.raises(PrivacyScanError) as losing:
                operation()
            losing_errors.append(losing.value)
        catalog_release.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert worker_errors == []
        assert len(worker_outcomes) == 1
        assert [error.code for error in losing_errors] == [
            "SCAN_CONCURRENT_USE",
            "SCAN_CONCURRENT_USE",
        ]

    def test_scan_30_empty_scan_invalidates_previous_generation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner = _scanner()
        first = scanner.scan_paths([])
        first_generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert first_generation.handle is first.resolution_handle

        with pytest.raises(PrivacyScanError) as captured:
            scanner.scan_paths([tmp_path / "MISSING_ORACLE"])
        assert captured.value.code == "SCAN_PATH_NOT_FOUND"
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None

        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(
                first.resolution_handle,
                "root_0001/pth1_" + "1" * 64,
            )
        assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"

        second = scanner.scan_paths([])
        scanner.close()
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        scanner.close()
        with pytest.raises(PrivacyScanError) as closed:
            scanner.resolve_location(
                second.resolution_handle,
                "root_0001/pth1_" + "2" * 64,
            )
        assert closed.value.code == "SCAN_LOCATION_UNAVAILABLE"

        real_check = privacy_scan_module._scan_catalog_check
        check_count = 0

        def drift_on_post(binding: object, limits: ScanLimits) -> None:
            nonlocal check_count
            check_count += 1
            if check_count == 2:
                raise privacy_scan_module._ScanFailure("SCAN_CATALOG_CHANGED")
            real_check(binding, limits)

        third = scanner.scan_paths([])
        assert third.report.hits == ()
        monkeypatch.setattr(
            privacy_scan_module,
            "_scan_catalog_check",
            drift_on_post,
        )
        with pytest.raises(PrivacyScanError) as drifted:
            scanner.scan_paths([])
        assert drifted.value.code == "SCAN_CATALOG_CHANGED"
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None

    def test_scan_32_repeated_empty_scans_have_distinct_handles(self) -> None:
        scanner = _scanner()
        first = scanner.scan_paths([])
        second = scanner.scan_paths([])
        assert first.report == second.report == PrivacyScanReport(hits=())
        assert first.resolution_handle is not second.resolution_handle
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert generation.handle is second.resolution_handle
        with pytest.raises(TypeError) as direct:
            ScanResolutionHandle()
        assert direct.value.args == ("SCAN_LOCATION_UNAVAILABLE",)


class TestScannerFileProtocol:
    @staticmethod
    def _scan_bytes(
        tmp_path: Path,
        data: bytes,
        *,
        name: str = "payload.bin",
        scanner: PrivacyScanner | None = None,
    ) -> tuple[PrivacyScanner, Path, PrivacyScanOutcome]:
        path = tmp_path / name
        path.write_bytes(data)
        selected = _scanner() if scanner is None else scanner
        return selected, path, selected.scan_paths([path])

    @staticmethod
    def _rule_hits(
        outcome: PrivacyScanOutcome,
        rule_id: str,
    ) -> tuple[PrivacyHit, ...]:
        return tuple(
            hit for hit in outcome.report.hits if hit.rule_id == rule_id
        )

    def test_scan_01_canary_chunks_and_lines(self, tmp_path: Path) -> None:
        markers = tuple(
            value.encode("ascii")
            for value in json.loads(_CANARY_DEFINITION.read_bytes())["markers"]
        )
        first = markers[0]
        prefix = b"x" * (SCAN_CHUNK_BYTES - len(first) // 2)
        data = prefix + first + b"\n" + markers[1]
        scanner, path, outcome = self._scan_bytes(tmp_path, data)
        hits = self._rule_hits(outcome, "known_canary")
        assert len(hits) == 2
        assert [hit.line_number for hit in hits] == [1, 2]
        assert all(hit.location_ref == hits[0].location_ref for hit in hits)
        assert scanner.resolve_location(
            outcome.resolution_handle,
            hits[0].location_ref,
        ) == path

        recursive_root = tmp_path / "recursive-root"
        recursive_payload = recursive_root / "nested" / "payload.bin"
        recursive_payload.parent.mkdir(parents=True)
        recursive_payload.write_bytes(data)
        recursive = scanner.scan_paths([recursive_root])
        recursive_hits = self._rule_hits(recursive, "known_canary")
        assert len(recursive_hits) == 2
        assert [hit.line_number for hit in recursive_hits] == [1, 2]
        assert all(
            hit.location_ref == recursive_hits[0].location_ref
            for hit in recursive_hits
        )
        assert scanner.resolve_location(
            recursive.resolution_handle,
            recursive_hits[0].location_ref,
        ) == recursive_payload

    def test_scan_04_definition_exemption_requires_path_identity_rule_marker_and_span(
        self,
        tmp_path: Path,
    ) -> None:
        scanner = _scanner()
        definition = scanner.scan_paths([_CANARY_DEFINITION])
        assert self._rule_hits(definition, "known_canary") == ()

        real_fstat = privacy_scan_module._FSTAT

        def alternate_ctime_channel(descriptor: int) -> object:
            status = real_fstat(descriptor)
            values = {
                name: getattr(status, name)
                for name in dir(status)
                if name.startswith("st_")
            }
            values["st_ctime_ns"] = status.st_ctime_ns + 1
            return SimpleNamespace(**values)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_FSTAT",
                alternate_ctime_channel,
            )
            channel_outcome = scanner.scan_paths([_CANARY_DEFINITION])
        assert self._rule_hits(channel_outcome, "known_canary") == ()

        copied = tmp_path / _CANARY_DEFINITION.name
        copied.write_bytes(_CANARY_DEFINITION.read_bytes())
        copy_outcome = scanner.scan_paths([copied])
        copy_hits = self._rule_hits(copy_outcome, "known_canary")
        assert len(copy_hits) == len(
            json.loads(_CANARY_DEFINITION.read_bytes())["markers"]
        )
        assert all(hit.line_number is not None for hit in copy_hits)

        span_catalog = _write_catalog(
            tmp_path / "span-definition.json",
            _catalog_bytes(("known_canary",)),
        )
        span_scanner = PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=span_catalog,
            hash_key=bytes(range(32)),
        )
        span_outcome = span_scanner.scan_paths([span_catalog])
        span_hits = self._rule_hits(span_outcome, "known_canary")
        assert len(span_hits) == 1
        assert span_hits[0].line_number == 4

    def test_scan_05_definition_other_rules_are_not_exempt(
        self,
        tmp_path: Path,
    ) -> None:
        marker = "marker" + "@" + "example.test"
        catalog = _write_catalog(
            tmp_path / "definition.db",
            _catalog_bytes((marker,)),
        )
        scanner = PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=catalog,
            hash_key=bytes(range(32)),
        )
        outcome = scanner.scan_paths([catalog])
        assert self._rule_hits(outcome, "known_canary") == ()
        assert len(self._rule_hits(outcome, "email_address")) == 1
        assert len(self._rule_hits(outcome, "forbidden_path_suffix")) == 1

    def test_scan_06_raw_bytes_utf8_bom_and_nul(self, tmp_path: Path) -> None:
        email = b"alpha" + b"@" + b"example.test"
        stable = b"client_" + b"a1" * 6
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            b"\xef\xbb\xbf\x00\xff" + email + b"\x00" + stable,
        )
        assert len(self._rule_hits(outcome, "email_address")) == 1
        assert len(self._rule_hits(outcome, "stable_client_id")) == 1

    def test_scan_07_utf16_and_utf32_are_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        boms = (
            b"\xff\xfe",
            b"\xfe\xff",
            b"\xff\xfe\x00\x00",
            b"\x00\x00\xfe\xff",
        )
        for index, bom in enumerate(boms):
            path = tmp_path / f"encoded-{index}.bin"
            path.write_bytes(bom + b"plain")
            with pytest.raises(PrivacyScanError) as captured:
                _scanner().scan_paths([path])
            assert captured.value.code == "SCAN_UNSUPPORTED_ENCODING"
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None

        previous_path = tmp_path / "previous.txt"
        previous_path.write_bytes(b"previous" + b"@" + b"example.test")
        real_open = privacy_scan_module._open_scan_descriptor
        real_read = privacy_scan_module._READ
        for bom_index, bom in enumerate(boms):
            for leading_bytes in range(1, len(bom)):
                path = tmp_path / f"split-{bom_index}-{leading_bytes}.bin"
                path.write_bytes(bom + b"plain")
                scanner = _scanner()
                previous = scanner.scan_paths([previous_path])
                previous_ref = previous.report.hits[0].location_ref
                target_descriptors: set[int] = set()
                pending_splits: dict[int, int] = {}
                requested_sizes: list[int] = []

                def capture_open(
                    candidate: Path,
                    *,
                    target: Path = path,
                    split: int = leading_bytes,
                ) -> int:
                    descriptor = real_open(candidate)
                    if candidate == target:
                        target_descriptors.add(descriptor)
                        pending_splits[descriptor] = split
                    return descriptor

                def split_read(descriptor: int, size: int) -> bytes:
                    if descriptor in target_descriptors:
                        requested_sizes.append(size)
                        if descriptor in pending_splits:
                            amount = pending_splits.pop(descriptor)
                            return real_read(descriptor, min(size, amount))
                    return real_read(descriptor, size)

                with monkeypatch.context() as patch:
                    patch.setattr(
                        privacy_scan_module,
                        "_open_scan_descriptor",
                        capture_open,
                    )
                    patch.setattr(privacy_scan_module, "_READ", split_read)
                    with pytest.raises(PrivacyScanError) as captured:
                        scanner.scan_paths([path])
                assert captured.value.code == "SCAN_UNSUPPORTED_ENCODING"
                assert captured.value.__cause__ is None
                assert captured.value.__context__ is None
                assert requested_sizes
                assert all(
                    0 < size <= SCAN_CHUNK_BYTES for size in requested_sizes
                )
                assert object.__getattribute__(
                    scanner,
                    "_PrivacyScanner__generation",
                ) is None
                with pytest.raises(PrivacyScanError) as stale:
                    scanner.resolve_location(
                        previous.resolution_handle,
                        previous_ref,
                    )
                assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"

    def test_scan_08_newline_and_chunk_boundary_oracle(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        email = b"line" + b"@" + b"example.test"
        data = (
            b"x" * (SCAN_CHUNK_BYTES - 1)
            + b"\r\n"
            + email
            + b"\r"
            + email
            + b"\n"
            + email
        )
        _scanner_value, _path, outcome = self._scan_bytes(tmp_path, data)
        hits = self._rule_hits(outcome, "email_address")
        assert [hit.line_number for hit in hits] == [2, 3, 4]
        assert len({hit.hit_hash for hit in hits}) == 1

        maximum_email = (
            b"a" * 64
            + b"@"
            + b"b" * 63
            + b"."
            + b"c" * 63
            + b"."
            + b"d" * 61
        )
        maximum_marker = b"M" * 128
        assert len(maximum_email) == 254
        assert len(maximum_marker) == 128
        catalog = _write_catalog(
            tmp_path / "maximum-token-catalog.json",
            _catalog_bytes((maximum_marker.decode("ascii"),)),
        )
        token_scanner = PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=catalog,
            hash_key=bytes(range(32)),
        )

        email_start = SCAN_CHUNK_BYTES - len(maximum_email) // 2
        maximum_data = b"x" * (email_start - 1) + b" " + maximum_email + b" "
        marker_start = 2 * SCAN_CHUNK_BYTES - len(maximum_marker) // 2
        maximum_data += (
            b"x" * (marker_start - len(maximum_data) - 1)
            + b" "
            + maximum_marker
            + b" "
        )
        maximum_path = tmp_path / "maximum-tokens.bin"
        maximum_path.write_bytes(maximum_data)
        oracle = token_scanner.scan_paths([maximum_path]).report
        assert sum(hit.rule_id == "email_address" for hit in oracle.hits) == 1
        assert sum(hit.rule_id == "known_canary" for hit in oracle.hits) == 1

        real_open = privacy_scan_module._open_scan_descriptor
        real_read = privacy_scan_module._READ
        target_descriptors: set[int] = set()
        requested_sizes: list[int] = []
        short_read_caps = (1, 3, 17, 251, 4096)
        read_index = 0

        def capture_open(candidate: Path) -> int:
            descriptor = real_open(candidate)
            if candidate == maximum_path:
                target_descriptors.add(descriptor)
            return descriptor

        def short_read(descriptor: int, size: int) -> bytes:
            nonlocal read_index
            if descriptor in target_descriptors:
                requested_sizes.append(size)
                cap = short_read_caps[read_index % len(short_read_caps)]
                read_index += 1
                return real_read(descriptor, min(size, cap))
            return real_read(descriptor, size)

        monkeypatch.setattr(
            privacy_scan_module,
            "_open_scan_descriptor",
            capture_open,
        )
        monkeypatch.setattr(privacy_scan_module, "_READ", short_read)
        short_read_report = token_scanner.scan_paths([maximum_path]).report
        assert short_read_report == oracle
        assert requested_sizes
        assert all(0 < size <= SCAN_CHUNK_BYTES for size in requested_sizes)

    def test_scan_20_mobile_matrix(self, tmp_path: Path) -> None:
        positive = b"13800" + b"138000"
        prefixed = b"+86 139-" + b"0013-8001"
        negative = b"a" + positive + b" " + b"1" + positive
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            positive + b"\n" + prefixed + b"\n" + negative,
        )
        hits = self._rule_hits(outcome, "cn_mobile_number")
        assert len(hits) == 2
        assert [hit.line_number for hit in hits] == [1, 2]

    def test_scan_21_resident_id_matrix(self, tmp_path: Path) -> None:
        valid = b"110105" + b"19900101" + b"123X"
        invalid_month = b"110105" + b"19901301" + b"123X"
        short = b"110105" + b"900101" + b"123"
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            valid + b"\n" + invalid_month + b"\n" + short,
        )
        hits = self._rule_hits(outcome, "cn_resident_id")
        assert len(hits) == 1
        assert hits[0].line_number == 1

    def test_scan_22_email_matrix(self, tmp_path: Path) -> None:
        first = b"alpha" + b"@" + b"example.test"
        second = b"a.b+tag" + b"@" + b"sub.example.test"
        invalid_dot = b"..bad" + b"@" + b"example.test"
        invalid_label = b"bad" + b"@" + b"-label.example"
        overlong = b"a" * 65 + b"@" + b"example.test"
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            b"\n".join((first, second, invalid_dot, invalid_label, overlong)),
        )
        hits = self._rule_hits(outcome, "email_address")
        assert len(hits) == 2
        assert [hit.line_number for hit in hits] == [1, 2]

    def test_scan_23_stable_client_id_matrix(self, tmp_path: Path) -> None:
        lower = b"client_" + b"a1" * 6
        mixed = b"CLIENT_" + b"B2" * 6
        regex_text = b"client_[a-z0-9]{12}"
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            lower + b"\nxx" + mixed + b"yy\n" + regex_text,
        )
        hits = self._rule_hits(outcome, "stable_client_id")
        assert len(hits) == 2
        assert [hit.line_number for hit in hits] == [1, 2]

    def test_scan_24_profile_suffix_matrix(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        forbidden_names = (
            "main.sqlite3",
            "main.sqlite3-wal",
            "main.sqlite3-shm",
            "main.sqlite3-journal",
            "main.db",
            "main.db-wal",
            "main.db-shm",
            "main.db-journal",
            "identity-map.enc",
        )
        allowed_names = ("array.npy", "current.json", "opaque.enc")
        for profile in ("repo_tracked", "shared_derivative"):
            profile_root = tmp_path / profile
            profile_root.mkdir()
            for name in forbidden_names:
                scanner, _path, outcome = self._scan_bytes(
                    profile_root,
                    b"plain",
                    name=name,
                    scanner=_scanner(profile=profile),
                )
                del scanner
                hits = self._rule_hits(outcome, "forbidden_path_suffix")
                assert len(hits) == 1
                assert hits[0].line_number is None
            for ordinal, name in enumerate(allowed_names):
                _scanner_value, _path, outcome = self._scan_bytes(
                    profile_root,
                    b"plain",
                    name=f"{ordinal}-{name}",
                    scanner=_scanner(profile=profile),
                )
                assert self._rule_hits(outcome, "forbidden_path_suffix") == ()

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_PLATFORM_NAME", "posix")
            assert privacy_scan_module._native_component_supported(
                "ordinary\\name.db"
            )
            assert privacy_scan_module._forbidden_suffix_match(
                "repo_tracked",
                b"ordinary\\name.db",
            ) == b".db"
        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_PLATFORM_NAME", "nt")
            assert not privacy_scan_module._native_component_supported(
                "ordinary\\name.db"
            )
            assert privacy_scan_module._forbidden_suffix_match(
                "repo_tracked",
                b"ordinary\\name.db",
            ) is None

    def test_scan_25_shared_catalog_is_not_exempt(self, tmp_path: Path) -> None:
        path = tmp_path / "global-catalog.sqlite3"
        path.write_bytes(_CANARY_DEFINITION.read_bytes())
        scanner = _scanner(profile="shared_derivative")
        outcome = scanner.scan_paths([path])
        assert len(self._rule_hits(outcome, "known_canary")) == 2
        assert len(self._rule_hits(outcome, "forbidden_path_suffix")) == 1

    def test_scan_26_occurrences_are_not_deduplicated(
        self,
        tmp_path: Path,
    ) -> None:
        occurrence = b"repeat" + b"@" + b"example.test"
        _scanner_value, _path, outcome = self._scan_bytes(
            tmp_path,
            occurrence + b" " + occurrence,
        )
        hits = self._rule_hits(outcome, "email_address")
        assert len(hits) == 2
        assert hits[0] == hits[1]
        assert outcome.report.hit_count == 2


class TestScannerTreeOwnership:
    @staticmethod
    def _email() -> bytes:
        return b"tree" + b"@" + b"example.test"

    def test_scan_11_overlap_uses_most_specific_owner(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        outer = tmp_path / "outer"
        nested = outer / "nested"
        nested.mkdir(parents=True)
        payload = nested / "payload.txt"
        payload.write_bytes(self._email())
        scanner = _scanner()
        first = scanner.scan_paths([outer, nested, outer])
        second = scanner.scan_paths([nested, outer])
        assert first.report == second.report
        assert first.report.hit_count == 1
        ordered = sorted(
            (outer, nested),
            key=lambda path: os.path.normcase(os.path.normpath(os.fspath(path))),
        )
        expected_label = f"root_{ordered.index(nested) + 1:04d}/"
        hit = first.report.hits[0]
        assert hit.location_ref.startswith(expected_label)
        assert scanner.resolve_location(
            second.resolution_handle,
            hit.location_ref,
        ) == payload

        indexed_root = tmp_path / "indexed-root"
        indexed_nested = indexed_root / "one" / "two"
        indexed_nested.mkdir(parents=True)
        indexed_payload = indexed_nested / "payload.txt"
        indexed_payload.write_bytes(self._email())
        explicit_files: list[Path] = []
        for ordinal in range(12):
            explicit_file = tmp_path / f"explicit-{ordinal:02d}.txt"
            explicit_file.write_bytes(b"plain")
            explicit_files.append(explicit_file)
        indexed_roots = [indexed_root, *explicit_files]
        owner_lookup_candidate = getattr(
            privacy_scan_module,
            "_owner_index_lookup",
            None,
        )
        assert callable(owner_lookup_candidate)
        real_owner_lookup = cast(
            Callable[
                [Mapping[str, privacy_scan_module._ExplicitRoot], str],
                privacy_scan_module._ExplicitRoot | None,
            ],
            owner_lookup_candidate,
        )
        owner_lookups: list[
            tuple[Mapping[str, privacy_scan_module._ExplicitRoot], str]
        ] = []

        def counted_owner_lookup(
            owner_index: Mapping[str, privacy_scan_module._ExplicitRoot],
            path_key: str,
        ) -> privacy_scan_module._ExplicitRoot | None:
            owner_lookups.append((owner_index, path_key))
            return real_owner_lookup(owner_index, path_key)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_owner_index_lookup",
                counted_owner_lookup,
            )
            indexed_scanner = _scanner()
            indexed = indexed_scanner.scan_paths(indexed_roots)
        indexed_hits = tuple(
            candidate
            for candidate in indexed.report.hits
            if candidate.rule_id == "email_address"
        )
        assert len(indexed_hits) == 1
        assert indexed_scanner.resolve_location(
            indexed.resolution_handle,
            indexed_hits[0].location_ref,
        ) == indexed_payload
        deduplicated_candidates = {indexed_payload, *explicit_files}
        relative_depth = len(indexed_payload.relative_to(indexed_root).parts)
        expected_owner_lookups = len(deduplicated_candidates) + relative_depth
        assert owner_lookups
        assert len(owner_lookups) == expected_owner_lookups

    def test_scan_12_hardlink_pathnames_are_distinct_locations(
        self,
        tmp_path: Path,
    ) -> None:
        root = tmp_path / "hardlinks"
        root.mkdir()
        first = root / "first.txt"
        second = root / "second.txt"
        first.write_bytes(self._email())
        os.link(first, second)
        scanner = _scanner()
        outcome = scanner.scan_paths([root])
        hits = tuple(
            hit for hit in outcome.report.hits if hit.rule_id == "email_address"
        )
        assert len(hits) == 2
        assert len({hit.location_ref for hit in hits}) == 2
        resolved = {
            scanner.resolve_location(outcome.resolution_handle, hit.location_ref)
            for hit in hits
        }
        assert resolved == {first, second}

    def test_scan_13_path_segments_run_five_content_rules(
        self,
        tmp_path: Path,
    ) -> None:
        marker = json.loads(_CANARY_DEFINITION.read_bytes())["markers"][0]
        mobile = "13800" + "138000"
        resident = "110105" + "19900101" + "123X"
        email = "segment" + "@" + "example.test"
        stable = "client_" + "a1" * 6
        root = tmp_path / "path-rules"
        current = root
        for segment in (marker, mobile, resident, email, stable):
            current = current / segment
        current.mkdir(parents=True)
        payload = current / "plain.txt"
        payload.write_bytes(b"plain")
        outcome = _scanner().scan_paths([root])
        rules = {hit.rule_id for hit in outcome.report.hits}
        assert {
            "known_canary",
            "cn_mobile_number",
            "cn_resident_id",
            "email_address",
            "stable_client_id",
        } <= rules
        assert all(hit.line_number is None for hit in outcome.report.hits)
        public = repr(outcome.report.hits)
        for segment in (marker, mobile, resident, email, stable):
            assert segment not in public

    def test_scan_14_suffix_and_nonascii_path_metadata(
        self,
        tmp_path: Path,
    ) -> None:
        root = tmp_path / "nonascii"
        root.mkdir()
        payload = root / "名字 space.db"
        payload.write_bytes(b"plain")
        outcome = _scanner().scan_paths([root])
        assert outcome.report.hit_count == 1
        hit = outcome.report.hits[0]
        assert hit.rule_id == "forbidden_path_suffix"
        assert hit.line_number is None
        assert re.fullmatch(
            r"root_[0-9]{4,}/pth1_[0-9a-f]{64}",
            hit.location_ref,
        )
        assert "名字" not in repr(hit)
        assert "space" not in repr(hit)

    def test_scan_15_invalid_relative_structure_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "invalid-relative"
        root.mkdir()
        real_scandir = os.scandir

        class FakeEntry:
            def __init__(self, name: str) -> None:
                self._name = name

            @property
            def name(self) -> str:
                return self._name

        injected_name = "CALLER_ORACLE\x01"

        def injected_scandir(path: object) -> object:
            if Path(path) == root:
                return iter((FakeEntry(injected_name),))
            return real_scandir(path)

        monkeypatch.setattr(
            privacy_scan_module,
            "_SCANDIR",
            injected_scandir,
            raising=False,
        )
        scanner = _scanner()
        valid_payload = tmp_path / "valid-before-invalid.txt"
        valid_payload.write_bytes(self._email())

        def assert_invalid_scan() -> None:
            previous = scanner.scan_paths([valid_payload])
            previous_ref = previous.report.hits[0].location_ref
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths([root])
            assert captured.value.code == "SCAN_INPUT_INVALID"
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None
            assert "CALLER_ORACLE" not in str(captured.value)
            assert os.fspath(root) not in str(captured.value)
            assert (
                object.__getattribute__(
                    scanner,
                    "_PrivacyScanner__generation",
                )
                is None
            )
            with pytest.raises(PrivacyScanError) as stale:
                scanner.resolve_location(
                    previous.resolution_handle,
                    previous_ref,
                )
            assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"

        for invalid_name in (
            "CALLER_ORACLE\x01",
            "CALLER_ORACLE\x7f",
            ".",
            "..",
            f"..{os.sep}CALLER_ORACLE_ESCAPE",
        ):
            injected_name = invalid_name
            assert_invalid_scan()

        real_fsencode = os.fsencode

        def unstable_fsencode(value: object) -> bytes:
            if value == injected_name:
                raise UnicodeError("CALLER_ORACLE_ENCODING")
            return real_fsencode(value)  # type: ignore[arg-type]

        injected_name = "CALLER_ORACLE_ENCODING"
        monkeypatch.setattr(
            privacy_scan_module.os,
            "fsencode",
            unstable_fsencode,
        )
        assert_invalid_scan()

    def test_scan_34_owner_identity_prevents_cross_root_alias(
        self,
        tmp_path: Path,
    ) -> None:
        roots = (tmp_path / "one", tmp_path / "two")
        paths: list[Path] = []
        for root in roots:
            root.mkdir()
            path = root / "same.txt"
            path.write_bytes(self._email())
            paths.append(path)
        outcome = _scanner().scan_paths(list(roots))
        hits = tuple(
            hit for hit in outcome.report.hits if hit.rule_id == "email_address"
        )
        assert len(hits) == 2
        assert hits[0].location_ref != hits[1].location_ref

    def test_scan_35_native_relative_limit_excludes_absolute_prefix(
        self,
        tmp_path: Path,
    ) -> None:
        root = tmp_path / ("long-absolute-prefix-" + "x" * 40)
        nested = root / "n"
        nested.mkdir(parents=True)
        payload = nested / "p.txt"
        payload.write_bytes(self._email())
        relative_bytes = os.fsencode(os.fspath(payload.relative_to(root)))
        assert len(os.fsencode(os.fspath(payload))) > len(relative_bytes)
        limits = replace(
            DEFAULT_SCAN_LIMITS,
            max_native_relative_bytes=len(relative_bytes),
        )
        outcome = _scanner(limits=limits).scan_paths([root])
        assert outcome.report.hit_count == 1

    def test_scan_36_depth_root_file_overlap_and_hardlink_counts(
        self,
        tmp_path: Path,
    ) -> None:
        root = tmp_path / "counts"
        nested = root / "nested"
        nested.mkdir(parents=True)
        first = nested / "first.txt"
        second = nested / "second.txt"
        first.write_bytes(self._email())
        os.link(first, second)
        limits = replace(
            DEFAULT_SCAN_LIMITS,
            max_input_paths=4,
            max_roots=3,
            max_files=2,
            max_depth=2,
        )
        scanner = _scanner(limits=limits)
        outcome = scanner.scan_paths([root, root, nested, first])
        hits = tuple(
            hit for hit in outcome.report.hits if hit.rule_id == "email_address"
        )
        assert len(hits) == 2
        assert len({hit.location_ref for hit in hits}) == 2

    def test_scan_37_total_bytes_overlap_and_hardlink_accounting(
        self,
        tmp_path: Path,
    ) -> None:
        root = tmp_path / "bytes"
        root.mkdir()
        first = root / "first.txt"
        second = root / "second.txt"
        data = self._email()
        first.write_bytes(data)
        os.link(first, second)
        exact = replace(DEFAULT_SCAN_LIMITS, max_total_bytes=len(data) * 2)
        outcome = _scanner(limits=exact).scan_paths([root, first])
        assert outcome.report.hit_count == 2
        too_small = replace(exact, max_total_bytes=len(data) * 2 - 1)
        with pytest.raises(PrivacyScanError) as captured:
            _scanner(limits=too_small).scan_paths([root, first])
        assert captured.value.code == "SCAN_LIMIT_TOTAL_BYTES"


class TestScannerDeterminismAndLimits:
    @staticmethod
    def _email(label: bytes = b"limit") -> bytes:
        return label + b"@" + b"example.test"

    @staticmethod
    def _assert_scan_code(
        scanner: PrivacyScanner,
        paths: Sequence[Path],
        expected: str,
    ) -> None:
        with pytest.raises(PrivacyScanError) as captured:
            scanner.scan_paths(paths)
        assert captured.value.code == expected
        assert captured.value.args == (expected,)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    def test_scan_18_fixed_snapshot_report_equality(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        roots = (tmp_path / "a", tmp_path / "b")
        for ordinal, root in enumerate(roots):
            root.mkdir()
            (root / f"{ordinal}.txt").write_bytes(self._email(str(ordinal).encode()))
        scanner = _scanner()
        first = scanner.scan_paths([roots[1], roots[0]])

        real_scandir = privacy_scan_module._SCANDIR

        class ReversedScandir:
            def __init__(self, path: object) -> None:
                self._entries = list(real_scandir(path))

            def __iter__(self) -> object:
                return iter(reversed(self._entries))

            def close(self) -> None:
                return None

        monkeypatch.setattr(privacy_scan_module, "_SCANDIR", ReversedScandir)
        second = scanner.scan_paths([roots[0], roots[1]])
        assert first.report == second.report
        assert first.report.hits == second.report.hits
        assert first.resolution_handle is not second.resolution_handle

    def test_scan_19_default_keys_are_instance_local(self, tmp_path: Path) -> None:
        path = tmp_path / "key.txt"
        path.write_bytes(self._email())
        first = _scanner(hash_key=None).scan_paths([path])
        second = _scanner(hash_key=None).scan_paths([path])
        assert first.report.hit_count == second.report.hit_count == 1
        assert first.report.hits[0].location_ref != second.report.hits[0].location_ref
        assert first.report.hits[0].hit_hash != second.report.hits[0].hit_hash

    def test_scan_27_defaults_and_hard_maxima_reflection(self) -> None:
        assert tuple(
            getattr(DEFAULT_SCAN_LIMITS, field_name)
            for field_name in _LIMIT_FIELDS
        ) == _DEFAULT_LIMIT_VALUES
        hard = ScanLimits(**dict(zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES)))
        assert isinstance(_scanner(limits=hard), PrivacyScanner)
        assert SCAN_CHUNK_BYTES == 65_536
        assert SCAN_CARRY_BYTES == 512
        assert privacy_scan_module._MAX_STREAM_TOKEN_BYTES == 254
        assert privacy_scan_module._MIN_STREAM_CARRY_BYTES == 510
        assert SCAN_CARRY_BYTES >= privacy_scan_module._MIN_STREAM_CARRY_BYTES
        canonical = privacy_scan_module._limits_canonical_bytes(DEFAULT_SCAN_LIMITS)
        assert canonical.count(b";") == 13
        for field_name in (
            b"inputs=",
            b"roots=",
            b"tree_entries=",
            b"files=",
            b"depth=",
            b"native=",
            b"file=",
            b"total=",
            b"hits=",
            b"catalog=",
            b"markers=",
            b"marker_bytes=",
            b"chunk=65536",
            b"carry=512",
        ):
            assert field_name in canonical

    def test_scan_28_all_runtime_limits_equal_and_plus_one(
        self,
        tmp_path: Path,
    ) -> None:
        self._assert_all_runtime_limits_equal_and_plus_one(tmp_path)

    def _assert_all_runtime_limits_equal_and_plus_one(
        self,
        tmp_path: Path,
    ) -> None:
        input_file = tmp_path / "input.txt"
        input_file.write_bytes(b"plain")
        input_limits = replace(DEFAULT_SCAN_LIMITS, max_input_paths=1)
        assert _scanner(limits=input_limits).scan_paths([input_file]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=input_limits),
            [input_file, input_file],
            "SCAN_LIMIT_INPUT_PATHS",
        )

        roots = (tmp_path / "root-a.txt", tmp_path / "root-b.txt")
        for root in roots:
            root.write_bytes(b"plain")
        roots_equal = replace(DEFAULT_SCAN_LIMITS, max_roots=2)
        assert _scanner(limits=roots_equal).scan_paths(list(roots)).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=replace(roots_equal, max_roots=1)),
            list(roots),
            "SCAN_LIMIT_ROOTS",
        )

        class RootLimitSequence(Sequence[Path]):
            def __init__(self, values: tuple[Path, ...]) -> None:
                self.values = values
                self.fetches: list[int] = []
                self.len_calls = 0

            def __len__(self) -> int:
                self.len_calls += 1
                raise AssertionError("ROOT_LIMIT_LEN_ORACLE")

            def __getitem__(self, index: int) -> Path:
                self.fetches.append(index)
                if index >= len(self.values):
                    raise AssertionError("ROOT_LIMIT_SENTINEL_FETCHED")
                return self.values[index]

        unique_plus_one = RootLimitSequence(roots)
        self._assert_scan_code(
            _scanner(
                limits=replace(
                    DEFAULT_SCAN_LIMITS,
                    max_input_paths=3,
                    max_roots=1,
                )
            ),
            unique_plus_one,
            "SCAN_LIMIT_ROOTS",
        )
        assert unique_plus_one.fetches == [0, 1]
        assert unique_plus_one.len_calls == 0

        duplicate_then_plus_one = RootLimitSequence(
            (roots[0], roots[0], roots[1])
        )
        self._assert_scan_code(
            _scanner(
                limits=replace(
                    DEFAULT_SCAN_LIMITS,
                    max_input_paths=4,
                    max_roots=1,
                )
            ),
            duplicate_then_plus_one,
            "SCAN_LIMIT_ROOTS",
        )
        assert duplicate_then_plus_one.fetches == [0, 1, 2]
        assert duplicate_then_plus_one.len_calls == 0

        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "only.txt").write_bytes(b"plain")
        tree_equal = replace(DEFAULT_SCAN_LIMITS, max_tree_entries=2)
        assert _scanner(limits=tree_equal).scan_paths([tree]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=replace(tree_equal, max_tree_entries=1)),
            [tree],
            "SCAN_LIMIT_TREE_ENTRIES",
        )

        files = tmp_path / "files"
        files.mkdir()
        for name in ("one.txt", "two.txt"):
            (files / name).write_bytes(b"plain")
        files_equal = replace(DEFAULT_SCAN_LIMITS, max_files=2)
        assert _scanner(limits=files_equal).scan_paths([files]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=replace(files_equal, max_files=1)),
            [files],
            "SCAN_LIMIT_FILES",
        )

        depth = tmp_path / "depth"
        depth.mkdir()
        (depth / "direct.txt").write_bytes(b"plain")
        depth_equal = replace(DEFAULT_SCAN_LIMITS, max_depth=1)
        assert _scanner(limits=depth_equal).scan_paths([depth]).report.hit_count == 0
        deep = tmp_path / "deep"
        (deep / "nested").mkdir(parents=True)
        (deep / "nested" / "too-deep.txt").write_bytes(b"plain")
        self._assert_scan_code(
            _scanner(limits=depth_equal),
            [deep],
            "SCAN_LIMIT_DEPTH",
        )

        native = tmp_path / "native-name.txt"
        native.write_bytes(b"plain")
        native_size = len(os.fsencode(native.name))
        native_equal = replace(
            DEFAULT_SCAN_LIMITS,
            max_native_relative_bytes=native_size,
        )
        assert _scanner(limits=native_equal).scan_paths([native]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(
                limits=replace(
                    native_equal,
                    max_native_relative_bytes=native_size - 1,
                )
            ),
            [native],
            "SCAN_LIMIT_NATIVE_RELATIVE_BYTES",
        )

        file_data = b"abcd"
        sized = tmp_path / "sized.txt"
        sized.write_bytes(file_data)
        file_equal = replace(DEFAULT_SCAN_LIMITS, max_file_bytes=len(file_data))
        assert _scanner(limits=file_equal).scan_paths([sized]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=replace(file_equal, max_file_bytes=len(file_data) - 1)),
            [sized],
            "SCAN_LIMIT_FILE_BYTES",
        )

        total_root = tmp_path / "total"
        total_root.mkdir()
        (total_root / "a.txt").write_bytes(b"abc")
        (total_root / "b.txt").write_bytes(b"defg")
        total_equal = replace(DEFAULT_SCAN_LIMITS, max_total_bytes=7)
        assert _scanner(limits=total_equal).scan_paths([total_root]).report.hit_count == 0
        self._assert_scan_code(
            _scanner(limits=replace(total_equal, max_total_bytes=6)),
            [total_root],
            "SCAN_LIMIT_TOTAL_BYTES",
        )

        hit_path = tmp_path / "hits.txt"
        occurrence = self._email()
        hit_path.write_bytes(occurrence + b" " + occurrence)
        hits_equal = replace(DEFAULT_SCAN_LIMITS, max_hits=2)
        assert _scanner(limits=hits_equal).scan_paths([hit_path]).report.hit_count == 2
        self._assert_scan_code(
            _scanner(limits=replace(hits_equal, max_hits=1)),
            [hit_path],
            "SCAN_LIMIT_HITS",
        )

        marker_a = "MARKER-A"
        marker_b = "MARKER-B"
        catalog_raw = _catalog_bytes((marker_a,))
        catalog = _write_catalog(tmp_path / "catalog-exact.json", catalog_raw)
        catalog_equal = replace(
            DEFAULT_SCAN_LIMITS,
            max_catalog_bytes=len(catalog_raw),
            max_markers=1,
            max_marker_bytes=len(marker_a),
        )
        assert isinstance(
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=catalog,
                hash_key=bytes(range(32)),
                limits=catalog_equal,
            ),
            PrivacyScanner,
        )
        for limits, expected, name, raw in (
            (
                replace(catalog_equal, max_catalog_bytes=len(catalog_raw) - 1),
                "SCAN_LIMIT_CATALOG_BYTES",
                "catalog-too-large.json",
                catalog_raw,
            ),
            (
                replace(
                    catalog_equal,
                    max_catalog_bytes=DEFAULT_SCAN_LIMITS.max_catalog_bytes,
                ),
                "SCAN_LIMIT_MARKERS",
                "markers-too-many.json",
                _catalog_bytes((marker_a, marker_b)),
            ),
            (
                replace(
                    catalog_equal,
                    max_catalog_bytes=DEFAULT_SCAN_LIMITS.max_catalog_bytes,
                    max_marker_bytes=len(marker_a) - 1,
                ),
                "SCAN_LIMIT_MARKER_BYTES",
                "marker-too-long.json",
                catalog_raw,
            ),
        ):
            path = _write_catalog(tmp_path / name, raw)
            with pytest.raises(PrivacyScanError) as captured:
                PrivacyScanner.default(
                    profile="repo_tracked",
                    canary_definition_path=path,
                    hash_key=bytes(range(32)),
                    limits=limits,
                )
            assert captured.value.code == expected

    def test_scan_29_invalid_limit_configuration_is_constructor_error(self) -> None:
        hard = ScanLimits(**dict(zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES)))
        for field_name, hard_value in zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES):
            for invalid in (True, 0, -1, hard_value + 1):
                with pytest.raises(PrivacyScanError) as captured:
                    _scanner(limits=replace(hard, **{field_name: invalid}))
                assert captured.value.code == "SCAN_LIMIT_CONFIGURATION_INVALID"


class TestScannerResolverLifecycle:
    @staticmethod
    def _payload() -> bytes:
        return b"resolver" + b"@" + b"example.test"

    @staticmethod
    def _scanned(tmp_path: Path) -> tuple[PrivacyScanner, Path, PrivacyScanOutcome]:
        path = tmp_path / "payload.txt"
        path.write_bytes(TestScannerResolverLifecycle._payload())
        scanner = _scanner()
        return scanner, path, scanner.scan_paths([path])

    def test_scan_30_current_handle_only_and_scan_start_invalidation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner, path, first = self._scanned(tmp_path)
        ref = first.report.hits[0].location_ref
        assert scanner.resolve_location(first.resolution_handle, ref) == path

        real_check = privacy_scan_module._scan_catalog_check
        entered = threading.Event()
        release = threading.Event()
        worker_errors: list[PrivacyScanError] = []

        def blocking_check(binding: object, limits: ScanLimits) -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("CATALOG_RELEASE_TIMEOUT")
            real_check(binding, limits)

        def failing_scan() -> None:
            try:
                scanner.scan_paths([tmp_path / "MISSING_ORACLE"])
            except PrivacyScanError as error:
                worker_errors.append(error)

        monkeypatch.setattr(
            privacy_scan_module,
            "_scan_catalog_check",
            blocking_check,
        )
        worker = threading.Thread(target=failing_scan)
        worker.start()
        assert entered.wait(timeout=5)
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        with pytest.raises(PrivacyScanError) as contended:
            scanner.resolve_location(first.resolution_handle, ref)
        assert contended.value.code == "SCAN_CONCURRENT_USE"
        release.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert [error.code for error in worker_errors] == ["SCAN_PATH_NOT_FOUND"]
        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(first.resolution_handle, ref)
        assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"

        monkeypatch.setattr(privacy_scan_module, "_scan_catalog_check", real_check)
        second = scanner.scan_paths([path])
        scanner.close()
        with pytest.raises(PrivacyScanError) as closed:
            scanner.resolve_location(
                second.resolution_handle,
                second.report.hits[0].location_ref,
            )
        assert closed.value.code == "SCAN_LOCATION_UNAVAILABLE"

    def test_scan_31_runtime_redaction_and_serialization_surface(
        self,
        tmp_path: Path,
    ) -> None:
        scanner, path, outcome = self._scanned(tmp_path)
        hit = outcome.report.hits[0]
        public = " ".join(
            (
                repr(scanner),
                repr(outcome),
                repr(outcome.resolution_handle),
                repr(outcome.report),
                repr(hit),
            )
        )
        assert os.fspath(path) not in public
        assert path.name not in public
        assert self._payload().decode("ascii") not in public
        assert not hasattr(scanner, "generation")
        assert not hasattr(scanner, "mapping")
        assert not hasattr(outcome.report, "path")
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert set(generation.mapping) == {hit.location_ref}
        assert os.fspath(path) not in repr(generation)

        for value in (scanner, outcome, outcome.resolution_handle):
            for operation in (
                lambda value=value: copy.copy(value),
                lambda value=value: copy.deepcopy(value),
                lambda value=value: pickle.dumps(value),
            ):
                with pytest.raises(TypeError) as captured:
                    operation()
                assert captured.value.args == ("SCAN_SERIALIZATION_FORBIDDEN",)

        forged = object.__new__(ScanResolutionHandle)
        with pytest.raises(PrivacyScanError) as unavailable:
            scanner.resolve_location(forged, hit.location_ref)
        assert unavailable.value.code == "SCAN_LOCATION_UNAVAILABLE"
        assert unavailable.value.__cause__ is None
        assert unavailable.value.__context__ is None
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ).handle is outcome.resolution_handle

        incomplete = object.__new__(PrivacyScanner)
        operations = (
            (lambda: PrivacyScanner.scan_paths(incomplete, []), "SCAN_INPUT_INVALID"),
            (
                lambda: PrivacyScanner.resolve_location(
                    incomplete,
                    forged,
                    hit.location_ref,
                ),
                "SCAN_LOCATION_UNAVAILABLE",
            ),
            (lambda: PrivacyScanner.close(incomplete), "SCAN_INPUT_INVALID"),
        )
        for operation, expected in operations:
            with pytest.raises(PrivacyScanError) as captured:
                operation()
            assert captured.value.code == expected
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None

    def test_scan_32_repeated_scans_equal_reports_distinct_handles(
        self,
        tmp_path: Path,
    ) -> None:
        scanner, path, first = self._scanned(tmp_path)
        second = scanner.scan_paths([path])
        assert first.report == second.report
        assert first.resolution_handle is not second.resolution_handle
        ref = second.report.hits[0].location_ref
        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(first.resolution_handle, ref)
        assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"
        assert scanner.resolve_location(second.resolution_handle, ref) == path

    def test_scan_33_cross_instance_handle_is_unavailable(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "shared.txt"
        path.write_bytes(self._payload())
        first_scanner = _scanner()
        second_scanner = _scanner()
        first = first_scanner.scan_paths([path])
        second = second_scanner.scan_paths([path])
        assert first.report == second.report
        ref = first.report.hits[0].location_ref
        assert first_scanner.resolve_location(first.resolution_handle, ref) == path
        assert second_scanner.resolve_location(second.resolution_handle, ref) == path
        with pytest.raises(PrivacyScanError) as crossed:
            second_scanner.resolve_location(first.resolution_handle, ref)
        assert crossed.value.code == "SCAN_LOCATION_UNAVAILABLE"

    def test_scan_38_shared_nonblocking_nonreentrant_lock(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner, path, current = self._scanned(tmp_path)
        current_ref = current.report.hits[0].location_ref
        lock = object.__getattribute__(scanner, "_PrivacyScanner__operation_lock")
        assert type(lock) is type(threading.Lock())

        real_check = privacy_scan_module._scan_catalog_check
        entered = threading.Event()
        release = threading.Event()
        worker_outcomes: list[PrivacyScanOutcome] = []

        def blocking_check(binding: object, limits: ScanLimits) -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("CATALOG_RELEASE_TIMEOUT")
            real_check(binding, limits)

        def run_scan() -> None:
            worker_outcomes.append(scanner.scan_paths([path]))

        monkeypatch.setattr(
            privacy_scan_module,
            "_scan_catalog_check",
            blocking_check,
        )
        worker = threading.Thread(target=run_scan)
        worker.start()
        assert entered.wait(timeout=5)
        losing_codes: list[str] = []
        for operation in (
            lambda: scanner.scan_paths([path]),
            lambda: scanner.resolve_location(current.resolution_handle, current_ref),
            scanner.close,
        ):
            with pytest.raises(PrivacyScanError) as captured:
                operation()
            losing_codes.append(captured.value.code)
        assert losing_codes == ["SCAN_CONCURRENT_USE"] * 3
        release.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(worker_outcomes) == 1

        reentry_codes: list[str] = []

        def reentrant_check(binding: object, limits: ScanLimits) -> None:
            for operation in (
                lambda: scanner.scan_paths([path]),
                lambda: scanner.resolve_location(
                    worker_outcomes[0].resolution_handle,
                    worker_outcomes[0].report.hits[0].location_ref,
                ),
                scanner.close,
            ):
                with pytest.raises(PrivacyScanError) as captured:
                    operation()
                reentry_codes.append(captured.value.code)
            real_check(binding, limits)

        monkeypatch.setattr(
            privacy_scan_module,
            "_scan_catalog_check",
            reentrant_check,
        )
        completed = scanner.scan_paths([path])
        assert completed.report.hit_count == 1
        assert reentry_codes == ["SCAN_CONCURRENT_USE"] * 6

    def test_scan_39_success_failure_commit_atomicity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scanner, path, first = self._scanned(tmp_path)
        ref = first.report.hits[0].location_ref
        real_outcome = privacy_scan_module.PrivacyScanOutcome

        def raising_outcome(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise RuntimeError("OUTCOME_ORACLE")

        monkeypatch.setattr(
            privacy_scan_module,
            "PrivacyScanOutcome",
            raising_outcome,
        )
        with pytest.raises(PrivacyScanError) as failed_commit:
            scanner.scan_paths([path])
        assert failed_commit.value.code == "SCAN_INPUT_INVALID"
        assert "OUTCOME_ORACLE" not in str(failed_commit.value)
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(first.resolution_handle, ref)
        assert stale.value.code == "SCAN_LOCATION_UNAVAILABLE"

        monkeypatch.setattr(
            privacy_scan_module,
            "PrivacyScanOutcome",
            real_outcome,
        )
        recovered = scanner.scan_paths([path])
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert generation.handle is recovered.resolution_handle
        assert generation.mapping[
            recovered.report.hits[0].location_ref
        ] == path


class TestScannerCatalogContract:
    def test_scan_02_strict_catalog_schema_tokens_and_identity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical_raw = _CANARY_DEFINITION.read_bytes()
        canonical_document = json.loads(canonical_raw)
        canonical_markers = tuple(
            marker.encode("ascii") for marker in canonical_document["markers"]
        )
        canonical_status = _CANARY_DEFINITION.stat()

        scanner = _scanner()
        binding = scanner._PrivacyScanner__catalog_binding
        assert binding.canonical_path == _CANARY_DEFINITION
        assert binding.identity == (
            canonical_status.st_mode,
            canonical_status.st_dev,
            canonical_status.st_ino,
            canonical_status.st_nlink,
            canonical_status.st_size,
            canonical_status.st_mtime_ns,
            canonical_status.st_ctime_ns,
            int(getattr(canonical_status, "st_file_attributes", 0)),
        )
        assert binding.raw_sha256 == hashlib.sha256(canonical_raw).hexdigest()
        assert binding.markers == canonical_markers
        assert len(binding.marker_spans) == len(canonical_markers)
        for marker, (start, end) in zip(
            binding.markers,
            binding.marker_spans,
        ):
            assert canonical_raw[start:end] == marker
            assert canonical_raw[start - 1 : start] == b'"'
            assert canonical_raw[end : end + 1] == b'"'
            assert b"\\" not in canonical_raw[start:end]

        concrete_path_type = type(Path())
        monkeypatch.chdir(tmp_path)
        subtype_catalog = _write_catalog(
            tmp_path / "subtype-catalog.json",
            canonical_raw,
        )
        relative_fspath_calls: list[str] = []
        relative_virtual_calls: list[str] = []

        class RelativeCatalogPretendingAbsolute(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                frozen = super().__fspath__()
                relative_fspath_calls.append(frozen)
                return frozen

            def is_absolute(self) -> bool:
                relative_virtual_calls.append("is_absolute")
                return True

            def resolve(self, *args: object, **kwargs: object) -> Path:
                del args, kwargs
                relative_virtual_calls.append("resolve")
                raise AssertionError("CATALOG_VIRTUAL_PATH")

        relative_catalog = RelativeCatalogPretendingAbsolute(
            subtype_catalog.name
        )
        catalog_boundary_calls: list[str] = []
        real_lstat_for_subtype = privacy_scan_module._LSTAT
        real_realpath_for_subtype = privacy_scan_module._REALPATH

        def subtype_catalog_lstat(path: object) -> object:
            catalog_boundary_calls.append("lstat")
            return real_lstat_for_subtype(path)

        def subtype_catalog_realpath(path: str) -> str:
            catalog_boundary_calls.append("realpath")
            return real_realpath_for_subtype(path)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_LSTAT",
                subtype_catalog_lstat,
            )
            patch.setattr(
                privacy_scan_module,
                "_REALPATH",
                subtype_catalog_realpath,
            )
            with pytest.raises(PrivacyScanError) as relative_error:
                PrivacyScanner.default(
                    profile="repo_tracked",
                    canary_definition_path=relative_catalog,
                    hash_key=bytes(range(32)),
                )
        assert relative_error.value.code == "SCAN_CANARY_CATALOG_INVALID"
        assert relative_fspath_calls == [subtype_catalog.name]
        assert relative_virtual_calls == []
        assert catalog_boundary_calls == []

        absolute_fspath_calls: list[str] = []
        absolute_virtual_calls: list[str] = []

        class AbsoluteCatalogSubtype(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                frozen = super().__fspath__()
                absolute_fspath_calls.append(frozen)
                return frozen

            def is_absolute(self) -> bool:
                absolute_virtual_calls.append("is_absolute")
                raise AssertionError("CATALOG_VIRTUAL_PATH")

            def resolve(self, *args: object, **kwargs: object) -> Path:
                del args, kwargs
                absolute_virtual_calls.append("resolve")
                raise AssertionError("CATALOG_VIRTUAL_PATH")

        absolute_catalog = AbsoluteCatalogSubtype(os.fspath(subtype_catalog))
        absolute_scanner = PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=absolute_catalog,
            hash_key=bytes(range(32)),
        )
        assert isinstance(absolute_scanner, PrivacyScanner)
        assert absolute_fspath_calls == [os.fspath(subtype_catalog)]
        assert absolute_virtual_calls == []

        class NonExactCatalogText(str):
            pass

        nonexact_catalog_calls = 0

        class NonExactCatalogPath(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                nonlocal nonexact_catalog_calls
                nonexact_catalog_calls += 1
                return NonExactCatalogText(os.fspath(subtype_catalog))

        with pytest.raises(PrivacyScanError) as nonexact_catalog_error:
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=NonExactCatalogPath("unused"),
                hash_key=bytes(range(32)),
            )
        assert nonexact_catalog_error.value.code == "SCAN_CANARY_CATALOG_INVALID"
        assert nonexact_catalog_error.value.__cause__ is None
        assert nonexact_catalog_error.value.__context__ is None
        assert nonexact_catalog_calls == 1

        raising_catalog_calls = 0

        class RaisingCatalogPath(  # type: ignore[misc,valid-type]
            concrete_path_type
        ):
            def __fspath__(self) -> str:
                nonlocal raising_catalog_calls
                raising_catalog_calls += 1
                raise RuntimeError("CATALOG_ORACLE_FSPATH")

        with pytest.raises(PrivacyScanError) as raising_catalog_error:
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=RaisingCatalogPath("unused"),
                hash_key=bytes(range(32)),
            )
        assert raising_catalog_error.value.code == "SCAN_CANARY_CATALOG_INVALID"
        assert raising_catalog_error.value.__cause__ is None
        assert raising_catalog_error.value.__context__ is None
        assert raising_catalog_calls == 1

        lexical_path = (
            _CANARY_DEFINITION.parent
            / ".."
            / "consultation_kb"
            / "canaries.json"
        )
        lexical_scanner = PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=lexical_path,
            hash_key=bytes(range(32)),
        )
        lexical_binding = lexical_scanner._PrivacyScanner__catalog_binding
        assert lexical_binding.canonical_path == _CANARY_DEFINITION
        assert lexical_binding.identity == binding.identity
        assert lexical_binding.raw_sha256 == binding.raw_sha256

        marker_a = "-".join(("SYNTH", "MARKER", "ALPHA", "9F3A"))
        marker_b = "-".join(("SYNTH", "MARKER", "BETA", "71D2"))
        markers = (marker_a, marker_b)
        valid_raw = _catalog_bytes(markers)
        valid_path = _write_catalog(tmp_path / "valid.json", valid_raw)
        exact_limits = replace(
            DEFAULT_SCAN_LIMITS,
            max_catalog_bytes=len(valid_raw),
            max_markers=len(markers),
            max_marker_bytes=max(len(marker.encode("ascii")) for marker in markers),
        )
        exact_scanner = PrivacyScanner.default(
            profile="shared_derivative",
            canary_definition_path=valid_path,
            hash_key=bytes(range(32)),
            limits=exact_limits,
        )
        exact_binding = exact_scanner._PrivacyScanner__catalog_binding
        assert exact_binding.markers == tuple(
            marker.encode("ascii") for marker in markers
        )
        assert tuple(
            valid_raw[start:end]
            for start, end in exact_binding.marker_spans
        ) == exact_binding.markers

        def assert_catalog_error(
            path: Path,
            code: str,
            *,
            limits: ScanLimits = DEFAULT_SCAN_LIMITS,
        ) -> None:
            with pytest.raises(PrivacyScanError) as captured:
                PrivacyScanner.default(
                    profile="repo_tracked",
                    canary_definition_path=path,
                    hash_key=bytes(range(32)),
                    limits=limits,
                )
            assert captured.value.code == code
            assert captured.value.location_ref is None
            assert captured.value.args == (code,)
            assert str(captured.value) == code
            assert repr(captured.value) == "<PrivacyScanError redacted>"
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None
            assert os.fspath(path) not in str(captured.value)
            assert os.fspath(path) not in repr(captured.value)

        def changed_status(status: object, **changes: int) -> SimpleNamespace:
            values = {
                "st_mode": status.st_mode,
                "st_dev": status.st_dev,
                "st_ino": status.st_ino,
                "st_nlink": status.st_nlink,
                "st_size": status.st_size,
                "st_mtime_ns": status.st_mtime_ns,
                "st_ctime_ns": status.st_ctime_ns,
                "st_file_attributes": int(
                    getattr(status, "st_file_attributes", 0)
                ),
            }
            values.update(changes)
            return SimpleNamespace(**values)

        original_platform = privacy_scan_module._PLATFORM_NAME
        original_open = privacy_scan_module._OPEN
        original_nofollow = privacy_scan_module._O_NOFOLLOW
        original_nonblock = privacy_scan_module._O_NONBLOCK
        original_native_is_absolute = privacy_scan_module._native_is_absolute

        injected_nofollow = 1 << 24
        injected_nonblock = 1 << 25
        posix_open_calls: list[tuple[object, int]] = []

        def injected_posix_open(path: object, flags: int) -> int:
            posix_open_calls.append((path, flags))
            return os.open(
                path,
                os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
            )

        monkeypatch.setattr(privacy_scan_module, "_PLATFORM_NAME", "posix")
        monkeypatch.setattr(
            privacy_scan_module,
            "_native_is_absolute",
            lambda path_text: os.path.isabs(path_text),
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_O_NOFOLLOW",
            injected_nofollow,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_O_NONBLOCK",
            injected_nonblock,
        )
        monkeypatch.setattr(privacy_scan_module, "_OPEN", injected_posix_open)
        PrivacyScanner.default(
            profile="repo_tracked",
            canary_definition_path=valid_path,
            hash_key=bytes(range(32)),
        )
        assert len(posix_open_calls) == 1
        assert posix_open_calls[0][1] & injected_nofollow
        assert posix_open_calls[0][1] & injected_nonblock

        missing_primitive_opens: list[object] = []

        def should_not_open(path: object, flags: int) -> int:
            del flags
            missing_primitive_opens.append(path)
            raise AssertionError

        monkeypatch.setattr(privacy_scan_module, "_O_NOFOLLOW", None)
        monkeypatch.setattr(privacy_scan_module, "_OPEN", should_not_open)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        assert missing_primitive_opens == []

        monkeypatch.setattr(
            privacy_scan_module,
            "_PLATFORM_NAME",
            original_platform,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_O_NOFOLLOW",
            original_nofollow,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_O_NONBLOCK",
            original_nonblock,
        )
        monkeypatch.setattr(
            privacy_scan_module,
            "_native_is_absolute",
            original_native_is_absolute,
        )
        monkeypatch.setattr(privacy_scan_module, "_OPEN", original_open)

        if original_platform == "nt":
            real_create_file = privacy_scan_module._WINDOWS_CREATE_FILE
            assert real_create_file is not None
            windows_open_calls: list[tuple[int, int, int]] = []

            def recording_create_file(
                path: str,
                access: int,
                share: int,
                security: int,
                creation: int,
                flags: int,
                template: int,
            ) -> int:
                windows_open_calls.append((access, creation, flags))
                return real_create_file(
                    path,
                    access,
                    share,
                    security,
                    creation,
                    flags,
                    template,
                )

            monkeypatch.setattr(
                privacy_scan_module,
                "_WINDOWS_CREATE_FILE",
                recording_create_file,
            )
            PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=valid_path,
                hash_key=bytes(range(32)),
            )
            assert len(windows_open_calls) == 1
            access, creation, flags = windows_open_calls[0]
            assert access == privacy_scan_module._WINDOWS_GENERIC_READ
            assert creation == privacy_scan_module._WINDOWS_OPEN_EXISTING
            assert flags & privacy_scan_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT

            monkeypatch.setattr(
                privacy_scan_module,
                "_WINDOWS_CREATE_FILE",
                None,
            )
            assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
            monkeypatch.setattr(
                privacy_scan_module,
                "_WINDOWS_CREATE_FILE",
                real_create_file,
            )

        real_fstat = privacy_scan_module._FSTAT

        def mismatched_fstat(descriptor: int) -> object:
            status = real_fstat(descriptor)
            return changed_status(status, st_ino=status.st_ino + 1)

        monkeypatch.setattr(privacy_scan_module, "_FSTAT", mismatched_fstat)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        monkeypatch.setattr(privacy_scan_module, "_FSTAT", real_fstat)

        fstat_count = 0

        def drifting_fstat(descriptor: int) -> object:
            nonlocal fstat_count
            fstat_count += 1
            status = real_fstat(descriptor)
            if fstat_count > 1:
                return changed_status(
                    status,
                    st_mtime_ns=status.st_mtime_ns + 1,
                )
            return status

        monkeypatch.setattr(privacy_scan_module, "_FSTAT", drifting_fstat)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        assert fstat_count >= 2
        monkeypatch.setattr(privacy_scan_module, "_FSTAT", real_fstat)

        real_lstat_for_drift = privacy_scan_module._LSTAT
        lstat_count = 0

        def drifting_lstat(path: object) -> object:
            nonlocal lstat_count
            lstat_count += 1
            status = real_lstat_for_drift(path)
            if lstat_count > 2:
                return changed_status(
                    status,
                    st_ctime_ns=status.st_ctime_ns + 1,
                )
            return status

        monkeypatch.setattr(privacy_scan_module, "_LSTAT", drifting_lstat)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        assert lstat_count >= 3
        monkeypatch.setattr(
            privacy_scan_module,
            "_LSTAT",
            real_lstat_for_drift,
        )

        assert_catalog_error(
            valid_path,
            "SCAN_LIMIT_CATALOG_BYTES",
            limits=replace(
                exact_limits,
                max_catalog_bytes=len(valid_raw) - 1,
            ),
        )
        assert_catalog_error(
            valid_path,
            "SCAN_LIMIT_MARKERS",
            limits=replace(exact_limits, max_markers=len(markers) - 1),
        )
        assert_catalog_error(
            valid_path,
            "SCAN_LIMIT_MARKER_BYTES",
            limits=replace(
                exact_limits,
                max_marker_bytes=max(
                    len(marker.encode("ascii")) for marker in markers
                )
                - 1,
            ),
        )

        escaped_marker = (
            b"\\u"
            + f"{ord(marker_a[0]):04x}".encode("ascii")
            + marker_a[1:].encode("ascii")
        )
        escaped_raw = valid_raw.replace(
            marker_a.encode("ascii"),
            escaped_marker,
            1,
        )
        duplicate_key_raw = valid_raw.replace(
            b'  "rule_id": "known_canary",\n',
            (
                b'  "rule_id": "known_canary",\n'
                b'  "rule_id": "known_canary",\n'
            ),
            1,
        )
        invalid_catalogs = (
            duplicate_key_raw,
            escaped_raw,
            _catalog_bytes((),),
            _catalog_bytes((marker_a, marker_a)),
            _catalog_bytes((marker_a, marker_a + "-TAIL")),
            _catalog_bytes(("",)),
            _catalog_bytes(("".join(("NONASCII-", chr(0x00E9))),)),
            _catalog_bytes((marker_a,), schema_version="2.0"),
            _catalog_bytes((marker_a,), synthetic_only=1),
            _catalog_bytes((marker_a,), rule_id="other_rule"),
            _catalog_bytes(marker_a),
            _catalog_bytes((marker_a,), key_order=(
                "synthetic_only",
                "schema_version",
                "rule_id",
                "markers",
            )),
            _catalog_bytes((marker_a,), extra_pairs=(("unknown", 1),)),
            b"\xef\xbb\xbf" + _catalog_bytes((marker_a,)),
            _catalog_bytes((marker_a,)) + b"\x00",
            b"{\xff}\n",
        )
        for index, invalid_raw in enumerate(invalid_catalogs):
            invalid_path = _write_catalog(
                tmp_path / f"invalid-{index}.json",
                invalid_raw,
            )
            assert_catalog_error(
                invalid_path,
                "SCAN_CANARY_CATALOG_INVALID",
            )

        relative_path = Path("relative-canaries.json")
        assert_catalog_error(relative_path, "SCAN_CANARY_CATALOG_INVALID")
        missing_path = tmp_path / "missing.json"
        assert_catalog_error(missing_path, "SCAN_CANARY_CATALOG_INVALID")
        directory_path = tmp_path / "catalog-directory"
        directory_path.mkdir()
        assert_catalog_error(directory_path, "SCAN_CANARY_CATALOG_INVALID")

        real_lstat = privacy_scan_module._LSTAT
        real_status = real_lstat(valid_path)
        reparse_status = SimpleNamespace(
            st_mode=real_status.st_mode,
            st_dev=real_status.st_dev,
            st_ino=real_status.st_ino,
            st_nlink=real_status.st_nlink,
            st_size=real_status.st_size,
            st_mtime_ns=real_status.st_mtime_ns,
            st_ctime_ns=real_status.st_ctime_ns,
            st_file_attributes=int(
                getattr(real_status, "st_file_attributes", 0)
            )
            | privacy_scan_module._REPARSE_ATTRIBUTE,
        )

        def injected_reparse(path: object) -> object:
            if Path(path) == valid_path:
                return reparse_status
            return real_lstat(path)

        monkeypatch.setattr(privacy_scan_module, "_LSTAT", injected_reparse)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        monkeypatch.setattr(privacy_scan_module, "_LSTAT", real_lstat)

        hardlink_path = tmp_path / "hardlink.json"
        os.link(valid_path, hardlink_path)
        assert_catalog_error(valid_path, "SCAN_CANARY_CATALOG_INVALID")
        assert_catalog_error(hardlink_path, "SCAN_CANARY_CATALOG_INVALID")


def _assert_slice7_safe_error(
    error: BaseException,
    expected_code: str,
    *,
    sensitive: Sequence[object] = (),
) -> None:
    if isinstance(error, PrivacyScanError):
        assert type(error) is PrivacyScanError
        assert error.code == expected_code
        assert repr(error) == "<PrivacyScanError redacted>"
    assert error.args == (expected_code,)
    assert str(error) == expected_code
    assert error.__cause__ is None
    assert error.__context__ is None
    surfaces = (str(error), repr(error), repr(error.args))
    for value in sensitive:
        candidates = {str(value), repr(value)}
        if isinstance(value, (str, bytes, os.PathLike)):
            try:
                candidates.add(os.fsdecode(value))
            except Exception:
                pass
        for candidate in candidates:
            if candidate and candidate != expected_code:
                assert all(candidate not in surface for surface in surfaces)


class TestScannerCatalogRaceAdversarial:
    def test_scan_03_catalog_identity_and_content_drift(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        marker = "CATALOG-RACE-MARKER-ALPHA"
        catalog_raw = _catalog_bytes((marker,))
        catalog = _write_catalog(tmp_path / "catalog-race.json", catalog_raw)

        def new_scanner() -> PrivacyScanner:
            return PrivacyScanner.default(
                profile="repo_tracked",
                canary_definition_path=catalog,
                hash_key=bytes(range(32)),
            )

        actual_drift_scanner = new_scanner()
        actual_drift_scanner.scan_paths([])
        replacement_raw = catalog_raw.replace(b"ALPHA", b"OMEGA", 1)
        assert len(replacement_raw) == len(catalog_raw)
        catalog.write_bytes(replacement_raw)
        with pytest.raises(PrivacyScanError) as actual_drift:
            actual_drift_scanner.scan_paths([])
        _assert_slice7_safe_error(
            actual_drift.value,
            "SCAN_CATALOG_CHANGED",
            sensitive=(catalog, marker, replacement_raw),
        )
        assert object.__getattribute__(
            actual_drift_scanner,
            "_PrivacyScanner__generation",
        ) is None
        catalog.write_bytes(catalog_raw)

        real_read_catalog = privacy_scan_module._read_catalog_file
        real_issue = privacy_scan_module._issue_resolution_handle

        def assert_scan_drift(
            *,
            catalog_check_ordinal: int,
            identity_index: int | None = None,
            content_drift: bool = False,
        ) -> None:
            scanner = new_scanner()
            previous = scanner.scan_paths([])
            read_calls = 0
            issue_calls = 0

            def drifting_read_catalog(
                path: object,
                limits: ScanLimits,
            ) -> tuple[
                Path,
                privacy_scan_module._StatIdentity,
                bytes,
            ]:
                nonlocal read_calls
                read_calls += 1
                canonical_path, identity, raw = real_read_catalog(path, limits)
                if read_calls != catalog_check_ordinal:
                    return canonical_path, identity, raw
                if content_drift:
                    changed_raw = bytes((raw[0] ^ 1,)) + raw[1:]
                    assert len(changed_raw) == len(raw)
                    return canonical_path, identity, changed_raw
                assert identity_index is not None
                changed_identity = list(identity)
                if identity_index == 7:
                    changed_identity[identity_index] |= (
                        privacy_scan_module._REPARSE_ATTRIBUTE
                    )
                else:
                    changed_identity[identity_index] += 1
                return (
                    canonical_path,
                    cast(
                        privacy_scan_module._StatIdentity,
                        tuple(changed_identity),
                    ),
                    raw,
                )

            def counted_issue() -> ScanResolutionHandle:
                nonlocal issue_calls
                issue_calls += 1
                return real_issue()

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_read_catalog_file",
                    drifting_read_catalog,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_issue_resolution_handle",
                    counted_issue,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    scanner.scan_paths([])
            _assert_slice7_safe_error(
                captured.value,
                "SCAN_CATALOG_CHANGED",
                sensitive=(catalog, catalog_raw),
            )
            assert read_calls == catalog_check_ordinal
            assert issue_calls == 0, "CATALOG_POST_FAILURE_ISSUED_HANDLE"
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            with pytest.raises(PrivacyScanError) as stale:
                scanner.resolve_location(
                    previous.resolution_handle,
                    "root_0001/pth1_" + "0" * 64,
                )
            _assert_slice7_safe_error(
                stale.value,
                "SCAN_LOCATION_UNAVAILABLE",
                sensitive=(catalog, previous.resolution_handle),
            )

        for catalog_check_ordinal in (1, 2):
            for field_index in range(8):
                assert_scan_drift(
                    catalog_check_ordinal=catalog_check_ordinal,
                    identity_index=field_index,
                )
            assert_scan_drift(
                catalog_check_ordinal=catalog_check_ordinal,
                content_drift=True,
            )

        clean_scanner = new_scanner()
        real_catalog_check = privacy_scan_module._scan_catalog_check
        clean_checks: list[int] = []

        def counted_catalog_check(binding: object, limits: ScanLimits) -> None:
            clean_checks.append(len(clean_checks) + 1)
            real_catalog_check(binding, limits)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                counted_catalog_check,
            )
            clean = clean_scanner.scan_paths([])
        assert clean.report == PrivacyScanReport(hits=())
        assert type(clean.resolution_handle) is ScanResolutionHandle
        assert clean_checks == [1, 2]
        generation = object.__getattribute__(
            clean_scanner,
            "_PrivacyScanner__generation",
        )
        assert generation.handle is clean.resolution_handle
        assert dict(generation.mapping) == {}


class TestScannerFileRaceAdversarial:
    @staticmethod
    def _changed_status(status: object, **changes: int) -> SimpleNamespace:
        values = {
            name: getattr(status, name)
            for name in (
                "st_mode",
                "st_dev",
                "st_ino",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        values["st_file_attributes"] = int(
            getattr(status, "st_file_attributes", 0)
        )
        values.update(changes)
        return SimpleNamespace(**values)

    def test_scan_10_file_identity_metadata_and_pathname_drift(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "file-races"
        root.mkdir()
        payload = root / "file-race.txt"
        payload_raw = b"file-race" + b"@" + b"example.test"
        payload.write_bytes(payload_raw)
        real_open = privacy_scan_module._open_scan_descriptor
        real_fstat = privacy_scan_module._FSTAT
        real_read = privacy_scan_module._READ
        real_close = privacy_scan_module._CLOSE
        real_lstat = privacy_scan_module._LSTAT
        real_close_records = privacy_scan_module._close_directory_records

        def changed_for(status: object, mutation: str) -> SimpleNamespace:
            if mutation == "type":
                return self._changed_status(
                    status,
                    st_mode=stat.S_IFIFO | 0o600,
                )
            if mutation == "dev":
                return self._changed_status(
                    status,
                    st_dev=status.st_dev + 1,
                )
            if mutation == "ino":
                return self._changed_status(
                    status,
                    st_ino=status.st_ino + 1,
                )
            if mutation == "swap":
                return self._changed_status(
                    status,
                    st_dev=status.st_dev + 1,
                    st_ino=status.st_ino + 1,
                )
            if mutation == "nlink":
                return self._changed_status(
                    status,
                    st_nlink=status.st_nlink + 1,
                )
            if mutation == "size":
                return self._changed_status(
                    status,
                    st_size=status.st_size + 1,
                )
            if mutation == "mtime":
                return self._changed_status(
                    status,
                    st_mtime_ns=status.st_mtime_ns + 1,
                )
            if mutation == "ctime":
                return self._changed_status(
                    status,
                    st_ctime_ns=status.st_ctime_ns + 1,
                )
            if mutation == "link":
                return self._changed_status(
                    status,
                    st_file_attributes=(
                        int(getattr(status, "st_file_attributes", 0))
                        | privacy_scan_module._REPARSE_ATTRIBUTE
                    ),
                )
            raise AssertionError("UNKNOWN_FILE_RACE_MUTATION")

        order_events: list[str] = []
        order_descriptors: set[int] = set()
        order_lstats = 0

        def ordered_open(path: Path) -> int:
            descriptor = real_open(path)
            if path == payload:
                order_events.append("open")
                order_descriptors.add(descriptor)
            return descriptor

        def ordered_fstat(descriptor: int) -> object:
            status = real_fstat(descriptor)
            if descriptor in order_descriptors:
                ordinal = sum(
                    event.startswith("fstat_") for event in order_events
                )
                order_events.append(
                    "fstat_before" if ordinal == 0 else "fstat_after"
                )
            return status

        def ordered_read(descriptor: int, size: int) -> bytes:
            if descriptor in order_descriptors:
                order_events.append("read")
            return real_read(descriptor, size)

        def ordered_close(descriptor: int) -> None:
            if descriptor in order_descriptors:
                order_events.append("close")
                order_descriptors.remove(descriptor)
            real_close(descriptor)

        def ordered_lstat(path: object) -> object:
            nonlocal order_lstats
            status = real_lstat(path)
            if Path(path) == payload:
                order_lstats += 1
                order_events.append(
                    (
                        "plan_lstat"
                        if order_lstats == 1
                        else "final_path_lstat"
                        if order_lstats == 2
                        else "tree_final_lstat"
                    )
                )
            return status

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_open_scan_descriptor",
                ordered_open,
            )
            patch.setattr(privacy_scan_module, "_FSTAT", ordered_fstat)
            patch.setattr(privacy_scan_module, "_READ", ordered_read)
            patch.setattr(privacy_scan_module, "_CLOSE", ordered_close)
            patch.setattr(privacy_scan_module, "_LSTAT", ordered_lstat)
            assert _scanner().scan_paths([root]).report.hit_count == 1
        assert order_events == [
            "plan_lstat",
            "open",
            "fstat_before",
            "read",
            "read",
            "fstat_after",
            "close",
            "final_path_lstat",
            "tree_final_lstat",
        ]

        def assert_drift(
            phase: str,
            mutation: str,
            expected_code: str = "SCAN_FILE_CHANGED",
        ) -> None:
            payload.write_bytes(payload_raw)
            scanner = _scanner()
            previous = scanner.scan_paths([root])
            previous_ref = previous.report.hits[0].location_ref
            target_descriptors: set[int] = set()
            target_fstats = 0
            target_lstats = 0
            tree_closure_calls = 0

            def capture_open(path: Path) -> int:
                if path == payload and phase == "open":
                    raise privacy_scan_module._ScanFailure(
                        "SCAN_UNREADABLE"
                    )
                descriptor = real_open(path)
                if path == payload:
                    target_descriptors.add(descriptor)
                return descriptor

            def drifting_fstat(descriptor: int) -> object:
                nonlocal target_fstats
                status = real_fstat(descriptor)
                if descriptor not in target_descriptors:
                    return status
                target_fstats += 1
                if phase == "handle_before" and target_fstats == 1:
                    return changed_for(status, mutation)
                if phase == "handle_after" and target_fstats == 2:
                    return changed_for(status, mutation)
                return status

            def drifting_read(descriptor: int, size: int) -> bytes:
                if descriptor in target_descriptors and phase == "read":
                    raise OSError("CALLER_ORACLE_READ")
                return real_read(descriptor, size)

            def drifting_close(descriptor: int) -> None:
                is_target = descriptor in target_descriptors
                if is_target:
                    target_descriptors.remove(descriptor)
                if is_target and phase == "close":
                    real_close(descriptor)
                    raise OSError("CALLER_ORACLE_CLOSE")
                real_close(descriptor)

            def drifting_lstat(path: object) -> object:
                nonlocal target_lstats
                status = real_lstat(path)
                if Path(path) != payload:
                    return status
                target_lstats += 1
                if phase == "plan" and target_lstats == 1:
                    return changed_for(status, mutation)
                if phase == "final_path" and target_lstats == 2:
                    if mutation == "disappear":
                        raise FileNotFoundError("CALLER_ORACLE_DISAPPEAR")
                    return changed_for(status, mutation)
                return status

            def counted_close_records(
                records: tuple[privacy_scan_module._DirectoryRecord, ...],
                limits: ScanLimits,
                tree_observations: list[int],
            ) -> None:
                nonlocal tree_closure_calls
                tree_closure_calls += 1
                real_close_records(records, limits, tree_observations)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_open_scan_descriptor",
                    capture_open,
                )
                patch.setattr(privacy_scan_module, "_FSTAT", drifting_fstat)
                patch.setattr(privacy_scan_module, "_READ", drifting_read)
                patch.setattr(privacy_scan_module, "_CLOSE", drifting_close)
                patch.setattr(privacy_scan_module, "_LSTAT", drifting_lstat)
                patch.setattr(
                    privacy_scan_module,
                    "_close_directory_records",
                    counted_close_records,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    scanner.scan_paths([root])
            _assert_slice7_safe_error(
                captured.value,
                expected_code,
                sensitive=(payload, payload_raw, "CALLER_ORACLE"),
            )
            if phase == "handle_after":
                assert target_fstats == 2
                assert target_lstats == 1
                assert tree_closure_calls == 0
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            with pytest.raises(PrivacyScanError) as stale:
                scanner.resolve_location(
                    previous.resolution_handle,
                    previous_ref,
                )
            _assert_slice7_safe_error(
                stale.value,
                "SCAN_LOCATION_UNAVAILABLE",
                sensitive=(payload, previous_ref, previous.resolution_handle),
            )

        for mutation in ("dev", "ino", "nlink", "size", "mtime", "ctime"):
            assert_drift("plan", mutation)
        assert_drift("open", "unreadable", "SCAN_UNREADABLE")
        for phase in ("handle_before", "handle_after"):
            for mutation in (
                "type",
                "dev",
                "ino",
                "swap",
                "nlink",
                "size",
                "mtime",
                "ctime",
                "link",
            ):
                assert_drift(phase, mutation)
        assert_drift("read", "failure")
        assert_drift("close", "failure")
        for mutation in (
            "type",
            "dev",
            "ino",
            "swap",
            "nlink",
            "size",
            "mtime",
            "ctime",
            "link",
            "disappear",
        ):
            assert_drift("final_path", mutation)

        premature_prefix = b"safe-prefix\n"
        unread_occurrence = b"unread" + b"@" + b"example.test"
        premature_raw = premature_prefix + unread_occurrence
        payload.write_bytes(premature_raw)
        premature_scanner = _scanner()
        premature_previous = premature_scanner.scan_paths([root])
        assert premature_previous.report.hit_count == 1
        assert premature_previous.report.hits[0].rule_id == "email_address"
        premature_ref = premature_previous.report.hits[0].location_ref
        premature_descriptors: set[int] = set()
        premature_reads = 0
        premature_fstats: list[privacy_scan_module._StatIdentity] = []
        premature_lstats = 0
        premature_tree_closures = 0
        premature_catalog_checks: list[int] = []
        premature_issue_calls = 0
        premature_outcome_calls = 0
        real_issue = privacy_scan_module._issue_resolution_handle
        real_outcome = privacy_scan_module.PrivacyScanOutcome
        real_catalog_check = privacy_scan_module._scan_catalog_check

        def premature_open(path: Path) -> int:
            descriptor = real_open(path)
            if path == payload:
                premature_descriptors.add(descriptor)
            return descriptor

        def premature_fstat(descriptor: int) -> object:
            status = real_fstat(descriptor)
            if descriptor in premature_descriptors:
                premature_fstats.append(
                    privacy_scan_module._scan_status_identity(status)
                )
            return status

        def premature_read(descriptor: int, size: int) -> bytes:
            nonlocal premature_reads
            if descriptor not in premature_descriptors:
                return real_read(descriptor, size)
            premature_reads += 1
            if premature_reads == 1:
                prefix = real_read(descriptor, len(premature_prefix))
                assert prefix == premature_prefix
                return prefix
            if premature_reads == 2:
                return b""
            raise AssertionError("PREMATURE_EOF_READ_AFTER_EOF")

        def premature_close(descriptor: int) -> None:
            try:
                real_close(descriptor)
            finally:
                premature_descriptors.discard(descriptor)

        def premature_lstat(path: object) -> object:
            nonlocal premature_lstats
            status = real_lstat(path)
            if Path(path) == payload:
                premature_lstats += 1
            return status

        def premature_close_records(
            records: tuple[privacy_scan_module._DirectoryRecord, ...],
            limits: ScanLimits,
            tree_observations: list[int],
        ) -> None:
            nonlocal premature_tree_closures
            premature_tree_closures += 1
            real_close_records(records, limits, tree_observations)

        def premature_catalog_check(
            binding: object,
            limits: ScanLimits,
        ) -> None:
            premature_catalog_checks.append(
                len(premature_catalog_checks) + 1
            )
            real_catalog_check(binding, limits)

        def premature_issue() -> ScanResolutionHandle:
            nonlocal premature_issue_calls
            premature_issue_calls += 1
            return real_issue()

        def premature_outcome(*args: object, **kwargs: object) -> object:
            nonlocal premature_outcome_calls
            premature_outcome_calls += 1
            return real_outcome(*args, **kwargs)  # type: ignore[arg-type]

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_open_scan_descriptor",
                premature_open,
            )
            patch.setattr(privacy_scan_module, "_FSTAT", premature_fstat)
            patch.setattr(privacy_scan_module, "_READ", premature_read)
            patch.setattr(privacy_scan_module, "_CLOSE", premature_close)
            patch.setattr(privacy_scan_module, "_LSTAT", premature_lstat)
            patch.setattr(
                privacy_scan_module,
                "_close_directory_records",
                premature_close_records,
            )
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                premature_catalog_check,
            )
            patch.setattr(
                privacy_scan_module,
                "_issue_resolution_handle",
                premature_issue,
            )
            patch.setattr(
                privacy_scan_module,
                "PrivacyScanOutcome",
                premature_outcome,
            )
            with pytest.raises(PrivacyScanError) as premature_error:
                premature_scanner.scan_paths([root])
        _assert_slice7_safe_error(
            premature_error.value,
            "SCAN_FILE_CHANGED",
            sensitive=(payload, premature_raw, unread_occurrence),
        )
        assert premature_reads == 2
        assert premature_descriptors == set()
        assert len(premature_fstats) == 2
        assert premature_fstats[0] == premature_fstats[1]
        assert premature_fstats[0][4] == len(premature_raw)
        assert premature_lstats == 1
        assert premature_tree_closures == 0
        assert premature_catalog_checks == [1]
        assert premature_issue_calls == 0
        assert premature_outcome_calls == 0
        assert object.__getattribute__(
            premature_scanner,
            "_PrivacyScanner__generation",
        ) is None
        with pytest.raises(PrivacyScanError) as premature_stale:
            premature_scanner.resolve_location(
                premature_previous.resolution_handle,
                premature_ref,
            )
        _assert_slice7_safe_error(
            premature_stale.value,
            "SCAN_LOCATION_UNAVAILABLE",
            sensitive=(payload, premature_ref, premature_previous.resolution_handle),
        )

        for mutation in ("grow", "shrink"):
            payload.write_bytes(payload_raw)
            scanner = _scanner()
            previous = scanner.scan_paths([root])
            previous_ref = previous.report.hits[0].location_ref
            target_descriptors: set[int] = set()
            read_entered = threading.Event()
            read_release = threading.Event()
            worker_errors: list[PrivacyScanError] = []

            def capture_open(path: Path) -> int:
                descriptor = real_open(path)
                if path == payload:
                    target_descriptors.add(descriptor)
                return descriptor

            def blocking_read(descriptor: int, size: int) -> bytes:
                if descriptor in target_descriptors:
                    read_entered.set()
                    if not read_release.wait(timeout=5):
                        raise AssertionError("FILE_READ_RELEASE_TIMEOUT")
                return real_read(descriptor, size)

            def run_scan() -> None:
                try:
                    scanner.scan_paths([root])
                except PrivacyScanError as error:
                    worker_errors.append(error)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_open_scan_descriptor",
                    capture_open,
                )
                patch.setattr(privacy_scan_module, "_READ", blocking_read)
                worker = threading.Thread(target=run_scan)
                worker.start()
                assert read_entered.wait(timeout=5)
                payload.write_bytes(
                    payload_raw + b"-grown"
                    if mutation == "grow"
                    else payload_raw[:5]
                )
                read_release.set()
                worker.join(timeout=5)
                assert not worker.is_alive()
            assert len(worker_errors) == 1
            _assert_slice7_safe_error(
                worker_errors[0],
                "SCAN_FILE_CHANGED",
                sensitive=(payload, payload_raw),
            )
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            with pytest.raises(PrivacyScanError) as stale:
                scanner.resolve_location(
                    previous.resolution_handle,
                    previous_ref,
                )
            _assert_slice7_safe_error(
                stale.value,
                "SCAN_LOCATION_UNAVAILABLE",
                sensitive=(payload, previous_ref, previous.resolution_handle),
            )

        missing = root / "missing.txt"
        with pytest.raises(PrivacyScanError) as missing_error:
            _scanner().scan_paths([missing])
        _assert_slice7_safe_error(
            missing_error.value,
            "SCAN_PATH_NOT_FOUND",
            sensitive=(missing,),
        )

        preflight = root / "preflight.txt"
        preflight.write_bytes(b"plain")
        for mutation, expected in (
            ("type", "SCAN_PATH_UNSUPPORTED"),
            ("link", "SCAN_LINK_OR_REPARSE"),
        ):
            def preflight_lstat(path: object) -> object:
                status = real_lstat(path)
                if Path(path) == preflight:
                    return changed_for(status, mutation)
                return status

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_LSTAT",
                    preflight_lstat,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    _scanner().scan_paths([preflight])
            _assert_slice7_safe_error(
                captured.value,
                expected,
                sensitive=(preflight,),
            )

    def test_scan_41_pathname_replacement_after_child_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "pathname-replacement"
        root.mkdir()
        payload = root / "payload.txt"
        payload_raw = b"pathname-race" + b"@" + b"example.test"
        payload.write_bytes(payload_raw)
        scanner = _scanner()
        previous = scanner.scan_paths([root])
        previous_ref = previous.report.hits[0].location_ref
        real_open = privacy_scan_module._open_scan_descriptor
        real_close = privacy_scan_module._CLOSE
        real_catalog_check = privacy_scan_module._scan_catalog_check
        target_descriptors: set[int] = set()
        catalog_checks: list[int] = []
        replaced = False

        def capture_open(path: Path) -> int:
            descriptor = real_open(path)
            if path == payload:
                target_descriptors.add(descriptor)
            return descriptor

        def replace_after_close(descriptor: int) -> None:
            nonlocal replaced
            if descriptor not in target_descriptors:
                real_close(descriptor)
                return
            real_close(descriptor)
            payload.unlink()
            payload.write_bytes(payload_raw)
            replaced = True

        def counted_catalog_check(binding: object, limits: ScanLimits) -> None:
            catalog_checks.append(len(catalog_checks) + 1)
            real_catalog_check(binding, limits)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_open_scan_descriptor",
                capture_open,
            )
            patch.setattr(privacy_scan_module, "_CLOSE", replace_after_close)
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                counted_catalog_check,
            )
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths([root])
        assert replaced
        _assert_slice7_safe_error(
            captured.value,
            "SCAN_FILE_CHANGED",
            sensitive=(payload, payload_raw),
        )
        assert catalog_checks == [1]
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(previous.resolution_handle, previous_ref)
        _assert_slice7_safe_error(
            stale.value,
            "SCAN_LOCATION_UNAVAILABLE",
            sensitive=(payload, previous_ref, previous.resolution_handle),
        )
        recovered = scanner.scan_paths([root])
        assert recovered.report.hit_count == 1
        assert scanner.resolve_location(
            recovered.resolution_handle,
            recovered.report.hits[0].location_ref,
        ) == payload


class TestScannerTreeRaceAdversarial:
    @staticmethod
    def _changed_status(status: object, **changes: int) -> SimpleNamespace:
        values = {
            name: getattr(status, name)
            for name in (
                "st_mode",
                "st_dev",
                "st_ino",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        values["st_file_attributes"] = int(
            getattr(status, "st_file_attributes", 0)
        )
        values.update(changes)
        return SimpleNamespace(**values)

    def test_scan_40_initial_final_tree_mutations(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real_lstat = privacy_scan_module._LSTAT
        real_snapshot = privacy_scan_module._directory_snapshot
        real_close_records = privacy_scan_module._close_directory_records
        real_catalog_check = privacy_scan_module._scan_catalog_check
        real_issue = privacy_scan_module._issue_resolution_handle

        initial_root = tmp_path / "initial-reparse"
        initial_root.mkdir()
        initial_payload = initial_root / "payload.txt"
        initial_payload.write_bytes(b"plain")

        def initial_reparse_lstat(path: object) -> object:
            status = real_lstat(path)
            if Path(path) != initial_payload:
                return status
            return self._changed_status(
                status,
                st_file_attributes=(
                    int(getattr(status, "st_file_attributes", 0))
                    | privacy_scan_module._REPARSE_ATTRIBUTE
                ),
            )

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_LSTAT",
                initial_reparse_lstat,
            )
            with pytest.raises(PrivacyScanError) as initial_reparse:
                _scanner().scan_paths([initial_root])
        _assert_slice7_safe_error(
            initial_reparse.value,
            "SCAN_LINK_OR_REPARSE",
            sensitive=(initial_root, initial_payload),
        )

        observed_codes: list[str] = []
        for mutation in ("add", "delete", "rename", "replace"):
            root = tmp_path / f"final-{mutation}"
            root.mkdir()
            payload = root / "payload.txt"
            payload_raw = b"plain"
            payload.write_bytes(payload_raw)
            scanner = _scanner()
            scanner.scan_paths([root])
            catalog_checks: list[int] = []

            def counted_catalog_check(
                binding: object,
                limits: ScanLimits,
            ) -> None:
                catalog_checks.append(len(catalog_checks) + 1)
                real_catalog_check(binding, limits)

            def mutate_before_close(
                records: tuple[privacy_scan_module._DirectoryRecord, ...],
                limits: ScanLimits,
                tree_observations: list[int],
            ) -> None:
                if mutation == "add":
                    (root / "late.txt").write_bytes(b"late")
                elif mutation == "delete":
                    payload.unlink()
                elif mutation == "rename":
                    payload.rename(root / "renamed.txt")
                else:
                    payload.unlink()
                    payload.write_bytes(payload_raw)
                real_close_records(records, limits, tree_observations)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_close_directory_records",
                    mutate_before_close,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_scan_catalog_check",
                    counted_catalog_check,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    scanner.scan_paths([root])
            _assert_slice7_safe_error(
                captured.value,
                "SCAN_TREE_CHANGED",
                sensitive=(root, payload, payload_raw),
            )
            observed_codes.append(captured.value.code)
            assert catalog_checks == [1]
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None

        for final_kind in ("reparse", "special"):
            root = tmp_path / f"final-{final_kind}"
            root.mkdir()
            payload = root / "payload.txt"
            payload.write_bytes(b"plain")
            scanner = _scanner()
            scanner.scan_paths([root])
            payload_lstats = 0
            catalog_checks: list[int] = []

            def final_drift_lstat(path: object) -> object:
                nonlocal payload_lstats
                status = real_lstat(path)
                if Path(path) != payload:
                    return status
                payload_lstats += 1
                if payload_lstats != 3:
                    return status
                if final_kind == "reparse":
                    return self._changed_status(
                        status,
                        st_file_attributes=(
                            int(getattr(status, "st_file_attributes", 0))
                            | privacy_scan_module._REPARSE_ATTRIBUTE
                        ),
                    )
                return self._changed_status(
                    status,
                    st_mode=stat.S_IFIFO | 0o600,
                )

            def counted_catalog_check(
                binding: object,
                limits: ScanLimits,
            ) -> None:
                catalog_checks.append(len(catalog_checks) + 1)
                real_catalog_check(binding, limits)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_LSTAT",
                    final_drift_lstat,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_scan_catalog_check",
                    counted_catalog_check,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    scanner.scan_paths([root])
            _assert_slice7_safe_error(
                captured.value,
                "SCAN_TREE_CHANGED",
                sensitive=(root, payload),
            )
            observed_codes.append(captured.value.code)
            assert payload_lstats == 3
            assert catalog_checks == [1]
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None

        assert observed_codes == ["SCAN_TREE_CHANGED"] * 6

        directory_identity_cases = (
            ("mode_type", 0),
            ("dev", 1),
            ("ino", 2),
            ("nlink", 3),
            ("mtime_ns", 4),
            ("ctime_ns", 5),
            ("reparse_attrs", 6),
        )
        for identity_kind, identity_index in directory_identity_cases:
            root = tmp_path / f"final-directory-own-{identity_kind}"
            root.mkdir()
            payload = root / "payload.txt"
            payload.write_bytes(b"plain")
            scanner = _scanner()
            scanner.scan_paths([root])
            root_snapshot_calls = 0
            root_snapshots: list[privacy_scan_module._DirectorySnapshot] = []
            catalog_checks: list[int] = []
            issue_calls = 0

            def directory_own_snapshot(
                path: Path,
                depth: int,
                limits: ScanLimits,
                tree_observations: list[int],
            ) -> tuple[
                privacy_scan_module._DirectorySnapshot,
                tuple[privacy_scan_module._TreeChild, ...],
            ]:
                nonlocal root_snapshot_calls
                snapshot, children = real_snapshot(
                    path,
                    depth,
                    limits,
                    tree_observations,
                )
                if path != root:
                    return snapshot, children
                root_snapshot_calls += 1
                if root_snapshot_calls == 2:
                    changed_identity = list(snapshot.identity)
                    if identity_kind == "mode_type":
                        changed_identity[identity_index] = (
                            stat.S_IFREG | stat.S_IMODE(snapshot.identity[0])
                        )
                    elif identity_kind == "reparse_attrs":
                        changed_identity[identity_index] |= (
                            privacy_scan_module._REPARSE_ATTRIBUTE
                        )
                    else:
                        changed_identity[identity_index] += 1
                    snapshot = privacy_scan_module._DirectorySnapshot(
                        identity=cast(
                            privacy_scan_module._DirectoryIdentity,
                            tuple(changed_identity),
                        ),
                        children=snapshot.children,
                    )
                root_snapshots.append(snapshot)
                return snapshot, children

            def counted_catalog_check(
                binding: object,
                limits: ScanLimits,
            ) -> None:
                catalog_checks.append(len(catalog_checks) + 1)
                real_catalog_check(binding, limits)

            def counted_issue() -> ScanResolutionHandle:
                nonlocal issue_calls
                issue_calls += 1
                return real_issue()

            own_error: PrivacyScanError | None = None
            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_directory_snapshot",
                    directory_own_snapshot,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_scan_catalog_check",
                    counted_catalog_check,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_issue_resolution_handle",
                    counted_issue,
                )
                try:
                    scanner.scan_paths([root])
                except PrivacyScanError as error:
                    own_error = error
                else:
                    pytest.fail("DIRECTORY_OWN_IDENTITY_DRIFT_ACCEPTED")
            assert own_error is not None
            _assert_slice7_safe_error(
                own_error,
                "SCAN_TREE_CHANGED",
                sensitive=(root, payload, identity_kind),
            )
            assert root_snapshot_calls == 2
            assert len(root_snapshots) == 2
            assert root_snapshots[0].children == root_snapshots[1].children
            assert sum(
                before != after
                for before, after in zip(
                    root_snapshots[0].identity,
                    root_snapshots[1].identity,
                    strict=True,
                )
            ) == 1
            assert (
                root_snapshots[0].identity[identity_index]
                != root_snapshots[1].identity[identity_index]
            )
            assert catalog_checks == [1]
            assert issue_calls == 0
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None

    def test_scan_41_postorder_parent_and_child_drift(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "postorder"
        child = root / "child"
        grandchild = child / "grandchild"
        grandchild.mkdir(parents=True)
        payload = grandchild / "payload.txt"
        payload.write_bytes(b"postorder" + b"@" + b"example.test")
        real_snapshot = privacy_scan_module._directory_snapshot
        real_lstat = privacy_scan_module._LSTAT
        real_scan_file = privacy_scan_module._scan_file_plan
        real_catalog_check = privacy_scan_module._scan_catalog_check
        real_issue = privacy_scan_module._issue_resolution_handle

        def assert_direct_entry_drift(drift_target: str) -> None:
            scanner = _scanner()
            previous = scanner.scan_paths([root])
            previous_ref = previous.report.hits[0].location_ref
            snapshot_counts: dict[Path, int] = {}
            snapshot_order: list[tuple[Path, int]] = []
            catalog_checks: list[int] = []
            issue_calls: list[int] = []
            descendant_read_complete = False
            inject_child_entry = False
            child_final_complete = False

            def changed_direct_entry_lstat(path: object) -> object:
                status = real_lstat(path)
                selected = Path(path)
                if (
                    drift_target == "child"
                    and selected == grandchild
                    and inject_child_entry
                ) or (
                    drift_target == "parent"
                    and selected == child
                    and child_final_complete
                ):
                    return self._changed_status(
                        status,
                        st_mtime_ns=status.st_mtime_ns + 1,
                    )
                return status

            def observed_file_plan(
                plan: privacy_scan_module._FilePlan,
                profile: privacy_scan_module.ScanProfile,
                binding: privacy_scan_module._CatalogBinding,
                limits: ScanLimits,
                scan_key: bytes,
                total_before: int,
                hits: list[PrivacyHit],
            ) -> int:
                nonlocal descendant_read_complete
                result = real_scan_file(
                    plan,
                    profile,
                    binding,
                    limits,
                    scan_key,
                    total_before,
                    hits,
                )
                if plan.canonical_path == payload:
                    descendant_read_complete = True
                return result

            def observed_snapshot(
                path: Path,
                depth: int,
                limits: ScanLimits,
                tree_observations: list[int],
            ) -> tuple[
                privacy_scan_module._DirectorySnapshot,
                tuple[privacy_scan_module._TreeChild, ...],
            ]:
                nonlocal inject_child_entry, child_final_complete
                count = snapshot_counts.get(path, 0) + 1
                snapshot_counts[path] = count
                snapshot_order.append((path, count))
                if path == child and count == 2 and drift_target == "child":
                    assert descendant_read_complete
                    inject_child_entry = True
                result = real_snapshot(path, depth, limits, tree_observations)
                if path == child and count == 2 and drift_target == "parent":
                    assert descendant_read_complete
                    child_final_complete = True
                return result

            def counted_catalog_check(
                binding: object,
                limits: ScanLimits,
            ) -> None:
                catalog_checks.append(len(catalog_checks) + 1)
                real_catalog_check(binding, limits)

            def counted_issue() -> ScanResolutionHandle:
                issue_calls.append(len(issue_calls) + 1)
                return real_issue()

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_LSTAT",
                    changed_direct_entry_lstat,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_scan_file_plan",
                    observed_file_plan,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_directory_snapshot",
                    observed_snapshot,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_scan_catalog_check",
                    counted_catalog_check,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_issue_resolution_handle",
                    counted_issue,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    scanner.scan_paths([root])
            _assert_slice7_safe_error(
                captured.value,
                "SCAN_TREE_CHANGED",
                sensitive=(root, child, grandchild, payload),
            )
            expected_order = [
                (root, 1),
                (child, 1),
                (grandchild, 1),
                (grandchild, 2),
                (child, 2),
            ]
            if drift_target == "parent":
                expected_order.append((root, 2))
            assert snapshot_order == expected_order
            assert descendant_read_complete
            assert inject_child_entry == (drift_target == "child")
            assert child_final_complete == (drift_target == "parent")
            assert catalog_checks == [1]
            assert issue_calls == []
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            with pytest.raises(PrivacyScanError) as stale:
                scanner.resolve_location(
                    previous.resolution_handle,
                    previous_ref,
                )
            _assert_slice7_safe_error(
                stale.value,
                "SCAN_LOCATION_UNAVAILABLE",
                sensitive=(payload, previous_ref, previous.resolution_handle),
            )

        assert_direct_entry_drift("child")
        assert_direct_entry_drift("parent")

    def test_scan_45_observation_count_before_lstat_sort(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "tree-observation"
        nested = root / "nested"
        nested.mkdir(parents=True)
        leaves = tuple(nested / f"empty-{index:02d}" for index in range(5))
        for leaf in leaves:
            leaf.mkdir()
        assert not any(path.is_file() for path in root.rglob("*"))

        expected_observations = 2 + 4 * len(leaves)
        real_scandir = privacy_scan_module._SCANDIR
        observed_paths: list[Path] = []

        class ObservedScandir:
            def __init__(self, path: object, *, reverse: bool = False) -> None:
                self.path = Path(path)
                self.inner = real_scandir(path)
                entries = list(self.inner)
                self.entries = iter(reversed(entries) if reverse else entries)

            def __iter__(self) -> ObservedScandir:
                return self

            def __next__(self) -> object:
                entry = next(self.entries)
                observed_paths.append(self.path)
                return entry

            def close(self) -> None:
                self.inner.close()

        exact_limits = replace(
            DEFAULT_SCAN_LIMITS,
            max_tree_entries=expected_observations,
        )
        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_SCANDIR",
                lambda path: ObservedScandir(path),
            )
            exact = _scanner(limits=exact_limits).scan_paths([root, nested])
        assert exact.report == PrivacyScanReport(hits=())
        assert len(observed_paths) == expected_observations
        assert observed_paths.count(root) == 2
        assert observed_paths.count(nested) == 4 * len(leaves)

        observed_paths.clear()
        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_SCANDIR",
                lambda path: ObservedScandir(path, reverse=True),
            )
            reversed_exact = _scanner(limits=exact_limits).scan_paths(
                [nested, root]
            )
        assert reversed_exact.report == exact.report
        assert len(observed_paths) == expected_observations
        assert observed_paths.count(root) == 2
        assert observed_paths.count(nested) == 4 * len(leaves)

        class SentinelEntry:
            name_calls = 0

            @property
            def name(self) -> str:
                self.name_calls += 1
                raise AssertionError("TREE_SENTINEL_NAME_INSPECTED")

        sentinel = SentinelEntry()
        root_scandir_calls = 0
        catalog_checks: list[int] = []
        real_catalog_check = privacy_scan_module._scan_catalog_check

        class FinalRootScandir:
            def __init__(self, path: object) -> None:
                self.inner = real_scandir(path)
                self.sentinel_pending = True

            def __iter__(self) -> FinalRootScandir:
                return self

            def __next__(self) -> object:
                try:
                    return next(self.inner)
                except StopIteration:
                    if self.sentinel_pending:
                        self.sentinel_pending = False
                        return sentinel
                    raise

            def close(self) -> None:
                self.inner.close()

        def raw_scandir(path: object) -> object:
            nonlocal root_scandir_calls
            if Path(path) == root:
                root_scandir_calls += 1
                if root_scandir_calls == 2:
                    return FinalRootScandir(path)
            return real_scandir(path)

        def counted_catalog_check(binding: object, limits: ScanLimits) -> None:
            catalog_checks.append(len(catalog_checks) + 1)
            real_catalog_check(binding, limits)

        scanner = _scanner(limits=exact_limits)
        previous = scanner.scan_paths([])

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_SCANDIR", raw_scandir)
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                counted_catalog_check,
            )
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths([root, nested])
        _assert_slice7_safe_error(
            captured.value,
            "SCAN_LIMIT_TREE_ENTRIES",
            sensitive=(root, nested, "TREE_SENTINEL_NAME_INSPECTED"),
        )
        assert sentinel.name_calls == 0
        assert root_scandir_calls == 2
        assert catalog_checks == [1]
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        with pytest.raises(PrivacyScanError) as stale:
            scanner.resolve_location(
                previous.resolution_handle,
                "root_0001/pth1_" + "0" * 64,
            )
        _assert_slice7_safe_error(
            stale.value,
            "SCAN_LOCATION_UNAVAILABLE",
            sensitive=(root, nested, previous.resolution_handle),
        )


class TestScannerLimitBoundaryAdversarial:
    def test_scan_28_every_runtime_limit_equal_and_plus_one(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Keep the established twelve-limit matrix as one node while extending
        # its max-files case with the frozen observation-order oracle.
        TestScannerDeterminismAndLimits()._assert_all_runtime_limits_equal_and_plus_one(
            tmp_path
        )

        root = tmp_path / "max-files-observation-order"
        root.mkdir()
        candidates = tuple(root / name for name in ("a.txt", "b.txt"))
        for candidate in candidates:
            candidate.write_bytes(b"plain")
        scanner = _scanner(
            limits=replace(DEFAULT_SCAN_LIMITS, max_files=1)
        )
        real_owner = privacy_scan_module._most_specific_owner
        real_native = privacy_scan_module._validated_native_relative
        real_owner_identity = privacy_scan_module._owner_identity
        real_location_ref = privacy_scan_module._location_ref
        real_open = privacy_scan_module._open_scan_descriptor
        owner_calls: list[Path] = []
        native_calls: list[Path] = []
        owner_identity_calls: list[Path] = []
        location_calls: list[bytes] = []
        open_calls: list[Path] = []

        def counted_owner(
            path: Path,
            path_key: str,
            file_roots: Mapping[str, privacy_scan_module._ExplicitRoot],
            directory_roots: Mapping[str, privacy_scan_module._ExplicitRoot],
            max_depth: int,
        ) -> privacy_scan_module._ExplicitRoot:
            owner_calls.append(path)
            return real_owner(
                path,
                path_key,
                file_roots,
                directory_roots,
                max_depth,
            )

        def counted_native(relative: Path, limits: ScanLimits) -> bytes:
            native_calls.append(relative)
            return real_native(relative, limits)

        def counted_owner_identity(path: Path) -> bytes:
            owner_identity_calls.append(path)
            return real_owner_identity(path)

        def counted_location_ref(
            scan_key: bytes,
            profile: bytes,
            root_label: bytes,
            limits_canonical_bytes: bytes,
            owner_root_identity_bytes: bytes,
            native_relative_bytes: bytes,
        ) -> str:
            location_calls.append(native_relative_bytes)
            return real_location_ref(
                scan_key,
                profile,
                root_label,
                limits_canonical_bytes,
                owner_root_identity_bytes,
                native_relative_bytes,
            )

        def counted_open(path: Path) -> int:
            open_calls.append(path)
            return real_open(path)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_most_specific_owner",
                counted_owner,
            )
            patch.setattr(
                privacy_scan_module,
                "_validated_native_relative",
                counted_native,
            )
            patch.setattr(
                privacy_scan_module,
                "_owner_identity",
                counted_owner_identity,
            )
            patch.setattr(
                privacy_scan_module,
                "_location_ref",
                counted_location_ref,
            )
            patch.setattr(
                privacy_scan_module,
                "_open_scan_descriptor",
                counted_open,
            )
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths([root])
        _assert_slice7_safe_error(
            captured.value,
            "SCAN_LIMIT_FILES",
            sensitive=(root, *candidates),
        )
        assert owner_calls == list(candidates)
        assert native_calls == [Path(candidates[0].name)]
        assert owner_identity_calls == [root]
        assert location_calls == [os.fsencode(candidates[0].name)]
        assert open_calls == []
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None

        input_path = tmp_path / "observation-input.txt"
        input_path.write_bytes(b"plain")
        input_sentinel = object()

        class InputSequence(Sequence[Path]):
            def __init__(self) -> None:
                self.fetches: list[int] = []

            def __len__(self) -> int:
                raise AssertionError("LIMIT_INPUT_LEN_ORACLE")

            def __getitem__(self, index: int) -> Path:
                self.fetches.append(index)
                if index == 0:
                    return input_path
                if index == 1:
                    return cast(Path, input_sentinel)
                raise IndexError

        input_sequence = InputSequence()
        input_observations: list[object] = []
        real_root_observation = privacy_scan_module._root_observation

        def input_root_observation(value: object) -> object:
            input_observations.append(value)
            return real_root_observation(value)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_root_observation",
                input_root_observation,
            )
            with pytest.raises(PrivacyScanError) as input_error:
                _scanner(
                    limits=replace(
                        DEFAULT_SCAN_LIMITS,
                        max_input_paths=1,
                    )
                ).scan_paths(input_sequence)
        _assert_slice7_safe_error(
            input_error.value,
            "SCAN_LIMIT_INPUT_PATHS",
            sensitive=(input_path, input_sentinel),
        )
        assert input_sequence.fetches == [0, 1]
        assert input_observations == [input_path]

        roots = tuple(
            tmp_path / f"observation-root-{name}.txt"
            for name in ("a", "b")
        )
        for candidate in roots:
            candidate.write_bytes(b"plain")
        root_observations: list[object] = []
        build_calls = 0
        real_build_plan = privacy_scan_module._build_scan_plan

        def root_observation(value: object) -> object:
            root_observations.append(value)
            return real_root_observation(value)

        def counted_build_plan(*args: object, **kwargs: object) -> object:
            nonlocal build_calls
            build_calls += 1
            return real_build_plan(*args, **kwargs)  # type: ignore[arg-type]

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_root_observation",
                root_observation,
            )
            patch.setattr(
                privacy_scan_module,
                "_build_scan_plan",
                counted_build_plan,
            )
            with pytest.raises(PrivacyScanError) as roots_error:
                _scanner(
                    limits=replace(
                        DEFAULT_SCAN_LIMITS,
                        max_input_paths=3,
                        max_roots=1,
                    )
                ).scan_paths([roots[0], roots[0], roots[1]])
        _assert_slice7_safe_error(
            roots_error.value,
            "SCAN_LIMIT_ROOTS",
            sensitive=roots,
        )
        assert root_observations == [roots[0], roots[0], roots[1]]
        assert build_calls == 0

        real_scandir = privacy_scan_module._SCANDIR
        tree_root = tmp_path / "observation-tree"
        tree_child = tree_root / "empty-child"
        tree_child.mkdir(parents=True)

        class LimitSentinelEntry:
            name_calls = 0

            @property
            def name(self) -> str:
                self.name_calls += 1
                raise AssertionError("LIMIT_TREE_NAME_ORACLE")

        tree_sentinel = LimitSentinelEntry()

        class TreeLimitScandir:
            def __init__(self, path: object) -> None:
                self.inner = real_scandir(path)
                self.entries = iter((*tuple(self.inner), tree_sentinel))

            def __iter__(self) -> TreeLimitScandir:
                return self

            def __next__(self) -> object:
                return next(self.entries)

            def close(self) -> None:
                self.inner.close()

        def tree_limit_scandir(path: object) -> object:
            if Path(path) == tree_root:
                return TreeLimitScandir(path)
            return real_scandir(path)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_SCANDIR",
                tree_limit_scandir,
            )
            with pytest.raises(PrivacyScanError) as tree_error:
                _scanner(
                    limits=replace(
                        DEFAULT_SCAN_LIMITS,
                        max_tree_entries=1,
                    )
                ).scan_paths([tree_root])
        _assert_slice7_safe_error(
            tree_error.value,
            "SCAN_LIMIT_TREE_ENTRIES",
            sensitive=(tree_root, tree_child, "LIMIT_TREE_NAME_ORACLE"),
        )
        assert tree_sentinel.name_calls == 0

        depth_root = tmp_path / "observation-depth"
        depth_child = depth_root / "child"
        depth_child.mkdir(parents=True)

        class DepthSentinelEntry:
            name_calls = 0

            @property
            def name(self) -> str:
                self.name_calls += 1
                raise AssertionError("LIMIT_DEPTH_NAME_ORACLE")

        depth_sentinel = DepthSentinelEntry()

        def depth_scandir(path: object) -> object:
            if Path(path) == depth_child:
                return iter((depth_sentinel,))
            return real_scandir(path)

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_SCANDIR", depth_scandir)
            with pytest.raises(PrivacyScanError) as depth_error:
                _scanner(
                    limits=replace(DEFAULT_SCAN_LIMITS, max_depth=1)
                ).scan_paths([depth_root])
        _assert_slice7_safe_error(
            depth_error.value,
            "SCAN_LIMIT_DEPTH",
            sensitive=(depth_root, depth_child, "LIMIT_DEPTH_NAME_ORACLE"),
        )
        assert depth_sentinel.name_calls == 0

        native_root = tmp_path / ("observation-native-" + "x" * 30)
        native_nested = native_root / "nested"
        native_nested.mkdir(parents=True)
        native_payload = native_nested / "payload.txt"
        native_payload.write_bytes(b"plain")
        native_relative = native_payload.relative_to(native_root)
        native_bytes = os.fsencode(os.fspath(native_relative))
        native_events: list[str] = []
        native_arguments: list[Path] = []

        def observed_native_owner(
            path: Path,
            path_key: str,
            file_roots: Mapping[str, privacy_scan_module._ExplicitRoot],
            directory_roots: Mapping[str, privacy_scan_module._ExplicitRoot],
            max_depth: int,
        ) -> privacy_scan_module._ExplicitRoot:
            native_events.append("owner")
            return real_owner(
                path,
                path_key,
                file_roots,
                directory_roots,
                max_depth,
            )

        def observed_native(relative: Path, limits: ScanLimits) -> bytes:
            native_events.append("native")
            native_arguments.append(relative)
            return real_native(relative, limits)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_most_specific_owner",
                observed_native_owner,
            )
            patch.setattr(
                privacy_scan_module,
                "_validated_native_relative",
                observed_native,
            )
            native_exact = _scanner(
                limits=replace(
                    DEFAULT_SCAN_LIMITS,
                    max_native_relative_bytes=len(native_bytes),
                )
            ).scan_paths([native_root])
        assert native_exact.report.hit_count == 0
        assert native_events == ["owner", "native"]
        assert native_arguments == [native_relative]
        assert not native_arguments[0].is_absolute()
        assert len(os.fsencode(os.fspath(native_payload))) > len(native_bytes)

        native_events.clear()
        native_arguments.clear()
        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_most_specific_owner",
                observed_native_owner,
            )
            patch.setattr(
                privacy_scan_module,
                "_validated_native_relative",
                observed_native,
            )
            with pytest.raises(PrivacyScanError) as native_error:
                _scanner(
                    limits=replace(
                        DEFAULT_SCAN_LIMITS,
                        max_native_relative_bytes=len(native_bytes) - 1,
                    )
                ).scan_paths([native_root])
        _assert_slice7_safe_error(
            native_error.value,
            "SCAN_LIMIT_NATIVE_RELATIVE_BYTES",
            sensitive=(native_root, native_payload, native_relative),
        )
        assert native_events == ["owner", "native"]
        assert native_arguments == [native_relative]

        real_fstat = privacy_scan_module._FSTAT
        real_read = privacy_scan_module._READ
        real_lstat = privacy_scan_module._LSTAT
        real_emit_content_window = privacy_scan_module._emit_content_window

        def assert_stream_limit(
            field_name: str,
            expected_code: str,
        ) -> None:
            stream_path = tmp_path / f"observation-{field_name}.bin"
            stream_path.write_bytes(b"abcde")
            trusted_size = 4
            target_descriptors: set[int] = set()
            read_calls = 0
            window_calls = 0

            def stream_lstat(path: object) -> object:
                status = real_lstat(path)
                if Path(path) == stream_path:
                    return TestScannerFileRaceAdversarial._changed_status(
                        status,
                        st_size=trusted_size,
                    )
                return status

            def stream_open(path: Path) -> int:
                descriptor = real_open(path)
                if path == stream_path:
                    target_descriptors.add(descriptor)
                return descriptor

            def stream_fstat(descriptor: int) -> object:
                status = real_fstat(descriptor)
                if descriptor in target_descriptors:
                    return TestScannerFileRaceAdversarial._changed_status(
                        status,
                        st_size=trusted_size,
                    )
                return status

            def short_read(descriptor: int, size: int) -> bytes:
                nonlocal read_calls
                if descriptor in target_descriptors:
                    read_calls += 1
                    return real_read(descriptor, min(size, 1))
                return real_read(descriptor, size)

            def counted_emit_content_window(
                **kwargs: object,
            ) -> None:
                nonlocal window_calls
                window_calls += 1
                real_emit_content_window(**kwargs)  # type: ignore[arg-type]

            limits = replace(
                DEFAULT_SCAN_LIMITS,
                **{field_name: trusted_size},
            )
            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_LSTAT",
                    stream_lstat,
                )
                patch.setattr(
                    privacy_scan_module,
                    "_open_scan_descriptor",
                    stream_open,
                )
                patch.setattr(privacy_scan_module, "_FSTAT", stream_fstat)
                patch.setattr(privacy_scan_module, "_READ", short_read)
                patch.setattr(
                    privacy_scan_module,
                    "_emit_content_window",
                    counted_emit_content_window,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    _scanner(limits=limits).scan_paths([stream_path])
            _assert_slice7_safe_error(
                captured.value,
                expected_code,
                sensitive=(stream_path, b"abcde"),
            )
            assert read_calls == trusted_size + 1
            assert window_calls == trusted_size

        assert_stream_limit("max_file_bytes", "SCAN_LIMIT_FILE_BYTES")
        assert_stream_limit("max_total_bytes", "SCAN_LIMIT_TOTAL_BYTES")

        hit_path = tmp_path / "observation-hits.txt"
        occurrence = b"observation" + b"@" + b"example.test"
        hit_path.write_bytes(occurrence + b" " + occurrence)
        real_hit_hash = privacy_scan_module._hit_hash
        real_hit_type = privacy_scan_module.PrivacyHit
        hash_calls: list[bytes] = []
        hit_constructions: list[str] = []

        def counted_hit_hash(
            scan_key: bytes,
            rule_id: bytes,
            matched: bytes,
        ) -> str:
            hash_calls.append(matched)
            return real_hit_hash(scan_key, rule_id, matched)

        def counted_hit(*args: object, **kwargs: object) -> PrivacyHit:
            hit_constructions.append("hit")
            return real_hit_type(*args, **kwargs)  # type: ignore[arg-type]

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_hit_hash",
                counted_hit_hash,
            )
            patch.setattr(privacy_scan_module, "PrivacyHit", counted_hit)
            with pytest.raises(PrivacyScanError) as hit_error:
                _scanner(
                    limits=replace(DEFAULT_SCAN_LIMITS, max_hits=1)
                ).scan_paths([hit_path])
        _assert_slice7_safe_error(
            hit_error.value,
            "SCAN_LIMIT_HITS",
            sensitive=(hit_path, occurrence),
        )
        assert hash_calls == [occurrence]
        assert hit_constructions == ["hit"]

        catalog_marker = "OBSERVATION-CATALOG-MARKER"
        catalog_raw = _catalog_bytes((catalog_marker,))
        catalog = _write_catalog(
            tmp_path / "observation-catalog.json",
            catalog_raw,
        )
        real_catalog_open = privacy_scan_module._open_catalog_descriptor
        real_parse_catalog = privacy_scan_module._parse_catalog
        catalog_descriptors: set[int] = set()
        catalog_bytes_observed = 0
        parse_calls = 0
        trusted_catalog_size = len(catalog_raw) - 1

        def observed_catalog_lstat(path: object) -> object:
            status = real_lstat(path)
            if Path(path) == catalog:
                return TestScannerFileRaceAdversarial._changed_status(
                    status,
                    st_size=trusted_catalog_size,
                )
            return status

        def observed_catalog_open(path: Path) -> int:
            descriptor = real_catalog_open(path)
            catalog_descriptors.add(descriptor)
            return descriptor

        def observed_catalog_fstat(descriptor: int) -> object:
            status = real_fstat(descriptor)
            if descriptor in catalog_descriptors:
                return TestScannerFileRaceAdversarial._changed_status(
                    status,
                    st_size=trusted_catalog_size,
                )
            return status

        def observed_catalog_read(descriptor: int, size: int) -> bytes:
            nonlocal catalog_bytes_observed
            chunk = real_read(descriptor, size)
            if descriptor in catalog_descriptors:
                catalog_bytes_observed += len(chunk)
            return chunk

        def counted_parse_catalog(
            raw: bytes,
            limits: ScanLimits,
        ) -> object:
            nonlocal parse_calls
            parse_calls += 1
            return real_parse_catalog(raw, limits)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_LSTAT",
                observed_catalog_lstat,
            )
            patch.setattr(
                privacy_scan_module,
                "_open_catalog_descriptor",
                observed_catalog_open,
            )
            patch.setattr(
                privacy_scan_module,
                "_FSTAT",
                observed_catalog_fstat,
            )
            patch.setattr(privacy_scan_module, "_READ", observed_catalog_read)
            patch.setattr(
                privacy_scan_module,
                "_parse_catalog",
                counted_parse_catalog,
            )
            with pytest.raises(PrivacyScanError) as catalog_error:
                PrivacyScanner.default(
                    profile="repo_tracked",
                    canary_definition_path=catalog,
                    hash_key=bytes(range(32)),
                    limits=replace(
                        DEFAULT_SCAN_LIMITS,
                        max_catalog_bytes=len(catalog_raw) - 1,
                    ),
                )
        assert catalog_bytes_observed == len(catalog_raw)
        assert parse_calls == 0
        _assert_slice7_safe_error(
            catalog_error.value,
            "SCAN_LIMIT_CATALOG_BYTES",
            sensitive=(catalog, catalog_marker, catalog_raw),
        )

        real_json_tokens = privacy_scan_module._json_string_tokens

        def assert_catalog_element_limit(
            path: Path,
            limits: ScanLimits,
            expected_code: str,
        ) -> None:
            token_calls = 0

            def counted_json_tokens(raw: bytes) -> object:
                nonlocal token_calls
                token_calls += 1
                return real_json_tokens(raw)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_json_string_tokens",
                    counted_json_tokens,
                )
                with pytest.raises(PrivacyScanError) as captured:
                    PrivacyScanner.default(
                        profile="repo_tracked",
                        canary_definition_path=path,
                        hash_key=bytes(range(32)),
                        limits=limits,
                    )
            _assert_slice7_safe_error(
                captured.value,
                expected_code,
                sensitive=(path,),
            )
            assert token_calls == 0

        markers_path = _write_catalog(
            tmp_path / "observation-markers.json",
            _catalog_bytes(("MARKER-A", "MARKER-B")),
        )
        assert_catalog_element_limit(
            markers_path,
            replace(DEFAULT_SCAN_LIMITS, max_markers=1),
            "SCAN_LIMIT_MARKERS",
        )
        marker_bytes_path = _write_catalog(
            tmp_path / "observation-marker-bytes.json",
            _catalog_bytes(("AB",)),
        )
        assert_catalog_element_limit(
            marker_bytes_path,
            replace(DEFAULT_SCAN_LIMITS, max_marker_bytes=1),
            "SCAN_LIMIT_MARKER_BYTES",
        )

    def test_scan_44_raw_input_limit_precedes_item_inspection(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        valid = tmp_path / "raw-limit.txt"
        valid.write_bytes(b"plain")

        class Sentinel:
            fspath_calls = 0

            def __fspath__(self) -> str:
                self.fspath_calls += 1
                raise AssertionError("RAW_LIMIT_SENTINEL_INSPECTED")

        sentinel = Sentinel()

        class HostileSequence(Sequence[Path]):
            def __init__(self, values: tuple[object, ...]) -> None:
                self.values = values
                self.fetches: list[int] = []
                self.len_calls = 0

            def __len__(self) -> int:
                self.len_calls += 1
                raise AssertionError("RAW_LIMIT_LEN_INSPECTED")

            def __getitem__(self, index: int) -> Path:
                self.fetches.append(index)
                if index >= len(self.values):
                    raise IndexError
                return cast(Path, self.values[index])

        sequence = HostileSequence((valid, valid, sentinel))
        observed_items: list[object] = []
        real_root_observation = privacy_scan_module._root_observation

        def counted_root_observation(item: object) -> object:
            observed_items.append(item)
            return real_root_observation(item)

        scanner = _scanner(
            limits=replace(DEFAULT_SCAN_LIMITS, max_input_paths=2)
        )
        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_root_observation",
                counted_root_observation,
            )
            with pytest.raises(PrivacyScanError) as captured:
                scanner.scan_paths(sequence)
        _assert_slice7_safe_error(
            captured.value,
            "SCAN_LIMIT_INPUT_PATHS",
            sensitive=(
                valid,
                "RAW_LIMIT_SENTINEL_INSPECTED",
                "RAW_LIMIT_LEN_INSPECTED",
            ),
        )
        assert sequence.fetches == [0, 1, 2]
        assert sequence.len_calls == 0
        assert observed_items == [valid, valid]
        assert sentinel.fspath_calls == 0
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None


class TestScannerConcurrencyAdversarial:
    def test_scan_38_all_lock_contention_and_reentry(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "lock-contention.txt"
        payload.write_bytes(b"lock-contention" + b"@" + b"example.test")
        real_operation_lock = privacy_scan_module._operation_lock_for

        def assert_winner(winner_name: str) -> None:
            scanner = _scanner()
            current = scanner.scan_paths([payload])
            current_ref = current.report.hits[0].location_ref
            generation_before = object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            )
            entered = threading.Event()
            release = threading.Event()
            winner_ident: list[int] = []
            winner_results: list[object] = []
            winner_errors: list[BaseException] = []

            def blocking_operation_lock(
                scanner_object: object,
                invalid_code: str,
            ) -> object:
                lock = real_operation_lock(scanner_object, invalid_code)
                if winner_ident and threading.get_ident() == winner_ident[0]:
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("LOCK_WINNER_RELEASE_TIMEOUT")
                return lock

            def run_winner() -> None:
                winner_ident.append(threading.get_ident())
                try:
                    if winner_name == "scan":
                        winner_results.append(scanner.scan_paths([payload]))
                    elif winner_name == "resolve":
                        winner_results.append(
                            scanner.resolve_location(
                                current.resolution_handle,
                                current_ref,
                            )
                        )
                    else:
                        winner_results.append(scanner.close())
                except BaseException as error:
                    winner_errors.append(error)

            with monkeypatch.context() as patch:
                patch.setattr(
                    privacy_scan_module,
                    "_operation_lock_for",
                    blocking_operation_lock,
                )
                worker = threading.Thread(target=run_winner)
                worker.start()
                assert entered.wait(timeout=5)
                assert object.__getattribute__(
                    scanner,
                    "_PrivacyScanner__generation",
                ) is generation_before
                losing_codes: list[str] = []
                for operation in (
                    lambda: scanner.scan_paths([payload]),
                    lambda: scanner.resolve_location(
                        current.resolution_handle,
                        current_ref,
                    ),
                    scanner.close,
                ):
                    with pytest.raises(PrivacyScanError) as losing:
                        operation()
                    _assert_slice7_safe_error(
                        losing.value,
                        "SCAN_CONCURRENT_USE",
                        sensitive=(
                            payload,
                            current_ref,
                            current.resolution_handle,
                        ),
                    )
                    losing_codes.append(losing.value.code)
                assert losing_codes == ["SCAN_CONCURRENT_USE"] * 3
                assert object.__getattribute__(
                    scanner,
                    "_PrivacyScanner__generation",
                ) is generation_before
                release.set()
                worker.join(timeout=5)
                assert not worker.is_alive()
            assert winner_errors == []
            assert len(winner_results) == 1
            generation_after = object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            )
            if winner_name == "scan":
                assert generation_after is not generation_before
                assert isinstance(winner_results[0], PrivacyScanOutcome)
            elif winner_name == "resolve":
                assert generation_after is generation_before
                assert winner_results == [payload]
            else:
                assert generation_after is None
                assert winner_results == [None]

        for winner_name in ("scan", "resolve", "close"):
            assert_winner(winner_name)

        scanner = _scanner()
        current = scanner.scan_paths([payload])
        current_ref = current.report.hits[0].location_ref
        reentry_started = False
        reentry_codes: list[str] = []

        def reentrant_operation_lock(
            scanner_object: object,
            invalid_code: str,
        ) -> object:
            nonlocal reentry_started
            lock = real_operation_lock(scanner_object, invalid_code)
            if reentry_started:
                return lock
            reentry_started = True
            for operation in (
                lambda: scanner.scan_paths([payload]),
                lambda: scanner.resolve_location(
                    current.resolution_handle,
                    current_ref,
                ),
                scanner.close,
            ):
                with pytest.raises(PrivacyScanError) as captured:
                    operation()
                _assert_slice7_safe_error(
                    captured.value,
                    "SCAN_CONCURRENT_USE",
                    sensitive=(payload, current_ref, current.resolution_handle),
                )
                reentry_codes.append(captured.value.code)
            return lock

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_operation_lock_for",
                reentrant_operation_lock,
            )
            completed = scanner.scan_paths([payload])
        assert completed.report.hit_count == 1
        assert reentry_started
        assert reentry_codes == ["SCAN_CONCURRENT_USE"] * 3

    def test_scan_39_success_failure_commit_interleavings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "commit-interleaving.txt"
        payload.write_bytes(b"commit-interleaving" + b"@" + b"example.test")
        scanner = _scanner()
        previous = scanner.scan_paths([payload])
        previous_ref = previous.report.hits[0].location_ref
        real_issue = privacy_scan_module._issue_resolution_handle
        real_close_records = privacy_scan_module._close_directory_records
        real_catalog_check = privacy_scan_module._scan_catalog_check
        issue_entered = threading.Event()
        issue_release = threading.Event()
        issue_calls: list[int] = []
        success_events: list[str] = []
        issue_event_prefixes: list[tuple[str, ...]] = []
        catalog_check_calls = 0
        worker_outcomes: list[PrivacyScanOutcome] = []
        worker_errors: list[BaseException] = []

        def ordered_close_records(
            records: tuple[privacy_scan_module._DirectoryRecord, ...],
            limits: ScanLimits,
            tree_observations: list[int],
        ) -> None:
            real_close_records(records, limits, tree_observations)
            success_events.append("close")

        def ordered_catalog_check(
            binding: object,
            limits: ScanLimits,
        ) -> None:
            nonlocal catalog_check_calls
            catalog_check_calls += 1
            real_catalog_check(binding, limits)
            success_events.append(
                "catalog_pre" if catalog_check_calls == 1 else "catalog_post"
            )

        def blocking_issue() -> ScanResolutionHandle:
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            issue_event_prefixes.append(tuple(success_events))
            success_events.append("issue")
            issue_calls.append(len(issue_calls) + 1)
            issue_entered.set()
            if not issue_release.wait(timeout=5):
                raise AssertionError("ISSUE_RELEASE_TIMEOUT")
            return real_issue()

        def run_scan() -> None:
            try:
                worker_outcomes.append(scanner.scan_paths([payload]))
            except BaseException as error:
                worker_errors.append(error)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_close_directory_records",
                ordered_close_records,
            )
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                ordered_catalog_check,
            )
            patch.setattr(
                privacy_scan_module,
                "_issue_resolution_handle",
                blocking_issue,
            )
            worker = threading.Thread(target=run_scan)
            worker.start()
            assert issue_entered.wait(timeout=5)
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is None
            with pytest.raises(PrivacyScanError) as contended:
                scanner.resolve_location(
                    previous.resolution_handle,
                    previous_ref,
                )
            _assert_slice7_safe_error(
                contended.value,
                "SCAN_CONCURRENT_USE",
                sensitive=(payload, previous_ref, previous.resolution_handle),
            )
            issue_release.set()
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert worker_errors == []
        assert issue_calls == [1]
        assert issue_event_prefixes == [
            ("catalog_pre", "close", "catalog_post")
        ], "HANDLE_ISSUE_BEFORE_CATALOG_POST"
        assert success_events == [
            "catalog_pre",
            "close",
            "catalog_post",
            "issue",
        ]
        assert len(worker_outcomes) == 1
        committed = worker_outcomes[0]
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert generation.handle is committed.resolution_handle

        def failing_issue() -> ScanResolutionHandle:
            raise RuntimeError("CALLER_ORACLE_ISSUE")

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_issue_resolution_handle",
                failing_issue,
            )
            with pytest.raises(PrivacyScanError) as issue_failure:
                scanner.scan_paths([payload])
        _assert_slice7_safe_error(
            issue_failure.value,
            "SCAN_INPUT_INVALID",
            sensitive=(payload, "CALLER_ORACLE_ISSUE"),
        )
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None

        real_outcome = privacy_scan_module.PrivacyScanOutcome

        def failing_outcome(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise RuntimeError("CALLER_ORACLE_OUTCOME")

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "PrivacyScanOutcome",
                failing_outcome,
            )
            with pytest.raises(PrivacyScanError) as outcome_failure:
                scanner.scan_paths([payload])
        _assert_slice7_safe_error(
            outcome_failure.value,
            "SCAN_INPUT_INVALID",
            sensitive=(payload, "CALLER_ORACLE_OUTCOME"),
        )
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is None
        assert privacy_scan_module.PrivacyScanOutcome is real_outcome

        recovery_checks: list[int] = []
        recovery_handles: list[ScanResolutionHandle] = []

        def counted_catalog_check(binding: object, limits: ScanLimits) -> None:
            recovery_checks.append(len(recovery_checks) + 1)
            real_catalog_check(binding, limits)

        def counted_issue() -> ScanResolutionHandle:
            handle = real_issue()
            recovery_handles.append(handle)
            return handle

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_scan_catalog_check",
                counted_catalog_check,
            )
            patch.setattr(
                privacy_scan_module,
                "_issue_resolution_handle",
                counted_issue,
            )
            empty = scanner.scan_paths([])
        assert empty.report == PrivacyScanReport(hits=())
        assert recovery_checks == [1, 2]
        assert recovery_handles == [empty.resolution_handle]
        empty_generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        assert empty_generation.handle is empty.resolution_handle
        assert dict(empty_generation.mapping) == {}


class TestScannerCapabilityAdversarial:
    def test_scan_31_redaction_copy_pickle_and_logs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret = "CALLER_ORACLE_SECRET_71D2"
        root = tmp_path / f"private-{secret}"
        root.mkdir()
        payload = root / f"payload-{secret}.txt"
        payload_raw = (secret + "@example.test").encode("ascii")
        payload.write_bytes(payload_raw)
        scanner = _scanner()
        outcome = scanner.scan_paths([root])
        hit = outcome.report.hits[0]
        assert repr(scanner) == "<PrivacyScanner redacted>"
        assert repr(outcome) == "<PrivacyScanOutcome redacted>"
        assert repr(outcome.resolution_handle) == (
            "<ScanResolutionHandle redacted>"
        )

        for value in (scanner, outcome, outcome.resolution_handle):
            for operation in (
                lambda value=value: copy.copy(value),
                lambda value=value: copy.deepcopy(value),
                lambda value=value: pickle.dumps(value),
            ):
                with pytest.raises(TypeError) as captured:
                    operation()
                _assert_slice7_safe_error(
                    captured.value,
                    "SCAN_SERIALIZATION_FORBIDDEN",
                    sensitive=(value,),
                )

        for value in (outcome.report, hit):
            assert copy.copy(value) == value
            assert copy.deepcopy(value) == value
            assert pickle.loads(pickle.dumps(value)) == value

        real_lstat = privacy_scan_module._LSTAT

        def failing_lstat(path: object) -> object:
            if Path(path) == payload:
                raise OSError(secret)
            return real_lstat(path)

        failure_cases: list[tuple[str, PrivacyScanError]] = []
        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_LSTAT", failing_lstat)
            with pytest.raises(PrivacyScanError) as captured:
                _scanner().scan_paths([payload])
        failure_cases.append(("SCAN_UNREADABLE", captured.value))

        real_open = privacy_scan_module._open_scan_descriptor
        real_read = privacy_scan_module._READ
        target_descriptors: set[int] = set()

        def capture_open(path: Path) -> int:
            descriptor = real_open(path)
            if path == payload:
                target_descriptors.add(descriptor)
            return descriptor

        def failing_read(descriptor: int, size: int) -> bytes:
            if descriptor in target_descriptors:
                raise OSError(secret)
            return real_read(descriptor, size)

        with monkeypatch.context() as patch:
            patch.setattr(
                privacy_scan_module,
                "_open_scan_descriptor",
                capture_open,
            )
            patch.setattr(privacy_scan_module, "_READ", failing_read)
            with pytest.raises(PrivacyScanError) as captured:
                _scanner().scan_paths([payload])
        failure_cases.append(("SCAN_FILE_CHANGED", captured.value))

        real_scandir = privacy_scan_module._SCANDIR

        def failing_scandir(path: object) -> object:
            if Path(path) == root:
                raise OSError(secret)
            return real_scandir(path)

        with monkeypatch.context() as patch:
            patch.setattr(privacy_scan_module, "_SCANDIR", failing_scandir)
            with pytest.raises(PrivacyScanError) as captured:
                _scanner().scan_paths([root])
        failure_cases.append(("SCAN_TREE_CHANGED", captured.value))

        public_log = caplog.text
        for expected_code, error in failure_cases:
            _assert_slice7_safe_error(
                error,
                expected_code,
                sensitive=(secret, root, payload, payload_raw),
            )
        assert caplog.records == []
        assert secret not in public_log
        assert os.fspath(payload) not in public_log
        assert payload_raw.decode("ascii") not in public_log

    def test_scan_43_forged_subclass_foreign_and_unknown_handles(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "capability.txt"
        payload.write_bytes(b"capability" + b"@" + b"example.test")
        scanner = _scanner()
        stale = scanner.scan_paths([payload])
        current = scanner.scan_paths([payload])
        current_ref = current.report.hits[0].location_ref
        stale_ref = stale.report.hits[0].location_ref
        foreign_scanner = _scanner()
        foreign = foreign_scanner.scan_paths([payload])

        with pytest.raises(TypeError) as direct:
            ScanResolutionHandle()
        _assert_slice7_safe_error(
            direct.value,
            "SCAN_LOCATION_UNAVAILABLE",
        )

        class HandleSubclass(ScanResolutionHandle):  # type: ignore[misc]
            def __eq__(self, other: object) -> bool:
                del other
                return True

            def __ne__(self, other: object) -> bool:
                del other
                return False

        forged = object.__new__(ScanResolutionHandle)
        subclass_forged = object.__new__(HandleSubclass)
        unknown_issued = privacy_scan_module._issue_resolution_handle()

        class NonExactRef(str):
            pass

        invalid_capabilities = (
            (forged, current_ref),
            (subclass_forged, current_ref),
            (unknown_issued, current_ref),
            (stale.resolution_handle, stale_ref),
            (foreign.resolution_handle, current_ref),
            (object(), current_ref),
            (current.resolution_handle, "root_0001/pth1_" + "f" * 64),
            (current.resolution_handle, NonExactRef(current_ref)),
            (current.resolution_handle, None),
        )
        generation = object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        )
        for handle, location_ref in invalid_capabilities:
            with pytest.raises(PrivacyScanError) as captured:
                scanner.resolve_location(  # type: ignore[arg-type]
                    handle,
                    location_ref,
                )
            _assert_slice7_safe_error(
                captured.value,
                "SCAN_LOCATION_UNAVAILABLE",
                sensitive=(payload, handle, location_ref),
            )
            assert object.__getattribute__(
                scanner,
                "_PrivacyScanner__generation",
            ) is generation
            assert scanner.resolve_location(
                current.resolution_handle,
                current_ref,
            ) == payload

        def handles_equal(self: object, other: object) -> bool:
            del self, other
            return True

        def handles_not_equal(self: object, other: object) -> bool:
            del self, other
            return False

        with monkeypatch.context() as patch:
            patch.setattr(
                ScanResolutionHandle,
                "__eq__",
                handles_equal,
                raising=False,
            )
            patch.setattr(
                ScanResolutionHandle,
                "__ne__",
                handles_not_equal,
                raising=False,
            )
            with pytest.raises(PrivacyScanError) as identity_only:
                scanner.resolve_location(forged, current_ref)
        _assert_slice7_safe_error(
            identity_only.value,
            "SCAN_LOCATION_UNAVAILABLE",
            sensitive=(payload, forged, current_ref),
        )
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is generation

        subclass_generation = privacy_scan_module._Generation(
            handle=subclass_forged,
            mapping=types.MappingProxyType({current_ref: payload}),
        )
        object.__setattr__(
            scanner,
            "_PrivacyScanner__generation",
            subclass_generation,
        )
        with pytest.raises(PrivacyScanError) as exact_type_only:
            scanner.resolve_location(subclass_forged, current_ref)
        _assert_slice7_safe_error(
            exact_type_only.value,
            "SCAN_LOCATION_UNAVAILABLE",
            sensitive=(payload, subclass_forged, current_ref),
        )
        assert object.__getattribute__(
            scanner,
            "_PrivacyScanner__generation",
        ) is subclass_generation
        object.__setattr__(
            scanner,
            "_PrivacyScanner__generation",
            generation,
        )
        assert scanner.resolve_location(
            current.resolution_handle,
            current_ref,
        ) == payload


class TestScannerHmacContract:
    def test_scan_16_fixed_hit_and_location_vectors(self) -> None:
        scan_key = bytes(range(32))
        limits_bytes = (
            b"inputs=100000;roots=50000;tree_entries=500000;files=100000;"
            b"depth=64;native=32768;file=1073741824;total=8589934592;"
            b"hits=10000;catalog=65536;markers=256;marker_bytes=128;"
            b"chunk=65536;carry=512"
        )

        assert privacy_scan_module._frame_parts(b"a", b"bc") == (
            b"\x00\x00\x00\x00\x00\x00\x00\x01a"
            b"\x00\x00\x00\x00\x00\x00\x00\x02bc"
        )
        assert privacy_scan_module._limits_canonical_bytes(
            DEFAULT_SCAN_LIMITS
        ) == limits_bytes
        assert privacy_scan_module._hit_hash(
            scan_key,
            b"forbidden_path_suffix",
            b".db",
        ) == "82d9fd66db590f5ae51c31f30703402390bca544a8194cd4355e771020a1c3b1"
        location_ref = privacy_scan_module._location_ref(
            scan_key,
            b"repo_tracked",
            b"root_0001",
            limits_bytes,
            b"/synthetic/root",
            b"docs/readme.md",
        )
        assert location_ref == (
            "root_0001/"
            "pth1_39e668170e93ac9298ab787ae762272ad1d50f5d71e8ac1201a5cff85bf91a9a"
        )
        assert re.fullmatch(
            r"root_[0-9]{4,}/pth1_[0-9a-f]{64}",
            location_ref,
        )

        assert privacy_scan_module._hit_hash(
            scan_key,
            b"email_address",
            b".db",
        ) != privacy_scan_module._hit_hash(
            scan_key,
            b"forbidden_path_suffix",
            b".db",
        )
        assert privacy_scan_module._hit_hash(
            scan_key,
            b"forbidden_path_suffix",
            b".sqlite3",
        ) != privacy_scan_module._hit_hash(
            scan_key,
            b"forbidden_path_suffix",
            b".db",
        )
        assert privacy_scan_module._frame_parts(b"a", b"bc") != (
            privacy_scan_module._frame_parts(b"ab", b"c")
        )

        limit_mutations = {
            "max_input_paths": DEFAULT_SCAN_LIMITS.max_input_paths + 1,
            "max_roots": DEFAULT_SCAN_LIMITS.max_roots + 1,
            "max_tree_entries": DEFAULT_SCAN_LIMITS.max_tree_entries + 1,
            "max_files": DEFAULT_SCAN_LIMITS.max_files + 1,
            "max_depth": DEFAULT_SCAN_LIMITS.max_depth + 1,
            "max_native_relative_bytes": (
                DEFAULT_SCAN_LIMITS.max_native_relative_bytes - 1
            ),
            "max_file_bytes": DEFAULT_SCAN_LIMITS.max_file_bytes + 1,
            "max_total_bytes": DEFAULT_SCAN_LIMITS.max_total_bytes + 1,
            "max_hits": DEFAULT_SCAN_LIMITS.max_hits + 1,
            "max_catalog_bytes": DEFAULT_SCAN_LIMITS.max_catalog_bytes - 1,
            "max_markers": DEFAULT_SCAN_LIMITS.max_markers - 1,
            "max_marker_bytes": DEFAULT_SCAN_LIMITS.max_marker_bytes - 1,
        }
        for field_name, value in limit_mutations.items():
            changed_limits_bytes = privacy_scan_module._limits_canonical_bytes(
                replace(DEFAULT_SCAN_LIMITS, **{field_name: value})
            )
            assert changed_limits_bytes != limits_bytes
            assert privacy_scan_module._location_ref(
                scan_key,
                b"repo_tracked",
                b"root_0001",
                changed_limits_bytes,
                b"/synthetic/root",
                b"docs/readme.md",
            ) != location_ref

        changed_parts = (
            (
                b"shared_derivative",
                b"root_0001",
                b"/synthetic/root",
                b"docs/readme.md",
            ),
            (
                b"repo_tracked",
                b"root_0002",
                b"/synthetic/root",
                b"docs/readme.md",
            ),
            (
                b"repo_tracked",
                b"root_0001",
                b"/synthetic/other",
                b"docs/readme.md",
            ),
            (
                b"repo_tracked",
                b"root_0001",
                b"/synthetic/root",
                b"docs/other.md",
            ),
        )
        for profile, root_label, owner_identity, native_relative in changed_parts:
            assert privacy_scan_module._location_ref(
                scan_key,
                profile,
                root_label,
                limits_bytes,
                owner_identity,
                native_relative,
            ) != location_ref


class TestScannerRulePrimitives:
    def test_mobile_rule_primitives(self) -> None:
        assert privacy_scan_module._CN_MOBILE_NUMBER_PATTERN.pattern == (
            rb"(?<![0-9A-Za-z])(?:(?:\+86|0086)[ -]?)?1[3-9][0-9]"
            rb"(?:[ -]?[0-9]){8}(?![0-9A-Za-z])"
        )
        plain = "".join(("138", "0013", "8000")).encode("ascii")
        prefixed = b"+86 " + plain
        separated = b"0086-" + b"138-" + b"0013-" + b"8000"
        assert privacy_scan_module._candidate_matches(
            "cn_mobile_number",
            plain,
        ) == (plain,)
        assert privacy_scan_module._candidate_matches(
            "cn_mobile_number",
            b"x " + prefixed + b" y " + separated,
        ) == (prefixed, separated)
        assert privacy_scan_module._candidate_matches(
            "cn_mobile_number",
            b"A" + plain + b" sha256:" + b"a" * 64 + plain + b"Z",
        ) == ()
        assert privacy_scan_module._candidate_matches(
            "cn_mobile_number",
            "".join(("128", "0013", "8000")).encode("ascii"),
        ) == ()

    def test_resident_id_rule_primitives(self) -> None:
        assert privacy_scan_module._CN_RESIDENT_ID_PATTERN.pattern == (
            rb"(?<![0-9A-Za-z])[1-9][0-9]{5}(?:18|19|20)[0-9]{2}"
            rb"(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])"
            rb"[0-9]{3}[0-9Xx](?![0-9A-Za-z])"
        )
        valid_x = "".join(("110105", "1990", "0101", "123X")).encode(
            "ascii"
        )
        valid_digit = "".join(("320311", "2001", "1231", "4567")).encode(
            "ascii"
        )
        assert privacy_scan_module._candidate_matches(
            "cn_resident_id",
            valid_x + b" " + valid_digit,
        ) == (valid_x, valid_digit)
        invalid_values = (
            "".join(("010105", "1990", "0101", "123X")),
            "".join(("110105", "1790", "0101", "123X")),
            "".join(("110105", "1990", "1301", "123X")),
            "".join(("110105", "1990", "0100", "123X")),
            "".join(("110105", "900101", "123")),
        )
        for invalid in invalid_values:
            assert privacy_scan_module._candidate_matches(
                "cn_resident_id",
                invalid.encode("ascii"),
            ) == ()
        fullwidth = "".join(("１１０１０５", "１９９０", "０１０１", "１２３Ｘ"))
        assert privacy_scan_module._candidate_matches(
            "cn_resident_id",
            fullwidth.encode("utf-8"),
        ) == ()

    def test_email_rule_primitives(self) -> None:
        assert privacy_scan_module._EMAIL_ADDRESS_PATTERN.pattern == (
            rb"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
            rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
            rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            rb"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
            rb"(?![A-Za-z0-9.-])"
        )
        valid = b"first.last+tag" + b"@" + b"example-domain.co.uk"
        assert privacy_scan_module._candidate_matches(
            "email_address",
            valid,
        ) == (valid,)
        invalid_values = (
            b".leading@example.com",
            b"trailing.@example.com",
            b"two..dots@example.com",
            b"plain@example",
            b"name@-example.com",
            b"name@example-.com",
            b"a" * 65 + b"@example.com",
            b"a" * 64
            + b"@"
            + b".".join((b"b" * 63, b"c" * 63, b"d" * 63, b"e" * 63)),
        )
        for invalid in invalid_values:
            assert privacy_scan_module._candidate_matches(
                "email_address",
                invalid,
            ) == ()

    def test_stable_id_rule_primitives(self) -> None:
        assert privacy_scan_module._STABLE_CLIENT_ID_PATTERN.pattern == (
            rb"(?i:client_[a-z0-9]{12})"
        )
        lower = b"client_" + b"a1b2" + b"c3d4" + b"e5f6"
        mixed = b"CLIENT_" + b"A1b2" + b"C3d4" + b"E5f6"
        assert privacy_scan_module._candidate_matches(
            "stable_client_id",
            b"prefix" + lower + b"suffix " + mixed,
        ) == (lower, mixed)
        assert privacy_scan_module._candidate_matches(
            "stable_client_id",
            lower + b"z",
        ) == (lower,)
        assert privacy_scan_module._candidate_matches(
            "stable_client_id",
            b"client_" + b"a1b2" + b"c3-d" + b"e5f6",
        ) == ()
        assert privacy_scan_module._candidate_matches(
            "stable_client_id",
            privacy_scan_module._STABLE_CLIENT_ID_PATTERN.pattern,
        ) == ()

    def test_canary_rule_primitives(self) -> None:
        marker_a = b"-".join((b"SYNTH", b"MARKER", b"ALPHA", b"9F3A"))
        marker_b = b"-".join((b"SYNTH", b"MARKER", b"BETA", b"71D2"))
        assert privacy_scan_module._canary_matches(
            b"before " + marker_a + b" middle " + marker_b + b" " + marker_a,
            (marker_a, marker_b),
        ) == (marker_a, marker_b, marker_a)
        assert privacy_scan_module._canary_matches(
            marker_a.lower(),
            (marker_a, marker_b),
        ) == ()

    def test_suffix_profile_primitives(self) -> None:
        prohibited = (
            (b"catalog.sqlite3", b".sqlite3"),
            (b"catalog.SQLITE3-WAL", b".SQLITE3-WAL"),
            (b"catalog.sqlite3-shm", b".sqlite3-shm"),
            (b"catalog.sqlite3-journal", b".sqlite3-journal"),
            (b"cache.db", b".db"),
            (b"cache.DB-WAL", b".DB-WAL"),
            (b"cache.db-shm", b".db-shm"),
            (b"cache.db-journal", b".db-journal"),
            (b"IDENTITY-MAP.ENC", b"IDENTITY-MAP.ENC"),
        )
        allowed = (
            b"vectors.npy",
            b"other.enc",
            b"current.json",
            b"current.md",
            b"temporal.json",
            b"cache.db.backup",
            b"folder.db/name.txt",
        )
        for profile in ("repo_tracked", "shared_derivative"):
            for basename, exact_match in prohibited:
                assert privacy_scan_module._forbidden_suffix_match(
                    profile,
                    basename,
                ) == exact_match
            for basename in allowed:
                assert privacy_scan_module._forbidden_suffix_match(
                    profile,
                    basename,
                ) is None
