from __future__ import annotations

import ast
import copy
import dataclasses
import json
import logging
import os
import pickle
import stat
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from consultation_kb.core import config as config_contracts
from consultation_kb.core.config import (
    SCOPE_AUTOMATIC_FORMAL_WRITEBACK,
    SCOPE_INTERACTION_MODE,
    SCOPE_RUNTIME_NETWORK_INGEST,
    SCOPE_SINGLE_COUNSELOR,
    AppConfig,
    ConfigurationError,
)
from consultation_kb.vault.layout import VaultLayout


def _forbidden_config_acquisitions(source: str) -> tuple[int, ...]:
    tree = ast.parse(source)
    class_names = {"AppConfig"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "consultation_kb.core.config":
            continue
        for imported in node.names:
            if imported.name == "AppConfig":
                class_names.add(imported.asname or imported.name)

    findings: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and function.id in class_names:
            findings.append(node.lineno)
        elif isinstance(function, ast.Attribute) and function.attr == "AppConfig":
            findings.append(node.lineno)
        elif isinstance(function, ast.Attribute) and function.attr == "from_values":
            owner = function.value
            if (
                isinstance(owner, ast.Name)
                and owner.id in class_names
                or isinstance(owner, ast.Attribute)
                and owner.attr == "AppConfig"
            ):
                findings.append(node.lineno)
    return tuple(sorted(findings))


def _real_roots(tmp_path: Path, *, marker_file: bool = False) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    vault = tmp_path / "vault"
    repo.mkdir(parents=True)
    if marker_file:
        (repo / ".git").write_text("gitdir: synthetic\n", encoding="utf-8")
    else:
        (repo / ".git").mkdir()
    vault.mkdir()
    return repo, vault


def _inject_canonical_result(
    monkeypatch: pytest.MonkeyPatch,
    source_path: Path,
    canonical_result: str,
) -> list[str]:
    real_lexists = os.path.lexists
    real_lstat = os.lstat
    real_realpath = os.path.realpath
    source_identity = os.path.normcase(os.path.normpath(str(source_path)))
    source_drive = os.path.normcase(os.path.splitdrive(str(source_path))[0])
    canonical_drive = os.path.normcase(
        os.path.splitdrive(canonical_result)[0]
    )
    canonical_casefold = os.path.normcase(canonical_result)
    unsafe_observations: list[str] = []

    def is_canonical_tree(value: str | os.PathLike[str]) -> bool:
        raw = os.fspath(value)
        normalized = os.path.normcase(os.path.normpath(raw))
        candidate_drive = os.path.normcase(os.path.splitdrive(raw)[0])
        if canonical_casefold.startswith("\\??\\"):
            return normalized.startswith("\\??")
        if canonical_drive and canonical_drive != source_drive:
            return candidate_drive == canonical_drive
        return "canonical-review-" in normalized

    def injected_realpath(value: str) -> str:
        identity = os.path.normcase(os.path.normpath(value))
        if identity == source_identity:
            return canonical_result
        return real_realpath(value, strict=False)

    def injected_lexists(value: str | os.PathLike[str]) -> bool:
        if is_canonical_tree(value):
            unsafe_observations.append(os.fspath(value))
            return False
        return real_lexists(value)

    def injected_lstat(value: str | os.PathLike[str]) -> os.stat_result:
        if is_canonical_tree(value):
            unsafe_observations.append(os.fspath(value))
            raise FileNotFoundError
        return real_lstat(value)

    monkeypatch.setattr(config_contracts, "_REALPATH", injected_realpath)
    monkeypatch.setattr(config_contracts, "_LEXISTS", injected_lexists)
    monkeypatch.setattr(config_contracts, "_LSTAT", injected_lstat)
    return unsafe_observations


def _assert_configuration_error(
    expected_code: str,
    operation: object,
    *,
    expected_field: str | None = None,
) -> None:
    if not callable(operation):
        raise AssertionError("test operation must be callable")
    expected_message = (
        expected_code
        if expected_field is None
        else f"{expected_code}:{expected_field}"
    )
    with pytest.raises(ConfigurationError) as captured:
        operation()
    assert captured.value.code == expected_code
    assert captured.value.field == expected_field
    assert str(captured.value) == expected_message
    assert repr(captured.value) == f"ConfigurationError('{expected_message}')"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


class TestConfigValueContract:
    @pytest.mark.acceptance_id("CFG-17")
    def test_cfg_17_scope_values_require_exact_types(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        assert SCOPE_INTERACTION_MODE == "codex_text"
        assert type(SCOPE_INTERACTION_MODE) is str
        assert SCOPE_SINGLE_COUNSELOR is True
        assert type(SCOPE_SINGLE_COUNSELOR) is bool
        assert SCOPE_RUNTIME_NETWORK_INGEST is False
        assert type(SCOPE_RUNTIME_NETWORK_INGEST) is bool
        assert SCOPE_AUTOMATIC_FORMAL_WRITEBACK is False
        assert type(SCOPE_AUTOMATIC_FORMAL_WRITEBACK) is bool
        assert [field.name for field in dataclasses.fields(AppConfig)] == [
            "repo_root",
            "vault_root",
            "interaction_mode",
            "single_counselor",
            "runtime_network_ingest",
            "automatic_formal_writeback",
        ]
        assert AppConfig.__slots__ == (
            "repo_root",
            "vault_root",
            "interaction_mode",
            "single_counselor",
            "runtime_network_ingest",
            "automatic_formal_writeback",
        )

        valid = AppConfig(repo_root=repo, vault_root=vault)
        assert dataclasses.is_dataclass(valid)
        assert valid.interaction_mode == "codex_text"
        assert valid.single_counselor is True
        assert valid.runtime_network_ingest is False
        assert valid.automatic_formal_writeback is False
        with pytest.raises(TypeError):
            AppConfig(repo, vault)  # type: ignore[misc]

        invalid_values = (
            ("interaction_mode", "text"),
            ("interaction_mode", 1),
            ("single_counselor", 1),
            ("single_counselor", False),
            ("runtime_network_ingest", 0),
            ("runtime_network_ingest", True),
            ("automatic_formal_writeback", 0),
            ("automatic_formal_writeback", True),
        )
        for field_name, value in invalid_values:
            kwargs: dict[str, object] = {
                "repo_root": repo,
                "vault_root": vault,
                field_name: value,
            }
            _assert_configuration_error(
                "CONFIG_SCOPE_LOCKED",
                lambda kwargs=kwargs: AppConfig(**kwargs),  # type: ignore[arg-type]
                expected_field=field_name,
            )

    @pytest.mark.acceptance_id("CFG-19")
    def test_cfg_19_repr_error_and_log_are_redacted(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        config = AppConfig(repo_root=repo, vault_root=vault)
        assert repr(config) == "<AppConfig redacted>"
        assert str(repo) not in repr(config)
        assert str(vault) not in repr(config)

        with caplog.at_level("ERROR"):
            try:
                AppConfig(
                    repo_root=repo,
                    vault_root=vault,
                    interaction_mode="private-value",  # type: ignore[arg-type]
                )
            except ConfigurationError as error:
                logging.getLogger("config-contract").error("%s", error)
            else:
                raise AssertionError("locked scope value was accepted")
        assert caplog.messages == ["CONFIG_SCOPE_LOCKED:interaction_mode"]
        captured = caplog.text
        for forbidden in (str(repo), str(vault), "private-value"):
            assert forbidden not in captured

        class ExplodingPath:
            def __fspath__(self) -> str:
                raise RuntimeError("PRIVATE_CONTEXT_TOKEN")

        _assert_configuration_error(
            "CONFIG_PATH_TYPE",
            lambda: AppConfig(
                repo_root=ExplodingPath(),  # type: ignore[arg-type]
                vault_root=vault,
            ),
            expected_field="repo_root",
        )

    @pytest.mark.acceptance_id("CFG-24")
    def test_cfg_24_runtime_subclass_seal(self) -> None:
        assert getattr(AppConfig, "__final__", False) is True

        with pytest.raises(TypeError, match="^CONFIG_SUBCLASS_FORBIDDEN$"):

            class ForbiddenConfig(AppConfig):
                def __post_init__(self) -> None:
                    pass

        def body(namespace: dict[str, object]) -> None:
            namespace["__post_init__"] = lambda self: None

        with pytest.raises(TypeError, match="^CONFIG_SUBCLASS_FORBIDDEN$"):
            types.new_class("OtherForbiddenConfig", (AppConfig,), exec_body=body)

        class NonCooperativeBase:
            def __init_subclass__(cls, **kwargs: object) -> None:
                del cls, kwargs

        with pytest.raises(TypeError, match="^CONFIG_SUBCLASS_FORBIDDEN$"):

            class MultipleInheritanceForbidden(NonCooperativeBase, AppConfig):
                def __post_init__(self) -> None:
                    pass

        with pytest.raises(TypeError, match="^CONFIG_SUBCLASS_FORBIDDEN$"):
            types.new_class(
                "OtherMultipleInheritanceForbidden",
                (NonCooperativeBase, AppConfig),
                exec_body=body,
            )


class TestConfigRootContract:
    @pytest.mark.acceptance_id("CFG-01")
    def test_cfg_01_local_sibling_roots(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        before = tuple(sorted(tmp_path.iterdir()))

        config = AppConfig(repo_root=str(repo), vault_root=str(vault))  # type: ignore[arg-type]

        assert config.repo_root == Path(os.path.realpath(repo, strict=False))
        assert config.vault_root == Path(os.path.realpath(vault, strict=False))
        assert isinstance(config.repo_root, Path)
        assert isinstance(config.vault_root, Path)
        assert tuple(sorted(tmp_path.iterdir())) == before
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.repo_root = vault  # type: ignore[misc]

    @pytest.mark.acceptance_id("CFG-02")
    def test_cfg_02_bidirectional_overlap(self, tmp_path: Path) -> None:
        repo, external_vault = _real_roots(tmp_path)
        nested_vault = repo / "nested-vault"
        nested_vault.mkdir()
        outer_vault = tmp_path / "outer"
        nested_repo = outer_vault / "nested-repo"
        nested_repo.mkdir(parents=True)
        (nested_repo / ".git").mkdir()

        for candidate_repo, candidate_vault in (
            (repo, repo),
            (repo, nested_vault),
            (nested_repo, outer_vault),
        ):
            _assert_configuration_error(
                "CONFIG_ROOTS_OVERLAP",
                lambda candidate_repo=candidate_repo, candidate_vault=candidate_vault: AppConfig(
                    repo_root=candidate_repo,
                    vault_root=candidate_vault,
                ),
            )
        assert external_vault.exists()

    @pytest.mark.acceptance_id("CFG-03")
    def test_cfg_03_raw_relative_and_traversal(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)

        for value in ("relative-repo", Path("relative-repo")):
            _assert_configuration_error(
                "CONFIG_PATH_NOT_ABSOLUTE",
                lambda value=value: AppConfig(repo_root=value, vault_root=vault),
                expected_field="repo_root",
            )

        class VirtualString(str):
            def __str__(self) -> str:
                return str(repo)

            def startswith(self, *args: object, **kwargs: object) -> bool:
                del args, kwargs
                raise RuntimeError("VIRTUAL_STRING_ORACLE")

            def replace(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                raise RuntimeError("VIRTUAL_STRING_ORACLE")

            def split(self, *args: object, **kwargs: object) -> list[str]:
                del args, kwargs
                raise RuntimeError("VIRTUAL_STRING_ORACLE")

        class VirtualPathLike:
            def __fspath__(self) -> str:
                return VirtualString("relative-repo")

        class HostileClassString(str):
            @property
            def __class__(self) -> type:
                raise RuntimeError("PRIVATE_CLASS_ORACLE")

        for value in (
            VirtualString("relative-repo"),
            VirtualPathLike(),
            HostileClassString("relative-repo"),
        ):
            _assert_configuration_error(
                "CONFIG_PATH_NOT_ABSOLUTE",
                lambda value=value: AppConfig(
                    repo_root=value,  # type: ignore[arg-type]
                    vault_root=vault,
                ),
                expected_field="repo_root",
            )

        class PRIVATE_CALLER_TOKEN:
            @property
            def __class__(self) -> type:
                return str

        _assert_configuration_error(
            "CONFIG_PATH_TYPE",
            lambda: AppConfig(
                repo_root=PRIVATE_CALLER_TOKEN(),  # type: ignore[arg-type]
                vault_root=vault,
            ),
            expected_field="repo_root",
        )
        _assert_configuration_error(
            "CONFIG_PATH_NAMESPACE_UNSUPPORTED",
            lambda: AppConfig(repo_root="C:relative-repo", vault_root=vault),
            expected_field="repo_root",
        )
        for segment in (".", ".."):
            raw_repo = f"{repo}{os.sep}{segment}{os.sep}child"
            _assert_configuration_error(
                "CONFIG_PATH_TRAVERSAL",
                lambda raw_repo=raw_repo: AppConfig(
                    repo_root=raw_repo,  # type: ignore[arg-type]
                    vault_root=vault,
                ),
                expected_field="repo_root",
            )

        invalid_inputs: tuple[tuple[object, str], ...] = (
            (b"private", "CONFIG_PATH_TYPE"),
            (object(), "CONFIG_PATH_TYPE"),
            ("   ", "CONFIG_PATH_EMPTY"),
            (f"{repo}\x00hidden", "CONFIG_PATH_NUL_OR_CONTROL"),
            (f"{repo}\nline", "CONFIG_PATH_NUL_OR_CONTROL"),
        )
        for value, code in invalid_inputs:
            _assert_configuration_error(
                code,
                lambda value=value: AppConfig(
                    repo_root=value,  # type: ignore[arg-type]
                    vault_root=vault,
                ),
                expected_field="repo_root",
            )

        class StringPath:
            def __fspath__(self) -> str:
                return str(repo)

        class BytesPath:
            def __fspath__(self) -> bytes:
                return os.fsencode(repo)

        class ExplodingPath:
            def __fspath__(self) -> str:
                raise RuntimeError("private path detail")

        assert AppConfig(repo_root=StringPath(), vault_root=vault).repo_root == repo  # type: ignore[arg-type]
        _assert_configuration_error(
            "CONFIG_PATH_TYPE",
            lambda: AppConfig(repo_root=BytesPath(), vault_root=vault),  # type: ignore[arg-type]
            expected_field="repo_root",
        )
        _assert_configuration_error(
            "CONFIG_PATH_TYPE",
            lambda: AppConfig(repo_root=ExplodingPath(), vault_root=vault),  # type: ignore[arg-type]
            expected_field="repo_root",
        )

    @pytest.mark.acceptance_id("CFG-04")
    def test_cfg_04_git_marker_file_or_directory(self, tmp_path: Path) -> None:
        directory_repo, directory_vault = _real_roots(tmp_path / "directory")
        file_repo, file_vault = _real_roots(tmp_path / "file", marker_file=True)
        assert AppConfig(
            repo_root=directory_repo,
            vault_root=directory_vault,
        ).repo_root == directory_repo
        assert AppConfig(repo_root=file_repo, vault_root=file_vault).repo_root == file_repo

        missing_repo = tmp_path / "missing-marker" / "repo"
        missing_vault = tmp_path / "missing-marker" / "vault"
        missing_repo.mkdir(parents=True)
        missing_vault.mkdir()
        _assert_configuration_error(
            "CONFIG_REPO_MARKER_INVALID",
            lambda: AppConfig(repo_root=missing_repo, vault_root=missing_vault),
        )

    @pytest.mark.acceptance_id("CFG-04")
    def test_cfg_04_git_marker_reparse_and_special_types(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        marker_identity = os.path.normcase(os.path.normpath(str(repo / ".git")))
        real_lstat = os.lstat
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        scenarios = (
            SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=reparse_flag,
            ),
            SimpleNamespace(st_mode=stat.S_IFIFO, st_file_attributes=0),
        )
        for marker_status in scenarios:
            def injected_lstat(
                value: str | os.PathLike[str],
                marker_status: object = marker_status,
            ) -> object:
                identity = os.path.normcase(os.path.normpath(os.fspath(value)))
                if identity == marker_identity:
                    return marker_status
                return real_lstat(value)

            with monkeypatch.context() as scoped:
                scoped.setattr(config_contracts, "_LSTAT", injected_lstat)
                _assert_configuration_error(
                    "CONFIG_REPO_MARKER_INVALID",
                    lambda: AppConfig(repo_root=repo, vault_root=vault),
                )

    @pytest.mark.acceptance_id("CFG-05")
    def test_cfg_05_missing_vault_is_not_created(self, tmp_path: Path) -> None:
        repo, _existing_vault = _real_roots(tmp_path)
        missing_vault = tmp_path / "future" / "vault"
        assert not missing_vault.exists()

        config = AppConfig(repo_root=repo, vault_root=missing_vault)

        assert config.vault_root == missing_vault
        assert not missing_vault.exists()
        nested_missing = repo / "future" / "vault"
        _assert_configuration_error(
            "CONFIG_ROOTS_OVERLAP",
            lambda: AppConfig(repo_root=repo, vault_root=nested_missing),
        )
        assert not nested_missing.exists()

    @pytest.mark.acceptance_id("CFG-06")
    def test_cfg_06_existing_vault_file_is_rejected(self, tmp_path: Path) -> None:
        repo, _vault = _real_roots(tmp_path)
        vault_file = tmp_path / "vault-file"
        vault_file.write_text("synthetic", encoding="utf-8")
        _assert_configuration_error(
            "CONFIG_VAULT_INVALID",
            lambda: AppConfig(repo_root=repo, vault_root=vault_file),
        )

    @pytest.mark.acceptance_id("CFG-06")
    def test_cfg_06_existing_vault_special_type_is_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        vault_identity = os.path.normcase(os.path.normpath(str(vault)))
        real_lstat = os.lstat

        def injected_lstat(value: str | os.PathLike[str]) -> object:
            identity = os.path.normcase(os.path.normpath(os.fspath(value)))
            if identity == vault_identity:
                return SimpleNamespace(st_mode=stat.S_IFIFO, st_file_attributes=0)
            return real_lstat(value)

        monkeypatch.setattr(config_contracts, "_LSTAT", injected_lstat)
        _assert_configuration_error(
            "CONFIG_VAULT_INVALID",
            lambda: AppConfig(repo_root=repo, vault_root=vault),
        )

    @pytest.mark.acceptance_id("CFG-07")
    def test_cfg_07_different_windows_drives_are_disjoint(self) -> None:
        assert not config_contracts._roots_overlap(  # type: ignore[attr-defined]
            r"C:\synthetic-repo",
            r"D:\synthetic-vault",
            windows=True,
        )

    @pytest.mark.acceptance_id("CFG-18")
    def test_cfg_18_all_construction_paths_revalidate(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        direct = AppConfig(repo_root=str(repo), vault_root=str(vault))  # type: ignore[arg-type]
        from_values = AppConfig.from_values(str(repo), str(vault))
        loaded = AppConfig.load(repo_root=str(repo), vault_root=str(vault), environ={})
        replaced = dataclasses.replace(direct)
        assert direct == from_values == loaded == replaced
        assert all(isinstance(item.repo_root, Path) for item in (direct, from_values, loaded, replaced))

        class VirtualCanonicalString(str):
            def __str__(self) -> str:
                return "relative-canonical"

            def startswith(self, *args: object, **kwargs: object) -> bool:
                del args, kwargs
                raise RuntimeError("VIRTUAL_CANONICAL_ORACLE")

            def replace(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                raise RuntimeError("VIRTUAL_CANONICAL_ORACLE")

            def split(self, *args: object, **kwargs: object) -> list[str]:
                del args, kwargs
                raise RuntimeError("VIRTUAL_CANONICAL_ORACLE")

        real_realpath = os.path.realpath

        def virtual_realpath(value: str) -> str:
            return VirtualCanonicalString(real_realpath(value, strict=False))

        with monkeypatch.context() as scoped:
            scoped.setattr(config_contracts, "_REALPATH", virtual_realpath)
            frozen_canonical = AppConfig(repo_root=repo, vault_root=vault)
        assert frozen_canonical.repo_root == repo
        assert frozen_canonical.vault_root == vault

        class PRIVATE_CANONICAL_TOKEN:
            @property
            def __class__(self) -> type:
                return str

        def spoofed_realpath(_value: str) -> str:
            return PRIVATE_CANONICAL_TOKEN()  # type: ignore[return-value]

        with monkeypatch.context() as scoped:
            scoped.setattr(config_contracts, "_REALPATH", spoofed_realpath)
            _assert_configuration_error(
                "CONFIG_PATH_INSPECTION_FAILED",
                lambda: AppConfig(repo_root=repo, vault_root=vault),
                expected_field="repo_root",
            )

        for operation in (
            lambda: AppConfig(repo_root=repo, vault_root=repo),
            lambda: AppConfig.from_values(repo, repo),
            lambda: AppConfig.load(repo_root=repo, vault_root=repo, environ={}),
            lambda: dataclasses.replace(direct, vault_root=repo),
        ):
            _assert_configuration_error("CONFIG_ROOTS_OVERLAP", operation)
        _assert_configuration_error(
            "CONFIG_SCOPE_LOCKED",
            lambda: dataclasses.replace(direct, single_counselor=1),  # type: ignore[arg-type]
            expected_field="single_counselor",
        )


class TestConfigWindowsContract:
    @pytest.mark.acceptance_id("CFG-08")
    def test_cfg_08_unsupported_namespaces(self) -> None:
        candidates = (
            r"\\server\share\repo",
            r"\\?\C:\repo",
            r"\\.\C:\repo",
            r"\??\C:\repo",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\repo",
            r"\rooted-without-drive",
            r"C:drive-relative",
        )
        for candidate in candidates:
            _assert_configuration_error(
                "CONFIG_PATH_NAMESPACE_UNSUPPORTED",
                lambda candidate=candidate: config_contracts._validate_raw_syntax(
                    candidate,
                    "repo_root",
                    windows=True,
                ),
                expected_field="repo_root",
            )

    @pytest.mark.acceptance_id("CFG-08")
    def test_cfg_08_canonical_namespace_is_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        canonical_results = (
            r"\\server\share\canonical-review-vault",
            r"\\?\C:\canonical-review-vault",
            r"\\.\C:\canonical-review-vault",
            r"\??\C:\canonical-review-vault",
        )
        for canonical_result in canonical_results:
            with monkeypatch.context() as scoped:
                unsafe_observations = _inject_canonical_result(
                    scoped,
                    vault,
                    canonical_result,
                )
                _assert_configuration_error(
                    "CONFIG_PATH_NAMESPACE_UNSUPPORTED",
                    lambda: AppConfig(repo_root=repo, vault_root=vault),
                    expected_field="vault_root",
                )
                assert unsafe_observations == []

    @pytest.mark.acceptance_id("CFG-09")
    def test_cfg_09_nonlocal_drive_types(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unexpected_realpath(_value: str) -> str:
            raise AssertionError("resolve must not run before the drive gate")

        scenarios: tuple[object, ...] = (
            4,
            0,
            1,
            OSError("private drive detail"),
            RuntimeError("private drive detail"),
        )
        for scenario in scenarios:
            calls: list[str] = []

            def drive_type(_root: str, scenario: object = scenario) -> int:
                calls.append("drive")
                if isinstance(scenario, BaseException):
                    raise scenario
                return int(scenario)

            with monkeypatch.context() as scoped:
                scoped.setattr(
                    config_contracts,
                    "_DRIVE_TYPE_QUERY",
                    drive_type,
                    raising=False,
                )
                scoped.setattr(
                    config_contracts,
                    "_REALPATH",
                    unexpected_realpath,
                    raising=False,
                )
                _assert_configuration_error(
                    "CONFIG_PATH_DRIVE_UNSUPPORTED",
                    lambda: config_contracts._validate_windows_drive(
                        r"C:\synthetic-repo",
                        "repo_root",
                    ),
                    expected_field="repo_root",
                )
            assert calls == ["drive"]

    @pytest.mark.acceptance_id("CFG-09")
    def test_cfg_09_canonical_drive_is_revalidated(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        source_drive = os.path.splitdrive(str(vault))[0]
        canonical_drive = "Z:" if source_drive.casefold() != "z:" else "Y:"
        canonical_root = f"{canonical_drive}\\"
        canonical_result = (
            f"{canonical_root}canonical-review-drive\\vault"
        )
        scenarios: tuple[object, ...] = (
            4,
            0,
            RuntimeError("private canonical drive detail"),
        )
        for scenario in scenarios:
            drive_calls: list[str] = []

            def drive_type(root: str, scenario: object = scenario) -> int:
                drive_calls.append(os.path.normcase(root))
                if os.path.normcase(root) == os.path.normcase(canonical_root):
                    if isinstance(scenario, BaseException):
                        raise scenario
                    return int(scenario)
                return 3

            with monkeypatch.context() as scoped:
                unsafe_observations = _inject_canonical_result(
                    scoped,
                    vault,
                    canonical_result,
                )
                scoped.setattr(config_contracts, "_DRIVE_TYPE_QUERY", drive_type)
                _assert_configuration_error(
                    "CONFIG_PATH_DRIVE_UNSUPPORTED",
                    lambda: AppConfig(repo_root=repo, vault_root=vault),
                    expected_field="vault_root",
                )
                assert os.path.normcase(canonical_root) in drive_calls
                assert unsafe_observations == []

    @pytest.mark.acceptance_id("CFG-10")
    def test_cfg_10_unsupported_components(self) -> None:
        components = (
            "name:stream",
            "wild*card",
            "wild?card",
            "CON",
            "prn.txt",
            "Aux.data",
            "NUL",
            "com1.log",
            "LPT9",
            "trailing.",
            "trailing ",
        )
        for component in components:
            _assert_configuration_error(
                "CONFIG_PATH_COMPONENT_UNSUPPORTED",
                lambda component=component: config_contracts._validate_path_components(
                    rf"C:\safe\{component}",
                    "vault_root",
                    windows=True,
                ),
                expected_field="vault_root",
            )

    @pytest.mark.acceptance_id("CFG-10")
    def test_cfg_10_canonical_unsupported_component_is_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        drive = os.path.splitdrive(str(vault))[0]
        canonical_result = (
            f"{drive}\\canonical-review-component\\name:stream"
        )
        unsafe_observations = _inject_canonical_result(
            monkeypatch,
            vault,
            canonical_result,
        )
        _assert_configuration_error(
            "CONFIG_PATH_COMPONENT_UNSUPPORTED",
            lambda: AppConfig(repo_root=repo, vault_root=vault),
            expected_field="vault_root",
        )
        assert unsafe_observations == []

    @pytest.mark.acceptance_id("CFG-11")
    def test_cfg_11_dos_alias_components(self, tmp_path: Path) -> None:
        existing_alias = tmp_path / "AbCdEf~1"
        existing_alias.mkdir()
        candidates = (
            r"C:\safe\ABCDEF~1",
            r"C:\safe\abcdef~123456.TxT",
            r"C:\safe\A~1.x",
            str(existing_alias),
        )
        for candidate in candidates:
            _assert_configuration_error(
                "CONFIG_PATH_ALIAS_UNSUPPORTED",
                lambda candidate=candidate: config_contracts._validate_path_components(
                    candidate,
                    "repo_root",
                    windows=True,
                ),
                expected_field="repo_root",
            )

    @pytest.mark.acceptance_id("CFG-11")
    def test_cfg_11_canonical_dos_alias_is_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        drive = os.path.splitdrive(str(vault))[0]
        canonical_result = f"{drive}\\canonical-review-alias\\ABCDEF~1"
        unsafe_observations = _inject_canonical_result(
            monkeypatch,
            vault,
            canonical_result,
        )
        _assert_configuration_error(
            "CONFIG_PATH_ALIAS_UNSUPPORTED",
            lambda: AppConfig(repo_root=repo, vault_root=vault),
            expected_field="vault_root",
        )
        assert unsafe_observations == []

    @pytest.mark.acceptance_id("CFG-12")
    def test_cfg_12_identity_aliases_cannot_bypass_overlap(self) -> None:
        identities = (
            r"C:\Synthetic\Repository",
            r"c:/synthetic/repository/",
            r"c:\SYNTHETIC\REPOSITORY\\",
        )
        normalized = {
            config_contracts._canonical_identity(value, windows=True)
            for value in identities
        }
        assert len(normalized) == 1
        assert config_contracts._roots_overlap(
            identities[0],
            identities[1],
            windows=True,
        )

    @pytest.mark.acceptance_id("CFG-13")
    def test_cfg_13_reparse_and_broken_link_fail_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        real_lstat = os.lstat
        real_lexists = os.path.lexists
        real_realpath = os.path.realpath
        vault_identity = os.path.normcase(os.path.normpath(str(vault)))

        def reparse_lstat(value: str | os.PathLike[str]) -> object:
            result = real_lstat(value)
            identity = os.path.normcase(os.path.normpath(os.fspath(value)))
            attributes = int(getattr(result, "st_file_attributes", 0))
            if identity == vault_identity:
                attributes |= int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            return SimpleNamespace(
                st_mode=result.st_mode,
                st_file_attributes=attributes,
            )

        with monkeypatch.context() as scoped:
            scoped.setattr(config_contracts, "_LEXISTS", real_lexists, raising=False)
            scoped.setattr(config_contracts, "_LSTAT", reparse_lstat, raising=False)
            scoped.setattr(
                config_contracts,
                "_REALPATH",
                lambda value: real_realpath(value, strict=False),
                raising=False,
            )
            _assert_configuration_error(
                "CONFIG_PATH_REPARSE",
                lambda: AppConfig(repo_root=repo, vault_root=vault),
                expected_field="vault_root",
            )

        with monkeypatch.context() as scoped:
            scoped.setattr(
                config_contracts,
                "_LEXISTS",
                lambda _value: (_ for _ in ()).throw(
                    RuntimeError("private inspection detail")
                ),
                raising=False,
            )
            scoped.setattr(config_contracts, "_LSTAT", real_lstat, raising=False)
            scoped.setattr(
                config_contracts,
                "_REALPATH",
                lambda value: real_realpath(value, strict=False),
                raising=False,
            )
            _assert_configuration_error(
                "CONFIG_PATH_INSPECTION_FAILED",
                lambda: AppConfig(repo_root=repo, vault_root=vault),
                expected_field="repo_root",
            )

        lstat_observations: list[str] = []

        def observed_lstat(value: str | os.PathLike[str]) -> os.stat_result:
            lstat_observations.append(
                os.path.normcase(os.path.normpath(os.fspath(value)))
            )
            return real_lstat(value)

        with monkeypatch.context() as scoped:
            scoped.setattr(config_contracts, "_LEXISTS", real_lexists, raising=False)
            scoped.setattr(config_contracts, "_LSTAT", observed_lstat, raising=False)
            scoped.setattr(
                config_contracts,
                "_REALPATH",
                lambda value: real_realpath(value, strict=False),
                raising=False,
            )
            AppConfig(repo_root=repo, vault_root=vault)
        assert lstat_observations.count(vault_identity) >= 2

        broken_link = tmp_path / "broken-vault-link"
        try:
            os.symlink(tmp_path / "absent-target", broken_link, target_is_directory=True)
        except OSError:
            pass
        else:
            _assert_configuration_error(
                "CONFIG_PATH_REPARSE",
                lambda: AppConfig(repo_root=repo, vault_root=broken_link),
                expected_field="vault_root",
            )

    @pytest.mark.acceptance_id("CFG-21")
    def test_cfg_21_posix_absolute_candidate_contract(self) -> None:
        config_contracts._validate_raw_syntax(
            "/srv/consultation/repo",
            "repo_root",
            windows=False,
        )
        config_contracts._validate_path_components(
            "/srv/CON/wild*card/trailing.",
            "repo_root",
            windows=False,
        )
        assert (
            config_contracts._canonical_identity(
                "/srv/consultation/repo/",
                windows=False,
            )
            == "/srv/consultation/repo"
        )
        _assert_configuration_error(
            "CONFIG_PATH_TRAVERSAL",
            lambda: config_contracts._validate_raw_syntax(
                "/srv/consultation/../repo",
                "repo_root",
                windows=False,
            ),
            expected_field="repo_root",
        )


class TestConfigEnvironmentContract:
    @pytest.mark.acceptance_id("CFG-14")
    def test_cfg_14_vault_source_resolution(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        other_vault = tmp_path / "other-vault"
        other_vault.mkdir()
        baseline = AppConfig.load(repo_root=repo, vault_root=vault, environ={})

        same = AppConfig.load(
            repo_root=repo,
            vault_root=vault,
            environ={"consultation_vault_root": f"{vault}{os.sep}"},
        )
        env_only = AppConfig.load(
            repo_root=repo,
            environ={"CONSULTATION_VAULT_ROOT": str(vault)},
        )
        assert same == env_only == baseline
        _assert_configuration_error(
            "CONFIG_VAULT_SOURCE_CONFLICT",
            lambda: AppConfig.load(
                repo_root=repo,
                vault_root=vault,
                environ={"CONSULTATION_VAULT_ROOT": str(other_vault)},
            ),
        )
        _assert_configuration_error(
            "CONFIG_VAULT_ROOT_MISSING",
            lambda: AppConfig.load(repo_root=repo, environ={}),
        )
        _assert_configuration_error(
            "CONFIG_ENV_INVALID",
            lambda: AppConfig.load(
                repo_root=repo,
                environ={"CONSULTATION_VAULT_ROOT": "   "},
            ),
        )

    @pytest.mark.acceptance_id("CFG-15")
    def test_cfg_15_env_allowlist_is_redacted(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        unknown_names = (
            "CONSULTATION_INTERACTION_MODE",
            "consultation_single_counselor",
            "CONSULTATION_RUNTIME_NETWORK_INGEST",
            "consultation_automatic_formal_writeback",
            "CONSULTATION_WEB_ENABLED",
            "CONSULTATION_API_ENABLED",
            "CONSULTATION_VOICE_ENABLED",
            "CONSULTATION_MULTI_USER",
            "CONSULTATION_AUTOMATIC_DIAGNOSIS",
            "consultation_private_secret",
        )
        reserved_names = (
            "CONSULTATION_RESOLVER_SCENARIO",
            "consultation_resolver_scenario_log",
            "Consultation_Fault_Point",
        )
        for name in unknown_names:
            _assert_configuration_error(
                "CONFIG_ENV_UNKNOWN",
                lambda name=name: AppConfig.load(
                    repo_root=repo,
                    vault_root=vault,
                    environ={name: "private-value"},
                ),
            )
        for name in reserved_names:
            _assert_configuration_error(
                "CONFIG_ENV_RESERVED",
                lambda name=name: AppConfig.load(
                    repo_root=repo,
                    vault_root=vault,
                    environ={name: "private-value"},
                ),
            )

        invalid_mappings: tuple[object, ...] = (
            {
                "CONSULTATION_VAULT_ROOT": str(vault),
                "consultation_vault_root": str(vault),
            },
            {
                "CONSULTATION_PYTHON": "python-a",
                "consultation_python": "python-b",
            },
            {1: "private-value"},
            {"CONSULTATION_VAULT_ROOT": 1},
            {"CONSULTATION_VAULT_ROOT": "\t"},
            [("CONSULTATION_VAULT_ROOT", str(vault))],
        )
        for environ in invalid_mappings:
            _assert_configuration_error(
                "CONFIG_ENV_INVALID",
                lambda environ=environ: AppConfig.load(
                    repo_root=repo,
                    vault_root=vault,
                    environ=environ,  # type: ignore[arg-type]
                ),
            )

        try:
            AppConfig.load(
                repo_root=repo,
                vault_root=vault,
                environ={"CONSULTATION_PRIVATE_KEY": "private-value"},
            )
        except ConfigurationError as error:
            with caplog.at_level("ERROR"):
                logging.getLogger("config-env-contract").error("%s", error)
        else:
            raise AssertionError("unknown environment key was accepted")
        assert caplog.messages == ["CONFIG_ENV_UNKNOWN"]
        for forbidden in (
            "CONSULTATION_PRIVATE_KEY",
            "consultation_private_key",
            "private-value",
            str(repo),
            str(vault),
        ):
            assert forbidden not in caplog.text

    @pytest.mark.acceptance_id("CFG-16")
    def test_cfg_16_consultation_python_is_inert(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        baseline = AppConfig.load(
            repo_root=repo,
            environ={"CONSULTATION_VAULT_ROOT": str(vault)},
        )
        with_python = AppConfig.load(
            repo_root=repo,
            environ={
                "CONSULTATION_VAULT_ROOT": str(vault),
                "consultation_python": "C:/synthetic/python.exe",
            },
        )
        assert with_python == baseline
        assert tuple(
            getattr(with_python, field.name) for field in dataclasses.fields(AppConfig)
        ) == tuple(getattr(baseline, field.name) for field in dataclasses.fields(AppConfig))
        for value in ("", "   ", 312):
            _assert_configuration_error(
                "CONFIG_ENV_INVALID",
                lambda value=value: AppConfig.load(
                    repo_root=repo,
                    vault_root=vault,
                    environ={"CONSULTATION_PYTHON": value},  # type: ignore[dict-item]
                ),
            )

    @pytest.mark.acceptance_id("CFG-23")
    def test_cfg_23_explicit_values_ignore_ambient_env(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        other_vault = tmp_path / "other-vault"
        other_vault.mkdir()
        baseline_direct = AppConfig(repo_root=repo, vault_root=vault)
        baseline_factory = AppConfig.from_values(repo, vault)

        monkeypatch.setenv("CONSULTATION_PRIVATE_AMBIENT", "private-value")
        monkeypatch.setenv("CONSULTATION_VAULT_ROOT", str(other_vault))

        assert AppConfig(repo_root=repo, vault_root=vault) == baseline_direct
        assert AppConfig.from_values(repo, vault) == baseline_factory
        assert AppConfig.load(
            repo_root=repo,
            vault_root=vault,
            environ={},
        ) == baseline_direct
        _assert_configuration_error(
            "CONFIG_ENV_UNKNOWN",
            lambda: AppConfig.load(repo_root=repo, vault_root=vault),
        )


class TestConfigArchitectureContract:
    @pytest.mark.acceptance_id("CFG-20")
    def test_cfg_20_imports_and_doctor_help_are_lazy(
        self,
        tmp_path: Path,
    ) -> None:
        project_root = Path(__file__).resolve().parents[3]
        script = "\n".join(
            (
                "import json",
                "import sys",
                "import consultation_kb",
                "import consultation_kb.core",
                "prefixes = ('consultation_kb.core.config', 'consultation_kb.vault', "
                "'consultation_kb.evaluation', 'consultation_kb.policy', 'yaml', 'pydantic')",
                "before = sorted(name for name in sys.modules if name.startswith(prefixes))",
                "from consultation_kb.entrypoint import main",
                "try:",
                "    main(['doctor', '--help'])",
                "except SystemExit as error:",
                "    status = error.code",
                "else:",
                "    status = None",
                "after = sorted(name for name in sys.modules if name.startswith(prefixes))",
                "print('__CONFIG_IMPORT_PROBE__' + json.dumps("
                "{'before': before, 'after': after, 'status': status}, sort_keys=True))",
            )
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(project_root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        before = tuple(tmp_path.iterdir())

        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert completed.returncode == 0, completed.stderr
        marker = "__CONFIG_IMPORT_PROBE__"
        payload_line = next(
            line for line in completed.stdout.splitlines() if line.startswith(marker)
        )
        payload = json.loads(payload_line.removeprefix(marker))
        assert payload == {"after": [], "before": [], "status": 0}
        assert tuple(tmp_path.iterdir()) == before

    @pytest.mark.acceptance_id("CFG-22")
    def test_cfg_22_production_acquisition_uses_load_only(self) -> None:
        project_root = Path(__file__).resolve().parents[3]
        package_root = project_root / "consultation_kb"
        config_path = package_root / "core" / "config.py"
        findings: dict[str, tuple[int, ...]] = {}
        for source_path in sorted(package_root.rglob("*.py")):
            if source_path == config_path:
                continue
            source = source_path.read_text(encoding="utf-8")
            source_findings = _forbidden_config_acquisitions(source)
            if source_findings:
                findings[str(source_path.relative_to(project_root))] = source_findings
        assert findings == {}

        assert _forbidden_config_acquisitions(
            "def start():\n    return AppConfig.from_values('/repo', '/vault')\n"
        ) == (2,)
        assert _forbidden_config_acquisitions(
            "def start():\n    return config.AppConfig(repo_root='/r', vault_root='/v')\n"
        ) == (2,)
        assert _forbidden_config_acquisitions(
            "def start():\n    return AppConfig.load(repo_root='/r')\n"
        ) == ()
        assert _forbidden_config_acquisitions(
            "from consultation_kb.core.config import AppConfig as Config\n"
            "def start():\n    return Config.from_values('/repo', '/vault')\n"
        ) == (3,)


class TestVaultLayoutContract:
    _PATHS = {
        "identity_map": "identity/identity-map.enc",
        "sources": "sources",
        "wiki_draft": "wiki/draft",
        "wiki_approved": "wiki/approved",
        "wiki_history": "wiki/history",
        "global_db": "global/catalog.sqlite3",
        "global_graph": "global/graph/graph.json",
        "lexical_indexes": "global/indexes/bm25",
        "vector_indexes": "global/indexes/vector",
        "cases_draft": "cases/draft",
        "cases_approved": "cases/approved",
        "cases_quarantine": "cases/quarantine",
        "clients_root": "clients",
        "global_objects_root": "global/objects",
        "global_staging_root": "global/.staging",
        "review_queue": "review-queue",
        "audit_root": "audit",
        "quarantine": "quarantine",
    }

    @pytest.mark.acceptance_id("LAYOUT-01")
    def test_layout_01_exact_paths(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        layout = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=vault)
        )

        observed = {
            name: getattr(layout, name) for name in self._PATHS
        }

        assert observed == {
            name: vault / relative
            for name, relative in self._PATHS.items()
        }
        assert all(type(path) is type(vault) for path in observed.values())
        assert all(path.is_absolute() for path in observed.values())

    @pytest.mark.acceptance_id("LAYOUT-02")
    def test_layout_02_exact_app_config_only(self, tmp_path: Path) -> None:
        _repo, vault = _real_roots(tmp_path)

        class DuckConfig:
            vault_root = vault

        for candidate in (vault, str(vault), DuckConfig()):
            with pytest.raises(TypeError) as captured:
                VaultLayout.from_config(candidate)  # type: ignore[arg-type]
            assert str(captured.value) == "VAULT_VALIDATED_CONFIG_REQUIRED"
            assert str(vault) not in str(captured.value)

        for operation in (
            lambda: VaultLayout(),
            lambda: VaultLayout(vault),  # type: ignore[call-arg]
        ):
            with pytest.raises(TypeError) as captured:
                operation()
            assert str(captured.value) == "VAULT_VALIDATED_CONFIG_REQUIRED"

    @pytest.mark.acceptance_id("LAYOUT-03")
    def test_layout_03_frozen_and_deterministic(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        config = AppConfig(repo_root=repo, vault_root=vault)
        first = VaultLayout.from_config(config)
        second = VaultLayout.from_config(config)
        expected_identity_map = vault / "identity" / "identity-map.enc"

        assert first.identity_map == first.identity_map == expected_identity_map
        assert tuple(getattr(first, name) for name in self._PATHS) == tuple(
            getattr(second, name) for name in self._PATHS
        )

        for operation in (
            lambda: setattr(first, "_vault_root", tmp_path),
            lambda: setattr(first, "identity_map", tmp_path),
            lambda: setattr(first, "extra", tmp_path),
            lambda: delattr(first, "_vault_root"),
        ):
            with pytest.raises(AttributeError):
                operation()
        assert first.identity_map == expected_identity_map

    @pytest.mark.acceptance_id("LAYOUT-04")
    def test_layout_04_zero_io(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        config = AppConfig(repo_root=repo, vault_root=vault)
        observations: list[str] = []

        def reject(name: str) -> object:
            def forbidden(*_args: object, **_kwargs: object) -> None:
                observations.append(name)
                raise AssertionError(name)

            return forbidden

        for name in (
            "mkdir",
            "touch",
            "open",
            "resolve",
            "exists",
            "iterdir",
            "stat",
            "lstat",
        ):
            monkeypatch.setattr(Path, name, reject(f"Path.{name}"))
        for name in ("mkdir", "stat", "lstat", "scandir"):
            monkeypatch.setattr(os, name, reject(f"os.{name}"))

        layout = VaultLayout.from_config(config)
        observed = tuple(getattr(layout, name) for name in self._PATHS)

        assert len(observed) == 18
        assert observations == []

    @pytest.mark.acceptance_id("LAYOUT-05")
    def test_layout_05_exact_public_surface(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        layout = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=vault)
        )
        expected_public = {"from_config", *self._PATHS}
        public_names = {
            name for name in dir(layout) if not name.startswith("_")
        }
        property_names = {
            name
            for name, value in vars(VaultLayout).items()
            if isinstance(value, property)
        }

        assert VaultLayout.__slots__ == ("_vault_root",)
        assert public_names == expected_public
        assert property_names == set(self._PATHS)
        for forbidden in (
            "root",
            "vault_root",
            "objects_root",
            "client_root",
            "session_path",
            "path_for",
            "__getitem__",
        ):
            assert not hasattr(layout, forbidden)

    @pytest.mark.acceptance_id("LAYOUT-06")
    def test_layout_06_redaction_and_serialization_bans(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        repo, vault = _real_roots(tmp_path)
        layout = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=vault)
        )
        root_text = str(vault)

        assert not dataclasses.is_dataclass(VaultLayout)
        assert not dataclasses.is_dataclass(layout)
        assert repr(layout) == "<VaultLayout redacted>"
        assert str(layout) == "<VaultLayout redacted>"

        with caplog.at_level("INFO"):
            logging.getLogger("vault-layout-contract").info("%r", layout)
        assert caplog.messages == ["<VaultLayout redacted>"]
        assert root_text not in caplog.text

        for operation in (
            lambda: vars(layout),
            lambda: dataclasses.asdict(layout),  # type: ignore[arg-type]
            lambda: dataclasses.astuple(layout),  # type: ignore[arg-type]
        ):
            with pytest.raises(TypeError) as captured:
                operation()
            assert root_text not in str(captured.value)

        for operation in (
            lambda: copy.copy(layout),
            lambda: copy.deepcopy(layout),
            lambda: pickle.dumps(layout, protocol=pickle.HIGHEST_PROTOCOL),
        ):
            with pytest.raises(TypeError) as captured:
                operation()
            assert str(captured.value) == "VAULT_SERIALIZATION_FORBIDDEN"
            assert root_text not in str(captured.value)

        for serializer in (
            "to_dict",
            "dict",
            "json",
            "model_dump",
            "model_dump_json",
        ):
            assert not hasattr(layout, serializer)

    @pytest.mark.acceptance_id("LAYOUT-07")
    def test_layout_07_equality_and_hash(self, tmp_path: Path) -> None:
        repo, vault = _real_roots(tmp_path)
        other_vault = tmp_path / "other-vault"
        other_vault.mkdir()
        first = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=vault)
        )
        same = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=vault)
        )
        different = VaultLayout.from_config(
            AppConfig(repo_root=repo, vault_root=other_vault)
        )

        class DuckLayout:
            vault_root = vault

            def __eq__(self, _other: object) -> bool:
                return True

        assert first == same
        assert hash(first) == hash(same)
        assert first != different
        assert first != DuckLayout()
        assert first != vault

    @pytest.mark.acceptance_id("CFG-25")
    def test_cfg_25_unchecked_config_subtype_is_rejected(
        self,
        tmp_path: Path,
    ) -> None:
        parent_subclasses = tuple(AppConfig.__subclasses__())
        parent_subclass_seal = AppConfig.__dict__["__init_subclass__"]
        project_root = Path(__file__).resolve().parents[3]
        script = "\n".join(
            (
                "from consultation_kb.core.config import AppConfig",
                "from consultation_kb.vault.layout import VaultLayout",
                "original_seal = AppConfig.__dict__['__init_subclass__']",
                "def allow_test_subclass(_cls, **_kwargs):",
                "    return None",
                "def reject_attribute_access(self, _name):",
                "    raise AssertionError('ATTRIBUTE_ACCESS_ORACLE')",
                "try:",
                "    setattr(AppConfig, '__init_subclass__', "
                "classmethod(allow_test_subclass))",
                "    UncheckedConfig = type.__new__(",
                "        type(AppConfig),",
                "        'UncheckedConfig',",
                "        (AppConfig,),",
                "        {'__getattribute__': reject_attribute_access},",
                "    )",
                "    unchecked = object.__new__(UncheckedConfig)",
                "finally:",
                "    setattr(AppConfig, '__init_subclass__', original_seal)",
                "try:",
                "    VaultLayout.from_config(unchecked)",
                "except TypeError as error:",
                "    assert type(error) is TypeError",
                "    assert error.args == ('VAULT_VALIDATED_CONFIG_REQUIRED',)",
                "    assert str(error) == 'VAULT_VALIDATED_CONFIG_REQUIRED'",
                "else:",
                "    raise AssertionError('unchecked subtype was accepted')",
            )
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(project_root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        before = tuple(tmp_path.iterdir())

        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == ""
        assert completed.stderr == ""
        assert tuple(tmp_path.iterdir()) == before
        assert tuple(AppConfig.__subclasses__()) == parent_subclasses
        assert AppConfig.__dict__["__init_subclass__"] is parent_subclass_seal
