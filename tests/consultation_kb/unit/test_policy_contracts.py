from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import shutil
import stat
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import pytest
import yaml
from pydantic import TypeAdapter

from consultation_kb.core.config import AppConfig
from consultation_kb.models.evidence import EmpiricalSupport, SourceGrade
import consultation_kb.policy.loader as policy_loader_module
from consultation_kb.policy.loader import (
    EvidenceLevelsPolicy,
    LoadedPolicy,
    PolicyAuditMetadata,
    PolicyBundle,
    PolicyFilename,
    PolicyId,
    PolicyLoadError,
    PolicyLoader,
    RelationTypesPolicy,
    RetentionPolicy,
    RiskRulePolicy,
    RiskRulesPolicy,
)


_LOADED_FIELDS = (
    "filename",
    "schema_version",
    "policy_id",
    "policy_version",
    "raw_bytes_sha256",
    "canonical_bytes",
    "content_sha256",
    "document",
)
_AUDIT_FIELDS = (
    "filename",
    "policy_id",
    "policy_version",
    "raw_bytes_sha256",
    "content_sha256",
)
_SOURCE_GRADES = (
    "T1",
    "T2",
    "T3",
    "T4",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "K1",
    "K2",
    "K3",
    "K4",
    "L1",
    "L2",
    "L3",
    "L4",
)
_EMPIRICAL_SUPPORT = (
    "unassessed",
    "case_supported",
    "observation_supported",
    "empirically_supported",
    "guideline_consistent",
    "conflicting",
)
_RELATION_TYPES = (
    "CITES",
    "SUPPORTS",
    "CONTRADICTS",
    "INTERPRETS",
    "DERIVED_FROM",
    "APPLIES_TO",
    "NOT_APPLICABLE_TO",
    "ANALOGOUS_TO",
    "DISTINCT_FROM",
    "CONTRAINDICATED_FOR",
    "REQUIRES_REFERRAL",
    "EXEMPLIFIED_BY",
    "SUPERSEDES",
)
_RETENTION_CATEGORIES = (
    "identity_mapping",
    "source_record",
    "private_session_record",
    "approved_fact_governance",
    "approved_shared_case",
    "rebuildable_derivative",
    "temporary_staging",
    "minimal_noncontent_audit",
)
_CHECKOUT_ROOT = Path(__file__).resolve().parents[3]
_POLICY_FILENAMES = (
    "evidence-levels.yaml",
    "relation-types.yaml",
    "retention.yaml",
    "risk-rules.yaml",
)
_ROOT_GIT_ATTRIBUTES = (
    b"/.gitattributes text eol=lf\n"
    b"docs/superpowers/specs/2026-07-17-consultation-kb-p0-task4-security-policy-design.md text eol=lf\n"
    b"policies/evidence-levels.yaml text eol=lf\n"
    b"policies/relation-types.yaml text eol=lf\n"
    b"policies/retention.yaml text eol=lf\n"
    b"policies/risk-rules.yaml text eol=lf\n"
    b"requirements/consultation-*.in text eol=lf\n"
    b"requirements/consultation-*.lock.txt text eol=lf\n"
    b"schemas/*.schema.json text eol=lf\n"
)
_RISK_RULE_VALUES = (
    (
        "synthetic_general_observation",
        1,
        "synthetic_general_observation",
        "general",
        "literal",
        "SYNTH-RISK-GENERAL-4C2E",
        0,
        ("synthetic_context_present",),
        ("SYNTH-QUESTION-GENERAL-VERIFY",),
    ),
    (
        "synthetic_high_observation",
        1,
        "synthetic_high_observation",
        "high",
        "literal",
        "SYNTH-RISK-HIGH-7D1A",
        0,
        ("synthetic_context_present",),
        ("SYNTH-QUESTION-HIGH-VERIFY",),
    ),
    (
        "suicide_intent_zh",
        1,
        "suicide_intent",
        "high",
        "literal",
        "我想自杀",
        6,
        (),
        ("确认当前意图、计划、可用手段、时间范围和保护因素。",),
    ),
    (
        "suicide_intent_en",
        1,
        "suicide_intent",
        "high",
        "literal",
        "I want to kill myself",
        6,
        (),
        (
            "Confirm current intent, plan, access to means, timeframe, and protective factors.",
        ),
    ),
    (
        "suicide_plan_zh",
        1,
        "suicide_plan",
        "high",
        "literal",
        "我准备自杀",
        6,
        (),
        ("确认计划、可用手段、预定时间、准备行为和保护因素。",),
    ),
    (
        "suicide_plan_en",
        1,
        "suicide_plan",
        "high",
        "literal",
        "I plan to kill myself",
        6,
        (),
        (
            "Confirm the plan, access to means, intended timeframe, preparations, and protective factors.",
        ),
    ),
    (
        "self_harm_intent_zh",
        1,
        "self_harm_intent",
        "high",
        "literal",
        "我想伤害自己",
        6,
        (),
        ("确认伤害冲动、具体方式、可用手段和当前可控性。",),
    ),
    (
        "self_harm_intent_en",
        1,
        "self_harm_intent",
        "high",
        "literal",
        "I want to hurt myself",
        6,
        (),
        (
            "Confirm the urge, intended method, access to means, and current ability to stay safe.",
        ),
    ),
    (
        "harm_other_intent_zh",
        1,
        "harm_other_intent",
        "high",
        "literal",
        "我准备伤害别人",
        6,
        (),
        ("确认目标、意图、计划、手段、时间范围和当前隔离条件。",),
    ),
    (
        "harm_other_intent_en",
        1,
        "harm_other_intent",
        "high",
        "literal",
        "I plan to hurt someone",
        6,
        (),
        (
            "Confirm the target, intent, plan, access to means, timeframe, and current separation.",
        ),
    ),
    (
        "immediate_interpersonal_danger_zh",
        1,
        "immediate_interpersonal_danger",
        "high",
        "literal",
        "他现在要杀我",
        6,
        (),
        ("确认威胁者是否在场、是否有武器及当前可安全联系的支持。",),
    ),
    (
        "immediate_interpersonal_danger_en",
        1,
        "immediate_interpersonal_danger",
        "high",
        "literal",
        "He is going to kill me",
        6,
        (),
        (
            "Confirm whether the threatening person is present, has a weapon, and what support can be contacted safely.",
        ),
    ),
    (
        "ongoing_interpersonal_violence_zh",
        1,
        "ongoing_interpersonal_violence",
        "general",
        "literal",
        "他经常打我",
        6,
        (),
        ("确认事件频率、最近一次时间、伤势、升级趋势和当前安全条件。",),
    ),
    (
        "ongoing_interpersonal_violence_en",
        1,
        "ongoing_interpersonal_violence",
        "general",
        "literal",
        "He keeps hitting me",
        6,
        (),
        (
            "Confirm frequency, recency, injuries, escalation, and present safety conditions.",
        ),
    ),
)


def _inert_artifacts() -> tuple[
    PolicyBundle,
    tuple[object, ...],
]:
    evidence = EvidenceLevelsPolicy(
        schema_version="1.0",
        policy_id="evidence_levels",
        policy_version=1,
        source_grades=("T1",),
        empirical_support=("unassessed",),
    )
    relations = RelationTypesPolicy(
        schema_version="1.0",
        policy_id="relation_types",
        policy_version=1,
        global_relation_types=("CITES",),
    )
    retention = RetentionPolicy(
        schema_version="1.0",
        policy_id="retention",
        policy_version=1,
        retention_categories=("identity_mapping",),
    )
    rule = RiskRulePolicy(
        rule_id="synthetic_general_observation",
        version=1,
        category="synthetic_general_observation",
        level="general",
        pattern_type="literal",
        pattern="inert",
        negation_window_tokens=0,
        required_context=("synthetic_context_present",),
        suggested_questions=("inert",),
    )
    risks = RiskRulesPolicy(
        schema_version="1.0",
        policy_id="risk_rules",
        policy_version=1,
        rules=(rule,),
    )

    def loaded(filename: str, policy_id: str, document: object) -> LoadedPolicy[object]:
        return LoadedPolicy(
            filename=filename,
            schema_version="1.0",
            policy_id=policy_id,
            policy_version=1,
            raw_bytes_sha256="0" * 64,
            canonical_bytes=b"{}",
            content_sha256="1" * 64,
            document=document,
        )

    loaded_evidence = loaded("evidence-levels.yaml", "evidence_levels", evidence)
    loaded_relations = loaded("relation-types.yaml", "relation_types", relations)
    loaded_retention = loaded("retention.yaml", "retention", retention)
    loaded_risks = loaded("risk-rules.yaml", "risk_rules", risks)
    bundle = PolicyBundle(
        evidence_levels=loaded_evidence,
        relation_types=loaded_relations,
        retention=loaded_retention,
        risk_rules=loaded_risks,
    )
    return bundle, (
        evidence,
        relations,
        retention,
        rule,
        risks,
        loaded_evidence,
        loaded_relations,
        loaded_retention,
        loaded_risks,
        bundle,
    )


def _assert_serialization_forbidden(value: object) -> None:
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"^POLICY_SERIALIZATION_FORBIDDEN$"):
            operation(value)


def _policy_config(tmp_path: Path, label: str) -> tuple[Path, AppConfig]:
    root = tmp_path / label
    repo = root / "repo"
    vault = root / "vault"
    (repo / ".git").mkdir(parents=True)
    vault.mkdir()
    shutil.copytree(_CHECKOUT_ROOT / "policies", repo / "policies")
    return repo, AppConfig.from_values(repo, vault)


def _run_git(*arguments: str, cwd: Path | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )
    return completed.stdout


def _expect_policy_error(
    config: AppConfig,
    code: str,
    policy_id: str | None = None,
) -> PolicyLoadError:
    expected = code if policy_id is None else f"{code}:{policy_id}"
    with pytest.raises(PolicyLoadError, match=rf"^{expected}$") as caught:
        PolicyLoader.from_config(config).load_all()
    assert caught.value.code == code
    assert caught.value.policy_id == policy_id
    assert str(caught.value) == expected
    return caught.value


def _replace_bytes(path: Path, old: bytes, new: bytes) -> None:
    raw = path.read_bytes()
    assert old in raw
    path.write_bytes(raw.replace(old, new, 1))


def _pad_last_line(path: Path, target_size: int) -> None:
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    padding = target_size - len(raw)
    assert padding >= 0
    path.write_bytes(raw[:-1] + (b" " * padding) + b"\n")
    assert path.stat().st_size == target_size


def _yaml_metrics(raw: bytes) -> tuple[int, int, int]:
    root = yaml.compose(raw.decode("utf-8"), Loader=yaml.SafeLoader)
    assert root is not None

    def visit(node: yaml.Node, depth: int) -> tuple[int, int, int]:
        count = 1
        maximum_depth = depth
        maximum_scalar = len(node.value) if isinstance(node, yaml.ScalarNode) else 0
        if isinstance(node, yaml.MappingNode):
            children = tuple(
                child
                for pair in node.value
                for child in pair
            )
        elif isinstance(node, yaml.SequenceNode):
            children = tuple(node.value)
        else:
            children = ()
        for child in children:
            child_count, child_depth, child_scalar = visit(child, depth + 1)
            count += child_count
            maximum_depth = max(maximum_depth, child_depth)
            maximum_scalar = max(maximum_scalar, child_scalar)
        return count, maximum_depth, maximum_scalar

    return visit(root, 1)


def _raw_with_node_count(path: Path, target: int) -> bytes:
    prefix = path.read_bytes()[:-1] + b"\npadding:\n"
    base_count, _depth, _scalar = _yaml_metrics(prefix)
    assert base_count <= target
    raw = prefix + (b"  - n\n" * (target - base_count))
    assert _yaml_metrics(raw)[0] == target
    return raw


def _raw_with_depth(path: Path, target: int) -> bytes:
    prefix = path.read_bytes()[:-1]
    for levels in range(1, target + 1):
        value = (b"[" * levels) + b"n" + (b"]" * levels)
        raw = prefix + b"\npadding: " + value + b"\n"
        if _yaml_metrics(raw)[1] == target:
            return raw
    raise AssertionError("unable to build depth fixture")


def _clone_stat(status: os.stat_result, **changes: int) -> SimpleNamespace:
    names = (
        "st_mode",
        "st_dev",
        "st_ino",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_file_attributes",
    )
    values = {
        name: int(getattr(status, name, 0))
        for name in names
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _mutated_policy_error(
    tmp_path: Path,
    label: str,
    filename: str,
    old: bytes,
    new: bytes,
    code: str,
    policy_id: str,
) -> None:
    repo, config = _policy_config(tmp_path, label)
    _replace_bytes(repo / "policies" / filename, old, new)
    _expect_policy_error(config, code, policy_id)


def _expected_plain_documents() -> dict[str, dict[str, object]]:
    return {
        "evidence_levels": {
            "schema_version": "1.0",
            "policy_id": "evidence_levels",
            "policy_version": 1,
            "source_grades": list(_SOURCE_GRADES),
            "empirical_support": list(_EMPIRICAL_SUPPORT),
        },
        "relation_types": {
            "schema_version": "1.0",
            "policy_id": "relation_types",
            "policy_version": 1,
            "global_relation_types": list(_RELATION_TYPES),
        },
        "retention": {
            "schema_version": "1.0",
            "policy_id": "retention",
            "policy_version": 1,
            "retention_categories": list(_RETENTION_CATEGORIES),
        },
        "risk_rules": {
            "schema_version": "1.0",
            "policy_id": "risk_rules",
            "policy_version": 1,
            "rules": [
                {
                    "rule_id": values[0],
                    "version": values[1],
                    "category": values[2],
                    "level": values[3],
                    "pattern_type": values[4],
                    "pattern": values[5],
                    "negation_window_tokens": values[6],
                    "required_context": list(values[7]),
                    "suggested_questions": list(values[8]),
                }
                for values in _RISK_RULE_VALUES
            ],
        },
    }


class TestPolicyPublicContract:
    @pytest.mark.acceptance_id("POLICY-01")
    def test_policy_01_canonical_bundle(
        self,
        repo_root: Path,
        tmp_path: Path,
    ) -> None:
        suffix = hashlib.sha256(os.fspath(tmp_path).encode("utf-8")).hexdigest()[:16]
        vault = repo_root.parent / f"policy-vault-{suffix}"
        vault.mkdir()
        try:
            bundle = PolicyLoader.from_config(
                AppConfig.from_values(repo_root, vault)
            ).load_all()
        finally:
            shutil.rmtree(vault)

        assert tuple(field.name for field in fields(type(bundle))) == (
            "evidence_levels",
            "relation_types",
            "retention",
            "risk_rules",
        )
        artifacts = (
            bundle.evidence_levels,
            bundle.relation_types,
            bundle.retention,
            bundle.risk_rules,
        )
        assert tuple(value.filename for value in artifacts) == (
            "evidence-levels.yaml",
            "relation-types.yaml",
            "retention.yaml",
            "risk-rules.yaml",
        )
        assert tuple(value.policy_id for value in artifacts) == (
            "evidence_levels",
            "relation_types",
            "retention",
            "risk_rules",
        )
        assert all(value.schema_version == "1.0" for value in artifacts)
        assert all(type(value.policy_version) is int for value in artifacts)
        assert all(value.policy_version == 1 for value in artifacts)
        assert all(
            tuple(field.name for field in fields(type(value))) == _LOADED_FIELDS
            for value in artifacts
        )
        assert bundle.evidence_levels.document.source_grades == _SOURCE_GRADES
        assert (
            bundle.evidence_levels.document.empirical_support
            == _EMPIRICAL_SUPPORT
        )
        assert (
            bundle.relation_types.document.global_relation_types
            == _RELATION_TYPES
        )
        assert (
            bundle.retention.document.retention_categories
            == _RETENTION_CATEGORIES
        )
        assert len(bundle.risk_rules.document.rules) == 14

    @pytest.mark.acceptance_id("POLICY-03")
    def test_policy_03_repo_root_not_cwd(
        self,
        repo_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        suffix = hashlib.sha256(os.fspath(tmp_path).encode("utf-8")).hexdigest()[:16]
        vault = repo_root.parent / f"policy-vault-cwd-{suffix}"
        vault.mkdir()
        unrelated_cwd = vault / "unrelated-cwd"
        unrelated_cwd.mkdir()
        monkeypatch.chdir(unrelated_cwd)
        try:
            bundle = PolicyLoader.from_config(
                AppConfig.from_values(repo_root, vault)
            ).load_all()
        finally:
            monkeypatch.chdir(repo_root)
            shutil.rmtree(vault)
        assert bundle.evidence_levels.filename == "evidence-levels.yaml"
        assert bundle.risk_rules.policy_id == "risk_rules"

    @pytest.mark.acceptance_id("POLICY-04")
    def test_policy_04_no_resource_fallback_or_caller_filename(
        self,
        synthetic_workspace: tuple[Path, Path],
    ) -> None:
        source = inspect.getsource(inspect.getmodule(PolicyLoader))
        assert "importlib.resources" not in source
        assert "pkg_resources" not in source
        assert "load_one" not in vars(PolicyLoader)
        assert "load_file" not in vars(PolicyLoader)
        assert tuple(inspect.signature(PolicyLoader.from_config).parameters) == (
            "config",
        )
        assert tuple(inspect.signature(PolicyLoader.load_all).parameters) == (
            "self",
        )
        repo, vault = synthetic_workspace
        _expect_policy_error(
            AppConfig.from_values(repo, vault),
            "POLICY_DIRECTORY_MISSING",
        )

    @pytest.mark.acceptance_id("POLICY-16")
    def test_policy_16_no_reply_generator_dependency(self) -> None:
        source = inspect.getsource(inspect.getmodule(PolicyLoader))
        for forbidden in (
            "reply_generator",
            "ReplyGenerator",
            "risk_engine",
            "RiskEngine",
            "natural_language_goal",
        ):
            assert forbidden not in source

    @pytest.mark.acceptance_id("POLICY-17")
    def test_policy_17_public_success_type_repr_and_serializer_bans(
        self,
        synthetic_workspace: tuple[Path, Path],
    ) -> None:
        bundle, artifacts = _inert_artifacts()
        expected_reprs = (
            "<EvidenceLevelsPolicy redacted>",
            "<RelationTypesPolicy redacted>",
            "<RetentionPolicy redacted>",
            "<RiskRulePolicy redacted>",
            "<RiskRulesPolicy redacted>",
            "<LoadedPolicy redacted>",
            "<LoadedPolicy redacted>",
            "<LoadedPolicy redacted>",
            "<LoadedPolicy redacted>",
            "<PolicyBundle redacted>",
        )
        assert tuple(repr(value) for value in artifacts) == expected_reprs
        for value in artifacts:
            _assert_serialization_forbidden(value)
            for serializer_name in (
                "asdict",
                "astuple",
                "dict",
                "json",
                "model_dump",
                "to_dict",
            ):
                assert not hasattr(value, serializer_name)

        repo, vault = synthetic_workspace
        loader = PolicyLoader.from_config(AppConfig.from_values(repo, vault))
        assert repr(loader) == "<PolicyLoader redacted>"
        _assert_serialization_forbidden(loader)
        assert tuple(field.name for field in fields(type(bundle.evidence_levels))) == (
            _LOADED_FIELDS
        )
        assert get_args(PolicyId) == (
            "evidence_levels",
            "relation_types",
            "retention",
            "risk_rules",
        )
        assert get_args(PolicyFilename) == _POLICY_FILENAMES

    @pytest.mark.acceptance_id("POLICY-21")
    def test_policy_21_loader_and_error_redaction_surface(
        self,
        synthetic_workspace: tuple[Path, Path],
    ) -> None:
        repo, vault = synthetic_workspace
        loader = PolicyLoader.from_config(AppConfig.from_values(repo, vault))
        assert repr(loader) == "<PolicyLoader redacted>"
        error = PolicyLoadError("POLICY_DIRECTORY_MISSING", "risk_rules")
        assert error.code == "POLICY_DIRECTORY_MISSING"
        assert error.policy_id == "risk_rules"
        assert str(error) == "POLICY_DIRECTORY_MISSING:risk_rules"
        assert repr(error) == "<PolicyLoadError redacted>"
        for secret in (str(repo), str(vault), "risk-rules.yaml", "inert"):
            assert secret not in repr(loader)
            assert secret not in repr(error)
            assert secret not in str(error)

    @pytest.mark.acceptance_id("POLICY-22")
    @pytest.mark.acceptance_id("CFG-25")
    def test_policy_22_exact_app_config_only(
        self,
        synthetic_workspace: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, vault = synthetic_workspace
        config = AppConfig.from_values(repo, vault)

        def forbid_io(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("from_config performed I/O")

        io_seams = (
            "_LSTAT",
            "_STAT",
            "_FSTAT",
            "_FSTAT_DIRECTORY",
            "_OPEN",
            "_READ",
            "_CLOSE",
            "_CLOSE_DIRECTORY",
            "_SCANDIR",
            "_WINDOWS_CREATE_FILE",
            "_WINDOWS_OPEN_OSFHANDLE",
            "_WINDOWS_CLOSE_HANDLE",
            "_windows_descriptor",
            "_open_directory_descriptor",
            "_open_file_descriptor_no_follow",
            "_entry_lstat",
            "_open_policy_directory",
            "_snapshot_directory",
        )
        for seam in io_seams:
            assert hasattr(policy_loader_module, seam)
            monkeypatch.setattr(policy_loader_module, seam, forbid_io)
        with pytest.raises(
            AssertionError,
            match=r"^from_config performed I/O$",
        ):
            policy_loader_module._LSTAT(repo)
        loader = PolicyLoader.from_config(config)
        assert repr(loader) == "<PolicyLoader redacted>"

        for invalid in (repo, str(repo), object(), {"repo_root": repo}):
            for construct in (PolicyLoader.from_config, PolicyLoader):
                with pytest.raises(
                    PolicyLoadError,
                    match=r"^POLICY_VALIDATED_CONFIG_REQUIRED$",
                ) as caught:
                    construct(invalid)  # type: ignore[arg-type]
                assert caught.value.code == "POLICY_VALIDATED_CONFIG_REQUIRED"
                assert caught.value.policy_id is None

        project_root = Path(__file__).resolve().parents[3]
        script = "\n".join(
            (
                "from consultation_kb.core.config import AppConfig",
                "from consultation_kb.policy.loader import PolicyLoadError, PolicyLoader",
                "original_seal = AppConfig.__dict__['__init_subclass__']",
                "def allow_test_subclass(_cls, **_kwargs):",
                "    return None",
                "def reject_attribute_access(self, _name):",
                "    raise AssertionError('ATTRIBUTE_ACCESS_ORACLE')",
                "try:",
                "    setattr(AppConfig, '__init_subclass__', classmethod(allow_test_subclass))",
                "    UncheckedConfig = type.__new__(",
                "        type(AppConfig),",
                "        'UncheckedConfig',",
                "        (AppConfig,),",
                "        {'__getattribute__': reject_attribute_access},",
                "    )",
                "    unchecked = object.__new__(UncheckedConfig)",
                "finally:",
                "    setattr(AppConfig, '__init_subclass__', original_seal)",
                "for construct in (PolicyLoader.from_config, PolicyLoader):",
                "    try:",
                "        construct(unchecked)",
                "    except PolicyLoadError as error:",
                "        assert type(error) is PolicyLoadError",
                "        assert error.args == ('POLICY_VALIDATED_CONFIG_REQUIRED',)",
                "        assert error.policy_id is None",
                "    else:",
                "        raise AssertionError('unchecked subtype was accepted')",
            )
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(project_root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        before = tuple(sorted(os.listdir(repo.parent)))
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repo.parent,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == ""
        assert completed.stderr == ""
        assert tuple(sorted(os.listdir(repo.parent))) == before

    @pytest.mark.acceptance_id("POLICY-22")
    @pytest.mark.acceptance_id("CFG-25")
    def test_policy_22_loader_root_is_frozen(self, tmp_path: Path) -> None:
        repo, config = _policy_config(tmp_path, "loader-frozen")
        rogue_root = tmp_path / "rogue-root"
        shutil.copytree(repo / "policies", rogue_root / "policies")

        def rebind(loader: PolicyLoader) -> None:
            loader._repo_root = rogue_root  # type: ignore[attr-defined]

        def delete(loader: PolicyLoader) -> None:
            del loader._repo_root  # type: ignore[attr-defined]

        for mutate in (rebind, delete):
            loader = PolicyLoader.from_config(config)
            with pytest.raises(
                AttributeError,
                match=r"^POLICY_LOADER_FROZEN$",
            ):
                mutate(loader)
            bundle = loader.load_all()
            assert bundle.evidence_levels.raw_bytes_sha256 == hashlib.sha256(
                (repo / "policies" / "evidence-levels.yaml").read_bytes(),
            ).hexdigest()

        with pytest.raises(
            TypeError,
            match=r"^POLICY_LOADER_SUBCLASS_FORBIDDEN$",
        ) as caught:

            class RootBypass(PolicyLoader):
                __slots__ = ("rogue",)

                def __init__(self, root: Path) -> None:
                    object.__setattr__(self, "rogue", root)

                @property
                def _repo_root(self) -> Path:
                    return self.rogue

        assert caught.value.args == ("POLICY_LOADER_SUBCLASS_FORBIDDEN",)
        public_error = f"{caught.value!s} {caught.value!r} {caught.value.args!r}"
        for secret in (str(rogue_root), "RootBypass", "rogue"):
            assert secret not in public_error

    @pytest.mark.acceptance_id("POLICY-22")
    @pytest.mark.acceptance_id("CFG-25")
    def test_policy_22_multiple_inheritance_entry_guard(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        rogue_root = tmp_path / "never-validated-root"
        shutil.copytree(_CHECKOUT_ROOT / "policies", rogue_root / "policies")

        class NonDelegatingBase:
            def __init_subclass__(cls, **kwargs: object) -> None:
                del cls, kwargs

        class MultipleInheritanceBypass(NonDelegatingBase, PolicyLoader):
            __slots__ = ("rogue",)

            def __init__(self, root: Path) -> None:
                object.__setattr__(self, "rogue", root)

            @property
            def _repo_root(self) -> Path:
                return self.rogue

        loader = MultipleInheritanceBypass(rogue_root)
        assert isinstance(loader, PolicyLoader)
        assert type(loader) is MultipleInheritanceBypass
        assert MultipleInheritanceBypass.load_all is PolicyLoader.load_all
        assert loader._repo_root == rogue_root

        io_calls: list[str] = []

        def forbidden_io(seam: str) -> object:
            def invoke(*args: object, **kwargs: object) -> object:
                del args, kwargs
                io_calls.append(seam)
                raise AssertionError("FILESYSTEM_IO_FORBIDDEN")

            return invoke

        io_seams = (
            "_LSTAT",
            "_STAT",
            "_FSTAT",
            "_FSTAT_DIRECTORY",
            "_OPEN",
            "_READ",
            "_CLOSE",
            "_CLOSE_DIRECTORY",
            "_SCANDIR",
            "_WINDOWS_CREATE_FILE",
            "_WINDOWS_OPEN_OSFHANDLE",
            "_WINDOWS_CLOSE_HANDLE",
        )
        failure: BaseException | None = None
        with monkeypatch.context() as patch:
            for seam in io_seams:
                patch.setattr(policy_loader_module, seam, forbidden_io(seam))
            try:
                loader.load_all()
            except BaseException as error:
                failure = error

        assert io_calls == []
        assert type(failure) is PolicyLoadError
        assert failure.args == ("POLICY_VALIDATED_CONFIG_REQUIRED",)
        assert failure.code == "POLICY_VALIDATED_CONFIG_REQUIRED"
        assert failure.policy_id is None
        assert failure.__cause__ is None
        assert failure.__context__ is None
        public_error = f"{failure!s} {failure!r} {failure.args!r}"
        for secret in (
            str(rogue_root),
            "NonDelegatingBase",
            "MultipleInheritanceBypass",
            "_repo_root",
            "rogue",
        ):
            assert secret not in public_error

    @pytest.mark.acceptance_id("POLICY-23")
    def test_policy_23_audit_metadata_surface(self) -> None:
        bundle, _artifacts = _inert_artifacts()
        loaded = bundle.evidence_levels
        metadata = loaded.audit_metadata()
        assert tuple(field.name for field in fields(type(loaded))) == _LOADED_FIELDS
        assert tuple(field.name for field in fields(PolicyAuditMetadata)) == _AUDIT_FIELDS
        assert repr(metadata) == "<PolicyAuditMetadata redacted>"
        assert metadata == PolicyAuditMetadata(
            filename="evidence-levels.yaml",
            policy_id="evidence_levels",
            policy_version=1,
            raw_bytes_sha256="0" * 64,
            content_sha256="1" * 64,
        )
        _assert_serialization_forbidden(metadata)
        assert not hasattr(metadata, "document")
        assert not hasattr(metadata, "canonical_bytes")

    @pytest.mark.acceptance_id("POLICY-28")
    def test_policy_28_no_bundle_identity(self) -> None:
        bundle, _artifacts = _inert_artifacts()
        assert tuple(field.name for field in fields(type(bundle))) == (
            "evidence_levels",
            "relation_types",
            "retention",
            "risk_rules",
        )
        for forbidden in (
            "audit_metadata",
            "bundle_digest",
            "canonical_bytes",
            "content_sha256",
            "digest",
            "identity",
            "raw_bytes_sha256",
        ):
            assert not hasattr(bundle, forbidden)


class TestRiskRuleMemberIdentity:
    @pytest.mark.acceptance_id("POLICY-24")
    def test_policy_24_field_order_and_known_vectors(
        self,
        tmp_path: Path,
    ) -> None:
        identity_type = getattr(
            policy_loader_module,
            "RiskRuleMemberIdentity",
        )
        member_identities = getattr(
            policy_loader_module,
            "risk_rule_member_identities",
        )
        _repo, config = _policy_config(tmp_path, "member-known-vectors")
        loaded = PolicyLoader.from_config(config).load_all().risk_rules
        identities = member_identities(loaded)

        assert tuple(field.name for field in fields(identity_type)) == (
            "owner_schema_version",
            "owner_policy_id",
            "owner_policy_version",
            "owner_content_sha256",
            "member_kind",
            "member_ordinal",
            "rule_id",
            "version",
            "canonical_bytes",
            "content_sha256",
        )
        assert loaded.content_sha256 == (
            "37c66b3db4f6d204fbf30e52408cbc9ecf2491c0464905aa2d24235b437e2f85"
        )
        assert tuple(identity.content_sha256 for identity in identities) == (
            "9868ab6640dfdc453223dec233975c477855690388db45290136ea388f93f606",
            "2ed515d3efd3ff02061662ce7ba89d2fe7fbd9a3243b6d1c9d99fd8bee78f558",
            "f02a399925f32c5943f50ee0e981fda9d1e0a55e8c0fbf68e7f0e4ca1276021a",
            "e68d0a3cf09f0699fce909975eef6f0b8f7402830e5e306b15b24b8230793912",
            "c2e5b581794946f279deeb9aa267260a12d5301e548c68af17cec7dd831342ba",
            "17f9dd577b668f0128c4391c9fa03f679ef8dd97596520fbbf65519f60ae4e7d",
            "be7efcaecdc1d5e4944fece739029fac9c96ba5e7cec0bde4a4edad431f9e8d7",
            "c72f71ac2516ddeffd2183c946dac60860f61d9012ca17f1765a60f9ead04d52",
            "d22fc42651343b36a6fcc995ca0c57c3306ccac93ebcfa236c14069d2bdc4867",
            "be51c4812f7b82a85719246d1528d326b9523b15a3e154841809f4767fb12df8",
            "9a682fd56c6e9e47f027f474d190c7b6eb698915e9209c7878c7ed2674669a18",
            "38473593c8e1c04246b1b4709da51fa1847943424ec2388f046afd3c9de4a105",
            "2e2627bf3f9ba3a8d4fe3bdb861d6f6ae7f3e4694c2b1ad08dee5d5f2a7e282f",
            "7c7217e9f1fb2aeacef5e1a185cc47ae7d0c195fd3c0b461f871c04e8b5854ba",
        )

        assert len(identities) == len(loaded.document.rules) == 14
        for ordinal, (identity, rule) in enumerate(
            zip(identities, loaded.document.rules, strict=True)
        ):
            assert type(identity) is identity_type
            assert identity.owner_schema_version == loaded.schema_version == "1.0"
            assert identity.owner_policy_id == loaded.policy_id == "risk_rules"
            assert identity.owner_policy_version == loaded.policy_version == 1
            assert identity.owner_content_sha256 == loaded.content_sha256
            assert identity.member_kind == "risk_rule"
            assert identity.member_ordinal == ordinal
            assert identity.rule_id == rule.rule_id
            assert identity.version == rule.version == 1
            assert hashlib.sha256(identity.canonical_bytes).hexdigest() == (
                identity.content_sha256
            )
            assert identity.canonical_bytes[-1:] != b"\n"
            assert json.loads(identity.canonical_bytes) == {
                "owner": {
                    "schema_version": loaded.schema_version,
                    "policy_id": loaded.policy_id,
                    "policy_version": loaded.policy_version,
                    "content_sha256": loaded.content_sha256,
                },
                "member_kind": "risk_rule",
                "member_ordinal": ordinal,
                "member": {
                    "rule_id": rule.rule_id,
                    "version": rule.version,
                    "category": rule.category,
                    "level": rule.level,
                    "pattern_type": rule.pattern_type,
                    "pattern": rule.pattern,
                    "negation_window_tokens": rule.negation_window_tokens,
                    "required_context": list(rule.required_context),
                    "suggested_questions": list(rule.suggested_questions),
                },
            }
            assert repr(identity) == "<RiskRuleMemberIdentity redacted>"
            assert not hasattr(identity, "__dict__")
            _assert_serialization_forbidden(identity)
            with pytest.raises(FrozenInstanceError):
                identity.member_ordinal = 9  # type: ignore[misc]

    @pytest.mark.acceptance_id("POLICY-24")
    def test_policy_24_owner_ordinal_and_member_mutations_change_or_reject(
        self,
        tmp_path: Path,
    ) -> None:
        member_identities = getattr(
            policy_loader_module,
            "risk_rule_member_identities",
        )
        _repo, config = _policy_config(tmp_path, "member-mutations")
        loaded = PolicyLoader.from_config(config).load_all().risk_rules
        baseline = member_identities(loaded)
        assert tuple(identity.member_ordinal for identity in baseline) == tuple(
            range(14)
        )
        assert baseline[0].content_sha256 != baseline[1].content_sha256

        def assert_invalid(candidate: object) -> None:
            with pytest.raises(
                PolicyLoadError,
                match=r"^POLICY_MEMBER_IDENTITY_INVALID$",
            ) as caught:
                member_identities(candidate)
            assert caught.value.args == ("POLICY_MEMBER_IDENTITY_INVALID",)
            assert caught.value.code == "POLICY_MEMBER_IDENTITY_INVALID"
            assert caught.value.policy_id is None
            assert caught.value.__cause__ is None
            assert caught.value.__context__ is None

        owner_mutations = (
            replace(loaded, filename="evidence-levels.yaml"),
            replace(loaded, schema_version="9.0"),  # type: ignore[arg-type]
            replace(loaded, policy_id="retention"),
            replace(loaded, policy_version=2),  # type: ignore[arg-type]
            replace(loaded, raw_bytes_sha256="G" * 64),
            replace(loaded, canonical_bytes=loaded.canonical_bytes + b" "),
            replace(loaded, content_sha256="0" * 64),
        )
        for candidate in owner_mutations:
            assert_invalid(candidate)

        def rebound(document: RiskRulesPolicy) -> LoadedPolicy[RiskRulesPolicy]:
            raw_hash, canonical, content_hash = policy_loader_module._artifact_hashes(
                b"synthetic-risk-policy\n",
                "risk_rules",
                document,
            )
            return replace(
                loaded,
                raw_bytes_sha256=raw_hash,
                canonical_bytes=canonical,
                content_sha256=content_hash,
                document=document,
            )

        assert_invalid(rebound(replace(loaded.document, rules=tuple(reversed(
            loaded.document.rules
        )))))
        for owner_field, value in (
            ("schema_version", "9.0"),
            ("policy_id", "retention"),
            ("policy_version", 2),
        ):
            assert_invalid(
                rebound(replace(loaded.document, **{owner_field: value}))
            )

        first_rule = loaded.document.rules[0]
        member_mutations = (
            ("rule_id", "synthetic_general_changed"),
            ("version", 2),
            ("category", "synthetic_category_changed"),
            ("level", "high"),
            ("pattern_type", "regex"),
            ("pattern", "SYNTH-RISK-GENERAL-CHANGED"),
            ("negation_window_tokens", 1),
            ("required_context", ("synthetic_context_changed",)),
            ("suggested_questions", ("SYNTH-QUESTION-CHANGED",)),
        )
        for field_name, value in member_mutations:
            mutated_rule = replace(first_rule, **{field_name: value})
            mutated_document = replace(
                loaded.document,
                rules=(mutated_rule, loaded.document.rules[1]),
            )
            assert_invalid(rebound(mutated_document))

    @pytest.mark.acceptance_id("POLICY-25")
    def test_policy_25_fake_or_wrong_owner_loaded_policy_is_rejected(
        self,
        tmp_path: Path,
    ) -> None:
        member_identities = getattr(
            policy_loader_module,
            "risk_rule_member_identities",
        )
        _repo, config = _policy_config(tmp_path, "member-wrong-owner")
        bundle = PolicyLoader.from_config(config).load_all()
        loaded = bundle.risk_rules

        class ForgedLoadedPolicy(LoadedPolicy[RiskRulesPolicy]):
            pass

        forged_subtype = ForgedLoadedPolicy(
            filename=loaded.filename,
            schema_version=loaded.schema_version,
            policy_id=loaded.policy_id,
            policy_version=loaded.policy_version,
            raw_bytes_sha256=loaded.raw_bytes_sha256,
            canonical_bytes=loaded.canonical_bytes,
            content_sha256=loaded.content_sha256,
            document=loaded.document,
        )
        fake_loaded = LoadedPolicy(
            filename="risk-rules.yaml",
            schema_version="1.0",
            policy_id="risk_rules",
            policy_version=1,
            raw_bytes_sha256="0" * 64,
            canonical_bytes=b"{}",
            content_sha256="1" * 64,
            document=object(),
        )
        invalid_inputs = (
            bundle.evidence_levels,
            forged_subtype,
            fake_loaded,
            loaded.document.rules[0],
            object(),
        )
        for candidate in invalid_inputs:
            with pytest.raises(
                PolicyLoadError,
                match=r"^POLICY_MEMBER_IDENTITY_INVALID$",
            ) as caught:
                member_identities(candidate)
            error = caught.value
            assert type(error) is PolicyLoadError
            assert error.args == ("POLICY_MEMBER_IDENTITY_INVALID",)
            assert error.code == "POLICY_MEMBER_IDENTITY_INVALID"
            assert error.policy_id is None
            assert error.__cause__ is None
            assert error.__context__ is None
            public_text = f"{error!s} {error!r} {error.args!r}"
            for secret in (
                loaded.document.rules[0].rule_id,
                loaded.document.rules[0].pattern,
                loaded.content_sha256,
                loaded.canonical_bytes.hex(),
            ):
                assert secret not in public_text

    @pytest.mark.acceptance_id("POLICY-25")
    def test_policy_25_bare_rule_api_does_not_exist(
        self,
        tmp_path: Path,
    ) -> None:
        identity_type = getattr(
            policy_loader_module,
            "RiskRuleMemberIdentity",
        )
        member_identities = getattr(
            policy_loader_module,
            "risk_rule_member_identities",
        )
        assert tuple(inspect.signature(member_identities).parameters) == ("loaded",)

        _repo, config = _policy_config(tmp_path, "member-bare-rule")
        rule = PolicyLoader.from_config(
            config
        ).load_all().risk_rules.document.rules[0]
        with pytest.raises(
            PolicyLoadError,
            match=r"^POLICY_MEMBER_IDENTITY_INVALID$",
        ):
            member_identities(rule)

        for forbidden in (
            "canonical_bytes",
            "content_sha256",
            "identity",
            "member_identity",
            "owner_content_sha256",
        ):
            assert not hasattr(rule, forbidden)
        for forbidden in (
            "risk_rule_identity",
            "risk_rule_identity_from_rule",
            "risk_rule_member_identity_from_rule",
            "member_identity_from_rule",
            "policy_bundle_digest",
            "load_latest_policy",
            "materialize_risk_rule",
        ):
            assert not hasattr(policy_loader_module, forbidden)
        assert not hasattr(identity_type, "object_id")
        assert not hasattr(identity_type, "version_ref")
        source = inspect.getsource(policy_loader_module)
        for forbidden_token in (
            "ObjectId",
            "VersionRef",
            "NotImplemented",
            "immutable_manifest",
        ):
            assert forbidden_token not in source


class TestPolicyResourceSafety:
    @pytest.mark.acceptance_id("POLICY-02")
    def test_policy_02_exact_safe_file_set(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, config = _policy_config(tmp_path, "missing")
        (repo / "policies" / "relation-types.yaml").unlink()
        _expect_policy_error(config, "POLICY_FILE_SET_MISMATCH")

        repo, config = _policy_config(tmp_path, "extra")
        (repo / "policies" / "extra.yaml").write_bytes(b"extra\n")
        _expect_policy_error(config, "POLICY_FILE_SET_MISMATCH")

        repo, config = _policy_config(tmp_path, "subdir")
        (repo / "policies" / "nested").mkdir()
        _expect_policy_error(config, "POLICY_FILE_SET_MISMATCH")

        repo, config = _policy_config(tmp_path, "hardlink")
        target = repo / "policies" / "evidence-levels.yaml"
        link_source = repo / "hardlink-source"
        shutil.copyfile(target, link_source)
        target.unlink()
        os.link(link_source, target)
        _expect_policy_error(config, "POLICY_FILE_UNSAFE", "evidence_levels")

        repo, config = _policy_config(tmp_path, "reparse")
        target = repo / "policies" / "evidence-levels.yaml"
        real_lstat = os.lstat

        def reparse_lstat(path: object) -> object:
            status = real_lstat(path)
            if Path(path) == target:
                attributes = int(getattr(status, "st_file_attributes", 0)) | 0x400
                return _clone_stat(status, st_file_attributes=attributes)
            return status

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_LSTAT",
                reparse_lstat,
                raising=False,
            )
            _expect_policy_error(config, "POLICY_FILE_UNSAFE", "evidence_levels")

        repo, config = _policy_config(tmp_path, "directory-reparse")
        policy_root = repo / "policies"
        real_lstat = os.lstat

        def directory_reparse_lstat(path: object) -> object:
            status = real_lstat(path)
            if Path(path) == policy_root:
                attributes = int(getattr(status, "st_file_attributes", 0)) | 0x400
                return _clone_stat(status, st_file_attributes=attributes)
            return status

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_LSTAT",
                directory_reparse_lstat,
            )
            _expect_policy_error(config, "POLICY_DIRECTORY_UNSAFE")

    @pytest.mark.acceptance_id("POLICY-02")
    def test_policy_02_platform_no_follow_primitives(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        open_directory = getattr(
            policy_loader_module,
            "_open_directory_descriptor",
            None,
        )
        assert callable(open_directory), "directory no-follow seam is required"

        if os.name == "nt":
            create_file = getattr(
                policy_loader_module,
                "_WINDOWS_CREATE_FILE",
                None,
            )
            open_osfhandle = getattr(
                policy_loader_module,
                "_WINDOWS_OPEN_OSFHANDLE",
                None,
            )
            close_handle = getattr(
                policy_loader_module,
                "_WINDOWS_CLOSE_HANDLE",
                None,
            )
            assert callable(create_file)
            assert callable(open_osfhandle)
            assert callable(close_handle)

            calls: list[tuple[int, int, int]] = []

            def recording_create_file(
                path: str,
                desired_access: int,
                share_mode: int,
                security_attributes: int,
                creation_disposition: int,
                flags_and_attributes: int,
                template_file: int,
            ) -> int:
                calls.append(
                    (desired_access, share_mode, flags_and_attributes),
                )
                return create_file(
                    path,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file,
                )

            _repo, config = _policy_config(tmp_path, "windows-flags")
            with monkeypatch.context() as patch:
                patch.setattr(
                    policy_loader_module,
                    "_WINDOWS_CREATE_FILE",
                    recording_create_file,
                )
                PolicyLoader.from_config(config).load_all()

            open_reparse_point = 0x00200000
            backup_semantics = 0x02000000
            share_delete = 0x00000004
            directory_calls = [
                call for call in calls if call[2] & backup_semantics
            ]
            file_calls = [
                call for call in calls if not call[2] & backup_semantics
            ]
            assert len(directory_calls) == 1
            assert len(file_calls) == 4
            assert all(call[2] & open_reparse_point for call in calls)
            assert all(not call[1] & share_delete for call in calls)
            assert directory_calls[0][0] & 0x00000001
            assert all(call[0] & 0x80000000 for call in file_calls)

            for primitive in (
                "_WINDOWS_CREATE_FILE",
                "_WINDOWS_OPEN_OSFHANDLE",
                "_WINDOWS_CLOSE_HANDLE",
            ):
                _repo, config = _policy_config(
                    tmp_path,
                    f"missing-{primitive}",
                )
                with monkeypatch.context() as patch:
                    patch.setattr(policy_loader_module, primitive, None)
                    _expect_policy_error(config, "POLICY_DIRECTORY_UNSAFE")

        for primitive in ("_O_NOFOLLOW", "_O_NONBLOCK"):
            _repo, config = _policy_config(
                tmp_path,
                f"missing-posix-{primitive}",
            )
            open_calls = 0

            def forbidden_posix_open(*args: object, **kwargs: object) -> int:
                nonlocal open_calls
                del args, kwargs
                open_calls += 1
                raise AssertionError("POSIX_OPEN_RAN_WITH_MISSING_PRIMITIVE")

            with monkeypatch.context() as patch:
                patch.setattr(policy_loader_module, "_PLATFORM_NAME", "posix")
                patch.setattr(policy_loader_module, "_O_NOFOLLOW", 0x20000)
                patch.setattr(policy_loader_module, "_O_DIRECTORY", 0x10000)
                patch.setattr(
                    policy_loader_module,
                    "_O_NONBLOCK",
                    0x800,
                    raising=False,
                )
                patch.setattr(policy_loader_module, primitive, None)
                patch.setattr(policy_loader_module, "_OPEN_SUPPORTS_DIR_FD", True)
                patch.setattr(policy_loader_module, "_STAT_SUPPORTS_DIR_FD", True)
                patch.setattr(policy_loader_module, "_STAT_SUPPORTS_NOFOLLOW", True)
                patch.setattr(policy_loader_module, "_SCANDIR_SUPPORTS_FD", True)
                patch.setattr(policy_loader_module, "_OPEN", forbidden_posix_open)
                _expect_policy_error(config, "POLICY_DIRECTORY_UNSAFE")
            assert open_calls == 0

    @pytest.mark.acceptance_id("POLICY-05")
    def test_policy_05_encoding_and_newline_gate(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cases = (
            ("bom", lambda raw: b"\xef\xbb\xbf" + raw, "POLICY_ENCODING_INVALID"),
            ("invalid", lambda raw: b"\xff" + raw, "POLICY_ENCODING_INVALID"),
            ("null-byte", lambda raw: raw[:-1] + b"\x00\n", "POLICY_RAW_FORMAT_INVALID"),
            ("crlf", lambda raw: raw.replace(b"\n", b"\r\n"), "POLICY_RAW_FORMAT_INVALID"),
            ("no-newline", lambda raw: raw[:-1], "POLICY_RAW_FORMAT_INVALID"),
            ("two-newlines", lambda raw: raw + b"\n", "POLICY_RAW_FORMAT_INVALID"),
        )
        for label, mutate, code in cases:
            repo, config = _policy_config(tmp_path, label)
            path = repo / "policies" / "evidence-levels.yaml"
            path.write_bytes(mutate(path.read_bytes()))
            _expect_policy_error(config, code, "evidence_levels")

        def parser_must_not_run(raw: bytes, policy_id: str) -> object:
            del raw, policy_id
            raise AssertionError("parser ran before Unicode newline gate")

        for label, separator in (
            ("nel", b"\xc2\x85"),
            ("line-separator", b"\xe2\x80\xa8"),
            ("paragraph-separator", b"\xe2\x80\xa9"),
        ):
            repo, config = _policy_config(tmp_path, label)
            path = repo / "policies" / "evidence-levels.yaml"
            path.write_bytes(path.read_bytes().replace(b"\n", separator, 1))
            with monkeypatch.context() as patch:
                patch.setattr(
                    policy_loader_module,
                    "_parse_yaml",
                    parser_must_not_run,
                )
                _expect_policy_error(
                    config,
                    "POLICY_RAW_FORMAT_INVALID",
                    "evidence_levels",
                )

    @pytest.mark.acceptance_id("POLICY-05")
    def test_policy_05_checkout_eol_pin(self, tmp_path: Path) -> None:
        attributes_path = _CHECKOUT_ROOT / ".gitattributes"
        assert attributes_path.is_file(), "root .gitattributes is required"
        attributes_bytes = attributes_path.read_bytes()
        assert attributes_bytes == _ROOT_GIT_ATTRIBUTES

        source = tmp_path / "source"
        clone = tmp_path / "clone"
        vault = tmp_path / "vault"
        source.mkdir()
        (source / "docs" / "superpowers" / "specs").mkdir(parents=True)
        (source / "policies").mkdir()
        (source / "requirements").mkdir()
        (source / "schemas" / "nested").mkdir(parents=True)
        (source / "nested").mkdir()
        (source / ".gitattributes").write_bytes(attributes_bytes)
        (source / "nested" / ".gitattributes").write_bytes(
            b"# nested scope oracle\n",
        )

        real_target_bytes = {".gitattributes": attributes_bytes}
        pinned_paths: list[str] = []
        design_path = (
            "docs/superpowers/specs/"
            "2026-07-17-consultation-kb-p0-task4-security-policy-design.md"
        )
        design_bytes = (_CHECKOUT_ROOT / design_path).read_bytes()
        real_target_bytes[design_path] = design_bytes
        (source / design_path).write_bytes(design_bytes)
        pinned_paths.append(design_path)

        for filename in _POLICY_FILENAMES:
            git_path = f"policies/{filename}"
            pinned_paths.append(git_path)
            raw = (_CHECKOUT_ROOT / "policies" / filename).read_bytes()
            real_target_bytes[git_path] = raw
            (source / "policies" / filename).write_bytes(raw)

        requirement_path = "requirements/consultation-win-py312.in"
        requirement_bytes = (_CHECKOUT_ROOT / requirement_path).read_bytes()
        real_target_bytes[requirement_path] = requirement_bytes
        (source / requirement_path).write_bytes(requirement_bytes)
        pinned_paths.append(requirement_path)

        schema_paths = tuple(
            sorted(
                (_CHECKOUT_ROOT / "schemas").glob("*.schema.json"),
                key=lambda path: path.name,
            )
        )
        assert len(schema_paths) == 21
        for schema_path in schema_paths:
            git_path = f"schemas/{schema_path.name}"
            raw = schema_path.read_bytes()
            real_target_bytes[git_path] = raw
            (source / git_path).write_bytes(raw)
            pinned_paths.append(git_path)

        negative_targets = (
            "nested/.gitattributes",
            "schemas/nested/unpinned.schema.json",
            "schemas/unpinned.txt",
        )
        (source / negative_targets[1]).write_bytes(b"{}\n")
        (source / negative_targets[2]).write_bytes(b"not a schema\n")
        positive_targets = [".gitattributes", *pinned_paths]
        long_paths = ("-c", "core.longpaths=true")

        _run_git(
            "-c",
            "core.autocrlf=false",
            *long_paths,
            "init",
            "-q",
            str(source),
        )
        _run_git(
            "-c",
            "core.autocrlf=false",
            *long_paths,
            "-C",
            str(source),
            "add",
            "--",
            *positive_targets,
            *negative_targets,
        )
        _run_git(
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=policy-contract-test",
            "-c",
            "user.email=policy-contract-test@example.invalid",
            *long_paths,
            "-C",
            str(source),
            "commit",
            "-q",
            "-m",
            "policy checkout fixture",
        )

        committed_blobs: dict[str, bytes] = {}
        for git_path in positive_targets:
            blob = _run_git(
                *long_paths,
                "-C",
                str(source),
                "cat-file",
                "blob",
                f"HEAD:{git_path}",
            )
            assert blob == real_target_bytes[git_path]
            committed_blobs[git_path] = blob

        _run_git(
            "-c",
            "core.autocrlf=true",
            *long_paths,
            "clone",
            "--no-local",
            "--quiet",
            str(source),
            str(clone),
        )

        for git_path in positive_targets:
            effective = _run_git(
                "-c",
                "core.autocrlf=true",
                *long_paths,
                "-C",
                str(clone),
                "check-attr",
                "text",
                "eol",
                "--",
                git_path,
            ).decode("utf-8")
            assert effective.splitlines() == [
                f"{git_path}: text: set",
                f"{git_path}: eol: lf",
            ]
            checkout_bytes = (clone / Path(git_path)).read_bytes()
            assert checkout_bytes == committed_blobs[git_path]
            assert b"\r" not in checkout_bytes

        for git_path in negative_targets:
            negative_effective = _run_git(
                "-c",
                "core.autocrlf=true",
                *long_paths,
                "-C",
                str(clone),
                "check-attr",
                "text",
                "eol",
                "--",
                git_path,
            ).decode("utf-8")
            assert negative_effective.splitlines() == [
                f"{git_path}: text: unspecified",
                f"{git_path}: eol: unspecified",
            ]

        vault.mkdir()
        bundle = PolicyLoader.from_config(
            AppConfig.from_values(clone, vault),
        ).load_all()
        assert tuple(
            loaded.filename
            for loaded in (
                bundle.evidence_levels,
                bundle.relation_types,
                bundle.retention,
                bundle.risk_rules,
            )
        ) == _POLICY_FILENAMES

    @pytest.mark.acceptance_id("POLICY-06")
    def test_policy_06_raw_forbidden_bytes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def parser_must_not_run(raw: bytes, policy_id: str) -> object:
            del raw, policy_id
            raise AssertionError("parser ran before raw gate")

        cases = (
            ("comment", b'schema_version: "1.0"\n', b'schema_version: "1.0" # no\n'),
            ("quoted-hash", b'schema_version: "1.0"\n', b'schema_version: "1.#0"\n'),
            ("tab", b"  - T1\n", b"\t- T1\n"),
            ("directive", b'schema_version: "1.0"\n', b'%YAML 1.2\nschema_version: "1.0"\n'),
            ("document-start", b'schema_version: "1.0"\n', b'---\nschema_version: "1.0"\n'),
            ("document-end", b"  - conflicting\n", b"  - conflicting\n...\n"),
        )
        for label, old, new in cases:
            repo, config = _policy_config(tmp_path, f"raw-{label}")
            _replace_bytes(repo / "policies" / "evidence-levels.yaml", old, new)
            with monkeypatch.context() as patch:
                patch.setattr(
                    policy_loader_module,
                    "_parse_yaml",
                    parser_must_not_run,
                    raising=False,
                )
                _expect_policy_error(
                    config,
                    "POLICY_RAW_FORMAT_INVALID",
                    "evidence_levels",
                )

    @pytest.mark.acceptance_id("POLICY-08")
    def test_policy_08_forbidden_yaml_features(self, tmp_path: Path) -> None:
        cases = (
            (
                "anchor",
                b"source_grades:\n",
                b"source_grades: &grades\n",
                "POLICY_YAML_FORBIDDEN_FEATURE",
            ),
            (
                "alias",
                b"source_grades:\n",
                b"source_grades: &grades\n",
                "POLICY_YAML_FORBIDDEN_FEATURE",
            ),
            (
                "merge",
                b"source_grades:\n",
                b"source_grades: &base\n",
                "POLICY_YAML_FORBIDDEN_FEATURE",
            ),
            (
                "explicit-tag",
                b'schema_version: "1.0"\n',
                b'schema_version: !!str "1.0"\n',
                "POLICY_YAML_FORBIDDEN_FEATURE",
            ),
            (
                "custom-tag",
                b'schema_version: "1.0"\n',
                b'schema_version: !custom "1.0"\n',
                "POLICY_YAML_FORBIDDEN_FEATURE",
            ),
            (
                "multi-document",
                b'schema_version: "1.0"\n',
                b'---\nschema_version: "1.0"\n',
                "POLICY_RAW_FORMAT_INVALID",
            ),
        )
        for label, old, new, code in cases:
            repo, config = _policy_config(tmp_path, f"feature-{label}")
            path = repo / "policies" / "evidence-levels.yaml"
            _replace_bytes(path, old, new)
            if label == "alias":
                _replace_bytes(
                    path,
                    b"empirical_support:\n",
                    b"alias_copy: *grades\nempirical_support:\n",
                )
            if label == "merge":
                _replace_bytes(
                    path,
                    b"empirical_support:\n",
                    b"merged:\n  <<: *base\nempirical_support:\n",
                )
            _expect_policy_error(config, code, "evidence_levels")

    @pytest.mark.acceptance_id("POLICY-10")
    def test_policy_10_resource_limits(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert policy_loader_module._MAX_POLICY_BYTES == 65_536
        assert policy_loader_module._MAX_BUNDLE_BYTES == 262_144
        assert policy_loader_module._MAX_YAML_NODES == 4_096
        assert policy_loader_module._MAX_YAML_DEPTH == 16
        assert policy_loader_module._MAX_SCALAR_CODEPOINTS == 4_096

        repo, config = _policy_config(tmp_path, "file-equal")
        _pad_last_line(repo / "policies" / "evidence-levels.yaml", 65_536)
        PolicyLoader.from_config(config).load_all()

        repo, config = _policy_config(tmp_path, "file-plus-one")
        _pad_last_line(repo / "policies" / "evidence-levels.yaml", 65_537)
        _expect_policy_error(config, "POLICY_SIZE_LIMIT", "evidence_levels")

        repo, config = _policy_config(tmp_path, "bundle-equal")
        for filename in _POLICY_FILENAMES:
            _pad_last_line(repo / "policies" / filename, 65_536)
        PolicyLoader.from_config(config).load_all()

        repo, config = _policy_config(tmp_path, "bundle-plus-one")
        for filename in _POLICY_FILENAMES:
            _pad_last_line(repo / "policies" / filename, 65_536)
        _pad_last_line(repo / "policies" / "evidence-levels.yaml", 65_537)
        with monkeypatch.context() as patch:
            patch.setattr(policy_loader_module, "_MAX_POLICY_BYTES", 65_537)
            _expect_policy_error(config, "POLICY_SIZE_LIMIT", "risk_rules")

        repo, config = _policy_config(tmp_path, "nodes-equal")
        path = repo / "policies" / "retention.yaml"
        path.write_bytes(_raw_with_node_count(path, 4_096))
        try:
            PolicyLoader.from_config(config).load_all()
        except PolicyLoadError as error:
            assert error.code != "POLICY_STRUCTURE_LIMIT"

        repo, config = _policy_config(tmp_path, "nodes-plus-one")
        path = repo / "policies" / "retention.yaml"
        path.write_bytes(_raw_with_node_count(path, 4_097))
        _expect_policy_error(config, "POLICY_STRUCTURE_LIMIT", "retention")

        repo, config = _policy_config(tmp_path, "depth-equal")
        path = repo / "policies" / "retention.yaml"
        path.write_bytes(_raw_with_depth(path, 16))
        try:
            PolicyLoader.from_config(config).load_all()
        except PolicyLoadError as error:
            assert error.code != "POLICY_STRUCTURE_LIMIT"

        repo, config = _policy_config(tmp_path, "depth-plus-one")
        path = repo / "policies" / "retention.yaml"
        path.write_bytes(_raw_with_depth(path, 17))
        _expect_policy_error(config, "POLICY_STRUCTURE_LIMIT", "retention")

        repo, config = _policy_config(tmp_path, "scalar-equal")
        path = repo / "policies" / "risk-rules.yaml"
        _replace_bytes(path, b"SYNTH-RISK-GENERAL-4C2E", b"A" * 4_096)
        try:
            PolicyLoader.from_config(config).load_all()
        except PolicyLoadError as error:
            assert error.code != "POLICY_STRUCTURE_LIMIT"

        repo, config = _policy_config(tmp_path, "scalar-plus-one")
        path = repo / "policies" / "risk-rules.yaml"
        _replace_bytes(path, b"SYNTH-RISK-GENERAL-4C2E", b"A" * 4_097)
        _expect_policy_error(config, "POLICY_STRUCTURE_LIMIT", "risk_rules")

    @pytest.mark.acceptance_id("POLICY-20")
    def test_policy_20_read_and_directory_race(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _repo, config = _policy_config(tmp_path, "read-race")
        real_fstat = os.fstat
        calls = 0

        def drifting_fstat(file_descriptor: int) -> object:
            nonlocal calls
            status = real_fstat(file_descriptor)
            calls += 1
            if calls == 2:
                return _clone_stat(status, st_mtime_ns=status.st_mtime_ns + 1)
            return status

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_FSTAT",
                drifting_fstat,
                raising=False,
            )
            _expect_policy_error(
                config,
                "POLICY_CHANGED_DURING_READ",
                "evidence_levels",
            )

        _repo, config = _policy_config(tmp_path, "directory-race")
        original_snapshot = getattr(
            policy_loader_module,
            "_snapshot_directory",
            lambda _path: (),
        )
        snapshots = 0

        def drifting_snapshot(path: Path) -> tuple[object, ...]:
            nonlocal snapshots
            snapshot = tuple(original_snapshot(path))
            snapshots += 1
            if snapshots == 2:
                return snapshot + (("changed",),)
            return snapshot

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_snapshot_directory",
                drifting_snapshot,
                raising=False,
            )
            _expect_policy_error(config, "POLICY_CHANGED_DURING_READ")

        repo, config = _policy_config(tmp_path, "snapshot-restore-race")
        target = repo / "policies" / "evidence-levels.yaml"
        replacement = target.read_bytes().replace(
            b'schema_version: "1.0"\n',
            b'schema_version:  "1.0"\n',
            1,
        )
        original_snapshot = policy_loader_module._snapshot_directory
        saved_snapshot: tuple[object, ...] | None = None

        def restored_snapshot(path: Path) -> tuple[object, ...]:
            nonlocal saved_snapshot
            if saved_snapshot is None:
                saved_snapshot = tuple(original_snapshot(path))
                target.write_bytes(replacement)
            return saved_snapshot

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_snapshot_directory",
                restored_snapshot,
            )
            _expect_policy_error(
                config,
                "POLICY_CHANGED_DURING_READ",
                "evidence_levels",
            )

        _repo, config = _policy_config(tmp_path, "close-race")
        real_close = os.close

        def close_then_fail(file_descriptor: int) -> None:
            real_close(file_descriptor)
            raise OSError("synthetic close failure")

        with monkeypatch.context() as patch:
            patch.setattr(policy_loader_module, "_CLOSE", close_then_fail)
            _expect_policy_error(
                config,
                "POLICY_CHANGED_DURING_READ",
                "evidence_levels",
            )

    @pytest.mark.acceptance_id("POLICY-20")
    def test_policy_20_no_follow_race_boundaries(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        open_directory = getattr(
            policy_loader_module,
            "_open_directory_descriptor",
            None,
        )
        open_file = getattr(
            policy_loader_module,
            "_open_file_descriptor_no_follow",
            None,
        )
        assert callable(open_directory), "directory no-follow seam is required"
        assert callable(open_file), "file no-follow seam is required"

        repo, config = _policy_config(tmp_path, "directory-open-boundary")
        policy_root = repo / "policies"
        original_root = repo / "policies-before-open"

        def replace_directory_before_open(path: Path) -> int:
            assert path == policy_root
            path.rename(original_root)
            path.mkdir()
            return open_directory(path)

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_open_directory_descriptor",
                replace_directory_before_open,
            )
            _expect_policy_error(config, "POLICY_DIRECTORY_UNSAFE")

        repo, config = _policy_config(tmp_path, "file-open-boundary")
        target = repo / "policies" / "evidence-levels.yaml"
        original_file = repo / "evidence-before-open.yaml"
        swapped = False

        def replace_file_before_open(guard: object, filename: str) -> int:
            nonlocal swapped
            if filename == "evidence-levels.yaml" and not swapped:
                swapped = True
                target.rename(original_file)
                target.write_bytes(original_file.read_bytes())
            return open_file(guard, filename)

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_open_file_descriptor_no_follow",
                replace_file_before_open,
            )
            _expect_policy_error(
                config,
                "POLICY_CHANGED_DURING_READ",
                "evidence_levels",
            )

        repo, config = _policy_config(tmp_path, "directory-binding")
        policy_root = repo / "policies"
        renamed_root = repo / "renamed-policies"
        real_scandir = os.scandir
        observed_binding = False

        def binding_scandir(path: object) -> object:
            nonlocal observed_binding
            if not observed_binding:
                observed_binding = True
                if os.name == "nt":
                    with pytest.raises(PermissionError):
                        policy_root.rename(renamed_root)
                else:
                    assert type(path) is int
            return real_scandir(path)  # type: ignore[arg-type]

        with monkeypatch.context() as patch:
            patch.setattr(
                policy_loader_module,
                "_SCANDIR",
                binding_scandir,
            )
            PolicyLoader.from_config(config).load_all()
        assert observed_binding

    @pytest.mark.acceptance_id("POLICY-20")
    def test_policy_20_posix_fifo_swap_is_nonblocking(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, config = _policy_config(tmp_path, "posix-fifo-swap")
        policy_root = repo / "policies"
        target = policy_root / "evidence-levels.yaml"
        directory_descriptor = 73
        file_descriptor = 101
        nofollow = 0x20000
        directory = 0x10000
        nonblock = 0x800
        guard = policy_loader_module._DirectoryGuard(
            path=policy_root,
            descriptor=directory_descriptor,
            handle_relative=True,
        )
        initial_snapshot = (
            policy_loader_module._stat_identity(os.lstat(policy_root)),
            tuple(
                (
                    filename,
                    policy_loader_module._stat_identity(
                        os.lstat(policy_root / filename),
                    ),
                )
                for filename in _POLICY_FILENAMES
            ),
        )
        regular_status = os.lstat(target)
        fifo_status = _clone_stat(
            regular_status,
            st_mode=stat.S_IFIFO | 0o600,
            st_nlink=1,
            st_size=0,
        )
        open_entered = threading.Event()
        release_blocked_open = threading.Event()
        swapped_to_fifo = False
        observed_lstat_modes: list[int] = []
        observed_flags: list[int] = []
        outcomes: list[object] = []

        def fixed_guard(path: Path) -> object:
            assert path == policy_root
            return guard

        def fixed_snapshot(observed_guard: object) -> object:
            assert observed_guard is guard
            return initial_snapshot

        def raced_lstat(observed_guard: object, filename: str) -> object:
            assert observed_guard is guard
            if filename == "evidence-levels.yaml" and swapped_to_fifo:
                return fifo_status
            status = os.lstat(policy_root / filename)
            observed_lstat_modes.append(status.st_mode)
            return status

        def raced_open(
            filename: str,
            flags: int,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped_to_fifo
            assert filename == "evidence-levels.yaml"
            assert dir_fd == directory_descriptor
            observed_flags.append(flags)
            swapped_to_fifo = True
            open_entered.set()
            if not flags & nonblock:
                release_blocked_open.wait(timeout=5.0)
                raise OSError("synthetic blocking FIFO released")
            return file_descriptor

        def fifo_fstat(descriptor: int) -> object:
            assert descriptor == file_descriptor
            return fifo_status

        def close_descriptor(descriptor: int) -> None:
            assert descriptor in (directory_descriptor, file_descriptor)

        def invoke_public_loader() -> None:
            try:
                outcomes.append(PolicyLoader.from_config(config).load_all())
            except BaseException as error:
                outcomes.append(error)

        with monkeypatch.context() as patch:
            patch.setattr(policy_loader_module, "_PLATFORM_NAME", "posix")
            patch.setattr(policy_loader_module, "_O_NOFOLLOW", nofollow)
            patch.setattr(policy_loader_module, "_O_DIRECTORY", directory)
            patch.setattr(
                policy_loader_module,
                "_O_NONBLOCK",
                nonblock,
                raising=False,
            )
            patch.setattr(policy_loader_module, "_OPEN_SUPPORTS_DIR_FD", True)
            patch.setattr(policy_loader_module, "_STAT_SUPPORTS_DIR_FD", True)
            patch.setattr(policy_loader_module, "_STAT_SUPPORTS_NOFOLLOW", True)
            patch.setattr(policy_loader_module, "_SCANDIR_SUPPORTS_FD", True)
            patch.setattr(policy_loader_module, "_open_policy_directory", fixed_guard)
            patch.setattr(policy_loader_module, "_snapshot_directory", fixed_snapshot)
            patch.setattr(policy_loader_module, "_entry_lstat", raced_lstat)
            patch.setattr(policy_loader_module, "_OPEN", raced_open)
            patch.setattr(policy_loader_module, "_FSTAT", fifo_fstat)
            patch.setattr(policy_loader_module, "_CLOSE", close_descriptor)
            patch.setattr(
                policy_loader_module,
                "_CLOSE_DIRECTORY",
                close_descriptor,
            )

            worker = threading.Thread(target=invoke_public_loader, daemon=True)
            worker.start()
            entered_in_time = open_entered.wait(timeout=1.0)
            if entered_in_time:
                worker.join(timeout=1.0)
            returned_before_release = not worker.is_alive()
            release_blocked_open.set()
            worker.join(timeout=1.0)

        assert entered_in_time, "public load did not reach the POSIX file open"
        assert not worker.is_alive(), "bounded test worker did not terminate"
        assert returned_before_release, "public load blocked on a raced FIFO"
        assert observed_flags == [
            os.O_RDONLY
            | nofollow
            | nonblock
            | policy_loader_module._O_CLOEXEC
        ]
        assert observed_flags[0] & nonblock
        assert swapped_to_fifo
        assert len(observed_lstat_modes) == 1
        assert stat.S_ISREG(observed_lstat_modes[0])
        assert stat.S_ISFIFO(fifo_status.st_mode)
        assert len(outcomes) == 1
        failure = outcomes[0]
        assert type(failure) is PolicyLoadError
        assert failure.args == ("POLICY_FILE_UNSAFE:evidence_levels",)
        assert failure.code == "POLICY_FILE_UNSAFE"
        assert failure.policy_id == "evidence_levels"


class TestPolicyYamlContract:
    @pytest.mark.acceptance_id("POLICY-07")
    def test_policy_07_exact_keys_order_and_unique_arrays(
        self,
        tmp_path: Path,
    ) -> None:
        repo, config = _policy_config(tmp_path, "duplicate-top")
        path = repo / "policies" / "evidence-levels.yaml"
        _replace_bytes(
            path,
            b"policy_id: evidence_levels\n",
            b"policy_id: evidence_levels\npolicy_id: evidence_levels\n",
        )
        _expect_policy_error(config, "POLICY_YAML_DUPLICATE_KEY", "evidence_levels")

        repo, config = _policy_config(tmp_path, "duplicate-nested")
        path = repo / "policies" / "risk-rules.yaml"
        _replace_bytes(
            path,
            b"    version: 1\n",
            b"    version: 1\n    version: 1\n",
        )
        _expect_policy_error(config, "POLICY_YAML_DUPLICATE_KEY", "risk_rules")

        repo, config = _policy_config(tmp_path, "unknown-key")
        path = repo / "policies" / "retention.yaml"
        _replace_bytes(
            path,
            b"retention_categories:\n",
            b"unexpected: value\nretention_categories:\n",
        )
        _expect_policy_error(config, "POLICY_SCHEMA_INVALID", "retention")

        repo, config = _policy_config(tmp_path, "wrong-order")
        path = repo / "policies" / "relation-types.yaml"
        _replace_bytes(
            path,
            b'schema_version: "1.0"\npolicy_id: relation_types\n',
            b'policy_id: relation_types\nschema_version: "1.0"\n',
        )
        _expect_policy_error(config, "POLICY_SCHEMA_INVALID", "relation_types")

        repo, config = _policy_config(tmp_path, "duplicate-array")
        path = repo / "policies" / "evidence-levels.yaml"
        _replace_bytes(path, b"  - T2\n", b"  - T1\n")
        _expect_policy_error(config, "POLICY_SCHEMA_INVALID", "evidence_levels")

    @pytest.mark.acceptance_id("POLICY-09")
    def test_policy_09_exact_constructed_types(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        raw_cases = (
            ("bool-as-int", b"policy_version: 1\n", b"policy_version: true\n"),
            ("null", b"  - T1\n", b"  - null\n"),
            ("float", b"negation_window_tokens: 0\n", b"negation_window_tokens: 0.0\n"),
            ("timestamp", b'schema_version: "1.0"\n', b"schema_version: 2026-01-01\n"),
        )
        for label, old, new in raw_cases:
            repo, config = _policy_config(tmp_path, f"type-{label}")
            filename = "risk-rules.yaml" if label == "float" else "evidence-levels.yaml"
            policy_id = "risk_rules" if label == "float" else "evidence_levels"
            _replace_bytes(repo / "policies" / filename, old, new)
            _expect_policy_error(config, "POLICY_YAML_TYPE_INVALID", policy_id)

        canonical = yaml.safe_load(
            (_CHECKOUT_ROOT / "policies" / "evidence-levels.yaml").read_text(
                encoding="utf-8"
            )
        )
        for label, invalid in (("set", {"T1"}), ("object", object())):
            _repo, config = _policy_config(tmp_path, f"type-injected-{label}")
            parsed = copy.deepcopy(canonical)
            parsed["source_grades"] = invalid
            original_parse = getattr(policy_loader_module, "_parse_yaml", None)

            def injected(raw: bytes, policy_id: str) -> object:
                if policy_id == "evidence_levels":
                    return parsed
                assert original_parse is not None
                return original_parse(raw, policy_id)

            with monkeypatch.context() as patch:
                patch.setattr(
                    policy_loader_module,
                    "_parse_yaml",
                    injected,
                    raising=False,
                )
                _expect_policy_error(
                    config,
                    "POLICY_YAML_TYPE_INVALID",
                    "evidence_levels",
                )

    @pytest.mark.acceptance_id("POLICY-11")
    def test_policy_11_v1_versions_only(self, tmp_path: Path) -> None:
        cases = (
            (
                "schema-future",
                "evidence-levels.yaml",
                b'schema_version: "1.0"\n',
                b'schema_version: "2.0"\n',
                "evidence_levels",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "policy-zero",
                "retention.yaml",
                b"policy_version: 1\n",
                b"policy_version: 0\n",
                "retention",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "policy-two",
                "relation-types.yaml",
                b"policy_version: 1\n",
                b"policy_version: 2\n",
                "relation_types",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "policy-string",
                "retention.yaml",
                b"policy_version: 1\n",
                b'policy_version: "1"\n',
                "retention",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "member-zero",
                "risk-rules.yaml",
                b"    version: 1\n",
                b"    version: 0\n",
                "risk_rules",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "member-two",
                "risk-rules.yaml",
                b"    version: 1\n",
                b"    version: 2\n",
                "risk_rules",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "member-bool",
                "risk-rules.yaml",
                b"    version: 1\n",
                b"    version: true\n",
                "risk_rules",
                "POLICY_YAML_TYPE_INVALID",
            ),
        )
        for label, filename, old, new, policy_id, code in cases:
            repo, config = _policy_config(tmp_path, f"version-{label}")
            _replace_bytes(repo / "policies" / filename, old, new)
            _expect_policy_error(config, code, policy_id)


class TestPolicySemantics:
    @pytest.mark.acceptance_id("POLICY-12")
    def test_policy_12_evidence_model_parity(self, tmp_path: Path) -> None:
        _repo, config = _policy_config(tmp_path, "evidence-canonical")
        document = PolicyLoader.from_config(config).load_all().evidence_levels.document
        assert document.source_grades == get_args(SourceGrade) == _SOURCE_GRADES
        assert (
            document.empirical_support
            == get_args(EmpiricalSupport)
            == _EMPIRICAL_SUPPORT
        )
        source_adapter = TypeAdapter(SourceGrade)
        empirical_adapter = TypeAdapter(EmpiricalSupport)
        assert tuple(
            source_adapter.validate_python(value)
            for value in document.source_grades
        ) == document.source_grades
        assert tuple(
            empirical_adapter.validate_python(value)
            for value in document.empirical_support
        ) == document.empirical_support

        _mutated_policy_error(
            tmp_path,
            "evidence-invalid-model",
            "evidence-levels.yaml",
            b"  - T1\n",
            b"  - Z1\n",
            "POLICY_MODEL_PARITY_FAILED",
            "evidence_levels",
        )
        _mutated_policy_error(
            tmp_path,
            "evidence-order",
            "evidence-levels.yaml",
            b"  - T1\n  - T2\n",
            b"  - T2\n  - T1\n",
            "POLICY_MODEL_PARITY_FAILED",
            "evidence_levels",
        )
        _mutated_policy_error(
            tmp_path,
            "empirical-invalid-model",
            "evidence-levels.yaml",
            b"  - unassessed\n",
            b"  - unsupported\n",
            "POLICY_MODEL_PARITY_FAILED",
            "evidence_levels",
        )

    @pytest.mark.acceptance_id("POLICY-13")
    def test_policy_13_relation_tuple(self, tmp_path: Path) -> None:
        _repo, config = _policy_config(tmp_path, "relations-canonical")
        relations = (
            PolicyLoader.from_config(config)
            .load_all()
            .relation_types.document.global_relation_types
        )
        assert relations == _RELATION_TYPES
        assert relations[-1] == "SUPERSEDES"
        assert "REVOKES" not in relations

        _mutated_policy_error(
            tmp_path,
            "relations-revoke",
            "relation-types.yaml",
            b"  - SUPERSEDES\n",
            b"  - REVOKES\n",
            "POLICY_SEMANTICS_INVALID",
            "relation_types",
        )
        _mutated_policy_error(
            tmp_path,
            "relations-order",
            "relation-types.yaml",
            b"  - CITES\n  - SUPPORTS\n",
            b"  - SUPPORTS\n  - CITES\n",
            "POLICY_SEMANTICS_INVALID",
            "relation_types",
        )

    @pytest.mark.acceptance_id("POLICY-14")
    def test_policy_14_retention_tuple_and_non_authority(
        self,
        tmp_path: Path,
    ) -> None:
        _repo, config = _policy_config(tmp_path, "retention-canonical")
        document = PolicyLoader.from_config(config).load_all().retention.document
        assert document.retention_categories == _RETENTION_CATEGORIES
        assert tuple(field.name for field in fields(type(document))) == (
            "schema_version",
            "policy_id",
            "policy_version",
            "retention_categories",
        )
        for forbidden in (
            "authorization",
            "can_share",
            "deny_delete",
            "legal_hold",
            "preservation_permission",
            "tombstone_delay",
        ):
            assert not hasattr(document, forbidden)

        _mutated_policy_error(
            tmp_path,
            "retention-authority-like",
            "retention.yaml",
            b"  - minimal_noncontent_audit\n",
            b"  - legal_hold\n",
            "POLICY_SEMANTICS_INVALID",
            "retention",
        )
        _mutated_policy_error(
            tmp_path,
            "retention-order",
            "retention.yaml",
            b"  - identity_mapping\n  - source_record\n",
            b"  - source_record\n  - identity_mapping\n",
            "POLICY_SEMANTICS_INVALID",
            "retention",
        )

    @pytest.mark.acceptance_id("POLICY-15")
    def test_policy_15_exact_synthetic_risk_rules(self, tmp_path: Path) -> None:
        _repo, config = _policy_config(tmp_path, "risk-canonical")
        rules = PolicyLoader.from_config(config).load_all().risk_rules.document.rules
        observed = tuple(
            (
                rule.rule_id,
                rule.version,
                rule.category,
                rule.level,
                rule.pattern_type,
                rule.pattern,
                rule.negation_window_tokens,
                rule.required_context,
                rule.suggested_questions,
            )
            for rule in rules
        )
        assert observed == _RISK_RULE_VALUES

        mutations = (
            (
                "rule-id",
                b"synthetic_general_observation",
                b"synthetic_general_changed",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "version",
                b"    version: 1\n",
                b"    version: 2\n",
                "POLICY_VERSION_UNSUPPORTED",
            ),
            (
                "category",
                b"    category: synthetic_general_observation\n",
                b"    category: synthetic_changed\n",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "level",
                b"    level: general\n",
                b"    level: medium\n",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "pattern-type",
                b"    pattern_type: literal\n",
                b"    pattern_type: regex\n",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "pattern",
                b"SYNTH-RISK-GENERAL-4C2E",
                b"SYNTH-RISK-GENERAL-CHANGED",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "negation",
                b"    negation_window_tokens: 0\n",
                b"    negation_window_tokens: 1\n",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "context",
                b"      - synthetic_context_present\n",
                b"      - synthetic_context_changed\n",
                "POLICY_SEMANTICS_INVALID",
            ),
            (
                "question",
                b"      - SYNTH-QUESTION-GENERAL-VERIFY\n",
                b"      - SYNTH-QUESTION-GENERAL-CHANGED\n",
                "POLICY_SEMANTICS_INVALID",
            ),
        )
        for label, old, new, code in mutations:
            _mutated_policy_error(
                tmp_path,
                f"risk-{label}",
                "risk-rules.yaml",
                old,
                new,
                code,
                "risk_rules",
            )

        repo, config = _policy_config(tmp_path, "risk-rule-order")
        path = repo / "policies" / "risk-rules.yaml"
        raw = path.read_bytes()
        first = raw.index(b"  - rule_id: synthetic_general_observation")
        second = raw.index(b"  - rule_id: synthetic_high_observation")
        path.write_bytes(raw[:first] + raw[second:] + raw[first:second])
        _expect_policy_error(config, "POLICY_SEMANTICS_INVALID", "risk_rules")

    @pytest.mark.acceptance_id("POLICY-26")
    def test_policy_26_no_future_version_or_migration(self, tmp_path: Path) -> None:
        assert policy_loader_module._POLICY_FILES == (
            ("evidence_levels", "evidence-levels.yaml"),
            ("relation_types", "relation-types.yaml"),
            ("retention", "retention.yaml"),
            ("risk_rules", "risk-rules.yaml"),
        )
        for forbidden in (
            "dispatcher",
            "fallback",
            "latest",
            "load_version",
            "migrate",
            "migration",
        ):
            assert forbidden not in vars(PolicyLoader)

        _mutated_policy_error(
            tmp_path,
            "future-schema",
            "evidence-levels.yaml",
            b'schema_version: "1.0"\n',
            b'schema_version: "9.0"\n',
            "POLICY_VERSION_UNSUPPORTED",
            "evidence_levels",
        )
        _mutated_policy_error(
            tmp_path,
            "future-policy",
            "retention.yaml",
            b"policy_version: 1\n",
            b"policy_version: 9\n",
            "POLICY_VERSION_UNSUPPORTED",
            "retention",
        )

    @pytest.mark.acceptance_id("POLICY-27")
    def test_policy_27_version_bump_discipline(self, tmp_path: Path) -> None:
        _mutated_policy_error(
            tmp_path,
            "v1-value-drift",
            "relation-types.yaml",
            b"  - CITES\n",
            b"  - REFERENCES\n",
            "POLICY_SEMANTICS_INVALID",
            "relation_types",
        )
        _mutated_policy_error(
            tmp_path,
            "v1-order-drift",
            "retention.yaml",
            b"  - identity_mapping\n  - source_record\n",
            b"  - source_record\n  - identity_mapping\n",
            "POLICY_SEMANTICS_INVALID",
            "retention",
        )
        _mutated_policy_error(
            tmp_path,
            "v1-shape-drift",
            "retention.yaml",
            b"retention_categories:\n",
            b"new_shape_field: value\nretention_categories:\n",
            "POLICY_SCHEMA_INVALID",
            "retention",
        )
        repo, config = _policy_config(tmp_path, "unowned-version-bump")
        path = repo / "policies" / "relation-types.yaml"
        _replace_bytes(path, b"policy_version: 1\n", b"policy_version: 2\n")
        _replace_bytes(path, b"  - CITES\n", b"  - REFERENCES\n")
        _expect_policy_error(
            config,
            "POLICY_VERSION_UNSUPPORTED",
            "relation_types",
        )


class TestPolicyArtifactContract:
    @pytest.mark.acceptance_id("POLICY-17")
    def test_policy_17_deep_immutability_and_serialization_ban(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo, config = _policy_config(tmp_path, "artifact-alias")
        parsed_risk = yaml.safe_load(
            (repo / "policies" / "risk-rules.yaml").read_text(encoding="utf-8")
        )
        original_parse = policy_loader_module._parse_yaml

        def aliasing_parse(raw: bytes, policy_id: str) -> object:
            if policy_id == "risk_rules":
                return parsed_risk
            return original_parse(raw, policy_id)

        with monkeypatch.context() as patch:
            patch.setattr(policy_loader_module, "_parse_yaml", aliasing_parse)
            bundle = PolicyLoader.from_config(config).load_all()

        risk_document = bundle.risk_rules.document
        parsed_risk["rules"][0]["pattern"] = "changed-after-load"
        parsed_risk["rules"][0]["required_context"].append("changed_after_load")
        assert risk_document.rules[0].pattern == "SYNTH-RISK-GENERAL-4C2E"
        assert risk_document.rules[0].required_context == (
            "synthetic_context_present",
        )

        with pytest.raises(FrozenInstanceError):
            risk_document.policy_version = 2  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            risk_document.rules[0].pattern = "changed"  # type: ignore[misc]
        with pytest.raises(TypeError):
            risk_document.rules[0].required_context[0] = "changed"  # type: ignore[index]
        with pytest.raises(TypeError):
            bundle.evidence_levels.document.source_grades[0] = "T2"  # type: ignore[index]

        artifacts: tuple[object, ...] = (
            bundle,
            bundle.evidence_levels,
            bundle.relation_types,
            bundle.retention,
            bundle.risk_rules,
            bundle.evidence_levels.document,
            bundle.relation_types.document,
            bundle.retention.document,
            risk_document,
            *risk_document.rules,
            bundle.risk_rules.audit_metadata(),
        )
        for artifact in artifacts:
            assert not hasattr(artifact, "__dict__")
            _assert_serialization_forbidden(artifact)

        assert tuple(field.name for field in fields(EvidenceLevelsPolicy)) == (
            "schema_version",
            "policy_id",
            "policy_version",
            "source_grades",
            "empirical_support",
        )
        assert tuple(field.name for field in fields(RelationTypesPolicy)) == (
            "schema_version",
            "policy_id",
            "policy_version",
            "global_relation_types",
        )
        assert tuple(field.name for field in fields(RetentionPolicy)) == (
            "schema_version",
            "policy_id",
            "policy_version",
            "retention_categories",
        )
        assert tuple(field.name for field in fields(RiskRulePolicy)) == (
            "rule_id",
            "version",
            "category",
            "level",
            "pattern_type",
            "pattern",
            "negation_window_tokens",
            "required_context",
            "suggested_questions",
        )
        assert tuple(field.name for field in fields(RiskRulesPolicy)) == (
            "schema_version",
            "policy_id",
            "policy_version",
            "rules",
        )

    @pytest.mark.acceptance_id("POLICY-18")
    def test_policy_18_canonical_and_raw_hash_vectors(
        self,
        tmp_path: Path,
    ) -> None:
        repo, config = _policy_config(tmp_path, "artifact-hashes")
        bundle = PolicyLoader.from_config(config).load_all()
        artifacts = (
            bundle.evidence_levels,
            bundle.relation_types,
            bundle.retention,
            bundle.risk_rules,
        )
        plain_documents = _expected_plain_documents()
        for artifact in artifacts:
            expected_canonical = json.dumps(
                plain_documents[artifact.policy_id],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            expected_raw_hash = hashlib.sha256(
                (repo / "policies" / artifact.filename).read_bytes()
            ).hexdigest()
            expected_content_hash = hashlib.sha256(expected_canonical).hexdigest()
            assert artifact.canonical_bytes == expected_canonical
            assert artifact.raw_bytes_sha256 == expected_raw_hash
            assert artifact.content_sha256 == expected_content_hash
            assert len(artifact.raw_bytes_sha256) == 64
            assert len(artifact.content_sha256) == 64
            assert artifact.canonical_bytes[-1:] != b"\n"
            metadata = artifact.audit_metadata()
            assert metadata.raw_bytes_sha256 == expected_raw_hash
            assert metadata.content_sha256 == expected_content_hash
            assert not hasattr(metadata, "canonical_bytes")
            assert not hasattr(metadata, "document")

        assert (
            bundle.risk_rules.content_sha256
            == "37c66b3db4f6d204fbf30e52408cbc9ecf2491c0464905aa2d24235b437e2f85"
        )

    @pytest.mark.acceptance_id("POLICY-19")
    def test_policy_19_formatting_only_raw_change(self, tmp_path: Path) -> None:
        _repo, canonical_config = _policy_config(tmp_path, "format-canonical")
        canonical = PolicyLoader.from_config(canonical_config).load_all()

        repo, formatted_config = _policy_config(tmp_path, "format-changed")
        path = repo / "policies" / "evidence-levels.yaml"
        _replace_bytes(
            path,
            b'schema_version: "1.0"\n',
            b'schema_version:  "1.0"   \n',
        )
        formatted = PolicyLoader.from_config(formatted_config).load_all()
        assert (
            formatted.evidence_levels.raw_bytes_sha256
            != canonical.evidence_levels.raw_bytes_sha256
        )
        assert (
            formatted.evidence_levels.canonical_bytes
            == canonical.evidence_levels.canonical_bytes
        )
        assert (
            formatted.evidence_levels.content_sha256
            == canonical.evidence_levels.content_sha256
        )

        repo, invalid_config = _policy_config(tmp_path, "format-invalid-semantic")
        path = repo / "policies" / "relation-types.yaml"
        _replace_bytes(path, b"  - CITES\n", b"  - REFERENCES   \n")
        _expect_policy_error(
            invalid_config,
            "POLICY_SEMANTICS_INVALID",
            "relation_types",
        )

    @pytest.mark.acceptance_id("POLICY-21")
    def test_policy_21_redacted_success_error_and_logs(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        repo, config = _policy_config(tmp_path, "redacted-success")
        caplog.clear()
        bundle = PolicyLoader.from_config(config).load_all()
        assert caplog.records == []
        assert repr(bundle) == "<PolicyBundle redacted>"
        assert repr(bundle.risk_rules) == "<LoadedPolicy redacted>"
        assert repr(bundle.risk_rules.document) == "<RiskRulesPolicy redacted>"
        assert repr(bundle.risk_rules.document.rules[0]) == "<RiskRulePolicy redacted>"
        assert repr(bundle.risk_rules.audit_metadata()) == (
            "<PolicyAuditMetadata redacted>"
        )

        repo, invalid_config = _policy_config(tmp_path, "redacted-error")
        secret_path = repo / "policies" / "evidence-levels.yaml"
        secret_path.write_bytes(b"\xffsecret-policy-scalar\n")
        caplog.clear()
        with pytest.raises(
            PolicyLoadError,
            match=r"^POLICY_ENCODING_INVALID:evidence_levels$",
        ) as caught:
            PolicyLoader.from_config(invalid_config).load_all()
        error = caught.value
        assert error.code == "POLICY_ENCODING_INVALID"
        assert error.policy_id == "evidence_levels"
        assert repr(error) == "<PolicyLoadError redacted>"
        assert error.__cause__ is None
        assert error.__context__ is None
        assert caplog.records == []
        public_text = f"{error!s} {error!r} {error.args!r}"
        for secret in (
            str(repo),
            str(secret_path),
            "evidence-levels.yaml",
            "secret-policy-scalar",
            "ff736563726574",
        ):
            assert secret not in public_text
