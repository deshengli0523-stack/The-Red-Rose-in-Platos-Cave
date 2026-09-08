from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml


_BOOL_TAG = "tag:yaml.org,2002:bool"


class _ActionsLoader(yaml.SafeLoader):
    """Parse GitHub Actions YAML without treating `on` as a boolean."""


_ActionsLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != _BOOL_TAG]
    for first, resolvers in copy.deepcopy(
        yaml.SafeLoader.yaml_implicit_resolvers
    ).items()
}
_ActionsLoader.add_implicit_resolver(
    _BOOL_TAG,
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


EXPECTED_WORKFLOW: dict[str, Any] = yaml.load(
    """
name: CI

on:
  push:
    branches: ["v1", "v2", "v3", "v4", "main"]
  pull_request:
    branches: ["v1", "v2", "v3", "v4", "main"]

jobs:
  upstream:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install -e ".[mcp,pdf,watch]"
          python -m pip install pytest

      - name: Run upstream tests
        run: |
          python -m pytest tests/ -q --tb=short --ignore=tests/consultation_kb

      - name: Verify Python 3.10 consultation boundary
        if: matrix.python-version == '3.10'
        run: |
          python -m compileall -q consultation_kb
          python -m pytest -q tests/consultation_kb/compat/test_py310_entrypoint.py

      - name: Verify install works end-to-end
        run: |
          graphify --help
          graphify install

  consultation:
    runs-on: windows-latest
    env:
      CONSULTATION_LOCK_TARGET: py312-core

    steps:
      - uses: actions/checkout@v4

      - name: Set up ECMA regex runtime
        uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Set up consultation Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          architecture: "x64"

      - name: Install locked consultation environment
        run: |
          python -m pip install --require-hashes -r requirements/consultation-win-py312.lock.txt
          python -m pip install --no-index --no-build-isolation --no-deps .
          python -m pip check

      - name: Verify locked production runtime
        run: |
          python -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_locked_clean_venvs.py

      - name: Run consultation tests
        run: |
          python -m pytest -q -p no:cacheprovider tests/consultation_kb -m "not model and not fault"

      - name: Verify consultation CLI shell and upstream CLI
        run: |
          python -m consultation_kb --help
          python -m consultation_kb doctor --help
          python -c "import consultation_kb; print(consultation_kb.__version__)"
          graphify --help

  consultation-313:
    runs-on: windows-latest
    env:
      CONSULTATION_LOCK_TARGET: py313-core

    steps:
      - uses: actions/checkout@v4

      - name: Set up ECMA regex runtime
        uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Set up compatibility Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          architecture: "x64"

      - name: Install locked compatibility environment
        run: |
          python -m pip install --require-hashes -r requirements/consultation-win-py313.lock.txt
          python -m pip install --no-index --no-build-isolation --no-deps .
          python -m pip check

      - name: Verify Python 3.13 degraded runtime
        run: |
          python -m compileall -q consultation_kb
          python -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_locked_clean_venvs.py
          python -m consultation_kb --help
          graphify --help

  consultation-ml:
    runs-on: windows-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - python-version: "3.12"
            lock: requirements/consultation-ml-win-py312.lock.txt
            target: py312-ml
          - python-version: "3.13"
            lock: requirements/consultation-ml-win-py313.lock.txt
            target: py313-ml
    env:
      CONSULTATION_LOCK_TARGET: ${{ matrix.target }}
      HF_HUB_OFFLINE: "1"
      TRANSFORMERS_OFFLINE: "1"
      HF_DATASETS_OFFLINE: "1"
      TOKENIZERS_PARALLELISM: "false"

    steps:
      - uses: actions/checkout@v4

      - name: Set up ML Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          architecture: "x64"

      - name: Install locked ML environment
        run: |
          python -m pip install --require-hashes -r ${{ matrix.lock }}
          python -m pip install --no-index --no-build-isolation --no-deps .
          python -m pip check

      - name: Verify locked CPU ML runtime
        run: |
          python -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_locked_clean_venvs.py
          python -c "import sentence_transformers, torch; assert not torch.cuda.is_available(); print(sentence_transformers.__version__, torch.__version__)"

      - name: Run offline model contract tests
        run: |
          python -m pytest -q -p no:cacheprovider -m model tests/consultation_kb/model

  consultation-fault:
    runs-on: windows-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up fault-test Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          architecture: "x64"

      - name: Install locked fault-test environment
        run: |
          python -m venv .venv
          ./.venv/Scripts/python.exe -m pip install --require-hashes -r requirements/consultation-win-py312.lock.txt
          ./.venv/Scripts/python.exe -m pip install --no-index --no-build-isolation --no-deps .
          ./.venv/Scripts/python.exe -m pip check

      - name: Run consultation process-fault tests
        run: |
          ./.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider -m fault tests/consultation_kb/fault
""",
    Loader=_ActionsLoader,
)

SKIP_CONDITIONS = [
    pytest.param(False, id="boolean-false"),
    pytest.param("false", id="string-false"),
    pytest.param("${{ false }}", id="expression-false"),
    pytest.param("${{ 1 == 0 }}", id="false-comparison"),
    pytest.param("${{ cancelled() }}", id="cancelled-only"),
]

REQUIRED_CONDITION_TARGETS = [
    pytest.param("upstream", None, id="upstream-job"),
    pytest.param("consultation", None, id="consultation-job"),
    pytest.param("consultation-313", None, id="consultation-313-job"),
    pytest.param("consultation-ml", None, id="consultation-ml-job"),
    pytest.param("consultation-fault", None, id="consultation-fault-job"),
    pytest.param(
        "upstream",
        "Set up Python ${{ matrix.python-version }}",
        id="upstream-setup",
    ),
    pytest.param("upstream", "Install dependencies", id="upstream-install"),
    pytest.param("upstream", "Run upstream tests", id="upstream-tests"),
    pytest.param(
        "upstream",
        "Verify install works end-to-end",
        id="upstream-install-verification",
    ),
    pytest.param(
        "consultation",
        "Set up consultation Python",
        id="consultation-setup",
    ),
    pytest.param(
        "consultation",
        "Install locked consultation environment",
        id="consultation-install",
    ),
    pytest.param(
        "consultation",
        "Verify locked production runtime",
        id="consultation-lock-probe",
    ),
    pytest.param(
        "consultation",
        "Run consultation tests",
        id="consultation-tests",
    ),
    pytest.param(
        "consultation",
        "Verify consultation CLI shell and upstream CLI",
        id="consultation-cli",
    ),
    pytest.param(
        "consultation-313",
        "Set up compatibility Python",
        id="consultation-313-setup",
    ),
    pytest.param(
        "consultation-313",
        "Install locked compatibility environment",
        id="consultation-313-install",
    ),
    pytest.param(
        "consultation-313",
        "Verify Python 3.13 degraded runtime",
        id="consultation-313-tests",
    ),
    pytest.param(
        "consultation-ml",
        "Set up ML Python",
        id="consultation-ml-setup",
    ),
    pytest.param(
        "consultation-ml",
        "Install locked ML environment",
        id="consultation-ml-install",
    ),
    pytest.param(
        "consultation-ml",
        "Verify locked CPU ML runtime",
        id="consultation-ml-tests",
    ),
    pytest.param(
        "consultation-ml",
        "Run offline model contract tests",
        id="consultation-ml-model-tests",
    ),
    pytest.param(
        "consultation-fault",
        "Set up fault-test Python",
        id="consultation-fault-setup",
    ),
    pytest.param(
        "consultation-fault",
        "Install locked fault-test environment",
        id="consultation-fault-install",
    ),
    pytest.param(
        "consultation-fault",
        "Run consultation process-fault tests",
        id="consultation-fault-tests",
    ),
]

EXECUTION_SCOPES = [
    pytest.param("workflow", None, id="workflow"),
    pytest.param("upstream", None, id="upstream-job"),
    pytest.param("consultation", None, id="consultation-job"),
    pytest.param("consultation-313", None, id="consultation-313-job"),
    pytest.param("consultation-ml", None, id="consultation-ml-job"),
    pytest.param("consultation-fault", None, id="consultation-fault-job"),
    pytest.param("upstream", "Run upstream tests", id="upstream-tests"),
    pytest.param(
        "consultation",
        "Install locked consultation environment",
        id="consultation-install",
    ),
    pytest.param(
        "consultation",
        "Run consultation tests",
        id="consultation-tests",
    ),
    pytest.param(
        "consultation",
        "Verify locked production runtime",
        id="consultation-lock-probe",
    ),
    pytest.param(
        "consultation",
        "Verify consultation CLI shell and upstream CLI",
        id="consultation-cli",
    ),
    pytest.param(
        "consultation-313",
        "Install locked compatibility environment",
        id="consultation-313-install",
    ),
    pytest.param(
        "consultation-313",
        "Verify Python 3.13 degraded runtime",
        id="consultation-313-tests",
    ),
    pytest.param(
        "consultation-ml",
        "Install locked ML environment",
        id="consultation-ml-install",
    ),
    pytest.param(
        "consultation-ml",
        "Verify locked CPU ML runtime",
        id="consultation-ml-tests",
    ),
    pytest.param(
        "consultation-ml",
        "Run offline model contract tests",
        id="consultation-ml-model-tests",
    ),
    pytest.param(
        "consultation-fault",
        "Install locked fault-test environment",
        id="consultation-fault-install",
    ),
    pytest.param(
        "consultation-fault",
        "Run consultation process-fault tests",
        id="consultation-fault-tests",
    ),
]


def _workflow(repo_root: Path) -> dict[str, Any]:
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow = yaml.load(
        workflow_path.read_text(encoding="utf-8"),
        Loader=_ActionsLoader,
    )
    assert isinstance(workflow, dict)
    return workflow


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    return next(step for step in job["steps"] if step.get("name") == name)


def _uses_step(job: dict[str, Any], prefix: str) -> dict[str, Any]:
    return next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith(prefix)
    )


def _execution_target(
    workflow: dict[str, Any],
    job_name: str,
    step_name: str | None,
) -> dict[str, Any]:
    job = workflow["jobs"][job_name]
    if step_name is None:
        return job
    return _step(job, step_name)


def _assert_upstream_ci_contract(workflow: dict[str, Any]) -> None:
    assert workflow["jobs"]["upstream"] == EXPECTED_WORKFLOW["jobs"]["upstream"]


def _assert_consultation_ci_contract(workflow: dict[str, Any]) -> None:
    assert workflow["jobs"]["consultation"] == EXPECTED_WORKFLOW["jobs"]["consultation"]


def _assert_workflow_contract(workflow: dict[str, Any]) -> None:
    assert workflow == EXPECTED_WORKFLOW, (
        "CI workflow must match the complete structured execution contract"
    )


def test_actions_loader_uses_github_boolean_semantics() -> None:
    parsed = yaml.load(
        'on: push\nbare: false\nquoted: "false"\n',
        Loader=_ActionsLoader,
    )

    assert parsed == {"on": "push", "bare": False, "quoted": "false"}


def test_upstream_ci_preserves_310_312_matrix_and_ignores_consultation_tests(
    repo_root: Path,
) -> None:
    _assert_upstream_ci_contract(_workflow(repo_root))


def test_python_310_ci_compiles_package_and_runs_only_compat_contract(
    repo_root: Path,
) -> None:
    _assert_upstream_ci_contract(_workflow(repo_root))


def test_upstream_ci_has_no_additional_consultation_pytest_commands(
    repo_root: Path,
) -> None:
    _assert_upstream_ci_contract(_workflow(repo_root))


def test_windows_312_ci_installs_hash_lock_and_excludes_model_and_fault(
    repo_root: Path,
) -> None:
    _assert_consultation_ci_contract(_workflow(repo_root))


def test_windows_313_ci_is_visible_locked_and_explicitly_degraded(
    repo_root: Path,
) -> None:
    job = _workflow(repo_root)["jobs"]["consultation-313"]
    assert "needs" not in job
    assert job["env"] == {"CONSULTATION_LOCK_TARGET": "py313-core"}
    setup = _step(job, "Set up compatibility Python")
    assert setup["with"] == {"python-version": "3.13", "architecture": "x64"}
    install = _step(job, "Install locked compatibility environment")["run"]
    assert "--require-hashes -r requirements/consultation-win-py313.lock.txt" in install
    assert "pip install pip==" not in install
    assert "--no-index --no-build-isolation --no-deps ." in install
    assert "-e ." not in install
    verify = _step(job, "Verify Python 3.13 degraded runtime")["run"]
    assert "test_locked_clean_venvs.py" in verify


def test_windows_ml_ci_covers_both_cpu_hash_locks_without_masking(
    repo_root: Path,
) -> None:
    job = _workflow(repo_root)["jobs"]["consultation-ml"]
    assert "needs" not in job
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {
            "include": [
                {
                    "python-version": "3.12",
                    "lock": "requirements/consultation-ml-win-py312.lock.txt",
                    "target": "py312-ml",
                },
                {
                    "python-version": "3.13",
                    "lock": "requirements/consultation-ml-win-py313.lock.txt",
                    "target": "py313-ml",
                },
            ]
        },
    }
    assert job["env"] == {
        "CONSULTATION_LOCK_TARGET": "${{ matrix.target }}",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "TOKENIZERS_PARALLELISM": "false",
    }
    install = _step(job, "Install locked ML environment")["run"]
    assert "--require-hashes -r ${{ matrix.lock }}" in install
    assert "pip install pip==" not in install
    assert "--no-index --no-build-isolation --no-deps ." in install
    assert "-e ." not in install
    verify = _step(job, "Verify locked CPU ML runtime")["run"]
    assert "test_locked_clean_venvs.py" in verify
    assert "torch.cuda.is_available()" in verify
    model_tests = _step(job, "Run offline model contract tests")["run"].strip()
    assert model_tests == (
        "python -m pytest -q -p no:cacheprovider -m model tests/consultation_kb/model"
    )


def test_windows_ml_ci_collects_real_offline_adapter_smoke(repo_root: Path) -> None:
    source = (
        repo_root
        / "tests"
        / "consultation_kb"
        / "model"
        / "test_real_sentence_transformers_runtime.py"
    ).read_text(encoding="utf-8")

    assert "pytestmark = pytest.mark.model" in source
    assert "SentenceTransformersEmbedder" in source
    assert "SentenceTransformersCrossEncoderReranker" in source
    assert 'pytest.importorskip("sentence_transformers")' in source


def test_windows_fault_ci_is_independent_locked_and_cannot_zero_collect(
    repo_root: Path,
) -> None:
    workflow = _workflow(repo_root)
    job = workflow["jobs"]["consultation-fault"]
    assert "needs" not in job
    install = _step(job, "Install locked fault-test environment")["run"]
    assert install.splitlines() == [
        "python -m venv .venv",
        "./.venv/Scripts/python.exe -m pip install --require-hashes -r "
        "requirements/consultation-win-py312.lock.txt",
        "./.venv/Scripts/python.exe -m pip install --no-index "
        "--no-build-isolation --no-deps .",
        "./.venv/Scripts/python.exe -m pip check",
    ]
    command = _step(job, "Run consultation process-fault tests")["run"].strip()
    assert command == (
        "./.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider -m fault "
        "tests/consultation_kb/fault"
    )
    # Pytest exits 5 when this exact selected path/marker collects no tests;
    # there is no shell masking, ignore flag, or allow-empty wrapper.
    assert "--ignore" not in command
    assert not any(token in command for token in ("||", ";", "continue-on-error"))


@pytest.mark.parametrize(
    ("job_name", "step_name"),
    (
        ("consultation", "Install locked consultation environment"),
        ("consultation-313", "Install locked compatibility environment"),
        ("consultation-ml", "Install locked ML environment"),
        ("consultation-fault", "Install locked fault-test environment"),
    ),
)
def test_locked_ci_builds_the_project_only_from_locked_bootstrap_tools(
    repo_root: Path,
    job_name: str,
    step_name: str,
) -> None:
    install = _step(_workflow(repo_root)["jobs"][job_name], step_name)["run"]

    assert "pip install pip==" not in install
    assert "--require-hashes" in install
    assert "--no-index --no-build-isolation --no-deps ." in install


def test_all_ci_run_commands_are_exact_and_propagate_failures(repo_root: Path) -> None:
    _assert_workflow_contract(_workflow(repo_root))


def test_ci_guard_rejects_alternate_upstream_consultation_pytest_mutation(
    repo_root: Path,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    workflow["jobs"]["upstream"]["steps"].append(
        {
            "name": "Bypass consultation isolation",
            "run": "pytest -q tests/consultation_kb",
        }
    )

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    "scope",
    [
        "job",
        "Install locked consultation environment",
        "Run consultation tests",
        "Verify consultation CLI shell and upstream CLI",
    ],
)
def test_ci_guard_rejects_continue_on_error_mutation(
    repo_root: Path,
    scope: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    consultation = workflow["jobs"]["consultation"]
    if scope == "job":
        consultation["continue-on-error"] = True
    else:
        _step(consultation, scope)["continue-on-error"] = True

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


def test_ci_guard_rejects_floating_install_mutation(repo_root: Path) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    install = _step(
        workflow["jobs"]["consultation"],
        "Install locked consultation environment",
    )
    install["run"] += '\npython -m pip install -e ".[consultation-core]"'

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    "mutation",
    [
        "\nexit 0",
        " || true",
    ],
)
def test_ci_guard_rejects_test_failure_masking_mutation(
    repo_root: Path,
    mutation: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    test_step = _step(workflow["jobs"]["consultation"], "Run consultation tests")
    test_step["run"] += mutation

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


def test_ci_guard_rejects_consultation_step_reordering_mutation(
    repo_root: Path,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    steps = workflow["jobs"]["consultation"]["steps"]
    install_index = steps.index(
        _step(
            workflow["jobs"]["consultation"], "Install locked consultation environment"
        )
    )
    test_index = steps.index(
        _step(workflow["jobs"]["consultation"], "Run consultation tests")
    )
    steps[install_index], steps[test_index] = steps[test_index], steps[install_index]

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("scope", ["workflow", "job", "step"])
def test_ci_guard_rejects_success_masking_shell_override_mutation(
    repo_root: Path,
    scope: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    masking_shell = 'bash -c "{0} || true"'
    if scope == "workflow":
        workflow["defaults"] = {"run": {"shell": masking_shell}}
    elif scope == "job":
        workflow["jobs"]["consultation"]["defaults"] = {"run": {"shell": masking_shell}}
    else:
        _step(workflow["jobs"]["consultation"], "Run consultation tests")["shell"] = (
            masking_shell
        )

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("condition", SKIP_CONDITIONS)
@pytest.mark.parametrize(("job_name", "step_name"), REQUIRED_CONDITION_TARGETS)
def test_structured_ci_guard_rejects_skip_condition_mutation(
    repo_root: Path,
    job_name: str,
    step_name: str | None,
    condition: object,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    _execution_target(workflow, job_name, step_name)["if"] = condition

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("condition", SKIP_CONDITIONS)
@pytest.mark.parametrize("job_name", ["upstream", "consultation"])
def test_structured_ci_guard_rejects_checkout_skip_condition_mutation(
    repo_root: Path,
    job_name: str,
    condition: object,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    workflow["jobs"][job_name]["steps"][0]["if"] = condition

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("PYTEST_ADDOPTS", "--collect-only"),
        ("PIP_CONFIG_FILE", ".ci/pip.conf"),
    ],
)
@pytest.mark.parametrize(("scope_name", "step_name"), EXECUTION_SCOPES)
def test_structured_ci_guard_rejects_execution_env_mutation(
    repo_root: Path,
    scope_name: str,
    step_name: str | None,
    env_name: str,
    env_value: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    target = (
        workflow
        if scope_name == "workflow"
        else _execution_target(workflow, scope_name, step_name)
    )
    target["env"] = {env_name: env_value}

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(("scope_name", "step_name"), EXECUTION_SCOPES)
def test_structured_ci_guard_rejects_working_directory_mutation(
    repo_root: Path,
    scope_name: str,
    step_name: str | None,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    if scope_name == "workflow":
        workflow["defaults"] = {"run": {"working-directory": "elsewhere"}}
    elif step_name is None:
        workflow["jobs"][scope_name]["defaults"] = {
            "run": {"working-directory": "elsewhere"}
        }
    else:
        _step(workflow["jobs"][scope_name], step_name)["working-directory"] = (
            "elsewhere"
        )

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    "mutation",
    ["exclude", "include", "extra-dimension", "consultation-matrix"],
)
def test_structured_ci_guard_rejects_matrix_mutation(
    repo_root: Path,
    mutation: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    upstream_strategy = workflow["jobs"]["upstream"]["strategy"]
    if mutation == "exclude":
        upstream_strategy["matrix"]["exclude"] = [{"python-version": "3.10"}]
    elif mutation == "include":
        upstream_strategy["matrix"]["include"] = [{"python-version": "3.13"}]
    elif mutation == "extra-dimension":
        upstream_strategy["matrix"]["os"] = ["ubuntu-latest"]
    else:
        workflow["jobs"]["consultation"]["strategy"] = {
            "matrix": {"python-version": ["3.12"]}
        }

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


def test_structured_ci_guard_rejects_extra_uses_only_job_mutation(
    repo_root: Path,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    workflow["jobs"]["gate"] = {
        "runs-on": "ubuntu-latest",
        "steps": [{"uses": "actions/checkout@v4"}],
    }

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


def test_structured_ci_guard_rejects_skipped_needs_chain_mutation(
    repo_root: Path,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    workflow["jobs"]["gate"] = {
        "runs-on": "ubuntu-latest",
        "if": False,
        "steps": [{"uses": "actions/checkout@v4"}],
    }
    workflow["jobs"]["consultation"]["needs"] = "gate"

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("job_name", ["upstream", "consultation"])
def test_structured_ci_guard_rejects_required_job_needs_mutation(
    repo_root: Path,
    job_name: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    other_job = "consultation" if job_name == "upstream" else "upstream"
    workflow["jobs"][job_name]["needs"] = other_job

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("job_name", ["upstream", "consultation"])
def test_structured_ci_guard_rejects_extra_uses_only_step_mutation(
    repo_root: Path,
    job_name: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    workflow["jobs"][job_name]["steps"].append(
        {"name": "Unexpected action", "uses": "actions/checkout@v4"}
    )

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    ("job_name", "action_prefix", "replacement"),
    [
        ("upstream", "actions/checkout@", "actions/checkout@untrusted"),
        ("upstream", "actions/setup-python@", "actions/setup-python@untrusted"),
        ("consultation", "actions/checkout@", "actions/checkout@untrusted"),
        (
            "consultation",
            "actions/setup-python@",
            "actions/setup-python@untrusted",
        ),
    ],
)
def test_structured_ci_guard_rejects_action_ref_mutation(
    repo_root: Path,
    job_name: str,
    action_prefix: str,
    replacement: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    _uses_step(workflow["jobs"][job_name], action_prefix)["uses"] = replacement

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize("job_name", ["upstream", "consultation"])
def test_structured_ci_guard_rejects_setup_action_reordering_mutation(
    repo_root: Path,
    job_name: str,
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    steps = workflow["jobs"][job_name]["steps"]
    setup_step = _uses_step(workflow["jobs"][job_name], "actions/setup-python@")
    steps.remove(setup_step)
    steps.append(setup_step)

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)


@pytest.mark.parametrize(
    ("job_name", "action_prefix", "extra_with"),
    [
        ("upstream", "actions/checkout@", {"fetch-depth": 0}),
        ("upstream", "actions/setup-python@", {"cache": "pip"}),
        ("consultation", "actions/checkout@", {"fetch-depth": 0}),
    ],
)
def test_structured_ci_guard_rejects_action_with_mutation(
    repo_root: Path,
    job_name: str,
    action_prefix: str,
    extra_with: dict[str, object],
) -> None:
    workflow = copy.deepcopy(_workflow(repo_root))
    action_step = _uses_step(workflow["jobs"][job_name], action_prefix)
    action_step.setdefault("with", {}).update(extra_with)

    with pytest.raises(AssertionError):
        _assert_workflow_contract(workflow)
