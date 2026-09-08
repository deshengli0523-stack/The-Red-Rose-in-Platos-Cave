# Upstream Graphify test baseline

This file records observed evidence, not a permanent expected test count.

## Snapshot

- Run date: 2026-07-17 (Asia/Shanghai)
- Baseline commit: `2b1bc7e99f2bc0f8d6d9c7bba99c1d676cbaa58c`
- Runtime: CPython 3.12.10, 64-bit, virtual environment enabled
- SQLite: 3.49.1; an in-memory `CREATE VIRTUAL TABLE ... USING fts5` probe passed
- pip: 26.0.1
- Base runtime: independent legacy-launcher/PEP 514 registration; executable SHA-256 `4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a`
- The virtual environment `sys.base_prefix` and `pyvenv.cfg home` are outside the repository and the Codex runtime cache.

No machine-specific executable path is stored in this document.

## Pre-change reconstruction

The Task 1 RED tests were already present as untracked files when the replacement implementer took over. The original upstream-only set was therefore reconstructed by excluding that directory:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests --ignore=tests/consultation_kb
```

With the host-default pytest temporary root and Windows legacy locale, the command exited 1 with `275 passed, 10 failed, 148 errors`. The 148 setup errors were all the same inaccessible pytest temporary-root `WinError 5`; nine failures were locale-dependent default-decoding errors and one was the linked-worktree hidden-directory case. This run is a host-condition diagnostic, not a product regression result.

The comparable baseline used an ignored, writable temporary root and UTF-8 mode:

```powershell
$env:PYTHONUTF8 = '1'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  --basetemp '.venv\pytest-basetemp\task1-prechange' `
  tests --ignore=tests/consultation_kb
```

Observed result: exit 1, `426 passed, 7 failed, 0 skipped`.

The previous implementer handoff reported `427 passed, 6 failed`: five `WinError 1314` symlink-privilege failures and one no-Git assertion caused by a temporary directory inside an outer Git ancestor. The independent run confirmed those six environment/worktree failures and additionally observed `tests/test_extract.py::test_collect_files_from_dir`: the upstream collector rejects every absolute path containing a dot-prefixed component, and this checkout is intentionally under `.worktrees`. Consequently, the current verified baseline is `426/7`, not an all-green result and not the unverified `427/6` handoff count.

The seven current failures are:

- Five symlink creation tests fail with `WinError 1314` because the process lacks symlink privilege.
- `tests/test_extract.py::test_collect_files_from_dir` fails because the linked-worktree absolute path contains `.worktrees`, which the upstream collector treats as hidden.
- `tests/test_hooks.py::test_no_git_repo_raises` resolves the temporary case back to the linked worktree and then treats its `.git` file as a directory.

## Task 1 verification

The exact target command from the task plan was run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  tests/consultation_kb/unit/test_repository_contract.py `
  tests/consultation_kb/unit/test_python_runtime_contract.py
```

On the host-default pytest temporary root it exited 1 with `14 passed, 15 errors`; every error was the same pre-existing temporary-root `WinError 5`. With only the temporary-root control added, the target suite passed:

```powershell
$env:PYTHONUTF8 = '1'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  --basetemp '.venv\pytest-basetemp\task1-fix-target-final' `
  tests/consultation_kb/unit/test_repository_contract.py `
  tests/consultation_kb/unit/test_python_runtime_contract.py
```

Observed result: exit 0, `32 passed, 0 skipped`. The three added passing regressions cover two real-process nonlaunchable-candidate paths and one real pytest collection/marker-selection path.

The upstream-only post-change rerun used the same controlled conditions as the pre-change reconstruction and remained `426 passed, 7 failed, 0 skipped`. The complete post-change suite was:

```powershell
$env:PYTHONUTF8 = '1'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  --basetemp '.venv\pytest-basetemp\task1-fix-full-final' tests
```

Observed result: exit 1, `458 passed, 7 failed, 0 skipped`. The failure set was exactly the seven environment/worktree failures listed above; no consultation knowledge-base test failed.

## P0 Tasks 5-6 verification

- Run date: 2026-07-18 (Asia/Shanghai)
- Working-tree base: `1d0b953f3b66e0f332510e03bb6cff472b386c63`
- Runtime: CPython 3.12.10, 64-bit
- SQLite: 3.49.1; a real in-memory FTS5 create/insert/query returned one row
- Dependency state: the checked-in hash lock installed successfully, the project was installed editable with `--no-deps`, and `pip check` reported no broken requirements

The final P0 selection was run with a controlled writable pytest base:

```powershell
$env:PYTHONUTF8 = '1'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  --basetemp '.venv\pytest-basetemp\p0-gate-final' `
  tests/consultation_kb/unit `
  tests/consultation_kb/integration/test_doctor.py `
  tests/consultation_kb/integration/test_doctor_cli.py `
  tests/consultation_kb/integration/test_p0_vertical_slice.py
```

Observed result: exit 0, `552 passed`. This includes the real FTS5 and Git-tracked privacy probes, CLI single-JSON/fail-closed behavior, acceptance registry/collection contracts, cross-thread and cross-process append serialization, and the P0 vertical slice.

The raw full-suite run exposed only six known host-condition failures: five Windows `WinError 1314` symlink-privilege cases and the upstream no-Git test whose controlled temporary directory is intentionally inside the checkout. No consultation test failed. A final current-tree run deselecting exactly those six host-condition cases produced:

```powershell
$env:PYTHONUTF8 = '1'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider `
  --basetemp '.venv\pytest-basetemp\full-p0-final' tests `
  --deselect tests/test_detect.py::test_detect_follows_symlinked_directory `
  --deselect tests/test_detect.py::test_detect_follows_symlinked_file `
  --deselect tests/test_detect.py::test_detect_handles_circular_symlinks `
  --deselect tests/test_extract.py::test_collect_files_follows_symlinked_directory `
  --deselect tests/test_extract.py::test_collect_files_handles_circular_symlinks `
  --deselect tests/test_hooks.py::test_no_git_repo_raises
```

Observed result: exit 0, `982 passed, 6 deselected, 2 upstream dependency warnings`.

Static and operational gates:

```powershell
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb scripts
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor `
  --repo-root . --vault-root '..\.consultation-doctor-vault' --json
```

Observed results: Ruff passed; Mypy reported no issues in 28 source files; Doctor wrote one JSON object with `ok=true`, 21 matching Schemas, four loaded policy files, zero Git-tracked privacy hits, and a successful FTS5 roundtrip. Repeating Doctor with a repository-internal vault returned exit 2 and a path-free `CONFIG_ROOTS_OVERLAP` failure object.
