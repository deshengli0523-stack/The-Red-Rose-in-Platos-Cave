# P0：契约与测试地基实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 建立不改变 Graphify 行为的 `consultation_kb` 包、依赖/Schema 真相源、确定性测试夹具、无正文审计、隐私扫描和可执行 `doctor`，为后续安全与知识功能提供冻结合同。

**Architecture:** Pydantic 模型定义跨阶段 Schema，stdlib 配置和固定时钟保证测试可复现，CLI 仅负责本地运维入口。上游发行元数据继续允许 Python 3.10+，轻量 entrypoint 在导入咨询依赖前拒绝低于 3.12 的运行时；P0 不实现正式客户写入，只验证运行时、vault 边界、测试数据和日志合同，并保存上游回归基线。

**Tech Stack:** 咨询运行时 Python 3.12、Python 3.10 解析/拒绝冒烟、Pydantic v2、stdlib argparse/sqlite3/tomllib/hashlib、pytest/Hypothesis、ruff/mypy、PowerShell。

## Global Constraints

- 先阅读[实施总计划](2026-07-16-consultation-knowledge-base-implementation-program.md)和设计规格第 1–7、19、20、22–26 节。
- 本阶段不创建真实客户，不写 `knowledge-vault` 正文，不下载模型，不修改 `graphify/`。
- 所有 fixture 都是明显合成内容；真实姓名、手机号、身份证、稳定客户标识或会谈正文模式触发测试失败。
- `doctor` 遇到 vault 位于 Git 仓库内部、FTS5 缺失、Schema 漂移或审计正文风险时返回非零，不给“可继续”的假成功。

---

## Task 1：冻结上游基线与测试目录合同

**Files:**

- Create: `tests/consultation_kb/unit/test_repository_contract.py`
- Create: `tests/consultation_kb/unit/test_python_runtime_contract.py`
- Create: `tests/consultation_kb/conftest.py`
- Create: `tests/fixtures/consultation_kb/canaries.json`
- Create: `requirements/consultation-python.toml`
- Create: `scripts/resolve_consultation_python.ps1`
- Create: `docs/consultation-kb/upstream-baseline.md`

**Interfaces produced:** 合成 repo/vault fixture、固定 UTC 时钟 fixture、上游测试基线记录。

- [ ] 先冻结环境规格：`consultation-python.toml` 要求 `implementation=CPython`、`series=3.12`、`min_patch=10`、`bits=64`、`venv=true`，并拒绝 base executable 位于 `.cache/codex-runtimes`、仓库、vault 或临时目录。resolver 依次检查显式 `CONSULTATION_PYTHON`、`pymanager` 管理的 3.12、legacy launcher/PEP 514 已登记的 3.12；候选必须真实运行版本/位数/`venv`/SSL/SQLite FTS5 probe。stdout 只输出最终绝对路径，诊断走 stderr；不存在返回专用退出码，不能返回 bootstrap 路径。
- [ ] 本机若没有合格 3.12，停止本任务并请求安装授权。批准后若 `pymanager` 缺失，执行 Python 官方命令 `winget install 9NQ7512CXL7T -e --accept-package-agreements --disable-interactivity` 安装 Python install manager；随后明确执行 `pymanager install 3.12` 并重跑 resolver。禁止调用 `py install`：legacy Python Launcher 可能优先占用 `py.exe` 并明确不提供 install 子命令；也禁止为解决冲突而卸载 legacy launcher。安装动作和联网不是 doctor/普通启动的隐式副作用。当前官方 3.12 安全发布已不再提供传统 Windows installer，因此不硬编码过时安装器 URL，由 manager 选择其受支持的 3.12 Windows runtime，并把实际 patch/tag/hash写入本机诊断。
- [ ] `test_python_runtime_contract.py` 对 fake candidate runner 覆盖正确 3.12 x64、Codex cache、3.13、32 位、缺 FTS5、多个候选排序，以及“legacy `py` 存在但 `pymanager` 可用/不可用”两种主机；断言 resolver 从不尝试 `py install`、不卸载 launcher。并对真实 `.venv` 断言 `sys.base_prefix` 和 `pyvenv.cfg home` 不在 Codex cache。先由独立解释器创建 `.venv`，再运行完整上游测试：

```powershell
$BootstrapPy = '<CODEX_RUNTIME>\dependencies\python\python.exe'
& $BootstrapPy -c "import sys; print('bootstrap-only', sys.version)"
$ProdPy = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\resolve_consultation_python.ps1 -SpecPath .\requirements\consultation-python.toml).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Install/authorize independent CPython 3.12 x64, then retry' }
& $ProdPy -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install 'pip==26.0.1'
& '.\.venv\Scripts\python.exe' -m pip install -e '.[pdf,office,watch]'
& '.\.venv\Scripts\python.exe' -m pip install 'mcp>=1.28.1,<2' 'pytest>=8.3,<10' 'pytest-cov>=6,<8'
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
```

Expected: 现有测试全部通过；若失败，记录精确失败并先判断是否为当前环境/上游基线问题，不能把失败归入新系统。

- [ ] 写入第一个失败测试，锁定仓库不得已有咨询运行时目录：

```python
from pathlib import Path


def test_repository_has_no_runtime_vault(repo_root: Path) -> None:
    forbidden = [repo_root / "knowledge-vault", repo_root / "clients"]
    assert not [path for path in forbidden if path.exists()]
```

- [ ] 在 `conftest.py` 提供真实实现可消费的 fixture：

```python
from datetime import datetime, timezone
from pathlib import Path

import pytest


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def synthetic_workspace(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    vault = tmp_path / "knowledge-vault"
    (repo / ".git").mkdir(parents=True)
    vault.mkdir()
    return repo, vault
```

- [ ] 在同一 `conftest.py` 用 `pytest_collection_modifyitems` 按相对目录为 `integration/`、`fault/`、`golden/`、`model/` 自动加同名 marker；单元测试验证各目录 sample item 获得正确 marker，使最终 `-m fault/golden/model` 命令不会静默 deselect 全部测试。

- [ ] `canaries.json` 只保存明确合成标记及扫描规则名，例如 `SYNTH-CANARY-` + `ALPHA-` + `9F3A`、`SYNTH-CANARY-` + `BETA-` + `71D2`，不保存任何真实客户数据。
- [ ] 在 `upstream-baseline.md` 记录 HEAD、Python/SQLite 版本、完整命令、通过/跳过数量和运行日期；记录是基线证据，不硬编码“永远相同”的测试数。
- [ ] 运行：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_repository_contract.py tests/consultation_kb/unit/test_python_runtime_contract.py
git diff --check
```

Expected: 新测试通过，完整上游测试结果与改造前一致。

---

## Task 2：扩展包发现、依赖组与 CLI 壳

**Files:**

- Modify: `pyproject.toml`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`
- Create: `consultation_kb/__init__.py`
- Create: `consultation_kb/__main__.py`
- Create: `consultation_kb/entrypoint.py`
- Create: `consultation_kb/cli.py`
- Create: `scripts/export_consultation_requirements.py`
- Create: `requirements/consultation-win-py312.in`
- Create: `requirements/consultation-win-py312.lock.txt`
- Create: `tests/consultation_kb/unit/test_packaging.py`
- Create: `tests/consultation_kb/unit/test_dependency_lock.py`
- Create: `tests/consultation_kb/unit/test_ci_contract.py`
- Create: `tests/consultation_kb/compat/test_py310_entrypoint.py`

**Interfaces produced:** `consultation-kb` console script；`python -m consultation_kb`；四组可选依赖和 pytest marker；首个 Windows CPython 3.12 third-party hash lock；上游/咨询 CI 分轨。

- [ ] 定义包装契约测试，使用 `tomllib` 精确验证包/脚本/extra；按 C 级机械变更集中运行，不要求单独展示 RED：

```python
import tomllib
from pathlib import Path


def test_pyproject_packages_consultation_kb(repo_root: Path) -> None:
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["consultation-kb"] == "consultation_kb.entrypoint:main"
    assert data["tool"]["setuptools"]["packages"]["find"]["include"] == [
        "graphify*",
        "consultation_kb*",
    ]
    extras = data["project"]["optional-dependencies"]
    assert {"consultation-core", "consultation-ml", "consultation-test"} <= extras.keys()
```

- [ ] 修改 `pyproject.toml`：保留所有现有依赖和 `graphify` 脚本；把现有 `mcp` extra 固定为 `mcp>=1.28.1,<2`，加入总计划第 5 节的精确依赖范围和 `[tool.mypy]` strict 配置；包发现为 `graphify*` 与 `consultation_kb*`；Python 迁移作为普通包模块随包发现收录；pytest markers 为 `integration`、`fault`、`golden`、`model`、`slow`、`acceptance_id`。
- [ ] 增加：

```toml
[project.scripts]
graphify = "graphify.__main__:main"
consultation-kb = "consultation_kb.entrypoint:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["graphify*", "consultation_kb*"]
```

- [ ] `.gitignore` 仅增加精确运行时规则：

```gitignore
knowledge-vault/
*.sqlite3-wal
*.sqlite3-shm
.consultation-staging/
.consultation-models/
consultation-leak-report.json
.codex/config.toml
!.agents/
!.agents/skills/
!.agents/skills/**
```

- [ ] 保留上游 `project.requires-python = ">=3.10"`，禁止为了咨询子系统整体提高发行包门槛。`entrypoint.py` 与 `__main__.py` 只用 Python 3.10 stdlib/语法；在任何 Pydantic、MCP、SQLite 或业务模块导入前检查 `sys.version_info >= (3, 12)`，低版本向 stderr 输出固定支持边界并返回退出码 2。全部 `consultation_kb/**/*.py` 必须通过 Python 3.10 `compileall`，3.10 compat test 只导入 entrypoint 并验证拒绝行为，不加载业务模块。
- [ ] `.gitignore` 中已有的通用 `skills/` 规则不得吞掉 Codex repo Skills；末尾精确 unignore `.agents/skills/**`。`test_packaging.py` 用 `git check-ignore --no-index` 断言三个预定 Skill 路径不被忽略，同时 `.codex/config.toml` 和 vault 仍被忽略。
- [ ] `cli.py` 实现 `argparse` 子命令注册和明确的未实现退出；P0 只激活 `doctor`，其余 `init-vault/migrate/serve/recover/rebuild/delete` 暂不注册，避免暴露假能力。`main(argv: Sequence[str] | None = None) -> int` 必须可直接测试。
- [ ] `consultation_kb.__version__` 与 Graphify adapter 都调用 `core.version.distribution_version()`，唯一发行名固定为 `importlib.metadata.version("graphifyy")`；仅在 source tree 尚未安装时返回带显式 `+uninstalled` 的 fallback，禁止尝试不存在的 `consultation-kb` distribution。
- [ ] `export_consultation_requirements.py` 从 `pyproject.toml` 选定 `mcp/pdf/office/watch/leiden/consultation-core/consultation-test` 的第三方 requirements，确定性写 `.in`；禁止 `-e .`、本项目 distribution 和未固定 index。先在 bootstrap venv 显式安装官方 `pip-tools==7.5.3`，再生成 `--generate-hashes` lock；编译器版本及生成命令写入 lock header，重复生成必须无 diff。P1–P8 安装顺序固定为 lock → `pip install --no-deps -e .`，不能继续用浮动 extras。
- [ ] 写真实 clean-venv 验证：从 lock 安装第三方、`--no-deps` 安装项目、运行 `pip check`、imports、doctor 和 P0 tests；不能用 `pip install --dry-run` 代替。生产 3.12 lock 包含 `leiden` extra，缺失时 lock 测试失败。
- [ ] 修改现有 CI：保留 Ubuntu Python 3.10/3.12 上游 job，其完整 pytest 命令显式 `--ignore=tests/consultation_kb`；但 3.10 job 随后必须运行 `python -m compileall -q consultation_kb` 和 `pytest -q tests/consultation_kb/compat/test_py310_entrypoint.py`，证明安装仍可解析且入口明确拒绝，而不是暴露半可用包。新增 `windows-latest`/Python 3.12 consultation job，从 hash lock 安装后运行 `tests/consultation_kb` 的非 model/non-fault 测试。`test_ci_contract.py` 解析 workflow 并锁定三条约束，禁止上游 job误收其余咨询测试。
- [ ] 重新安装并验证：

```powershell
& '.\.venv\Scripts\python.exe' -m pip install 'pip-tools==7.5.3'
& '.\.venv\Scripts\python.exe' scripts/export_consultation_requirements.py --python 3.12
& '.\.venv\Scripts\python.exe' -m piptools compile --generate-hashes --output-file requirements/consultation-win-py312.lock.txt requirements/consultation-win-py312.in
& '.\.venv\Scripts\python.exe' -m pip install --require-hashes -r requirements/consultation-win-py312.lock.txt
& '.\.venv\Scripts\python.exe' -m pip install --no-deps -e .
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_packaging.py tests/consultation_kb/unit/test_dependency_lock.py tests/consultation_kb/unit/test_ci_contract.py tests/consultation_kb/compat/test_py310_entrypoint.py
& '.\.venv\Scripts\python.exe' -c "import consultation_kb; print(consultation_kb.__version__)"
```

Expected: PASS；输出与项目版本一致；原 `graphify --help` 仍成功。

---

## Task 3：建立严格核心模型与可重复 Schema 导出

**Files:**

- Modify: `consultation_kb/core/__init__.py`
- Create: `consultation_kb/core/clock.py`
- Modify: `consultation_kb/core/version.py`
- Create: `consultation_kb/core/ids.py`
- Create: `consultation_kb/core/errors.py`
- Create: `consultation_kb/core/result.py`
- Create: `consultation_kb/models/__init__.py`
- Create: `consultation_kb/models/common.py`
- Create: `consultation_kb/models/client.py`
- Create: `consultation_kb/models/evidence.py`
- Create: `consultation_kb/models/manifests.py`
- Create: `consultation_kb/models/generation.py`
- Create: `consultation_kb/models/risk.py`
- Create: `scripts/export_consultation_schemas.py`
- Create: `schemas/*.schema.json`
- Create: `tests/consultation_kb/unit/test_core_contracts.py`
- Create: `tests/consultation_kb/unit/test_schema_exports.py`

**Interfaces produced:** 总计划第 3 节全部跨阶段模型；`Clock`/`FixedClock`；UUIDv7 ID；机器可读错误；确定性 JSON Schema。

**首个 Schema 前合同裁决（2026-07-17）：**

- Task 2 已创建 `core/__init__.py` 与 `core/version.py`；本任务只增量修改。`core/__init__.py` 在Task 3继续**只导出version helper**，不得重导出clock/ids，更不得急切导入Pydantic/MCP/SQLite/业务模块，否则会在3.12入口门之前破坏Python 3.10拒绝合同。消费者显式导入 `consultation_kb.core.clock`/`.ids`。
- UUIDv7以 [RFC 9562 §5.7](https://www.rfc-editor.org/rfc/rfc9562.html#section-5.7) 与 Appendix A.6 为规范源：48-bit Unix毫秒、version 7、12-bit `rand_a`、variant `10`、62-bit `rand_b`，并用官方 `017f22e2-79b0-7cc3-98c4-dc0c0c07398f` 向量测试。
- 完整 `AuthoritativeFilterSnapshot.allowed_ref_ids` 与完整 `Provenance` 只留服务端；新增不含allowed set的 `AuthoritySnapshotBinding` 与不含任何客户ID字段的 `EvidenceProvenanceView`。`EvidenceCandidate` 使用安全view，并新增必填 `EvidenceLocator` 与 `EvidenceFreshnessSnapshot`。
- `EvidencePack` 首版直接采用总计划第3.5节修订后的内容寻址闭包：`authority`、`client_snapshot_ref`、`temporary_fact_refs`、`unresolved_conflict_refs`、`exclusion_proof_ref`、四个 `*_manifest_ref` 与 `reranker_descriptor_ref`。不得双写旧裸ID字段，不得按ID查询latest。
- scope/policy/derivation/locator/freshness等包外规则均以 `VersionRef` 绑定；包Schema的类型图、`$defs`、默认dump和JSON不得出现 `client_id/client_ids/private_owner_client_id/case_contributor_client_ids`。
- `SourceGrade` 首版枚举固定18值 `T1..T4/C1..C6/K1..K4/L1..L4`；`EmpiricalSupport` 固定 `unassessed/case_supported/observation_supported/empirically_supported/guideline_consistent/conflicting`。Task 4 YAML只能与这些类型对齐，不得另造字符串。
- `client_id`持久化格式固定为 `client_[a-z0-9]{12}`；设计文档中的 `client_0042` 仅是人类示例别名。公共approval state使用总计划冻结的小写枚举；P4实现统一使用 `allowed_ref_ids`，不用文案中的 `allowed_ids`。
- `core/result.py` 只提供内部泛型exactly-one-of result；P5 concrete MCP envelope、P1 `PublicationOperation`、P6七类stage body与risk lifecycle均延后到各自阶段，Task 3不得猜测冻结。

**模块归属与单向import DAG：**

| 模块 | 本任务拥有 | 允许的内部依赖 |
|---|---|---|
| `core/version.py` | 唯一distribution version helper | stdlib only |
| `core/clock.py`、`core/ids.py` | Clock/FixedClock、UUIDv7/ID factory | stdlib；ids可依赖clock |
| `models/common.py` | scalar aliases、`StrictModel`、`FrozenSafeDetails`、`VersionRef`、`SessionScope` | stdlib + Pydantic only |
| `core/errors.py` | `ToolError`与受控exception映射 | `models.common`；不被models反向导入 |
| `core/result.py` | internal generic result | `core.errors`；不从`core/__init__`导出 |
| `models/client.py` | `FactState`、`BitemporalWindow` | `models.common` |
| `models/manifests.py` | draft/approval models | `models.common` |
| `models/evidence.py` | full/safe provenance、scope/snapshot、candidate、C1、pack | `models.common` |
| `models/generation.py`、`models/risk.py` | 最小generation/client-output/risk roots | `models.common` |
| `models/__init__.py` | package marker，禁止eager all-model import | none |

任何models模块不得导入 `core.errors/result`，Schema exporter从具体模块显式导入，避免循环和pre-gate副作用。

**首发 generation/risk roots（字段名与类型不得猜测）：**

```python
GenerationStageName = Literal[
    "query_plan", "conceptualization", "theory_comparison",
    "reply_drafts", "evidence_audit", "consistency_risk_review",
    "final_bundle",
]

class GenerationStageEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: GenerationStageName
    turn_id: Uuid7String
    run_id: Uuid7String
    parent_sha256s: tuple[Sha256Hex, ...]
    created_at: UtcDateTime

class ClientReplyOutput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    text: NonEmptyStr

class InternalRiskObservation(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    observation_id: ObjectId
    category: SafePolicyKey
    level: Literal["general", "high"]
    trigger_turn_ids: tuple[Uuid7String, ...]
    rule_ref: VersionRef
    detected_at: UtcDateTime
    suggested_questions: tuple[NonEmptyStr, ...]
    client_facing_visibility: Literal["never"] = "never"
```

`parent_sha256s` 必须显式、unique并按hash排序，可为空；`trigger_turn_ids` 必须显式、非空、unique并按UUID排序；`suggested_questions` 非空、拒绝blank/duplicate并保留作者顺序。P6只能用组合增加stage body/risk lifecycle，不能改这三个v1 root。

- [ ] 先写失败测试，证明四状态轴、双时间轴和风险可见性不可被简化：

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.models.client import BitemporalWindow, FactState
from consultation_kb.models.risk import InternalRiskObservation


NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)


def test_fact_state_rejects_collapsed_status() -> None:
    with pytest.raises(ValidationError):
        FactState.model_validate({"status": "active"})


def test_bitemporal_window_rejects_naive_time() -> None:
    with pytest.raises(ValidationError):
        BitemporalWindow(
            effective_from=datetime(2026, 7, 1),
            effective_to=None,
            recorded_at=NOW,
            superseded_at=None,
        )


def test_internal_risk_visibility_is_constant(fixed_id_factory, fixed_version_ref) -> None:
    item = InternalRiskObservation(
        observation_id=fixed_id_factory.object_id("risk"),
        category="urgent_safety",
        level="high",
        trigger_turn_ids=(fixed_id_factory.uuid7(),),
        rule_ref=fixed_version_ref("risk_policy"),
        detected_at=NOW,
        suggested_questions=("你现在是否处在安全的地方？",),
    )
    assert item.client_facing_visibility == "never"


def test_non_utc_offset_is_rejected() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        BitemporalWindow(
            effective_from=datetime.fromisoformat("2026-07-01T08:00:00+08:00"),
            effective_to=None,
            recorded_at=NOW,
            superseded_at=None,
        )
```

- [ ] 在 `models/common.py` 建立单一严格基类：

```python
from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC offset +00:00")
    return value.astimezone(timezone.utc)


UtcDateTime = Annotated[datetime, AfterValidator(require_utc)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
```

- [ ] 所有时间字段显式使用 `UtcDateTime`，不靠一个未绑定 helper；反射式覆盖每个顶层/嵌套时间字段，测试 naive、`+08:00`/DST offset、UTC JSON round-trip。实现总计划冻结及本任务裁决后的 `VersionRef`、`ToolError`、`SessionScope`、`FactState`、`BitemporalWindow`、完整 `Provenance`（含 private owner/case contributors）、`RetrievalScope`、`AuthoritativeFilterSnapshot`、`AuthoritySnapshotBinding`、`EvidenceProvenanceView`、`EvidenceLocator`、`EvidenceFreshnessSnapshot`、安全 `EvidenceCandidate`、`C1ApplicabilityDecision`、`EvidencePack`、`DraftDescriptor`、`ApprovalReceipt`、`ApprovalExecution` 和最小生成/风险外壳。`InternalRiskObservation.client_facing_visibility` 使用 `Literal["never"] = "never"`；来访者输出模型中不定义该字段。`ApprovalReceipt.expires_at > approved_at`，execution的issued/claimed无commit而applied/acknowledged有正commit。
- [ ] `SystemClock.now()`返回aware UTC；`FixedClock`构造时即拒绝naive和任意非零offset，不静默normalize。`ids.py` 实现 RFC 9562 UUIDv7 位布局，允许注入 `Clock` 与完整74位随机源；随机结果必须是exact int，显式拒绝bool/float/string/coercion，接受 `0` 与 `2**74-1`，拒绝负数与 `>=2**74`；时间越48位拒绝而非截断。测试Appendix A.6官方向量、同一固定时间下版本位7/variant `10`、不同ID唯一、跨毫秒排序。随机模式不虚假承诺同毫秒单调。
- [ ] 为hash、client/object/UUIDv7 ID、正/非负版本、finite score、四状态轴、双时态端点、批准状态与空白字符串写负例。Object kind长度1..64且以full-match匹配 `[a-z][a-z0-9]*(?:_[a-z0-9]+)*`，并拒绝任意client-ID子串；长度与full-match分别验证，不能依赖Pydantic/Rust regex不支持的look-around。`FrozenSafeDetails`只接受 `str|int|bool` 标量，拒绝嵌套容器，复制+canonical排序输入、默认序列化为JSON object，并测试字段重绑定、item mutation和原始input alias mutation均不能改变已构造错误。
- [ ] 冻结并参数化完整C1矩阵：`applicable`/`not_applicable` 要求revision+`active`+空missing+非空matched/exclusion rule；`insufficient_context` 要求revision+`active`+非空missing；`unavailable`+`none` 要求无revision、空matched/missing和`unassessed`；`unavailable`+`expired|superseded|revoked` 要求revision+空missing；`unavailable`+`active` 非法。matched/missing使用1..64的lower-snake `SafePolicyKey`，拒绝client/path/control/free-text canary，各tuple去重、canonical排序；P3/P4验证rule/context key属于 `scope_policy_ref` manifest对应成员词表。
- [ ] 冻结pack-local交叉引用：字段名为 `supports_evidence_ids`/`contradicts_evidence_ids` 且必须显式提供，与C1 conflict IDs都只能命中supporting/contradicting candidate并集，禁止self/dangling/tuple内重复，同一candidate的support/contradict target集合不相交；两个顶层序列各自ID唯一并按evidence ID排序，candidate内部support/contradict和C1 conflict tuples按ObjectId排序，temporary facts/unresolved conflicts/anchors按完整VersionRef排序，输入置换不得改变pack canonical hash。允许同一candidate同时处于两组但对象必须完全相同且融合只计一次。测试 `authority.run_id == pack.run_id`。完整Provenance矩阵：global要求source非空且case/client/contributor/owner空；private要求owner、`client_ids={owner}`且source/case/contributor空，可含本客户private Passage；case要求case/contributor非空、`client_ids=contributors`且source/owner空，可含approved case-turn Passage；mixed要求source/case/contributor非空、`client_ids=contributors`且owner空，owner不得自动成为contributor。safe view使用 `not_applicable/current_subject_private/no_subject_contribution/leave_one_subject_out_applied`，按scope/channel闭合并验证对应source/case/contributor/independent count的零/非零关系与 `independent_source_count <= source_count`；private/case的passage_count可非零但必须由P4 scope/closure验证。
- [ ] `EvidenceLocator.anchor_refs` 必须非空、canonical排序且在同一closure。`locator_kind` 精确十值：`source_page_span/source_paragraph_span/source_line_span/source_table_span/source_sheet_range/client_fact/session_turn/wiki_section/case_turn/graph_path`。五类source grammar覆盖全部首阶段格式：PDF `pages:<p1>:<b1>-<p2>:<b2>`（支持同页/跨页），DOCX `paragraphs:<a>-<b>` 或 table span，TXT/MD `lines:<a>-<b>`，CSV `table:<n>;rows:<a>-<b>;columns:<c>-<d>`，XLSX `sheet:<n>;range:<A1>-<B2>`；另有fact ObjectId、turn UUIDv7、section slug、case turn和graph hash。数字为无前导零正整数、page/block pair与range有序、cell为uppercase canonical；拒绝kind/grammar错配、控制字符、client-ID、路径、traversal和自由正文。缺坐标不得伪造页码或产出approved Passage。freshness测试 `source_observed_at/last_reviewed_at <= evaluated_at`（两者互不排序）以及 `stale/current` review-due矩阵；P4只能通过受控renderer构造locator。
- [ ] EvidencePack Schema（含 `$defs`）、默认dump和JSON以generic `client_[a-z0-9]{12}` regex及多个合成ClientId canary扫描，必须零命中；pack-visible field/enum/string常量自身也不能制造合法canary假阳性，不能用serializer `exclude`假装安全。`InternalRiskObservation` 使用必填 `rule_ref: VersionRef` 而非可变rule label；client reply Schema不得含任何risk字段。
- [ ] Schema 导出脚本使用显式root registry，固定导出 `version_ref/tool_error/session_scope/draft_descriptor/approval_receipt/approval_execution/fact_state/bitemporal_window/provenance/retrieval_scope/authoritative_filter_snapshot/authority_snapshot_binding/evidence_provenance_view/evidence_locator/evidence_freshness_snapshot/evidence_candidate/c1_applicability_decision/evidence_pack/internal_risk_observation/generation_stage_envelope/client_reply_output` 这21个 `.schema.json` 文件。UTF-8无BOM、`ensure_ascii=False`、`sort_keys=True`、两空格缩进且仅一个末尾换行；UTC definitions带稳定 `x-utc-only` 标记。所有StrictModel object root/`$defs`要求 `additionalProperties:false`；`FrozenSafeDetails` mapping是唯一明确例外，其 `additionalProperties` 只能是 `str|int|bool` scalar union且嵌套object/array非法。`test_schema_exports.py` 在临时目录重新导出，比较精确文件集合与逐字节内容，防止Pydantic模型与Schema漂移或遗留旧文件。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' scripts/export_consultation_schemas.py
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_core_contracts.py tests/consultation_kb/unit/test_schema_exports.py
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb/core consultation_kb/models
```

Expected: PASS；第二次导出 `git diff` 为空。

---

## Task 4：配置、vault 边界和合成数据扫描

**Files:**

- Create: `consultation_kb/core/config.py`
- Create: `consultation_kb/vault/__init__.py`
- Create: `consultation_kb/vault/layout.py`
- Create: `consultation_kb/evaluation/__init__.py`
- Create: `consultation_kb/evaluation/privacy_scan.py`
- Create: `policies/evidence-levels.yaml`
- Create: `policies/relation-types.yaml`
- Create: `policies/retention.yaml`
- Create: `policies/risk-rules.yaml`
- Create: `tests/consultation_kb/unit/test_config.py`
- Create: `tests/consultation_kb/unit/test_privacy_scan.py`

**Interfaces produced:** `AppConfig.load()`；`VaultLayout`；`PrivacyScanner.scan_paths()`；版本化策略文件。

- [ ] 写失败测试：vault 必须在 repo 外、必须是绝对路径、未知环境变量不得被忽略：

```python
from pathlib import Path

import pytest

from consultation_kb.core.config import AppConfig, ConfigurationError


def test_vault_inside_repo_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "graphify"
    repo.mkdir()
    with pytest.raises(ConfigurationError, match="outside the Git repository"):
        AppConfig.from_values(repo_root=repo, vault_root=repo / "knowledge-vault")
```

- [ ] 写范围锁定测试：第一阶段只允许 `interaction_mode="codex_text"`、`single_counselor=true`、`runtime_network_ingest=false`、`automatic_formal_writeback=false`；web/API/voice/multi-user/自动诊断/自动联网入库/未审核写回配置均拒绝，而不是处于“看似可启用”的半实现状态。

- [ ] 写失败测试：扫描器必须发现临时共享工件中的合成 canary，同时允许 canary 定义文件本身：

```python
def test_scanner_finds_canary_outside_definition(tmp_path: Path) -> None:
    leaked = tmp_path / "shared-index.txt"
    leaked.write_text("SYNTH-CANARY-" + "ALPHA-" + "9F3A", encoding="utf-8")
    report = PrivacyScanner.default().scan_paths([leaked])
    assert report.hit_count == 1
    assert report.hits[0].rule_id == "known_canary"
```

- [ ] `VaultLayout` 只负责固定目录，不接收任意运行时相对路径。它暴露 `identity_map`、`sources`、`wiki_draft/approved/history`、`global_db`、`global_graph`、`lexical_indexes`、`vector_indexes`、`cases_draft/approved/quarantine`、`clients_root`、`global_objects_root`、`global_staging_root`、`review_queue`、`audit_root`、`quarantine`；客户 `objects/.staging/sessions` 路径只能由 P1 broker 在已验证 client root 内构造，不提供一个跨 scope 的 `objects_root`。
- [ ] `AppConfig` 从显式参数或 `CONSULTATION_VAULT_ROOT` 读取，解析后用 `os.path.commonpath` 证明 vault 不在 repo 内；默认不自行创建。禁止将 vault 或模型目录默认为仓库子目录；第一阶段范围字段使用 Literal/constant 校验，不能由环境变量悄悄打开 Web/API/voice/multi-user/联网入库/自动正式写回。
- [ ] 策略 YAML 写入所有设计枚举和策略版本：P0冻结的18值 `SourceGrade` 与6值 `EmpiricalSupport`；全局关系；资料保留类别；风险规则只使用合成触发例，不保存真实会谈文本。增加测试把策略枚举与 Task 3 Pydantic Literal/Enum 精确对齐，不在Task 4修改 evidence模型或Schema。
- [ ] `PrivacyScanner` 至少扫描：known canary、手机号样式、身份证样式、电子邮箱、明确客户稳定标识前缀、禁入路径后缀。报告只保存文件相对路径、规则 ID、行号和命中哈希，不复制命中文字。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_config.py tests/consultation_kb/unit/test_privacy_scan.py
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor --help
```

Expected: PASS；CLI 帮助不创建 vault。

---

## Task 5：无正文审计、run manifest 与可执行 doctor

**Files:**

- Create: `consultation_kb/observability/__init__.py`
- Create: `consultation_kb/observability/audit.py`
- Create: `consultation_kb/observability/runs.py`
- Create: `consultation_kb/core/doctor.py`
- Modify: `consultation_kb/cli.py`
- Create: `tests/consultation_kb/unit/test_audit_contract.py`
- Create: `tests/consultation_kb/integration/test_doctor.py`

**Interfaces produced:** `AuditSink.emit(AuditEvent)`；`RunManifestStore`；`Doctor.run()`；`consultation-kb doctor --json`。

- [ ] 写失败测试，证明审计模型不能接收正文：

```python
import pytest
from pydantic import ValidationError

from consultation_kb.observability.audit import AuditEvent


def test_audit_event_rejects_raw_text(fixed_now, fixed_id_factory) -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({
            "event_id": fixed_id_factory.object_id("audit"),
            "run_id": fixed_id_factory.uuid7(),
            "event_type": "scope_denied",
            "occurred_at": fixed_now,
            "object_ids": (),
            "counts": {"denied": 1},
            "raw_text": "synthetic client body",
        })
```

- [ ] 写 doctor 集成测试：

```python
def test_doctor_checks_fts5_and_external_vault(synthetic_workspace) -> None:
    repo, vault = synthetic_workspace
    report = Doctor(AppConfig.from_values(repo, vault)).run()
    assert report.ok is True
    assert report.checks["sqlite_fts5_roundtrip"].status == "pass"
    assert report.checks["vault_outside_repo"].status == "pass"
```

- [ ] `AuditEvent` 字段固定为 event/run/type/time、当前作用域不可逆哈希、对象 ID、版本、计数、错误码和结果哈希；不提供通用 `details: dict`，防止正文绕过。客户作用域审计文件位于客户目录，P1 才启用；共享汇总只保留聚合数值。
- [ ] `RunManifest` 保存设计规格第 19 节的版本和路由字段，但生成候选/实际回复只保存受治理对象 ID 与哈希。P0 实现 append-only JSONL 编码器；P1 将其放入正确 scope。
- [ ] Doctor 执行真实操作：SQLite `CREATE VIRTUAL TABLE ... USING fts5`、插入/查询；Pydantic Schema 导出比对；vault/repo commonpath；Git tracked 隐私扫描；Python x64/版本；策略加载。它不下载依赖或模型。
- [ ] CLI JSON 模式 stdout 只输出一个 JSON 对象，诊断日志走 stderr；任一必需检查失败退出码 2。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_audit_contract.py tests/consultation_kb/integration/test_doctor.py
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor --repo-root . --vault-root ..\knowledge-vault --json
```

Expected: 在有效外部临时 vault 上 `ok=true`；仓库内 vault 返回退出码 2。

---

## Task 6：P0 垂直验收与架构守卫

**Files:**

- Create: `tests/consultation_kb/unit/test_architecture_boundaries.py`
- Create: `tests/consultation_kb/unit/test_acceptance_runner.py`
- Create: `tests/consultation_kb/integration/test_p0_vertical_slice.py`
- Create: `tests/consultation_kb/acceptance_registry.py`
- Create: `scripts/run_consultation_acceptance.py`
- Modify: `docs/consultation-kb/upstream-baseline.md`

**Interfaces consumed:** 包装、配置、Schema、隐私扫描、doctor、上游 Graphify。

- [ ] 写 AST 架构测试：`graphify` 不导入 `consultation_kb`；`consultation_kb/client`（存在后）不得导入 `graphify.build`、`graphify.serve`、`graphify.wiki`；P0 时目录不存在也应稳定通过。
- [ ] 在 `conftest.py` 注册 `@pytest.mark.acceptance_id("ISO-01")` 及 `--acceptance-id` 过滤；requested ID 零收集必须失败。`acceptance_registry.py` 冻结总计划第 7 节的 ID→required primary/extension modules 映射；runner 先拒绝未知 ID，再要求 primary 存在、核对所有已存在注册模块的静态/收集 marker，最后按 ID 的 OR 语义调用 pytest 并保留原退出码。P1–P9 只能通过 `scripts/run_consultation_acceptance.py --ids ID1,ID2` 重跑，不能按文件名猜验收。
- [ ] registry 从 P0 即登记未来 extension 路径：P4 `test_graph_01_global.py/test_ver_01.py`、P7 `test_outbox_saga_exceptions.py`，以及 P8 五个 `test_*_crash.py`；文件在所属阶段前可不存在，一旦出现就必须带映射的 `GRAPH-01/VER-01/TX-01` marker。这样后续阶段不用修改 runner 规则。
- [ ] `test_acceptance_runner.py` 覆盖：单 marker、多 marker、两个请求 ID、未知 ID、marker 拼写错误、primary 模块缺失和某个请求 ID 零收集；后四类必须非零。P0 尚未实现的 ID 只有在被请求时才要求 primary 存在；尚未到阶段的 extension 可以不存在，一旦文件出现就必须带 marker。
- [ ] 写垂直测试，完整执行：创建临时 repo/vault → 加载配置 → 运行 doctor → 扫描 Git/fixture → 导出 Schema → 断言无正文审计序列化。
- [ ] 故意在临时 repo 写入 canary，确认垂直测试对应 scanner 分支失败；删除后重新运行通过。该故障注入只发生在 `tmp_path`。
- [ ] Run P0 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb scripts
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit tests/consultation_kb/integration/test_doctor.py tests/consultation_kb/integration/test_p0_vertical_slice.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
git diff --check
git status --short
```

Expected: 全部通过；Git 状态不含 vault、SQLite、WAL/SHM、模型或泄漏报告。

- [ ] 把最终命令、测试数、Python/SQLite/FTS5 结果追加到 baseline 文档；不复制敏感路径以外的正文。
## P0 完成定义

- [ ] `consultation_kb` 可安装、导入、生成 Schema；Graphify 原命令和测试不变。
- [ ] `doctor` 实际验证 FTS5、配置、Schema 和隐私边界并正确 fail closed。
- [ ] 测试与审计合同不能携带原始客户正文。
- [ ] P1 可直接复用所有冻结模型；任何必要合同变更先回到本计划更新 Schema 和兼容测试。
