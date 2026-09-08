# P0 Task 4：配置、Vault 边界、隐私扫描与策略合同设计

> 状态：方案 A 已批准；本文件冻结实现合同，尚未实现
> 日期：2026-07-17
> 适用基线：`consultation-kb-implementation` worktree，Task 3 合同提交 `f8c6d0736433bbfdcd13613942ff2cc369e53300`
> 上位设计：`2026-07-16-consultation-knowledge-base-design.md`
> 上位计划：`2026-07-16-consultation-kb-p0-contracts-test-foundation.md` 的 Task 4
> 规范性关键词：`MUST`/“必须”、`MUST NOT`/“不得”、`SHOULD`/“应”按字面执行

## 1. 决策摘要

Task 4 采用以下不可拆分的方案 A：

1. `AppConfig` 的所有公开构造路径执行同一套 type、绝对路径、canonical identity、repo/vault 双向不重叠和第一阶段 scope 校验；它同时以 runtime seal 禁止 subclass，所有 validated-config consumer 只接受 `type(config) is AppConfig`。只有 `load()` 获取并校验环境 namespace，direct constructor/`from_values()` 不读取 ambient env，且生产 CLI/doctor/runtime 的配置 acquisition 必须经 `load()`。
2. `VaultLayout` 只能从已验证的 `AppConfig` 构造；它是非 dataclass 的 frozen-slots value object，只暴露 18 个固定路径，零 I/O，不接受任意客户 ID、session ID 或相对路径。
3. `PrivacyScanner` 是确定性泄漏探测器。它按 bytes 有界流式扫描，任何链接、检测到的 snapshot 竞态不一致、编码或资源上限问题均 fail closed；命中摘要与位置引用分别使用 length-prefixed、domain-separated HMAC-SHA256，报告和异常不复制正文、basename、相对/绝对路径或原始异常。
4. 确定性的报告只返回 `location_ref`；它绑定 owner root identity 与真正的 native root-relative bytes。raw path 只存在于 scanner 当前、由 opaque object-identity handle 保护的进程内 generation；新 scan 获锁开始即使旧 generation 失效，失败保持空。
5. Task 4 新增生产级 `consultation_kb/policy/loader.py`。四份 YAML 由一个严格 loader 安全读取、验证并返回不可变对象；测试不得拥有另一套“真正的”加载逻辑。
6. 资源合同仅承诺显式 checkout root 和 editable install。完整 wheel 中携带策略资源、模型资源及安装态资源测试留给 P9；Task 4 不声称普通 wheel 可独立运行。
7. 跟踪文件中的完整合成 canary 和稳定客户标识采用机械分片，精确 canary 定义文件是唯一允许保留两个完整 marker bytes 的跟踪文件。不建立目录级或“看起来是 synthetic”豁免。
8. 实现开始前必须分别通过独立安全合同审查和独立策略 Schema 合同审查；两份结论均须 `P0=0/P1=0/P2=0`。

### 1.1 规范优先级与 Task 4 erratum

本文件是在上位 P0 计划之后经批准形成的 Task 4 专项规范。仅当 `2026-07-16-consultation-kb-p0-contracts-test-foundation.md` 的 Task 4 文本与本文件冲突时，本文件优先；上位设计、其他 Task 和未冲突条款的规范地位不变。旧 P0 计划保留为历史计划，不做语义编辑；第 7.2 节允许的 marker bytes 机械分片不属于语义编辑。

以下旧 Task 4 RED/API 语义被本 erratum 明确替代：

- 旧无参 `PrivacyScanner.default()` 示例由本文件第 6.1 节的显式 `profile`、`canary_definition_path`、可选 key/limits 构造替代；无参调用不是 RED 目标而是禁止的 API；
- 旧报告中的 `relative_path` 由 deterministic `PrivacyScanReport` 的 opaque `location_ref` 替代，报告不得包含 basename、相对路径或绝对路径；
- Task 4 首个 RED 及全部后续实现/测试必须以本文件的 `scan_paths(...) -> PrivacyScanOutcome`、generation handle 和 `resolve_location(handle, location_ref)` 为准。

这是一项 normative override，不授权修改旧计划语义，也不得为了让旧示例继续运行而增加兼容 overload、默认 catalog、路径字段或第二套 scanner API。

### 1.2 策略资源与确定性生成物 Git EOL erratum

实施期在 Windows 主机上确认：当 Git 安装级配置为 `core.autocrlf=true` 且仓库未声明 attributes 时，四份提交为 LF 的 YAML blob 会在 fresh checkout 中被转换为 CRLF，而第 8.2 节的严格 raw gate 必须拒绝这些 bytes。合并至全新主工作树后的集成验证进一步确认，同一转换会使 `requirements/consultation-win-py312.in` 与 21 份 checked-in Schema 偏离各自确定性 exporter 的 LF bytes。不能通过放宽 loader、把字节相等降级为语义相等、依赖开发者本机 Git 配置或只检查 index blob 规避该矛盾。

因此 Task 4 必须在仓库根创建唯一、精确的 `.gitattributes`，内容为以下八行且仅有一个终端 LF：

```gitattributes
/.gitattributes text eol=lf
docs/superpowers/specs/2026-07-17-consultation-kb-p0-task4-security-policy-design.md text eol=lf
policies/evidence-levels.yaml text eol=lf
policies/relation-types.yaml text eol=lf
policies/retention.yaml text eol=lf
policies/risk-rules.yaml text eol=lf
requirements/consultation-win-py312.in text eol=lf
schemas/*.schema.json text eol=lf
```

第一行带前导 `/` 的 root-only self-pin 保证根 attributes 文件自身在第一次 checkout 时也保持 canonical LF bytes，且不得把属性传播给任何嵌套同名文件；第二行冻结本规范的 checkout bytes，使 normative SHA-256 可跨工作树复核；其后四行只冻结四个 canonical policy resource；最后两行分别冻结单个 requirements 输入与根 `schemas/` 下直接匹配 `*.schema.json` 的确定性生成物。Schema 规则不得传播到嵌套目录或非 Schema 文件。该合同不授权 blanket `*.yaml`、全仓换行归一化或其他 attributes。`POLICY-05` 仍须对任意 CRLF/BOM/非法换行 fixture fail closed；checkout 验收必须从临时 Git source repository 执行 `git -c core.autocrlf=true clone`，证明根 `.gitattributes`、本规范、四份策略、requirements 输入与全部 21 份 Schema 工作树文件均无 CR、raw bytes 与 committed blobs 一致且 production `PolicyLoader` 成功加载，并证明 `nested/.gitattributes`、嵌套 Schema 与非 Schema 文件的 `text`/`eol` 均为 `unspecified`。缺少/漂移根 `.gitattributes`、28 个正向目标中任一未得到 `text: set` 与 `eol: lf`、任一反向目标获得属性、或 fresh checkout 发生 bytes 转换都必须使验收失败。

## 2. 范围与非范围

### 2.1 Task 4 必须交付

- 一个 stdlib-only、无默认目录创建行为的 `AppConfig`；
- 一个从 `AppConfig` 派生、零 I/O 的固定 `VaultLayout`；
- 一个 stdlib-only、显式支持 `repo_tracked`/`shared_derivative` profile 的 `PrivacyScanner`；
- 一个生产级严格 `PolicyLoader` 及四类不可变 policy document；
- 四份顶层 YAML policy，精确版本、精确顺序、精确语义；
- config、layout、scanner、policy loader 的 RED-first 单元/合同测试；
- 对已跟踪 synthetic marker/client ID 的无语义机械分片；
- `doctor --help` 的无副作用回归，以及 Task 3/P0/上游回归。

### 2.2 明确不在 Task 4

- 不创建或初始化真实 vault，不创建任何客户、会谈、SQLite、WAL/SHM 或模型目录；
- 不实现客户 broker、capability、客户路径、session 路径或 final-handle 打开；
- scanner 只实现第 6.6 节“检测到的 snapshot inconsistency”提交门；不声称提供事务快照或消灭全部 TOCTOU，也不解决 hardlink 授权、SUBST/volume alias 或 ISO-01；这些最终 authority 边界属于 P1；
- 不实现知识导入、关系生产、C1、Wiki 或 policy manifest materialization；这些从 P3 起消费本合同；
- 不实现风险 engine、内部 observation 生命周期或来访者输出投影；这些属于 P6；
- 不实现去标识化变换、罕见属性组合判断或人工脱敏复核；这些属于 P7；
- 不实现 recovery、tombstone、物理删除、backup 生命周期或 fault injection；这些属于 P8；
- 不实现完整 wheel/package-data 资源、模型交付或全量评估；这些属于 P9；
- 不修改 Task 3 的 `SourceGrade`、`EmpiricalSupport`、Pydantic model 或已导出 Schema；
- 不修改 `graphify/`、依赖输入、hash lock、CLI 行为、根包导入边界或现有 `.gitignore` 合同。

`PrivacyScanner` 只能证明“已执行本规范列出的确定性探测”。它不是完整匿名化证明，不检测任意姓名、所有 Unicode 标识、图像/OCR、压缩/加密内容或罕见属性组合；`location_ref` 也不是共享数据标识。

## 3. 依赖与模块边界

### 3.1 模块依赖

| 模块 | 允许依赖 | 禁止依赖/副作用 |
|---|---|---|
| `consultation_kb/core/config.py` | Python stdlib | PyYAML、Pydantic、vault/evaluation/policy/models、目录创建、文件写入 |
| `consultation_kb/vault/layout.py` | stdlib、`core.config.AppConfig` 与其安全错误类型 | scanner、policy、models、客户目录枚举、任意 path join、I/O |
| `consultation_kb/evaluation/privacy_scan.py` | Python stdlib，包括 `json`、`hmac`、`hashlib`、`secrets`、`os` | PyYAML、Pydantic、AppConfig、VaultLayout、Git 命令、`.gitignore` 解释、可持久化 path mapping |
| `consultation_kb/policy/loader.py` | stdlib、PyYAML、`AppConfig`、Task 3 `SafePolicyKey`/`SourceGrade`/`EmpiricalSupport` 的 `TypeAdapter`/`get_args` | scanner、vault layout、CLI、模型/网络下载、manifest 激活、目录创建 |

`consultation_kb/vault/__init__.py`、`evaluation/__init__.py`、`policy/__init__.py` 只作无副作用 package marker，不重导出业务类。`consultation_kb/core/__init__.py` 继续只导出 `distribution_version`；`consultation_kb/__init__.py` 不得导入 config、vault、evaluation、policy、PyYAML 或 Pydantic。

所有新增源码必须可被 Python 3.10 grammar 解析；支持的运行时仍为 Python 3.12+。模块 import 不得读取环境、stat 路径、加载 YAML、读取 canary 或创建任何文件。

### 3.2 单一职责

- config 只验证运行配置与 root identity；
- layout 只从获准 root 计算固定路径；
- scanner 只探测泄漏并返回无正文报告；
- policy loader 只定位、严格读取、验证和规范化四份 policy；
- Task 5 doctor 只编排这些公开合同，不复制路径、YAML 或扫描实现。

## 4. `AppConfig` 公共合同

### 4.1 冻结常量与 API

```python
from typing import Final, Literal, Mapping, TypeAlias, final

SCOPE_INTERACTION_MODE: Final[Literal["codex_text"]] = "codex_text"
SCOPE_SINGLE_COUNSELOR: Final[Literal[True]] = True
SCOPE_RUNTIME_NETWORK_INGEST: Final[Literal[False]] = False
SCOPE_AUTOMATIC_FORMAL_WRITEBACK: Final[Literal[False]] = False

PathInput: TypeAlias = str | os.PathLike[str]

class ConfigurationError(ValueError):
    code: str
    field: str | None

@final
@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class AppConfig:
    repo_root: Path
    vault_root: Path
    interaction_mode: Literal["codex_text"] = SCOPE_INTERACTION_MODE
    single_counselor: Literal[True] = SCOPE_SINGLE_COUNSELOR
    runtime_network_ingest: Literal[False] = SCOPE_RUNTIME_NETWORK_INGEST
    automatic_formal_writeback: Literal[False] = SCOPE_AUTOMATIC_FORMAL_WRITEBACK

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("CONFIG_SUBCLASS_FORBIDDEN")

    @classmethod
    def from_values(
        cls,
        repo_root: PathInput,
        vault_root: PathInput,
        *,
        interaction_mode: object = SCOPE_INTERACTION_MODE,
        single_counselor: object = SCOPE_SINGLE_COUNSELOR,
        runtime_network_ingest: object = SCOPE_RUNTIME_NETWORK_INGEST,
        automatic_formal_writeback: object = SCOPE_AUTOMATIC_FORMAL_WRITEBACK,
    ) -> AppConfig: ...

    @classmethod
    def load(
        cls,
        *,
        repo_root: PathInput,
        vault_root: PathInput | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> AppConfig: ...
```

直接 `AppConfig(...)`、`from_values()` 和 `load()` 必须汇入同一个私有纯 value 校验/规范化函数。该函数只接收显式字段，统一执行 type、scope、路径、canonicalization、repo marker 与双向 disjoint invariants；它不读取 ambient env。`__post_init__` 必须再次执行该函数并只用 `object.__setattr__` 写回 canonical `Path`；不得提供公开/半公开 unchecked constructor。`dataclasses.replace()` 因而也会重新校验。

`typing.final` 只提供静态提示，不构成安全边界；上述 `__init_subclass__` 是必须实现的 runtime seal。任何普通 class statement、`types.new_class` 或其他正常 Python subclass 路径都必须在类创建时固定抛 `TypeError("CONFIG_SUBCLASS_FORBIDDEN")`，不得让子类覆写/no-op `__post_init__`。本合同不把任意 in-process monkeypatch 视为受支持扩展点。

四个 scope 字段按 `type(value) is ...` 和精确值检查：`1` 不等于 `True`，`0` 不等于 `False`，字符串形式不做 coercion。`load()` 不从 env 读取任何 scope 字段。`AppConfig` 不增加 `model_root` 或任何仓库内资源默认路径。

环境 acquisition、namespace allowlist、env source conflict 和 reserved-key gate **只属于 `load()`**。direct constructor 与 `from_values()` 不接受 environ 参数、不读取 `os.environ`，也不因 ambient `CONSULTATION_*` 改变结果；它们并非生产启动入口。所有需要取得配置的 production CLI、doctor 和 runtime callsite 必须调用 `AppConfig.load(...)`，不得直接构造或调用 `from_values()`；`doctor --help` 不取得配置、仍保持 lazy/no-side-effect。Task 4 以静态 AST/import-callsite 检查加显式 production-callsite 测试锁定这一边界。测试和内部纯 value fixture 才可使用 direct/`from_values()`。`VaultLayout.from_config()`、`PolicyLoader.from_config()` 及以后任何声称接收 validated config 的 consumer 必须先检查 `type(config) is AppConfig`，不得使用 `isinstance`、Protocol、duck typing 或 subclass acceptance；否则返回各自固定 validated-config error。

`repr(config)` 必须为固定的脱敏表示，不含 repo/vault；异常和日志也不得序列化 `dataclasses.asdict(config)`。`AppConfig` 没有 canonical bytes API；确定性只按 frozen dataclass 的六个字段及其值做 exact equality，不得用 repr、pickle 或自创 JSON bytes 作为合同。

### 4.2 环境 allowlist

`load(environ=None)` 是唯一环境 acquisition boundary：它对 `os.environ` 做一次快照；注入 mapping 用于测试。只在这条路径上对 ASCII case-insensitive 的 `CONSULTATION_*` namespace 执行下表；direct constructor/`from_values()` 不检查 ambient namespace：

| 规范化键 | 行为 |
|---|---|
| `CONSULTATION_VAULT_ROOT` | 唯一由 AppConfig 消费的 runtime env；非空并按路径合同验证 |
| `CONSULTATION_PYTHON` | 为兼容既有 bootstrap 而识别的 known key；允许存在、要求 string/nonblank，但对 AppConfig 完全 inert，绝不能改变任何 config/scope；启动 wrapper 应在进入 runtime 前移除 |
| `CONSULTATION_RESOLVER_SCENARIO` | test-only reserved；生产 `load()` 必须拒绝 |
| `CONSULTATION_RESOLVER_SCENARIO_LOG` | test-only reserved；生产 `load()` 必须拒绝 |
| `CONSULTATION_FAULT_POINT` | P8 reserved；Task 4 生产 `load()` 必须拒绝 |
| 其他任意 `CONSULTATION_*` | 未知键，必须拒绝 |

键在内部使用 ASCII uppercase 规范化。规范化后有两个同名键时，无论 value 是否相同均拒绝；不得依赖 Windows mapping 已经去重。非字符串键、非字符串 value、空白 value 都拒绝。unknown-key 错误只能是固定 `CONFIG_ENV_UNKNOWN`，不得回显原始或规范化后的未知 key；known/reserved key 错误也不得回显 value。

以下名称没有特例，即使值“安全”也走 unknown/reserved 拒绝路径：

```text
CONSULTATION_INTERACTION_MODE
CONSULTATION_SINGLE_COUNSELOR
CONSULTATION_RUNTIME_NETWORK_INGEST
CONSULTATION_AUTOMATIC_FORMAL_WRITEBACK
CONSULTATION_WEB_ENABLED
CONSULTATION_API_ENABLED
CONSULTATION_VOICE_ENABLED
CONSULTATION_MULTI_USER
CONSULTATION_AUTOMATIC_DIAGNOSIS
```

显式 `vault_root` 与 env 同时存在时，两者各自 canonicalize 后必须 identity-equal；相同则接受，不同则 `CONFIG_VAULT_SOURCE_CONFLICT`。显式值不得静默覆盖 env。两者都缺失则 `CONFIG_VAULT_ROOT_MISSING`。

### 4.3 路径输入与 canonicalization

每个 root 严格按以下顺序处理：

1. 只接受 `str` 或返回 `str` 的 `os.PathLike`；拒绝 `bytes`、空白、NUL 和 ASCII 控制字符。
2. 在任何 `resolve`/`abspath`/`normpath` 之前检查原始输入为绝对路径；相对路径不得因当前 cwd 变成可接受路径。
3. 不展开 `~`、`%VAR%`、`$VAR`，不做 shell expansion。
4. 拆分原始路径段；根之后出现精确 `.` 或 `..` 段即拒绝，不靠折叠后掩盖。Windows drive-relative（如只有盘符而非盘符根）也拒绝。
5. Windows 只接受普通 fully-qualified local drive path。UNC、extended UNC、volume-GUID、device/NT namespace（包括 `\\?\`、`\\.\`、`\??\` 族）全部以 `CONFIG_PATH_NAMESPACE_UNSUPPORTED` 拒绝。使用 stdlib `ctypes` 查询 drive type；mapped remote、`DRIVE_UNKNOWN`、`DRIVE_NO_ROOT_DIR` 均拒绝。查询失败不得当作 local。
6. Windows 任一 root 后组件含 `:`（ADS）、`*`/`?` wildcard、尾点、尾空格，或 base name（第一点号前、忽略大小写）属于 `CON/PRN/AUX/NUL/COM1..COM9/LPT1..LPT9` 时拒绝。ASCII case-insensitive 匹配 `^[^ .\\/:]{1,6}~[0-9]{1,6}(?:\.[^ .\\/:]{1,3})?$` 的 DOS 8.3 alias 形态段也以 `CONFIG_PATH_ALIAS_UNSUPPORTED` 拒绝；即使普通目录恰好使用该形态也不例外。
7. 对原始 normalized path 的每个组件先用 `os.path.lexists` 区分“不存在”和 broken link，再 `lstat`；broken symlink、symlink、junction 或具有 `FILE_ATTRIBUTE_REPARSE_POINT` 的组件全部拒绝。检查失败不得当作“不存在”。
8. 调用 `os.path.normpath`，再调用 `os.path.realpath(..., strict=False)`，解析所有已存在前缀；对得到的 canonical 已存在组件再次执行同一 `lexists/lstat/reparse` 检查。
9. Windows identity 比较使用 `normcase` 后的 canonical string，因此大小写、正反斜杠或尾分隔符差异不能制造不同 root；保存值是 canonical absolute `Path`，不是原始字符串。
10. repo 必须已存在且是目录；`repo/.git` 必须是非 reparse 的 regular file 或 directory，以兼容 linked worktree。repo 不存在、marker 缺失或类型不对均拒绝。
11. vault 可以不存在；若存在必须是非 reparse directory，existing regular file 或特殊文件拒绝。AppConfig 不创建它。

Windows UNC/device/remote drive 的拒绝是 P0 本地资料库合同，不是 Python 一般路径能力声明。POSIX 只接受语法普通的绝对路径候选；P0 不声称能识别 bind/network mount。若以后需要网络或别名 mount，必须作为新的安全设计评估 ACL、final identity、锁、备份和可用性，不能放宽本版本常量。

### 4.4 repo/vault 完全 disjoint

对 canonical、Windows 已 `normcase` 的两个 root 做双向 containment：

```text
vault == repo                  -> reject
commonpath(repo, vault) == repo -> reject  # vault 在 repo 内
commonpath(repo, vault) == vault -> reject # repo 在 vault 内
```

`os.path.commonpath` 因不同盘符抛 `ValueError` 时定义为“不重叠”，应接受，不得 crash，也不得把异常路径写入错误。字符串 `startswith` 禁用，因为它不能处理段边界、大小写或 alias。

不存在 vault 的最深已存在祖先仍必须通过 reparse 检查；canonical lexical tail 仍须与 repo 双向不重叠。允许不存在 root 只表示“配置可以提前生成”，不表示未来创建安全：第一次创建、每次打开和每次权限敏感操作都由 P1 重新验证。

### 4.5 P0/P1 安全边界

Task 4 配置验证是启动时 identity preflight，不是 open-time authority。它不能证明检查后路径未被替换，也不能彻底消除 SUBST、volume mount、hardlink 或字符串检查后的 TOCTOU。

P1 必须在每次 create/open 时：检查所有中间组件、以不跟随链接方式打开、用 `GetFinalPathNameByHandle`/等价 final handle 重新核对最终 identity、验证 link count/文件 identity，并继续使用同一已验证 handle，不能验证后按字符串重开。Task 4 测试通过不得被表述为 ISO-01 已完成。

## 5. `VaultLayout` 合同

### 5.1 构造与行为

`VaultLayout` 是自定义的、非 dataclass、frozen-slots、repr-redacted value object；`dataclasses.is_dataclass(VaultLayout)` 与 `dataclasses.is_dataclass(layout)` 都必须为 `False`。它不公开 `root`。唯一支持的公共工厂是：

```python
@classmethod
def from_config(cls, config: AppConfig) -> VaultLayout: ...
```

裸 `Path`、`str`、duck-typed config 或任何 `AppConfig` subclass instance 必须拒绝；工厂只在 `type(config) is AppConfig` 时接收该已验证对象，否则 `VAULT_VALIDATED_CONFIG_REQUIRED`。实现只保存单个 private slot `_vault_root`，创建后禁止重新绑定或增加属性；18 个路径由只读 property 固定拼接，不得作为 18 个可序列化 fields 保存。`repr(layout)` 精确为 `<VaultLayout redacted>`；`dataclasses.asdict(layout)`、`dataclasses.astuple(layout)` 和 `vars(layout)` 必须以 `TypeError` 受控拒绝且不得在 message 中出现 root。没有 `to_dict`、`model_dump`、JSON 或其他 public serializer；pickle/copy/deepcopy 固定以 `TypeError("VAULT_SERIALIZATION_FORBIDDEN")` 拒绝。

两个 `VaultLayout` 的语义 equality/hash 只按其 canonical vault root identity；不同 root 不相等。equality 不公开该 identity，也不得接受 duck object。public surface 除普通 object protocol、`from_config` 与下列 18 个只读 property 外不增加业务属性。构造和属性读取不得调用 `mkdir`、`touch`、`open`、`resolve`、`exists`、`iterdir` 或客户枚举；它只做固定 `Path` 拼接。

### 5.2 18 个精确路径

| 属性 | 固定路径 |
|---|---|
| `identity_map` | `<root>/identity/identity-map.enc` |
| `sources` | `<root>/sources` |
| `wiki_draft` | `<root>/wiki/draft` |
| `wiki_approved` | `<root>/wiki/approved` |
| `wiki_history` | `<root>/wiki/history` |
| `global_db` | `<root>/global/catalog.sqlite3` |
| `global_graph` | `<root>/global/graph/graph.json` |
| `lexical_indexes` | `<root>/global/indexes/bm25` |
| `vector_indexes` | `<root>/global/indexes/vector` |
| `cases_draft` | `<root>/cases/draft` |
| `cases_approved` | `<root>/cases/approved` |
| `cases_quarantine` | `<root>/cases/quarantine` |
| `clients_root` | `<root>/clients` |
| `global_objects_root` | `<root>/global/objects` |
| `global_staging_root` | `<root>/global/.staging` |
| `review_queue` | `<root>/review-queue` |
| `audit_root` | `<root>/audit` |
| `quarantine` | `<root>/quarantine` |

18 个属性都由 `config.vault_root` 派生且保持 absolute/canonical，必须每次产生语义相同的 `Path`。`clients_root` 只交给 P1 control-plane broker；整个 `VaultLayout` 对象、`clients_root` 或其他 global roots 均不得传给客户 worker。

### 5.3 明确禁止的 API

- `objects_root`；
- public `root`/`vault_root`；
- `client_root(client_id)`、`session_path(...)`、`path_for(...)`、`__getitem__`；
- 接受任意相对路径、对象 ID、客户 ID 或 session ID 的 API；
- 枚举 `clients_root` 或按是否存在返回不同结果；
- 自动创建目录、修复权限或初始化数据库。

客户 `objects/.staging/sessions` 只能由 P1 broker 在 capability、client root 和 final handle 校验后构造。

## 6. `PrivacyScanner` 公共合同

### 6.1 API 与不可变 limits

```python
ScanProfile = Literal["repo_tracked", "shared_derivative"]

SCAN_CHUNK_BYTES: Final = 65_536
SCAN_CARRY_BYTES: Final = 512

@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_input_paths: int = 100_000
    max_roots: int = 50_000
    max_tree_entries: int = 500_000
    max_files: int = 100_000
    max_depth: int = 64
    max_native_relative_bytes: int = 32_768
    max_file_bytes: int = 1_073_741_824       # 1 GiB
    max_total_bytes: int = 8_589_934_592      # 8 GiB
    max_hits: int = 10_000
    max_catalog_bytes: int = 65_536
    max_markers: int = 256
    max_marker_bytes: int = 128

DEFAULT_SCAN_LIMITS: Final = ScanLimits()

@dataclass(frozen=True, slots=True)
class PrivacyHit:
    location_ref: str
    rule_id: str
    line_number: int | None
    hit_hash: str

@dataclass(frozen=True, slots=True)
class PrivacyScanReport:
    hits: tuple[PrivacyHit, ...]

    @property
    def hit_count(self) -> int: ...

class PrivacyScanError(RuntimeError):
    code: str
    location_ref: str | None

class ScanResolutionHandle:
    # public type, scanner-only construction, zero public fields
    ...

@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PrivacyScanOutcome:
    report: PrivacyScanReport
    resolution_handle: ScanResolutionHandle

class PrivacyScanner:
    @classmethod
    def default(
        cls,
        *,
        profile: ScanProfile,
        canary_definition_path: Path,
        hash_key: bytes | None = None,
        limits: ScanLimits = DEFAULT_SCAN_LIMITS,
    ) -> PrivacyScanner: ...

    def scan_paths(self, paths: Sequence[Path]) -> PrivacyScanOutcome: ...

    def resolve_location(
        self,
        handle: ScanResolutionHandle,
        location_ref: str,
    ) -> Path: ...

    def close(self) -> None: ...
```

`profile` 为显式必填参数，没有默认值。`ScanLimits` 是 deep-frozen 显式参数，不可由环境变量、YAML、cwd 或文件 metadata 调整；每个字段要求 exact positive `int`，bool 不得当 int。

八项可上调字段的硬上限为：raw input paths `1_000_000`、unique roots `100_000`、tree-entry observations `2_000_000`、files `1_000_000`、depth `256`、单文件 `8_589_934_592` bytes（8 GiB）、总量 `68_719_476_736` bytes（64 GiB）、hits `100_000`。native-relative/catalog/marker 三类四项的默认值同时是 v1 硬上限：32,768 bytes、65,536 bytes、256 项、每项 128 bytes；测试可以显式下调，不能上调。chunk 固定 64 KiB、carry 固定 512 bytes，不可调整。超过硬上限的 `ScanLimits` 在构造时拒绝。

所有 runtime maximum 都是 inclusive：当前值 `<= max` 成功；尝试纳入第 `max + 1` 个 raw input/root/tree-entry observation/file/hit/marker、遇到 depth `max_depth + 1` 的 entry、或读取/编码第 `max + 1` 个 native-relative/file/total/catalog/marker byte 时，立即用对应 limit code fail closed，不返回截断的 clean 或 partial outcome。逐项计数口径冻结如下：

- raw input paths 在读取 `paths` sequence 的每一项时、任何 type/path normalization/canonicalization/stat 之前递增；不得依赖 caller 的 `len()` 作为唯一检查。exact duplicate、非法项和最终重叠项仍先消耗一个 `max_input_paths` 计数；第 `max + 1` 项立即 `SCAN_LIMIT_INPUT_PATHS`，不继续检查该项；
- roots 先按 canonical identity 去掉 exact duplicate，再计 `max_roots`；nested roots 保留且各计一个；
- tree-entry observations 对每次 initial 或 final/post-order `scandir` 产生的每个 raw entry，在 `lstat`、保存 tuple、排序、去重或 ownership 判断之前递增；同一 pathname 在 initial/final snapshot、overlapping root 或重复 traversal 中每次被观察都分别计数。explicit root 本身由 raw-input/unique-root limit 约束，不额外算 tree entry；第 `max_tree_entries + 1` 次观察立即 `SCAN_LIMIT_TREE_ENTRIES`；因此 empty-directory tree、超宽目录和 snapshot tuple memory 均有硬上界；
- directory root 自身 depth `0`，其 direct child depth `1`；file root depth `0`；任何被枚举的 directory/file entry 都服从 inclusive `max_depth`；
- files 在最终 canonical pathname 去重和最具体 root ownership 归属后计数；overlap 的同 pathname 只计一次，不同 hardlink pathname 各计一次；
- `max_native_relative_bytes` 只计第 6.3 节的 native relative bytes，不计 owner root identity 或 HMAC framing；
- `max_file_bytes` 按该 pathname 实际读取 bytes 计；预检 size 恰等于上限可读，实际出现第 `max + 1` byte 即失败；
- `max_total_bytes` 是本调用所有最终扫描 pathname 的实际读取量之和；overlap 同 pathname 只读/计一次，hardlink pathname 分别读取/计费；catalog bytes 不计入该总量；
- hits 以 occurrence entry 计，尝试发出第 `max_hits + 1` 个即整次失败；catalog/markers/marker bytes 也分别以 raw catalog bytes、数组项和单 marker UTF-8 bytes 按同一 inclusive 规则计。

每项测试必须同时覆盖 exact-equal success 与 plus-one failure；不得用“达到上限失败”等含糊表述。

`PrivacyScanner` 的任何构造路径都必须校验 profile、canary definition、key 和 limits。无参 `default()` 禁止；不存在基于 cwd 的 canary 猜测。

`PrivacyHit` 与 `PrivacyScanReport` 使用 frozen dataclass exact value equality；报告的确定性合同是 `hits` ordered tuple 及每个 hit 四字段完全相等。它们没有 canonical report bytes API。`PrivacyScanOutcome` 明确 `eq=False`，不参与 value equality；`repr(outcome)` 精确为 `<PrivacyScanOutcome redacted>`，pickle/copy/deepcopy 均以固定 `TypeError("SCAN_SERIALIZATION_FORBIDDEN")` 拒绝。

`ScanResolutionHandle` 只能由一次成功 scan 的提交步骤构造，调用方不能直接/反射构造有效 capability。它无 public fields，repr 精确为 `<ScanResolutionHandle redacted>`，不实现 value equality/hash contract；授权只使用该 Python object 的 `is` identity。pickle/copy/deepcopy 同样固定拒绝，generation token 不进入 outcome/report equality、repr、日志、异常或任何 serializer。

### 6.2 Canary catalog

`canary_definition_path` 必须是 absolute、已存在、非 symlink/junction/reparse、link count 精确为 1 的 regular JSON file。catalog 最多 65,536 bytes；JSON 用 duplicate-key rejecting `object_pairs_hook`，普通覆盖重复键的 `json.load(s)` 禁止。当前权威定义是 `tests/fixtures/consultation_kb/canaries.json`，其 exact schema 为：

```text
schema_version: exact string "1.0"
synthetic_only: exact bool true
rule_id: exact string "known_canary"
markers: nonempty unique JSON array of UTF-8 strings
```

marker 必须是未使用 JSON escape 的 ASCII string，1..128 bytes、无 BOM/NUL/control/newline，catalog 最多 256 项；重复项、一个 marker 是另一个 marker 的子串、unknown key 或错误类型均 `SCAN_CANARY_CATALOG_INVALID`。定义文件的完整 marker bytes 不在本规范复写。

scanner 构造时以 no-follow handle 绑定 catalog 的 canonical path、file identity、link count、size、mtime_ns、ctime_ns、raw SHA-256，并由 strict JSON token span 记录每个 `markers` string value 在 raw bytes 中的精确 span。每次 scan（包括 empty `paths`）都在旧 generation 作废后执行完整 catalog pre-check，并在提交前执行 post-check；两次都重新 no-follow 打开/读取并核对同一 identity/link count/size/mtime_ns/ctime_ns/raw hash。任何变化使整个扫描 `SCAN_CATALOG_CHANGED`，不得采用新内容或返回 partial outcome。

### 6.3 输入 root、枚举与重叠

- 空 `paths` 也必须先完整执行 catalog pre/post check；成功时提交 `PrivacyScanOutcome(report=PrivacyScanReport(hits=()), resolution_handle=<fresh handle>)` 与空 mapping，失败时不发行 handle；
- 非空 `paths` 必须单次、有界枚举 raw sequence；每取得一项先按第 6.1 节计 `max_input_paths`，再做任何 type/path/canonical/stat 工作。raw duplicate 不能通过后续 canonical 去重逃避该预处理上限；
- 每个非空输入必须是 absolute、已存在 regular file 或 directory；不得接受 UNC/device namespace、special file、相对路径或不存在路径；
- root canonicalization 不跟随 link；root 自身是 symlink/junction/reparse 时 fail closed；
- directory 使用显式 `scandir + lstat` 递归全部 regular files，包括隐藏文件，不解释 `.gitignore`；
- 不递归 `.git/` 的责任由 caller 通过传入精确 Git tracked file list 实现，scanner 不运行 Git；
- 规范化 root 只删除 exact canonical duplicates，显式 nested roots全部保留；去重后才执行 inclusive `max_roots` 计数。全部显式 roots 按 canonical platform identity key 排序后编号为 `root_0001` 等；
- 同一 pathname 被多个 root 覆盖时，归属 component depth 最大的最具体显式 root；深度并列时按 canonical root key 最小者。归属完成后再按 canonical pathname 排序扫描；
- 相同 canonical pathname 只扫描一次；同一文件通过不同 hardlink pathname 出现时按两个泄漏位置分别扫描和报告；
- directory root 必须先完成 canonical ownership/containment，再用 `child_path.relative_to(owner_root)` 得到真正的 relative `Path`，验证其不是 `.`、不含 `..`/空/control/escape component，然后以 `os.fsencode(os.fspath(relative_path))` 得到 native-relative bytes；绝不得把 absolute child path 编进该字段；
- file root 的 native-relative bytes 是 `os.fsencode(file_root.name)`；directory/file 两类都保留本机 separator/case bytes；owner root absolute identity 只进入第 6.4 节的独立 HMAC field，不消耗 native-relative limit；
- depth 与其他计数按第 6.1 节 inclusive 口径；任何 plus-one 立即 fail closed。

### 6.4 Length-prefixed HMAC、`location_ref` 与路径 metadata

两个 HMAC domain 使用同一个 exact 32-byte immutable scan key，但 framing 和 domain 不同。统一 framing 为：

```text
FRAME(part_1, ..., part_n) =
  uint64_be(len(part_1)) || part_1 || ... || uint64_be(len(part_n)) || part_n
```

长度是 bytes 长度；所有 part 都是 bytes；不使用 NUL、分隔字符、JSON 或隐式字符串拼接。

命中摘要精确为：

```text
lower_hex(HMAC-SHA256(
  scan_key,
  FRAME(
    b"consultation-privacy-hit-v1",
    rule_id.encode("ascii"),
    exact_match_bytes,
  ),
))
```

limits canonical bytes 包含 `ScanLimits` 的十二个动态十进制字段，再追加 chunk/carry 两个冻结常量字段；共十四个 `name=value` entries，按下列 ASCII 顺序、无空格：

```text
inputs=<n>;roots=<n>;tree_entries=<n>;files=<n>;depth=<n>;native=<n>;file=<n>;total=<n>;hits=<n>;catalog=<n>;markers=<n>;marker_bytes=<n>;chunk=65536;carry=512
```

`owner_root_identity_bytes` 是独立、不可公开的 HMAC input：Windows 取 scanner canonical root 的 `os.path.normcase(os.path.normpath(os.fspath(owner_root)))` 后用 `os.fsencode(...)`；POSIX 取 scanner 已验证 canonical native root identity string 后用 `os.fsencode(...)`。它不是 native-relative bytes，不受 `max_native_relative_bytes` 计费，不进入 report/error/repr/log。无法稳定取得或编码 identity 时 fail closed。

位置引用精确为：

```text
location_digest = lower_hex(HMAC-SHA256(
  scan_key,
  FRAME(
    b"consultation-privacy-location-v1",
    profile.encode("ascii"),
    root_label.encode("ascii"),
    limits_canonical_bytes,
    owner_root_identity_bytes,
    native_relative_bytes,
  ),
))
location_ref = root_label + "/pth1_" + location_digest
```

framing 的跨平台 synthetic known vector 冻结如下；它直接向 HMAC helper 传 exact bytes，不经过 OS path derivation，也不包含 canary/client 内容：

```text
scan_key = bytes(range(32))
profile = b"repo_tracked"
root_label = b"root_0001"
limits_canonical_bytes = b"inputs=100000;roots=50000;tree_entries=500000;files=100000;depth=64;native=32768;file=1073741824;total=8589934592;hits=10000;catalog=65536;markers=256;marker_bytes=128;chunk=65536;carry=512"
owner_root_identity_bytes = b"/synthetic/root"
native_relative_bytes = b"docs/readme.md"

hit_hash(rule_id=b"forbidden_path_suffix", exact_match_bytes=b".db") =
82d9fd66db590f5ae51c31f30703402390bca544a8194cd4355e771020a1c3b1

location_ref =
root_0001/pth1_39e668170e93ac9298ab787ae762272ad1d50f5d71e8ac1201a5cff85bf91a9a
```

Task 4 test 必须把这些 literal inputs 交给 production framing/HMAC helper 并断言两个 literal outputs；不得在 expected side 复制同一 helper。任一动态 limit field 的名称、值或顺序变化都必须改变 location vector，并按新的 scanner/security version 重新冻结，不能只更新 parser 而保留旧 HMAC identity。

格式必须匹配 `^root_[0-9]{4,}/pth1_[0-9a-f]{64}$`。owner identity 的单独 framing 保证不同 canonical roots 即使有相同 basename/relative bytes 也不 alias；`root_label` 仍由本次排序确定。报告不得保留任何 raw basename、path segment、native-relative bytes、owner identity、absolute root、盘符或用户目录。

每个 raw path segment 仍运行 `known_canary`、手机号、身份证、email、stable client ID 五类 bytes 规则；命中产生相同 `location_ref`、对应 rule ID、`line_number=None` 和 exact-match hit HMAC。final basename 另运行 `forbidden_path_suffix`，也使用 `line_number=None`。精确 `.`/`..`、NUL/control、空段、越过 root 或 native-relative bytes 无法稳定编码均是结构错误，整个扫描 fail closed；非 ASCII、空格或姓名样式不会被原样报告，也不会凭空新增第七个 rule。

默认 `scan_key = secrets.token_bytes(32)`，每个 scanner instance 生成一次。test 可注入 exact `bytes` 且长度必须为 32；`bytearray`、memoryview、其他长度和空 key 拒绝。key 不可读取、repr、pickle、序列化、记录或写盘。同一文件 snapshot、canonical root set/profile/limits/key 下 `PrivacyScanReport` exact value deterministic；默认 ephemeral key 导致不同 scanner instance 的 HMAC 不同，这是预期隐私性质。generation handle 每次成功 scan 都是 fresh identity，不属于报告确定性。

`forbidden_path_suffix` 的 `exact_match_bytes` 是实际匹配到的 basename suffix 或 exact basename bytes；其他规则使用原始 occurrence bytes。

### 6.5 Bytes streaming、编码与换行

- 所有六类 v1 规则按 bytes 匹配；不因 NUL、非文本 bytes 或 decode error 跳过文件；
- UTF-8 和 UTF-8 BOM 正常扫描，文件起始 BOM 不属于 match；
- 检测到 UTF-16/UTF-32 BOM 必须 `SCAN_UNSUPPORTED_ENCODING`，不得返回零命中；
- 其他无 BOM bytes 按原始 bytes 扫描 ASCII 子序列，不声称理解其字符编码；
- 每次精确最多读取 `65_536` bytes；carry 固定 `512` bytes，覆盖最大 128-byte marker、254-byte email 和 chunk 跨界；每个 match 使用全文件 absolute byte offset，跨 chunk 时只在其 end offset 首次进入新数据区时发出，禁止因 carry 重复计数；
- 行号从 1 开始；CRLF 算一个换行，LF 算一个，bare CR 算一个；CR/LF 和 match 被 chunk 切开时结果必须与单块扫描相同；
- v1 regex 不允许跨换行；同一行两个非重叠相同 occurrence 保留两个 hit；
- 打开前以可信 `stat.size` 做单文件和总预算预检，读取时再按实际 bytes 累加；任一计数超限或两者不一致时抛对应 limit/file-changed error；
- 单文件、总 bytes、文件数或 hit 数尝试越过 inclusive runtime limit 时抛对应 limit error，不返回部分 outcome；exact-equal 仍成功。

### 6.6 链接、containment 与竞态

- 遇到 symlink、junction 或任意 reparse point，不 follow、不 skip，而是 `SCAN_LINK_OR_REPARSE`；
- 每个 directory 必须先取得 no-follow initial snapshot，冻结 directory 的 type、device/file ID、link count、reparse attributes、mtime_ns、ctime_ns，并冻结按 native child name bytes 排序的直接 child entry tuple；每个 entry tuple 至少含 name bytes、type、device/file ID 与 reparse attributes；无法可靠取得任一字段即 fail closed；
- 扫描该 directory 的全部 descendants 后，必须按 post-order（child directory 先于 parent）重新取得 final snapshot，精确比较上述 directory metadata 与排序后的直接 child entry tuple；新增、删除、rename、replacement、type/identity/link/reparse/mtime_ns/ctime_ns 任一变化均为 `SCAN_TREE_CHANGED`；所有 root 的 final closure 都必须在 catalog post-check 与 generation commit 之前完成；
- 每个 regular file 的唯一读取序列必须为 pathname `lstat` → no-follow `open` → handle `fstat` → streaming read → handle `fstat` → final pathname `lstat`。所有 stat observations 在适用处精确比较 type、device/file ID、link count、size、mtime_ns、ctime_ns；final pathname identity 必须仍等于已读取 handle identity，replacement、grow/shrink、metadata drift 或 pathname 消失均为 `SCAN_FILE_CHANGED`；
- 打开后的 canonical location 必须仍在所属 root 内，否则 `SCAN_ROOT_ESCAPE`；
- unreadable、消失、类型变化或底层不支持所需 identity 检查均 fail closed；
- 不把原始 `OSError` message、filename、winerror path 或 traceback 放入公开异常/日志。

上述协议是一个“检测到的 snapshot inconsistency gate”：它要求在观察到不一致时拒绝提交，但不声称提供 filesystem transaction/snapshot isolation，也不声称消灭两个 syscalls 之间所有 TOCTOU。P1 仍必须在授权 create/open 时使用同一 verified final handle；不得把 Task 4 clean report 当作 open-time authority。

每个 scanner instance 只有一个 nonblocking、non-reentrant operation lock，`scan_paths()` 与 `resolve_location()` 共用。调用者不得等待锁：并发或同线程重入在 acquisition 失败时统一抛 `SCAN_CONCURRENT_USE`，不得清空、安装或改变正在进行调用及其 generation 状态。合法 scan 获锁后第一步原子清空 current mapping/handle；随后任何 catalog/root/file/tree/limit/encoding/规则错误都保持 current generation 为空。只有全部 root post-order closure 和 catalog post-check 通过后，才在持锁状态一次性提交本次 report 中 `location_ref -> canonical absolute Path` mapping 与 fresh handle，然后返回 outcome。commit 不得发生在检查之间；锁在返回/抛出前释放。

成功提交之后，scanner 持有的 current handle 必须是 `outcome.resolution_handle` 的 exact object。下一次合法 scan 获锁开始（无论其后成功或失败）即使旧 handle 不可用；empty scan 也先清空旧 generation、完整检查 catalog并提交 fresh handle + empty mapping。一个因 `SCAN_CONCURRENT_USE` 根本未获锁的调用不算 scan start，不得改变 current generation。

这些措施是 scanner 自身的基础一致性保护，不代替 P1 的授权 root、hardlink link-count 和 final-handle 保证。

### 6.7 六个 v1 rule IDs

| `rule_id` | 精确语义 |
|---|---|
| `known_canary` | 精确匹配严格 catalog 中的 marker bytes |
| `cn_mobile_number` | 中国大陆 11 位手机样式，可选 `+86`/`0086` 与空格/短横线；两端拒绝 ASCII alphanumeric |
| `cn_resident_id` | 18 位身份证样式；地址码首位非 0、年份 18/19/20xx、月日范围、尾位数字/X；v1 不要求 checksum 正确 |
| `email_address` | bounded ASCII mailbox/domain；local <=64、总长 <=254、合法 domain labels 和 ASCII token boundary |
| `stable_client_id` | ASCII case-insensitive 匹配 `client_[a-z0-9]{12}` 子串，不要求外部边界 |
| `forbidden_path_suffix` | 只匹配 path metadata/profile；`line_number=None` |

候选 bytes 模式冻结为：

```text
cn_mobile_number:
(?<![0-9A-Za-z])(?:(?:\+86|0086)[ -]?)?1[3-9][0-9](?:[ -]?[0-9]){8}(?![0-9A-Za-z])

cn_resident_id:
(?<![0-9A-Za-z])[1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx](?![0-9A-Za-z])

email_address:
(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![A-Za-z0-9.-])

stable_client_id:
(?i:client_[a-z0-9]{12})
```

Email post-validation拒绝 local 首尾点、连续点、总长 >254；regex 与 validator 必须看到 carry 后的同一完整 token。手机边界不得退化为 digit-only，否则 lock SHA 会误报。

已知 v1 边界：不覆盖港澳台/护照、15 位证件、全角/零宽变体、SMTPUTF8、图像/OCR、压缩/加密/base64 或语义重识别。不得在文档、错误或测试日志中用完整静态客户标识作为示例。

### 6.8 Profile 与禁入 suffix

suffix/basename 比较在所有平台均 ASCII case-insensitive，并只针对 final basename：

| profile | 禁止集合 |
|---|---|
| `repo_tracked` | `.sqlite3`、`.sqlite3-wal`、`.sqlite3-shm`、`.sqlite3-journal`、`.db`、`.db-wal`、`.db-shm`、`.db-journal`，以及 exact basename `identity-map.enc` |
| `shared_derivative` | `.sqlite3`、`.sqlite3-wal`、`.sqlite3-shm`、`.sqlite3-journal`、`.db`、`.db-wal`、`.db-shm`、`.db-journal`，以及 exact basename `identity-map.enc` |

两 profile 都禁主数据库及 sidecars。获准的 `global/catalog.sqlite3` 不是 shared derivative，绝不能为了扫描它而放宽 `shared_derivative`；未来如需扫描该 authority store，必须新增 exact-target、exact-identity 合同。`.npy` 不禁；`.enc`、`current.json`、`current.md`、`temporal.json` 不做宽泛禁名。Git tracked 输入固定 `repo_tracked`，共享图/索引/cache/export 固定 `shared_derivative`。

### 6.9 Canary 定义的窄豁免

豁免必须同时满足：

1. 当前扫描 pathname 与 configured definition 的 exact canonical pathname 相同；
2. 当前 handle identity、link count 和 bound catalog identity 精确相同；它不是 symlink、hardlink alias、copy 或同 basename 的其他文件；
3. 当前 rule 是 `known_canary`；
4. occurrence bytes 与已验证 catalog marker 精确相同；
5. occurrence absolute byte span 与构造时绑定的该 marker JSON string value span 精确相同。

只抑制这些 occurrence。该文件仍执行其余五个规则和路径规则；copy、同名文件、其他路径或 marker 周围的其他 PII 均报告。不得豁免整个文件、`tests/`、`docs/` 或 basename。

### 6.10 Resolver、去重、排序与报告

- occurrence 是计数单位，不是 unique value；同一行同值出现两次则 `hit_count` 增加 2；
- nested/overlapping roots 看到同一 canonical pathname/offset 时按最具体 root 只保留一次；不同 hardlink pathname 各保留；
- hits 最终按 `(location_ref, line_number or 0, rule_id, hit_hash)` 稳定排序；完全相同 occurrence entries 仍按数量保留；
- report 的公开/序列化字段只有 `location_ref`、`rule_id`、`line_number`、`hit_hash`；`hit_count` 是派生 property；
- 禁止 snippet、column/context、match length、原始 bytes、basename、相对/绝对 path、root、原始异常、客户 ID 或 key；
- 任一 scan error 使整个调用抛异常且不返回 partial outcome/report/handle。零 hit 只有在全部输入成功扫描后成立。

`resolve_location(handle, location_ref)` 必须 nonblocking 获取同一 operation lock，再按下列顺序执行并在返回/抛出前释放：要求 `type(handle) is ScanResolutionHandle`、`handle is scanner 当前 handle`、`location_ref` 是当前 mapping 的 exact key；仅三项全部成立才返回对应 canonical `Path`。value-equal、deepcopy、伪造、旧 generation、另一个 scanner instance（即使 key/root/report 完全相同）及 unknown ref 全部统一 `SCAN_LOCATION_UNAVAILABLE`，错误不得揭示失败的是哪一项。scan/resolve 并发或重入则只返回 `SCAN_CONCURRENT_USE`，不得改变 current generation。

mapping 只含有当前 report 中有 hit 的 refs，不能迭代、dump、copy、repr、log、pickle 或进入 report/audit。`repr(scanner)` 精确为 `<PrivacyScanner redacted>`，pickle/copy/deepcopy 固定 `TypeError("SCAN_SERIALIZATION_FORBIDDEN")`；不得暴露 key、catalog binding、owner identity、generation token 或 mapping。scanner 可在受信进程内显式 `close()`，其唯一效果是在获取 operation lock 后清空 current handle/mapping；`close()` 同样 nonblocking/non-reentrant，争用时报 `SCAN_CONCURRENT_USE`。

### 6.11 确定性与已知边界

相同文件 snapshot、相同显式 canonical root set、profile、limits 和 exact key 必须产生 exact-equal `PrivacyScanReport`：ordered `hits` tuple 长度、顺序及每个 hit 的四个字段值完全相等；输入排列和 OS 枚举顺序不得影响。没有 canonical report/config bytes，outcome 与 handle 不参加比较；两个相同顺序 scan 可返回 value-equal report，但 handle 必须是不同 object，旧 handle 不得解析当前 mapping。默认 ephemeral key 使跨 scanner 实例 report 不稳定是预期，不能用于持久 ID、跨运行关联或审计 join。

位置 HMAC 隐藏 raw path 但不是授权：只有本地受信 caller 才能调用临时 resolver。scanner clean 也不代表姓名、语义组合或共享授权安全；P7 deidentifier + 人工复核边界不变。

## 7. 跟踪 synthetic bytes 的机械分片裁决

### 7.1 唯一豁免与目标状态

唯一允许在 tracked bytes 中保存两个完整 canary marker 的文件是 exact `tests/fixtures/consultation_kb/canaries.json`。其他代码、测试和文档只可用明显分片在 runtime/展示时组合，例如 canary 采用 `SYNTH-CANARY-`、family fragment、tail fragment 三段，客户标识采用 prefix 与多个 suffix fragment 分开。

Task 4 实现完成后的 Git bytes gate：

- 两个完整 catalog marker 只命中 exact canary definition；
- `client_` 加 12 个小写字母数字的完整静态序列在 tracked bytes 中零命中；
- runtime 组合后的测试值、断言语义和 Task 3 Schema bytes 不变；
- 不建立 expected-hit ledger，不按目录豁免。

### 7.2 允许的机械修改

在本规范基线的 live grep 下，以下文件允许仅为消除完整静态 bytes 做机械分片：

- `docs/superpowers/plans/2026-07-16-consultation-kb-p0-contracts-test-foundation.md`：只分片 marker 展示/示例，不改变计划语义、步骤或 checkbox；
- `tests/consultation_kb/unit/test_repository_contract.py`：runtime 组合两个 marker；
- `tests/consultation_kb/unit/test_core_contracts.py`：runtime 组合 synthetic client values；
- `tests/consultation_kb/unit/test_schema_exports.py`：runtime 组合 synthetic client values。

任何其他命中必须先做新的精确审查，不得扩大 allowlist。`canaries.json` 保持定义内容不变。

## 8. 生产级严格 Policy Loader

### 8.1 模块与 API

Task 4 增加 `consultation_kb/policy/loader.py`，不是 test helper。公共面冻结为：

```python
PolicyId = Literal["evidence_levels", "relation_types", "retention", "risk_rules"]
PolicyFilename = Literal[
    "evidence-levels.yaml",
    "relation-types.yaml",
    "retention.yaml",
    "risk-rules.yaml",
]

class PolicyLoadError(ValueError):
    code: str
    policy_id: PolicyId | None

T = TypeVar("T")

@dataclass(frozen=True, slots=True, repr=False)
class PolicyAuditMetadata:
    filename: PolicyFilename
    policy_id: PolicyId
    policy_version: Literal[1]
    raw_bytes_sha256: str
    content_sha256: str

@dataclass(frozen=True, slots=True, repr=False)
class LoadedPolicy(Generic[T]):
    filename: PolicyFilename
    schema_version: Literal["1.0"]
    policy_id: PolicyId
    policy_version: Literal[1]
    raw_bytes_sha256: str
    canonical_bytes: bytes
    content_sha256: str
    document: T

    def audit_metadata(self) -> PolicyAuditMetadata: ...

@dataclass(frozen=True, slots=True, repr=False)
class PolicyBundle:
    evidence_levels: LoadedPolicy[EvidenceLevelsPolicy]
    relation_types: LoadedPolicy[RelationTypesPolicy]
    retention: LoadedPolicy[RetentionPolicy]
    risk_rules: LoadedPolicy[RiskRulesPolicy]

class PolicyLoader:
    @classmethod
    def from_config(cls, config: AppConfig) -> PolicyLoader: ...

    def load_all(self) -> PolicyBundle: ...
```

`LoadedPolicy` 的公共 dataclass fields 必须精确为上述八项、精确同序；`audit_metadata()` 是 method，不是第九个 field。不得增加 path、mtime、raw YAML text、mutable parse tree、loader 或 cache 引用。`PolicyAuditMetadata` fields 精确为上述五项、同序；它是唯一允许 Task 5 记录的成功视图。上述签名本身使用 Python 3.10 可解析的 `TypeVar`/`Generic` 写法。

`LoadedPolicy`、`PolicyBundle`、`PolicyAuditMetadata`、四类 document、nested `RiskRulePolicy` 及第 8.9 节的 member identity 都必须 `repr=False` 并实现精确 fixed repr `<ClassName redacted>`。这些成功对象的 pickle/copy/deepcopy 必须以 `TypeError("POLICY_SERIALIZATION_FORBIDDEN")` 拒绝；hash/canonical bytes/document/pattern/question 不得借默认 dataclass repr、exception context 或 logger argument 泄露。`PolicyLoader` 自身 repr 精确为 `<PolicyLoader redacted>`，同样拒绝 pickle/copy/deepcopy且不得暴露 repo/policy root。loader 和 Task 5 均禁止对任何 policy success artifact 使用 `dataclasses.asdict()`、`dataclasses.astuple()`、pickle 或通用 JSON serializer 做日志；Task 5 也不得读取/记录 `LoadedPolicy.document` 或 `canonical_bytes`，只能逐字段消费 `audit_metadata()` 返回值。

loader 只从 `type(config) is AppConfig` 的已验证对象取得 `config.repo_root / "policies"`，不得用 `isinstance` 接受 subclass；其他类型统一 `POLICY_VALIDATED_CONFIG_REQUIRED`。它不接受 cwd、任意 policy directory、裸 repo `Path`、caller-supplied filename/policy ID 或 `importlib.resources` fallback。裸 Path 构造必须拒绝，避免绕过 repo root 合同。四个 ID 与文件名的唯一固定映射为：

| `policy_id` | `filename` |
|---|---|
| `evidence_levels` | `evidence-levels.yaml` |
| `relation_types` | `relation-types.yaml` |
| `retention` | `retention.yaml` |
| `risk_rules` | `risk-rules.yaml` |

`PolicyLoader.from_config()` 零 I/O；`load_all()` 一次性读取并验证整个 bundle。任何一份失败则无 bundle、无 cache 更新、无 partial policy 返回。

### 8.2 文件、YAML 与资源上限

`policies/` 必须存在、位于 repo 直接子目录、非 symlink/junction/reparse。目录内容必须恰好是四个 regular files：

```text
evidence-levels.yaml
relation-types.yaml
retention.yaml
risk-rules.yaml
```

missing、extra entry、subdirectory、hardlink (`link count != 1`)、link/reparse、无法取得可靠 link count 或读取竞态均 fail closed。每份文件最多 65,536 bytes，bundle 最多 262,144 bytes；YAML node 最多 4,096、嵌套深度最多 16、单 scalar 最多 4,096 Unicode code points。上限不可由 env、YAML 或 metadata 调整。

raw bytes gate 在任何 YAML scanner/parser 之前运行。raw bytes 必须为 UTF-8 无 BOM、无 NUL、只用 LF、恰好一个末尾 `\n`；空文档、CRLF、末尾多个空行均拒绝。此外：

- raw bytes 任意位置出现 `#` (`0x23`) 或 TAB (`0x09`) 都拒绝，因此 v1 不允许 YAML comment；
- 按 LF 分行后，任一行匹配 `^[ ]*(?:%|---(?:[ ]|$)|\.\.\.(?:[ ]|$))` 都拒绝，覆盖 directive、document start/end marker；
- 这些是 byte gate，不因引号、YAML scalar context 或 parser 的解释而豁免。

加载顺序必须为：

1. raw format/size 检查；
2. PyYAML token/node guard 拒绝 anchor、alias、merge key、显式 tag、自定义 tag 和多文档；
3. duplicate-key rejecting `SafeLoader`；禁止 `FullLoader`、`UnsafeLoader` 或普通会静默覆盖键的 `safe_load`；
4. 对构造结果递归按 `type(value) is ...` 检查，只允许 `dict`、`list`、`str`、`int`；`bool`、`None`/null、`float`、timestamp/date、bytes、set、tuple 及任何用户对象均非法，`bool` 不得借其 `int` 子类关系通过；mapping key 必须是 `str`；
5. exact key、key order、array uniqueness/order、值域与跨模型 parity；
6. 打开前 `lstat`、打开后 `fstat`、读取后 `fstat` 及目录结束复核必须保持同一 file identity/link count/size/mtime；变化即拒绝；
7. 生成 deep-immutable tuple/frozen-slots-dataclass document、canonical bytes 与 hashes。

异常只含安全 error code 和固定 policy ID，不含路径、filename、YAML snippet、parser context、line content、raw/canonical hash 或原始 PyYAML/OSError message。固定 filename 只存在于成功的 `LoadedPolicy.filename`，不得成为任意资源探测接口。

### 8.3 公共 envelope

四份 YAML 都以以下三键开头，且顺序固定：

```yaml
schema_version: "1.0"
policy_id: <exact SafePolicyKey>
policy_version: 1
```

`schema_version` 必须 `type is str` 且精确等于 `"1.0"`；`policy_version` 必须 `type is int` 且精确等于 `1`，不得接受其他正整数。top-level 和 nested mapping 均按本规范给出的 exact keys、exact order；array 去重且顺序为本规范冻结顺序。所有 risk rule member 的 `version` 同样必须精确为 int `1`。

`policy_id`、全部 retention category、risk 的 `rule_id/category/required_context` 使用 Task 3 `TypeAdapter(SafePolicyKey)`；每个 evidence value 使用 `TypeAdapter(SourceGrade)`/`TypeAdapter(EmpiricalSupport)`，随后再用 `typing.get_args()` 做整 tuple 精确比较。loader 不复制近似 regex，不能只比较 set。

成功构造后的 `document` 类型冻结为以下 deep-immutable shape；所有 mapping 都已消失，所有 YAML list 都变成 tuple，嵌套对象全部是 frozen/slots/repr-redacted dataclass。调用方不得取得 parser tree 的引用：

```python
@dataclass(frozen=True, slots=True, repr=False)
class EvidenceLevelsPolicy:
    schema_version: Literal["1.0"]
    policy_id: Literal["evidence_levels"]
    policy_version: Literal[1]
    source_grades: tuple[SourceGrade, ...]
    empirical_support: tuple[EmpiricalSupport, ...]

@dataclass(frozen=True, slots=True, repr=False)
class RelationTypesPolicy:
    schema_version: Literal["1.0"]
    policy_id: Literal["relation_types"]
    policy_version: Literal[1]
    global_relation_types: tuple[str, ...]

@dataclass(frozen=True, slots=True, repr=False)
class RetentionPolicy:
    schema_version: Literal["1.0"]
    policy_id: Literal["retention"]
    policy_version: Literal[1]
    retention_categories: tuple[SafePolicyKey, ...]

@dataclass(frozen=True, slots=True, repr=False)
class RiskRulePolicy:
    rule_id: SafePolicyKey
    version: Literal[1]
    category: SafePolicyKey
    level: Literal["general", "high"]
    pattern_type: Literal["literal"]
    pattern: str
    negation_window_tokens: Literal[0]
    required_context: tuple[SafePolicyKey, ...]
    suggested_questions: tuple[str, ...]

@dataclass(frozen=True, slots=True, repr=False)
class RiskRulesPolicy:
    schema_version: Literal["1.0"]
    policy_id: Literal["risk_rules"]
    policy_version: Literal[1]
    rules: tuple[RiskRulePolicy, ...]
```

这些 annotations 不放宽下面的 exact-value contract；尤其 `str`/tuple 类型正确但值或顺序漂移仍须拒绝。`LoadedPolicy.document`、`canonical_bytes` 和所有 tuple 必须可安全共享但不可原地修改；policy loader、Task 5 和生产 logging/audit code 不得调用 `dataclasses.asdict()`/`astuple()`，也不得记录 document/canonical bytes。允许后续 owner 在明确受限、非日志的 materialization 代码中逐字段读取 typed object，但不得把通用 serializer 当身份公式。

### 8.4 `evidence-levels.yaml`

```yaml
schema_version: "1.0"
policy_id: evidence_levels
policy_version: 1
source_grades:
  - T1
  - T2
  - T3
  - T4
  - C1
  - C2
  - C3
  - C4
  - C5
  - C6
  - K1
  - K2
  - K3
  - K4
  - L1
  - L2
  - L3
  - L4
empirical_support:
  - unassessed
  - case_supported
  - observation_supported
  - empirically_supported
  - guideline_consistent
  - conflicting
```

top-level key order如上；18/6 tuples 必须与 `SourceGrade`/`EmpiricalSupport` 完全同序同值。

### 8.5 `relation-types.yaml`

```yaml
schema_version: "1.0"
policy_id: relation_types
policy_version: 1
global_relation_types:
  - CITES
  - SUPPORTS
  - CONTRADICTS
  - INTERPRETS
  - DERIVED_FROM
  - APPLIES_TO
  - NOT_APPLICABLE_TO
  - ANALOGOUS_TO
  - DISTINCT_FROM
  - CONTRAINDICATED_FOR
  - REQUIRES_REFERRAL
  - EXEMPLIFIED_BY
  - SUPERSEDES
```

共 13 个，顺序与上位设计 7.3 完全一致。关系 policy 中只有 `SUPERSEDES`，没有 `REVOKES`。P3 的 revoke 是 governance/tombstone intent 与 revision lifecycle，不是知识图 relation；不得把它补进此 YAML，也不得在 P3 另建顺序不同的关系常量。

### 8.6 `retention.yaml`

```yaml
schema_version: "1.0"
policy_id: retention
policy_version: 1
retention_categories:
  - identity_mapping
  - source_record
  - private_session_record
  - approved_fact_governance
  - approved_shared_case
  - rebuildable_derivative
  - temporary_staging
  - minimal_noncontent_audit
```

| 类别 | v1 语义 |
|---|---|
| `identity_mapping` | 独立敏感身份映射；日常检索不读，客户删除/映射撤销单独清理 |
| `source_record` | 原始来源与版本的权威记录；版本化、不静默覆盖，合法删除先 tombstone |
| `private_session_record` | 客户私有实际会谈；绝不共享，按客户和用途清理 |
| `approved_fact_governance` | 获准事实事件及 review/approval/correction/delete 决定；保留历史但服从删除 |
| `approved_shared_case` | 仅复用授权和脱敏批准后存在；授权撤回先 tombstone |
| `rebuildable_derivative` | Wiki render、图、索引、profile view、cache/evaluation derivative；由权威源重建 |
| `temporary_staging` | DRAFT/PREPARED/staging；不可查询，按恢复/过期策略清理 |
| `minimal_noncontent_audit` | 只含 ID/category/time/result hash 的最小无正文证明 |

backup 继承被备份对象类别；model cache 属于 derivative。具体天数、法律保留期和物理清理算法不在 P0 硬编码，由后续 versioned policy 扩展。

retention category **只做生命周期分类**。它不是 authorization、capability、reuse/share consent、legal hold、保存许可、访问许可，也不得成为拒绝删除、延迟 tombstone、恢复已撤回权限或扩大原始处理 scope 的依据。权限收紧、授权撤回、删除 intent 与 tombstone 一律优先于普通 retention schedule；类别名称本身不能推导“可继续保存/共享”。任何确需覆盖普通清理的例外必须来自独立、显式、版本化、可撤回且可审计的 authorization/legal-hold policy ref，并在 P8 设计中冻结权限主体、对象范围、起止/撤回与 tombstone 交互；不得修改本 YAML 或把 category 当例外开关。

### 8.7 `risk-rules.yaml`

```yaml
schema_version: "1.0"
policy_id: risk_rules
policy_version: 1
rules:
  - rule_id: synthetic_general_observation
    version: 1
    category: synthetic_general_observation
    level: general
    pattern_type: literal
    pattern: SYNTH-RISK-GENERAL-4C2E
    negation_window_tokens: 0
    required_context:
      - synthetic_context_present
    suggested_questions:
      - SYNTH-QUESTION-GENERAL-VERIFY
  - rule_id: synthetic_high_observation
    version: 1
    category: synthetic_high_observation
    level: high
    pattern_type: literal
    pattern: SYNTH-RISK-HIGH-7D1A
    negation_window_tokens: 0
    required_context:
      - synthetic_context_present
    suggested_questions:
      - SYNTH-QUESTION-HIGH-VERIFY
```

`rules` 必须精确有两项；每项的九个字段、字段顺序、字符串、tuple 值及 tuple 顺序全部精确等于上例，不接受“同类”替换、大小写变化、额外 context/question 或新增字段。第一项只允许：

```text
synthetic_general_observation | 1 | synthetic_general_observation | general |
literal | SYNTH-RISK-GENERAL-4C2E | 0 |
(synthetic_context_present,) | (SYNTH-QUESTION-GENERAL-VERIFY,)
```

第二项只允许：

```text
synthetic_high_observation | 1 | synthetic_high_observation | high |
literal | SYNTH-RISK-HIGH-7D1A | 0 |
(synthetic_context_present,) | (SYNTH-QUESTION-HIGH-VERIFY,)
```

因此两个 `version` 都是 exact int `1`、两个 `negation_window_tokens` 都是 exact int `0`、`pattern_type` 都是 exact `literal`。文件不得含真实会谈文本、第一人称危险陈述、手机号、身份证、email、稳定客户标识或路径。

这两条只是验证 loader、versioning 和 P6 接线的 synthetic contract sentinel；它们不代表真实风险词表、临床安全覆盖、一般/高风险召回率或可部署的风险检测能力。Task 4 加载 policy 并提供第 8.9 节 deterministic member identity helper；P6 才按该 identity 一次审批并持久化 whole/member `VersionRef`、ObjectId、manifest，再实现 engine/lifecycle。

P6 必须保持 projector boundary：`rule_id`、`category`、`level`、`pattern_type`、`pattern`、匹配位置、触发原文/quote、required context、synthetic suggested-question key 及整个 `LoadedPolicy`/internal observation 都不得进入 reply generator prompt、tool input 或用户输出。只有独立 deterministic projector 选择的 allowlisted natural-language question goals 可以传给 reply generator；projector mapping 与输出 allowlist 属于 P6 versioned policy/测试，不得把本 YAML 的 synthetic string 当作可直接呈现文案。

### 8.8 Hash 与 checkout/editable 资源合同

对每份完成 raw、YAML、shape、exact-value 和 model-parity 验证的 policy，先构造 plain semantic document：只包含该 YAML 的规范键和值，tuple 转 JSON array，nested frozen dataclass 转 JSON object；不含 `filename`、任何 hash、path、mtime 或 loader metadata。canonical bytes 精确为：

```python
json.dumps(
    plain_semantic_document,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

不得用 `default=str`、locale、pretty printing、末尾 newline 或平台换行。随后填充：

- `raw_bytes_sha256 = hashlib.sha256(exact_validated_raw_bytes).hexdigest()`；
- `canonical_bytes =` 上式返回的 exact immutable `bytes`；
- `content_sha256 = hashlib.sha256(canonical_bytes).hexdigest()`。

三个值分别表示 source bytes、canonical content bytes、canonical content digest，命名和比较不得互换。hash 不含路径、cwd、mtime 或 file identity，也不是资源授权、版本接受或语义验证的替代品；必须先完成全部 exact validation 才能公开。loader 不接收 expected hash，因此不存在 caller-controlled hash bypass；canonicalization/hash 异常只返回固定 code，不回显 bytes/hash。Task 5 doctor 只能调用每个 artifact 的 `audit_metadata()`，并逐字段记录该窄视图；不得记录/传递 document、canonical bytes、pattern、question、parser tree 或通用 serialization。Task 4 不创建 immutable manifest 或 `VersionRef`，`canonical_bytes` 也不得写入 repo/cache。

支持形态精确为：调用方显式提供 checkout `repo_root`，代码可来自该 checkout 或 editable install。loader 不从 cwd 猜测、不复制 YAML 到 package 内、不形成双真相源，也不枚举任意资源名。普通 wheel 缺顶层 `policies/` 时明确 `POLICY_DIRECTORY_MISSING`；不得尝试 package resource、网络、相邻 cwd 或用户目录 fallback。完整 wheel resource/package-data 与安装态测试属于 P9。

### 8.9 Risk rule member identity 与 P6 materialization

Task 4 在 production `consultation_kb/policy/loader.py` 冻结并实现以下 helper/type；P6 必须直接复用，不得另写 canonicalizer：

```python
@dataclass(frozen=True, slots=True, repr=False)
class RiskRuleMemberIdentity:
    owner_schema_version: Literal["1.0"]
    owner_policy_id: Literal["risk_rules"]
    owner_policy_version: Literal[1]
    owner_content_sha256: str
    member_kind: Literal["risk_rule"]
    member_ordinal: int
    rule_id: SafePolicyKey
    version: Literal[1]
    canonical_bytes: bytes
    content_sha256: str

def risk_rule_member_identities(
    loaded: LoadedPolicy[RiskRulesPolicy],
) -> tuple[RiskRuleMemberIdentity, ...]: ...
```

helper 只接受 exact `LoadedPolicy[RiskRulesPolicy]` 的已验证 runtime shape；它必须按第 8.8 节从 `loaded.document` 重新构造 whole canonical bytes，并同时验证 `loaded.canonical_bytes`、`sha256(canonical_bytes)`、`loaded.content_sha256` 及各 owner envelope field 一致。错误 owner ID/version/document type、hash 格式或值、tuple/rule drift 统一 `POLICY_MEMBER_IDENTITY_INVALID`，不接受裸 `RiskRulePolicy` 或 caller-supplied owner hash。ordinal 是 `rules` tuple 的 zero-based array ordinal，当前固定为 `0, 1`。每项先构造以下 plain canonical envelope；`member` 必须包含对应 rule 的完整九字段，tuple 转 JSON array：

```json
{
  "owner": {
    "schema_version": "1.0",
    "policy_id": "risk_rules",
    "policy_version": 1,
    "content_sha256": "<loaded whole-policy content_sha256>"
  },
  "member_kind": "risk_rule",
  "member_ordinal": 0,
  "member": {
    "rule_id": "<exact member rule_id>",
    "version": 1,
    "category": "<exact member category>",
    "level": "<exact member level>",
    "pattern_type": "literal",
    "pattern": "<exact member pattern>",
    "negation_window_tokens": 0,
    "required_context": ["<exact values>"],
    "suggested_questions": ["<exact values>"]
  }
}
```

member canonical bytes 使用第 8.8 节完全相同的 `json.dumps(... ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")` 参数，无 newline/default/locale；member `content_sha256 = sha256(member canonical_bytes).hexdigest()`。owner whole-policy content hash 进入 envelope，因此相同 rule text 位于不同 owner policy version/content/ordinal 时 identity 必须不同。

当前 canonical fixture 的 known vectors 冻结为：whole risk policy `content_sha256` 是 `904ba9969635d246491a96a3821d38745037550033b715fe0e19edc66a779c94`；ordinal `0` member hash 是 `c8fbe22922807a3c2fbc5c12197412ccf149725ba6ea0c2453c3b1705f10ba80`；ordinal `1` member hash 是 `2aad1e438d31f50135ddebc461b8b9e34ab7eccbe91dca7deb5fa99dd50349e0`。Task 4 tests 必须从实际 production loader artifact 调用 helper 并对这三个 literal known vectors 断言，不能在测试中复制另一 canonicalizer 来生成 expected value。

P6 的审批/materialization 必须一次生成并持久化 whole policy `risk_policy_<uuid7>` ObjectId 与每个 member `risk_rule_<uuid7>` ObjectId；不得在 load、process restart、engine run 或 observation creation 时重新生成。whole policy `VersionRef.version = loaded.policy_version`、`content_sha256 = loaded.content_sha256`；member `VersionRef.version = identity.version`、`content_sha256 = identity.content_sha256`。immutable manifest 必须绑定 whole owner policy ref，以及每个 member 的 owner ref、zero-based ordinal、rule_id、object_id、version、member content hash；lookup 必须按 exact immutable ref，禁止 ID-to-latest 或用新 policy 重新解释旧 observation。P6 首次实现前必须独立审查该 manifest/approval lifecycle；Task 4 只提供 deterministic identities，不创建 ObjectId/VersionRef/manifest。

### 8.10 版本演进、迁移与 bundle 边界

v1 loader 只认本文件四个 exact filename 的 exact schema `"1.0"`/policy version `1`；unknown/future schema、policy 或 member version 全部 `POLICY_VERSION_UNSUPPORTED`，不得 auto-migrate、猜测 latest、fallback 到其他文件/资源或把旧 ref 按当前 YAML 重解释。

- 任一既有 semantic value 或 array order 变化必须 bump `policy_version`；
- envelope/shape/key/type/canonicalization contract 变化必须 bump `schema_version`，同时由 owner 明确其 policy version 规则；
- 后续 P3（evidence/relation）、P6（risk）、P8（retention）各自必须先设计并独立审查 version dispatcher、immutable history/manifest resolution 和 old-ref compatibility，再让 production 接受新版本；P9 只负责相应资源交付，不得静默改变版本解释；
- live auto-migration、mutable latest pointer fallback、in-place overwrite 和旧 object/member ID 指向新 content 全部禁止。

Task 4 不定义 migration，也**不定义或承诺 PolicyBundle digest**。四个 artifact field order 不是 bundle identity 公式；后续若确需 bundle-level ref，必须另行冻结以固定 filename/order/content_sha256 array 为输入的 canonical JSON 公式、known vectors、version 与 owner，不能临时拼接 digest。

## 9. 错误代码与失败语义

### 9.1 Config/Layout codes

| code | 条件 |
|---|---|
| `CONFIG_PATH_TYPE` | path 不是 string PathLike |
| `CONFIG_PATH_EMPTY` | 空白 path |
| `CONFIG_PATH_NUL_OR_CONTROL` | NUL/control |
| `CONFIG_PATH_NOT_ABSOLUTE` | resolve 前不是 absolute |
| `CONFIG_PATH_TRAVERSAL` | raw `.`/`..` 段 |
| `CONFIG_PATH_NAMESPACE_UNSUPPORTED` | UNC/extended UNC/volume-GUID/device/NT/drive-relative namespace |
| `CONFIG_PATH_DRIVE_UNSUPPORTED` | Windows mapped remote、unknown/no-root drive 或 drive query 失败 |
| `CONFIG_PATH_COMPONENT_UNSUPPORTED` | ADS colon、wildcard、reserved DOS name、尾点/尾空格 |
| `CONFIG_PATH_ALIAS_UNSUPPORTED` | 8.3 或未批准 root alias |
| `CONFIG_PATH_REPARSE` | existing/broken symlink、junction、reparse |
| `CONFIG_PATH_INSPECTION_FAILED` | 不能安全判断组件 |
| `CONFIG_REPO_INVALID` | repo 不存在/非目录 |
| `CONFIG_REPO_MARKER_INVALID` | `.git` 非 file/dir 或不安全 |
| `CONFIG_VAULT_INVALID` | existing vault 非目录 |
| `CONFIG_ROOTS_OVERLAP` | same/任一方向 containment |
| `CONFIG_VAULT_ROOT_MISSING` | 无显式/env vault |
| `CONFIG_VAULT_SOURCE_CONFLICT` | 显式/env canonical 不同 |
| `CONFIG_ENV_INVALID` | key/value type、duplicate、blank |
| `CONFIG_ENV_UNKNOWN` | 未知 `CONSULTATION_*` |
| `CONFIG_ENV_RESERVED` | test/future reserved env |
| `CONFIG_SCOPE_LOCKED` | 四个 scope 的值或 type 不精确 |
| `CONFIG_SUBCLASS_FORBIDDEN` | runtime subclass 创建；固定 `TypeError`，不是可扩展点 |
| `VAULT_VALIDATED_CONFIG_REQUIRED` | layout 未从 exact AppConfig 构造 |

### 9.2 Scanner codes

`SCAN_INPUT_INVALID`、`SCAN_PROFILE_INVALID`、`SCAN_PATH_NOT_ABSOLUTE`、`SCAN_PATH_NOT_FOUND`、`SCAN_PATH_NAMESPACE_UNSUPPORTED`、`SCAN_PATH_UNSUPPORTED`、`SCAN_LINK_OR_REPARSE`、`SCAN_ROOT_ESCAPE`、`SCAN_UNREADABLE`、`SCAN_UNSUPPORTED_ENCODING`、`SCAN_FILE_CHANGED`、`SCAN_TREE_CHANGED`、`SCAN_CANARY_CATALOG_INVALID`、`SCAN_CATALOG_CHANGED`、`SCAN_KEY_INVALID`、`SCAN_LOCATION_UNAVAILABLE`、`SCAN_CONCURRENT_USE`、`SCAN_LIMIT_CONFIGURATION_INVALID`、`SCAN_LIMIT_INPUT_PATHS`、`SCAN_LIMIT_ROOTS`、`SCAN_LIMIT_TREE_ENTRIES`、`SCAN_LIMIT_FILES`、`SCAN_LIMIT_DEPTH`、`SCAN_LIMIT_NATIVE_RELATIVE_BYTES`、`SCAN_LIMIT_FILE_BYTES`、`SCAN_LIMIT_TOTAL_BYTES`、`SCAN_LIMIT_HITS`、`SCAN_LIMIT_CATALOG_BYTES`、`SCAN_LIMIT_MARKERS`、`SCAN_LIMIT_MARKER_BYTES`。

limits 类型/非正值/超过 hard max 在 scanner 构造时统一 `SCAN_LIMIT_CONFIGURATION_INVALID`；运行时是哪一项耗尽就使用对应 `SCAN_LIMIT_*`。catalog 超过 byte/marker/marker-byte 上限使用对应 limit code；其 schema/duplicate/escape/identity 不合法使用 catalog code。失败不得返回已累积 hits。

### 9.3 Policy codes

`POLICY_VALIDATED_CONFIG_REQUIRED`、`POLICY_DIRECTORY_MISSING`、`POLICY_DIRECTORY_UNSAFE`、`POLICY_FILE_SET_MISMATCH`、`POLICY_FILE_UNSAFE`、`POLICY_SIZE_LIMIT`、`POLICY_STRUCTURE_LIMIT`、`POLICY_ENCODING_INVALID`、`POLICY_RAW_FORMAT_INVALID`、`POLICY_YAML_FORBIDDEN_FEATURE`、`POLICY_YAML_DUPLICATE_KEY`、`POLICY_YAML_PARSE_FAILED`、`POLICY_YAML_TYPE_INVALID`、`POLICY_SCHEMA_INVALID`、`POLICY_VERSION_UNSUPPORTED`、`POLICY_SEMANTICS_INVALID`、`POLICY_MODEL_PARITY_FAILED`、`POLICY_CANONICALIZATION_FAILED`、`POLICY_MEMBER_IDENTITY_INVALID`、`POLICY_CHANGED_DURING_READ`。

Config/layout 异常公开字符串固定为 `<CODE>` 或 `<CODE>:<fixed field>`；`CONFIG_ENV_UNKNOWN` 只能是裸 code，尤其不得含原始/规范化 unknown key；runtime subclass 创建固定抛 `TypeError("CONFIG_SUBCLASS_FORBIDDEN")`。Scanner 异常公开字符串固定为 `<CODE>`，可用的 opaque `location_ref` 只放在结构化属性而不拼入 message。Policy 异常为 `<CODE>` 或 `<CODE>:<fixed PolicyId>`，不得含 filename/hash。policy identity helper 对伪造/错误 typed artifact 使用 `POLICY_MEMBER_IDENTITY_INVALID`，不回显 member。禁止 pickle/copy/deepcopy 是固定 `TypeError("VAULT_SERIALIZATION_FORBIDDEN")`、`TypeError("SCAN_SERIALIZATION_FORBIDDEN")` 或 `TypeError("POLICY_SERIALIZATION_FORBIDDEN")`，不包装原始 serializer 异常。所有层都不得包含 path value、env value、matched text、YAML scalar、OSError/PyYAML 原文、对象存在性、原始 key 或 normalized key。Config/layout/scanner/loader 均不得在失败时创建、修改或删除任何文件。

## 10. RED-first 测试与验收矩阵

### 10.1 Config / path

| ID | 输入/故障 | 必须结果 |
|---|---|---|
| CFG-01 | local sibling repo/vault | canonical success；零创建 |
| CFG-02 | vault inside repo、same、repo inside vault | `CONFIG_ROOTS_OVERLAP` |
| CFG-03 | relative、drive-relative、raw `.`/`..` | 对应 absolute/traversal error |
| CFG-04 | repo `.git` file 与 directory | 两者接受；missing/special/reparse 拒绝 |
| CFG-05 | vault 不存在 sibling | 接受但不创建；不存在 tail 指回 repo 拒绝 |
| CFG-06 | existing vault regular/special file | `CONFIG_VAULT_INVALID` |
| CFG-07 | 两个 local drives | 视为 disjoint，不泄露 `commonpath` ValueError |
| CFG-08 | UNC、extended UNC、volume-GUID、device/NT namespace | `CONFIG_PATH_NAMESPACE_UNSUPPORTED` |
| CFG-09 | injected Windows drive type remote/unknown/no-root/query failure | `CONFIG_PATH_DRIVE_UNSUPPORTED`；不尝试 resolve |
| CFG-10 | ADS、wildcard、reserved DOS component、尾点/尾空格 | `CONFIG_PATH_COMPONENT_UNSUPPORTED` |
| CFG-11 | 8.3 alias pattern（存在/不存在、不同 case） | `CONFIG_PATH_ALIAS_UNSUPPORTED` |
| CFG-12 | 大小写/分隔符/尾斜杠别名 | identity-equal，不绕过 overlap |
| CFG-13 | symlink、broken symlink、junction、injected reparse：repo/vault alias 到 repo/sibling | `lexists/lstat` fail closed |
| CFG-14 | explicit/env canonical same、conflict、missing、blank | same 接受；其余精确失败 |
| CFG-15 | unknown/reserved env 大小写变体、规范化重复 | fail closed；message/log 均不回显 raw/normalized key 或 value |
| CFG-16 | `load()` 中 `CONSULTATION_PYTHON` nonblank | 被识别但完全 inert；六个 AppConfig fields/value exact-equal 于无该键时结果 |
| CFG-17 | scope 显式非法值与 bool/int/string coercion | `CONFIG_SCOPE_LOCKED` |
| CFG-18 | direct constructor、from_values、load、dataclasses.replace | type/path/canonical/disjoint/scope 结果相同；direct/from_values 不读 ambient env，`load()` 独占 env allowlist |
| CFG-19 | repr/error/log capture | 不含任何 absolute root/env key/value |
| CFG-20 | import root/core、`doctor --help` | 不 import config/YAML/Pydantic/vault/evaluation/policy，不创建路径 |
| CFG-21 | POSIX ordinary absolute local candidate | 仅执行语法/component/identity 合同；测试与文档不宣称识别 network mount |
| CFG-22 | production CLI/doctor/runtime AST/callsite 架构检查 | 所有 AppConfig production acquisition 只调用 `load()`；direct/from_values 只见于 config 内部或测试 fixture |
| CFG-23 | 相同 explicit values、不同 ambient `CONSULTATION_*` | direct/from_values exact field/value equality 不变；`load()` 对 unknown/reserved 精确拒绝 |
| CFG-24 | class statement/`types.new_class` 以 no-op `__post_init__` subclass AppConfig | 类创建固定 `TypeError("CONFIG_SUBCLASS_FORBIDDEN")`；`typing.final` 不是唯一 gate |
| CFG-25 | test-only 临时绕过 seal 造出的 unchecked subtype 传 layout/loader | 两个 consumer 都以 `type(config) is AppConfig` 拒绝并返回各自 validated-config error；不得按 `isinstance` 接受 |

Windows junction live test 在具备权限时运行；无权限时必须有 injected path-inspector deterministic test，不能把 WinError 1314 当覆盖完成。

### 10.2 VaultLayout

| ID | 输入/故障 | 必须结果 |
|---|---|---|
| LAYOUT-01 | valid AppConfig | 18 属性逐项 exact table、全 absolute |
| LAYOUT-02 | bare Path/string/duck object/AppConfig subtype | `VAULT_VALIDATED_CONFIG_REQUIRED`；只接受 exact type |
| LAYOUT-03 | frozen mutation/repeated construction | mutation 拒绝，结果 deterministic |
| LAYOUT-04 | I/O spies | constructor/property 零 I/O、零 stat/mkdir |
| LAYOUT-05 | API reflection | public `root`/`vault_root`/`objects_root` 与任意 path/client/session API 全部不存在；只见 18 properties |
| LAYOUT-06 | repr/log/dataclass/serializer inspection | `is_dataclass=False`、repr exact redacted；`asdict`/`astuple`/`vars` TypeError 且无 root；无 public serializer |
| LAYOUT-07 | canonical same/different root equality | same canonical vault root equality/hash 相同；不同 root 不等；比较过程不公开 root |

“worker 不得接 `VaultLayout`/global roots”没有 Task 4 worker 可供 RED；它保留为第 12 节 P1 downstream acceptance，在 P1 worker 存在后由其 dependency/constructor test 验收，不得伪造空壳 worker 只为满足 Task 4。

### 10.3 PrivacyScanner

| ID | 输入/故障 | 必须结果 |
|---|---|---|
| SCAN-01 | file/recursive directory 的分片组合 canary | exact occurrence 与正确行号 |
| SCAN-02 | duplicate JSON key、escaped marker、marker substring/duplicate、catalog hardlink | 构造失败；要求 strict JSON、raw span、`nlink == 1` |
| SCAN-03 | catalog 在构造后或扫描中 identity/nlink/size/mtime_ns/ctime_ns/raw hash 变化 | `SCAN_CATALOG_CHANGED`；current generation 为空、无 partial outcome |
| SCAN-04 | exact definition、copy、same basename、hardlink alias | 只有 exact pathname + identity + rule + marker raw span occurrence 获豁免 |
| SCAN-05 | definition 同时含其他五类命中 | 其他规则仍报告，path suffix 也不豁免 |
| SCAN-06 | bytes、UTF-8 BOM、binary NUL | 都扫描；BOM 不入 match |
| SCAN-07 | UTF-16/32 BOM | `SCAN_UNSUPPORTED_ENCODING`，无 partial outcome/report/handle |
| SCAN-08 | LF/CRLF/bare CR 及 64 KiB chunk 切在 CRLF/match 中 | 行号/occurrence 与单块 oracle 一致；carry 精确 512 |
| SCAN-09 | symlink file/dir、junction/reparse、root escape | fail closed，不 skip |
| SCAN-10 | unreadable/special/disappearing/swapped/growing file、pathname replacement、metadata drift | 精确 `SCAN_FILE_CHANGED`/安全错误；final pathname identity 必须等于 read handle，无 raw OSError |
| SCAN-11 | duplicate root、nested/overlapping roots、输入 permutation | same pathname 归最具体显式 root；canonical tie-break、label、排序完全相同 |
| SCAN-12 | 两个 hardlink pathname | 不按 file identity 去重；两个 opaque location 分别报告 |
| SCAN-13 | native-relative bytes 含五类内容 token | 五类对应 rule、`line_number=None`；raw basename/segment 不进入 hit |
| SCAN-14 | suffix path rule 与 non-ASCII/space pathname | `forbidden_path_suffix` 或无 path hit；只有 `root_####/pth1_<64hex>`，无新增 rule |
| SCAN-15 | path control/`.`/`..`、越 root、不可稳定编码 | fail closed；无路径 oracle |
| SCAN-16 | 第 6.4 节 fixed 32-byte key literal known vectors | hit/location 两个 literal output 精确；uint64 length-prefix、domain、十二 dynamic limits、owner identity与relative bytes任一变化都改变对应向量；expected side不复制 helper |
| SCAN-17 | 31/33-byte key、bytearray/memoryview | `SCAN_KEY_INVALID`；key 不进 repr/pickle/log |
| SCAN-18 | 相同 snapshot/profile/root set/limits/key 与输入 permutation | `PrivacyScanReport` exact dataclass value equality、ordered hits tuple equality；limits bytes 参与 location domain；outcome/handle 不比较 |
| SCAN-19 | 两个默认-key scanner | opaque hashes/refs 应不同；不得断言跨实例稳定 |
| SCAN-20 | 手机 plain/区号/分隔正例与 lock SHA/长 token 负例 | 无 lock false positive |
| SCAN-21 | 18 位证件年月日/X 边界 | v1 矩阵精确；15 位/全角不宣称覆盖 |
| SCAN-22 | bounded email 正负、invalid labels/dots/过长 | regex + post-validation 一致 |
| SCAN-23 | stable ID lowercase/mixed/embedded runtime 组合 | 全命中；regex 文字本身不命中 |
| SCAN-24 | `repo_tracked`/`shared_derivative` exact suffix matrix | 两者都禁 `.sqlite3`/`.db` 主文件与 WAL/SHM/journal、exact `identity-map.enc`；line null |
| SCAN-25 | `global/catalog.sqlite3` under shared scan | 命中；没有 global-catalog 豁免，未来 exact-target 合同不在 Task 4 |
| SCAN-26 | 同行重复 occurrence | `hit_count` 为 occurrence count |
| SCAN-27 | defaults + hard maxima reflection | inputs100k/roots50k/tree500k/files100k/depth64/native32768/file1GiB/total8GiB/hits10k/catalog64KiB/markers256/marker128B 与 hard caps 精确；HMAC 是十二 dynamic limit fields + chunk/carry 两常量；无 env/YAML override |
| SCAN-28 | 每个 runtime limit 的 exact-equal 与 plus-one | `== max` 成功；第 `max+1` raw-input/root/tree-observation/file/depth/native/file/total/hit/catalog/marker/marker-byte 对应精确 code，无截断 outcome |
| SCAN-29 | bool/zero/negative/超过 hard max limit | 构造时 `SCAN_LIMIT_CONFIGURATION_INVALID` |
| SCAN-30 | 成功 scan 后 `resolve(handle, ref)`；下一合法 scan 获锁开始/失败/close 后旧 handle | current exact handle 可解；旧 handle统一 `SCAN_LOCATION_UNAVAILABLE` |
| SCAN-31 | report/outcome/handle/scanner/repr/error/log/pickle/copy/deepcopy | report 无路径；其余 fixed redacted/serialization forbidden；无 owner identity、generation、key、catalog binding、mapping 或原始异常 |
| SCAN-32 | 两次相同顺序 scan、same fixed key/snapshot | 两个 report exact-equal、两个 handle `is not`；第二次后旧 handle unavailable、current handle 可解，即使 ref string相同 |
| SCAN-33 | 两 scanner instances、same key/root/report/ref | 只有各自 exact current handle 可解；把 A handle/ref 给 B 统一 unavailable |
| SCAN-34 | 两个不同 canonical roots 有相同 basename/relative bytes | owner identity framing 使 refs 不 alias；报告不泄露 root identity |
| SCAN-35 | 相同 relative tree 位于短/长 absolute root，relative limit 介于 relative 与长 absolute bytes | 两者都通过 native-relative limit；absolute prefix 只进独立 owner identity field |
| SCAN-36 | directory root/file root depth，duplicate/nested/overlap/hardlink 计数 | root/file depth 0、direct child 1；roots canonical 去重后计且 nested 保留；overlap pathname一次、hardlink paths各次 |
| SCAN-37 | total-byte 计费的 overlap 与 hardlink | same pathname overlap 只读/计一次；hardlink pathname 各读取/计费；exact limit pass、plus-one fail |
| SCAN-38 | scan-vs-scan、scan-vs-resolve、resolve重入/scan重入（barrier/injected hook） | 未获 nonblocking lock 的调用固定 `SCAN_CONCURRENT_USE`；不改变 in-flight/current generation；无 deadlock/等待 |
| SCAN-39 | scan success/failure interleave attempt | operation lock 禁止交错 commit；合法 scan 开始先作废，成功原子提交，失败保持空 |
| SCAN-40 | initial tree snapshot 后新增/删除/rename/replacement child | parent post-order final snapshot 返回 `SCAN_TREE_CHANGED`；无 clean report/generation |
| SCAN-41 | child read 后 parent/new child drift；file read 后 pathname replacement | final post-order tree closure 或 final pathname lstat 失败；catalog post-check前不 commit |
| SCAN-42 | empty paths 的 success/catalog mutation | 仍做 catalog pre/post check；success发行 fresh handle+empty mapping，mutation失败且旧 generation已作废 |
| SCAN-43 | caller 构造/伪造/subclass/foreign handle、unknown ref | 全部与 stale/wrong-instance相同 `SCAN_LOCATION_UNAVAILABLE`，无失败原因 oracle；copy/deepcopy 尝试按 SCAN-31 固定拒绝 |
| SCAN-44 | 远多于 `max_roots` 但 canonical-equal 的重复 raw inputs | 在任何第 `max_input_paths+1` 项 canonical/stat 前 `SCAN_LIMIT_INPUT_PATHS`；unique-root语义不变 |
| SCAN-45 | 无 regular files 的超宽/海量 empty-directory tree | initial/final/overlap 每次 raw `scandir` observation 都计；exact `max_tree_entries` pass，第 `+1` 项在 lstat/tuple/sort 前 `SCAN_LIMIT_TREE_ENTRIES` |

### 10.4 Policy loader

| ID | 输入/故障 | 必须结果 |
|---|---|---|
| POLICY-01 | 四份 canonical files | immutable `PolicyBundle`；每个 artifact 只有八个 exact fields、fixed filename、schema/policy version |
| POLICY-02 | missing/extra/subdir/link/reparse/hardlink | bundle fail closed |
| POLICY-03 | cwd 切换、editable code location | 仍只从 explicit repo root 加载 |
| POLICY-04 | caller-supplied filename/ID、wheel-like layout 无顶层 policies | API 不存在或明确 missing；不 fallback/枚举任意资源 |
| POLICY-05 | BOM/CRLF/no newline/two newline/invalid UTF-8/NUL；`core.autocrlf=true` fresh checkout | 非 canonical fixture 返回 raw format/encoding error；根 attributes、本规范、四份 tracked policy、requirements 输入与 21 份 Schema 由精确八行 root-only self-pinned `.gitattributes` 保持 LF、零 CR、blob/checkout bytes 一致；嵌套同名/Schema及非 Schema 文件不继承属性，策略可加载 |
| POLICY-06 | 任意 `#`、TAB、`%YAML`、`---`、`...` raw line | parser 前 `POLICY_RAW_FORMAT_INVALID` |
| POLICY-07 | duplicate key、unknown key、wrong top/nested key order、duplicate array | 全部拒绝 |
| POLICY-08 | anchor、alias、merge、explicit/custom tag、多 YAML docs | 全部拒绝 |
| POLICY-09 | constructed bool/null/float/timestamp/set/object、bool-as-int | `POLICY_YAML_TYPE_INVALID`；只允许 exact dict/list/str/int |
| POLICY-10 | file/bundle size、node/depth/scalar limit | fail closed，无 parser snippet |
| POLICY-11 | schema/policy/member version 0/2/`true`/string | 只接受 schema `"1.0"` 与 exact int `1` |
| POLICY-12 | 18/6 exact tuple vs `get_args` | 同序通过，任一 drift 失败 |
| POLICY-13 | 13 relations exact tuple | 只有 `SUPERSEDES`；治理 revoke 不进入 |
| POLICY-14 | 8 retention categories 与语义 | exact order，无 duplicate/unknown；category 不产生授权/legal-hold/拒删或延迟 tombstone |
| POLICY-15 | 两 risk rules逐字段 mutation | 任一字符串、整数、顺序、context/question drift 均失败；只认两条 synthetic sentinels |
| POLICY-16 | Task 4 risk architectural static contract | loader 不 import reply generator；Task 4 不伪造 P6；P6 downstream acceptance 必须只经 allowlisted natural-language-goal projector 输出 |
| POLICY-17 | deep mutation/reflection/repr/pickle | document/nested rule/list 全 immutable、无 parser alias；所有 success artifact fixed redacted，pickle/copy/deepcopy fixed forbidden |
| POLICY-18 | canonical JSON known vectors | `canonical_bytes` exact；raw/content digest 分域命名并分别匹配公式 |
| POLICY-19 | formatting-only raw change但语义相同 | raw digest 可变，canonical bytes/content digest 不变；exact semantic gate仍通过才可比较 |
| POLICY-20 | read-time replacement/directory set change | `POLICY_CHANGED_DURING_READ` 或 directory unsafe；无 partial bundle |
| POLICY-21 | error/repr/log capture | error 只含 code/固定 policy ID；success repr fixed redacted；除显式 audit metadata 外无 filename/path/YAML/hash/parser/OSError value |
| POLICY-22 | direct raw Path/duck object/AppConfig subtype loader 构造 | `POLICY_VALIDATED_CONFIG_REQUIRED`；只接受 exact AppConfig type |
| POLICY-23 | `audit_metadata()` reflection/value | `LoadedPolicy` 仍精确八 fields；返回精确五-field DTO；Task 5 static contract 不读 document/canonical bytes/pattern/question 或 asdict/astuple |
| POLICY-24 | risk member identity production helper known vectors | whole hash与两 member hashes精确匹配第 8.9 节；ordinal/owner hash/任一九字段 mutation改变或拒绝；测试不复制 expected canonicalizer |
| POLICY-25 | fake/wrong-owner LoadedPolicy 传 member helper | `POLICY_MEMBER_IDENTITY_INVALID`，无 member/hash正文；裸 rule API 不存在 |
| POLICY-26 | future schema/policy/member version、latest/migration fallback attempt | v1 loader fail closed；无 auto-migration、latest、旧 ref重解释或额外 filename |
| POLICY-27 | policy value/order vs shape/type 演进检查 | value/order要求 policy_version bump；shape/type/envelope要求 schema_version bump；当前未 bump fixture拒绝 |
| POLICY-28 | bundle identity reflection | 无 bundle digest/API/隐式 concat；后续需要时必须另冻 canonical formula |

### 10.5 Tracked bytes 与回归门

1. tracked canary grep：完整 marker 只在 exact definition；
2. tracked stable client regex grep：零命中；
3. policy files 通过 `repo_tracked` privacy profile，除定义文件窄豁免外零 hit；
4. Task 4 focused tests；
5. 全 `tests/consultation_kb`；
6. Python 3.10 entrypoint compatibility；
7. Task 3 focused core/schema suite、两次 exporter、exact 21 schemas、checked-in bytes 无 diff；
8. Task 2 packaging/dependency/entrypoint/CI guards；
9. comparable upstream 与 full suite；
10. ruff、strict mypy、`doctor --help`、`git diff --check`、精确 `git status --short`。

建议命令：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_config.py tests/consultation_kb/unit/test_privacy_scan.py tests/consultation_kb/unit/test_policy_contracts.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/compat/test_py310_entrypoint.py
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb scripts
& '.\.venv\Scripts\python.exe' -m mypy --strict consultation_kb
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor --help
git diff --check
git status --short
```

full suite 只能保留经当前基线复核的既有环境差异；任何新增失败、skip 或 xfail 都是 Task 4 回归，不得用“Windows 限制”泛化豁免。

## 11. 实现阶段允许与禁止修改文件

### 11.1 允许创建

```text
.gitattributes
consultation_kb/core/config.py
consultation_kb/vault/__init__.py
consultation_kb/vault/layout.py
consultation_kb/evaluation/__init__.py
consultation_kb/evaluation/privacy_scan.py
consultation_kb/policy/__init__.py
consultation_kb/policy/loader.py
policies/evidence-levels.yaml
policies/relation-types.yaml
policies/retention.yaml
policies/risk-rules.yaml
tests/consultation_kb/unit/test_config.py
tests/consultation_kb/unit/test_privacy_scan.py
tests/consultation_kb/unit/test_policy_contracts.py
```

### 11.2 允许机械修改

仅第 7.2 节列出的四个 tracked 文档/测试可做 synthetic bytes 分片；不得顺手重构、重排测试或改变 Schema 期望。

### 11.3 禁止修改

- `consultation_kb/models/common.py`、`evidence.py` 或任何 Task 3 model/Schema；
- `consultation_kb/core/__init__.py`、根 `__init__.py`、`cli.py`、`entrypoint.py`；
- `pyproject.toml`、依赖 inputs、locks、CI、`.gitignore`；
- `graphify/`；
- 上位设计和其他 phase plan；P0 plan 除精确机械分片外也禁止语义修改；
- canary definition 的值；
- 真实 vault、model cache、SQLite/WAL/SHM、scan report、临时目录或 `.superpowers/sdd` 证据。

需要越过 allowlist 时必须停止，先修订本规范并重新走两项合同审查。

## 12. 下游消费边界

| 阶段 | 必须复用 | 不得归给 Task 4 |
|---|---|---|
| P0 Task 5 | `AppConfig.load()`、`PolicyLoader.load_all()`、`repo_tracked` scanner outcome；doctor 传精确 tracked files，只逐字段记录 `PolicyAuditMetadata` | direct/from_values production acquisition、第二套 commonpath/YAML/parser、document/canonical bytes/pattern/question日志、目录创建、P1 path authorization |
| P1 | canonical roots/`VaultLayout`；每次 create/open 重新验证；worker 出现后验证不得接 layout/global roots | final handle、hardlink、ACL/DPAPI、capability、client/session paths、ISO-01 均由 P1 完成；Task 4 snapshot gate不替代 |
| P3 | evidence/relation loaded policy；18/6/13 顺序 | 不得改 Task 3 types；governance revoke 不得污染 relation YAML；evidence/relation manifest/member ref 与未来 version dispatcher 由 P3 形成 |
| P6 | strict synthetic risk policy document、`risk_rule_member_identities()` exact helper/known vectors | engine、negation/context、whole/member ObjectId 与 immutable manifest一次审批持久化、observation lifecycle、allowlisted natural-language-goal projector 与 client-output 隔离属于 P6；禁止重新生成ID、ID-to-latest或自创canonicalizer；internal rule/trigger fields不得进 reply generator |
| P7 | scanner 作为附加泄漏检查 | deidentifier transform、第三方/罕见组合、reuse authorization、人审属于 P7；scanner clean 不等于可共享 |
| P8 | retention categories；Task 4 对 fault env 的 reserved 拒绝 | category不是授权/legal hold；独立版本化例外政策、retention version dispatcher、test-mode marker + fault env gate、recovery、tombstone、物理清除、backup closure 属于 P8 |
| P9 | `repo_tracked`/`shared_derivative` profiles、无正文报告、policy raw/content digests | evaluation/cache/backup 全覆盖、limits/version 调优、模型/完整 wheel resources 与安装态测试属于 P9 |

下游若需要新增 rule、relation、retention category、risk field、放宽路径 namespace 或提高生产 limits，必须通过新的 policy/schema/security version；不得静默改变 v1。所有 future policy version acceptance 必须先按第 8.10 节由 owner 冻结 dispatcher/immutable history；Task 4 不提供 migration/latest/bundle digest。

## 13. 独立审查与实施门

### 13.1 安全合同审查

由未撰写本规范且不承担首轮实现的人独立审查：

- 所有构造路径是否不可绕过；AppConfig runtime seal 与所有 validated-config consumer exact-type gate 是否同时存在；
- absolute/canonical/disjoint、different drive、case、UNC/device、`..`、nonexistent、reparse 边界；
- env acquisition 只在 `load()`、production callsite gate 与四个 scope 常量；
- scanner inclusive defaults/hard caps/计数口径，尤其 canonicalization 前 raw-input 与每次 scandir observation 上界；64 KiB/512-byte streaming、newline、post-order tree/file closure、两个显式 profiles、opaque `location_ref`；
- hit/location length-prefixed HMAC domains、owner root identity 与真正 native-relative bytes、exact 32-byte key；
- outcome/handle object-identity generation、nonblocking non-reentrant lock、stale/wrong-instance/concurrency/empty scan 与 resolver 生命周期、canary path+identity+rule+span 窄豁免；
- report/outcome/handle/error/repr/log/pickle 是否无正文、无 absolute root/generation、无 path oracle；
- P1 TOCTOU/final-handle 边界是否没有被提前宣称。

### 13.2 策略 Schema 合同审查

由另一名独立 reviewer 审查：

- loader 是生产模块且单一职责；
- raw `#`/TAB/directive/document marker、duplicate/alias/anchor/merge/tag/multi-doc/type/limits 全部 fail closed；
- 四份 YAML exact shape/order/semantics；
- LoadedPolicy 八字段、五字段 `PolicyAuditMetadata`、fixed redacted repr/pickle ban、canonical JSON、raw/content digest、deep immutability；
- exact version 1、18/6 与 Task 3 parity、13 relations、8 retention、两条逐值冻结的 synthetic risk rules；
- `SUPERSEDES` 与 governance revoke 边界；
- risk member envelope/known vectors/P6 immutable ObjectId+VersionRef lifecycle，以及 internal risk fields 与 reply generator 之间的 projector boundary；
- retention category 非授权边界、v1-only/version dispatcher ownership、无 auto-migration/latest/bundle digest；
- checkout/editable 定位及明确不承诺 wheel；
- Task 5/P3/P6/P8/P9 消费边界。

两份报告都必须给出明确 `PASS` 且 `P0=0/P1=0/P2=0`。此外，Task 3 最新完整范围复审必须 PASS、HEAD 稳定、tracked worktree clean，才可派 Task 4 implementer。实现完成后还需独立实现安全复审和完整回归；本设计通过不等于实现通过。

## 14. 完成定义

Task 4 只有在以下条件全部满足时才能声称完成：

- 本规范优先级/erratum 被执行；Task 4 RED/API 不再使用无参 scanner 或 `relative_path`；
- 本规范的 API、error code、路径、inclusive 默认/硬 limits及逐项 equal/+1（含 canonicalization 前 raw inputs 与每次 tree-entry observation）、64 KiB/512-byte streaming、六规则、两个显式 profiles、YAML 与文件边界逐项实现；
- AppConfig runtime subclass seal、所有 consumer exact-type gate、direct/from_values 的 value invariants、`load()` 独占 env acquisition、production load-only callsites、Windows drive/namespace/component alias、`location_ref` 均无旁路；`CONSULTATION_PYTHON` 仅 recognized-but-inert；
- hit/location 均使用 exact 32-byte key、length-prefixed domain HMAC、独立 owner identity 与真正 native-relative bytes；
- scanner post-order tree/file closure 在 catalog post-check前完成；outcome/opaque handle、object-identity current generation、nonblocking non-reentrant lock与 stale/wrong-instance/concurrency/empty-scan测试全部通过；
- policy loader 是实际生产入口，测试未复制另一套逻辑；
- 根 `.gitattributes` 精确包含 root-only 自身 self-pin、本规范、四份 canonical policy、单个 requirements 输入与根 Schema 通配的八条 `text eol=lf` 规则；`core.autocrlf=true` fresh checkout 的 28 份正向 bytes 与 blobs 一致、零 CR，嵌套同名/Schema与非 Schema 反向目标不继承属性且 production loader 可加载策略；
- `VaultLayout` 非 dataclass、18 paths exact、serializer拒绝且 equality按canonical root；P1 worker boundary 保留为下游验收；
- 四个 LoadedPolicy 只含八个 exact fields，`PolicyAuditMetadata` 只含五 fields，version 精确为 1，success repr/pickle安全、documents deep immutable，canonical bytes/raw-content digests 按公式可复算；Task 5 只记录 audit metadata；
- 两条 risk sentinel 逐字段精确且只证明 synthetic contract；whole/member known vectors与production helper通过；P6未来必须一次持久化ObjectId/VersionRef、禁止latest/重生成并保持projector boundary的downstream acceptance已精确冻结，但Task 4不伪造或提前实现P6；
- retention category 不授予保存/共享/拒删权；future version fail closed、owner dispatcher边界与Task4无migration/bundle digest均锁定；
- tracked synthetic bytes 达到第 7.1 节零/唯一命中状态；
- focused、consultation、compat、Schema、packaging、upstream/full、lint/type/check 命令新鲜通过；
- 无真实客户内容、完整静态客户示例、scan report、vault 或生成状态进入 Git；
- 安全实现审查和策略实现审查均 `P0=0/P1=0/P2=0`。

本文件已裁决预检及独立书面复审中的关键未决项：scanner report 只返回 opaque `root_####/pth1_<64hex>`，raw path mapping 只存在于 opaque current-generation handle保护的进程内瞬时状态；defaults/hard maxima不可由env/YAML调整且全部inclusive，canonicalization 前 raw inputs 与每次 tree-entry observation 也有独立硬上界；两profile都拒绝主数据库、sidecars和`identity-map.enc`；AppConfig 以runtime seal禁止subclass、所有consumer要求exact type，env只由production `load()`获取；VaultLayout无serializer；严格policy loader/audit metadata/risk member identity进入Task 4。检测到的scanner snapshot inconsistency gate不等于事务快照；OS same-handle final authority/完整TOCTOU保证仍在P1，完整wheel资源仍在P9。
