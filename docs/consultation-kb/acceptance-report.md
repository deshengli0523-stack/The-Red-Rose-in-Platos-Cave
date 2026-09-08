# 咨询知识库 P9 验收报告

- 生成日期：2026-07-22
- 证据基线：`73279b04fc546df42bc19d0ee9f7fa12c2798426`（P8）加当前 P9 工作树
- 报告状态：**部分完成；不得据此宣称 P9 已全部验收**

本报告只记录命令、版本、计数、指标、失败或缺失证据 ID 与哈希，不收录咨询正文、评估正文、稳定客户标识、vault 路径或可逆身份映射。

## 1. 当前结论

| 验收面 | 状态 | 可核验证据 |
|---|---|---|
| 15 项确定性强制验收 | 通过 | 2026-07-22 在最终修复后使用冻结 registry 一次运行，`102 passed in 87.55s`，失败 ID：无 |
| 跨阶段真实 STDIO 咨询烟测 | 通过 | `test_consultation_pipeline.py`：`1 passed in 22.17s` |
| MCP STDIO 完整文件 | 通过 | `test_mcp_stdio.py`：`5 passed in 35.38s` |
| 全仓受控回归 | 与 Windows 上游基线一致，无新增回归 | `3032 passed, 5 skipped, 5 deselected in 489.41s`；仅精确排除本机无权限创建 symlink 的 5 个上游节点 |
| MCP 工具合同 | 通过自动合同 | 预期工具数 `51`；schema SHA-256 `99eff229f44d3b6b05ea12f2725b9f4d4fc284701b352d067ef34d064952f129` |
| CPython 3.12/3.13 core 与 ML 锁安装 | 通过既有自动证据 | 3.12 core `3 passed, 1 skipped`；3.13 core `3 passed, 1 skipped`；3.12 ML `4 passed`；3.13 ML `4 passed`；四个环境 `pip check` 均通过 |
| 本地真实四模型导入与 benchmark | 通过 | 四个固定 revision 均已导入；4 个组合均零约束失败；报告 SHA-256 `46fbf4ca6ec1945900db9dcdf370153513b9548438fa2000b16d67b50673ea19` |
| 五基线与三消融完整 gold queue | 待真实 Codex 队列运行 | runner 合同通过不等于真实回答质量运行；见 `MISSING-GOLD-QUEUE` |
| 至少两名专家随机双盲 | 待人工执行 | packet/importer 合同通过不等于人工评分已发生；见 `MISSING-BLIND-REVIEW` |
| Codex 宿主 `/mcp` 与真实文本演练 | 待宿主手工证明 | STDIO 自动测试与 `codex mcp list` 均不能替代宿主初始化和实际工具调用；见 `MISSING-CODEX-HOST` |
| 最终 staged/tracked/privacy 扫描 | 通过 | 报告重新暂存前后两轮均为：staged/tracked production `408` 个路径零命中；两个本地模型运行报告零命中；稳定客户 ID 与禁止运行时文件/目录计数均为 `0` |

当前可以确认已执行的确定性不变量和受控全仓回归没有新增失败；尚不能确认质量目标已经达到，也不能确认 P9 完成定义全部满足。

## 2. 冻结验收运行

冻结输入：

- registry SHA-256：`9cb088d02c1aee253ac91745edc3abaa44d92035bc494cd76782329065e48efe`
- runner SHA-256：`090db5cc84e5f2c7d4b34a7c93635b766af7a01d2da190c75f93fb27ecc3a3d4`
- 验收 ID：`ISO-01,ISO-02,CASE-01,CASE-02,TURN-01,FACT-01,THEORY-01,GRAPH-01,WRITE-01,TX-01,VER-01,DEL-01,REBUILD-01,RISK-01,ARCHIVE-01`

运行命令：

```powershell
$Py = (Resolve-Path '.venv\Scripts\python.exe').Path
$BaseTemp = Join-Path $env:TEMP 'pytest-consultation-acceptance-p9'
& $Py scripts/run_consultation_acceptance.py `
  --ids ISO-01,ISO-02,CASE-01,CASE-02,TURN-01,FACT-01,THEORY-01,GRAPH-01,WRITE-01,TX-01,VER-01,DEL-01,REBUILD-01,RISK-01,ARCHIVE-01 `
  -- -q -p no:cacheprovider --basetemp $BaseTemp
```

结果：`102 passed in 87.55s`；collection contract 为 `102 tests collected in 1.24s`；failure IDs：无。`--basetemp` 必须为该运行独占目录，避免并发 pytest 共用临时目录造成非产品性碰撞。

## 3. 跨阶段咨询流水线证据

新增烟测不重复 15 项 registry 的细粒度不变量，而验证此前没有由一个测试串起来的跨阶段接缝：

```text
真实 STDIO MCP
  -> 固定会谈快照与一轮七阶段生成
  -> 记录实际采用回复
  -> 关闭会谈并生成三用途归档草稿
  -> 独立批准共享案例并完成全局发布/源 outbox ACK
  -> MCP 进程退出并重启
  -> 已关闭会谈拒绝恢复
  -> 同一客户可以开始下一次新会谈
  -> 实际回复、全局案例版本与发布证明仍一致
```

运行命令：

```powershell
$Py = (Resolve-Path '.venv\Scripts\python.exe').Path
$BaseTemp = Join-Path $env:TEMP 'pytest-p9-task8-pipeline-final'
& $Py -m pytest -q -p no:cacheprovider --basetemp $BaseTemp `
  tests/consultation_kb/integration/test_consultation_pipeline.py
```

结果：`1 passed in 22.17s`；failure IDs：无。最终修复后的完整 MCP STDIO 文件另行通过 `5 passed in 35.38s`。

该烟测证明真实 STDIO、实际回复、归档关闭、共享发布和重启边界能连通；它不冒充以下已经由专门验收拥有的证明：

| 流程要求 | 证明归属 | 当前状态 |
|---|---|---|
| 知识 MCP ingest Source/C1/Wiki 与正式批准 | `test_knowledge_mcp_end_to_end.py`、`THEORY-01`、`WRITE-01` | 自动覆盖 |
| A 的两轮回复与“上一轮实际回复先记录” | `TURN-01` 与 `test_two_turn_session.py` | 自动覆盖 |
| 非零内部风险观察及来访者输出无标签泄漏 | `RISK-01` | 自动覆盖 |
| private/profile/shared 三条批准路径 | `ARCHIVE-01` 与 archive integration tests | 自动覆盖 |
| B 可用共享案例而 A 全谱系排除自己的案例 | `CASE-01`、`CASE-02` | 自动覆盖 |
| profile 更新后的下一次会谈与原会谈固定快照 | profile/session integration tests | 自动覆盖；同一“大而全”宿主演练仍待执行 |
| revoke/delete/rebuild/poll 完成 | `DEL-01`、`REBUILD-01`、`TX-01`、`VER-01` | 自动覆盖 |
| 由 `create_client` 实际返回随机 ID 驱动整条 Codex 文本流程 | Codex 宿主手工演练 | 尚未证明 |

## 4. 依赖与模型证据

锁文件矩阵的既有 clean-venv 证据：

| 环境 | 运行时语义 | 结果 |
|---|---|---|
| Windows CPython 3.12 core | 生产；Graphify Leiden | `pip check` 通过；`3 passed, 1 skipped` |
| Windows CPython 3.13 core | 兼容；Louvain degraded 明示 | `pip check` 通过；`3 passed, 1 skipped` |
| Windows CPython 3.12 ML | CPU torch、本地模型合同 | `pip check` 通过；clean runtime `4 passed`；完整 model marker `31 passed, 1 skipped` |
| Windows CPython 3.13 ML | CPU torch、本地模型合同 | `pip check` 通过；clean runtime `4 passed`；完整 model marker `31 passed, 1 skipped` |

跟踪模型候选清单 SHA-256：`9ae7be779edc1f8d2b16c05209336935ef1401ae4e7669cab6d18355b486feee`。

四个实际导入记录：

| 逻辑 ID | 角色 | 固定 revision | descriptor SHA-256 |
|---|---|---|---|
| `bge_m3` | embedding | `5617a9f61b028005a4858fdac845db406aefb181` | `e065894403e4d5901ffa60a1caa9cadffbe2475c3d5416c18b23bfd8523ba097` |
| `bge_small_zh_v1_5` | embedding | `7999e1d3359715c523056ef9478215996d62a620` | `802aacc4b5a351062ab11e1998b49ab4cbed7d3a0cc3719918f095fdbe7bda52` |
| `bge_reranker_base` | reranker | `2cfc18c9415c912f9d8155881c133215df768a70` | `583f2d2d9b64803a9ff89eeab9d675bea3e00a3abaef7afdf5f026a5ebaef4c6` |
| `bge_reranker_v2_m3` | reranker | `953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e` | `63d938d220c878289fb428f758407bd86fe0e1a9fd118c8f84c34711876a1878` |

runtime manifest 规范 SHA-256 为 `63ee209298482bc81ee854d1f68979f9699700486d2bf07162b6b297d449f71c`，原子 JSON 文件 SHA-256 为 `b97155c0c698cf482ae6c0671c72c9b6a701cc81c0a59ef2718b875a10b0bf6d`。权重布局复核只存在每个候选允许的单一 root 权重，无 ONNX、OpenVINO、备选或分片权重。

正式离线 benchmark 使用 suite SHA-256 `4611fe7de696527658a2fd7645ab2cc65b0fb32e0292e3f6e4a9a02c468cd90e`，报告 SHA-256 `46fbf4ca6ec1945900db9dcdf370153513b9548438fa2000b16d67b50673ea19`。四个组合 Recall@10、counterevidence recall 与 MRR 均为 `1.0`，constraint failures 均为 `0`：

| embedding | reranker | nDCG@10 | rerank gain | 预热后平均延迟 ms |
|---|---|---:|---:|---:|
| `bge_small_zh_v1_5` | `bge_reranker_v2_m3` | `0.991166` | `0.051390` | `389.753` |
| `bge_m3` | `bge_reranker_v2_m3` | `0.991166` | `0.049670` | `685.140` |
| `bge_small_zh_v1_5` | `bge_reranker_base` | `0.933596` | `-0.006179` | `144.197` |
| `bge_m3` | `bge_reranker_base` | `0.933596` | `-0.007900` | `441.089` |

按预注册的质量优先序选出正式 default：`bge_small_zh_v1_5` + `bge_reranker_v2_m3`。延迟只在质量完全持平时参与选择；`peak_memory_bytes` 已明确标记为 Python `tracemalloc` 诊断范围且不参与选择，不得当作 PyTorch/native 总 RAM。报告扫描确认无 query/text/passages、绝对路径或 vault 名称。四模型真实加载由本次 benchmark 的统一预热和推理覆盖；此外，3.12/3.13 ML 锁环境分别动态构建微型真实 Bert SentenceTransformer 与 CrossEncoder，并通过生产 adapter 的离线 CPU 加载和推理，完整 model marker 均为 `31 passed, 1 skipped`。唯一 skip 是需要显式官方本地模型路径的可选 adapter smoke，不替代上述真实动态模型 smoke。

## 5. 质量评估与人工证据

以下两类结果必须来自真实执行，当前不填写推测值或合成“达标”值：

| 缺失证据 ID | 完成条件 | 当前状态 |
|---|---|---|
| `MISSING-GOLD-QUEUE` | 五基线与三消融完成完整 gold queue；JSON/Markdown 报告冻结版本、缺失样本、失败 slice、CI 与报告 hash | 未执行完整真实队列 |
| `MISSING-BLIND-REVIEW` | 至少两名专家完成匿名随机 packet；导入 mapping hash、评分者不可逆 ID、一致性和 preference CI | 未进行人工评分 |

持续质量目标仍按评估规范解释，不是额外运营上线门：

- C1 permission/version：`100%`；
- C1 applicable/out-of-scope：`>=95%`；
- C1 empirical：`>=95%`，deterministic overclaim：`0`；
- Recall@10：`>=90%`；
- supported claims：`>=95%`；
- unexplained contradiction-free：`>=95%`；
- full system 相对 hybrid RAG 专家偏好：`>=70%`。

当前没有真实 gold queue 或专家结果，因此这些目标的状态均为“未判定”，不是“通过”或“失败”。

## 6. Codex 宿主证明

`MISSING-CODEX-HOST` 必须在受信任 graphify 工作区补齐以下证据：

1. 执行 `configure-codex` 并重启 Codex MCP 连接；
2. 由宿主 `/mcp` 确认 required 状态、`51` 个工具及 schema hash；
3. 宿主实际调用一次 `doctor`；
4. 宿主实际调用一次未批准正式写并得到拒绝；
5. 使用 `create_client` 的实际返回 ID 完成两轮文本咨询、逐轮实际回复、归档草稿、private/profile/case 分别审核和重启恢复；
6. 记录日期、Codex task 引用、状态、计数和哈希，但不复制正文或稳定客户 ID。

`codex mcp list` 只证明配置存在；自动 `test_mcp_stdio.py` 只证明 SDK/STDIO 服务合同。二者都不得标记 `MISSING-CODEX-HOST` 已关闭。

2026-07-22 宿主预检记录：`codex-cli 0.130.0-alpha.5`；当前 `codex mcp list` 中没有 `consultation-kb`。`configure-codex --repo-root .` 以退出码 `2` 和固定错误 `CONFIGURE_SCOPE_INVALID` 失败，原因是预期的仓库外运行 vault 尚未初始化；命令没有生成 `.codex/config.toml`。这是明确的未完成证据，不是宿主验收通过。在可用的正式或受控演练 vault 就绪前，不应为了让配置命令表面通过而创建伪初始化空目录。

## 7. 最终门禁与隐私扫描

最终提交前运行：

```powershell
$Py = (Resolve-Path '.venv\Scripts\python.exe').Path
& $Py -m pip check
& $Py -m ruff check consultation_kb tests/consultation_kb scripts
& $Py -m mypy consultation_kb
& $Py -m pytest -q -p no:cacheprovider tests
& $Py -m pytest -q -p no:cacheprovider -m fault tests/consultation_kb
& $Py -m pytest -q -p no:cacheprovider -m golden tests/consultation_kb
& $Py -m pytest -q -p no:cacheprovider -m model tests/consultation_kb
& $Py -m consultation_kb.cli doctor
& $Py -m consultation_kb.cli migrate --check
& $Py -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_mcp_stdio.py
git diff --check
git status --short
```

随后对最终 staged/tracked 集合及共享 logs/index/cache/eval/backups 边界执行隐私扫描。只有扫描退出码为 `0`、泄漏计数为 `0`，且确认 runtime vault、SQLite/WAL/SHM、模型缓存、评估正文和真实咨询正文均未进入 Git，才可关闭 `MISSING-FINAL-SCAN`。

最终暂存后的第一轮扫描已关闭 `MISSING-FINAL-SCAN`：production profile 扫描 `408` 个 staged/tracked 路径，hit count `0`；shared-derivative profile 扫描被忽略的本地 runtime manifest 与 benchmark report，hit count `0`；全 index 不区分大小写的稳定客户 ID、SQLite/DB/WAL/SHM/journal、`identity-map.enc` 与非测试运行时边界计数均为 `0`。两个定义 canary 的唯一跟踪位置均为 `tests/fixtures/consultation_kb/canaries.json`。报告更新重新暂存后还必须用同一合同复扫最终 index；第二轮结果记录在本节末尾。

2026-07-22 最终修复后的新鲜自动门禁：

| 门禁 | 结果 |
|---|---|
| 全仓受控回归 | `3032 passed, 5 skipped, 5 deselected in 489.41s`；5 个 deselect 精确对应上游 symlink 用例，本机进程无 `SeCreateSymbolicLinkPrivilege` 且未开启 Developer Mode |
| fault | `54 passed, 2551 deselected in 40.49s` |
| golden | `35 passed, 2570 deselected in 11.18s` |
| model | core `30 passed, 2 skipped in 1.84s`（不安装 ML 依赖且未指定官方模型路径）；3.12/3.13 ML 锁环境均为 `31 passed, 1 skipped`，且均实际加载 SentenceTransformer/CrossEncoder 并推理 |
| P9 Task 1–7 evaluation/model 合同 | `118 passed in 3.40s` |
| 15 项冻结验收 | `102 passed in 87.55s`；failure IDs：无 |
| 跨阶段 pipeline / MCP STDIO | `1 passed in 22.17s` / `5 passed in 35.38s` |
| Ruff / mypy | Ruff 全通过；mypy `282` 个源码文件无问题 |
| 最终评测并发/终态 delta | evaluation runner + Evaluation MCP `43 passed in 5.78s`；覆盖双进程 submit/prepare、staging 原子发布、exact reopen、报告投影和 incomplete 封存 |
| CI/依赖/运维文档 delta | `269 passed in 1.69s`；四份输入显式固定 pip/setuptools/wheel，四环境 `--no-index --no-build-isolation --no-deps` 构建及 `pip check` 通过 |
| 依赖完整性 | 当前环境和 3.12/3.13 core/ML 四个 fresh lock 环境的 `pip check` 均通过 |
| diff | `git diff --check` 通过 |

受控全仓回归没有修改或跳过任何咨询知识库测试。精确 deselect 的上游节点为：

- `tests/test_detect.py::test_detect_follows_symlinked_directory`
- `tests/test_detect.py::test_detect_follows_symlinked_file`
- `tests/test_detect.py::test_detect_handles_circular_symlinks`
- `tests/test_extract.py::test_collect_files_follows_symlinked_directory`
- `tests/test_extract.py::test_collect_files_handles_circular_symlinks`

因此这项证据只能解释为“与已记录的 Windows 上游基线一致且无新增回归”，不能解释为五个未执行节点已通过。恢复闭包回归还验证：metadata-only 的 `risk_rule_policy` 不被通用 CAS 误判，但其 manifest hash、成员闭包和墓碑仍失败闭合；CAS-backed 的 `risk_model_descriptor` 继续校验正文。原先四个启动失败节点联合重跑 `4 passed`，相关恢复/STDIO 邻近矩阵 `27 passed`。

CLI `doctor` 与 `migrate --check` 没有在空临时目录上伪装通过：两者都要求已初始化的正式或受控演练 vault；空目录探针分别固定失败为缺失数据库/无效 MCP runtime。相关能力已由全仓集成测试覆盖，但真实 vault 的运维命令仍属于 `MISSING-CODEX-HOST` 的宿主演练范围。

首轮有效扫描曾发现一个固定内部错误码会被大小写不敏感的稳定 ID 规则识别为 `CLIENT_` 加 12 个字符；它不是客户数据，但会使生产隐私门永久非零。错误码已改为不含该形态，静态 Git 守卫同步改为大小写不敏感，两个既有的 uppercase invalid-ID fixture 改为运行时拼接。相关 privacy/catalog/cleanup/del 回归 `160 passed in 5.03s`。报告重新暂存后的第二轮以及最终并发/依赖审查 delta 后的第三轮扫描结果完全一致：production `408/0`、ignored model reports `2/0`、stable ID/runtime file/runtime boundary `0/0/0`，staged secret/machine-path 为 `0/0`，canary 仍只在受控定义文件。

## 8. 交付哈希清单

| 工件 | SHA-256 / 状态 |
|---|---|
| acceptance registry | `9cb088d02c1aee253ac91745edc3abaa44d92035bc494cd76782329065e48efe` |
| acceptance runner | `090db5cc84e5f2c7d4b34a7c93635b766af7a01d2da190c75f93fb27ecc3a3d4` |
| cross-phase pipeline smoke test | `4dd8a5392209a3d9f5356f639550f0bebfb6398d527653f2e8ed364574aab76d` |
| tracked model candidates | `9ae7be779edc1f8d2b16c05209336935ef1401ae4e7669cab6d18355b486feee` |
| quality-evaluator Skill | `48e1dd22aadf85945304629be004484272486a456e7b3ca002cb4887c2baeb08` |
| MCP tool schemas | `99eff229f44d3b6b05ea12f2725b9f4d4fc284701b352d067ef34d064952f129` |
| runtime model manifest | canonical `63ee209298482bc81ee854d1f68979f9699700486d2bf07162b6b297d449f71c`；file `b97155c0c698cf482ae6c0671c72c9b6a701cc81c0a59ef2718b875a10b0bf6d` |
| model benchmark report | `46fbf4ca6ec1945900db9dcdf370153513b9548438fa2000b16d67b50673ea19` |
| full gold queue report | `MISSING-GOLD-QUEUE` |
| blind-review import/report | `MISSING-BLIND-REVIEW` |
| Codex host evidence | `MISSING-CODEX-HOST` |
| final privacy scan | `PASS`；production staged/tracked `408` paths / `0` hits；ignored model reports `2` paths / `0` hits；stable ID/runtime-file/runtime-boundary counts `0/0/0` |

P9 完成判定必须以缺失证据 ID 全部关闭、最终全门禁通过为准；不得只依据本报告中已通过的自动测试提前标记完成。
