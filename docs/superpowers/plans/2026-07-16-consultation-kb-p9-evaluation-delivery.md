# P9：质量评估与交付实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 建立可复现的金标准、全指标、五个系统基线、Graphify/C1 消融、embedding/reranker 本地基准、专家盲评、无正文可观测性、Codex 端到端演练和运维交付，使架构价值由数据证明并可持续优化。

**Architecture:** `EvaluationDataset` 只引用合成/获准受控对象；local runner 创建版本冻结的 case queue，Codex `quality-evaluator` Skill 逐例运行同一生成合同，无需 API。确定性指标自动计算，主观有用性由随机化盲评工件收集。所有运行通过 `run_id` 绑定模型、Skill、资料快照、索引/图和结果 hash。

**Tech Stack:** Pydantic/JSONL、NumPy/stdlib metrics、P1–P8 runtime、Codex Skill/MCP、Sentence Transformers local models、pytest/golden/fault、Markdown+JSON reports、pip-tools lock。

## Global Constraints

- 先完成 P8；读取设计规格第 2、19、20、24–26 节。
- 金标准和报告不得包含真实身份；真实案例若用于评估仍在客户/用途 scope 内，不进入 Git 或共享评估集。
- 五基线使用相同问题、客户快照和模型/生成预算，只有被比较的知识层变化；不能用不同 Prompt/模型制造虚假提升。
- 确定性约束 100% 是正确性；质量目标是持续优化下限，不额外制造打断日常咨询的“上线审批门”。
- 专家评分者看到随机化、去系统身份输出；模型自评不能替代专家盲评。
- C1 scope-policy 权威、确定性 applicability provider、硬约束接线和真实 STDIO production wiring 必须在 P6 完成；P9 只负责 embedding/reranker 模型锁、真实模型质量基准、消融与持续评估，不得把 deterministic C1 correctness 延后到评估阶段。

---

## Task 1：完整 run manifest 与无正文可观测性

**Files:**

- Modify: `consultation_kb/observability/runs.py`
- Modify: `consultation_kb/observability/audit.py`
- Create: `consultation_kb/observability/metrics_sink.py`
- Create: `tests/consultation_kb/unit/test_run_manifest.py`
- Create: `tests/consultation_kb/integration/test_no_body_observability.py`

**Interfaces produced:** 完整 `RunManifest`；聚合 `MetricsSink`；每回答/归档/评估 run ID。

- [x] 写 manifest contract：保存EvidencePack自身的 `VersionRef`/canonical hash，并逐项固定 `authority.snapshot_ref/policy_ref`、`client_snapshot_ref`、temporary facts、candidate text/locator/freshness/provenance/derivation refs、C1 revision/scope policy、conflicts、proof、wiki/lex/vector/graph root manifests和reranker descriptor；另保存model/params、Prompt/Skill refs、query plan/routes、filter counts、critique/retry/degradation、candidate/actual reply/diff refs、archive/review decisions。run closure还记录Python implementation/exact version/bits、base executable SHA-256、runtime source tag、Schema/package/lock hashes，但不记录机器绝对路径、正文、client ID或full authority/provenance。生产 manifest 若base interpreter来自Codex cache则拒绝开始run；不得只记EvidencePack ID或可变component version字符串。
- [x] 写隐私测试：对包含所有合成 canary 的完整咨询跑回答/归档/评估，扫描 global logs/metrics/audit；只允许客户 scope content objects有正文，共享 run/audit 只有 object IDs/hashes/counts。Pydantic extra fields阻止 `prompt/text/content/transcript`。
- [x] 写 run lineage：一个 turn 的 query/retrieval/stages/final/actual/archive 共用 parent/child run refs；重复 run ID 不可跨 client 使用。
- [x] MetricsSink 只接收数值/枚举/不可逆 scope ID；每客户详细日志放其目录，共享聚合不保留稳定 client ID。candidate/actual text 只由 governed object ref 关联。
- [x] model/Skill descriptor 使用 content hash，不只用可变名称；所有时间/随机 seed/route policy/retry count可复现。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_run_manifest.py tests/consultation_kb/integration/test_no_body_observability.py
```

Expected: PASS；设计规格第 19 节字段齐全且无正文副本。

验证证据：Task 1 聚焦测试与 Task 2–3 联合回归共 `25 passed`；对应 7 个 production 文件通过 Ruff 与 strict mypy。

---

## Task 2：金标准数据模型与全部切片

**Files:**

- Create: `consultation_kb/evaluation/datasets.py`
- Create: `consultation_kb/models/evaluation.py`
- Create: `tests/fixtures/consultation_kb/evaluation/gold_cases.jsonl`
- Create: `tests/fixtures/consultation_kb/evaluation/gold_retrieval.jsonl`
- Create: `tests/fixtures/consultation_kb/evaluation/canary_cases.jsonl`
- Create: `tests/consultation_kb/unit/test_evaluation_dataset.py`

**Interfaces produced:** `EvaluationCase`；dataset loader/validator/splitter；不可混用 scope。

- [x] 每个 case 必填：synthetic client snapshot ref、input turns、关键/替代 evidence、forbidden sources/conclusions、核心回答特征、profile diff、允许不确定性/条件路径、risk expectation、archive expectation 和 evaluator rubric。
- [x] 数据至少覆盖：国学原典/注疏/现代解释、情感咨询、生涯时效、跨理论类比、C1 applicable/out-of-scope/expired/superseded/aligned/conflicting、证据不足/冲突、关系/目标/问题时态变化、自案例排除、客户隔离/权限、风险、资料去重/失效/依赖传播。
- [x] 写泄漏/重复测试：所有 client/case 是合成 ID；gold train/dev/test 按 scenario family 分组防近重复；canary 不能进入正式 knowledge indexes；每条 source ref 可解析且 version固定。
- [x] loader 只读 immutable dataset manifest，验证 object hashes/policy version；任何真实客户受控评估通过 vault catalog单独注册，Git fixture loader拒绝非 synthetic sensitivity。
- [x] 明确评分字段的 machine/human ownership；同一 case 支持多个 acceptable evidence/path，避免只接受一套措辞。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_evaluation_dataset.py
```

Expected: PASS；所有 slice count > 0，hash固定。

---

## Task 3：检索、证据、一致性、更新、隔离、风险与归档指标

**Files:**

- Create: `consultation_kb/evaluation/metrics.py`
- Create: `consultation_kb/evaluation/scorers.py`
- Create: `tests/consultation_kb/unit/test_retrieval_metrics.py`
- Create: `tests/consultation_kb/unit/test_consultation_metrics.py`

**Interfaces produced:** `MetricResult`；deterministic scorers；metric aggregation with confidence intervals。

- [x] 精确手算 fixtures 验证 Recall@k/Precision@k/nDCG、exact quote/location、source diversity/duplicate、counterevidence、prefilter accuracy。
- [x] 证据/回答：claim support、paraphrase fidelity标注输入、C1 applicability/active/main-framework、empirical status/conflict/overclaim、cognitive type、uncertainty calibration。
- [x] 一致性/更新：single answer、多回复、跨轮、跨次、conclusion-change explanation、entity/relation/dependency、direct-vs-indirect、current stale/resolved/duplicate residue、expected profile diff match。
- [x] 隔离/边界：cross-client leak、全谱系 self-case misuse、unauthorized case、deid miss/overdelete/rare combination、post-tombstone recall、diagnosis/dangerous advice、internal risk recall/false positive/label leak/high-attention path/ack/closure、双份归档 field/omission。
- [x] 每个 metric 定义 denominator/undefined policy/micro-macro aggregation/95% bootstrap CI/threshold direction；禁止缺样本时默认为 100%。确定性 zero-tolerance 指标任一失败使 correctness summary fail。
- [x] 人工字段只生成待标注项，不让本地字符串规则伪装“共情质量”评分；机器自动指标与专家指标分表。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_retrieval_metrics.py tests/consultation_kb/unit/test_consultation_metrics.py
```

Expected: PASS；手算与实现一致。

---

## Task 4：五系统基线、Graphify/C1 消融与公平运行

**Files:**

- Create: `consultation_kb/evaluation/variants.py`
- Create: `consultation_kb/evaluation/runner.py`
- Create: `consultation_kb/evaluation/work_queue.py`
- Create: `tests/consultation_kb/unit/test_evaluation_variants.py`
- Create: `tests/consultation_kb/integration/test_evaluation_runner.py`

**Interfaces produced:** `SystemVariant`、`EvaluationRunPlan`、`EvaluationRunner.prepare/submit/finalize`。

- [x] 精确固定五基线：

  1. `general_model_only`：无知识检索；
  2. `hybrid_rag_only`：词法+向量，不用 Wiki/graph/case/C1；
  3. `wiki_hybrid_rag`：Wiki+词法+向量，不用 graph/client temporal/case/C1 priority；
  4. `full_without_c1_priority`：完整技术层，C1 当普通来源；
  5. `full_system`：C1+Wiki+hybrid RAG+global graph+client temporal graph+cases+multi-stage critique。

- [x] 额外消融：`full_without_graphify_navigation`、`full_without_cases`、`full_without_reranker`。只有 feature flags/route policy不同；固定可观察的 Codex model label、reasoning effort、Skill/prompt/schema versions、reply contract/retry budget与input snapshot。Codex-only宿主未暴露 temperature/seed 时不得声称已固定，run manifest写 `host_unknown_fields=["temperature","generation_seed"]`。
- [x] Runner不调用OpenAI API：prepare在vault生成per-case/variant queue；quality-evaluator Skill在Codex中逐项执行并用MCP submit exact FinalTurnBundle；runner核对manifest/variant rules，防止full evidence漏入baseline。采用同一Codex任务内配对随机顺序、每variant多次重复和置信区间降低宿主未知采样参数影响；若未来要求严格temperature/seed，只能新增实现相同StageRunner合同的可选API/本地runner，不能写进Codex-only完成定义。
- [x] 单元使用 `DeterministicFakeStageRunner`，集成对每 variant 运行合成小集，断言禁止 channel count=0、run manifest公平字段相同。
- [x] runner使用独立且可控的**队列顺序 seed**随机化case/variant，不能把它称为模型generation seed；同一case snapshots/evidence catalog version冻结；失败/重试不偷偷换资料版本。
- [x] finalize 只接受完整 queue 或明确 missing reasons，输出 machine JSON report和human Markdown；不把不完整样本当成功。
- [x] prepare 使用 run-ID 跨进程锁，在非枚举 staging 目录完整写入并原子发布；崩溃遗留 staging 不污染已发布 run 枚举。submission 的 read-modify-write、finalize 与报告投影复核使用同一跨进程锁；封存后的 incomplete run 不再返回不可提交的 pending item。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_evaluation_variants.py tests/consultation_kb/integration/test_evaluation_runner.py
```

Expected: PASS；五基线公平隔离。

验证证据：最终 evaluation runner 聚焦测试 `33 passed`；与 Evaluation MCP 合并 `43 passed`。双实例、双进程提交竞态、冲突 prepare、崩溃 staging、exact reopen、报告 missing/variant 投影和 incomplete 终态均有回归；Ruff 与 strict mypy 通过。

---

## Task 5：本地 embedding/reranker 基准、模型锁与依赖锁

**Files:**

- Create: `consultation_kb/evaluation/model_benchmark.py`
- Create: `consultation_kb/models/model_lock.py`
- Create: `consultation_kb/models/importer.py`
- Modify: `consultation_kb/cli.py`
- Create: `models/consultation-models.json`
- Modify: `requirements/consultation-win-py312.in`
- Modify: `requirements/consultation-win-py312.lock.txt`
- Create: `requirements/consultation-ml-win-py312.in`
- Create: `requirements/consultation-ml-win-py312.lock.txt`
- Create: `requirements/consultation-win-py313.in`
- Create: `requirements/consultation-win-py313.lock.txt`
- Create: `requirements/consultation-ml-win-py313.in`
- Create: `requirements/consultation-ml-win-py313.lock.txt`
- Modify: `.github/workflows/ci.yml`
- Create: `tests/consultation_kb/unit/test_model_lock.py`
- Create: `tests/consultation_kb/unit/test_model_import_cli.py`
- Create: `tests/consultation_kb/integration/test_locked_clean_venvs.py`
- Create: `tests/consultation_kb/model/test_model_benchmark.py`
- Create: `tests/consultation_kb/model/test_real_sentence_transformers_runtime.py`

**Interfaces produced:** tracked immutable model candidate spec；vault-local runtime model manifest；`models-import` CLI；benchmark report；Windows CPython 3.12 production与3.13兼容性 hash locks。

- [x] Tracked `models/consultation-models.json` 只列逻辑 `model_id`、角色、repo、期望license、完整P4编码参数与相对 `artifact_relpath`，不把mutable main当runtime revision，也不保存绝对/本机路径。候选：embedding `BAAI/bge-m3`、`BAAI/bge-small-zh-v1.5`；reranker `BAAI/bge-reranker-v2-m3`、`BAAI/bge-reranker-base`。
- [x] `models-import` 是 Task5先实现的显式联网运维动作：解析官方snapshot到40-hex commit、下载到vault model root、核对repo/revision/file hashes/license与完整ModelDescriptor，原子写被忽略的 `.consultation-models/runtime-manifest.json`。runtime加载仍 `local_files_only=true/trust_remote_code=false`。单元测试用本地fake repository，不联网。
- [x] 写 lock test：runtime revision必须40-hex、所有文件hash存在，目录/文件/descriptor不匹配fail closed；tracked/runtime registry均不能含API key/URL token，tracked文件拒绝盘符、UNC、home/user绝对路径。
- [x] 基准使用 gold retrieval 的中文原句、改写、跨域、反证、C1 scope；报告 Recall@10/nDCG/MRR、rerank gain、CPU latency/memory仅作次要信息。质量优先按预先定义 lexicographic rule：zero constraint failures → Recall/counterevidence → nDCG → resource。
- [x] 模型下载是明确运维动作，runtime不自动联网：

```powershell
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli models-import --repo 'BAAI/bge-m3' --resolve-main
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli models-import --repo 'BAAI/bge-small-zh-v1.5' --resolve-main
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli models-import --repo 'BAAI/bge-reranker-v2-m3' --resolve-main
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli models-import --repo 'BAAI/bge-reranker-base' --resolve-main
```

- [x] P0 core 3.12 lock继续只含第三方distribution；P9刷新它并新增3.12 ML lock、3.13 core/ML locks。`.in` 从pyproject导出，不含editable项目，并显式固定 `pip==26.0.1`、`setuptools==83.0.0`、`wheel==0.47.0`；Windows CPU torch使用官方直接wheel URL与SHA-256，避免多index歧义。pip-tools `--generate-hashes` 后分别创建**全新**3.12/3.13 venv真实安装 lock → `pip install --no-index --no-build-isolation --no-deps .` → `pip check/imports/doctor/FTS5/DPAPI/MCP/ML tests`，不能用dry-run替代。
- [x] 3.12生产clean-venv断言 Graphify backend=Leiden；3.13兼容矩阵明确排除Leiden并断言Louvain degraded flag、其余core/DPAPI/MCP/ML合同通过。CI新增Windows 3.13兼容job；失败必须可见，不静默当作3.12生产支持。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_model_lock.py tests/consultation_kb/unit/test_model_import_cli.py tests/consultation_kb/integration/test_locked_clean_venvs.py
& '.\.venv\Scripts\python.exe' -m pytest -q -m model tests/consultation_kb/model/test_model_benchmark.py
```

Expected: 四个本地模型导入后 model benchmark PASS，选出并记录正式 default；缺任一候选时 P9 不算完成。

验证证据（2026-07-22）：四个官方固定 revision 真实导入并通过 license/单一权重布局/全树 hash 复核，runtime manifest canonical SHA-256 `63ee209298482bc81ee854d1f68979f9699700486d2bf07162b6b297d449f71c`。统一预热后的 2×2 真实离线 benchmark 四组均零约束失败、Recall@10/counterevidence recall/MRR 均为 `1.0`，报告 SHA-256 `46fbf4ca6ec1945900db9dcdf370153513b9548438fa2000b16d67b50673ea19`，正式 default 为 `bge_small_zh_v1_5` + `bge_reranker_v2_m3`，nDCG@10 `0.991166`。3.12 与 3.13 ML 锁环境各自执行动态生成的真实 SentenceTransformer embedding 与 CrossEncoder 离线 CPU smoke，均为 `31 passed, 1 skipped`；skip 仅为需要官方模型环境变量的可选路径。四套 core/ML 环境的无索引、无构建隔离项目安装与 `pip check` 均通过，3.12 core 为 Leiden，3.13 core 明示 Louvain degraded。

---

## Task 6：专家随机盲评与质量报告

**Files:**

- Create: `consultation_kb/evaluation/blind_review.py`
- Create: `consultation_kb/evaluation/feedback.py`
- Create: `consultation_kb/evaluation/report.py`
- Create: `tests/consultation_kb/unit/test_blind_review.py`
- Create: `tests/consultation_kb/unit/test_counselor_feedback.py`
- Create: `tests/consultation_kb/unit/test_quality_report.py`

**Interfaces produced:** random pair packets；review importer；JSON/Markdown report。

- [x] pair packet 对相同 case 的 `full_system` vs `hybrid_rag_only` 随机左右、隐藏 system/run/model version，保留来访者上下文和必要评分说明；packet 不含 client/source IDs或内部风险标签。
- [x] rubric：咨询有用性、共情、具体性、可执行性、自主性、事实/证据忠实、冲突/不确定性处理、专业边界；评分者选 left/right/tie并写结构化原因。
- [x] importer 验证双盲 mapping hash、评分者 ID不可逆、重复/缺失/自相矛盾；至少两名评分时计算一致性；报告 confidence interval，不用单次评价作确定结论。
- [x] `FeedbackAnalyzer` 关联候选选择、咨询师编辑 diff、缺失证据、客户事实纠错和后续效果，输出检索/生成失败 slice 与知识候选；它只能写 evaluation finding 或 P3 draft proposal，测试证明不能直接写 Wiki、CasePattern 或客户长期事实。
- [x] report 并列 deterministic correctness、retrieval/evidence、consistency/update、privacy/risk/archive、expert preference；显示每个 slice/失败样本 ID和版本，不掩盖 degradation/missing。
- [x] 目标值：C1 permission/version 100%；C1 applicable/out-of-scope >=95%；C1 empirical >=95%且 deterministic overclaim 0；Recall@10 >=90%；supported claims >=95%；unexplained contradiction-free >=95%；full vs hybrid expert preference >=70%。报告明确这些是持续质量目标，不是额外运营审批门。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_blind_review.py tests/consultation_kb/unit/test_counselor_feedback.py tests/consultation_kb/unit/test_quality_report.py
```

Expected: PASS；小型合成 report deterministic。

验证证据：双盲、反馈写边界与质量报告聚焦测试 `14 passed`；Ruff、format-check 与 strict mypy 通过。

---

## Task 7：quality-evaluator Skill、MCP 与运维文档

**Files:**

- Create: `.agents/skills/quality-evaluator/SKILL.md`
- Create: `consultation_kb/mcp/evaluation_tools.py`
- Modify: `consultation_kb/mcp/server.py`
- Modify: `consultation_kb/cli.py`
- Create: `docs/consultation-kb/operations.md`
- Create: `docs/consultation-kb/evaluation.md`
- Create: `tests/consultation_kb/unit/test_quality_skill.py`
- Create: `tests/consultation_kb/unit/test_evaluation_mcp.py`

**Interfaces produced:** `prepare_evaluation`、`get_next_evaluation_case`、`submit_evaluation_result`、`finalize_evaluation`；Codex evaluator workflow。

- [x] Skill 明确先 doctor/frozen versions，再 prepare queue，逐 case/variant 按相同 stage contract，提交结果，运行 deterministic metrics，生成 blind packets/report；禁止把一个 variant evidence带入另一个。
- [x] MCP 工具不返回真实 client ID/body；case text在受控 evaluation scope按需提供；submit 绑定 case/variant/snapshot/pack hashes；finalize缺样本明确失败。
- [x] operations 文档覆盖：CPython 3.12 install、venv/locked deps、vault ACL/BitLocker建议、model import/offline、migrate/doctor/MCP restart、backup/restore、session recovery、delete/rebuild、Codex task vs local deletion。
- [x] evaluation 文档覆盖：数据登记、五基线、model benchmark、专家盲评、目标解释、失败 slice修复和版本回归。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_quality_skill.py tests/consultation_kb/unit/test_evaluation_mcp.py
```

Expected: PASS；Skill/tool/docs一致。

验证证据（2026-07-22）：quality-evaluator Skill 与 Evaluation MCP 精确合同 `12 passed in 0.96s`；运维文档合同 `5 passed in 0.18s`；实时 MCP surface 为 51 tools，schema SHA-256 `99eff229f44d3b6b05ea12f2725b9f4d4fc284701b352d067ef34d064952f129`。

---

## Task 8：15 项强制验收、五基线和 Codex 端到端演练

**Files:**

- Create: `tests/consultation_kb/integration/test_consultation_pipeline.py`
- Reuse: `tests/consultation_kb/acceptance_registry.py` and `scripts/run_consultation_acceptance.py`（不再新增会嵌套重复执行同一批测试的 matrix wrapper）
- Create: `docs/consultation-kb/acceptance-report.md`

**Interfaces consumed:** P0–P9 全部能力。

- [ ] 端到端合成流程：create A/B并保存实际返回的随机runtime IDs（human aliases另列）→ 通过P5 knowledge MCP ingest Source/C1/Wiki → build indexes/graphs → A多轮咨询/actual replies/internal risk → private/profile/shared archive → B可用案例、A自案例排除 → A下一次咨询加载新profile → revoke/delete/start rebuild并poll job完成。
- [x] 复用 P0 冻结 registry runner 一次调用 `ISO-01`、`ISO-02`、`CASE-01`、`CASE-02`、`TURN-01`、`FACT-01`、`THEORY-01`、`GRAPH-01`、`WRITE-01`、`TX-01`、`VER-01`、`DEL-01`、`REBUILD-01`、`RISK-01`、`ARCHIVE-01`；任一 failure 原样返回非零，不再创建嵌套 pytest 的冗余 wrapper。2026-07-22 最终修复后使用独立 basetemp 实跑：`102 passed in 87.55s`，collection contract 为 `102 tests collected in 1.24s`。
- [ ] 运行完整 gold queue的五基线和三消融，生成版本冻结 JSON/Markdown report；完成模型 benchmark和专家盲评。若质量目标未到，报告具体 slice并继续优化，但不把结果伪装达标。
- [ ] 在受信任graphify工作区运行 `configure-codex`并重启Codex；通过宿主 `/mcp` 确认完整预期tools/schema hash、required状态，实际调用一次doctor和一次未批准write拒绝。然后以 create_client实际返回ID执行“开始咨询 <runtime-id>”→两轮实际回复→“结束咨询，生成归档草稿”→分别审核private/profile/case并验证恢复。`codex mcp list`只证明配置存在，不能替代宿主初始化/tool调用证据。
- [x] 最终扫描 Git staged/tracked、shared logs/index/cache/eval/backups/vault boundaries，不得有真实客户正文/稳定 ID；合成 canary只出现在受控 fixture/客户 scope。2026-07-22 报告重新暂存前后及最终审查 delta 后共三轮 production profile 均扫描 `408` 个路径、ignored model reports 均扫描 `2` 个路径，全部 `0` hits；全 index 稳定 ID、禁止运行时文件和非测试运行时边界计数均为 `0`，最终 staged secret/machine-path 为 `0/0`，canary 只在受控定义文件中。
- [ ] Run final gates:

```powershell
$Py = (Resolve-Path '.venv\Scripts\python.exe').Path
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb scripts
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider -m fault tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider -m golden tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider -m model tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli migrate --check
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_mcp_stdio.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids ISO-01,ISO-02,CASE-01,CASE-02,TURN-01,FACT-01,THEORY-01,GRAPH-01,WRITE-01,TX-01,VER-01,DEL-01,REBUILD-01,RISK-01,ARCHIVE-01
codex mcp list
git diff --check
git status --short
```

Expected: 所有强制验收/上游测试通过；3.12生产与3.13兼容clean-venv结果明确；quality report真实记录目标达成情况；Git无运行时数据。宿主MCP人工演练证据单独记录，不能由STDIO单测冒充。

2026-07-22 自动证据：受控全仓基线 `3032 passed, 5 skipped, 5 deselected`，五个 deselect 仅为当前 Windows 进程无 symlink 权限的既知上游节点；fault `54 passed`、golden `35 passed`、完整 MCP STDIO `5 passed`、跨阶段 pipeline `1 passed`。最终审查 delta 另行通过 evaluation runner + MCP `43 passed`、CI/dependency/docs `269 passed`、3.12/3.13 ML 各 `31 passed, 1 skipped`；四环境无索引本地构建及 `pip check` 全通过。Ruff、282-source strict mypy、`git diff --check` 均通过。五个未执行上游节点、真实 gold queue、两名专家盲评、Codex 宿主演练和最终 index 隐私扫描仍按各自证据状态处理，不由这些自动计数替代。

- [x] `acceptance-report.md` 只写命令、版本、counts/metrics、failure IDs 和 vault外报告hash，不复制客户/评估正文。明确 Codex宿主端实际演练日期/任务、MCP状态和人工检查结果；未发生的宿主演练明确记录为 `MISSING-CODEX-HOST`，不以 STDIO 测试替代。
## P9 完成定义

- [ ] 15 项确定性强制验收和上游 Graphify 回归全部通过。
- [ ] 五基线、Graphify/C1/案例/重排消融与模型 benchmark可复现且公平。
- [ ] 专家盲评工件随机、匿名、可核验；质量目标是否达成被如实报告。
- [ ] Codex+本地 MCP 完成真实文本工作流，无独立 API；运维/恢复/删除/评估文档可执行。
