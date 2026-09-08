# P6：多阶段生成、一致性与内部风险实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 在不引入独立模型 API 的前提下，让 Codex 按可持久化的结构化阶段完成查询规划、案例概念化、理论比较、多版本回复、证据审计、一致性批评和最终综合，同时以独立内部对象提示咨询师风险而永不向来访者输出风险标签。

**Architecture:** Codex Skill 负责模型推理，MCP `submit_generation_stage` 接收严格 Pydantic 工件并验证阶段顺序、证据引用、C1 规则和重试上限。系统只保存简明可审计结论/依据，不要求或保存隐藏思维链。确定性风险规则与模型观察合并为内部对象，再投影成不含标签的自然回应目标供最终综合。

**Tech Stack:** Pydantic discriminated unions、P5 session stage store/MCP、P4 EvidencePack、YAML risk policy、pytest/golden、纯本地 deterministic validators。

## Global Constraints

- 先完成 P5；读取设计规格第 3.1、3.3、11.3–11.4、13、15、19、20 节。
- 阶段工件保存“结论、证据引用、替代解释、限制、编辑动作”，不保存自由展开的私密思维链。
- 适用 active C1 是主框架；范围外、过期、取代或硬约束冲突时不得强套。C1 不等于外部最高实证。
- 多个回复可以语气/策略不同，但核心判断、事实和行动方向必须相容。
- 内部风险对象和来访者回复 Schema 物理分离；来访者回复生成器永不接收内部 category/level/rule/alert text。

## P6 生产闭环补充（综合审查后纳入，不得延后到 P9）

- [x] C1 scope policy 必须是经 CAS、SQLite 状态机和一次性批准约束的正式权威对象；Theory approval 只接受 exact approved policy。生产 `GenerationC1Provider` 从 active theory + exact policy 确定性判定适用性，区分 missing 与 known-empty；多个 active C1 在 v1 fail closed，模型不得自报 applicability decision。
- [x] Worker 从受信客户 snapshot/current-turn temporary facts 构造 evidence-bound applicability input，并把事实、法律、专业边界硬约束自动交给 `TheoryUsePolicy`；C1 的最高框架优先级永不覆盖事实 truth type、来源等级或硬约束。
- [x] `ReplyClaim` 必须以 Unicode character offsets、exact substring 和 SHA-256 无缝覆盖全部 client-visible text；未声明正文、span gap/overlap、错 hash、把陈述伪装成开放问题均在合同边界拒绝。Final bundle 的 counselor internal/evidence quality 必须是已审 artifacts 的确定性投影，未知 ID 或相反摘要拒绝。
- [x] EvidenceAudit 对每个 analysis/reply claim 的 support/contradict evidence pair 必须交付独立语义评估、独立 `assessed_claim_type` 与冻结正文的 exact excerpt、Unicode offsets、SHA-256；同一 evidence-bearing claim 的各 pair 类型评估必须一致并等于声明类型，建议误标为事实/结论产生 blocking finding。ConsistencyRiskReview 对当前候选的 fact/core/action 每轴提交唯一、覆盖完整候选正文的 exact-span assessment；历史/资料快照按 fact×其自身 evidence IDs、core/action/conclusion×conclusion evidence IDs 完整展开，每 pair 绑定 EvidencePack 冻结 evidence context 的 exact excerpt/hash。scoped worker 验证无多余/遗漏 pair、来源和投影闭包。确定性层只证明原文追溯、pair 闭包与结构决策；语义值由独立 critic authored，不得用关键词规则或闭包校验伪称已自动证明语义蕴含。
- [x] EvidencePack 固定后，当前 temporary fact refs/digest 进入每个后续 stage 的前后 freshness 校验；追加或纠正事实使旧 pack 失效并要求重新检索。`historical_change` 的 `temporal_graph_edge` 等 required evidence types 必须由真实受信 route/candidate metadata 履约，不能只由 QueryPlan 声明字符串。
- [x] 风险评估使用 durable pending/completed 状态与 crash replay；trigger content ref、offset、substring hash 在 scoped worker 对真实 client message 逐项核验。生产既支持 approved model observation draft 与 deterministic rule 合并，也支持 counselor-only acknowledge 后显式 close，且任何风险对象都不进入 client reply。
- [x] 长驻 runtime 每次读取 fresh ACTIVE risk/C1 authority，不使用跨调用 no-match 缓存；无 active risk authority 时一律 fail closed，不得把字面无命中或 provider 自报模型版本当成已授权的安全证明。
- [x] ProductionRuntime 提供显式、可测试的 embedding/C1 provider factory 注入路径，默认缺失仍 fail closed；旧公开 `store_candidate_set` 在 generation-capable runtime 禁用，不能绕过七阶段。
- [x] P6 验收必须经真实 MCP STDIO 完成 append → risk complete → query/retrieval → 七阶段 → final → actual reply，并覆盖重启恢复、provider 缺失、旧工具绕过、临时事实失效和客户隔离；direct worker 测试不能替代该验收。

---

## Task 1：生成阶段 Schema、顺序与私有工件存储

**Files:**

- Create: `consultation_kb/generation/__init__.py`
- Create: `consultation_kb/generation/contracts.py`
- Create: `consultation_kb/generation/stage_store.py`
- Create: `consultation_kb/generation/state_machine.py`
- Create: `tests/consultation_kb/unit/test_generation_contracts.py`
- Create: `tests/consultation_kb/unit/test_generation_stage_store.py`

**Interfaces produced:** 七类 stage payload；`GenerationStageStore.submit/get_latest`；`GenerationStateMachine`。

- [x] 定义阶段序列和依赖 hash 契约测试；按 B 级业务能力与本 Task 其他生成契约集中验证，不要求单独展示 RED：

```python
def test_generation_stages_require_order_and_parent_hash(stage_store, turn_context) -> None:
    with pytest.raises(GenerationStageOrderError):
        stage_store.submit(turn_context, stage="reply_drafts", payload=valid_reply_drafts())
    plan = stage_store.submit(turn_context, stage="query_plan", payload=valid_query_plan())
    with pytest.raises(GenerationParentMismatch):
        stage_store.submit(
            turn_context,
            stage="conceptualization",
            payload=valid_conceptualization(parent_hash="0" * 64),
        )
    assert plan.content_sha256 != "0" * 64
```

- [x] Schema 测试拒绝自由 `reasoning/chain_of_thought/scratchpad` 字段；允许 `rationale_summary` 但限制长度，并要求 structured facts/hypotheses/evidence IDs。
- [x] 写 retry 测试：evidence audit/consistency 可要求最多 2 次重新检索或重写；第 3 次返回 `QUALITY_RETRY_EXHAUSTED` 和 evidence不足/冲突，不无限循环。
- [x] 判别联合固定：`QueryPlan`、`Conceptualization`、`TheoryComparison`、`ReplyDraftSet`、`EvidenceAudit`、`ConsistencyRiskReview`、`FinalTurnBundle`。每类组合且不修改P0首发 `GenerationStageEnvelope(schema_version,stage,turn_id,run_id,parent_sha256s,created_at)`，不得另造 `parent_hashes` 等别名；再增加严格结构化body。`QueryPlan` 明确没有尚未产生的 EvidencePack hash，只绑定 client snapshot/runtime epochs。检索结果 hash成为 `Conceptualization` 及以后每个 stage的必填 parent。
- [x] stage store 把正文工件写客户 session content store，数据库只存 refs/hashes；同一 stage + idempotency key 相同 hash 返回原结果，不同 hash 需显式 revision/retry reason。
- [x] 第一个 QueryPlan提交时原子把 P5 turn从 `client_turn_received` 置为 `generation_in_progress`；后续 stages只允许此状态。`FinalTurnBundle` 调用 P5 `CandidateSetService.store_and_await`，在一个事务保存候选并记录 `candidates_generated → awaiting_actual_reply`；实际回复仍由 P5 单独记录。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_generation_contracts.py tests/consultation_kb/unit/test_generation_stage_store.py
```

Expected: PASS；无隐藏思维链字段，阶段可恢复/审计。

---

## Task 2：查询规划与检索路由合同

**Files:**

- Create: `consultation_kb/generation/query_planning.py`
- Create: `tests/consultation_kb/unit/test_query_planning.py`
- Create: `tests/consultation_kb/golden/query_plan_cases.jsonl`

**Interfaces produced:** `QueryPlanValidator.validate`；`Subquery` 类型与 required route policy。

- [x] 金标准覆盖：当前客户事实、情绪/需要/关系动力、历史变化、理论/方法/边界/反例、案例类比、反证/冲突、内部风险。每个问题不必调用全部通道。
- [x] 写硬规则测试：每轮始终包含 current client snapshot validation、provenance/source-client filter 和 tombstone/version check；出现事实变化时必须路由 client history/temporal graph；理论建议必须路由 applicability/boundary；案例类比必须路由 case provenance。
- [x] 写 minimality 测试：简单共情澄清不强制 graph/case；规划器不得为“架构看起来完整”无差别调用所有通道。被省略通道保存 reason。
- [x] Validator 不自行用 LLM 拆 query；它检查 Codex 提交的 Subquery category、question、routes、required evidence types、scope 和 conflicts target。非法/遗漏返回明确 correction request。
- [x] 合法 plan 交 P4 RetrievalCoordinator；返回 EvidencePack hash 作为 Conceptualization及后续 stage parent，不能在后续 stage临时引用 pack外 evidence。检索失败时 turn保留可恢复的 `generation_in_progress`，不伪造空 pack。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_query_planning.py
```

Expected: PASS；关键过滤永不因 route 省略。

---

## Task 3：案例概念化、C1 理论政策与回复候选合同

**Files:**

- Create: `consultation_kb/generation/conceptualization.py`
- Create: `consultation_kb/generation/theory_policy.py`
- Create: `consultation_kb/generation/reply_policy.py`
- Create: `tests/consultation_kb/unit/test_conceptualization.py`
- Create: `tests/consultation_kb/unit/test_generation_theory_policy.py`
- Create: `tests/consultation_kb/unit/test_reply_drafts.py`

**Interfaces produced:** `ConceptualizationValidator`；`TheoryUsePolicy`；`ReplyDraftValidator`。

- [x] 概念化测试要求：每项区分 `client_fact/client_reported/counselor_observation/hypothesis/suggestion`；hypothesis 有 supporting/contradicting evidence、uncertainty 和可澄清问题；禁止自动诊断。
- [x] C1 表格测试：

| EvidencePack 状态 | 必须行为 |
|---|---|
| applicable active C1 | C1 为 `primary_framework`，其他资料补充/验证/冲突 |
| no applicable C1 | 按各领域等级选择，不伪造 C1 |
| insufficient C1 context | 先提澄清问题，不强套 |
| expired/superseded/revoked | 不使用该 revision |
| C1 与 C2/C3 冲突 | 内部保留冲突和 empirical status，C1 仍为本系统框架 |
| C1 与客户事实/法律/硬约束冲突 | 禁用具体建议，记录不适用原因 |

- [x] 回复测试：至少三个可配置策略（温和共情、直接澄清、探索引导）；每个带不可见 `core_positions`/`action_directions` 用于一致性比较；client text 自然、无默认引用/术语；不得压过来访者意义。
- [x] Validators 只核对结构/证据 refs/policy，不在本地重新生成内容。重要结论必须引用 pack evidence IDs；建议标明由何事实/假设支持；无 evidence 的表达只能是开放问题或明确不确定。
- [x] `TheoryUsePolicy` 只读取 pack内冻结的 `C1ApplicabilityDecision`，不能接受 stage自报 `is_c1=true`；`not_applicable` 与 `insufficient_context` 分别触发“不使用”和“优先澄清”，source grade与empirical status分开输出。
- [x] `ReplyDraftValidator` 禁止诊断、危险建议、受害者归因、国学医学化、单案例普遍化的明确 policy finding；P9 再做人工质量评分。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_conceptualization.py tests/consultation_kb/unit/test_generation_theory_policy.py tests/consultation_kb/unit/test_reply_drafts.py
```

Expected: PASS；C1 适用/不适用行为确定性。

---

## Task 4：证据审计、核心结论一致性和解释性变化

**Files:**

- Create: `consultation_kb/generation/evidence_audit.py`
- Create: `consultation_kb/generation/consistency.py`
- Create: `consultation_kb/models/consistency.py`
- Create: `tests/consultation_kb/unit/test_evidence_audit.py`
- Create: `tests/consultation_kb/unit/test_consistency_review.py`

**Interfaces produced:** `EvidenceAuditor.audit`；`ConsistencyReviewer.review`；`ConclusionChangeRecord`。

- [x] 写 evidence audit 测试：从 internal analysis/reply claims 获取 claim IDs，验证每个重要主张在 EvidencePack，有忠实 paraphrase、未遗漏关联反证；不存在的 ID、过期/tombstone ref、把 hypothesis 写成 fact，以及把独立 critic 判定的 suggestion 伪装成 fact/important conclusion 均 error。
- [x] 写多候选一致性测试：语气/顺序可不同；`core_positions` 与 `action_directions` 各至少一项，且每个当前 fact/core/action 状态由唯一、完整候选 exact span assessment 投影核对，不能相反。历史/资料快照逐 axis-evidence pair 绑定冻结原文；缺 pair、多 pair、错来源、错 excerpt/hash 均 fail closed。一个说“建议立即分手”、另一个说“关系无需变化”必须失败，不因文风不同而放过。
- [x] 写跨轮/跨次测试：对比 current snapshot、session earlier final bundles 和上一客户 profile；新证据改变结论时必须提交 `old_conclusion/new_information/change_reason/impact_on_advice_profile_followup`。
- [x] 写 retry exhaustion：审计失败请求 `retrieve_more/rewrite`，最多 2 次；仍失败的 final bundle 明确 `insufficient_evidence/unresolved_conflict/needs_counselor_judgment`，不能编造确定性。
- [x] EvidenceAuditor 产生结构化 finding：claim/evidence/ref fidelity/conflict status/severity/correction；不依赖字符串中出现引用标记，因为 client replies 默认无引用。
- [x] ConsistencyReviewer 使用结构化 facts/core positions/action directions，文本相似度只作提示；事实矛盾和行动相反为 blocking，表达差异为 allowed。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_evidence_audit.py tests/consultation_kb/unit/test_consistency_review.py
```

Expected: PASS；所有结论改变有可审计解释。

---

## Task 5：确定性风险规则、模型观察合并与确认闭环

**Files:**

- Create: `consultation_kb/risk/__init__.py`
- Create: `consultation_kb/risk/rules.py`
- Create: `consultation_kb/risk/engine.py`
- Create: `consultation_kb/risk/repository.py`
- Create: `consultation_kb/risk/resources.py`
- Create: `tests/consultation_kb/unit/test_risk_rules.py`
- Create: `tests/consultation_kb/unit/test_risk_lifecycle.py`
- Create: `tests/consultation_kb/unit/test_regional_resources.py`

**Interfaces produced:** `RiskEngine.evaluate`；`InternalRiskObservationRepository.acknowledge/close`；`RegionalResourceCatalog`。

- [x] 使用合成语句测试一般/高关注规则、否定/引用/历史语境和模糊表述；规则结果带 trigger turn/span hash、`rule_ref: VersionRef`、confidence、建议追问，不把单一分数当最终判断。raw rule version只能是display metadata，不能代替immutable ref。
- [x] 模型可提交 `ModelRiskObservationDraft`，engine 与 deterministic finding 去重/并列；模型不能改 rule finding 或自行标记 acknowledged/resolved。
- [x] 生命周期测试：高关注 observation 在咨询师确认前每轮持续返回；`acknowledge` 保存时间/处置/驳回理由，但不自动表示风险解除；显式 close 需要人工决定和理由。
- [x] 地区资源测试：仅 approved、地区匹配、复核日期未过期的资源可投影；过期联系方式绝不自动输出，返回 `RESOURCE_REVIEW_REQUIRED`。
- [x] `policies/risk-rules.yaml` 每条规则有 version/category/level/pattern/negation-window/required context/suggested questions，不含真实客户原话；category使用P0 `SafePolicyKey`，level只序列化 `general|high`。加载后整个approved policy及单条rule materialize为immutable manifest/member `VersionRef`，engine先构造不改字段的P0 `InternalRiskObservation`，`rule_ref`必须命中该closure；confidence/span/lifecycle放组合外壳。Engine 保存触发原话的客户私有 content span ref，不写共享日志。
- [x] 风险对象固定 `client_facing_visibility=never`；repository 只在客户 DB；内部 UI/Tool response 中给咨询师 category/level/evidence/action，绝不混入 reply payload。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_risk_rules.py tests/consultation_kb/unit/test_risk_lifecycle.py tests/consultation_kb/unit/test_regional_resources.py
```

Expected: PASS；提醒持久且人工闭环完整。

---

## Task 6：风险到自然回应目标的不可逆投影

**Files:**

- Create: `consultation_kb/risk/projection.py`
- Create: `consultation_kb/risk/output_guard.py`
- Create: `tests/consultation_kb/unit/test_risk_projection.py`
- Create: `tests/consultation_kb/golden/test_risk_01.py`

**Interfaces produced:** `RiskResponseProjector.to_client_goals`；`ClientReplyOutputGuard.validate`。

- [x] `test_risk_01.py` 使用模块级 `@pytest.mark.acceptance_id("RISK-01")`。
- [x] 写结构隔离测试：projector 输入内部 observation，输出只含自然目标枚举，如 `check_immediate_safety`、`invite_real_world_support`、`offer_reviewed_resource`、`maintain_conversation`，不含 category/level/rule/alert text/trigger quote。
- [x] 写 `RISK-01`：尝试把内部对象直接传 reply model/FinalTurnBundle，Pydantic 类型拒绝；来访者候选中出现内部标签、级别、规则 ID、“系统告警”等泄漏词，output guard 阻断；自然询问“你现在是否安全”允许。
- [x] 写一般/高关注 goldens：对外仍是正常、自然、尊重自主性的回应；高关注可自然确认安全、现实支持和合适帮助，但没有机器风险提示；内部 bundle 始终显示观察直到确认。
- [x] projector 是 allowlist 映射，不把内部自由文本复制到 client goals；approved regional resource 只以独立 public text ref 注入。OutputGuard 结合 Schema field allowlist、内部 token canary 和确定性 phrase rules；不以删词方式修补，发现泄漏要求重新生成。
- [x] FinalTurnBundle 分为 `counselor_internal`、`client_reply_candidates`、`follow_up_guidance`、`evidence_quality` 四个 sibling；风险对象只能在 counselor_internal，序列化 client candidate 时使用独立模型。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_risk_projection.py tests/consultation_kb/golden/test_risk_01.py
```

Expected: PASS；风险标签泄漏率在确定性集合为 0。

---

## Task 7：MCP generation stage 工具与 Skill 流程

**Files:**

- Create: `consultation_kb/mcp/generation_tools.py`
- Modify: `consultation_kb/mcp/server.py`
- Modify: `consultation_kb/mcp/schemas.py`
- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Modify: `.agents/skills/consultation-session/SKILL.md`
- Create: `tests/consultation_kb/unit/test_generation_mcp.py`
- Create: `tests/consultation_kb/integration/test_generation_worker_boundary.py`
- Modify: `tests/consultation_kb/unit/test_project_instructions.py`

**Interfaces produced:** MCP `submit_generation_stage/get_generation_state/acknowledge_risk_observation`；同名严格 worker operations；完整 Codex 多阶段流程。

- [x] Handler 测试：stage payload 与 session/turn/evidence hash 绑定；越序、伪造 evidence、其他 session、超过 retry、内部 risk 注入 client reply 全拒绝。
- [x] `worker_main.py` 显式注册 P6 operations，request只含 session/turn handles与结构化 payload，无 client/path/sql；真实 subprocess测试证明 generation/risk/session DB与客户 CAS只在 scoped worker打开。
- [x] Skill 明确每轮顺序：append turn → temp facts → query plan → parallel retrieval → conceptualization → theory comparison → reply drafts → evidence audit → consistency/risk review → final synthesis → counselor choice → record actual reply。
- [x] Skill 要求生成 2–3 个核心一致、策略不同版本；输出内部依据但 client text 无引用/风险标签；若不足/冲突明确交咨询师判断。不得声称多子代理是安全边界。
- [x] 第一阶段不导入 `openai` SDK、不读取 API key、不从 MCP 主动调用托管模型；测试扫描 dependencies/imports。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_generation_mcp.py tests/consultation_kb/unit/test_project_instructions.py tests/consultation_kb/integration/test_generation_worker_boundary.py
```

Expected: PASS；Skill 与 stage machine/tool names 完全一致。

---

## Task 8：P6 端到端回答、C1、一致性与 RISK 验收

**Files:**

- Create: `tests/consultation_kb/integration/test_generation_pipeline.py`
- Create: `tests/consultation_kb/golden/test_c1_generation_cases.py`
- Create: `tests/consultation_kb/golden/test_consistency_cases.py`
- Create: `tests/consultation_kb/golden/test_professional_boundaries.py`

**Interfaces consumed:** P4 EvidencePack；P5 session/MCP；P6 stages/risk。

- [x] 使用 deterministic fake Codex stage outputs 跑完整管线，包含适用 C1、范围外 C1、C1/C2 冲突、事实变化、证据不足、高关注风险各一例。
- [x] 断言重要主张支持、多回复核心一致、结论变化解释、C1 双轴/适用边界、反证披露、有限 retry、风险内部持续/对外零标签。
- [x] 禁止性 goldens：诊断、危险建议、受害者归因、国学医学化、单案例普遍化、强化妄想/控制判断、忽略事实冲突全部 blocking。
- [x] 经真实 MCP STDIO 提交完整 stages，验证响应 envelope 和私有存储；之后记录实际回复，未采用 candidates 不成为 actual。
- [x] Run P6 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_generation_contracts.py tests/consultation_kb/unit/test_generation_stage_store.py tests/consultation_kb/unit/test_query_planning.py tests/consultation_kb/unit/test_conceptualization.py tests/consultation_kb/unit/test_generation_theory_policy.py tests/consultation_kb/unit/test_reply_drafts.py tests/consultation_kb/unit/test_evidence_audit.py tests/consultation_kb/unit/test_consistency_review.py tests/consultation_kb/unit/test_risk_rules.py tests/consultation_kb/unit/test_risk_lifecycle.py tests/consultation_kb/unit/test_risk_projection.py tests/consultation_kb/unit/test_generation_mcp.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_risk_01.py tests/consultation_kb/golden/test_c1_generation_cases.py tests/consultation_kb/golden/test_consistency_cases.py tests/consultation_kb/golden/test_professional_boundaries.py tests/consultation_kb/integration/test_generation_pipeline.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_turn_01.py tests/consultation_kb/integration/test_mcp_stdio.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids RISK-01,THEORY-01,TURN-01
```

Expected: `RISK-01`、生成侧 `THEORY-01`、`TURN-01` 回归通过。

## P6 完成定义

- [x] Codex 多阶段推理有严格顺序、引用和版本，不需要独立 API。
- [x] 多回复策略可不同，核心判断/事实/行动方向一致；改变结论有完整解释。
- [x] 适用 C1 为最高框架但不伪造外部实证、不覆盖硬事实/边界。
- [x] 风险只提示咨询师；来访者回复无标签、级别、规则或系统告警文本。
