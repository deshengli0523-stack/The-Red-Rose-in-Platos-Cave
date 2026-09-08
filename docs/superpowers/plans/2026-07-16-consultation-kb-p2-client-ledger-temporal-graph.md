# P2：客户双时态账本与时态图实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 在每客户 SQLite 中实现不可覆盖的双时态事实事件、四个正交状态轴、六类资料更新操作、当前资料物化、依赖边效应和独立 NetworkX `MultiDiGraph` 时态视图，使已解决/失效/重复信息离开当前上下文但完整历史仍可复现。

**Status (2026-07-19):** 已完成并通过根级复验。计划单元测试 39 项、Golden/集成 19 项、强制验收 18 项通过；扩展安全、worker、fault 集合与全仓复跑无 consultation 回归。Ruff、strict Mypy（19 个生产文件）、compileall、`git diff --check` 通过。全仓为 1380 passed，另有 5 个既有 Windows symlink 测试因当前进程缺少创建符号链接权限失败。

**Architecture:** SQLite fact event log 是唯一真相源；所有修订追加事件，不更新旧正文。正式更新以一个 client publication operation 同时准备 FactEvent、profile与客户图，完整验证后切 client runtime epoch。`BitemporalFactQuery` 按业务时间与系统知情时间重建状态；`DependencyImpactService` 只生成待审核提案；客户 `MultiDiGraph` 从同一快照物化，绝不反向写账本。

**Tech Stack:** sqlite3、Pydantic、NetworkX MultiDiGraph、确定性 canonical JSON、pytest/Hypothesis。

## Global Constraints

- 先完成 P1，读取设计规格第 7.4、9、11.2、14.3、17.1–17.3、21 节。
- 正式事实变化只允许经 P1 一次性批准后追加；P2 单元测试可注入 `ApprovedMutation`，生产入口不能绕过 ApprovalService。
- `review_status`、`validity_status`、`resolution_status`、`epistemic_status` 永远独立；禁止新增万能 `status` 列。
- 当前资料移除不等于删除：resolved/superseded/invalidated/merged member 仍在历史事件与来源链中。
- 图上的路径只能产生失效/复核提案，不能直接修改事实。

---

## Task 1：客户事实迁移与不可变事件仓储

**Files:**

- Create: `consultation_kb/storage/migrations/client/v0002_fact_ledger.py`
- Create: `consultation_kb/storage/client_ledger.py`
- Create: `consultation_kb/models/facts.py`
- Create: `tests/consultation_kb/unit/test_fact_schema.py`
- Create: `tests/consultation_kb/unit/test_fact_repository.py`

**Interfaces produced:** `FactEvent`、`FactMutation` 判别联合、`FactEventRepository.append/list_events/current_commit_version`。

- [ ] 写失败测试，证明同一事实可同时是 approved/active/open/uncertain，且旧事件不能更新/删除：

```python
import sqlite3

import pytest


def test_fact_event_is_append_only(client_fact_repo, approved_uncertain_fact) -> None:
    event = client_fact_repo.append(approved_uncertain_fact)
    row = client_fact_repo.connection.execute(
        "SELECT review_status, validity_status, resolution_status, epistemic_status "
        "FROM fact_events WHERE event_id = ?",
        (event.event_id,),
    ).fetchone()
    assert tuple(row) == ("approved", "active", "open", "uncertain")
    with pytest.raises(sqlite3.IntegrityError):
        client_fact_repo.connection.execute(
            "UPDATE fact_events SET epistemic_status='asserted' WHERE event_id=?",
            (event.event_id,),
        )
```

- [ ] 写并发测试：两个 mutation 都以 `base_commit_version=7` 预览，先提交一个后，第二个抛 `StaleFactPreview`；失败不消费/覆盖第一笔事件。
- [ ] v0002 创建：`fact_events`、`fact_evidence`、`fact_dependencies`、`fact_merge_members`、`profile_revisions`、`profile_members`、`session_fact_events`。fact/profile revision同时带 `publication_operation_id` 与 `visible_runtime_epoch`；为 `fact_events` 增加 `BEFORE UPDATE/DELETE` trigger 直接 `RAISE(ABORT, 'fact_events are append-only')`。
- [ ] `fact_events` 包含设计规格 9.4 的全部字段；`object_json`、用途与适用范围使用 canonical JSON；`canonical_key` 单独索引；四轴各自 CHECK；`effective_to > effective_from`。咨询派生事实强制非空 `source_session_id/source_turn_id/reported_at` 或 `observed_at`；非会谈导入必须使用互斥的受控 `source_kind` + source ref，不能以一组空 FK 代替来源。DB CHECK 与 Pydantic validator测试所有 cognitive type 的必填/互斥组合。
- [ ] `FactMutation` 是 `ADD/CONFIRM/CORRECT/SUPERSEDE/RESOLVE/MERGE` 的 Pydantic 判别联合，每个操作有精确必填字段。CORRECT 的 `correction_kind=value/time/validity` 决定字段；validity correction只允许追加 invalidated事件且不能改旧值。MERGE 要求至少两个 member 和无冲突证明。
- [ ] repository 仅由 scoped worker 调用；在一个 `BEGIN IMMEDIATE` 中由 `ApprovalExecutionGuard` 核对 base commit/receipt/operation，写事件、依赖、审核决定与 PREPARED manifests并增加 authority commit。新事件在 runtime epoch 激活前对 current query不可见；返回 operation/new commit/event refs，不返回路径。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_fact_schema.py tests/consultation_kb/unit/test_fact_repository.py
```

Expected: PASS；update/delete trigger 生效，乐观冲突无半写。

---

## Task 2：六类原子更新操作与来源保全

**Files:**

- Create: `consultation_kb/client/__init__.py`
- Create: `consultation_kb/client/mutations.py`
- Create: `consultation_kb/client/normalization.py`
- Create: `tests/consultation_kb/unit/test_fact_mutations.py`
- Create: `tests/consultation_kb/unit/test_fact_merge.py`

**Interfaces produced:** `FactMutationService.preview/commit`；`CanonicalFactKey`；`DuplicateCandidate`。

- [ ] 对每个操作写失败测试和状态转换表：

| 操作 | 新事件结果 | 旧事件的历史解释 | 必须拒绝 |
|---|---|---|---|
| ADD | 新 fact active | 无 | 相同 canonical key 的无审核重复 |
| CONFIRM | 同 fact 新证据/置信度事件 | 旧证据保留 | 改值或时间 |
| CORRECT | 同 fact 新版本 | 旧版本保留为错误历史 | 不声明旧值/理由 |
| SUPERSEDE | 新 fact/version active | 旧值在新快照为 superseded | 自己取代自己、时间倒置 |
| RESOLVE | resolution=resolved | 问题历史保留 | 抹除事实有效性 |
| MERGE | 新 canonical projection | member 原文/来源全保留 | 冲突值、不同作用域强并 |

`INVALIDATE` 不新增为第七种顶层操作：无替代值的失效使用 `CORRECT(correction_kind="validity", new_validity_status="invalidated")`，必须给 target、旧状态、理由、effective time与来源；有替代事实仍使用 `SUPERSEDE`。

- [ ] 写规范化测试：NFKC、空白/全半角、日期/角色别名确定性；实体+谓词+规范值+有效时间+作用域生成 key。相似但冲突的“现伴侣甲/乙”只能进入冲突队列，不能作为重复合并。
- [ ] 写来源链测试：MERGE 后 `fact_merge_members` 包含全部原始 event、session、turn 和时间；当前 profile 只显示一个 canonical 项，history query 仍返回每个 member。
- [ ] `preview` 输出机器可读 mutation、旧/新值、人类可读 diff、直接依赖/重复/冲突候选和 P1 `DraftDescriptor`；不写正式表。`commit` 只能消费匹配批准并再次核对 base commit。
- [ ] CONFIRM 只增加支持来源或校准置信度；CORRECT 记录纠正发生的系统时间而不篡改原 recorded_at；SUPERSEDE/RESOLVE 用新事件表达状态变化；MERGE 建 projection 关系，不删除 member。
- [ ] 置信度更新规则版本化：人工明确确认可设人工分值；多个独立来源组合使用固定 policy 函数；不能把模型抽取置信度当事实置信度。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_fact_mutations.py tests/consultation_kb/unit/test_fact_merge.py
```

Expected: 六类操作和所有拒绝路径通过。

---

## Task 3：双时态查询与四轴独立过滤

**Files:**

- Create: `consultation_kb/client/bitemporal.py`
- Create: `tests/consultation_kb/unit/test_bitemporal_query.py`
- Create: `tests/consultation_kb/golden/test_fact_01.py`

**Interfaces produced:** `FactQuery(effective_at, known_at, axis filters)`；`BitemporalFactQuery.execute/snapshot`。

- [ ] `test_fact_01.py` 使用模块级 `@pytest.mark.acceptance_id("FACT-01")`；普通 bitemporal 单元测试不得冒充该验收。
- [ ] 写核心历史测试：系统 7 月 16 日才获准知晓“7 月 1 日已经分手”。查询 `effective_at=7月5日, known_at=7月10日` 仍显示旧认知；相同 effective、`known_at=7月16日后` 显示纠正后状态。
- [ ] 增加两个选择顺序回归：已知但未来才生效的新版本不能让较早 `effective_at` 返回空，应回到仍适用旧版本；追溯纠正在较晚 `known_at` 查询较早业务时间时应选择纠正版本，而较早 `known_at` 仍选原认知。
- [ ] 写四轴 property test：对四个轴分别改变过滤器，只影响该轴；不传某轴表示不按该轴过滤，不能由一个默认 status 隐式排除 uncertain/disputed。
- [ ] 写 `FACT-01` 金标准：一条 approved/active/open/uncertain 事实必须在相应过滤器命中；改为 asserted filter 时不命中；历史快照 JSON 在同一 effective/known 时间逐字节稳定。
- [ ] 查询算法先同时筛选 `recorded_at <= known_at`、`approved_at <= known_at`、`visible_runtime_epoch <= fixed_epoch` 且业务有效窗口包含 `effective_at` 的事件，再在这些合格版本中按 `(approved_at, recorded_at, event_version)` 选每个 fact 最新；禁止“先选最新再过滤业务时间”。系统时间结束由下一版本 recorded/approved 时间推导，不能覆盖旧 row。
- [ ] `snapshot` 保存 query 参数、client commit version、event ID 有序列表和 canonical hash；`known_at` 同时约束 `recorded_at` 与 `approved_at`，未在该知识时点批准的事件不可见；同一参数结果确定性排序 `(subject, predicate, effective_from, fact_id)`。
- [ ] 通用查询服务允许显式选择四轴；`ProfileMaterializer` 的 current 默认只选 approved + active + open，并把 asserted/uncertain/disputed 分区呈现。resolved 只在显式历史/诊断查询中返回，生成侧不可能把 uncertain 丢掉标签后当 asserted。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_bitemporal_query.py tests/consultation_kb/golden/test_fact_01.py
```

Expected: PASS；两个时间轴和四状态轴完全独立。

---

## Task 4：当前资料 JSON/Markdown 物化与历史版本

**Files:**

- Create: `consultation_kb/client/profile.py`
- Create: `consultation_kb/models/profile.py`
- Create: `tests/consultation_kb/unit/test_profile_materializer.py`
- Create: `tests/consultation_kb/golden/profile_current.json`
- Create: `tests/consultation_kb/golden/profile_current.md`

**Interfaces produced:** `ProfileMaterializer.build/prepare_publish`；`ProfileSnapshot`；稳定 JSON/Markdown renderer。

- [ ] 写失败测试：current profile 只显示 approved/active 当前综合结果；resolved、superseded、invalidated 和 merge member 从 current 移除，但 `source_event_ids`/history revision 全保留。
- [ ] 写 ordering test：目标、未解决事项、关系、偏好、约束、有效事实、不确定/争议、待复核固定顺序；相同快照重复渲染 bytes 相同。
- [ ] 写 stale preview 测试：profile 基于 commit 8 构建，提交前事实库到 commit 9，prepare/activate 拒绝并要求重建，不发布过期视图。
- [ ] `ProfileSnapshot` 不是自由摘要，包含每个 section 的结构化 fact ref、认知类型、四轴、置信度、业务/系统时间和最小来源；Markdown 仅为该 JSON 的人类视图。
- [ ] materializer 从“base active snapshot + proposed mutation”的预期 `BitemporalSnapshot` 构建，不能解析旧 Markdown 作为输入；JSON/MD 与客户图先写同一 client publication operation 的 PREPARED manifests。只有事实事件、审核执行、profile、graph closure全部验证后才切 runtime epoch；不得先让新事实可见再异步补 profile。
- [ ] current profile 对 resolved/superseded/重复项零显示；history 目录保留旧 immutable object ref。回滚在 P8 以新反向事件实现，不能直接把指针倒回后假装事实从未发生。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_profile_materializer.py
```

Expected: PASS；golden JSON/MD 稳定且来源完备。

---

## Task 5：依赖边、直接失效与间接复核

**Files:**

- Create: `consultation_kb/client/dependencies.py`
- Create: `consultation_kb/models/dependencies.py`
- Create: `tests/consultation_kb/unit/test_dependency_impact.py`

**Interfaces produced:** `DependencyRepository`；`DependencyImpactService.preview`；`ImpactProposal`。

- [ ] 写伴侣变化测试：

```python
def test_partner_change_splits_direct_and_indirect_impact(impact_service, partner_fixture) -> None:
    proposal = impact_service.preview(partner_fixture.supersede_current_partner)
    assert {item.fact_id for item in proposal.direct_invalidations} == {
        partner_fixture.weekend_plan_fact_id,
        partner_fixture.current_partner_preference_fact_id,
    }
    assert {item.fact_id for item in proposal.manual_reviews} == {
        partner_fixture.communication_pattern_fact_id,
        partner_fixture.attachment_hypothesis_fact_id,
    }
    assert proposal.applied_mutations == ()
```

- [ ] 写传播测试：直接确定依赖有替代事实时建议 `SUPERSEDE`，无替代值时建议 `CORRECT(correction_kind="validity", new_validity_status="invalidated")`；间接或模型推断边只生成 `REVIEW`，即使路径短也不自动删除。循环依赖必须终止并保留最强/最短解释路径。
- [ ] 写批准失效完整测试：批准 validity correction → 追加 invalidated事件 → 新 epoch current profile/graph移除 → 旧 epoch/history仍能验证；不得 SQL UPDATE/DELETE 或发明第七种 mutation。
- [ ] 写置信度测试：`path_confidence = product(edge_confidence) * 0.85 ** inferred_hops`，每个 proposal 保存 policy version、路径 edge IDs 和分类理由；不得把结果写回原事实置信度。
- [ ] `fact_dependencies` 区分 `direct_deterministic`、`direct_conditional`、`indirect_inferred`，保存来源与 reviewer；只有第一类可产生自动建议，但仍需咨询师批准 commit。
- [ ] 变化预览包含旧值、新值、受影响 fact、完整依赖路径、建议操作、置信度和“保留为历史/进入复核”的理由；相同输入按 fact/edge ID 稳定排序。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_dependency_impact.py
```

Expected: PASS；无任何 impact preview 自动应用 mutation。

---

## Task 6：独立客户 MultiDiGraph 物化与时态查询

**Files:**

- Create: `consultation_kb/client/temporal_graph.py`
- Create: `consultation_kb/client/graph_query.py`
- Create: `consultation_kb/client/graph_serialization.py`
- Create: `tests/consultation_kb/unit/test_temporal_graph.py`
- Create: `tests/consultation_kb/unit/test_client_weighted_path.py`
- Create: `tests/consultation_kb/unit/test_client_graph_boundary.py`

**Interfaces produced:** `TemporalGraphBuilder.build(snapshot)`；`TemporalGraphQuery.edges_at/weighted_paths`；deterministic serialization。

- [ ] 写 `GRAPH-01` 客户侧测试：同一 Client/PersonRole 之间写当前关系、历史关系、多个来源支持边；`MultiDiGraph.number_of_edges(u,v)` 保留全部；指定业务/系统时点只返回有效 edge。
- [ ] 写禁止调用测试，AST 扫描 `consultation_kb/client` 不得导入 `graphify.build`、`graphify.serve`、`graphify.wiki`；对 NetworkX shortest-path API采用 allowlist，禁止 `shortest_path*`、`dijkstra_*`、`bidirectional_dijkstra`、`all_shortest_paths` 及 `networkx.algorithms.shortest_paths` 绕过自研来源感知多边查询器。行为测试以平行支持/反证边、时态过滤与最大 hop 为主防线。
- [ ] 写 weighted path 测试：只用已批准、在两个时间轴有效的 edge；边代价由直接性、认知类型、审核、置信度、时间和 hop penalty 构成；输出每条 edge 的 fact/source/限制。
- [ ] Builder 只消费 `BitemporalSnapshot` 和 dependency rows，创建设计规格 9.2/9.3 节节点/关系；edge key 固定为 `edge_id`，绝不让 NetworkX 默认 key 造成覆盖。
- [ ] Graph JSON 是派生物，包含 `publication_operation_id`、`source_client_commit_version`、runtime epoch、query effective/known time、builder policy version、node/edge 有序列表与 hash；与 fact/profile一起通过 P1 publication closure 激活。加载时版本不符 fail closed，不从图反向更新账本。
- [ ] weighted path 使用自实现 Dijkstra/A* 权重函数并显式过滤 edge；返回 top-k simple paths，固定 tie-breaker `(total_cost, edge_id_sequence)`，有循环时限制最大 hops。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_temporal_graph.py tests/consultation_kb/unit/test_client_weighted_path.py tests/consultation_kb/unit/test_client_graph_boundary.py
```

Expected: PASS；多边不覆盖，指定时点结果稳定。

---

## Task 7：P2 伴侣变化垂直切片与强制验收

**Files:**

- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Create: `tests/consultation_kb/integration/test_client_profile_lifecycle.py`
- Create: `tests/consultation_kb/integration/test_client_worker_fact_boundary.py`
- Create: `tests/consultation_kb/integration/test_client_publication_atomicity.py`
- Create: `tests/consultation_kb/golden/test_graph_01_client.py`
- Create: `tests/fixtures/consultation_kb/client_partner_change.json`

**Interfaces consumed:** P1 批准/发布/scope；P2 mutation/query/profile/dependency/graph。**Interfaces produced:** worker operations `query_fact_snapshot`、`preview_fact_mutation`、`commit_fact_mutation`（提交完整 fact/profile/graph publication）、`query_profile_snapshot`、`query_client_graph`、`preview_dependency_impact`。

- [ ] `test_graph_01_client.py` 使用模块级 `@pytest.mark.acceptance_id("GRAPH-01")`，作为 registry 的 required primary module。
- [ ] fixture 使用纯合成 A：初始当前伴侣甲、依赖甲的周末安排、一般沟通模式；随后在 7 月 16 日批准得知 7 月 1 日已分手且当前伴侣乙。
- [ ] 集成测试按真实服务顺序执行：预览 ADD/批准/commit publication → 同 epoch profile/graph v1 → 预览 SUPERSEDE + impact → 批准/commit publication → 同 epoch profile/graph v2。
- [ ] 扩展 P1 registry：每个 P2 operation 有 frozen request/response且不含 client/path/sql；`worker_main.py` 显式注册。真实 subprocess 测试记录 PID，证明 client repository/DB/CAS只在 scoped worker 打开；control-plane production composition若直接实例化 `FactEventRepository`/client connection则架构测试失败。
- [ ] exception-injection遍历权威事件事务、profile finalize、graph finalize、PREPARED、verify和epoch切换；查询只能看到完整 v1或完整 v2。P8 对相同 named points执行真实 kill。
- [ ] 断言 v2 current 只显示乙；v1/v2 历史都可验证；旧伴侣边变 historical；直接依赖进入失效提案；一般模式/假设只进入人工复核；没有 proposal 被自动提交。
- [ ] 重跑 `FACT-01` 和客户侧 `GRAPH-01`，再重跑 P1 `ISO-01/WRITE-01`，证明账本扩展没有打开跨客户或写绕过。
- [ ] Run P2 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_fact_schema.py tests/consultation_kb/unit/test_fact_repository.py tests/consultation_kb/unit/test_fact_mutations.py tests/consultation_kb/unit/test_fact_merge.py tests/consultation_kb/unit/test_bitemporal_query.py tests/consultation_kb/unit/test_profile_materializer.py tests/consultation_kb/unit/test_dependency_impact.py tests/consultation_kb/unit/test_temporal_graph.py tests/consultation_kb/unit/test_client_weighted_path.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_fact_01.py tests/consultation_kb/golden/test_graph_01_client.py tests/consultation_kb/integration/test_client_profile_lifecycle.py tests/consultation_kb/integration/test_iso_01.py tests/consultation_kb/integration/test_write_01.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids FACT-01,GRAPH-01,ISO-01,WRITE-01
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
```

Expected: 全部通过；`FACT-01` 和客户侧 `GRAPH-01` 成立，上游无回归。

## P2 完成定义

- [ ] 两个时间轴、四个状态轴、六类操作和乐观版本冲突均有确定性测试。
- [ ] current profile 删除已解决/失效/被取代/重复展示，但历史、来源和审核决定完整。
- [ ] 伴侣变化的直接影响只生成失效提案，间接模式只进入复核。
- [ ] 客户 MultiDiGraph 是可重建派生视图，未调用上游无权/单边查询器。
- [ ] 新事实、profile与客户图只在一个完整 runtime epoch可见；所有客户 DB/CAS访问只发生在 scoped worker。
