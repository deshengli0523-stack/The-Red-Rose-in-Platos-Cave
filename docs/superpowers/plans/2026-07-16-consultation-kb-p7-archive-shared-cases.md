# P7：双份归档、共享案例与全谱系排除实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 会谈结束时可靠保存客户私有完整实际记录，生成可独立审核的结构化客户资料差异和可选共享脱敏案例；共享案例具备复用授权、去标识化、outbox/saga、传递性来源谱系和 leave-one-client-out，使任何客户都不会被自己的案例或其派生物举例。

**Status:** 已完成（功能提交 `7879f0b`，2026-07-19）。以下 Task 复选框保留为原始范围与验收清单；阶段完成状态以本行、完成定义和总实施计划为准。

**Architecture:** P5 `ActualTranscript` 是不可拒绝的已发生源记录；P7从中生成可修改/拒绝的 `PrivateArchiveDraft`。`archive_bundle_id` 只关联私有归档、profile diff、共享案例三种目的，不把它们做成单一成败事务。前两者属于客户库；共享 candidate由客户 outbox交给 global publisher，只有 global ACTIVE manifest可检索。每个共享/派生对象保存受控 provenance closure；查询前按 current client排除或替换为经审核的 LOO版本。

**Tech Stack:** P5 actual session log、P2 fact/profile diff、P1 manifest/approval、SQLite outbox/saga、P4 filters/indexes、deterministic deidentification + human review、pytest/fault injection。

## Global Constraints

- 先完成 P6；读取设计规格第 3.2、7.4、8.3、12.3、14、17、18 中撤回传播、19 节。
- 私有会谈记录只保存实际来访者消息与实际回复；候选/分析可另存受治理工件，但不能伪装成发生过的对话。
- profile diff 与共享案例完全独立；无授权/脱敏失败/拒绝共享不能阻塞合法资料更新。
- source client ID 只存受控 global catalog provenance，不写案例正文、Wiki 正文、embedding text、对外示例或共享日志。
- 自案例排除必须覆盖 Case、CasePattern、Claim、Wiki、图 edge、BM25/char、vector 和 reranker 输入，不只过滤最终案例列表。
- P7 新增唯一、窄化的 `case_leave_one_out_variants` 权威映射：exact parent ref + excluded-client hash 唯一指向 approved exact variant/authority manifest/provenance/minimum independent-source count。普通 Source/Passage/Claim 字段继续以既有表为唯一权威，不新增通用 `retrieval_candidates` 表；P4 期间没有该映射的 LOO 一律不可用。

---

## Task 1：归档 bundle 与实际私有会谈记录

**Files:**

- Create: `consultation_kb/storage/migrations/client/v0005_archive.py`
- Create: `consultation_kb/models/archive.py`
- Create: `consultation_kb/archive/__init__.py`
- Create: `consultation_kb/archive/private_record.py`
- Create: `consultation_kb/archive/private_review.py`
- Create: `consultation_kb/archive/bundles.py`
- Create: `tests/consultation_kb/unit/test_private_archive.py`
- Create: `tests/consultation_kb/unit/test_private_archive_review.py`
- Create: `tests/consultation_kb/unit/test_archive_bundle.py`

**Interfaces produced:** `ArchiveBundleService.propose`；`ActualTranscriptReader.snapshot`；`PrivateArchiveDraftBuilder.build`；`PrivateArchiveReviewService.preview/approve_modified/reject/commit`；三目的独立状态。

- [ ] 写失败测试：有未关闭 turn 时不能结束；`external_reply_unknown` 可结束但 bundle `incomplete_evidence=true`；候选回复不在 actual transcript。

```python
def test_private_archive_contains_only_actual_replies(
    session_with_candidates, valid_turn_id, valid_candidate_id,
) -> None:
    session_with_candidates.record_actual_reply(
        turn_id=valid_turn_id, candidate_id=valid_candidate_id,
    )
    bundle = PrivateArchiveDraftBuilder(session_with_candidates.repository).build(
        session_with_candidates.session_id,
    )
    assert [item.reply_text for item in bundle.turns] == [session_with_candidates.candidate_text(valid_candidate_id)]
    assert session_with_candidates.unselected_candidate_text not in bundle.canonical_text
```

- [ ] 写两层记录测试：P5 ActualTranscript在每轮 actual reply后已经持久化且不可由归档拒绝删除；PrivateArchiveDraft包含情绪/目标变化、干预解释、理论/证据/局限与复盘，必须 preview并使用 `purpose=private_archive_publish` 独立批准。拒绝/修改draft时 actual transcript保持，未批准分析不进入下一次 client-history。
- [ ] 写用途状态测试：`private_archive/profile_diff/shared_case` 各自 `DRAFT/PREPARED/ACTIVE/REJECTED/NO_CHANGE/PRIVATE_ONLY` 合法子集；一个失败不改变另两个状态。ActualTranscript不属于可拒绝的三目的状态。
- [ ] v0005 创建/扩展 `archive_bundles`、`private_archive_revisions`、`archive_purpose_states`、`profile_diff_drafts`、`shared_case_candidates`、`outbox_events`。目的 state、manifest 和 review decision 分别外键关联。
- [ ] ActualTranscript只按 turn顺序引用 actual messages/replies和external unknown gap。PrivateArchiveDraft另含情绪/目标变化refs、关键事件、实际干预、来访者反应、理论/证据/局限和复盘；模型分析与 counselor reflection明确不同 section。
- [ ] PrivateArchiveReviewService展示 actual-vs-analysis边界和diff；target client事务执行批准并以 client manifest发布到客户CAS。实际 session source永不由私有归档或共享发布替换；archive audit只存refs/hash。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_private_archive.py tests/consultation_kb/unit/test_private_archive_review.py tests/consultation_kb/unit/test_archive_bundle.py
```

Expected: PASS；actual transcript 忠实，private archive analysis 仅在独立批准后生效。

---

## Task 2：结构化 profile diff、去重/失效和边效应复核

**Files:**

- Create: `consultation_kb/archive/profile_diff.py`
- Create: `consultation_kb/archive/profile_review.py`
- Create: `tests/consultation_kb/unit/test_profile_diff.py`
- Create: `tests/consultation_kb/unit/test_profile_review.py`
- Create: `tests/consultation_kb/golden/profile_diff_partner_change.json`

**Interfaces produced:** `ProfileDiffBuilder.build`；`ProfileDiffReviewService.preview/approve_partial/reject/no_change`。

- [ ] 写 diff 测试，必须包含 ADD/CONFIRM/CORRECT/SUPERSEDE/RESOLVE/MERGE、旧/新值、source turn/reason、direct impacts、indirect reviews、current-view removals、更新后目标/未解决/偏好/约束和最小下次摘要。
- [ ] 使用伴侣变化 golden：旧伴侣相关当前事实 SUPERSEDE；直接依赖的当前安排建议失效；更一般沟通/依恋模式只 review；历史事件保留；重复表达 MERGE；本次已解决事项 RESOLVE。
- [ ] 写数据污染测试：未采用 candidate、模型 hypothesis、external unknown reply 不得成为长期 fact evidence；来访者新陈述只能按 cognitive type 提议，不能自动 approved objective fact。
- [ ] 写 partial approval：咨询师可修改/批准部分操作，拒绝间接失效，或选择 no_change；base profile/session hash 变化全部 stale。
- [ ] Builder 输入固定 session actual record、temporary ledger、base profile 和 P2 dependency preview；它只产生 P2 `FactMutation` drafts，不写事实。summary 是从更新后 profile projection 生成的最小信息，而不是会谈摘要无限追加。
- [ ] ReviewService 显示每项 diff/影响路径/置信度/保留历史理由，生成 P1 approval descriptor；commit调用 P2 `commit_fact_mutation` worker operation，在一个 client publication operation准备/验证事实事件、profile与graph并切 runtime epoch，不能先写事实再补派生物。
- [ ] profile commit 成功/失败与 shared case 状态无关；测试故意使共享 case 失败，profile 仍可 ACTIVE。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_profile_diff.py tests/consultation_kb/unit/test_profile_review.py
```

Expected: PASS；当前资料移除失效/重复/已解决，历史完整。

---

## Task 3：共享 candidate、复用授权与去标识化审核

**Files:**

- Create: `consultation_kb/models/cases.py`
- Create: `consultation_kb/archive/deidentification.py`
- Create: `consultation_kb/archive/release_policy.py`
- Create: `consultation_kb/archive/shared_candidate.py`
- Create: `tests/consultation_kb/unit/test_deidentification.py`
- Create: `tests/consultation_kb/unit/test_case_release_policy.py`
- Create: `tests/consultation_kb/unit/test_shared_candidate.py`

**Interfaces produced:** `Deidentifier.scan/transform`；`CaseReleasePolicy.evaluate`；`SharedCaseCandidateBuilder`。

- [ ] 写 deidentification 测试：姓名/电话/邮箱/身份证/精确地址/单位/日期，以及第三方人物、罕见地点+职业+家庭结构+时间组合；报告保存 rule、span hash、替代类型，不在共享报告复制原文。
- [ ] 写过度删除测试：常见关系角色、问题轨迹和干预顺序应保留可用性；自动替换与模型建议都必须人工复核，不能自称保证匿名。
- [ ] 写 release matrix：`reuse_authorized=true`、授权版本、用途、有效期、未撤回、自动+人工脱敏完成、第三方/稀有组合检查、事实/实际回复/模型分析/复盘分区、provenance/grade/scope 完整时才 eligible。
- [ ] 写 `CASE-02` 基础：false/expired/revoked 为 `private_only`，不能产生 global outbox publish；profile diff 路径仍通过。
- [ ] candidate 只从 private actual record 派生，保存事实、实际回复、analysis、reflection 各自类型；不复制 candidates 未采用内容。source client/session 只在客户库和后续受控 catalog metadata。
- [ ] 自动 scan 通过不等于 publish approval；人类 review decision 必填 checked categories、residual risk、allowed uses/expiry。rare-combination finding 未处置时进入 `quarantine`。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_deidentification.py tests/consultation_kb/unit/test_case_release_policy.py tests/consultation_kb/unit/test_shared_candidate.py
```

Expected: PASS；不合格 candidate 为 private_only/quarantine。

---

## Task 4：global cases Schema 与 outbox/saga 发布

**Files:**

- Create: `consultation_kb/storage/migrations/global/v0005_cases.py`
- Create: `consultation_kb/storage/outbox.py`
- Create: `consultation_kb/archive/case_publisher.py`
- Create: `consultation_kb/archive/case_catalog.py`
- Create: `tests/consultation_kb/unit/test_outbox.py`
- Create: `tests/consultation_kb/integration/test_case_publish_saga.py`

**Interfaces produced:** `OutboxRepository`；`SharedCasePublisher.process/replay`；global `CaseCatalog`。

- [ ] 写 saga 状态测试：source client transaction 写 approval result + candidate hash + outbox；global worker copy 到 invisible staging → validate authorization/provenance/deidentification → PREPARED → ACTIVE；每步可幂等重入。
- [ ] 写原子可见测试：只有 source client approved 不足以被 global search 看见；只有 global ACTIVE manifest 可见；global query 绝不打开 source `client.sqlite3`。
- [ ] 写故障测试（P7 进程内 exception，P8 再 kill process）：copy 前/后、catalog prepare 前/后、activate 前/后；旧 global active 或完整新 active，不能 partial。
- [ ] v0005 创建 `cases`、`case_versions`、`case_authorizations`、`case_review_decisions`、`case_provenance`、`case_patterns`、`leave_one_out_variants`、`global_publish_sagas`；正文只保存 global content ref。
- [ ] source outbox payload 不含明文正文，只含 sealed candidate ref/hash、authorization/review IDs、provenance refs、idempotency key。Publisher 在受控 transfer scope 读取并复制，之后 global 检索只用 global copy。
- [ ] activation 后回写 source outbox `published_global_version` 失败可重试，不影响 global truth；同 event 重放不创建重复 case/version。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_outbox.py tests/consultation_kb/integration/test_case_publish_saga.py
```

Expected: PASS；无双库分布式半提交。

---

## Task 5：传递性谱系与 leave-one-client-out 派生

**Files:**

- Create: `consultation_kb/archive/provenance.py`
- Create: `consultation_kb/archive/leave_one_out.py`
- Create: `tests/consultation_kb/unit/test_case_provenance.py`
- Create: `tests/consultation_kb/unit/test_leave_one_out.py`

**Interfaces produced:** `CaseProvenanceService.propagate`；`LeaveOneOutBuilder.build/approve`。

- [ ] 写闭包链：Case A/B/C → Pattern → Claim → Wiki section → graph edge → lexical/vector rows；所有对象受控 metadata 继承 `{A,B,C}`，正文/embedding text 不含 ID。
- [ ] 写 LOO 行为：服务 A 时，包含 A 的原版本禁用；重算只使用 B/C 的 variant，保存新的正文/hash/evidence grade/scope，并需人工批准；若剩余来源数/grade 不达 policy，整项排除。
- [ ] 写单客户模式：不能通过简单删除 metadata 伪造成 LOO；A-only Pattern/Claim/Wiki/edge/index 全部排除。
- [ ] 写 independent evidence：Claim 同时有 A case 和独立 T/C source 时，生成去除 A case 支持但保留独立证据的 approved variant，且 evidence grade 重算。
- [ ] provenance closure 每次派生都计算并存 catalog，不能依赖运行时从正文猜；规则版本改变使下游 stale。LOO builder 重新运行原 aggregation/render/index input rule，不做字符串删段。
- [ ] LOO variant 与 excluded client/parent version/remaining evidence/approval/version绑定；P4 CandidateFilter 只替换为 exact matched active variant。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_case_provenance.py tests/consultation_kb/unit/test_leave_one_out.py
```

Expected: PASS；A 贡献不会在 A 查询中残留。

---

## Task 6：案例接入 Wiki/图/词法/向量与撤回零召回

**Files:**

- Create: `consultation_kb/archive/case_indexing.py`
- Modify: `consultation_kb/retrieval/filters.py`
- Modify: `consultation_kb/retrieval/lexical_builder.py`
- Modify: `consultation_kb/retrieval/vector_builder.py`
- Modify: `consultation_kb/graph/global_builder.py`
- Create: `tests/consultation_kb/integration/test_case_01_full_lineage.py`
- Create: `tests/consultation_kb/integration/test_case_02_authorization.py`

**Interfaces produced:** approved case/pattern 派生管线；授权撤回 → tombstone → rebuild queue。

- [ ] 模块级 marker：`test_case_01_full_lineage.py → CASE-01`、`test_case_02_authorization.py → CASE-02`。
- [ ] `CASE-01` 构造 A case 依次派生 CasePattern、Claim、Wiki section、graph edge、BM25/char row、vector row，再为 A 查询；spy 检查每个 channel、fusion、reranker 和 final pack，A contribution 为零或使用 approved LOO。
- [ ] `CASE-02` 覆盖授权 false/expired/revoked：global case 不 active；撤回先写 global tombstone，立即所有通道零召回，再排 rebuild。profile update 独立成功。
- [ ] 写 B 查询：授权 active 且 scope 适用时 B 可检索；正文不暴露 A ID/rare attributes；case 只能证明该案例记录和经审核 pattern，不宣称普遍有效。
- [ ] A 级 RED：先运行全谱系排除与授权测试，确认在 case indexing 尚未接入时按预期失败：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_case_01_full_lineage.py tests/consultation_kb/integration/test_case_02_authorization.py
```

Expected: case indexing not connected/failures.

- [ ] CaseIndexingService 为每个 artifact 写 provenance closure、authorization version、allowed uses/expiry/source catalog version；通过 P3 invalidation/P4 builders 发布。current-client ID 永不进入 index text。
- [ ] 过滤顺序先 tombstone/authorization，再 provenance/LOO，再 resolver；reranker 只接收 allowed text。撤回不等全量 rebuild，tombstone 同事务立即生效。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_case_01_full_lineage.py tests/consultation_kb/integration/test_case_02_authorization.py
```

Expected: `CASE-01/02` PASS；A 自案例全谱系零泄漏。

---

## Task 7：归档 MCP 工具与独立批准流程

**Files:**

- Create: `consultation_kb/mcp/archive_tools.py`
- Modify: `consultation_kb/mcp/server.py`
- Modify: `consultation_kb/mcp/schemas.py`
- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Modify: `.agents/skills/consultation-session/SKILL.md`
- Create: `tests/consultation_kb/unit/test_archive_mcp.py`
- Create: `tests/consultation_kb/integration/test_archive_worker_boundary.py`

**Interfaces produced:** MCP `propose_archive`、`preview_private_archive`、`commit_private_archive`、`preview_profile_diff`、`commit_profile_update`、`approve_case`；worker operations `build_private_archive`、`commit_private_archive`、`build_profile_diff`、`commit_profile_update`、`stage_shared_case_outbox`。

- [ ] MCP 测试：`propose_archive(session_handle)` 返回 archive bundle refs 和三个独立 draft state；`preview_private_archive` 返回 actual/analysis边界与独立 request，`commit_private_archive`只消费 `private_archive_publish` approval；`preview_profile_diff`/`commit_profile_update` 使用另一批准；`approve_case` 再用独立 approval/authorization，三者不共享 token。
- [ ] 无授权 approve_case、篡改脱敏后旧 approval、过期 authorization、错误 bundle/client、模型直接 write 全拒绝；profile commit 仍可执行。
- [ ] `worker_main.py` 显式注册五个严格 archive operations；真实 subprocess测试证明 private archive/profile diff/outbox client DB/CAS只在 worker打开，request无 client/path/sql。global case publisher只消费去标识化 outbox payload，不反向打开 client DB。
- [ ] Skill 结束流程：先补齐未关闭 turn → 确认 ActualTranscript已保存 → 展示/批准或拒绝 PrivateArchiveDraft → 独立展示 profile diff并批准/修改/拒绝/no change → 独立展示共享 candidate/授权/脱敏 → 可选批准。不得把 actual transcript、私有分析归档与共享案例视为同一文件直接复制。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_archive_mcp.py tests/consultation_kb/unit/test_project_instructions.py tests/consultation_kb/integration/test_archive_worker_boundary.py
```

Expected: PASS；写工具保持一次性批准和独立目的。

---

## Task 8：ARCHIVE/TX 垂直验收

**Files:**

- Create: `tests/consultation_kb/golden/test_archive_01.py`
- Create: `tests/consultation_kb/integration/test_archive_end_to_end.py`
- Create: `tests/consultation_kb/fault/test_outbox_saga_exceptions.py`

**Interfaces consumed:** P2 profile/impact；P5 actual session；P7 archive/case/saga/LOO。

- [ ] `test_archive_01.py` 使用模块级 `ARCHIVE-01` marker；`test_outbox_saga_exceptions.py` 使用 `TX-01` marker，作为事务验收 extension。
- [ ] `ARCHIVE-01` 会谈含解决事项、重复事实、伴侣变化、未采用候选、external unknown；断言 actual transcript/private archive/profile diff/shared candidate 各守用途，current profile 移除项正确，间接边未自动删除。
- [ ] 端到端：无复用授权时 private/profile 成功、case private_only；补齐授权和脱敏批准后 global case active，B 可检索，A 全谱系排除；撤回后立即零召回。
- [ ] fault 测试对 saga 每个 Python exception point 重放，断言 outbox 幂等、全局只见完整旧/新。P8 再使用真实 subprocess kill 覆盖文件/SQLite 边界。
- [ ] 重跑 `ISO-01/02`、`WRITE-01`、`TURN-01`、`FACT-01`、`GRAPH-01`、`RISK-01`，因为共享派生物扩大攻击面。
- [ ] Run P7 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_private_archive.py tests/consultation_kb/unit/test_private_archive_review.py tests/consultation_kb/unit/test_archive_bundle.py tests/consultation_kb/unit/test_profile_diff.py tests/consultation_kb/unit/test_profile_review.py tests/consultation_kb/unit/test_deidentification.py tests/consultation_kb/unit/test_case_release_policy.py tests/consultation_kb/unit/test_outbox.py tests/consultation_kb/unit/test_case_provenance.py tests/consultation_kb/unit/test_leave_one_out.py tests/consultation_kb/unit/test_archive_mcp.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_archive_01.py tests/consultation_kb/integration/test_case_01_full_lineage.py tests/consultation_kb/integration/test_case_02_authorization.py tests/consultation_kb/integration/test_archive_end_to_end.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider -m fault tests/consultation_kb/fault/test_outbox_saga_exceptions.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_iso_01.py tests/consultation_kb/integration/test_iso_02.py tests/consultation_kb/integration/test_write_01.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids CASE-01,CASE-02,ARCHIVE-01,TX-01,ISO-01,ISO-02,WRITE-01,TURN-01,FACT-01,GRAPH-01,RISK-01,VER-01
```

Expected: `CASE-01`、`CASE-02`、`ARCHIVE-01`、saga 基础 `TX-01` 全部通过。

## P7 完成定义

- [x] 私有记录、profile diff、共享案例是三个独立发布目的，失败互不阻塞。
- [x] ActualTranscript不可由归档审核抹除；PrivateArchiveDraft未单独批准时不进入长期历史召回。
- [x] current profile 删除失效/已解决/重复，但历史与来源完整，间接图影响需人工复核。
- [x] 共享案例只有授权+脱敏+人工审核后 active；global query 不打开 client DB。
- [x] 来源客户在所有派生/检索/重排通道被排除或使用获准 LOO，撤回立即零召回。
