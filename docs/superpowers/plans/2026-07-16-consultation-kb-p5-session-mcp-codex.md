# P5：统一 MCP、Codex Skill 与逐轮会谈实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

> **状态：已完成。** 2026-07-18 最终验证：咨询知识库全量测试 `1376 passed, 1 skipped`；P5 隐私/隔离/Doctor 定向门 `112 passed`；`TURN-01,ISO-01,FACT-01` 验收通过；Ruff、mypy、compileall 与 `git diff --check` 通过。

**Goal:** 让咨询师可在 Codex 中用自然语言开始/继续一次单客户文本咨询，加载固定客户快照、逐轮保存来访者消息和实际回复、维护临时事实账本、在中断后恢复，并通过一个本地 STDIO MCP 与项目 Skill 安全调用 P1–P4 能力。

**Architecture:** 会谈是客户库中的追加状态机。初始 `load_client_context` 是唯一接受 client ID 的控制面调用，成功后只返回不透明 `session_handle`；后续客户工具不接受客户 ID/路径。MCP handler 是可直接单测的顶层函数，server 只注册协议。Codex Skill 负责编排，不调用独立 OpenAI API。

**Tech Stack:** sqlite3、Pydantic、MCP Python SDK v1/FastMCP STDIO、P1 scoped worker、Codex `AGENTS.md`/repo Skills/`.codex/config.template.toml`、pytest async integration。

## Global Constraints

- 先完成 P4；读取设计规格第 4、6.3、11、16、17.2、19 节。
- 粘贴到 Codex 的文本已发生托管处理；本地 Skill/MCP 只能检测并阻止后续归档，不能撤回已经发送的文本。
- 正式客户 profile 在会谈期间只读；新陈述只进入 session ledger，结束时经 P7 差异审核后才能成为长期事实。
- 未采用候选不得作为实际回复、干预或事实来源；下一条来访者消息前必须关闭上一轮。
- MCP stdout 只写协议，日志全写 stderr；服务损坏时 `required=true`，不能静默无知识降级。

---

## Task 1：会谈、轮次、实际回复与 stage 数据迁移

**Files:**

- Create: `consultation_kb/storage/migrations/client/v0003_sessions.py`
- Create: `consultation_kb/models/session.py`
- Create: `consultation_kb/session/__init__.py`
- Create: `consultation_kb/session/repository.py`
- Create: `tests/consultation_kb/unit/test_session_schema.py`
- Create: `tests/consultation_kb/unit/test_session_repository.py`

**Interfaces produced:** `SessionRecord`、`TurnRecord`、`ActualReply`、`SessionRepository`。

- [x] 写失败测试，锁定一 session 一 client、turn 幂等、实际正文与审计引用分离：

```python
def test_turn_id_is_idempotent(
    session_repo, active_session, valid_turn_id, client_message,
) -> None:
    first = session_repo.append_client_turn(active_session.session_id, valid_turn_id, client_message)
    second = session_repo.append_client_turn(active_session.session_id, valid_turn_id, client_message)
    assert second == first
    assert session_repo.count_turns(active_session.session_id) == 1
```

- [x] 写冲突测试：相同 turn ID 不同正文 hash 拒绝；session/client snapshot 绑定不可修改；关闭 session 后不能 append；audit rows 只有 object ref/hash。
- [x] v0003 完成/扩展 `sessions`、`turns`、`candidate_replies`、`actual_replies`、`session_fact_events`、`generation_stage_artifacts`、`risk_observations`、`session_checkpoints`。正文全部存当前客户 CAS content object ref；表内保存 hash、状态、顺序和来源。`actual_replies` 强制带 UTC `sent_at`（external unknown保存 counselor确认 unknown的时间）。
- [x] sessions 保存 `client_snapshot_version/hash`、开始/结束、status、capability epoch、最后 closed turn、archive state；turns 保存 message ref/hash 和 `client_turn_received/.../turn_closed` 状态。
- [x] repository 所有 append 使用 `(session_id, turn_id, content_sha256)` 幂等键；hash 变化抛冲突。任何状态更新是新 checkpoint/event 或受约束 transition，不允许跳步。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_session_schema.py tests/consultation_kb/unit/test_session_repository.py
```

Expected: PASS；正文只存在客户作用域 content store。

---

## Task 2：开始会谈与固定客户上下文快照

**Files:**

- Create: `consultation_kb/session/context.py`
- Create: `consultation_kb/session/service.py`
- Create: `tests/consultation_kb/unit/test_client_context.py`
- Create: `tests/consultation_kb/integration/test_begin_session.py`

**Interfaces produced:** `SessionService.begin/resume/close_capability`；`ClientContextSnapshot`。

- [x] 写失败测试：begin A 返回 active snapshot/handle；snapshot 包含最新 approved profile、最近会谈摘要 refs、未解决事项、目标/偏好/约束、关键事实时间/置信度、冲突/过期/待复核和 profile version。
- [x] 写边界测试：不存在/未激活 client 给安全创建提示但不猜相近 ID；A begin 后请求 B ID 不能复用同 handle；同一 Codex task/session handle 永久绑定 A。
- [x] 写 stale test：会谈开始后 profile 更新为 v2，本 session 仍使用 v1 snapshot，同时 session ledger 可记录新陈述；不得中途无提示切 v2。
- [x] `begin(client_id)` 是控制面唯一接收 client ID 的会谈 API：核验 catalog/ACL/active profile，创建 session row，签发 P1 capability，启动 worker；返回 `session_handle` 和 snapshot，不返回客户目录。它同时把当前 MCP transport session ID 绑定到该客户；同一 transport 再请求另一客户必须返回 `TASK_SCOPE_ALREADY_BOUND`，恢复同一客户则允许。
- [x] context builder 只加载 current profile 的最小结构；较早私有历史保留 query refs，问题相关时由 P4 client-history channel 按需取，不把全部历史塞入上下文。
- [x] `resume(client_id, session_id)` 核对 session 绑定，签发新 capability epoch，恢复已保存 actual conversation/temp facts/last state；不恢复未保存模型中间推理。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_client_context.py tests/consultation_kb/integration/test_begin_session.py
```

Expected: PASS；snapshot 可复现且会谈中只读。

---

## Task 3：临时事实账本与轮次状态机

**Files:**

- Create: `consultation_kb/session/state_machine.py`
- Create: `consultation_kb/session/temporary_ledger.py`
- Create: `consultation_kb/session/turns.py`
- Create: `consultation_kb/session/candidate_sets.py`
- Create: `tests/consultation_kb/unit/test_session_state_machine.py`
- Create: `tests/consultation_kb/unit/test_temporary_fact_ledger.py`
- Create: `tests/consultation_kb/unit/test_candidate_sets.py`

**Interfaces produced:** `TurnStateMachine.transition`；`TemporaryFactLedger.propose/correct/conflict/snapshot`；`TurnService.append/begin_generation`；`CandidateSetService.store_and_await`。

- [x] 写状态转移表测试，只允许：

```text
client_turn_received → generation_in_progress
generation_in_progress → candidates_generated → awaiting_actual_reply
awaiting_actual_reply → actual_reply_recorded → turn_closed
awaiting_actual_reply → external_reply_unknown → turn_closed
```

任何跳过、重复不同 payload、下一 client turn 在 awaiting 状态均抛固定错误。
- [x] 写 temporary ledger 测试：新事实、纠正、可能失效、目标/问题/偏好/约束、假设、与 profile 冲突分类型保存；每项 source turn + cognitive type；不能写 `review_status=approved` 或长期 `fact_events`。
- [x] 写会谈内检索测试：session-reported fact 可进入本轮 EvidencePack 的 temporary section，但标签明确；不能冒充 approved objective fact，也不能在另一个 session 查询。
- [x] 写最小 candidate set测试：P5可由 MCP提交2–3个明确 dummy/人工候选（P6复用同一接口）。`store_and_await` 在一个 client事务写 candidate objects/refs并依次追加 `candidates_generated`、`awaiting_actual_reply` checkpoints；不同 hash同 idempotency key拒绝，候选必须属于当前 turn。
- [x] state machine 作为纯函数返回 transition/event；repository 在事务中核对 expected current state 再 append checkpoint。提交 query plan/开始生成才从 `client_turn_received` 进入 `generation_in_progress`；不得把 `candidates_generated` 同时解释为“仍在生成”。错误显示应采取的显式操作，不自动猜。
- [x] temporary ledger 是 append-only session events；对旧 profile 的 correction 保存 target fact/version；本会谈多次陈述冲突并列，不靠最新文本覆盖。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_session_state_machine.py tests/consultation_kb/unit/test_temporary_fact_ledger.py tests/consultation_kb/unit/test_candidate_sets.py
```

Expected: PASS；正式 profile/ledger 在会谈中未改变。

---

## Task 4：实际回复记录、未知外部回复与中断恢复

**Files:**

- Create: `consultation_kb/session/actual_replies.py`
- Create: `consultation_kb/session/recovery.py`
- Create: `tests/consultation_kb/unit/test_actual_replies.py`
- Create: `tests/consultation_kb/golden/test_turn_01.py`
- Create: `tests/consultation_kb/integration/test_session_recovery.py`

**Interfaces produced:** `ActualReplyService.record_adopted/record_edited/record_external_unknown`；`SessionRecovery.resume`。

- [x] `test_turn_01.py` 使用模块级 `@pytest.mark.acceptance_id("TURN-01")`。
- [x] 写三种实际回复测试：直接采用复制候选 exact hash；编辑采用保存 exact edited text、candidate ref 和 diff ref；外部未知无正文且 `evidence_gap=true`。三者都要求 UTC `sent_at/confirmed_at`；相同 idempotency key改变时间或正文 hash拒绝。只有这些记录可进入 actual conversation。
- [x] 写 `TURN-01`：生成候选后直接追加下一来访者消息，系统拒绝并要求选择/粘贴/unknown；不得默认 candidate 已发送。候选正文只能存在 `candidate_replies`，不能出现在 `actual_replies` 或干预事实。
- [x] 写 recovery：每个状态中断并 resume；已关闭 turn 不重复；awaiting 状态仍提示关闭；未完成模型 stage 被丢弃并重新生成；actual/temporary facts/snapshot version 完整。
- [x] actual reply write 要求 turn awaiting、candidate ID 属于该 turn（unknown 除外）、idempotency key；编辑文本的正文对象单独 hash。审计只记录 source type/object refs/diff hash。
- [x] resume 从最后 committed checkpoint 重建，不依赖 Codex context；若外部未知，后续因果分析/归档始终传播 `incomplete_evidence`。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_actual_replies.py tests/consultation_kb/golden/test_turn_01.py tests/consultation_kb/integration/test_session_recovery.py
```

Expected: PASS；`TURN-01` 全部断言成立。

---

## Task 5：MCP 工具 Schema 与可单测 handler

**Files:**

- Create: `consultation_kb/mcp/__init__.py`
- Create: `consultation_kb/mcp/schemas.py`
- Create: `consultation_kb/mcp/context.py`
- Create: `consultation_kb/mcp/read_tools.py`
- Create: `consultation_kb/mcp/graph_tools.py`
- Create: `consultation_kb/mcp/session_tools.py`
- Create: `consultation_kb/mcp/write_tools.py`
- Create: `consultation_kb/mcp/knowledge_tools.py`
- Create: `tests/consultation_kb/unit/test_mcp_schemas.py`
- Create: `tests/consultation_kb/unit/test_mcp_handlers.py`
- Create: `tests/consultation_kb/unit/test_knowledge_mcp.py`

**Interfaces produced:** 设计规格 16.4 工具的顶层 async handlers；统一 `ToolEnvelope`/安全错误。

- [x] 写 Schema 反射测试：只有 `load_client_context` 初始参数可含 client ID；调用后 MCP transport session 被永久绑定该客户，第二次用另一 client ID 失败；所有绑定后 client tools 只有 `session_handle` 和领域参数，未知 `client_id/path/sql` 字段被 `extra=forbid` 拒绝。
- [x] 锁定工具集：

  - 读取/检索：`load_client_context`、`search_client_history`、`search_wiki`、`search_lexical`、`search_vector`、`search_cases`；
  - 图：`query_global_graph`、`query_client_graph`、`weighted_path`、`preview_dependency_impact`；
  - 会谈/候选：`append_session_turn`、`append_temporary_fact`、`store_candidate_set`、`record_actual_reply`；
  - 知识草稿/预览：`list_source_inbox`、`register_source_draft`、`extract_passages`、`propose_claims`、`preview_claim_review`、`propose_wiki_update`、`preview_wiki_update`、`knowledge_lint`、`propose_theory_revision`；
  - 正式写：`create_client`、`approve_passage`、`approve_claim`、`revoke_claim`、`publish_wiki`、`approve_theory_revision`、`revoke_theory_revision`；P7追加归档/案例，P8追加持久作业式 rebuild/rollback/delete。

- [x] P5 对尚属 P7/P8 的工具不注册。测试精确要求 P5 只注册已实现读取、图、session/candidate、P3 knowledge/C1和 create client；P7/P8 实现时再扩展，不能暴露假成功工具。
- [x] 知识入口无任意 path：`list_source_inbox` 只枚举 vault global固定 inbox并返回 opaque source handle；`register_source_draft` 只接受 handle+metadata，服务端用 P1 PathGuard解析。Passage/Claim/Wiki工具只接受版本 ref/draft ID。draft写入明确标 `draft_write`，正式 Passage/Claim/C1/Wiki写入需要对应 `DraftDescriptor.purpose` 和本地批准。
- [x] 写 handler 测试：直接注入 service context，不启动 server；read handler annotation read-only；write annotation destructive/approval-required；handler 不 catch 后返回正文栈。
- [x] 每个 handler 只做 Schema validate → capability/service call → safe envelope；业务逻辑保持在 service。`store_candidate_set` 复用 P5 `CandidateSetService`，P6最终 bundle也走同一入口。`create_client` 的 preview 只接 alias+幂等键、commit 只接 `approval_request_id`；其余 formal write handler只接 `approval_request_id`。服务器内部取得receipt并交目标 transaction `ApprovalExecutionGuard`，不能先在控制面 consume。
- [x] `search_*` 返回过滤后的 evidence refs/摘要和版本，不返回 provenance client IDs；`load_client_context` 返回 session handle 一次，日志屏蔽；graph path 带来源和限制。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_mcp_schemas.py tests/consultation_kb/unit/test_mcp_handlers.py tests/consultation_kb/unit/test_knowledge_mcp.py
```

Expected: PASS；工具参数面没有跨客户/路径通道。

---

## Task 6：STDIO server、真实 MCP 子进程与项目配置

**Files:**

- Create: `consultation_kb/mcp/server.py`
- Create: `consultation_kb/mcp/lifespan.py`
- Create: `.codex/config.template.toml`
- Create: `.codex/start-consultation-kb.ps1`
- Modify: `consultation_kb/cli.py`
- Create: `tests/consultation_kb/integration/test_mcp_stdio.py`
- Create: `tests/consultation_kb/unit/test_codex_config.py`

**Interfaces produced:** `python -m consultation_kb.mcp.server` STDIO；Codex 项目 MCP 配置。

- [x] 写真实集成测试，使用官方 `ClientSession` + `StdioServerParameters` 启动子进程，完成 initialize、tools/list、doctor/read 调用和一次无批准 write 拒绝；捕获 stderr，断言 stdout 无额外日志。
- [x] 写 config test：template为合法 TOML，`required=true`、`default_tools_approval_mode="writes"`、startup=30、普通同步tool=600；只配置一个 consultation MCP；`cwd="."` 按 `.codex/` 解析，args直接引用 `start-consultation-kb.ps1`。wrapper无输出并从 `$PSScriptRoot` 计算 repo/vault/venv。测试 `git check-ignore .codex/config.toml` 成功且 template/wrapper不被忽略。
- [x] `server.py` 用 MCP v1 FastMCP 注册 P5 已实现 handlers；lifespan 创建 config/catalog/model lazy providers，退出时关闭 worker/mmap/SQLite。stdout 只由 SDK 协议 writer 使用，logging handler 指向 stderr。
- [x] `.codex/start-consultation-kb.ps1`：从 script directory求 repo root，vault为 repo同级 `knowledge-vault`；不仅验证 `.venv\Scripts\python.exe` 存在，还读取 `pyvenv.cfg` 并运行最小 runtime probe，核对 P0 spec、64 位、`sys.base_prefix` 不在 Codex cache/repo/vault。失败时只写 stderr并退出，绝不回退到当前 `python`。通过后设置 UTF8/unbuffered/offline env，`Set-Location $RepoRoot` 后 `& '.\.venv\Scripts\python.exe' -m consultation_kb.mcp.server`；退出码原样传递。
- [x] `.codex/config.template.toml` 使用 PowerShell wrapper、`cwd="."`、required/writes/timeouts；`consultation-kb configure-codex` 验证 wrapper/venv/vault边界后原子生成被忽略的 `.codex/config.toml`。模板/生成文件都不放 secret、approval token或真实客户 ID；默认利用官方 `.codex/` 相对路径语义，不硬编码当前机器。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_mcp_stdio.py tests/consultation_kb/unit/test_codex_config.py
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli configure-codex --repo-root .
codex mcp list
```

Expected: 子进程协议测试 PASS；重启 Codex 后 `consultation-kb` 显示 enabled/required。

---

## Task 7：根 AGENTS.md 与 consultation/curation Skills

**Files:**

- Create: `AGENTS.md`
- Create: `.agents/skills/consultation-session/SKILL.md`
- Create: `.agents/skills/knowledge-curator/SKILL.md`
- Create: `tests/consultation_kb/unit/test_project_instructions.py`

**Interfaces produced:** Codex 项目不可变规则；会谈/知识整理自然语言流程。

- [x] 写测试解析三份 Markdown，要求根规则包含：单 task 单 client、不读其他客户、来源客户案例排除、profile 只读、实际回复、diff+批准、模型回答不作证据、证据/一致性检查、客户内容不进 Git、风险标签不对外。
- [x] `consultation-session` Skill 明确触发语句“开始咨询/继续咨询/结束咨询/采用版本”；步骤调用已实现 MCP，上一轮未关闭先处理；P5用 `store_candidate_set` 注册候选后才能记录 actual，P6再补全结构化生成；每轮输出内部分析、多个回复、引导、依据。
- [x] `knowledge-curator` Skill 只处理固定本地 source inbox，工具顺序精确为 `list_source_inbox → register_source_draft → extract_passages → approve_passage → propose_claims → preview_claim_review → approve_claim → propose_wiki_update → preview_wiki_update → publish_wiki → knowledge_lint`；C1走 proposal+正式本地批准。P8注册 `start_rebuild` 前不得引用不存在的 rebuild工具；禁止网络自动写入或传文件路径。
- [x] 两个 Skill 都说明去标识化必须发生在粘贴 Codex 前，扫描不能撤回已发送文本；客户正文不加入 Git/Memory/Chronicle。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_project_instructions.py
```

Expected: PASS；规则与 MCP 工具名完全一致。

---

## Task 8：P5 两轮会谈与 TURN/ISO 强制验收

**Files:**

- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Create: `tests/consultation_kb/integration/test_two_turn_session.py`
- Create: `tests/consultation_kb/integration/test_mcp_iso_01.py`
- Create: `tests/consultation_kb/integration/test_session_worker_boundary.py`
- Create: `tests/consultation_kb/integration/test_knowledge_mcp_end_to_end.py`
- Modify: `consultation_kb/core/doctor.py`

**Interfaces consumed:** P1 scope；P2 profile；P3 knowledge；P4 evidence；P5 session/MCP。**Interfaces produced:** worker operations `begin_session`、`resume_session`、`append_client_turn`、`append_temporary_fact`、`begin_generation`、`store_candidate_set`、`record_actual_reply`、`read_session_state`；客户域图查询、加权路径与依赖影响预览也只通过同一 scoped worker 执行。

- [x] 合成 A：开始会谈加载 snapshot v1；追加第一条消息和临时事实；生成 dummy candidates；记录实际编辑回复；追加第二条消息；明确 external unknown 或实际回复；关闭所有 turn。
- [x] 在第一轮 awaiting 时先提交第二条消息，断言 `TURN-01` 拒绝；中断/新 capability resume 后仍保留状态；最终 actual conversation 只含实际内容。
- [x] 经真实 MCP 子进程重跑 `ISO-01`：A handle 尝试传 B、路径/unknown fields、过期/revoked handle；全部 safe reject，B 信息不出响应/stderr。
- [x] `worker_main.py` 显式注册全部 P5 client operations；真实 subprocess测试证明 client session/profile/history repository仅在 worker PID打开。所有 request不含 client/path/sql；control-plane production composition直接打开 client DB时架构测试失败。
- [x] 知识 MCP E2E 从合成 inbox handle完成 source draft→Passage→Claim preview/批准→Wiki preview/发布→lint；tools/list与Skill中名称逐字一致，无内部 service-only断点，无任意路径参数。
- [x] Doctor 新增 MCP import、tool schema hash、stdout discipline、config/wrapper、active session recovery count；不自动恢复/关闭会谈。
- [x] Run P5 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_session_schema.py tests/consultation_kb/unit/test_session_repository.py tests/consultation_kb/unit/test_client_context.py tests/consultation_kb/unit/test_session_state_machine.py tests/consultation_kb/unit/test_temporary_fact_ledger.py tests/consultation_kb/unit/test_candidate_sets.py tests/consultation_kb/unit/test_actual_replies.py tests/consultation_kb/unit/test_mcp_schemas.py tests/consultation_kb/unit/test_mcp_handlers.py tests/consultation_kb/unit/test_knowledge_mcp.py tests/consultation_kb/unit/test_project_instructions.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_turn_01.py tests/consultation_kb/integration/test_session_recovery.py tests/consultation_kb/integration/test_mcp_stdio.py tests/consultation_kb/integration/test_two_turn_session.py tests/consultation_kb/integration/test_mcp_iso_01.py tests/consultation_kb/integration/test_session_worker_boundary.py tests/consultation_kb/integration/test_knowledge_mcp_end_to_end.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids TURN-01,ISO-01,FACT-01
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/test_install.py tests/test_serve.py tests/test_claude_md.py
```

Expected: `TURN-01`、MCP 版 `ISO-01` 通过；上游安装/MCP 无回归。

## P5 完成定义

- [x] Codex 可经一个 required STDIO MCP 开始/恢复合成会谈，无需独立 API。
- [x] 会谈 snapshot 固定、临时事实分轨、每轮实际回复状态完整。
- [x] 所有绑定后工具只接受 session handle，不能指定客户或路径。
- [x] 根规则和 Skills 与服务端硬约束一致，但不把 Prompt 当安全边界。
