# P8：崩溃恢复、删除与重建实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 对每种发布目的完成逐步骤真实进程崩溃恢复、active 工件完整性验证、tombstone 立即阻断、覆盖 SQLite/WAL/索引/缓存/备份的物理清理，以及从权威来源和审核记录重建全部派生物。

**Architecture:** `RecoveryCoordinator` 扫描 manifest/outbox 状态并按幂等规则完成或清理 PREPARED；查询端永远先 tombstone 再 active verify。删除分“立即不可见”和“可证明物理清理”两阶段。重建器从 Source/Passage/approved Claim/Wiki revision、client FactEvent、actual session/review decision 和 case authorization/provenance 重放，不依赖丢失的模型中间推理。

**Tech Stack:** sqlite3 WAL/checkpoint/secure_delete/VACUUM INTO、immutable content store、NumPy shard rebuild、subprocess `os._exit` fault injection、P1 manifests/P7 saga、pytest fault tests。

## Global Constraints

- 先完成 P7；读取设计规格第 5.2、14.4、17、18、19、24.2 节。
- 所有 destructive 测试只在 `tmp_path` 的合成 vault；不得对真实 workspace/vault 执行测试删除。
- 删除/撤回先 tombstone，后台重建或物理清理失败不恢复可见性。
- active 缺文件、坏 hash、source-version mismatch 必须 fail closed；不能为了可用性静默跳过检索层。
- rollback 追加反向事件/新 revision，不擦除审核历史或把 active pointer 直接改回后伪装无变化。

---

## Task 1：统一恢复状态机与启动扫描

**Files:**

- Create: `consultation_kb/lifecycle/recovery.py`
- Create: `consultation_kb/lifecycle/recovery_policy.py`
- Create: `consultation_kb/models/recovery.py`
- Create: `tests/consultation_kb/unit/test_recovery_policy.py`
- Create: `tests/consultation_kb/unit/test_recovery_coordinator.py`

**Interfaces produced:** `RecoveryCoordinator.scan/recover`；`RecoveryDecision`；每 purpose 的 idempotent policy。

- [x] 写状态决策表测试：

| 状态 | 条件 | 决定 |
|---|---|---|
| DRAFT | 无正式 DB intent | 清理超期 staging |
| PREPARED | members 完整、hash/source/base/approval intent 有效 | 完成 verify/activate |
| PREPARED | 任一 member/版本/intent 无效 | 保留旧 active，tombstone prepared，清理 staging |
| ACTIVE | 完整有效 | 保持 |
| ACTIVE | 缺失/坏 hash/源版本错 | fail closed + enqueue rebuild，不回退未知旧版 |
| RETIRED | 在回滚窗口内 | 保留不可查询 |
| RETIRED | 窗口过期且无保留义务 | 排清理队列 |

- [x] 为 private record/profile/wiki/graph/lex/vector/case/index/outbox 分别写 idempotent recovery fixture；恢复两次结果相同，无 duplicate version/event。
- [x] 写 stale approval/base test：PREPARED 是基于旧 profile/catalog 或权限已收紧，不能激活；权限收紧 tombstone 优先。
- [x] Coordinator 先以只读方式 inventory，再按 database/purpose 单 writer lock 执行；每个 decision 保存 manifest ID、前后状态、验证结果和安全 hash，不保存正文。
- [x] outbox/saga recovery 与 P7 idempotency key 对齐：source ack 丢失但 global active 时只补 ack；global PREPARED 依 policy 完成/清理；绝不为了检查 global case 打开无关客户 DB。
- [x] 私有归档、profile 更新和共享案例的目标事务已经提交、但控制端 approval acknowledgement 丢失时，只能使用目标 worker 签发且可验证的 exact execution proof 恢复确认；不得重新消费已确认 approval、伪造普通重放，或仅凭业务行存在推断批准成功。
- [x] 服务 startup 在接受查询前验证 active manifests/tombstone epoch；可修复 PREPARED，但 active 损坏则 health degraded/required MCP 启动失败，明确给 rebuild 命令。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_recovery_policy.py tests/consultation_kb/unit/test_recovery_coordinator.py
```

Expected: PASS；两次恢复幂等。

---

## Task 2：真实 subprocess kill 故障注入

**Files:**

- Create: `consultation_kb/lifecycle/fault_points.py`
- Create: `tests/consultation_kb/fault/fault_worker.py`
- Create: `tests/consultation_kb/fault/test_manifest_process_crash.py`
- Create: `tests/consultation_kb/fault/test_outbox_process_crash.py`
- Create: `tests/consultation_kb/fault/test_approval_execution_crash.py`
- Create: `tests/consultation_kb/fault/test_client_publication_crash.py`
- Create: `tests/consultation_kb/fault/test_global_knowledge_publication_crash.py`

**Interfaces produced:** 测试专用 named fault points；真实重启 recovery harness。

- [x] 五个 `test_*_crash.py` 模块全部带 `TX-01` marker；其中 manifest/global publication tamper closure 可同时带 `VER-01`，但不得用 fault marker替代 acceptance ID marker。
- [x] fault points 精确列出：`after_stage_write`、`after_file_fsync`、`before_prepared_tx`、`after_prepared_tx`、`after_verify`、`before_active_tx`、`after_active_tx`、`before_cleanup`；批准执行另有 `after_approval_claim`、`before_target_commit`、`after_target_commit_before_ack`；client publication覆盖 fact/profile/graph，global knowledge publication覆盖 C1/Wiki/graph/lex/vector；saga另有 `after_source_outbox`、`after_global_copy`、`after_global_prepare`、`after_global_activate`、`before_source_ack`。
- [x] worker 只在 `CONSULTATION_FAULT_POINT` 且测试 mode/临时 vault marker 同时存在时调用 `os._exit(137)`；production config 出现该 env 时启动失败，避免保留后门。
- [x] 每个 fault point：准备 old active → subprocess尝试 new version → 被杀 → 新进程 recovery → query。断言只能完整 old或完整 new runtime epoch；SQLite/file/profile/graph/index不出现混合 source version。target commit前 approval execution/业务行全无；target commit后但ack前业务只出现一次，recovery补ack。
- [x] 对同一点重复 crash/recover 三次验证幂等；检查 staging/locks/WAL 状态和 outbox event count。
- [x] A 级回归覆盖并通过：真实进程崩溃用例覆盖 named fault points 与 recovery：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -m fault tests/consultation_kb/fault/test_manifest_process_crash.py tests/consultation_kb/fault/test_outbox_process_crash.py tests/consultation_kb/fault/test_approval_execution_crash.py tests/consultation_kb/fault/test_client_publication_crash.py tests/consultation_kb/fault/test_global_knowledge_publication_crash.py
```

Expected: PASS；named fault points 与 recovery 回归成立。

- [x] 使用 `subprocess.Popen` 启动 `.venv` Python，不用 mock transaction；worker 写 JSON result 到独立 control file，仅含 state/hash。父测试等待进程退出码 137，再启动新 worker `recover-and-query`。
- [x] Windows 文件锁路径覆盖打开/关闭 mmap 和 SQLite handles；activate/cleanup 前显式释放。若删除旧 shard 暂时被锁，放 retry queue，不影响新 active 或 tombstone。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -m fault tests/consultation_kb/fault/test_manifest_process_crash.py tests/consultation_kb/fault/test_outbox_process_crash.py tests/consultation_kb/fault/test_approval_execution_crash.py tests/consultation_kb/fault/test_client_publication_crash.py tests/consultation_kb/fault/test_global_knowledge_publication_crash.py
```

Expected: 全部 fault point PASS；`TX-01` 进程崩溃部分成立。

---

## Task 3：active 完整性验证与 fail-closed 查询门

**Files:**

- Create: `consultation_kb/storage/integrity.py`
- Modify: `consultation_kb/storage/manifests.py`
- Modify: `consultation_kb/retrieval/coordinator.py`
- Modify: `consultation_kb/mcp/lifespan.py`
- Create: `tests/consultation_kb/unit/test_integrity_verifier.py`
- Modify: `tests/consultation_kb/integration/test_ver_01.py`

**Interfaces produced:** `IntegrityVerifier.verify_active/verify_closure`；统一 `ArtifactUnavailable`。

- [x] 扩展 `VER-01`：缺 payload、目录替换、坏 hash、manifest member 缺失、source catalog/client commit 错、graph/lex/vector/wiki 彼此版本混用、模型 descriptor/file hash 错；每项查询前拒绝。
- [x] 写完整closure DAG test，逐边枚举 `authority.snapshot_ref/policy_ref`、`client_snapshot_ref`、每个temporary fact、candidate text、locator anchors/policy、freshness policy、safe provenance/derivation、C1 revision/scope policy及其matched-rule/context-field manifest membership、每个unresolved conflict、exclusion proof、wiki/lex/vector/graph root manifests、reranker descriptor和LOO variant。每条边核对exact `(object_id,version,content_sha256)`、immutable manifest直接/传递membership、tombstone/epoch/source version；拒绝ID-to-latest、active alias、mutable model/policy label、orphan ref和alternate-store fallback。
- [x] 写字段专属scope/authorization矩阵：client snapshot/temporary facts属于当前client/session与selection cutoff；private candidate text/anchors/provenance属于当前client store；global knowledge/manifests/models/policies属于global store；conflict/proof绑定当前run/authority/evidence；LOO text/provenance属于同一个approved LOO variant。允许明确的client/global双快照组合，但组合与全部root refs必须固定在run manifest。missing/unauthorized/cross-scope返回同一安全错误且不尝试其他store，opaque ref不得成为existence oracle。
- [x] 写 no silent fallback：vector 损坏时不能返回“其余通道正常”而不告知；是否允许降级由 query policy 明确，关键配置质量优先默认停止并给可重建错误。
- [x] A 级回归覆盖并通过：完整性与篡改用例覆盖新增 tampering cases：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_integrity_verifier.py tests/consultation_kb/integration/test_ver_01.py
```

Expected: PASS；tampering cases 全部 fail closed。

- [x] verifier 每次 activate 全验；运行时缓存验证结果以 manifest/hash 为 key，但 tombstone epoch/source version 变化立即失效。缓存本身不绕过 content hash。
- [x] `storage.integrity` 只依赖 storage/vault/models，不导入 retrieval或lifecycle；retrieval query gate与lifecycle recovery/rebuild共同依赖它，架构测试禁止 `retrieval ↔ lifecycle` 环。
- [x] MCP lifespan 对 required active artifacts 做 verify；损坏时 stderr 输出安全诊断/退出非零，Codex `required=true` 阻止静默启动。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_integrity_verifier.py tests/consultation_kb/integration/test_ver_01.py
```

Expected: `VER-01` 全部 PASS。

---

## Task 4：删除计划、tombstone 级联与即时零召回

**Files:**

- Create: `consultation_kb/lifecycle/deletion.py`
- Create: `consultation_kb/lifecycle/deletion_plan.py`
- Create: `consultation_kb/models/deletion.py`
- Create: `tests/consultation_kb/unit/test_deletion_plan.py`
- Create: `tests/consultation_kb/integration/test_tombstone_cascade.py`

**Interfaces produced:** `DeletionService.preview/commit_tombstone`；`DeletionPlan`；谱系级联。

- [x] 为 client/session/case/passage/claim 各写 preview：列出权威对象、case contribution、patterns/claims/wiki/graph/index/cache/evaluation/backups、保留的无正文审计和受影响 active manifests。
- [x] 写批准测试：删除是 P1 formal purpose，绑定 plan hash/base versions/scope；模型直接删、旧 plan、删错 client、receipt 重放全拒绝。
- [x] 写 tombstone cascade：case/client authorization 撤回时 global catalog 先 tombstone所有 provenance-dependent object 或标 LOO substitution；每个 retrieval channel 在同一 epoch 立即零召回。
- [x] 提供正式的 case/authorization revoke 运维入口：按 exact case/authorization version、当前 authority epoch 和批准后的 deletion plan 执行，原子写撤回/tombstone、提升 epoch 并排 rebuild；不得依赖直接改库、等待索引重建或只更新 source outbox 来实现撤回。
- [x] preview 通过 provenance/artifact dependency closure，不靠目录全文搜索猜依赖；plan 明确 `tombstone_now/physical_delete/rebuild/backup_expiry/manual_product_action` 五类动作。
- [x] commit 先在 authority SQLite 单事务写 tombstones/deletion request/version，更新 global tombstone epoch，再 enqueue 物理清理；若 enqueue 失败 tombstone 仍保留并可恢复补队列。
- [x] 错误/报告明确区分“本地不可检索/物理清理状态”和“Codex 托管任务状态”，不声称本地删除能删除 Codex task。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_deletion_plan.py tests/consultation_kb/integration/test_tombstone_cascade.py
```

Expected: PASS；立即零召回不依赖 rebuild 完成。

---

## Task 5：SQLite、不可变对象、索引、缓存与备份物理清理

**Files:**

- Create: `consultation_kb/lifecycle/physical_cleanup.py`
- Create: `consultation_kb/lifecycle/sqlite_cleanup.py`
- Create: `consultation_kb/lifecycle/backup_queue.py`
- Create: `tests/consultation_kb/fault/test_physical_cleanup.py`
- Create: `tests/consultation_kb/integration/test_sqlite_cleanup.py`

**Interfaces produced:** `PhysicalCleanupWorker.process`；`SqliteSanitizer`；`BackupDestructionQueue`。

- [x] 写清理范围测试：主文件/session、global case copy、case contribution、graph、FTS、vector shard、Wiki render、cache/export/temp、evaluation sample、old content objects、WAL/SHM、backup queue 全有 action/result。
- [x] SQLite 测试在合成 canary row 后 delete：`secure_delete=ON`，checkpoint TRUNCATE，重建/VACUUM 后扫描 db/WAL/SHM bytes 零命中；普通 SQL DELETE 的对照应仍可能命中，证明为何不够。
- [x] FTS5：SQLite >=3.42 启用 FTS5 secure-delete 并 optimize/rebuild；旧环境走 clean DB rebuild/atomic switch。Doctor 实际检查版本/capability，不能静默降低强度。
- [x] vector `.npy`：构建不含删除 row 的新 shard/metadata，激活后关闭 mmap，再回收旧 shard；Windows lock 失败进入 retry，不恢复可见性。
- [x] A 级回归覆盖并通过：物理清理用例覆盖 SQLite/FTS/vector/备份清理：

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_sqlite_cleanup.py
& '.\.venv\Scripts\python.exe' -m pytest -q -m fault tests/consultation_kb/fault/test_physical_cleanup.py
```

Expected: PASS；清理缺口回归均被 fail closed 检出。

- [x] 整客户删除：先 global tombstone/贡献清理，再关闭 worker/handles；重建保留最小 global catalog proof；清理 client dir 和 identity-map entry。第一阶段无每客户数据密钥，不能虚称 cryptographic erasure；使用 clean rebuild + verified removal。
- [x] backup queue 保存 backup ID、object hashes、location class、due/finished time、operator proof hash，不复制正文。离线/外部 backup 无法即时访问时报告 pending，不能标 complete。
- [x] 内容寻址对象只在 reference count/retention/rollback/backup policy 都允许时删除；删除后扫描 known canary 和 object hash。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/integration/test_sqlite_cleanup.py
& '.\.venv\Scripts\python.exe' -m pytest -q -m fault tests/consultation_kb/fault/test_physical_cleanup.py
```

Expected: PASS；本地所有可控副本零 canary。

---

## Task 6：从权威记录重建全部派生物

**Files:**

- Create: `consultation_kb/storage/migrations/global/v0006_lifecycle.py`
- Create: `consultation_kb/storage/migrations/client/v0006_lifecycle.py`
- Create: `consultation_kb/lifecycle/rebuild.py`
- Create: `consultation_kb/lifecycle/rebuild_registry.py`
- Create: `consultation_kb/lifecycle/rebuild_jobs.py`
- Create: `consultation_kb/lifecycle/equivalence.py`
- Create: `tests/consultation_kb/unit/test_rebuild_registry.py`
- Create: `tests/consultation_kb/integration/test_rebuild_all.py`
- Create: `tests/consultation_kb/integration/test_rebuild_job_recovery.py`

**Interfaces produced:** `RebuildCoordinator.plan/start`；`RebuildJobRepository.get/cancel_before_activation`；持久 worker queue；artifact builder registry；`EquivalenceReport`。

- [x] registry 测试要求 builder DAG：source/passages/approved claims/theory/wiki → global graph/lex/vector；fact events → profile/client graph；actual session/review → private archive/profile diff；approved global case/provenance → patterns/LOO/indexes。
- [x] 集成先记录 active refs/hash/semantic fingerprint，删除所有派生 Wiki render、graph、profile views、FTS/vector、case indexes和缓存，保留权威 source/fact/review；运行 rebuild 后比较。
- [x] exact equivalence：profile JSON/MD、Wiki render、graph ordered JSON、FTS row IDs/text hashes、case provenance closure；vector 要求 model descriptor/file hashes一致、embedding 数值 `allclose` 固定容差、top-k ranking 相同。任何非等价需明确新 version/原因，不伪称相同。
- [x] 证明 rebuild 不读取 generation scratch/unapproved drafts/模型中间推理；只读记录在 registry allowlist 的 authority tables/objects。
- [x] 持久作业测试：`start`在同步 MCP timeout内返回 `job_id`，随后 `get`报告 queued/running/verifying/activating/succeeded/failed/cancelled；客户端断开、MCP timeout或服务进程重启后worker从 journal继续。相同 idempotency key不重复构建；只在 activating前允许 cancel，任何中断都不切半套版本。
- [x] 每个 builder 声明 input authority versions/output purpose/policy/model descriptor，background worker topological run；先stage全套兼容 artifacts，verify closure后才切active，旧active在完成前保持。模型embedding全量重建不占用600秒同步tool调用。
- [x] rebuild 报告保存 inputs/outputs/hashes/equivalence/version/retries，不保存正文。tombstoned objects 在 rebuild 源和结果中均排除。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_rebuild_registry.py tests/consultation_kb/integration/test_rebuild_all.py tests/consultation_kb/integration/test_rebuild_job_recovery.py
```

Expected: `REBUILD-01` PASS。

---

## Task 7：可审计 rollback、MCP 运维工具与运行手册

**Files:**

- Create: `consultation_kb/lifecycle/rollback.py`
- Create: `consultation_kb/mcp/lifecycle_tools.py`
- Modify: `consultation_kb/mcp/server.py`
- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Modify: `consultation_kb/cli.py`
- Create: `docs/consultation-kb/recovery.md`
- Create: `docs/consultation-kb/deletion.md`
- Create: `tests/consultation_kb/unit/test_rollback.py`
- Create: `tests/consultation_kb/unit/test_lifecycle_mcp.py`
- Create: `tests/consultation_kb/integration/test_lifecycle_worker_boundary.py`

**Interfaces produced:** `rollback_version`、`start_rebuild`、`get_rebuild_status`、`get_rebuild_report`、`cancel_rebuild`、`preview_delete`、`commit_delete`；CLI `recover/recovery-report/rebuild-start/rebuild-status/delete-status`；worker operations `recover_client_manifests`、`preflight_client_lifecycle_commit`、`preview_client_delete`、`commit_client_tombstone`、`rebuild_client_derivatives`、`preview_client_rollback`、`commit_client_rollback`、`verify_client_integrity`。

- [x] rollback 测试：profile/fact rollback 追加反向 FactMutation/review；Wiki/C1 rollback 创建新 revision，C1 仍需主咨询师批准；artifact rollback 创建新 manifest source version，不删除原 history。
- [x] MCP/CLI 测试：所有 destructive/activation operations要 P1 approval、base versions和plan hash；read-only `delete-status/recovery-report/get_rebuild_*`不需要 write approval但必须scope。`start_rebuild`只入持久队列并立即返回 job ID，不同步等待embedding；cancel只在activation前成功。
- [x] `worker_main.py` 显式注册全部 client lifecycle operations，request无 client/path/sql；destructive commit 在一次性审批票据绑定前通过 `preflight_client_lifecycle_commit` 做 exact plan/ref/hash/base/scope 只读预检。真实 subprocess测试证明 client recovery/delete/rebuild/rollback/integrity只在 scoped worker打开 client DB/CAS；global lifecycle handler不能拿 client root。
- [x] 手册给出症状→安全命令→预期结果：PREPARED、active hash mismatch、outbox pending、mmap lock、WAL、backup pending、Codex task retention。每个命令先 dry-run/preview。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_rollback.py tests/consultation_kb/unit/test_lifecycle_mcp.py tests/consultation_kb/integration/test_lifecycle_worker_boundary.py
```

Expected: PASS；无无审批 destructive path。

---

## Task 8：TX/VER/DEL/REBUILD 全量强制验收

**Files:**

- Create: `tests/consultation_kb/golden/test_del_01.py`
- Create: `tests/consultation_kb/golden/test_rebuild_01.py`
- Create: `tests/consultation_kb/integration/test_lifecycle_end_to_end.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/consultation_kb/unit/test_ci_contract.py`
- Create: `consultation_kb/operations/doctor_probes.py`
- Modify: `consultation_kb/core/doctor.py`

**Interfaces consumed:** P1–P8 全部发布、检索、归档、删除、重建。

- [x] 模块级 marker：`test_del_01.py → DEL-01`、`test_rebuild_01.py → REBUILD-01`；`test_ver_01.py` 保留 `VER-01`，所有 fault extension 保留 `TX-01`。
- [x] `DEL-01` 对 client/case/claim 写 tombstone 后立即查询并重启，所有通道零召回；随后 physical cleanup 扫主文件/WAL/temp/old versions/backups，结果符合 policy。
- [x] `REBUILD-01` 删除全部派生物并从 authority rebuild，检查 exact/semantic equivalence 和 tombstone 排除。
- [x] `TX-01` 运行所有真实 kill points；`VER-01` 运行所有 tamper；同时重跑 `ISO-01/02`、`CASE-01/02` 和 `ARCHIVE-01`，确保 recovery/deletion 无泄漏回归。
- [x] Doctor新增 recovery pending、active integrity closure、tombstone epoch、cleanup queue、backup queue、WAL checkpoint、rebuild capability；任何 active corruption返回 nonzero。`core.doctor` 只定义/运行注入的 `DiagnosticProbe`协议，不反向 import P1/P4/P5/P8；CLI/MCP composition在 `operations/doctor_probes.py` 装配高层 probes，架构测试禁止 core依赖高层。
- [x] 扩展 Windows 3.12 CI为独立 fault job，使用P0 hash lock运行 `tests/consultation_kb/fault`；上游Ubuntu job仍忽略 consultation。`test_ci_contract.py` 锁定故障测试不会因 marker/路径配置而零收集。
- [x] Run P8 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_del_01.py tests/consultation_kb/golden/test_rebuild_01.py tests/consultation_kb/integration/test_ver_01.py tests/consultation_kb/integration/test_lifecycle_end_to_end.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider -m fault tests/consultation_kb/fault
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_iso_01.py tests/consultation_kb/integration/test_iso_02.py tests/consultation_kb/integration/test_case_01_full_lineage.py tests/consultation_kb/integration/test_case_02_authorization.py tests/consultation_kb/integration/test_archive_end_to_end.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids TX-01,VER-01,DEL-01,REBUILD-01,ISO-01,ISO-02,CASE-01,CASE-02,ARCHIVE-01
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
```

Expected: `TX-01`、`VER-01`、`DEL-01`、`REBUILD-01` 全部通过，所有旧强制验收无回归。

### P8 阶段收口证据（2026-07-22）

- [x] 强制验收 runner：客户端 exact-plan 预检变更后完整复跑 `84 passed in 52.29s`；最终收口轮为 `83 passed`，唯一 Win32 目录交换瞬时 `PermissionError` 随即隔离复跑 `1 passed`。
- [x] 一次性审批预检：客户端 lifecycle worker/protocol/security 与 MCP/architecture 两组分别 `40 passed`、`13 passed`；全局 exact-plan 预检及 rollback/recovery 定向组共 `24 passed`。错误 operation/ref 在票据绑定前 fail closed，approval receipt 保持未消费。
- [x] Rollback/lifecycle focused：`34 passed`。
- [x] Migration/recovery/retrieval 批次：`70 passed`；risk 外部 basetemp：`23 passed`；Schema exports：`39 passed`；Doctor：`9 passed`。
- [x] 全树分轨验证：consultation 全套先通过 `2380` 项、定位 `13` 项分域过约束后失败集 `13 passed`，并补跑 recovery/retrieval `37 passed`、STDIO `5 passed`；上游 Graphify 公平环境轨 `432 passed, 5 deselected`，5 项仅因当前 Windows 进程无 `SeCreateSymbolicLinkPrivilege`（`WinError 1314`）无法创建测试 symlink，Linux CI 保留完整 symlink 轨。
- [x] 静态/运行时门禁：Ruff 全绿；strict mypy `272` 个源文件零错误；compileall、`pip check`、diff check 全绿；MCP 冻结为 `47` 工具，schema hash `0748202be8a4105c0c2ee550301224dc9c11a5d849e651db2bd1325eb71e6064`。

## P8 完成定义

- [x] 每个 publish/saga 步骤真实进程被杀后只见完整旧/新版，恢复幂等。
- [x] active 工件任何损坏/错版 fail closed；required MCP 不静默启动。
- [x] tombstone 立即全通道零召回，物理清理覆盖 DB/WAL/FTS/vector/cache/temp/old object/backup。
- [x] 全部派生物可从权威源和人工决定重建，不依赖模型中间推理。
