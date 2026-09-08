# 恢复与重建运行手册

本手册面向本机咨询师/运维人员。所有示例都先做只读检查或预览；不要把数据库路径、客户 ID、咨询正文、审批票据或 nonce 粘贴到命令行、日志或 Codex 对话中。

CLI 的生命周期命令只直接检查配置中固定的 global scope，并使用 `recovery-report` 返回的 `database_ref_sha256` 继续操作。客户库恢复、删除和重建只能经已绑定会话的 MCP 与 scoped worker 执行，CLI 不会绕过该边界直接打开任意客户库。

## 标准检查顺序

```powershell
& '.\.venv\Scripts\consultation-kb.exe' doctor --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' recovery-report --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' recover --repo-root . --vault-root '<absolute-vault>' --json
```

第二条命令返回不含正文的队列计数、tombstone epoch、SQLite sidecar 状态和 opaque `database_ref_sha256`。第三条始终是 dry-run，`applied_count` 必须为 `0`。

正式激活或破坏性恢复属于 P1 正式写。当前 CLI 在没有一次性签名批准通道时对 `recover --apply` 固定返回 `LIFECYCLE_APPROVAL_REQUIRED`；这表示安全拒绝，不表示恢复已执行。

## 症状、命令与预期结果

| 症状 | 先执行的安全命令 | 预期结果与下一步 |
|---|---|---|
| 存在 `PREPARED` 或 `VERIFIED` publication | `recovery-report --json`，再执行 `recover --json` | `publication_operations` 显示计数，`startup_health` 为 `RECOVERY_PENDING`；dry-run 不改变版本。只有完整成员、hash/source/base/approval/permission/tombstone 证据都有效时，正式恢复器才可激活。 |
| active hash、member closure 或 source version 不匹配 | `doctor --json`，再执行 `recovery-report --json` | Doctor 非零退出；查询保持 fail closed，不回退到未知旧版本。使用报告中的数据库引用生成重建预览。 |
| outbox 长时间 pending/claimed | 先执行 `recovery-report --json`，再由当前会话 scoped worker 做 dry-run inventory | Global 报告的 `outbox.status` 为 `SCOPED_WORKER_REQUIRED`；具体计数只在所属客户 worker 内读取。恢复只允许重放同一幂等事件或补 source ack；不得重新消费批准、创建第二份案例或扫描无关客户库。 |
| Windows mmap/文件锁未释放 | 先停止对应服务或关闭持有该 vault 的 Codex 任务，再执行 `recovery-report --json` | 锁释放前不做清理/激活；释放后只读快照可打开。不要删除被锁文件，不要复制正在写入的数据库。 |
| 出现 `-wal`、`-shm` 或 journal sidecar | `recovery-report --json` | 返回 `LIFECYCLE_SNAPSHOT_UNSAFE`，并只报告 sidecar 是否存在及大小，不打开不安全 immutable snapshot。停止写入者并使用受管恢复/checkpoint 流程；不要手工删除 sidecar。 |
| backup destruction pending/failed | `recovery-report --json` | `backup_queue` 显示 `PENDING/RUNNING/FAILED/SUCCEEDED` 计数。tombstone 可见性不因备份清理失败而恢复；修复存储权限后重试同一队列项。 |
| Codex 任务已关闭但数据仍在 | `recovery-report --json`；若确需删除，按 deletion 手册先 `preview_delete` | 关闭或保留 Codex 任务不等于删除知识库对象。删除必须有独立 plan、base versions、P1 批准和 tombstone。 |

## 重建预览与状态

先从 `recovery-report` 复制 opaque 数据库引用：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' rebuild-start `
  --purpose all `
  --database-ref-sha256 '<sha256>' `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

预期返回 `status: preview`、`approval_required: true`、`plan_sha256` 和精确的 `tombstone_epoch` base version，不入队、不等待 embedding。该 `plan_sha256` 直接来自生产 `RebuildCoordinator.plan()`，绑定 builder DAG、权威快照、policy/model descriptor 与 P1 scope；它不是 CLI 另行生成的摘要 hash。正式 global/client 重建必须通过 P1 批准的 `start_rebuild` MCP；成功只表示持久队列已写入，并立即返回 job ID。

```powershell
& '.\.venv\Scripts\consultation-kb.exe' rebuild-status `
  --job '<rebuild_job_id>' `
  --database-ref-sha256 '<sha256>' `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

合法状态顺序为 `queued → running → verifying → activating → succeeded`，也可能终止为 `failed/cancelled`。只有 verification 成功后才出现 output manifest set 与 equivalence report hash；activation 前可通过正式批准的 MCP `cancel_rebuild` 取消，进入 activation 后固定拒绝。

重建必须从权威 Source/Passage、approved Claim、Wiki/C1 revision、客户 FactEvent、actual session/review decision 与案例 authorization/provenance 重放。不得把模型中间推理、旧 profile diff 或已 tombstone 内容当权威输入。

## Source-first rollback

Rollback 不是把 active pointer 指回历史 manifest，也不会删除或改写历史。先预览一个不可变 rollback plan，审核其中的当前版本、恢复版本、权威 base versions、精确 source diff 和影响闭包；正式提交必须使用同一 plan ref/hash 和一次性 P1 批准。

- 客户事实回滚追加一条反向 `FactEvent`，保留原事件历史，并在同一目标事务中排入 `purpose=all` 的客户闭包重建；提交后 scoped worker 会立即继续该 job，进程重启也会从 journal 恢复。
- Wiki 回滚创建新的 `PREPARED` revision，其内容由指定历史 revision 重新构造；不会把旧 revision 改回 ACTIVE。历史依赖若已 superseded、revoked、expired 或 tombstoned，预览/提交会 fail closed，需要先走新的受管内容与依赖审核。
- C1 回滚同样创建新的 `PREPARED` theory revision，完整保留 scope policy、claim refs、经验支持状态与来源引用，并仍需主咨询师批准。C1 的高优先级不允许绕过事实、权限、时态或硬约束。
- artifact rollback 必须引用已预览的 source rollback plan；它以 source successor 驱动完整 graph/lex/vector/wiki/profile/index 闭包重建，不直接复制历史派生字节，也不声称 source 与每个派生变化之间具有未经构建证明的唯一因果关系。

查询恢复前会联合验证 outer rollback plan、source plan、目标事务中的批准执行证明、rebuild job/stage bindings、active closure 与当前 authority/tombstone epoch。任一引用漂移或证据缺失都保持旧 active 或 fail closed，不使用 ID-to-latest、相邻客户库或其他 store 补全。

## 完成判据

- `doctor` 通过，required 查询恢复可用；
- `recovery-report` 无未知 PREPARED、无 pending source ack、无异常 WAL/journal；
- 重建 job 为 `succeeded`，且 output manifest set 与 equivalence report hash 均存在；
- exact/semantic equivalence 通过，并证明 tombstone 内容为零召回；
- 同一恢复/重建命令重试不产生第二个版本、事件或 job。
