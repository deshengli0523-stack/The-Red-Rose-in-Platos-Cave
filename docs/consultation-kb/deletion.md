# 删除与物理清理运行手册

删除分为两个不可混淆的阶段：先写权威 tombstone，使所有 SQL、图、词法、向量、Wiki、案例与缓存查询立即零召回；再由持久队列清理 SQLite/WAL/FTS/vector/cache/temp/旧对象和备份。后续清理或重建失败不得恢复可见性。

## 安全流程

1. 在已绑定当前来访者会话的 MCP 中调用 `preview_delete`。可预览绑定 session 内对象，或由当前绑定客户发起整客户删除；工具参数不能提交路径、SQL、客户 ID 或另一个会话 ID。
2. 核对返回的 immutable plan、影响闭包、`plan_sha256`、target scope hash 与全部 base versions。
3. 使用本地交互式批准：

   ```powershell
   & '.\.venv\Scripts\consultation-kb.exe' review --request '<approval_request_id>' --repo-root . --vault-root '<absolute-vault>'
   ```

4. 只有批准完成后，使用完全相同的 plan ref/hash、base versions、approval operation/request 调用 `commit_delete`。
5. commit 返回 tombstone 后立即验证所有查询零召回；物理清理与备份销毁通过队列异步完成。

不得跳过 preview，不得重新计算或替换 plan hash，不得在批准后修改 target/base version。过期、撤销、scope 不同或 nonce 已消费的批准一律重新 preview，而不是重放旧票据。

## 整客户删除

整客户删除只允许从当前已绑定客户的 scoped worker 发起。预览会固定客户本地闭包、global case/provenance contributions、identity-map entry、当前 tombstone/authorization epochs 与清理顺序；提交仍需精确 plan 和一次性 P1 批准。

执行顺序是：先在 global authority 中撤销该客户贡献并提升 tombstone epoch，使所有共享检索立即零召回；再停止该客户 worker/句柄，清理客户 SQLite、CAS、索引、WAL/SHM、缓存与到期备份；最后删除 identity-map entry，只保留无正文的 tombstone、审批和清理证明。相邻客户的 scope root、identity mapping、事实、案例与 active manifests 必须保持逐项不变。

进程中断或 Windows 文件锁只会把同一 saga/cleanup item 留在可重试状态。重启后按 journal 继续，不重新创建删除请求，不恢复可见性，也不扫描或打开无关客户库。

第一阶段没有每客户独立数据密钥，因此这里实现的是 clean rebuild、verified removal 与备份到期销毁，不宣称 per-client cryptographic erasure。只有未来引入独立客户密钥并验证所有副本都由该密钥覆盖后，才可使用“密码学擦除”表述。

## 状态查询

先运行：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' recovery-report --repo-root . --vault-root '<absolute-vault>' --json
```

再使用报告中的 opaque global database reference：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' delete-status `
  --database-ref-sha256 '<sha256>' `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

若已知删除请求，可加 `--request '<deletion_request_id>'`。输出仅包含 opaque ID/hash、版本、tombstone epoch、生命周期和队列状态，不含目标正文或直接身份。

| 状态/症状 | 安全解释 | 预期操作 |
|---|---|---|
| `TOMBSTONED / PENDING` | 权威不可见已经生效，物理清理尚未领取 | 继续保持零召回；等待持久队列，不要再次 commit。 |
| `TOMBSTONED / RUNNING` | 清理正在执行 | 不并发手工删除文件；等待同一请求更新。 |
| `TOMBSTONED / PARTIAL` | 部分对象因锁、WAL、备份或外部存储暂未清除 | 释放锁/修复权限后重试同一队列；不可撤销 tombstone。 |
| `TOMBSTONED / FAILED` | 清理失败但逻辑删除仍有效 | 查看 body-free error code，修复原因后幂等重试。 |
| `PHYSICAL_CLEANUP_COMPLETE / SUCCEEDED` | 主存储与到期备份闭包均有清理证明 | 保存审计 hash；不要删除 tombstone/history proof。 |
| `DELETION_REQUEST_NOT_FOUND` | 当前 global scope 中无该 opaque request | 检查是否应在已绑定客户 MCP 中查询；不要尝试枚举客户路径。 |
| `LIFECYCLE_SNAPSHOT_UNSAFE` | WAL/SHM/journal 或活跃句柄使离线快照不安全 | 停止写入者并按 recovery 手册处理；不要手工删除 sidecar。 |

## 边效应与级联

- 删除 session 时，案例授权、共享案例派生、profile/graph/index 依赖和备份对象必须进入同一闭包；
- 权限撤回与 tombstone 优先于 retention category；普通保存分类不能作为继续可见或继续共享的授权；
- source deletion intent 触发的重建不可取消，因为取消会留下已删除来源的派生物；
- 客户更换伴侣等事实变化不是物理删除的替代品，应通过新 FactEvent、边失效/置信度传播和结构化摘要更新；只有明确删除请求才走本流程；
- 客户 A 的私有内容、完整案例和派生贡献不得因删除/重建进入客户 B 或 global 的非授权通道。

## 验收清单

- commit 前：plan/base versions/approval descriptor 完全一致；
- commit 后：所有检索通道与进程重启后均零召回；
- cleanup 后：主文件、WAL/SHM、索引、缓存、临时文件、旧对象与到期备份均有 body-free proof；
- 重试同一请求只返回同一结果，不增加 deletion version；
- 审计、tombstone 和最小证明历史保留，但不能反推出正文或直接身份。
