# 咨询知识库运维手册

本手册描述 Windows 本机、单咨询师部署。生产基线是 CPython 3.12 x64；3.13 仅作为兼容性矩阵，不替代 3.12 的 Leiden/Graphify 生产路径。所有命令在仓库根目录执行，真实来访者正文、客户 ID、审批票据、数据库路径和密钥不得粘贴到共享日志、Git、评测集或 Codex 普通对话。

## 安装与锁定依赖

先安装官方 CPython 3.12 x64，并确认启动器选择的解释器不是 Codex cache 中的捆绑 Python。创建专用环境后，只从提交的 hash lock 安装第三方包和构建工具，再以禁止索引、禁止构建隔离且不解析依赖的方式安装本项目：

```powershell
py -3.12 -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install --require-hashes -r requirements/consultation-win-py312.lock.txt
& '.\.venv\Scripts\python.exe' -m pip install --no-index --no-build-isolation --no-deps .
& '.\.venv\Scripts\python.exe' -m pip check
```

需要本地 embedding/reranker 时，再安装对应的 `consultation-ml-win-py312.lock.txt`。不得在生产启动时临时 `pip install`、从 mutable `main` 加载模型或让 Transformers 自动联网。3.13 使用独立 core/ML lock；其 Graphify 后端必须明确报告 Louvain degradation，不能冒充 3.12 Leiden 生产结果。

## Vault 与 Windows 防护

- vault 必须位于仓库外的本机 NTFS 普通目录，不得是 UNC、网络盘、junction、symlink 或仓库子目录。
- 使用项目 ACL 初始化/检查流程关闭继承，只授予当前咨询师账户、SYSTEM 和经过授权的备份主体。不要通过给 `Everyone` 权限修复启动失败。
- 建议 vault 所在卷启用 BitLocker。DPAPI 保护本机秘密与身份映射，但不替代卷加密，也不使普通文件副本自动安全。
- 备份必须单独加密，并沿用源对象的保留、tombstone 与销毁队列规则。不要把 vault 放入 Git、同步盘或普通压缩包。

## 首次检查与 Codex MCP

```powershell
& '.\.venv\Scripts\consultation-kb.exe' migrate --check --repo-root . --vault-root '<absolute-vault>'
& '.\.venv\Scripts\consultation-kb.exe' doctor --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' configure-codex --repo-root .
```

`doctor` 必须验证迁移、ACL/DPAPI、active manifests、检索产物、MCP tool schema hash、STDIO stdout discipline 和会话恢复状态。配置生成后重启 Codex 的 MCP 连接；服务使用 STDIO，没有端口。若 schema 或本地代码变化而旧连接仍在，先结束该 MCP 进程，再让 Codex 重新启动 `.codex/start-consultation-kb.ps1`，随后重跑 `doctor`。

## 离线模型导入

运行时固定 `local_files_only=true`、`trust_remote_code=false`。模型导入只有以下两个互斥模式。

本地快照模式不联网，要求同时提供已核验目录、40 位小写 commit 和许可证：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' models-import `
  --repo 'BAAI/bge-m3' `
  --source 'D:\approved-model-snapshot' `
  --revision '<40-hex-commit>' `
  --license 'mit' `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

显式官方解析模式是运维人员主动发起的联网动作；它只访问官方 Hugging Face endpoint，把 `main` 解析为精确 commit，再下载、核验 repo/license/file hashes 并立即导入：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' models-import `
  --repo 'BAAI/bge-m3' `
  --resolve-main `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

`--resolve-main` 不能与 `--source`、`--revision` 或 `--license` 同时出现；本地模式也不能缺少其中任一项。只有这条显式命令拥有模型下载网络边界，MCP、咨询、检索、评测和后续模型加载仍保持离线。四个候选必须分别核验并登记；导入后重跑 model lock、benchmark 与 `doctor`。

## 本地模型基准

只有运行清单已登记全部两个 embedding 和两个 reranker 后才能执行正式基准。基准严格从 vault 本地加载固定快照，不得在缺模型时缩小候选集：

```powershell
$env:HF_HUB_OFFLINE = '1'
$env:TRANSFORMERS_OFFLINE = '1'
& '.\.venv\Scripts\consultation-kb.exe' model-benchmark `
  --output-ref 'p9_quality_baseline_20260722_a' `
  --repo-root . `
  --vault-root '<absolute-vault>' `
  --json
```

`output-ref` 是不含客户或模型正文的 opaque lower-snake 引用，每次正式运行使用新值。成功输出必须显示四个候选组合、固定 runtime manifest/suite hash、选中的 embedding/reranker 和报告 hash。主选择顺序是零硬约束失败、Recall/counterevidence、nDCG；延迟只是质量完全持平后的次级指标，内存字段若标记为 Python 诊断范围，不得解读为 PyTorch/native 真实总 RAM。报告只能含 ID、counts、metrics 和 hashes，不得含 query、passage、绝对路径或来访者正文。

## 日常启动与会话恢复

每次启动先运行 `doctor --json`。一个 Codex 任务只绑定一个客户；只有 `load_client_context` 可以接收客户身份，绑定后所有客户工具只使用 opaque `session_handle`。恢复中断会话时通过同一客户的 `resume_session_id` 重新加载，系统会按持久状态回到待检索、待生成、待确认实际回复或待归档阶段；不得另开客户库、猜测路径或跳过“实际发送回复已记录”门禁。

风险观察只进入咨询师内部路径。对来访者的正常文本回答不输出内部风险标签或风险提示；需要人工关注时由咨询师侧处理。

## 备份与恢复

备份前停止写入该 vault 的 MCP/worker，运行：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' recovery-report --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' recover --repo-root . --vault-root '<absolute-vault>' --json
```

只有报告无不安全 WAL/SHM/journal、无未知 publication 状态时，才使用组织批准的加密备份工具复制整个 vault 闭包；不能只复制 `.sqlite3`，也不能在活跃写入时做普通文件复制。备份清单应记录不可逆 vault 标识、策略版本、对象/hash 计数和备份时间，不记录正文或直接身份。

恢复必须先落到隔离的新本机目录，保持 ACL 与加密边界，运行 migration check、`doctor`、recovery dry-run、active manifest/hash 校验和 tombstone 零召回验证。验证通过后才切换配置。不要覆盖仍在使用的 vault，也不要手工删除 SQLite sidecar。详细故障流程见 [recovery.md](recovery.md)。

## 删除、重建与回滚

删除、正式重建和 source-first rollback 都是精确 plan + base versions + 一次性批准的正式写；CLI 只提供只读状态或预览，不能绕过已绑定客户 worker。标准顺序是 preview、人工 review、用同一 plan/ref/hash commit、验证所有通道零召回、等待物理清理/重建证明。

```powershell
& '.\.venv\Scripts\consultation-kb.exe' recovery-report --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' rebuild-status --job '<opaque-job>' --database-ref-sha256 '<sha256>' --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' delete-status --database-ref-sha256 '<sha256>' --repo-root . --vault-root '<absolute-vault>' --json
```

不要手工删除数据库、WAL、索引、缓存或客户目录。tombstone 先保证逻辑零召回；物理清理失败不得恢复可见性。详见 [deletion.md](deletion.md) 与 [recovery.md](recovery.md)。

## Codex 任务与本地数据不是同一生命周期

关闭、归档或删除 Codex 任务，只影响 Codex 对话/任务界面，不会删除 vault 中的客户资料、完整案例、结构化摘要、审计记录或派生索引。反之，执行知识库删除也不会自动删除 Codex 任务。需要删除客户数据时必须走 `preview_delete`/批准/`commit_delete`；需要清理 Codex 任务时另行操作，并分别验证两个结果。不得把“看不到任务”当作数据已删除的证据。

## 最小完成检查

- `pip check`、migration check 与 `doctor` 全部通过；
- MCP 列表/schema hash 与当前代码一致，stdout 无日志污染；
- required 检索/风险/评测能力缺失时 fail closed，无静默降级；
- 会话恢复不跨客户，actual reply 在下一轮前已经持久化；
- 删除后所有通道与进程重启后仍零召回；
- 备份、模型和评测报告均不含真实正文、稳定客户 ID 或本机绝对路径。
