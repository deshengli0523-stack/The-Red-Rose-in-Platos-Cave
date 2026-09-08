# 质量评测与回归手册

评测用于证明和持续提高回答质量，不是额外的日常咨询上线审批门。确定性安全、隔离、权限、C1 scope/version、tombstone 与归档不变量仍要求 100%；主观质量目标用于定位改进方向，不能用缺样本或模型自评伪装达标。

## 数据登记边界

Git 中只允许合成数据集：`gold_cases.jsonl`、`gold_retrieval.jsonl`、`canary_cases.jsonl`。loader 固定文件 hash、记录 hash、policy/object catalog 和 scenario family split，并拒绝真实敏感度、直接身份、客户 ID、重复/近重复 family 与把 canary 加入正式知识索引。

若未来把获准真实案例用于受控评测，它仍留在原客户/用途 scope 的 vault catalog 中，不进入 Git、共享评测集、全局日志或报告；MCP 也不得返回真实客户正文。当前 `EvaluationRuntime` 只从仓库固定的 synthetic fixtures 建队列。

## 公平比较的系统版本

五个基线固定为：

1. `general_model_only`：无知识检索；
2. `hybrid_rag_only`：词法与向量，不用 Wiki、图、案例和 C1；
3. `wiki_hybrid_rag`：Wiki、词法、向量，不用图、客户时态、案例和 C1 priority；
4. `full_without_c1_priority`：完整技术层，但 C1 只是普通来源；
5. `full_system`：C1 最高框架优先级、Wiki、hybrid RAG、全局图、客户时态图、案例和多阶段 critique。

另有 `full_without_graphify_navigation`、`full_without_cases`、`full_without_reranker` 三个消融。比较时只改变 feature flags/route policy；model label、reasoning effort、Prompt/Skill/schema/reply contract、客户快照、资料 manifests、retry budget 必须相同。Codex-only 宿主没有暴露 temperature/generation seed 时，manifest 必须保留 `host_unknown_fields`，不得声称已固定。

每个 case/variant 至少重复两次；`queue_order_seed` 只随机化配对顺序，不是模型 generation seed。失败重试不得换资料版本或把 full-system evidence 带进弱基线。

## Codex + MCP 执行顺序

1. 运行 `doctor`，确认资料、模型、Skill、schema 与 runtime closure 已冻结。
2. 调用 `prepare_evaluation`，提交 UUIDv7 run ID、完整 `EvaluationFairnessContract`、按 registry 顺序排列的 variants 与一一对应 route policy refs。工具不接收路径。
3. 保存返回的 64-hex `evaluation_handle`、`plan_sha256`、`queue_sha256` 与 bundle hash。
4. 循环调用 `get_next_evaluation_case`。它只在该不可猜测的 synthetic evaluation scope 中返回当前合成输入；durable queue、共享日志和其他工具仍无正文。
5. 对该 variant 严格使用相同 stage contract 生成 exact `FinalTurnBundle`。禁止读取或携带被该 variant 禁用的 channel；不要把前一个 variant 的 evidence 留在上下文中。
6. 调用 `submit_evaluation_result`，同时提交 `work_item_id`、`case_payload_sha256`、`variant_sha256`、固定 `client_snapshot_ref`、`evidence_catalog_sha256`、`evidence_pack_sha256` 和 exact stage result。任一 hash/snapshot/route/manifest 漂移都拒绝，错误不反射候选正文。
7. 全部完成后调用 `finalize_evaluation`。完整队列状态为 `succeeded`；若宿主中断，必须为每一个缺失 work item 给出精确 reason，报告只能是 `incomplete`，不能当成功或按 100% 计分。
8. 在冻结 submissions 上运行 deterministic metrics，再生成随机盲评 packet 与最终 JSON/Markdown 报告。

MCP 进程重启后，使用原 `evaluation_handle` 可从 body-free plan 恢复队列；运行时重新核验数据 bundle hash 后才再次按需返回合成输入。不要传队列目录或扫描任意路径。

## 本地 CLI 镜像

四个 CLI 命令接受一个严格 JSON request 文件，字段与同名 MCP schema 完全一致，适合离线诊断或受控自动化：

```powershell
& '.\.venv\Scripts\consultation-kb.exe' evaluation-prepare --request '.\prepare.json' --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' evaluation-next --request '.\next.json' --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' evaluation-submit --request '.\submit.json' --repo-root . --vault-root '<absolute-vault>' --json
& '.\.venv\Scripts\consultation-kb.exe' evaluation-finalize --request '.\finalize.json' --repo-root . --vault-root '<absolute-vault>' --json
```

request 文件只能放合成评测正文，不得用于搬运真实来访者内容；不得提交到 Git。CLI 输出不含路径，只有 `evaluation-next --json` 会按请求返回当前 synthetic case text。

## 指标与缺样本规则

检索层报告 Recall@k、Precision@k、nDCG、MRR、原句/定位、来源多样性、重复、反证和 prefilter accuracy。回答层报告 claim support、paraphrase fidelity、C1 applicability/active/main-framework、经验状态、冲突/过度断言、认知类型和不确定性校准。还要并列跨轮/跨次一致性、结论变化解释、时态更新、profile diff、隔离/自案例排除、风险内部流程、双份归档和 tombstone 零召回。

每项指标必须声明 denominator、undefined policy、micro/macro 和 95% bootstrap CI。缺样本是 `undefined/incomplete`，绝不能默认为 100%。任一 zero-tolerance 指标失败使 deterministic correctness summary 失败。

持续质量目标为：

- C1 permission/version 100%；
- C1 applicable/out-of-scope ≥95%；
- C1 empirical ≥95%，deterministic overclaim 为 0；
- Recall@10 ≥90%；
- supported claims ≥95%；
- unexplained contradiction-free ≥95%；
- `full_system` 相对 `hybrid_rag_only` 的专家偏好 ≥70%。

这些目标用于趋势和回归判断，不允许覆盖事实、权限、风险或隔离硬约束，也不额外阻断日常咨询。

## 本地模型基准

四个候选模型必须先按 [operations.md](operations.md) 固定 40-hex revision、license、文件 hash 与完整 descriptor，并以 offline/local-only 方式加载。embedding/reranker benchmark 使用 gold retrieval 的中文原句、改写、跨域、反证和 C1 scope slices；质量选择遵循：zero constraint failures → Recall/counterevidence → nDCG → 资源占用。CPU latency/memory 只作次要信息，不能用速度交换确定性错误。

缺任一候选或 runtime manifest/hash 不闭合时，模型比较保持 incomplete，不自动回退到未锁定模型。

## 专家盲评

对同一 case 的 `full_system` 与 `hybrid_rag_only` 随机左右排列，隐藏 system/run/model 身份；packet 只保留合成来访者上下文和评分说明，不含 client/source ID 或内部风险标签。至少两名咨询师分别评估有用性、共情、具体性、可执行性、自主性、事实/证据忠实、冲突/不确定性处理与专业边界，选择 left/right/tie 并填写结构化原因。

模型自评只能作为辅助 finding，不能替代专家结果。importer 必须核验 blind mapping hash、不可逆 reviewer ID、重复/缺失和自相矛盾，并报告一致性与置信区间。

## 失败 slice 修复与版本回归

报告必须显示每个失败 sample ID、slice、variant、固定版本与 degradation/missing，不得只给总分。按失败类型修复最小负责层：检索漏召回改索引/路由或模型；证据冲突改 evidence/critique；C1 scope 错误改权限或 deterministic applicability；时态残留改事实边传播/profile diff；同客户案例误用改全谱系 exclusion；主观表达问题改 Prompt/Skill，但不得改变比较中的其他固定变量。

修复后用同一冻结数据和公平合同重跑失败 slice，再跑所有 zero-tolerance、五基线与关键消融。新资料、模型、Prompt、Skill、schema、policy 或索引版本必须生成新的 run manifest；不能覆盖旧报告或把不同版本样本合并成同一 run。
