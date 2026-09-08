---
name: quality-evaluator
description: Use on demand when a counselor asks to run, resume, compare, benchmark, or finalize a consultation quality evaluation.
---

# Quality Evaluator

## 核心原则

只运行版本冻结、配对公平、可核验的本地评估。Codex 负责逐项执行统一生成合同；不得调用 OpenAI API，也不得用时间压力换取虚假的成功结论。

## 执行流程

1. 先运行 `doctor` 并核对 frozen versions。不得跳过 doctor；不得跳过版本冻结。任一必需 runtime、dataset、model、Skill、prompt、schema、资料快照或策略引用不可解析时停止，不创建 queue。
2. 调用 `prepare_evaluation`，固定 case、variant、重复次数、输入快照、证据目录、模型标签、reasoning effort、Skill/prompt/schema、reply contract 与 retry budget。`queue_order_seed` 只控制队列顺序；不得把它称作 `generation_seed`。宿主未暴露的 `temperature` 与 `generation_seed` 必须进入 `host_unknown_fields`。
3. 循环调用 `get_next_evaluation_case`。每个 variant 只使用其允许的检索通道；不得跨 variant 复用 EvidencePack、候选正文或检索结果。full-system 证据不能泄漏给基线。
4. 完成同一阶段合同后调用 `submit_evaluation_result`，提交 exact case/variant/snapshot/EvidencePack/final bundle/run-manifest hashes。失败或重试不得切换资料版本。
5. 队列完整后调用 `finalize_evaluation`。若仍有缺项，只能得到 `INCOMPLETE` 与明确 missing reasons；只跑一半不得标记成功。时间压力不能豁免完整性、公平性或版本检查。
6. 对完整结果运行 deterministic metrics，再生成 blind review packets，最后生成 JSON/Markdown report。报告必须显示 missing、degradation、失败 slice 与版本，不把质量目标冒充新的运营审批门。

## 数据边界

- MCP 输出不得包含真实 client ID 或客户正文；评估正文只在受控 synthetic evaluation scope 按需读取。
- 盲评包隐藏 system、run、model、client/source 标识及内部风险标签。内部风险标签不得进入盲评包。
- Git、共享日志、metrics 与 report 只保存引用、哈希、计数、枚举和合成 case ID。

## 常见错误

| 错误 | 正确处理 |
|---|---|
| 为赶时间跳过 doctor 或冻结 | 停止并报告不可复现 |
| 给基线复用 full-system 证据 | 为各 variant 独立检索并校验禁用通道 |
| 缺一半样本仍宣布成功 | 返回 `INCOMPLETE` 和 missing reasons |
| 用队列 seed 冒充模型 seed | 分开记录，并声明宿主未知字段 |
| 把风险标签给专家看 | 保持双盲，风险只留内部评估边界 |
