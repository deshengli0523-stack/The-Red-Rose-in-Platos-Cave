---
name: consultation-session
description: Use on demand when a counselor asks to start, continue, resume, end, or adopt a version for a text-only client consultation, and for every new client text after this task has an active bound session.
---

# Consultation Session

## 核心原则

一个 Codex task 只服务一个 client。会谈开始后 task 与该客户永久绑定；后续只传不透明 `session_handle`，不得换客户、读取其他客户或传客户路径。

## 触发语句

尚未绑定客户的 task，只有“开始咨询”“继续咨询”“恢复咨询”“结束咨询”“采用版本”及含义等价的明确请求才触发本 skill，普通讨论不自动加载。一旦本 task 已永久绑定且存在 active session，任何新的来访者正文都视为“继续咨询”并触发本 skill；不得因正文没有命令词而跳过追加、上一轮 actual closure 或候选登记。

## 每轮流程

1. 开始或恢复时调用 `load_client_context`，固定本次会谈的只读 profile 快照。新陈述只进本 session 的临时事实，不直接成为正式事实。
2. 调用 `append_session_turn` 保存来访者原文。若上一轮尚未记录实际回复，先关闭上一轮；不得接收下一条来访者消息。
3. 追加成功后，先让系统执行确定性内部风险规则。规则结果只进入咨询师内部对象；模型不得改写、确认或关闭它。随后对本轮明确的新事实、目标、纠正、冲突或待解决事项调用 `append_temporary_fact`，使用稳定幂等键；它只进入当前会谈临时账本，不得冒充已审核的客户长期事实。若事实直接决定 C1 的适用性，按下文的保留注解格式附加安全词表键；不得从自由文本暗自猜测适用性。
4. 调用 `get_generation_state` 取得当前 query binding，据此提交 `query_plan`。只有响应达到 `retrieval_status=ready` 并返回精确 EvidencePack hash，才能继续；禁止使用自报、旧版或未就绪的 pack。检索案例前必须按传递性来源客户排除当前客户，不能先读取再靠提示词删除。
5. 对同一个 ready EvidencePack，依次用 `submit_generation_stage` 提交 `conceptualization`、`theory_comparison`、包含 2–3 个版本的 `reply_drafts`、`evidence_audit`、`consistency_risk_review` 和 `final_bundle`。回复版本可以有不同语气与策略，但事实、核心判断和行动方向必须一致，且每个版本的核心判断与行动方向均不得为空。`evidence_audit` 必须覆盖每个分析/回复主张与其支持、反证证据的组合，并为每一组合提交独立语义判断、独立判定的主张类型、EvidencePack 冻结正文中的精确片段、Unicode 字符偏移和片段 SHA-256；同一主张的各组合类型判断必须一致并与声明类型相符，不能把建议误标为事实或结论来绕过建议约束。`consistency_risk_review` 必须为当前候选的每个事实状态、核心立场和行动方向各提交唯一一条覆盖完整候选正文的 exact-span critic 判断；历史/资料快照按“事实轴 × 该事实证据”及“核心立场/行动/结论 × 结论证据”逐对提交冻结 evidence context 的 exact excerpt、Unicode 偏移和 SHA-256，不得借用同一快照中的无关证据。确定性层只证明来源、完整 pair 集合和投影闭包；语义值由独立 critic 给出，不得用关键词匹配或结构校验冒充自动蕴含证明。内部分析、引导建议、依据与一致性说明进入咨询师工作台。
6. 若确定性复核返回 `retrieve_more`，必须修改上游 `query_plan` 并取得新的 ready EvidencePack；若返回 `rewrite`，必须修改被指出的上游工件，不能只改审计结论或重提相同内容。纠正最多 2 次；仍未解决时保留 `needs_counselor_judgment`、不足与冲突，明确交咨询师判断，不得伪造确定性。
7. `final_bundle` 成功后由咨询师选择版本。候选回复不是实际回复，模型输出也不是证据；不得再调用旧候选登记旁路。
8. 咨询师明确“采用版本”后，用 `record_actual_reply` 记录以下一种：原样采用、保存精确编辑正文与 diff 的编辑采用，或 `external_reply_unknown`。未记录实际发送内容时不得把候选推定为已发送。

## P6 MCP 工具边界

P6 新增 MCP 工具仅有：

- `submit_generation_stage`
- `get_generation_state`
- `acknowledge_risk_observation`

它们不能替代既有 session 生命周期和 actual reply 记录。风险观察只有在咨询师明确处置时，才以 `action=acknowledge` 确认；确认不等于风险已经解决。只有咨询师再次明确判断该观察已不再适用后，才以 `action=close` 提交 `close_decision` 与非空 `close_reason`；不得因为已确认、本轮未再命中规则或回复已生成而自动关闭。多代理不得被声称为安全边界，真正的边界是严格工件、阶段顺序、证据绑定和 scoped worker 校验。

## C1 适用性保留注解

只有受信的客户资料项或当前轮临时事实可带顶层 `c1_context`；其值必须是结构化安全词表，不得放客户原文或自由解释。格式为：

```json
{
  "value": "依既有事实字段保存的值",
  "c1_context": {
    "schema_version": "c1_context_projection.v1",
    "fields": [
      {
        "context_field": "domain",
        "state": "values",
        "value_keys": ["emotional_consultation"]
      }
    ]
  }
}
```

`fields` 按 `context_field` 排序且不重复，`value_keys` 也必须排序且不重复。`state=values` 必须有键；`known_empty` 表示已知为空，`unknown` 表示未知，两者的 `value_keys` 必须为空。当前轮的明确纠正覆盖资料快照；当 `target_fact_id` 使旧事实失效后，原字段先变为 `unknown`，不得沿用旧适用性。没有这个注解时系统必须返回上下文不足，不对原文做分类。

## 回答与理论边界

来访者文本默认无引用，不显示 evidence ID、来源等级、内部风险标签、级别、规则或系统警告；风险观察仅供咨询师内部使用。C1 是适用范围内的最高框架，但不得覆盖当前事实、反证、时态、授权、适用范围或其他事实硬约束。理论不足、事实冲突或证据有限时，保留不确定性并提出澄清问题。

## 结束与隐私

“结束咨询”时严格按以下顺序处理：

1. 先补齐未关闭轮次，并确认每一轮都已用 `record_actual_reply` 保存实际回复或 `external_reply_unknown`。候选回复不能补写成实际回复。
2. 调用 `propose_archive`，确认不可拒绝的 `ActualTranscript` 已持久化，并取得同一 bundle 下彼此独立的私有归档、profile diff 与共享案例草稿状态。
3. 调用 `preview_private_archive` 展示 actual/analysis 边界与精确 diff；咨询师可批准、拒绝或要求可信生产者修改。只有独立的 `private_archive_publish` 批准才能交给 `commit_private_archive`，不得拿 profile 或案例批准代替。
4. 独立调用 `preview_profile_diff`，逐项复核 ADD/CONFIRM/CORRECT/SUPERSEDE/RESOLVE/MERGE、直接失效与间接边效应；已解决、失效和重复信息必须从当前资料投影删除但保留历史。只有独立的 `profile_update` 批准才能交给 `commit_profile_update`；拒绝、部分批准或 no change 不受共享案例结果影响。
5. 最后独立展示共享 candidate、授权范围、脱敏扫描和人工复核。共享是可选项；只有咨询师明确批准时才调用 `approve_case`。未授权、授权过期/撤回、脱敏版本变化、稀有组合未处置或旧批准均必须关闭失败，但不得阻塞合法的私有归档或 profile 更新。

三种批准必须目的独立、一次性且不可互换。不得把 ActualTranscript、包含私有分析的 PrivateArchiveDraft、结构化 profile diff 与共享案例当作同一文件直接复制；模型不得直接写客户数据库、CAS、路径或 SQL，只能传当前绑定 `session_handle` 与工具返回的精确引用/批准标识。

## P7 MCP 归档工具边界

- `propose_archive`
- `preview_private_archive`
- `commit_private_archive`
- `preview_profile_diff`
- `commit_profile_update`
- `approve_case`

上述工具全部继承本 task 已有的永久客户绑定。任何错误 bundle、错误客户、非精确引用、过期或已消费批准都必须 fail closed；不得通过重试把一种批准转换为另一种用途。

`approve_case COMMIT` 只能消费一次独立案例批准。source P1 已为 `APPLIED` 且 outbox 已进入 `PENDING`/`CLAIMED` 后，全局发布或 source ACK 中断必须用该密封事件幂等重放，不得重新签发、重新提交或重新消费外部批准；只有 global case 为 `ACTIVE` 且 source exact ACK 已持久化后，工具才能返回带精确 `published_global_version` 的 `PUBLISHED`。

去标识化必须发生在粘贴到 Codex 前；扫描只能阻止后续写入，不能撤回已经发送的文本。客户正文、原始会谈、稳定身份信息与私有 profile 不得加入 Git、Codex Memory 或 Chronicle。

## 常见错误

| 错误 | 正确处理 |
|---|---|
| 中途刷新 profile | 保持开始时快照，只把变化记为临时事实 |
| 直接发送模型首稿 | 完成 P6 阶段并由咨询师选择，再记录实际采用文本 |
| 客户自己的旧案例被举例 | 在检索前按来源客户全谱系排除 |
| 在回复中显示风险级别 | 仅提醒咨询师内部观察 |
| 重提相同审计并增加 retry | 按决定修改查询或回复等上游工件 |
