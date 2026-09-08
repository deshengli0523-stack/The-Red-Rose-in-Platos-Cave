---
name: knowledge-curator
description: Use on demand when a counselor asks to curate local source-inbox material, review knowledge drafts, publish approved claims or Wiki revisions, or propose C1 theory changes in this repository.
---

# Knowledge Curator

## 核心原则

只整理咨询师明确放入固定本地 source inbox 的资料。工具之间只传 opaque handle、draft ID 或版本 ref；不得接受或传递任意文件路径，不得自动联网抓取或自动写入正式知识。

## 标准批准链

以下顺序不可跳步：

1. `list_source_inbox`
2. `register_source_draft`
3. `extract_passages`
4. `approve_passage`
5. `propose_claims`
6. `preview_claim_review`
7. `approve_claim`
8. `propose_wiki_update`
9. `preview_wiki_update`
10. `publish_wiki`
11. `knowledge_lint`

正式 Passage/Claim/Wiki 写入前必须展示精确 diff，并在目标事务中消费对应的一次性本地批准。模型、子代理和候选回答只能提出草稿，不能批准、提升审核级别或把草稿描述成已发布。lint 失败或版本漂移时停止发布并重新预览。

## C1 理论

C1 是咨询师自创理论的最高咨询框架，但不能覆盖客户事实、原文、当前官方事实或硬约束。先用 `propose_theory_revision` 生成 proposal 和精确 diff；只有咨询师正式本地批准后，才调用 `approve_theory_revision`。不得由模型代签批准。

## 边界与隐私

P8 注册 `start_rebuild` 前不得调用、暗示或伪造任何 rebuild 成功。未注册的归档、删除、回滚工具同样不能假成功。

去标识化必须发生在粘贴到 Codex 前；扫描只能拦截后续落盘，无法撤回已经发送的文本。客户正文、案例原文、稳定身份信息与私有 profile 不得加入 Git、Codex Memory 或 Chronicle。

## 快速检查

| 检查 | 必须成立 |
|---|---|
| 来源 | 固定 inbox，服务端解析 handle |
| 证据 | Passage 与 Claim 有明确版本和来源 |
| 正式写入 | 精确 diff + 匹配的一次性本地批准 |
| 网络 | 运行时自动联网关闭 |
| C1 | proposal 与咨询师批准分离 |
