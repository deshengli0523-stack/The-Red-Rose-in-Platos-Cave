# P3：知识、C1 与 LLM Wiki 实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 将本地国学、咨询、生涯和案例资料登记为不可变 Source/Passage/Claim 证据链，实现咨询师 C1 理论的专属版本/批准/撤销治理，并发布可差异修订、可回滚、可 lint 的正式 LLM Wiki。

**Status (2026-07-19):** 已完成并通过根级复验。P3 unit/schema 99 项、Golden/集成 30 项、`THEORY-01/WRITE-01/ISO-02` 强制验收 14 项通过；Ruff、strict Mypy（22 个生产文件）、compileall、`git diff --check` 通过。P4 真实 builder 创建 artifact version 时必须继续调用本阶段冻结的 dependency registration 入口。

**Architecture:** 原文件与稳定 Passage 是证据锚点；模型/Codex 只提交 draft Claim 和 Wiki 差异。全局 SQLite 保存治理状态、来源谱系和修订链；正文放内容寻址对象。C1 使用独立 `TheoryRevisionService`，不能由普通 Claim 定级绕过。Wiki 是获准 Claim 的编译层，不作为自身证据。

**Tech Stack:** sqlite3、Pydantic、pypdf/python-docx/openpyxl 可选本地提取、canonical hashing、P1 approval/manifest、pytest/Hypothesis。

## Global Constraints

- 先完成 P1；可与 P2 并行。读取设计规格第 7、8、10、16.4、17.3 节。
- 运行时只处理用户明确放入 `knowledge-vault/sources/` 的本地文件，不自动联网抓取。
- `Source → Passage → Claim` 是正式主张最小链；Wiki 和模型回答都不能引用自身作为原始证据。
- C1 只能来自 `sources/consultant-theory/` 的正式文档及主咨询师批准事件。普通知识审核不得将对象改为 C1。
- source grade、框架优先级、外部实证状态、模型置信度、审核状态和适用性分列保存。

---

## Task 1：全局知识 Schema 与来源登记

**Files:**

- Create: `consultation_kb/storage/migrations/global/v0002_knowledge.py`
- Create: `consultation_kb/models/knowledge.py`
- Create: `consultation_kb/knowledge/__init__.py`
- Create: `consultation_kb/knowledge/registrar.py`
- Create: `tests/consultation_kb/unit/test_source_registration.py`
- Create: `tests/consultation_kb/unit/test_knowledge_schema.py`

**Interfaces produced:** `SourceRecord`、`PassageRecord`、`ClaimRecord`、`TheoryRevision`、`WikiRevision`；`SourceRegistrar.register_local_file`。

- [ ] 写失败测试：原始文件每次内容变化创建新 source version，旧版不覆盖；路径必须位于 `sources/` 且通过 P1 PathGuard；许可/领域/语言/敏感级别缺一拒绝。

```python
def test_changed_source_creates_new_version(source_registrar, source_file, metadata) -> None:
    first = source_registrar.register_local_file(source_file, metadata)
    source_file.write_text("第二个明确合成版本", encoding="utf-8")
    second = source_registrar.register_local_file(source_file, metadata)
    assert second.source_id == first.source_id
    assert second.version == first.version + 1
    assert second.content_sha256 != first.content_sha256
    assert source_registrar.get(first.source_id, first.version).content_sha256 == first.content_sha256
```

- [ ] 写 Pydantic/DB 约束测试：`source_grade=C1` 的普通 `ClaimRecord` 若无 `theory_revision_id` 失败；`framework_priority=highest` 只有 active/applicable C1 可在运行时派生，不能直接在来源登记时任意写。
- [ ] v0002 创建设计规格 7.5 的表：`sources`、`source_versions`、`passages`、`claims`、`claim_evidence`、`theory_revisions`、`theory_revision_passages`、`entity_aliases`、`review_decisions`、`wiki_revisions`、`wiki_revision_claims`、`artifact_versions`、`artifact_dependencies`、`provenance_edges`。保留 P1 tombstone/manifest 表。
- [ ] 各表用 stable object ID + monotonic version；正文列保存 content object ref，不复制大段正文。Claim 分列 cognitive type、source grade、framework eligibility、empirical support、model confidence、review status、effective/review dates、applicability、privacy/use 和 provenance。
- [ ] Registrar 对源文件先 hash，复制到不可变 content store，再写 DRAFT catalog record；同一 logical source + 相同 hash 幂等返回，同一路径新 hash 创建新版本。原始文件只读，不原地添加 frontmatter。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_source_registration.py tests/consultation_kb/unit/test_knowledge_schema.py
```

Expected: PASS；旧 source version 可独立验证。

---

## Task 2：版面提取与领域稳定 Passage

**Files:**

- Create: `consultation_kb/knowledge/extractors.py`
- Create: `consultation_kb/knowledge/passages.py`
- Create: `consultation_kb/knowledge/anchors.py`
- Create: `tests/consultation_kb/unit/test_extractors.py`
- Create: `tests/consultation_kb/unit/test_passage_segmentation.py`
- Create: `tests/fixtures/consultation_kb/sources/synthetic_classic.md`
- Create: `tests/fixtures/consultation_kb/sources/synthetic_counseling.md`
- Create: `tests/fixtures/consultation_kb/sources/synthetic_career.csv`

**Interfaces produced:** `DocumentExtractor`；`ExtractedBlock`；`PassageSegmenter.segment(document_type, blocks)`；稳定 `PassageAnchor`。

- [ ] 为 txt/md/pdf/docx/xlsx/csv 写 extractor contract 测试；缺少可选依赖时返回明确 `OPTIONAL_EXTRACTOR_MISSING`，不返回空文档假成功。测试 PDF/DOCX 使用程序生成的纯合成小文件。
- [ ] 为五类切分写 golden：古籍按作品/版本/卷篇/章句；注疏/论文保留作者/页/章节/引用；咨询方法拆定义/适用/禁忌/步骤/证据；职业资料保留地区/时间/口径/复核日期；案例保持 session/turn/事件顺序且 scope 为 private。
- [ ] 写锚点稳定性测试：同一 logical source 的新版本只改变相邻上下文、结构路径和本段规范正文不变时 passage ID 不变；本段正文变化时 passage version/hash 改变但 stable passage ID 保持；结构路径真实改变时创建新 passage ID。锚点可返回前后窗口但原子正文边界不变。
- [ ] Extractor 不使用 `graphify.ingest` 的联网能力。可复用纯本地库，但每个 block 必须带document type、extractor version和适用的canonical坐标：PDF起止page+block pair（允许approved Passage跨页）、DOCX paragraph或table span、TXT/MD line span、CSV table/row/column span、XLSX sheet ordinal+A1 rectangle；不适用的坐标保持缺省，绝不伪造page=1。测试同页与跨页PDF span均可精确往返，倒序pair拒绝。坐标缺失/倒序/非canonical的文档不能产出approved Passage；OCR 不在第一阶段，扫描件明确进 quarantine。
- [ ] Stable Passage ID 由 logical source ID、document type 和 structural path 组成；`PassageVersion` 另存 source version、normalized-text hash 与 extractor version。保存原文 bytes ref、normalized retrieval text ref 和前后 context refs，三者不能互相覆盖。
- [ ] 固定 token 切块只作为超长 block 的二级保护，并在标点/句子边界切；古文章句与对话轮次不跨边界拼接。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_extractors.py tests/consultation_kb/unit/test_passage_segmentation.py
```

Expected: PASS；所有 Passage 有可回到源文件的位置。

---

## Task 3：Claim 草稿、证据关系与传递性谱系

**Files:**

- Create: `consultation_kb/knowledge/claims.py`
- Create: `consultation_kb/knowledge/provenance.py`
- Create: `consultation_kb/knowledge/review.py`
- Create: `tests/consultation_kb/unit/test_claims.py`
- Create: `tests/consultation_kb/unit/test_provenance.py`

**Interfaces produced:** `ClaimProposalService.propose/preview/commit`；`ProvenanceClosure.compute`；支持/反对多对多证据。

- [ ] 写失败测试：模型抽取的 Claim 初始只能 `draft`；必须标明 `explicit/ paraphrase/ counselor_judgment/ model_inference/ cross_theory_analogy`；缺 Passage 或精确位置不能批准。
- [ ] 写证据测试：一个 Claim 可被多个 Passage 支持、多个 Passage 反对；独立来源不能去重掉；Claim 正文不等于证据正文。
- [ ] 写谱系闭包测试：三个 Case → CasePattern → Claim → Wiki section 时，最终对象继承全部 case/client ID；client ID 仅在受控 catalog metadata，正文/向量文本序列化不含它们。
- [ ] 写循环测试：`DERIVED_FROM` 环检测拒绝；模型回答/Wiki 自身作为唯一 evidence 拒绝；另有独立原始证据时只保留合法链。
- [ ] Codex/模型提交的是 `ClaimDraft`，只引用 Passage IDs 和结构化字段；preview resolver 为咨询师显示原文、上下文、位置、拟议主张、等级、适用范围、冲突候选和 diff。
- [ ] 普通 Claim preview 的 `DraftDescriptor.purpose` 固定为 `claim_approve`，撤回为 `claim_revoke`；commit 经 P1 target-transaction approval execution写 approved Claim/review decision与 publication operation。若 Passage/source 版本、draft hash 或 catalog base version变化则拒绝并重建预览。
- [ ] `ProvenanceClosure` 在写派生对象时计算并冻结；任何上游撤回/tombstone 通过 `artifact_dependencies` 找下游，查询端也在 P4 统一过滤。闭包 deterministic sort，保存 `derivation_rule_ref: VersionRef` 并验证其全局policy manifest membership；不得只存可变rule version字符串。生产者必须满足P0完整矩阵：global有source无client/case/owner；private有唯一owner、无source且owner不成为contributor，可含本客户private Passage；case有case+contributors、无owner/source，可含approved case-turn Passage；mixed有source+case+contributors无owner；`client_ids`与owner/contributors精确一致。逐分支和private/case Passage正负测试。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_claims.py tests/consultation_kb/unit/test_provenance.py
```

Expected: PASS；所有 approved Claim 有合法 Passage 链和完整谱系。

---

## Task 4：C1 专属修订、适用范围和主咨询师批准

**Files:**

- Create: `consultation_kb/knowledge/theory.py`
- Create: `consultation_kb/knowledge/applicability.py`
- Create: `consultation_kb/models/theory.py`
- Create: `tests/consultation_kb/unit/test_theory_revisions.py`
- Create: `tests/consultation_kb/unit/test_theory_applicability.py`
- Create: `tests/consultation_kb/golden/test_theory_01_governance.py`
- Create: `tests/fixtures/consultation_kb/sources/synthetic_c1.md`

**Interfaces produced:** `TheoryRevisionService.propose/approve/revoke/get_active`；`ApplicabilityGate.evaluate -> C1ApplicabilityDecision`。

- [ ] `test_theory_01_governance.py` 使用模块级 `@pytest.mark.acceptance_id("THEORY-01")`，Task 5 扩展该模块时保留 marker。
- [ ] 写 `THEORY-01` 治理前置测试：模型/普通 reviewer 不能创建、批准、提升或废止 C1；主咨询师显式批准只产生 `PREPARED` revision，Task 5 的组合发布完成前不得 active；修改文档创建新 revision；旧版通过 `SUPERSEDES` 退出 active；过期/revoked 永不返回。

```python
def test_only_primary_counselor_can_prepare_c1(
    theory_service, primary_counselor_provider, c1_draft
) -> None:
    request = theory_service.propose(c1_draft, actor="codex")
    with pytest.raises(PrimaryCounselorApprovalRequired):
        theory_service.approve(request.request_id, actor="codex")
    provider_event = primary_counselor_provider.confirm(request)
    theory_service.approvals.confirm(provider_event)
    prepared = theory_service.approve(request.request_id)
    assert prepared.source_grade == "C1"
    assert prepared.status == "prepared"
    assert theory_service.get_active(prepared.theory_id) is None
```

- [ ] `TheoryRevision` 必填：正式文档 hash、作者、版本、批准/有效期、适用范围、核心命题、方法、禁忌、反例、Passage anchors、引用来源、empirical support、supersedes/revokes；缺一不可批准。
- [ ] 写双轴测试：C1 + `empirical_support=unassessed/conflicting` 合法；其余值只来自P0冻结的 `EmpiricalSupport` 六值枚举。C2/C3 不得因实证更强自动取得 C1 source grade；序列化和 lint 不把“内部最高框架”写成“外部最高实证”。
- [ ] 写 deterministic applicability 测试：domain/population/context/required conditions/exclusions/contraindications；结果为冻结的 `C1ApplicabilityDecision`，使用 `revision` 与 `scope_policy_ref: VersionRef`，并按P0完整矩阵区分 `applicable/not_applicable/insufficient_context/unavailable`。matched rule与missing context只能用canonical `SafePolicyKey`，前者必须命中approved scope-policy manifest的rule成员，后者必须命中同manifest的context-field词表；任意client canary/path/free-text/未知key都fail closed。P3可产生冲突evidence ObjectId候选；P4装pack时必须把每个 `conflict_evidence_id` 映射为pack candidate本地ID，否则fail closed。模型建议只可作为输入候选，不能绕过 approved scope；decision canonical hash进入 run manifest。
- [ ] `approve` 和 `revoke` 使用 P1 ApprovalService 且额外核验 `approver_role=primary_counselor`；目标 global事务只写获准但未 active 的 revision、SUPERSEDES/REVOKES intent与 publication operation。Task 4 禁止直接切 active pointer；revoke/权限收紧先 tombstone 立即阻断旧版，完整闭包发布由 Task 5 负责。
- [ ] generic Claim review API 明确拒绝设置 `source_grade=C1`，只允许 TheoryRevisionService 为关联 Claim 赋 C1；模型只能调用后续 MCP `propose_theory_revision`。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_theory_revisions.py tests/consultation_kb/unit/test_theory_applicability.py tests/consultation_kb/golden/test_theory_01_governance.py
```

Expected: PASS；C1 权限、PREPARED 版本和适用门控确定性通过，且不存在提前激活路径。

---

## Task 5：LLM Wiki 修订、差异预览与发布

**Files:**

- Create: `consultation_kb/knowledge/wiki.py`
- Create: `consultation_kb/knowledge/wiki_renderer.py`
- Create: `consultation_kb/knowledge/publication.py`
- Modify: `consultation_kb/knowledge/theory.py`
- Create: `consultation_kb/models/wiki.py`
- Create: `tests/consultation_kb/unit/test_wiki_revisions.py`
- Create: `tests/consultation_kb/unit/test_wiki_renderer.py`
- Modify: `tests/consultation_kb/golden/test_theory_01_governance.py`
- Create: `tests/consultation_kb/golden/wiki_relationship_boundaries.md`

**Interfaces produced:** `WikiRevisionService.propose_diff/approve`；`KnowledgePublicationService.publish_theory_and_wiki/publish_wiki`；`WikiRenderer.render`。

- [ ] 写失败测试：新资料必须对既有主题页产生结构化 `add/correct/parallel_disagreement/supersede/expire` diff，不能简单 append；发布前 base wiki version 改变时拒绝。
- [ ] 扩展 `THEORY-01`：`KnowledgePublicationService.publish_theory_and_wiki(operation_id)` 在 Wiki、C1 revision、graph/lex/vector 和 registry 要求的全部 manifest 未 PREPARED+verified 时拒绝；闭包完整后只切一次 global runtime epoch，revision 才变 active；任一点故障仍读完整旧 epoch。
- [ ] 写页面合同测试：定义、语境、不同解释及来源、适用/边界/禁忌/反例、关系、支持/反对 Claim、Passage anchors、审核/复核日期、未解决问题全部存在。
- [ ] 写国学边界 golden：“无为”与“接纳”关系只能是带来源的 ANALOGOUS_TO/DISTINCT_FROM/conditional APPLIES_TO，不允许 EQUIVALENT/CAUSES；传统概念不得生成诊断或医学因果。
- [ ] `WikiRevisionDraft` 只引用 approved Claim/Passage/TheoryRevision IDs；正文每个 section 保存 claim refs。Renderer 展示人类可读引用锚点，但运行时 retrieval metadata 仍从 catalog 读取。
- [ ] approve 经目标事务 approval execution 写 revision；`KnowledgePublicationService` 是唯一组合发布入口，把单页、全站索引、C1/Claim revision及当前 builder registry要求的 graph/lex/vector closure放入同一 global publication operation，经 `PublishCoordinator` 验证完整后切 global runtime epoch。`TheoryRevisionService` 与 `WikiRevisionService` 不暴露独立 active 切换。旧 revision/history 永久可验证；回滚在 P8 产生新反向 revision。
- [ ] 不调用 `graphify.wiki.to_wiki`；增加架构测试保证正式 Wiki 与上游图导出分离。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_wiki_revisions.py tests/consultation_kb/unit/test_wiki_renderer.py tests/consultation_kb/golden/test_theory_01_governance.py
```

Expected: PASS；Wiki 可从 Claim/Passage 重建，不引用自身。

---

## Task 6：知识 lint 与元数据失效传播

**Files:**

- Create: `consultation_kb/knowledge/lint.py`
- Create: `consultation_kb/knowledge/invalidation.py`
- Create: `consultation_kb/models/lint.py`
- Create: `tests/consultation_kb/unit/test_knowledge_lint.py`
- Create: `tests/consultation_kb/unit/test_artifact_invalidation.py`

**Interfaces produced:** `KnowledgeLinter.run(catalog_version)`；`ArtifactInvalidator.mark_stale`；结构化 lint findings。

- [ ] 为设计规格 10.5 每条规则各写一个 failing fixture：无源 Claim、陈旧 Wiki、未说明冲突、孤立页、循环证据、推断冒充原文明示、错误 C1、废止 C1 active、C1/empirical 混写、过期时效资料、单案例模式、关系缺 scope/source/review、metadata 与工件版本不一致。
- [ ] lint severity 固定：阻止发布的 `error`、需复核的 `warning`、信息 `info`；C1 权限/版本、无来源正式 Claim、tombstone/版本错配、循环证据为 error。
- [ ] 写 invalidation 测试：只修改 review status、source grade、C1 scope、授权、有效期或 provenance 时，即使正文 hash 不变，依赖 Wiki/graph/BM25/vector manifest 全部成为下一 publication operation的 required outputs；旧 active runtime epoch在新 closure齐备前继续使用，但若权限收紧/revoke/tombstone则 live authority filter立即不可见。
- [ ] Linter 只读 catalog/manifest，不解析模型回答；finding 保存对象 ID、规则、版本和安全摘要，不复制全部正文。发布服务在 error 存在时拒绝 activate。
- [ ] `ArtifactInvalidator` 沿 `artifact_dependencies` 传播，生成 rebuild queue；同一 source/catalog version 幂等合并。P4 消费 queue 构建索引/图。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_knowledge_lint.py tests/consultation_kb/unit/test_artifact_invalidation.py
```

Expected: PASS；metadata-only 变化可验证地使派生物失效。

---

## Task 7：P3 C1/Wiki 垂直验收

**Files:**

- Create: `tests/consultation_kb/integration/test_knowledge_c1_wiki_slice.py`
- Create: `tests/consultation_kb/integration/test_global_knowledge_epoch_atomicity.py`
- Create: `tests/consultation_kb/golden/test_theory_01_versions.py`

**Interfaces consumed:** P1 approval/manifest/tombstone；P3 source/passage/claim/C1/Wiki/lint。

- [ ] 流程导入一段合成古籍、一份外部咨询资料和一份咨询师 C1 文档；生成 Passage/Claim drafts；分别批准普通 Claim 和 C1；发布带原文锚点/冲突/适用边界的 Wiki 页。
- [ ] 断言适用 active C1 可查且 framework eligible；范围外、过期、被取代、revoke 版本不可作为 active；C2/C3 冲突完整保留；T1 原文和 C1 解释是不同 Claim。
- [ ] 尝试由模型、generic claim reviewer 和篡改 receipt 提升 C1，全部拒绝；重跑 `WRITE-01`。
- [ ] 发布前/后运行 lint，断言全部 error 解决；故意制造 source grade/empirical 混写，确认发布 fail closed。
- [ ] exception-injection覆盖批准执行、C1/Claim authority rows、Wiki finalize、PREPARED、closure verify与global epoch switch；查询只能得到全旧或全新的 C1/Wiki组合，P4 builder注册后同一测试扩展 graph/lex/vector。P8再以真实 kill重跑。
- [ ] Run P3 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit/test_source_registration.py tests/consultation_kb/unit/test_extractors.py tests/consultation_kb/unit/test_passage_segmentation.py tests/consultation_kb/unit/test_claims.py tests/consultation_kb/unit/test_provenance.py tests/consultation_kb/unit/test_theory_revisions.py tests/consultation_kb/unit/test_theory_applicability.py tests/consultation_kb/unit/test_wiki_revisions.py tests/consultation_kb/unit/test_wiki_renderer.py tests/consultation_kb/unit/test_knowledge_lint.py tests/consultation_kb/unit/test_artifact_invalidation.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_theory_01_governance.py tests/consultation_kb/golden/test_theory_01_versions.py tests/consultation_kb/integration/test_knowledge_c1_wiki_slice.py tests/consultation_kb/integration/test_write_01.py tests/consultation_kb/integration/test_iso_02.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids THEORY-01,WRITE-01,ISO-02
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/test_detect.py tests/test_cache.py tests/test_ingest.py tests/test_validate.py
```

Expected: `THEORY-01` 治理部分、`WRITE-01`、知识 `ISO-02` 通过；上游提取/缓存无回归。

## P3 完成定义

- [ ] 所有正式 Claim 可回到 Source/Passage，支持与反证均保留。
- [ ] 只有主咨询师可激活/修订/废止 C1；版本、适用范围、双轴证据和取代链完整。
- [ ] Wiki 是可审查的差异修订编译层，不成为循环证据。
- [ ] 正文或 metadata 变化都能使下游工件 stale；权限收紧和 tombstone 立即生效。
