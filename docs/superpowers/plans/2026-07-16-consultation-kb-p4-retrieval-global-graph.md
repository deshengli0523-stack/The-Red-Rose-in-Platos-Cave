# P4：混合检索、Graphify 全局图与证据包实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

**Goal:** 实现中文词法与精确向量检索、统一确定性预过滤、稳健融合/重排、Graphify 增强的全局关系图、自研带证据加权路径和版本化 EvidencePack，使精确原句、语义改写、关系导航、适用 C1 与外部反证能共同服务回答。

**Architecture:** 每轮先从 live authority DB冻结 `AuthoritativeFilterSnapshot`；词法、向量、图在排名/截断前用它预筛，随后统一 `CandidateFilter` 二次检查，resolver/model之前都不读被拒正文。词法使用 SQLite FTS5 的词/2-3 gram 双通道；向量使用 SQLite 元数据 + NumPy 精确余弦。canonical 全局图为 consultation-owned MultiDiGraph，Graphify 只接收去重投影做社区发现，咨询结构分析与来源感知路径由本系统完成。

**Tech Stack:** SQLite FTS5/BM25、jieba、Unicode NFKC/汉字 n-gram、NumPy `.npy` mmap、Sentence Transformers 协议适配器、NetworkX、Graphify `cluster`、consultation-owned structural analysis、pytest/golden。

## Global Constraints

- 先完成 P2 与 P3；读取设计规格第 5.1、8、12、20、21 节。
- 过滤器必须在正文 resolver、reranker 和模型之前运行；日志可记录计数和 ID，不记录被拒候选正文。
- 第一阶段精确向量是正确性基线，不引入 FAISS/HNSW/Chroma/LanceDB/远程搜索服务。
- Graphify 的聚类和分析结果只是导航信号，不能成为无 Passage 的证据。
- 适用 active C1 提升为最高框架，但范围外/过期/被取代不提升；C2/C3 冲突与 T1/L1/客户事实不被 C1 改写。
- P3 组合发布必须发布真实的 Wiki/registry/lexical/vector/graph CAS 成员，不接受仅含 builder 描述符的占位 manifest。五类派生物共享一个由 global DB、staged authority manifests 与 CAS 在同一只读事务重建的 canonical retrieval-input descriptor；每类 manifest 使用固定成员 ordinal/object type/media type 布局，目标纪元绑定 `MAX(runtime_epochs)+1`，激活事务内再次核对 ACTIVE 与 MAX。
- `Candidate.metadata.manifest_ref` 只能指向包含该 Claim/Wiki/C1 与其 exact Passage 闭包的 content-authority manifest，不能指向或借用 wiki-index、lexical、vector、graph 等路由 root。查询、Doctor 与发布验证使用同一个 active-artifact discovery/binding 实现；零命中也必须前后复验 exact root、epoch 和 CAS bytes。
- 一个 exact Claim/version 可以有多个 Passage 证据。词法和向量索引的 immutable row identity 必须由 exact Claim ref + exact Passage/content ref 共同产生；不得以 Claim stable ID 作为唯一主键而静默丢失后续 Passage，也不得在同一发布中混用同一 stable Claim 的不同版本。
- P4 尚无真实 Case LOO 权威映射时一律排除自案例变体，不接受调用方自报 LOO。P7 只增加窄化的 parent+excluded-client 到 approved exact variant 映射，不建立第二套通用 retrieval authority 表。

---

## Task 1：检索协议、统一过滤和正文延迟解析

**Files:**

- Create: `consultation_kb/retrieval/__init__.py`
- Create: `consultation_kb/retrieval/contracts.py`
- Create: `consultation_kb/retrieval/filters.py`
- Create: `consultation_kb/retrieval/resolver.py`
- Create: `consultation_kb/retrieval/authority_snapshot.py`
- Create: `consultation_kb/retrieval/client_history.py`
- Modify: `consultation_kb/security/worker_protocol.py`
- Modify: `consultation_kb/security/worker_main.py`
- Create: `tests/consultation_kb/unit/test_retrieval_contracts.py`
- Create: `tests/consultation_kb/unit/test_candidate_filters.py`
- Create: `tests/consultation_kb/unit/test_authority_snapshot.py`
- Create: `tests/consultation_kb/integration/test_client_history_scope.py`

**Interfaces produced:** `Retriever.search(query, scope, authority_snapshot) -> CandidateRef[]`；`AuthoritativeFilterSnapshot`；`CandidateFilter.filter`；`EvidenceResolver.resolve_many(filtered_refs)`；`ClientHistoryRetriever`；worker operation `query_client_history_candidates`；`ExclusionProof`。

- [ ] 写失败测试，证明未通过过滤不能解析正文：

```python
def test_denied_candidate_is_never_resolved(candidate_filter, tracking_resolver, scope, candidate_from_current_client) -> None:
    decision = candidate_filter.filter(scope, [case_candidate_from_current_client])
    resolved = tracking_resolver.resolve_many(decision.allowed)
    assert resolved == ()
    assert tracking_resolver.requested_ids == []
    assert decision.proof.reasons == {"source_client_excluded": 1}
```

- [ ] 参数化所有门：客户 scope、allowed use、approved、effective/expiry/review date、tombstone、sensitivity、case contributor、无合格 leave-one-out；每个 denied reason 有固定错误枚举。成对测试 `provenance_scope=client_private/private_owner=current` 的 profile/history允许，而 current client出现在 `case_contributor_client_ids` 的 Case/Pattern/Claim/Wiki/edge/index候选排除或替换 LOO。
- [ ] `AuthoritativeFilterSnapshot` 测试从 live global/client DB在一个读事务取得 `allowed_ref_ids`、global/client runtime epoch、tombstone/authorization epoch和 `policy_ref: VersionRef`；只含 ID/hash/状态，不含正文。epoch或policy ref在 resolver前变化时旧 snapshot/binding/decision整体失效并重新检索。
- [ ] client-history真实 worker测试：控制面只传 session handle/query类别；worker从本客户账本/时态图返回 `client_private` refs，不能指定 client/path/sql；A历史允许用于连续性但 `use=case_example` 永远拒绝，B不可探测。
- [ ] 写 side-channel 测试：不存在和跨客户/无权对象返回同样安全结果；proof 只包含运行 ID、`policy_ref`、input/allowed/denied counts 和 candidate ID 哈希，发布为 `exclusion_proof_ref: VersionRef`。opaque ref不是capability，不得跨store试探。
- [ ] `CandidateRef` 只含 exact `VersionRef`、metadata、完整provenance/score，不含 text；各 Retriever 不能调用 resolver。过滤按固定顺序 live snapshot/epoch → tombstone → scope/use → review → validity/freshness → sensitivity → case provenance/LOO，便于审计计数。
- [ ] 只有 current client 在 `case_contributor_client_ids` 时：存在 approved 且 source count/grade 仍达标的 `leave_one_out_ref` 则替换，否则排除。`client_private` 必须 owner=current且通道为 profile/client_history，并带禁止案例用途标签。P4 用合成 stub 测试，P7 接真实派生物。
- [ ] `EvidenceResolver` 重新检查 active manifest/hash/source version/tombstone 后读取 content ref；过滤决策带一次性 capability epoch，epoch 变化后旧决策不能解析。
- [ ] `worker_main.py` 显式注册 `query_client_history_candidates` 的严格 Schema；架构测试证明 client history repository/DB只能由 scoped worker打开，operation无通用路径/SQL。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_retrieval_contracts.py tests/consultation_kb/unit/test_candidate_filters.py
```

Expected: PASS；所有拒绝候选正文读取次数为 0。

---

## Task 2：SQLite FTS5 中文词级与字符级检索

**Files:**

- Create: `consultation_kb/retrieval/lexical_schema.py`
- Create: `consultation_kb/retrieval/normalization.py`
- Create: `consultation_kb/retrieval/fts_query.py`
- Create: `consultation_kb/retrieval/lexical.py`
- Create: `consultation_kb/retrieval/lexical_builder.py`
- Create: `tests/consultation_kb/unit/test_chinese_normalization.py`
- Create: `tests/consultation_kb/unit/test_lexical_index.py`
- Create: `tests/consultation_kb/unit/test_fts_query_builder.py`
- Create: `tests/consultation_kb/golden/test_classic_exact_recall.py`

**Interfaces produced:** `FtsQueryBuilder.build`；`LexicalIndexBuilder.build`；`LexicalRetriever.search`；版本化 tokenizer descriptor。

- [ ] 写 normalization 测试：NFKC、简繁不自动改写、古今异体/别名从 approved dictionary 扩展、标点/空白稳定；原文 text ref 永不被正规化结果覆盖。
- [ ] 写 FTS5 golden：两字古典词、完整原句、专名、精确术语和带标点改写都命中正确 Passage/位置；只用内建 trigram 会漏掉的两字词由 2-gram 通道命中。
- [ ] 写 SQL 预过滤测试：不可变 index含 approved/未审核/随后过期/随后 tombstoned或撤权文档；把 live `AuthoritativeFilterSnapshot.allowed_ref_ids` 装入连接 TEMP表并在 MATCH 排名/`LIMIT` 前 join。denied高分行不能挤掉较低分合法 top-k，撤回后无需 rebuild 即零召回/零正文读取。
- [ ] 写 FTS grammar攻击测试：原始文本含 `"`、`OR/NOT/NEAR`、`*`、`:`、括号、NUL、空白和超长输入时，`FtsQueryBuilder` 只生成应用层固定 AND/OR 结构；token按 FTS5 string规则引用、内嵌双引号加倍，拒绝 NUL/空/超限。解析失败返回受控错误，不能降级为未过滤 LIKE/全表扫描。
- [ ] `lexical_schema.create()` 在每个 staged immutable `lexical.sqlite3` 中创建 `lexical_documents`、`lexical_provenance`、`lexical_word_fts`、`lexical_char_fts`；全局 catalog 只通过既有 artifact manifest 记录该文件的 source version/hash。词 FTS 存 jieba 精确/搜索 tokens；字符 FTS 存中文 2/3-gram 与字母数字 token；正文仍以 content ref 为准。
- [ ] Builder manifest 记录 jieba version、自定义词典 hash、normalization version、n-gram 范围、source catalog version 和 row content hashes；只索引 approved eligible对象。
- [ ] lexical schema 以 deterministic Claim+Passage row ID 为主键，Claim ID 可重复并仅用于 live allowed-set join；builder manifest 同时绑定 shared input descriptor、lexical assigned-input hash、完整 row mapping/hash 和 target runtime epoch。全路由同时漏一条、只漏 Claim 的第二条 Passage、增加未授权行或与 vector 输入分叉都必须在 publication verify 阶段失败。
- [ ] Retriever 对词/字符分别执行受控 FTS5 MATCH；在同一 query connection的 TEMP allowed表 join后才 `ORDER BY bm25(...) ASC, evidence_id ASC LIMIT ?`。FTS5 BM25数值越小越好；送入 Task 5 RRF 的是排序 rank，不是原始分数。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_chinese_normalization.py tests/consultation_kb/unit/test_lexical_index.py tests/consultation_kb/unit/test_fts_query_builder.py tests/consultation_kb/golden/test_classic_exact_recall.py
```

Expected: PASS；原句/两字词/位置召回稳定。

---

## Task 3：精确 NumPy 向量索引与可插拔模型协议

**Files:**

- Create: `consultation_kb/retrieval/vector_schema.py`
- Create: `consultation_kb/retrieval/embeddings.py`
- Create: `consultation_kb/retrieval/vector.py`
- Create: `consultation_kb/retrieval/vector_builder.py`
- Create: `consultation_kb/retrieval/model_adapters.py`
- Create: `tests/consultation_kb/unit/test_embedding_contract.py`
- Create: `tests/consultation_kb/unit/test_exact_vector_index.py`
- Create: `tests/consultation_kb/model/test_sentence_transformers_adapter.py`

**Interfaces produced:** `Embedder`、`Reranker`、`ModelDescriptor`；`ExactVectorIndexBuilder`；`ExactVectorRetriever`。

- [ ] 写 deterministic fake：对固定词表输出固定 L2-normalized float32；query/doc 维度错误、NaN、零向量拒绝；同分按 evidence ID 稳定。
- [ ] 写向量过滤前置测试：把 live authority snapshot与 immutable vector metadata求交得到 allowed row IDs，才调用 `np.load`/matrix slice；denied rows 即使向量最高也不能占据 top-k或出现在 resolver请求。tombstone/撤权后不 rebuild也立即得到正确合法 top-k。
- [ ] 写 descriptor兼容测试：同 repo/revision/dimension，但 query prompt、document prompt、pooling、normalize、max length、truncation、dtype或score function任一不同，descriptor ID必须不同且旧 shard拒绝混用。
- [ ] 写 immutable shard 测试：builder 输出 float32 `.npy`、row mapping/hash/descriptor manifest；模型 revision、维度或 source catalog version 不同必须新建版本，不原地覆盖 mmap 文件。
- [ ] 实现协议：

```python
class Embedder(Protocol):
    @property
    def descriptor(self) -> ModelDescriptor: ...
    def encode_query(self, text: str) -> NDArray[np.float32]: ...
    def encode_documents(self, texts: Sequence[str]) -> NDArray[np.float32]: ...


class Reranker(Protocol):
    @property
    def descriptor(self) -> ModelDescriptor: ...
    def score(self, query: str, passages: Sequence[str]) -> NDArray[np.float32]: ...
```

- [ ] `ModelDescriptor.id` 是 canonical JSON的 SHA-256，字段至少包含 repo、40-hex commit、模型文件 hashes、adapter class/version、sentence-transformers/transformers/tokenizer versions与tokenizer hash、query/document prompt、pooling、`normalize_embeddings`、max sequence length、truncation、dtype/precision、dimension和score function。任一字段变化创建新 descriptor/shard并触发 rebuild。

- [ ] `vector_schema.create()` 在 staged immutable `vector-meta.sqlite3` 中保存 `vector_rows(evidence_id, shard_id, row_index, review_status, valid_from, valid_to, sensitivity, allowed_uses_json, provenance_ref, content_sha256, model_descriptor_id)`、`vector_provenance`、完整 model descriptor/hash；`.npy` 分片和 metadata DB 在同一 manifest。Builder按 descriptor normalize并发布；retriever先用 live snapshot求 allowed subset，再 `np.load(..., mmap_mode="r")` 和 `matrix @ query` 精确计算。
- [ ] vector metadata 同样使用 deterministic Claim+Passage row ID，允许同 Claim 多 Passage；vector shard、metadata SQLite、build manifest 和 builder input作为独立 CAS members发布，retriever从 opaque active binding取得各成员路径，不假定同一目录，也不接受外部路径注入。
- [ ] Sentence Transformers adapters 仅本地 fixed revision：`local_files_only=True`、`trust_remote_code=False`，验证 offline env；MCP lifespan 延迟加载。model test 若本地模型不存在按明确 marker skip，不联网下载。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_embedding_contract.py tests/consultation_kb/unit/test_exact_vector_index.py
& '.\.venv\Scripts\python.exe' -m pytest -q -m model tests/consultation_kb/model/test_sentence_transformers_adapter.py
```

Expected: unit PASS；model 测试在模型已锁定时 PASS，否则明确 skip reason `local model not installed`。

---

## Task 4：全局 Claim MultiDiGraph 与 Graphify 导航投影

**Files:**

- Create: `consultation_kb/graph/__init__.py`
- Create: `consultation_kb/graph/global_builder.py`
- Create: `consultation_kb/graph/graphify_adapter.py`
- Create: `consultation_kb/graph/navigation_analysis.py`
- Create: `consultation_kb/graph/serialization.py`
- Modify: `graphify/cluster.py`
- Create: `tests/consultation_kb/unit/test_global_graph_builder.py`
- Create: `tests/consultation_kb/unit/test_graphify_adapter.py`
- Create: `tests/consultation_kb/unit/test_graph_boundaries.py`
- Create: `tests/test_cluster_seed.py`

**Interfaces produced:** `GlobalGraphBuilder.build(catalog_version)`；`GraphifyProjectionAdapter.project/cluster`；`StructuralNavigationAnalyzer.analyze`；通用 `graphify.cluster.cluster(..., seed=42)` 向后兼容接口与 `cluster_with_metadata(...) -> ClusterResult(communities, backend, seed, degraded)`；版本化 graph artifact。

- [ ] 写多边测试：同一概念对的 SUPPORTS/CONTRADICTS/ANALOGOUS_TO，来自不同 Passage/时间，全部以 edge ID 保留；未审核、过期、tombstone、revoked C1 edge 不进入 canonical graph。
- [ ] 写 projection 测试：MultiDiGraph 按 node pair 生成简单 weighted Graph投影，edge count/source count/aggregate confidence保留为 consultation属性；只调用 `graphify.cluster.cluster(..., seed=42)` 产生 community。投影不伪造 `source_file/relation/confidence/_src/_tgt` 去迎合代码图分析，也不替换 canonical edge。
- [ ] 写架构测试：global adapter只可导入 `graphify.cluster`，不得调用 `graphify.analyze/serve/wiki/build_from_json`。god nodes、bridge、surprising connections和navigation questions由 `StructuralNavigationAnalyzer` 在已过滤的 canonical consultation graph上实现，每个 hint必须回到 Claim/Passage，否则不能进入 EvidenceCandidate。
- [ ] 为上游通用 `cluster` 增加 keyword-only `seed`：Leiden必须将其传给已检测到的正式 random-seed参数，Louvain也使用同 seed；后端不支持可控 seed时生产模式明确失败，不能宣称可重复。原 `cluster()` 仍只返回 dict并委托 `cluster_with_metadata()`；adapter调用后者取得 actual backend/degraded，禁止通过“能否 import”猜运行结果。新上游测试验证相同 seed稳定、metadata真实、不同 seed API有效、原无参数调用兼容。
- [ ] Builder 从 approved Claims/relations 构建 consultation-owned `nx.MultiDiGraph`，node/edge 带 version、source grade、review、effective/review dates、applicability、provenance、Passage refs；每条 edge key 是 stable edge ID。
- [ ] Graphify projection只承担 community discovery；结构导航分析由本系统承担。adapter将社区按 `(-size, sorted_node_ids)` 重新编号，避免同尺寸社区依赖上游 dict顺序；node/edge输入也先 canonical sort。
- [ ] canonical graph、projection、community annotations 同一 graph manifest 发布，记录 source catalog/runtime epoch、`importlib.metadata.version("graphifyy")`、`graphify.cluster` 文件 hash、NetworkX/graspologic版本、actual backend、seed、Graphify参数、projection schema与degraded flag。3.12生产验收必须 backend=Leiden；3.13兼容矩阵预期 Louvain degraded。metadata-only变化触发 P3 publication closure重建。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_global_graph_builder.py tests/consultation_kb/unit/test_graphify_adapter.py tests/consultation_kb/unit/test_graph_boundaries.py
& '.\.venv\Scripts\python.exe' -m pytest -q tests/test_cluster.py tests/test_cluster_seed.py tests/test_analyze.py tests/test_export.py
```

Expected: PASS；上游 Graphify 分析测试无回归。

---

## Task 5：来源感知的加权路径

**Files:**

- Create: `consultation_kb/graph/weighted_path.py`
- Create: `consultation_kb/graph/path_cost.py`
- Create: `tests/consultation_kb/unit/test_global_weighted_path.py`
- Create: `tests/consultation_kb/golden/test_graph_01_global.py`

**Interfaces produced:** `WeightedPathQuery.search`；`PathCostPolicy`；`EvidencePath`。

- [ ] `test_graph_01_global.py` 使用模块级 `@pytest.mark.acceptance_id("GRAPH-01")`，作为 registry 的 P4 extension module；runner 必须同时收集 client/global 两侧现存测试。
- [ ] 写路径代价表测试：直接原文明示/人工批准/当前有效/适用/独立来源多的边低代价；model inference、含糊、过期、跨领域 analogy、少来源和多 hop 加惩罚；tombstone/无权/未批准为不可通行而非高代价。
- [ ] 写 C1 测试：适用 active C1 的理论/方法 edge 获得最高 framework adjustment；范围外/过期/superseded 不获提升；C1 调整不能改变 T1/L1/client fact edge 的 statement text 或 truth type。
- [ ] 写 `GRAPH-01` 全局 golden：相同 node pair 多边全保留；查询指定时间只使用有效边；输出路径每条 edge 带 Claim/Passage、限制和独立来源数；禁止调用朴素无权 shortest path。
- [ ] `PathCostPolicy` 版本化且返回各分项，最终 cost 设下限防止负环；query 在过滤后的 MultiDiGraph 上做自实现 k-shortest simple paths，最大 hops/候选数有限，tie-breaker 为 edge ID 序列。
- [ ] 返回 `EvidencePath` 包含 total/breakdown、node/edge refs、support/contradiction 标记、source limits 和 graph version；Graphify community 只可作为 search seed，不进入 cost evidence。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_global_weighted_path.py tests/consultation_kb/golden/test_graph_01_global.py
```

Expected: PASS；多边与来源限制全部可解释。

---

## Task 6：RRF 融合、重排、反证与上下文预算

**Files:**

- Create: `consultation_kb/retrieval/fusion.py`
- Create: `consultation_kb/retrieval/rerank.py`
- Create: `consultation_kb/retrieval/budget.py`
- Create: `tests/consultation_kb/unit/test_rrf_fusion.py`
- Create: `tests/consultation_kb/unit/test_reranking.py`
- Create: `tests/consultation_kb/unit/test_context_budget.py`

**Interfaces produced:** `ReciprocalRankFusion.fuse`；`EvidenceReranker.rerank`；`ContextBudget.select`。

- [ ] 写 RRF 精确测试：`sum(1/(60+rank))`，channel 内 rank 从 1 开始；同分 `(score desc, evidence_id)`；同一 Claim 多 Passage 可聚合但独立支持/反对来源不丢。
- [ ] 写 C1/冲突测试：ApplicabilityGate=applicable 的 active C1 成为 primary framework；C2/C3/T1/K/L 候选仍按各自 evidence 排列；至少保留配置数量的 contradiction/alternative，不能因 C1 boost 被截断。
- [ ] 写 reranker 隔离测试：只有过滤并解析后的 allowed passages 传给 Reranker；fake 记录输入；model failure 返回明确 degraded component 并按 RRF 排序继续，但 run manifest 必须记录，不得假装已重排。
- [ ] 写预算测试：先保留 current facts、C1 scope/limits、关键 supporting、contradicting、精确 quote 和 source diversity，再按边际价值选择；预算不足时返回 omitted counts/reasons，不截断 Passage 造成错引。
- [ ] Fusion 输入 channel ranks 而非混合原始 score；dedup key 使用 Claim/Passage relation，不用纯文本相似把反证合并掉。C1 boost 是独立字段和排序层，不篡改 source grade/empirical status。
- [ ] Reranker 接本地 `Reranker` 协议；正式模型由 P9 benchmark 选，P4 默认 deterministic fake 用于测试。所有模型 descriptor/revision 写 run manifest。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_rrf_fusion.py tests/consultation_kb/unit/test_reranking.py tests/consultation_kb/unit/test_context_budget.py
```

Expected: PASS；反证/来源多样性在预算内确定性保留。

---

## Task 7：EvidencePack 组装与版本门控

**Files:**

- Create: `consultation_kb/retrieval/evidence_pack.py`
- Create: `consultation_kb/retrieval/coordinator.py`
- Create: `tests/consultation_kb/unit/test_evidence_pack.py`
- Create: `tests/consultation_kb/integration/test_ver_01.py`
- Create: `tests/consultation_kb/golden/test_retrieval_slice.py`

**Interfaces produced:** `RetrievalCoordinator.retrieve`；`EvidencePackBuilder.build`；完整版本/排除证明。

- [ ] `test_ver_01.py` 使用模块级 `@pytest.mark.acceptance_id("VER-01")`，作为 P1 manifest primary 之外的查询门控 extension；两模块均须被 runner 收集。
- [ ] 写 pack contract：按P0首个Schema冻结字段，`authority: AuthoritySnapshotBinding` 不含allowed set，`client_snapshot_ref`、`temporary_fact_refs`、support/contradiction、`unresolved_conflict_refs`、候选 exact locator/freshness、安全provenance view、完整 `C1ApplicabilityDecision`、`exclusion_proof_ref`、wiki/lex/vector/graph root manifest refs和reranker descriptor ref全部存在；范围外与上下文不足序列化不同。任何包外对象不得以裸ID或mutable label查询latest。
- [ ] 写 `VER-01`：active manifest 指向缺文件、坏 hash、catalog source version 不一致的 graph/lex/vector/wiki；每种都返回 `ARTIFACT_VERSION_MISMATCH` 并停止 EvidencePack，不能静默省略通道生成“正常包”。
- [ ] 写金标准切片：问题同时需要古籍原句、语义改写、C1、外部 C2/C3 反证和图路径；断言各通道贡献、C1 primary framework、冲突保留和来源位置。
- [ ] Coordinator 先冻结 live `AuthoritativeFilterSnapshot`，路由 query plan 所需通道并把 snapshot传给每个 retriever，始终执行 client scope/case-provenance filter；每个通道失败按设计 17.1 记录并决定重建/停止，不掩盖。关键 client/profile/epoch与版本不一致时整轮停止。
- [ ] Pack builder 只接收已解析 allowed evidence，先把完整 `Provenance` 单向投影为 `EvidenceProvenanceView`，再验证全部 `VersionRef` closure 和 `C1ApplicabilityDecision`；canonical JSON hash 写 run manifest。pack可以含 owner=current的 `client_private` profile/history refs，但其类型图、Schema、默认dump/JSON不得暴露 client IDs或把它们作为案例；完整authority snapshot/provenance resolver不向generation开放，过滤掉对象的正文/ID都不进入包。
- [ ] `test_evidence_pack.py` 逐字段枚举并验证完整DAG：`authority.snapshot_ref/policy_ref`、`client_snapshot_ref`、每个temporary fact、candidate `text_ref`、locator anchors/policy、freshness policy、safe provenance/derivation refs、C1 revision/scope policy、每个unresolved conflict、exclusion proof、四个root manifest和reranker descriptor。C1 matched rule必须是scope policy manifest的approved rule member，missing context key必须属于其approved context-field vocabulary。每条边核对exact `(object_id,version,sha256)`、manifest传递membership、tombstone/epoch和字段专属scope；禁止active/latest alias、descriptor name、orphan fallback或alternate-store lookup。
- [ ] 字段scope矩阵固定：client snapshot与temporary facts属于当前client/session及selection cutoff；private candidate text/anchor/provenance只在当前client store；global knowledge/manifests/models/policies只在global store；conflict/proof绑定当前run/authority/evidence；LOO text/provenance属于同一approved LOO variant。missing/unauthorized/cross-scope统一安全结果且不泄露存在性。`EvidenceLocatorRenderer` 只从approved PassageAnchor按P0固定grammar构造locator，并按document type测试PDF同页/跨页page-block pair、DOCX paragraph/table、TXT/MD line、CSV table、XLSX sheet/range五路；kind/grammar错配、缺坐标、自由正文一律拒绝。
- [ ] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_evidence_pack.py tests/consultation_kb/integration/test_ver_01.py tests/consultation_kb/golden/test_retrieval_slice.py
```

Expected: PASS；正常包可复现，损坏派生物全部 fail closed。

---

## Task 8：P4 强制验收与上游兼容

**Files:**

- Create: `tests/consultation_kb/integration/test_retrieval_graph_slice.py`
- Create: `tests/consultation_kb/integration/test_live_authority_prefilter.py`
- Modify: `consultation_kb/core/doctor.py`

**Interfaces consumed:** P2 client snapshot/graph；P3 C1/Wiki/provenance；P4 retrievers/global graph/pack。

- [ ] 集成测试从已批准合成 Source/Claim/C1/Wiki 和 client snapshot 构建所有 active artifacts，再执行检索垂直切片。控制面spy/audit fixture把packed candidate ID回连投影前完整Provenance，证明每个含current client贡献的self-case候选已被排除或替换为exact approved LOO variant；不得从safe pack读取 `case_contributor_client_ids`。另对最终pack Schema/default dump/JSON扫描禁止字段、generic `client_[a-z0-9]{12}` pattern和多个client canary，必须零命中；pack-visible enum常量本身也不得制造匹配。当前客户private history则以safe `client_private + current_subject_private + profile/client_history` 保留，并证明 `use=case_example` 被拒绝。
- [ ] live prefilter测试先构建含高分case/claim/lex/vector/graph row的不可变索引，再撤权/tombstone但不 rebuild；所有通道在 rank/top-k前排除它，合法较低分结果补足，resolver/reranker读取次数为零。
- [ ] 重跑 `THEORY-01` 的适用/范围外/过期/被取代/冲突、全局+客户 `GRAPH-01`、`VER-01` 和扩展后的 `ISO-02`。
- [ ] Doctor 新增 active lexical/vector/graph model descriptor、FTS5 roundtrip、vector dimension/hash、mmap release、artifact source-version closure；本地模型缺失为明确 capability 状态，不能自动下载。
- [ ] CLI Doctor 必须通过与查询相同的 active-artifact discovery 构造 probe：没有任何 active retrieval set 才是 not-applicable；partial、混合纪元、错误固定布局、descriptor-only v1、缺失/篡改 CAS、索引路径与 active root 无关均 fail closed。保留一条负向纵向测试，证明“合法 roots + 另一个临时目录中的索引文件”在 search 前失败。
- [ ] Run P4 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/golden/test_classic_exact_recall.py tests/consultation_kb/golden/test_graph_01_client.py tests/consultation_kb/golden/test_graph_01_global.py tests/consultation_kb/golden/test_retrieval_slice.py tests/consultation_kb/integration/test_retrieval_graph_slice.py tests/consultation_kb/integration/test_ver_01.py tests/consultation_kb/integration/test_iso_02.py
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_live_authority_prefilter.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids THEORY-01,GRAPH-01,VER-01,ISO-02
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/test_build.py tests/test_cluster.py tests/test_cluster_seed.py tests/test_analyze.py tests/test_export.py tests/test_serve.py tests/test_wiki.py
```

Expected: 全部通过；Graphify 上游无回归；EvidencePack 在所有通道前置过滤并完整保留反证。

## P4 完成定义

- [ ] 古籍原句/专名和中文语义改写分别有词法/向量召回证明。
- [ ] 所有通道在 resolver/reranker/model 前执行同一权限与来源客户过滤。
- [ ] canonical 全局多边图保留证据，Graphify 只作可重建导航增强。
- [ ] EvidencePack 带全部版本、C1 双轴、反证和 exclusion proof；坏版本 fail closed。
