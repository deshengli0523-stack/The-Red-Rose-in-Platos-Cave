# P1：安全 vault、审批、隔离与版本底座实施计划

> **执行策略：** 遵循[总实施计划](2026-07-16-consultation-knowledge-base-implementation-program.md)第 9 节的风险分级、内聚批次、并行审查与阶段单次回归。所有 Superpowers Skill 只按需调用；复选框是范围、接口与验收清单，只有 A 级不变量和回归修复要求严格测试先行，不要求每个 Task 独立对话、提交或复审。

> **状态（2026-07-18）：P1 已完成。** 独立安全复核无 Critical/Important 发现；P1 全模块 `795 passed`，强制验收 `23 passed`，受控全仓回归 `1223 passed, 5 deselected`（仅 Windows `WinError 1314` 符号链接权限基线）；Ruff、严格 Mypy、compile/diff、staged 隐私与 Doctor 门禁均已通过。以下复选框已作为已完成范围清单收口。

**Goal:** 建立全局/每客户 SQLite 真相源、不可变内容对象、manifest/tombstone、一次性人工批准、Windows 路径与身份映射保护、会谈 capability 和客户作用域 worker，使任何跨客户或路径逃逸请求在读取正文前 fail closed。

**Architecture:** 控制面只保存客户目录 catalog 和 capability 摘要；每客户数据库/目录/CAS 物理分开。正式写入由预览哈希和独立批准 receipt 绑定，目标数据库在业务事务内记录 approval execution；内容先进入本 scope 不可见暂存区，完整 publication operation 通过 runtime epoch 激活。客户 worker 的 RPC 协议没有任意路径或任意客户参数，所有内部打开动作仍经最终路径/链接检查。

**Tech Stack:** stdlib sqlite3、Pydantic、hashlib/os.replace/fsync、pywin32 DPAPI/ACL/file-handle APIs、multiprocessing/subprocess、pytest/Hypothesis。

## Global Constraints

- 先完成 P0，读取设计规格第 3.2、5.2、6、7.5、16.4、17.3、18.1、19 节。
- P1 只创建空合成客户；不导入真实会谈和知识正文。
- `ISO-01` 失败路径不能泄漏其他客户是否存在、对象数量、元数据或路径。
- MCP 宿主审批不是服务端安全凭据；默认正式批准由独立本地 review provider 产生，receipt 不返回给模型。
- tombstone 在 P1 就进入所有仓储读取入口；不得推迟到删除阶段。

---

## Task 1：显式 SQLite 连接与 checksum 迁移器

**Files:**

- Create: `consultation_kb/storage/__init__.py`
- Create: `consultation_kb/storage/connection.py`
- Create: `consultation_kb/storage/migrate.py`
- Create: `consultation_kb/storage/migrations/__init__.py`
- Create: `consultation_kb/storage/migrations/global/__init__.py`
- Create: `consultation_kb/storage/migrations/global/v0001_initial.py`
- Create: `consultation_kb/storage/migrations/client/__init__.py`
- Create: `consultation_kb/storage/migrations/client/v0001_initial.py`
- Modify: `consultation_kb/cli.py`
- Create: `tests/consultation_kb/unit/test_sqlite_connection.py`
- Create: `tests/consultation_kb/unit/test_migrations.py`
- Create: `tests/consultation_kb/integration/test_migrate_cli.py`

**Interfaces produced:** `connect_database(path, mode)`；`transaction(conn, immediate=True)`；`MigrationRunner.apply/check`；只读 CLI `migrate --check`。

- [x] 写失败测试，锁定 pragma 和显式事务行为：

```python
import sqlite3

from consultation_kb.storage.connection import connect_database, transaction


def test_writer_connection_uses_required_pragmas(tmp_path) -> None:
    conn = connect_database(tmp_path / "client.sqlite3", mode="writer")
    assert conn.isolation_level is None
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_transaction_rolls_back_all_rows(tmp_path) -> None:
    conn = connect_database(tmp_path / "x.sqlite3", mode="writer")
    conn.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
    try:
        with transaction(conn):
            conn.execute("INSERT INTO item(id) VALUES (1)")
            raise RuntimeError("inject")
    except RuntimeError:
        pass
    assert conn.execute("SELECT count(*) FROM item").fetchone()[0] == 0
```

- [x] 写迁移测试：首次应用写 `schema_migrations`；重复应用幂等；修改已应用模块 checksum 后 `check()` 抛 `MigrationChecksumError`；迁移中故障不留下半张表。CLI `migrate --check --repo-root ... --vault-root ...` 只读检查已存在 global/client DB 与迁移资源，缺失、落后或 checksum 不符返回非零且不创建文件；P9 最终门复用同一命令。
- [x] `connect_database` 使用 `sqlite3.connect(..., isolation_level=None)`；writer 执行 `WAL/FULL`，reader 使用 URI `mode=ro`；两者设置 `foreign_keys=ON` 和 `busy_timeout=5000`。禁止依赖 Python 隐式 transaction 行为。
- [x] `MigrationRunner.ensure_migration_table()` 先以固定内置 Schema 创建唯一 bootstrap 表 `schema_migrations`；随后 `Migration` 协议包含 `version/name/sha256/upgrade(conn)`，runner 按版本排序，在同一 `BEGIN IMMEDIATE` 中执行 upgrade 和迁移记录。SHA-256 基于迁移模块资源 bytes，不按 SQL 分号拆分，禁止嵌套 transaction。
- [x] global v0001 创建：`clients`、`approval_requests`、`approval_receipts`、`approval_executions`、`publication_operations`、`runtime_epochs`、`artifact_manifests`、`artifact_members`、`active_artifacts`、`tombstones`、`audit_events`。client v0001 创建 `sessions`、`review_decisions`、`approval_executions`、`publication_operations`、`runtime_epochs`、`artifact_manifests`、`artifact_members`、`active_artifacts`、`tombstones`；P2 再加入事实表。
- [x] 所有主键、unique、foreign key 和常用状态索引写在迁移里；时间保存 RFC3339 UTC 文本，布尔保存 `INTEGER CHECK(value IN (0,1))`。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_sqlite_connection.py tests/consultation_kb/unit/test_migrations.py tests/consultation_kb/integration/test_migrate_cli.py
& '.\.venv\Scripts\python.exe' -m consultation_kb.cli doctor --repo-root . --vault-root ..\knowledge-vault --json
```

Expected: PASS；doctor 报告 migration modules 可校验，但不改正式 vault。

---

## Task 2：内容寻址对象、manifest 与 tombstone 读取门

**Files:**

- Create: `consultation_kb/vault/content_store.py`
- Create: `consultation_kb/storage/manifests.py`
- Create: `consultation_kb/storage/tombstones.py`
- Create: `consultation_kb/lifecycle/__init__.py`
- Create: `consultation_kb/lifecycle/publish.py`
- Create: `tests/consultation_kb/unit/test_content_store.py`
- Create: `tests/consultation_kb/unit/test_manifests.py`
- Create: `tests/consultation_kb/unit/test_tombstones.py`
- Create: `tests/consultation_kb/unit/test_publication_operations.py`
- Create: `tests/consultation_kb/integration/test_content_scope_isolation.py`

**Interfaces produced:** `ContentStore(scope_root).stage_bytes/finalize/read_verified`；`ManifestRepository.insert_prepared/get/activate_expected`；`VisibilityGuard.assert_visible`；`PublishCoordinator.prepare/verify/activate/recover`；`RuntimeEpochRepository`。

- [x] 写失败测试，证明相同 canonical bytes 具有相同地址，任一篡改被拒绝：

```python
import pytest

from consultation_kb.vault.content_store import ContentHashMismatch, ContentStore


def test_content_store_detects_tampering(tmp_path, fixed_id_factory) -> None:
    store = ContentStore(tmp_path)
    staged = store.stage_bytes(
        b'{"a":1}\n',
        purpose="test",
        manifest_id=fixed_id_factory.object_id("manifest"),
        media_type="application/json",
    )
    ref = store.finalize(staged)
    ref.path.write_bytes(b'{"a":2}\n')
    with pytest.raises(ContentHashMismatch):
        store.read_verified(ref)
```

- [x] 写 manifest 测试：`DRAFT`/`PREPARED` 不可查询；只有所有 member 存在、哈希正确且 `source_version` 一致才可激活；active 指针切换采用 expected-current-version 乐观检查。
- [x] 写 tombstone 测试：对象即使仍在 active manifest 中，写 tombstone 后立即 `ObjectTombstoned`；关闭/重开数据库后仍拒绝。
- [x] 写 scope 测试：global 与 A/B client store 放入相同 bytes，必须产生三个各自 scope 内的物理对象；A store 不能探测 B/global 是否已有同 hash，内部 path 永不序列化到 MCP。
- [x] 写 publication operation 测试：同一 `operation_id` 的 required manifests未全部 verified时不能切 epoch；全部完成后一个事务切 active epoch；reader 固定旧/新任一完整 epoch，不能读混合版本。
- [x] `ContentStore(scope_root)` 只接受 broker 已验证的 global root或当前 client root。它对 bytes 计算 SHA-256，stage 在本 scope 同卷 `.staging/{purpose}/{manifest_id}/`，写临时文件后 `flush()`/`os.fsync()`；最终路径为本 scope `objects/sha256/{hash_prefix}/{content_sha256}/payload`。禁止跨 scope dedup。内部 `ContentObjectRef` 可带路径，但任何 MCP/Tool Schema 都不得序列化该路径。目录 fsync 在 Windows 不可用时记录明确平台结果，不伪称已完成；文件仍必须 flush/fsync 后 `os.replace`。
- [x] `PublishCoordinator.prepare` 完成 stage/finalize 后调用 `ManifestRepository.insert_prepared`；`verify` 对所有 member 重算哈希并核对源版本；`activate` 通过 repository 的 `activate_expected` 在一个事务切换 operation所需全部 `active_artifacts`、runtime epoch并标 ACTIVE。reader 始终 `VisibilityGuard → fixed runtime epoch → active pointer → manifest verify → content read`。禁止在 `ManifestRepository` 再暴露同名高层 prepare/verify/activate。
- [x] `VisibilityGuard` 同时检查对象 tombstone 和来源谱系 tombstone；错误只包含当前请求对象的类型和不可逆哈希。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_content_store.py tests/consultation_kb/unit/test_manifests.py tests/consultation_kb/unit/test_tombstones.py tests/consultation_kb/unit/test_publication_operations.py tests/consultation_kb/integration/test_content_scope_isolation.py
```

Expected: PASS；同一对象去重，篡改/版本错配/被删除均 fail closed。

---

## Task 3：一次性批准请求与独立 review provider

**Files:**

- Create: `consultation_kb/approvals/__init__.py`
- Create: `consultation_kb/approvals/models.py`
- Create: `consultation_kb/approvals/store.py`
- Create: `consultation_kb/approvals/execution.py`
- Create: `consultation_kb/approvals/provider.py`
- Create: `consultation_kb/approvals/review_agent.py`
- Modify: `consultation_kb/cli.py`
- Create: `tests/consultation_kb/unit/test_approvals.py`
- Create: `tests/consultation_kb/unit/test_approval_execution.py`
- Create: `tests/consultation_kb/integration/test_review_agent.py`

**Interfaces produced:** `ApprovalService.request/confirm/issue_for_execution/acknowledge`；`ApprovalExecutionGuard.apply_in_transaction`；`ApprovalProvider`；独立 `consultation-kb review` 进程。

- [x] 写 `WRITE-01` 的核心失败测试：

```python
import pytest

from consultation_kb.approvals.store import ApprovalMismatch, ApprovalService, ApprovalUsed


def test_approval_is_bound_to_hash_version_and_single_operation(
    approval_service, approval_provider, target_execution_guard, draft, fixed_id_factory,
) -> None:
    operation_id = fixed_id_factory.object_id("op")
    request = approval_service.request(draft)
    provider_event = approval_provider.confirm(request)
    approval_service.confirm(provider_event)
    changed = draft.model_copy(update={"draft_sha256": "0" * 64})
    with pytest.raises(ApprovalMismatch):
        approval_service.issue_for_execution(
            request.request_id, changed, operation_id=operation_id,
        )
    receipt = approval_service.issue_for_execution(
        request.request_id, draft, operation_id=operation_id,
    )
    assert receipt.descriptor_sha256 == request.descriptor_sha256
    execution = target_execution_guard.apply_in_transaction(
        receipt, draft, lambda conn: None,
    )
    approval_service.acknowledge(execution)
    assert target_execution_guard.apply_in_transaction(
        receipt, draft, lambda conn: pytest.fail("must not rerun callback"),
    ).state == "applied"
    with pytest.raises(ApprovalUsed):
        approval_service.issue_for_execution(
            request.request_id, draft,
            operation_id=fixed_id_factory.object_id("op"),
        )
```

- [x] 另测：过期、purpose/target/base version/session 变化、模型直接伪造 receipt、C1 非主咨询师批准、旧批准换 operation重放均拒绝；同 operation retry幂等；拒绝后审计不含 diff 正文。
- [x] 故障单元测试在 target callback 前、中、提交后/全局 ack前注入异常：提交前 target execution与业务行都不存在；提交后 target为 APPLIED且重试只补全局 acknowledged，不重复业务写。P8 再做真实 kill。
- [x] request 保存 canonical `DraftDescriptor` 哈希、展示用 diff object ref、过期时间和 256-bit nonce 的哈希。模型可见响应没有 nonce/receipt。
- [x] `ApprovalProvider` 只返回“本地人已确认”的受控事件。默认 Windows review agent 作为独立进程从 SQLite 读取待审核对象、在自己的控制台显示已验证 diff、要求交互式确认，检查 `stdin.isatty()`；它以 DPAPI 保护的本机 secret 对 request ID/descriptor hash/nonce/approver/time 做 HMAC。测试使用 `FakeApprovalProvider`，不能在生产 config 中启用 fake。
- [x] `issue_for_execution` 核验签名、TTL、角色、descriptor 与 operation binding，但不在 global DB 先标“已消费”。`ApprovalExecutionGuard` 在目标 global/client SQLite 的业务 `BEGIN IMMEDIATE` 内插入唯一 nonce/request/operation、执行 callback并标 APPLIED；同 operation重试返回已有结果，其他 operation重放拒绝。提交后 `acknowledge` 可恢复地更新 global receipt；不能把裸 receipt 返回给 MCP/模型。
- [x] CLI `review --request $RequestId` 不接受 `--approve yes`、stdin 管道或环境变量静默批准；非 TTY 返回退出码 2。集成测试用注入 provider，不弹真实交互窗口。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_approvals.py tests/consultation_kb/unit/test_approval_execution.py tests/consultation_kb/integration/test_review_agent.py
```

Expected: PASS；所有重放/篡改测试拒绝，错误不泄漏正文。

---

## Task 4：Windows DPAPI、NTFS ACL 与最终路径守卫

**Files:**

- Create: `consultation_kb/security/__init__.py`
- Create: `consultation_kb/security/dpapi.py`
- Create: `consultation_kb/security/ntfs_acl.py`
- Create: `consultation_kb/security/path_guard.py`
- Create: `tests/consultation_kb/unit/test_dpapi.py`
- Create: `tests/consultation_kb/unit/test_path_guard.py`
- Create: `tests/consultation_kb/integration/test_windows_security.py`

**Interfaces produced:** `SecretProtector`/`WindowsDpapiProtector`；`AclPolicy.verify/apply`；`PathGuard.open_scoped`。

- [x] 写路径攻击参数化测试，覆盖绝对路径、UNC、drive-relative、`..`、symlink、junction/reparse point、hardlink、大小写/短名绕过：

```python
import pytest


@pytest.mark.parametrize("candidate", [
    r"C:\\outside\\client.sqlite3",
    r"\\\\server\\share\\x",
    r"..\\client_beta\\client.sqlite3",
    r"sub\\..\\..\\x",
])
def test_path_guard_rejects_escape(client_root, candidate) -> None:
    with pytest.raises(ScopePathDenied):
        PathGuard(client_root).open_scoped(candidate, mode="rb")
```

- [x] Windows 集成测试在 `tmp_path` 创建 junction/symlink/hardlink；权限不足不能 skip 整个测试文件，分别记录无法创建的攻击类型，并由可注入 fake final-path provider 在单元层覆盖同一路径。
- [x] 写 DPAPI 测试：current-user scope 可 round-trip；不同 entropy/purpose 不能解密；非 Windows production factory 抛 `UnsupportedSecurityPlatform`，绝不明文回退。
- [x] `WindowsDpapiProtector` 使用 `win32crypt.CryptProtectData/CryptUnprotectData`，flags 不含 machine scope；entropy 绑定 vault ID 与 purpose。`identity-map.enc` 和 review-agent secret 分 purpose 加密。
- [x] `AclPolicy` 用 `win32security` 关闭受保护目录的继承，只授予当前用户 SID、SYSTEM 和可配置备份主体；doctor 每次验证 owner/DACL，不符合时 fail。修复是独立显式命令，不在读取路径静默改 ACL。
- [x] `PathGuard` 先拒绝非纯相对路径和 `..`，再 `resolve(strict=True)`/`normcase`/`commonpath`，然后用已打开 handle 的 `GetFinalPathNameByHandle` 再核对根；每个中间 component 检查 reparse attribute；客户文件 `nNumberOfLinks != 1` 时拒绝。检查后仍使用同一已验证 handle，避免 TOCTOU 重新按字符串打开。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_dpapi.py tests/consultation_kb/unit/test_path_guard.py
& '.\.venv\Scripts\python.exe' -m pytest -q -m integration tests/consultation_kb/integration/test_windows_security.py
```

Expected: 当前 Windows 环境全部攻击路径拒绝；审计只记录攻击类别和当前 scope hash。

---

## Task 5：客户 catalog、空客户创建与 capability

**Files:**

- Create: `consultation_kb/storage/catalog.py`
- Create: `consultation_kb/security/capability.py`
- Create: `consultation_kb/security/scope_broker.py`
- Create: `consultation_kb/core/client_ids.py`
- Create: `tests/consultation_kb/unit/test_catalog.py`
- Create: `tests/consultation_kb/unit/test_capability.py`
- Create: `tests/consultation_kb/integration/test_create_client.py`

**Interfaces produced:** `ClientCatalog`；`ClientCreationService.preview/commit`；`CapabilityService.issue/validate/revoke`；`SessionScope`。

- [x] 写失败测试：创建客户必须预览并消费批准；相近/大小写 ID 不猜测；重复 alias 拒绝；catalog 不保存真实身份：

```python
def test_client_creation_requires_matching_approval(client_creation) -> None:
    preview = client_creation.preview(alias="client_alpha")
    with pytest.raises(ApprovalRequired):
        client_creation.commit(preview.request_id)
```

- [x] 写 capability 测试：opaque token 至少 256-bit，数据库只保存 token SHA-256；绑定 session/client/permissions/expiry；过期、撤销、权限扩大和跨 session 重放拒绝；日志不含 token。
- [x] `client_id` 由服务生成，不使用 alias 作为目录名；alias 映射的真实身份部分只写 DPAPI `identity-map.enc`，catalog 仅保存 client ID、目录 object ID、创建状态和不可逆 alias lookup hash。
- [x] commit 在批准后创建临时客户目录、迁移空 `client.sqlite3`、验证 ACL/哈希，再原子 rename 为 `clients/<client_id>`，最后在 global catalog 激活；任何中途失败清理临时目录或留可恢复 PREPARED，不能 catalog active 但目录缺失。
- [x] `CapabilityService.issue` 只接受 catalog 中 active client 和新 session；返回 token 仅一次。validate 使用 `hmac.compare_digest` 比较 token hash，返回冻结 `SessionScope`；`revoke`/expiry 立即生效。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_catalog.py tests/consultation_kb/unit/test_capability.py tests/consultation_kb/integration/test_create_client.py
```

Expected: PASS；空客户 A/B 拥有独立目录/SQLite，catalog 不含正文或真实身份。

---

## Task 6：客户作用域 worker 与不可探测 RPC

**Files:**

- Create: `consultation_kb/security/scoped_worker.py`
- Create: `consultation_kb/security/worker_protocol.py`
- Create: `consultation_kb/security/worker_main.py`
- Create: `tests/consultation_kb/unit/test_worker_protocol.py`
- Create: `tests/consultation_kb/integration/test_scoped_worker.py`

**Interfaces produced:** `ScopedWorkerBroker.start/call/close`；版本化 `WorkerOperationRegistry`；严格 operation request/response models；worker 生命周期。

- [x] 写协议测试，证明 payload 中出现 `client_id`、`path`、`sql`、`shell`、绝对路径字段或未知键时 Pydantic 在发送前拒绝；P1 初始只注册严格 Schema 的 `ping`、`get_empty_context_metadata`、`append_scoped_audit`。
- [x] registry 测试要求每个新 discriminator 显式绑定 frozen Pydantic request/response 与 handler、版本号，重复/未知注册拒绝；后续 P2/P4/P5/P7/P8 只能在各自任务显式扩展，不能使用通用 `payload: dict`、动态模块名或字符串 dispatch。
- [x] 写集成测试：创建合成 A/B，启动 A worker；传 B ID、B 路径、parent path、链接路径和随机对象探测；结果统一 `SCOPE_DENIED`，不得出现 B ID、存在性或目录名。
- [x] 写生命周期测试：capability expiry/revoke 后现有 worker 下一次 RPC 失败并退出；close 后临时 token、DB handle 和内存 scope 清空。
- [x] broker 在控制面验证 token 后启动最小 subprocess，以长度前缀 JSON 在私有 pipe 通信；stdout 不传日志。worker 只收到当前 client root、当前 DB 和只读 global root 的已验证 descriptor，不收到 `clients_root`。
- [x] worker 每次操作先向 broker 验证 capability epoch/expiry，再通过 `PathGuard` 使用固定内部文件名；operation registry 无任意路径、SQL或动态 handler。任何解析/范围异常统一安全错误，详细栈只进客户作用域本地日志且不含正文。
- [x] 这不是通用 shell 沙箱：worker 模块不得暴露执行代码、打开任意文件、执行 SQL 或枚举目录的操作。架构测试禁止通用 path/sql/shell discriminator，并要求每个后续 operation都有严格 Schema与作用域集成测试；不禁止合法的显式领域 operation扩展。
- [x] Run:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q tests/consultation_kb/unit/test_worker_protocol.py tests/consultation_kb/integration/test_scoped_worker.py
```

Expected: PASS；A worker 能返回 A 空上下文元数据，所有 B/路径探测不可区分地失败。

---

## Task 7：P1 强制验收 ISO/WRITE/manifest

**Files:**

- Create: `tests/consultation_kb/integration/test_iso_01.py`
- Create: `tests/consultation_kb/integration/test_iso_02.py`
- Create: `tests/consultation_kb/integration/test_write_01.py`
- Create: `tests/consultation_kb/integration/test_manifest_visibility.py`
- Modify: `consultation_kb/core/doctor.py`

**Interfaces consumed:** P0 doctor/scanner；P1 catalog、approval、scope、worker、manifest、tombstone。

- [x] 按 P0 registry 加模块级 marker：`test_iso_01.py → ISO-01`、`test_iso_02.py → ISO-02`、`test_write_01.py → WRITE-01`、`test_manifest_visibility.py → TX-01 + VER-01`；同一模块双 marker 必须分别可被 runner 收集。
- [x] `test_iso_01.py` 按设计验收表逐项攻击 B ID、绝对路径、`..`、symlink、junction/reparse point 和 hardlink；断言 worker 只能读 A，错误响应不含 B 的任何值。
- [x] `test_iso_02.py` 在共享 catalog/manifest/object、日志和临时备份扫描 A/B 合成 canary；除专门受控 provenance catalog 测试表中的不可逆 client ID 外零命中。P1 尚无共享案例，测试建立以后新增派生物必须加入扫描路径。
- [x] `test_write_01.py` 模拟模型直接写、旧批准重放和批准后改 draft；全部拒绝。另证明合法本地批准只执行一次。
- [x] `test_manifest_visibility.py` 在 PREPARED 留下完整和不完整对象；查询仍只见旧 ACTIVE。P8 再对每一步做进程杀死故障注入。
- [x] Doctor 新增：migration checksum、vault ACL、DPAPI roundtrip（只在临时数据）、staging 同卷、identity-map 权限、遗留 PREPARED 数量、active manifest verify。
- [x] Run P1 gate:

```powershell
& '.\.venv\Scripts\python.exe' -m ruff check consultation_kb tests/consultation_kb
& '.\.venv\Scripts\python.exe' -m mypy consultation_kb
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/unit
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests/consultation_kb/integration/test_iso_01.py tests/consultation_kb/integration/test_iso_02.py tests/consultation_kb/integration/test_write_01.py tests/consultation_kb/integration/test_manifest_visibility.py
& '.\.venv\Scripts\python.exe' scripts/run_consultation_acceptance.py --ids ISO-01,ISO-02,WRITE-01,TX-01,VER-01
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider tests
```

Expected: `ISO-01`、P1 范围的 `ISO-02`、`WRITE-01` 和 manifest 可见性全部通过；上游无回归。

## P1 完成定义

- [x] 只有显式批准可创建空客户或激活正式对象；批准不可伪造、篡改、过期重用或重放。
- [x] approval在目标事务中一次执行并可补 ack；publication operation只有完整 closure才能切 runtime epoch。
- [x] A worker 无法通过任一验收攻击获得 B 的正文、元数据或存在性。
- [x] global/A/B相同正文仍落在各自 CAS；任何 client worker不离开自己的 scope root。
- [x] active 查询验证 manifest、hash、source version 和 tombstone，任何错误 fail closed。
- [x] P2/P3 可在此 commit 后并行，不共享客户写事务。
