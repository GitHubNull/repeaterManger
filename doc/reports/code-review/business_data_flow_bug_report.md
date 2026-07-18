# Repeater Manager 业务数据存储/读取/流转 Bug 与设计缺陷分析报告

> **审计时间**: 2026-06-30  
> **审计范围**: 全部数据层代码 (DAO/Schema/Pool/Model/IO/Service/Privilege DAO)  
> **审计方法**: 逐文件阅读 + 交叉引用分析 + 数据流追踪

---

## 一、Bug 类问题（功能缺陷，会导致数据错误或功能异常）

### BUG-001: ErmFormatConstants.CURRENT_SCHEMA_VERSION 与实际版本严重脱节

- **文件**: [ErmFormatConstants.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/ErmFormatConstants.java#L105)
- **严重程度**: ⚠️ 中（导入兼容性判断失效）

**问题描述**:
`CURRENT_SCHEMA_VERSION = 5` 是一个硬编码常量，而数据库实际 Schema 版本已经演进到 v12（经历了 v2→v3→...→v12 共10次迁移）。`ErmArchiveReader` 在导入时使用此常量判断兼容性（[ErmArchiveReader.java#L204-L208](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/ErmArchiveReader.java#L204-L208)）：

```java
if (manifestInfo.schemaVersion > ErmFormatConstants.CURRENT_SCHEMA_VERSION) {
    throw new IOException("存档schema版本(" + manifestInfo.schemaVersion
            + ")高于当前支持的版本(" + ErmFormatConstants.CURRENT_SCHEMA_VERSION
            + ")，请升级插件后重试");
}
```

这意味着任何 Schema 版本 >5 的 ERM 存档导入时都会被拒绝。而当前所有实际数据库都是 v12，所以 **ERM 导入功能实际上已经对所有正常数据库失效**。

此外，`ErmArchiveWriter.getSchemaVersion()` 方法在无法读取 schema_version 时的回退值也是 5（[ErmArchiveWriter.java#L670](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/ErmArchiveWriter.java#L670)），这会导致回退时写入错误的版本号。

**根因**: `ErmFormatConstants.CURRENT_SCHEMA_VERSION` 是一个独立于数据库 schema 演进流程的常量，10次 schema 迁移从未同步更新此常量。

---

### BUG-002: HistoryWriteDAO.saveHistory() 外键回退时静默丢失越权测试关键字段

- **文件**: [HistoryWriteDAO.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/history/HistoryWriteDAO.java#L62-L86)
- **严重程度**: 🔴 高（越权测试结果被丢弃）

**问题描述**:
当 `saveHistory()` 因外键约束失败（`FOREIGN KEY constraint failed`，即关联的 requestId 在 requests 表中不存在）触发回退逻辑时，代码创建了一个新的 `fallbackRecord`，但 **只复制了基础字段，遗漏了越权测试的关键字段**：

```java
// 第69-83行：只复制了这些字段
fallbackRecord.setRequestId(-1);
fallbackRecord.setMethod(record.getMethod());
fallbackRecord.setProtocol(record.getProtocol());
// ... statusCode, responseLength, responseTime, timestamp, requestData, responseData, comment, color

// 遗漏的字段：
// ❌ record.getUserSessionName()   — 用户会话名称
// ❌ record.getJudgment()          — 判决结果 (PENDING/ESCALATED/NOT_ESCALATED/ERROR)
// ❌ record.getSimilarity()        — 相似度分数
// ❌ record.getApi()               — API标识
// ❌ record.getBaselineResponseData() — 基线响应体
```

**影响**: 越权测试产生的历史记录如果关联的请求被删除，回退保存时会丢失判决结果、相似度等核心数据，导致报告生成时数据不完整。

**数据流路径**:
```
ReplayEngine/AutoTestEngine 重放 → 产生带 judgment/similarity 的 Record
  → UI addPrivilegeTestRecord()
    → HistoryRecordingService 异步保存
      → HistoryWriteDAO.saveHistory()
        → requestDAO.isValidRequestId() = false（请求可能已被删除）
          → 创建 fallbackRecord，**丢失 judgment/similarity/userSessionName**
            → 数据库存储了不完整的历史记录
```

---

### BUG-003: AutoTestEngine.sendSyncRequestOnce() 超时时缺少错误消息设置

- **文件**: [AutoTestEngine.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java#L325-L375)
- **严重程度**: ⚠️ 中（超时场景下判决原因丢失）

**问题描述**:
`AutoTestEngine.sendSyncRequestOnce()` 的超时处理逻辑与 `ReplayEngine.sendSyncOnce()` 不一致。对比两处实现：

**ReplayEngine (正确)** — [ReplayEngine.java#L383-L389](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/ReplayEngine.java#L383-L389):
```java
if (!done[0] && holder.errorMessage == null) {
    holder.errorMessage = String.format("请求超时（等待 %dms 未收到响应）", waitTimeoutMs);
    holder.durationMs = waitTimeoutMs;
    LogManager.getInstance().printError(...);
}
```

**AutoTestEngine (缺陷)** — [AutoTestEngine.java#L364-L374](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java#L364-L374):
```java
synchronized (lock) {
    long startTime = System.currentTimeMillis();
    while (!done[0] && (System.currentTimeMillis() - startTime) < Math.max(60000, timeoutSeconds * 2000L)) {
        // ...
    }
}
// ❌ 缺少超时后的 errorMessage 设置！
return holder;
```

AutoTestEngine 在超时退出循环后，`holder.errorMessage` 仍为 null。调用方（[AutoTestEngine.java#L213-L218](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java#L213-L218)）的判断链为：
```java
if (holder.response != null && holder.response.length > 0) {
    // 响应非空 → 正常判决
} else {
    judgment = JudgmentResult.ERROR.name();
    // holder.errorMessage 为 null → 跳过 if 分支 → judgmentNote 为空字符串
    if (holder.errorMessage != null && !holder.errorMessage.isEmpty()) {
        judgmentNote = "请求失败: " + holder.errorMessage;
    }
}
```

结果：超时的请求会被标记为 ERROR，但 `comment` 字段为空，用户无法从 UI 中得知失败原因（是超时还是其他原因）。

---

### BUG-004: ERM 存档导入后 PoolManager 内存缓存未被清理

- **文件**: 影响多个文件 — [ErmArchiveReader.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/ErmArchiveReader.java#L257-L268) 配合 [RequestDAO.java#L37](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/RequestDAO.java#L37)
- **严重程度**: ⚠️ 中（导入后显示旧数据/新数据无法正确读取）

**问题描述**:
ERM 存档导入流程：
1. `ErmArchiveReader.doImport()` 提取条目到文件系统
2. 调用 `dbManager.resetForNewSession()` 清空连接池并重置初始化状态
3. 调用 `dbManager.initialize()` 重新初始化（新数据库文件）
4. 调用 `refreshUIAfterImport()` 刷新 UI

但是，**各个 DAO 实例持有的 PoolManager 对象并未被替换或清理**。例如：
- `RequestDAO` 在构造函数中创建了自己的 `poolManager = new PoolManager()`（包含 `existenceCache`、`stringCache`、`headerCache`）
- `HistoryWriteDAO` 同样有自己的 `poolManager`
- `HistoryUpdateDAO` 同样有自己的 `poolManager`

这些 PoolManager 的内存缓存（`ConcurrentHashMap`）中残留着旧数据库的 hash → value 映射。导入新数据库后，如果新数据库中有相同 hash 但不同内容的数据（虽然 SHA-256 冲突概率极低但理论存在），或者缓存中的条目在新数据库中已被 GC 清理，就会导致数据读取错误。

**数据流路径**:
```
导入 ERM 存档 → resetForNewSession() → initialize() 创建新连接池
  → UI refreshUIAfterRefresh() → UI 调用 getAllRequests()
    → RequestDAO.getAllRequests() 
      → 使用旧的 poolManager（缓存仍是旧会话数据）
        → reconstructor.reconstructRequest() 可能从缓存读到旧数据
```

---

### BUG-005: SchemaMigrator.getCurrentSchemaVersion() 兜底版本号错误

- **文件**: [SchemaMigrator.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/schema/SchemaMigrator.java#L77-L91)
- **严重程度**: ⚠️ 中（schema_meta 表损坏时迁移行为不可预测）

**问题描述**:
```java
public static int getCurrentSchemaVersion(Connection conn) {
    try (...) {
        if (rs.next()) {
            try {
                return Integer.parseInt(rs.getString("value"));
            } catch (NumberFormatException e) {
                return 2;  // ❌ 解析失败返回2
            }
        }
    } catch (SQLException e) {
        // schema_meta 表可能不存在（极旧版本），忽略
    }
    return 2;  // ❌ 默认返回2
}
```

当 `schema_meta` 表不存在或 version 无法解析时，方法返回 `2`（即声称数据库是 v2 schema）。这会导致以下迁移逻辑被触发：

```java
if (currentVersion < 3) { migrateV2ToV3(conn); }  // 尝试 ALTER TABLE ADD COLUMN
if (currentVersion < 4) { migrateV3ToV4(conn); }
// ... 所有迁移都会执行
```

如果数据库实际上是 v12（新数据库），这会导致所有 `ALTER TABLE ADD COLUMN` 重复执行。SQLite 会抛出 "duplicate column name" 错误，这些错误被 try-catch 吞没（[SchemaMigrator.java#L103-L107](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/schema/SchemaMigrator.java#L103-L107)），但日志中会产生大量虚假的 `[!]` 错误输出，干扰真问题排查。

### BUG-006: RequestDAO.updateRequest() 错误释放响应基线 Pool 引用

- **文件**: [RequestDAO.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/RequestDAO.java#L148-L233)
- **严重程度**: 🔴 高（多次编辑请求后，原始响应数据永久丢失）

**问题描述**:

`updateRequest()` 在更新请求时存在一个严重的引用计数错误。方法流程如下：

1. `readRequestHashRefs()` 读取全部10个 hash 引用（含 `resp_header_hash`、`resp_body_hash`、`resp_body_storage`）
2. 为新请求字段（domain、path、query、req_header、req_body、api）创建新的 pool 条目
3. `UPDATE requests SET protocol=?, domain_hash=?, path_hash=?, query_hash=?, method=?, req_header_hash=?, req_body_hash=?, req_body_storage=?, api_hash=? WHERE id=?`
4. `releaseOldRefs()` 释放全部10个旧引用（**包含响应基线字段**）
5. `commit()`

关键问题在第3步和第4步之间：**UPDATE SQL 没有修改 `resp_header_hash`、`resp_body_hash`、`resp_body_storage` 列**，但 `releaseOldRefs()` 却将这些响应基线 hash 的 `ref_count` 各减1。

```java
// 第200行：UPDATE只更新请求侧字段，不包含resp_*字段
String sql = "UPDATE requests SET protocol=?, domain_hash=?, path_hash=?, " +
        "query_hash=?, method=?, req_header_hash=?, req_body_hash=?, req_body_storage=?, api_hash=? WHERE id=?";

// 第217行：但释放了全部10个引用（包括resp_*）
releaseOldRefs(conn, oldRefs);  // 释放 resp_header_hash[7], resp_body_hash[8], resp_body_storage[9]
```

**根因分析**:

```
现象：编辑请求后，原始基线响应无法读取（getOriginalResponseData返回null）
→ 为什么？响应基线对应的pool条目被GC删除了
→ 为什么pool条目被删除？ref_count降到了0
→ 为什么ref_count降到0？updateRequest()中releaseOldRefs()减了响应基线hash的引用计数
→ 为什么释放了不该释放的引用？releaseOldRefs无差别释放全部10个字段的引用
→ 根因：updateRequest只修改请求侧字段，但releaseOldRefs释放了包括响应侧的全部引用。
       多次编辑同一请求（修改请求体、header等）会反复触发此问题，
       每次编辑使响应基线的ref_count减1，直到归零被GC回收
```

**复现路径**:

1. 从 Proxy History 发送一个带响应的请求到 Repeater Manager（触发 `saveOriginalResponse` 保存基线响应）
2. 在 Repeater 中编辑该请求（修改请求头或Body）
3. 点击 "Save" 触发 `updateRequest()`
4. 重复步骤2-3若干次
5. 重启 Burp Suite 或触发一次 GC
6. 点击该请求 → 原始响应区域为空（`getOriginalResponseData()` 返回 null）

**影响范围**:

- 每次编辑请求（更新请求头、Body、Method等）都会减少响应基线的 ref_count
- 如果响应基线pool条目只有该请求一个引用，第一次编辑后 ref_count 变为0，GC 即会删除
- 基线响应数据永久丢失，无法恢复
- 影响越权测试的基线比对功能

**修复建议**:

方案一（推荐）：`updateRequest()` 中的 `releaseOldRefs()` 只释放请求侧字段（索引0-6），不释放响应基线字段（索引7-9）。因为 UPDATE 根本没有修改这些列。

方案二：在 `releaseOldRefs()` 中增加一个参数控制是否释放响应引用。

---

### BUG-007: createBasicRequest() 忽略 protocol 参数，始终硬编码 HTTP/1.1

- **文件**: [RequestDAO.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/RequestDAO.java#L670-L684)
- **严重程度**: ⚠️ 中（pool数据丢失时，重建的请求协议版本错误）

**问题描述**:

当 `ContentReconstructor.reconstructRequest()` 返回 null（pool数据被GC或其他原因导致无法重建请求字节）时，代码回退到 `createBasicRequest()` 生成一个最小化的 HTTP 请求。该方法虽然接受 `protocol` 参数，但**在请求行中硬编码了 `HTTP/1.1`**：

```java
private String createBasicRequest(String method, String protocol, String domain, String path, String query) {
    StringBuilder sb = new StringBuilder();
    sb.append(method).append(" ");
    sb.append(path);
    if (query != null && !query.isEmpty()) {
        sb.append("?").append(query);
    }
    sb.append(" HTTP/1.1\r\n");  // ← 硬编码，忽略了 protocol 参数！
    sb.append("Host: ").append(domain).append("\r\n");
    // ...
}
```

`protocol` 参数的语义是应用层协议（"http" 或 "https"），但在 HTTP 请求行中使用的应该是 HTTP 版本号（HTTP/1.1、HTTP/2 等）。虽然当前 Burp 体系下大多数请求都是 HTTP/1.1，但如果未来支持 HTTP/2，这个回退逻辑会产生错误的请求行。此外，未被使用的 `protocol` 参数会造成代码阅读者的困惑——以为协议信息会被正确反映，但实际没有。

**调用位置**:
- [RequestDAO.java#L334-L341](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/RequestDAO.java#L334-L341) — `getAllRequests()`
- [RequestDAO.java#L414-L421](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/RequestDAO.java#L414-L421) — `getRequest()`

**影响范围**: 仅在 pool 数据损坏/丢失时的回退路径触发，属于低频但影响数据完整性的问题。

**修复建议**: 移除未使用的 `protocol` 参数，或将注释明确说明此为 HTTP/1.1 回退。

---

### BUG-008: PostmanImporter 导入带响应数据时未创建对应的 requests 表记录

- **文件**: [PostmanImporter.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/PostmanImporter.java#L197-L226)
- **严重程度**: ⚠️ 中（导入的数据无法在请求列表中查看和编辑）

**问题描述**:

当 Postman Collection 中的某个 item 包含 `response` 数组（即有示例响应）时，导入器直接将数据作为 history 记录写入（`requestId=-1`），**不会同时创建对应的 requests 表记录**：

```java
if (responses.size() > 0) {
    // 有response → 导入为history
    for (JsonElement respElem : responses) {
        RequestResponseRecord record = new RequestResponseRecord();
        record.setRequestId(-1);  // ← 不关联任何request
        // ... 设置其他字段
        historyWriteDAO.saveHistory(record);  // ← 只写history表
        historyCount++;
    }
} else {
    // 无response → 导入为request
    int newId = requestDAO.saveRequest(url.protocol, url.domain, url.path, url.query, method, rawRequest);
    // ← 只有这种情况才创建requests记录
    requestCount++;
}
```

**导致的问题**:

1. **请求列表不可见**: 导入的 Postman 请求不会出现在 Repeater Manager 的请求列表中，用户无法看到、编辑或重新发送这些请求
2. **数据孤立**: 如果用户清空 history 记录，整个 Postman 导入的数据会全部丢失（因为 requests 表中没有对应记录）
3. **越权测试不可用**: 因为没有 requests 表记录，无法对该请求进行越权测试
4. **数据模型不一致**: 与 ERM 导入的行为不一致（ERM 导入同时创建 requests 和 history 记录）

**根因分析**:

```
现象：Postman导入的含响应请求无法在UI中显示
→ 为什么？UI的请求列表读取的是requests表
→ 为什么requests表没有该记录？导入时只写了history表
→ 为什么不同时写requests表？代码逻辑中，有response就走history分支，无response才走request分支
→ 根因：导入逻辑将"有示例响应"和"不需要创建请求记录"错误地等同起来，
       实际应该无论有无响应都创建requests记录，有响应时额外创建history记录
```

**修复建议**: 修改 `doImport()` 逻辑，先创建 requests 记录获取 requestId，然后以此为外键创建 history 记录。这样既能在请求列表中显示，又能关联历史响应。

---

### BUG-009: PostmanImporter 响应体重构不处理 Base64 编码

- **文件**: [PostmanImporter.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/PostmanImporter.java#L587-L614)
- **严重程度**: ⚠️ 低（仅影响 Postman 中以 Base64 存储的二进制响应）

**问题描述**:

`reconstructRawResponse()` 方法将 Postman 响应体重构为原始 HTTP 响应字节时，直接将 body 字段作为字符串拼接：

```java
private byte[] reconstructRawResponse(JsonObject responseObj) {
    // ... 拼接状态行和响应头 ...
    String body = getString(responseObj, "body", "");
    rawResponse.append(body);  // ← 直接拼接字符串，未检查编码格式
    return rawResponse.toString().getBytes(StandardCharsets.UTF_8);
}
```

Postman Collection v2.1 格式中，响应体可以是纯文本，也可以是 Base64 编码（当响应包含二进制数据时，Postman 会自动以 Base64 存储）。但此方法没有检查 `responseObj` 中是否有 Base64 编码标记，直接将 Base64 字符串当作原始 body 写入。

**影响**: 如果 Postman 导出的 Collection 中包含二进制响应（图片、PDF、压缩数据等），导入后历史记录中的 responseData 会是 Base64 字符串而非原始二进制数据，导致：
- 用户在 Repeater Manager 中看到的响应体是 Base64 乱码
- 越权测试的相似度比对使用错误数据

**修复建议**: 在拼接 body 之前检查是否有 Base64 编码标记，如有则先解码再写入。Postman 格式中通常通过 `response._postman_previewlanguage` 或 body 的特定包装来表示编码。

---

## 二、设计缺陷（架构/设计层面的不足，当前可能未触发但存在隐患）

### DSG-001: 两个 RequestResponseRecord 类共存 —— "幽灵类"问题

- **文件**: 
  - [http/RequestResponseRecord.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/http/RequestResponseRecord.java) (390行，完整模型)
  - [model/RequestResponseRecord.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/model/RequestResponseRecord.java) (100行，简化模型)
- **严重程度**: 🔴 高（类型混淆风险，IDE 自动导入可能选错）

**问题描述**:
项目中存在两个完全不同的类，使用相同的完全限定名模式（org.oxff.repeater.xxx.RequestResponseRecord）：

| 特性 | `http.RequestResponseRecord` | `model.RequestResponseRecord` |
|------|-------------------------------|-------------------------------|
| 字段数 | ~20个（含 id, requestId, protocol, domain, path, query, api, method, statusCode, responseLength, responseTime, timestamp, comment, color, requestData, responseData, userSessionName, judgment, similarity, baselineResponseData） | ~8个（request, response, timestamp, method, url, statusCode, responseLength, responseTime, comment, color） |
| 使用方 | HistoryReadDAO, HistoryWriteDAO, ReplayEngine, AutoTestEngine, HistoryRecordingService | 不明（可能是遗留代码） |
| 可变性 | Mutable（setter方法）| Immutable（字段为final，仅comment/color可变） |

`model.RequestResponseRecord` 的字段是 `final byte[] request` / `final byte[] response`，没有 `requestData`/`responseData` 的 getter。如果某处代码因 IDE 自动导入而错误选择了 `model.RequestResponseRecord`：
- 调用 `getRequestData()` 将**编译失败**（该方法不存在于 model 版本）
- 如果有地方使用了反射或 Map 传递，可能在运行时才暴露

**建议**: 删除或重命名 `model.RequestResponseRecord`，只保留 `http.RequestResponseRecord`。

---

### DSG-002: Schema 版本号管理分散在三处，缺乏单一真相源

- **文件**: 
  - [ErmFormatConstants.java#L105](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/io/ErmFormatConstants.java#L105): `CURRENT_SCHEMA_VERSION = 5`
  - [SchemaInitializer.java#L42](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/schema/SchemaInitializer.java#L42): 初始化为 `'11'`
  - [SchemaMigrator.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/schema/SchemaMigrator.java): 迁移到 v12
- **严重程度**: ⚠️ 中（版本不一致导致 BUG-001 和 BUG-005）

**问题描述**:
Schema 版本号在代码中的三个位置独立定义：
1. `ErmFormatConstants.CURRENT_SCHEMA_VERSION = 5` — 用于 ERM 导入兼容性检查
2. `SchemaInitializer.initializeV3Schema()` — 设置初始版本为 11
3. `SchemaMigrator.migrateIfNeeded()` — 实际支持到 v12

三个值（5, 11, 12）互不一致，且没有一个常量来统一定义"当前支持的最高 Schema 版本"。`ErmFormatConstants.CURRENT_SCHEMA_VERSION` 的名称暗示它是"当前版本"，但实际数值严重过时。

**建议**: 创建单一常量（如 `SchemaConstants.LATEST_SCHEMA_VERSION = 12`），所有三处引用同一个常量。

---

### DSG-003: DatabaseManager 连接池 — resetForNewSession 不重置 GC 服务

- **文件**: [DatabaseManager.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/DatabaseManager.java#L107-L127)
- **严重程度**: ⚠️ 中（切换会话后 GC 服务可能操作错误的数据库）

**问题描述**:
```java
public void resetForNewSession() {
    synchronized (connectionLock) {
        Connection conn;
        while ((conn = connectionPool.poll()) != null) { ... }
        initialized.set(false);
        currentDbPath = null;
        dbConfig.setSessionDirectory(null);
        // ❌ 缺少：停止旧 GC 服务并重置
    }
}
```

在 `closeConnections()` 方法中（[DatabaseManager.java#L75-L102](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/DatabaseManager.java#L75-L102)），GC 服务被显式停止。但在 `resetForNewSession()` 中，**GC 服务没有被停止**。后续的 `initialize()` 会创建新的 GC 服务实例（[DatabaseManager.java#L206-L207](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/DatabaseManager.java#L206-L207)），但旧的 `gcService` 引用被覆盖，旧的 `ScheduledExecutorService` 没有被 shutdown。

不过，由于旧 GC 服务使用的 scheduler 线程是 daemon 线程，JVM 退出时会被清理。问题主要在于：
- 旧 GC 服务可能仍在尝试连接旧数据库路径
- `GarbageCollectorService.processQueue()` 中调用 `DatabaseManager.getInstance().getConnection()` 会获取到新数据库的连接（因为 `getConnection()` 会触发重新初始化），但此时处理的是旧数据库残留的 gc_queue 条目

**建议**: `resetForNewSession()` 中先调用 `closeConnections()`（或提取公共的关闭逻辑）。

---

### DSG-004: HistoryReadDAO.getBaselineRecord() 基线判定逻辑与数据存储模型不一致

- **文件**: [HistoryReadDAO.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/history/HistoryReadDAO.java#L146-L187)
- **严重程度**: ⚠️ 中（基线误判导致比对结果错误）

**问题描述**:
基线记录的判别规则是 `user_session_name IS NULL OR user_session_name = ''`。但项目中存在两种途径产生的 history 记录：

1. **越权测试产生的历史记录**: `user_session_name` 有值（如 "admin", "user1"），judgment 有值
2. **Repeater 手动重放产生的普通历史记录**: `user_session_name` 为 NULL 或空字符串

这两类记录混在同一个 `history` 表中。当用户对一个请求先手动重放（产生 user_session_name=NULL 的普通记录），再进行越权测试时，`getBaselineRecord()` 会将**手动重放的记录**误判为越权测试的基线。虽然手动重放的记录确实代表了"原始响应"，但它的 requestData 可能已被用户修改，导致字段替换逻辑异常。

更根本的问题是：**基线响应已经存储在 `requests` 表中（`resp_header_hash`/`resp_body_hash` 等字段，通过 `RequestDAO.saveOriginalResponse()` 保存）**，而 HistoryReadDAO 仍然从 history 表中查找基线，这造成了同一数据存储在两个位置的不一致风险。

**建议**: 基线比对应该统一使用 `requests` 表的响应字段，并明确区分"越权重放基线"与"普通手动重放记录"。

---

### DSG-005: PoolManager 使用 ConcurrentHashMap 随机淘汰 —— 热数据可能被错误淘汰

- **文件**: [PoolManager.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/pool/PoolManager.java#L417-L430)
- **严重程度**: ⚠️ 中（缓存命中率下降，性能退化）

**问题描述**:
```java
private <K, V> void evictCache(ConcurrentHashMap<K, V> cache, int targetSize) {
    int toRemove = cache.size() - targetSize;
    int removed = 0;
    for (K key : cache.keySet()) {
        if (removed >= toRemove) break;
        cache.remove(key);
        removed++;
    }
}
```

`ConcurrentHashMap.keySet()` 的迭代顺序是不确定的。这意味着淘汰策略是**本质上随机的**，高频访问的热点数据（如频繁出现的 domain/path 字符串 hash）和冷数据被淘汰的概率完全相同。对于 Burp 插件的使用模式（短时间内大量重复请求同一域名），这种随机淘汰会显著降低缓存命中率。

更严重的是，如果在迭代过程中有并发写入，由于 ConcurrentHashMap 的弱一致性，`keySet()` 迭代器可能看到不一致的视图，导致 `size()` 计数不准，淘汰数量不可预测。

**建议**: 引入简单的 LRU 或访问计数机制，至少确保高频访问的条目不被随机淘汰。

---

### DSG-006: GC fullReclamation() 的 ref_count 重算与并发写入存在竞态窗口

- **文件**: [GarbageCollectorService.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/service/GarbageCollectorService.java#L160-L197)
- **严重程度**: ⚠️ 中（ref_count 计数不准导致数据被过早回收）

**问题描述**:
`fullReclamation()` 的逻辑是：
1. `UPDATE xxx_pool SET ref_count = 0` — 将所有池条目的引用计数清零
2. 从 `requests` 和 `history` 表中统计每个 hash 的实际引用次数
3. `UPDATE xxx_pool SET ref_count = N WHERE hash = ?` — 逐个回写正确的引用计数

问题在于步骤 1 和步骤 2-3 之间存在时间窗口。在这个窗口中，**其他线程正在写入新数据**（通过 `ensureString`/`ensureHeader`/`ensureBody`）。新写入的数据会用 `ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1` 正确增加引用计数，但步骤 3 的逐个回写会用统计值**覆盖**这个增量。

**具体场景**:
```
时间线：
T1: GC 线程执行 UPDATE body_pool SET ref_count = 0  （hash "abc" 的 ref_count 变为 0）
T2: 业务线程执行 INSERT ... ON CONFLICT DO UPDATE SET ref_count = ref_count + 1
    （hash "abc" 的 ref_count 变为 1）
T3: GC 线程统计 hash "abc" 的引用次数（此时 count=1，因为 T2 已写入 requests 表）
T4: GC 线程执行 UPDATE body_pool SET ref_count = 1 WHERE hash = 'abc'
    （ref_count 被设为 1 — 这恰好是正确的，但在另一个场景下可能不正确）

更危险的场景（如果 T2 发生在 T3 之后）：
T1: GC: SET ref_count = 0
T2: GC: 统计查询 - 此时尚未有新写入，count = 0
T3: 业务线程写入新数据，ref_count 变为 1
T4: GC: SET ref_count = 0 WHERE hash = 'abc'  ← 用旧统计值覆盖了 T3 的写入！
```

`fullReclamation()` 仅在 `clearAllRequests()`/`clearAllHistory()` 后由用户手动触发时调用，但调用时仍可能有并发的自动保存或其他异步写入，所以竞态窗口是真实存在的。

---

### DSG-007: AutoTestEngine 和 ReplayEngine 的 sendSync 方法约80%代码重复

- **文件**: 
  - [ReplayEngine.java#L299-L393](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/ReplayEngine.java#L299-L393)
  - [AutoTestEngine.java#L300-L376](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java#L300-L376)
- **严重程度**: ⚠️ 低（维护风险，导致 BUG-003 的产生）

**问题描述**:
两个 Engine 各自实现了几乎完全相同的 `sendSyncWithRetry()` + `sendSyncOnce()` + `ReplayResultHolder` 内部类。唯一的差异是 `ReplayEngine` 版本多了 `useHttp2` 参数。这种重复直接导致了 **BUG-003** — AutoTestEngine 的超时错误消息设置在同步过程中被省略了，而 ReplayEngine 后来修复了这个问题。

**建议**: 提取公共的 `SyncHttpSender` 工具类。

---

### DSG-008: SessionDAO.saveFieldValues() 先删后插 —— 事务回滚后字段值丢失

- **文件**: [SessionDAO.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/privilege/dao/SessionDAO.java#L516-L548)
- **严重程度**: ⚠️ 中（字段值可能在异常时全部丢失）

**问题描述**:
```java
public boolean saveFieldValues(int userSessionId, Map<Integer, String> fieldValues) {
    try (Connection conn = DatabaseManager.getInstance().getConnection()) {
        conn.setAutoCommit(false);
        try {
            // 1. 删除旧的字段值
            DELETE FROM field_values WHERE user_session_id = ?;
            // 2. 插入新的字段值（循环逐条 INSERT）
            for (entry : fieldValues) {
                INSERT INTO field_values ...
            }
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();  // ← 回滚后，新旧字段值都丢失了
        }
    }
}
```

"先删后插"模式在事务保护下语义上是正确的（原子性），但存在以下问题：

1. **外键约束失败不会导致整体失败**: 如果 fieldValues 中包含一个已不存在的 `field_id`，SQLite 的外键约束会触发失败，此时 rollback 不仅丢弃了新值，**旧值也无法恢复**。
2. **逐条 INSERT 性能差**: 对于大量字段（如 20+），逐条 executeUpdate 会产生 20+ 次磁盘 I/O。应使用 batch insert 或 `INSERT OR REPLACE` 的 upsert 模式。

**建议**: 使用 `INSERT OR REPLACE INTO field_values` 逐条 upsert，避免全删的风险。

---

### DSG-009: FileStorageManager.writeBodyFile() 的 ATOMIC_MOVE 在 Windows 上不可靠

- **文件**: [FileStorageManager.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/pool/FileStorageManager.java#L61-L63)
- **严重程度**: ⚠️ 低（Windows 特定，大文件写入可能残留临时文件）

**问题描述**:
```java
Files.move(tempFile.toPath(), targetFile.toPath(),
        StandardCopyOption.REPLACE_EXISTING,
        StandardCopyOption.ATOMIC_MOVE);
```

Java 的 `ATOMIC_MOVE` 在 Windows 上底层调用 `MoveFileExW`，**仅在同一卷内有效**。如果临时文件和目标文件不在同一文件系统（虽然这里在同一目录下，不太可能跨卷），原子移动会失败。更重要的是，Windows 上 `ATOMIC_MOVE` 的实现并非真正的原子操作 — 在大文件场景下仍可能出现部分写入。

**影响**: `finally` 块中的清理（[FileStorageManager.java#L68-L70](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/pool/FileStorageManager.java#L68-L70)）会尝试删除残留临时文件，但如果 ATOMIC_MOVE 失败且未抛异常（极少见但可能），临时文件会残留在磁盘上，导致 `blobs/` 目录膨胀。

---

### DSG-010: 数据库连接池大小硬编码为 15，无监控和自适应机制

- **文件**: [DatabaseManager.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/DatabaseManager.java#L33)
- **严重程度**: ⚠️ 低（高并发场景下连接池可能成为瓶颈）

**问题描述**:
```java
private static final int POOL_SIZE = 15;
```

连接池大小固定为 15。在以下场景可能成为瓶颈：
- 越权测试批量重放（多个线程同时写入 history 表）
- UI 刷新触发 `getAllRequests()` 的同时 GC 服务也在运行
- ERM 导入/导出期间的数据库操作

虽然 `getConnection()` 在池空时会动态创建新连接（[DatabaseManager.java#L258-L261](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/DatabaseManager.java#L258-L261)），但 SQLite 的并发写入限制（同一时间只有一个 write 事务）意味着额外连接实际上在等待 SQLITE_BUSY。连接池的大小意义不如对 MySQL 等重要，但仍建议添加 JMX 监控指标。

---

## 三、数据流 Bug（数据在不同组件间传递时发生的错误）

### DFB-001: HistoryRecordingService.recordFailure() 设置 responseData=null 导致保存时潜在空指针

- **文件**: [HistoryRecordingService.java](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/service/HistoryRecordingService.java#L174-L218)
- **严重程度**: ⚠️ 低（仅在极端情况下触发）

**问题描述**:
```java
// recordFailure 方法
record.setResponseData(null);  // ← 显式设为 null
```

然后记录被传递给 `HistoryWriteDAO.saveHistory()` → `saveHistoryInternal()`。在 `saveHistoryInternal()` 中（[HistoryWriteDAO.java#L163-L172](file:///d:/dev/java_dev/qoder/repeaterManger/src/main/java/org/oxff/repeater/db/history/HistoryWriteDAO.java#L163-L172)）：
```java
byte[] responseData = record.getResponseData();
if (responseData != null && responseData.length > 0) {
    SplitResult split = poolManager.getSplitter().splitResponse(responseData);
    // ...
}
```

当 `responseData` 为 null 时，条件判断正确跳过，不会有问题。但如果将来修改了条件判断，或添加了对 `responseData` 的其他处理（如 `.length` 调用），就会 NPE。

更安全的设计是：失败记录也写入一个空的字节数组 `new byte[0]` 而不是 null，与成功但无响应的场景保持一致。

---

## 四、汇总表

| 编号 | 类型 | 严重程度 | 简述 |
|------|------|----------|------|
| BUG-001 | 数据存储 | ⚠️ 中 | ERM Schema版本常量过期(5 vs 12)，导入兼容性判断失效 |
| BUG-002 | 数据存储 | 🔴 高 | HistoryWriteDAO外键回退丢失judgment/similarity/userSessionName |
| BUG-003 | 数据流转 | ⚠️ 中 | AutoTestEngine超时缺少errorMessage，导致判决原因丢失 |
| BUG-004 | 数据读取 | ⚠️ 中 | ERM导入后PoolManager缓存未清理，可能读取旧数据 |
| BUG-005 | 数据存储 | ⚠️ 中 | SchemaMigrator默认版本2，schema_meta损坏时过度迁移 |
| BUG-006 | 数据存储 | 🔴 高 | updateRequest错误释放响应基线pool引用，多次编辑后数据丢失 |
| BUG-007 | 数据读取 | ⚠️ 中 | createBasicRequest硬编码HTTP/1.1，忽略protocol参数 |
| BUG-008 | 数据导入 | ⚠️ 中 | PostmanImporter导入含响应数据时不创建requests记录 |
| BUG-009 | 数据导入 | ⚠️ 低 | PostmanImporter响应体重构不处理Base64编码 |
| DSG-001 | 设计缺陷 | 🔴 高 | 两个RequestResponseRecord类共存，类型混淆风险 |
| DSG-002 | 设计缺陷 | ⚠️ 中 | Schema版本号分散三处，缺乏单一真相源 |
| DSG-003 | 设计缺陷 | ⚠️ 中 | resetForNewSession不停止GC服务 |
| DSG-004 | 设计缺陷 | ⚠️ 中 | 基线判定逻辑模糊，history表与requests表基线双存 |
| DSG-005 | 设计缺陷 | ⚠️ 中 | PoolManager缓存随机淘汰，热数据可能被误淘汰 |
| DSG-006 | 设计缺陷 | ⚠️ 中 | GC ref_count重算与并发写入存在竞态窗口 |
| DSG-007 | 设计缺陷 | ⚠️ 低 | AutoTestEngine/ReplayEngine代码重复80% |
| DSG-008 | 设计缺陷 | ⚠️ 中 | SessionDAO先删后插，回滚后字段值全部丢失 |
| DSG-009 | 设计缺陷 | ⚠️ 低 | Windows上ATOMIC_MOVE不可靠，临时文件残留 |
| DSG-010 | 设计缺陷 | ⚠️ 低 | 连接池大小硬编码无监控 |
| DFB-001 | 数据流转 | ⚠️ 低 | recordFailure设置responseData=null，潜在NPE风险 |

---

## 五、建议的修复优先级

1. **立即修复**（影响核心功能）:
   - BUG-001: 更新 `CURRENT_SCHEMA_VERSION` 为 12，确保 ERM 导入可用
   - BUG-002: 外键回退逻辑补全越权测试字段
   - BUG-006: updateRequest 只释放请求侧引用，不释放响应基线引用
   - DSG-001: 删除或重命名 `model.RequestResponseRecord`

2. **尽快修复**（可能导致数据错误）:
   - BUG-004: ERM 导入后重建 DAO 实例或清理 PoolManager 缓存
   - BUG-003: AutoTestEngine 对齐 ReplayEngine 的超时处理
   - BUG-008: PostmanImporter 导入含响应数据时同步创建 requests 记录
   - DSG-008: SessionDAO 改用 upsert 模式

3. **计划修复**（设计改进）:
   - DSG-002: 统一 Schema 版本常量
   - DSG-004: 明确基线数据存储规范
   - DSG-005: 改进缓存淘汰策略为 LRU
   - DSG-006: GC 重算时暂停写入或使用版本号机制
   - BUG-005: SchemaMigrator 默认版本改为读取 actual schema
   - BUG-007: 清理 createBasicRequest 未使用的 protocol 参数或添加版本号支持

4. **低优先级**（优化项）:
   - DSG-007: 提取公共 HTTP 发送工具类
   - DSG-009: 添加 ATOMIC_MOVE 失败的优雅降级
   - DSG-010: 添加连接池监控
   - DFB-001: 统一空响应/失败时的 responseData 处理
   - BUG-009: PostmanImporter 增加 Base64 响应体解码支持

# Repeater Manager 业务数据流系统化调试报告

> 生成日期：2026-06-17 | 审查范围：业务数据流逻辑错误、数据存储问题、数据展示问题
> 调试方法：科学假设-验证循环 + 5-Why 根因分析

---

## 目录

1. [问题总览](#1-问题总览)
2. [BUG-001：大Body文件存储回退路由不一致导致数据丢失（严重）](#bug-001)
3. [BUG-002：删除/更新请求时响应基线Pool引用未释放（高）](#bug-002)
4. [BUG-003：GC全量重算遗漏requests表响应字段导致基线数据被误删（高）](#bug-003)
5. [BUG-004：incrementRefCount未校验影响行数，GC删除后静默失败（高）](#bug-004)
6. [BUG-005：状态栏对含body的错误响应误显示为成功（中）](#bug-005)
7. [BUG-006：Content-Length修正后DB与UI存储的请求体不一致（中）](#bug-006)
8. [BUG-007：响应体提取使用UTF-8字符串转换导致二进制数据截断风险（中）](#bug-007)
9. [BUG-008：ensureBodyFile在缓存检查前写文件导致冗余I/O与ref_count潜在错位（低）](#bug-008)
10. [问题汇总矩阵](#10-问题汇总矩阵)

---

## 1. 问题总览

本次审查覆盖以下业务数据流路径：

| 数据流路径 | 涉及核心类 |
|------------|-----------|
| 请求接收与保存 | `RepeaterManagerUI.setRequest()` → `RequestDAO.saveRequest()` → `PoolManager` |
| 请求发送与响应处理 | `RequestDispatchHandler.sendRequest()` → `RequestManager.makeHttpRequestAsync()` → `HistoryRecordingService` |
| 越权测试重放 | `ReplayEngine.replay()` → `FieldReplacementEngine` → `JudgmentEngine` |
| 历史记录持久化 | `HistoryWriteDAO.saveHistory()` → `PoolManager` → SQLite |
| 历史记录读取与展示 | `HistoryReadDAO` → `ContentReconstructor` → `HistoryPanel` |
| 池化去重存储 | `PoolManager.ensureXxx()` / `releaseXxx()` → `body_pool` / `file_pool` |
| 垃圾回收 | `GarbageCollectorService` → `gc_queue` → 批量删除 |
| 删除操作 | `RequestDAO.deleteRequest()` / `HistoryUpdateDAO.deleteHistory()` |

共发现 **8 个确认问题**：严重 1 个、高 3 个、中 3 个、低 1 个。

---

## BUG-001

### 大Body文件存储回退路由不一致导致数据丢失（严重）

**问题描述**

当请求/响应Body大于 8KB 阈值时，`BodyStorageRoute` 路由为 `FILE`，数据应存入 `file_pool` + 磁盘文件。但磁盘写入失败时，代码回退到行内存储（`body_pool`），而存储路由标记仍为 `"file"`，导致后续读取时从 `file_pool` 查找 → 找不到 → 返回空数据。

**涉及文件**

- `src/main/java/oxff/top/db/pool/PoolManager.java` — [ensureBody()](src/main/java/oxff/top/db/pool/PoolManager.java) L194-212、[ensureBodyFile()](src/main/java/oxff/top/db/pool/PoolManager.java) L297-328

**复现路径**

1. 构造一个 Body > 8KB 的请求或响应（如大文件上传请求、大 JSON 响应）
2. 使 `fileStorageManager.writeBodyFile()` 返回 `null`（磁盘满、权限不足、路径异常）
3. 保存请求或历史记录
4. 重启 Burp Suite 或刷新数据（`refreshAllData()`）
5. 点击该请求 → 响应/请求体显示为空白

**根因分析（5-Why）**

```
现象：大于8KB的Body读取时返回空数据
→ 为什么？ContentReconstructor.readBody() 按 storage="file" 路由到 readBodyFromFile()
→ 为什么找不到？数据实际存在 body_pool（行内），不在 file_pool
→ 为什么路由标记错误？ensureBody() 返回 route=FILE，但 ensureBodyFile() 内部回退到了 ensureBodyInline()
→ 为什么返回值不一致？ensureBody() 根据原始 route 判断后直接返回 route.getDbValue()，
   未感知到 ensureBodyFile() 内部的回退逻辑
→ 根因：存储路由决策（route）和实际存储位置（回退后）脱钩，返回值未反映实际存储位置
```

**代码证据**

```java
// PoolManager.java L194-212 — ensureBody()
public String[] ensureBody(Connection conn, byte[] body) throws SQLException {
    if (body == null || body.length == 0) {
        return new String[]{null, BodyStorageRoute.NONE.getDbValue()};
    }

    BodyStorageRoute route = hasher.routeBody(body);  // 大body → FILE
    String hash = hasher.hashBytes(body);

    switch (route) {
        case INLINE:
            ensureBodyInline(conn, hash, body);
            return new String[]{hash, BodyStorageRoute.INLINE.getDbValue()};
        case FILE:
            BodyStorageRoute actualRoute = ensureBodyFile(conn, hash, body);
            return new String[]{hash, actualRoute.getDbValue()};
        default:
            return new String[]{null, BodyStorageRoute.NONE.getDbValue()};
    }
}

// PoolManager.java L297-328 — ensureBodyFile() 回退逻辑（已修复）
private BodyStorageRoute ensureBodyFile(Connection conn, String hash, byte[] body) throws SQLException {
    // 先检查缓存，避免冗余文件写入（BUG-008）
    if (existenceCache.containsKey("file:" + hash)) {
        if (incrementRefCount(conn, "file_pool", hash)) {
            return BodyStorageRoute.FILE;
        }
        existenceCache.remove("file:" + hash);
    }

    String relativePath = fileStorageManager.writeBodyFile(body, hash);
    if (relativePath == null) {
        BurpExtender.printError("[!] 写入 Body 文件失败，hash: " + hash);
        ensureBodyInline(conn, hash, body);  // ← 回退到body_pool存储
        return BodyStorageRoute.INLINE;      // ← 返回实际路由INLINE
    }
    ...
}
```

**影响范围**

- 请求表中 `req_body_storage='file'` 且实际写入失败的记录
- `requests` 表的响应基线（`resp_body_storage='file'`）同样受影响
- `history` 表的请求体和响应体同样受影响
- 数据永久丢失，无法恢复（除非重新发送请求）

**修复方案（已实施）**

`ensureBodyFile()` 回退时应通知调用方实际使用了行内存储，`ensureBody()` 应返回实际存储路由：

```java
// 已修复：ensureBodyFile返回实际路由
private BodyStorageRoute ensureBodyFile(Connection conn, String hash, byte[] body) throws SQLException {
    // 先检查缓存，避免冗余文件写入
    if (existenceCache.containsKey("file:" + hash)) {
        if (incrementRefCount(conn, "file_pool", hash)) {
            return BodyStorageRoute.FILE;
        }
        existenceCache.remove("file:" + hash);
    }

    String relativePath = fileStorageManager.writeBodyFile(body, hash);
    if (relativePath == null) {
        ensureBodyInline(conn, hash, body);
        return BodyStorageRoute.INLINE;  // ← 返回实际路由
    }
    ...
    return BodyStorageRoute.FILE;
}

// ensureBody() 使用实际路由
case FILE:
    BodyStorageRoute actualRoute = ensureBodyFile(conn, hash, body);
    return new String[]{hash, actualRoute.getDbValue()};
```

**预防措施**

- 添加集成测试：构造 >8KB body，模拟文件写入失败，验证读取一致性
- 在 `ContentReconstructor.readBodyFromFile()` 返回 null 时，自动尝试从 `body_pool` 回退读取（防御性兜底）

---

## BUG-002

### 删除/更新请求时响应基线Pool引用未释放（高）

**问题描述**

`RequestDAO.deleteRequest()` 和 `updateRequest()` 释放池引用时，只释放了请求侧的引用（domain/path/query/req_header/req_body/api），**遗漏了响应基线字段的引用**（`resp_header_hash`、`resp_body_hash`、`resp_body_storage`）。这导致响应基线的 `ref_count` 永远不会归零，GC 无法回收，造成存储泄漏。

**涉及文件**

- `src/main/java/oxff/top/db/RequestDAO.java` — [readRequestHashRefs()](src/main/java/oxff/top/db/RequestDAO.java) L731-754、[releaseOldRefs()](src/main/java/oxff/top/db/RequestDAO.java) L759-779

**对比：HistoryUpdateDAO 是正确的**

`HistoryUpdateDAO.readHistoryHashRefs()` 读取了完整的 10 个引用字段（包含 `resp_header_hash`、`resp_body_hash`、`resp_body_storage`），并在 `releaseOldRefs()` 中正确释放。但 `RequestDAO` 只读取了 7 个字段。

**代码证据**

```java
// RequestDAO.java L731-754 — 已修复：读取全部10个字段
private String[] readRequestHashRefs(Connection conn, int requestId) throws SQLException {
    String sql = "SELECT domain_hash, path_hash, query_hash, req_header_hash, " +
                 "req_body_hash, req_body_storage, api_hash, " +
                 "resp_header_hash, resp_body_hash, resp_body_storage " +
                 "FROM requests WHERE id = ?";
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setInt(1, requestId);
        try (ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                return new String[]{
                        rs.getString("domain_hash"),
                        rs.getString("path_hash"),
                        rs.getString("query_hash"),
                        rs.getString("req_header_hash"),
                        rs.getString("req_body_hash"),
                        rs.getString("req_body_storage"),
                        rs.getString("api_hash"),
                        rs.getString("resp_header_hash"),   // ← 新增
                        rs.getString("resp_body_hash"),     // ← 新增
                        rs.getString("resp_body_storage")   // ← 新增
                };
            }
        }
    }
    return new String[10];
}

// RequestDAO.java L759-779 — 已修复：释放全部10个引用
private void releaseOldRefs(Connection conn, String[] refs) throws SQLException {
    if (refs == null) return;
    poolManager.releaseString(conn, refs[0]); // domain_hash
    poolManager.releaseString(conn, refs[1]); // path_hash
    poolManager.releaseString(conn, refs[2]); // query_hash
    poolManager.releaseHeader(conn, refs[3]); // req_header_hash
    poolManager.releaseBody(conn, refs[4], refs[5]); // req_body_hash + storage
    poolManager.releaseString(conn, refs[6]); // api_hash
    poolManager.releaseHeader(conn, refs[7]);     // resp_header_hash ← 新增
    poolManager.releaseBody(conn, refs[8], refs[9]); // resp_body_hash + storage ← 新增
}
```

**根因分析（5-Why）**

```
现象：删除请求后，响应基线的header_pool/body_pool条目ref_count不归零
→ 为什么？deleteRequest()未释放resp_header_hash和resp_body_hash的引用
→ 为什么？readRequestHashRefs()查询SQL未包含这三个响应字段
→ 为什么？该方法在添加响应基线功能(saveOriginalResponse)前已编写，后续未同步更新
→ 根因：功能迭代时未同步更新引用释放逻辑，缺少防御性校验
```

**影响范围**

- 每次删除带响应基线的请求，泄漏 1-2 个 header_pool 条目 + 1 个 body_pool/file_pool 条目
- 高频删除场景（如批量清理）会累积大量无法回收的孤立数据
- 不影响数据正确性，但导致数据库和 blobs/ 目录持续膨胀

**修复方案（已实施）**

```java
// 1. readRequestHashRefs 增加 resp_header_hash, resp_body_hash, resp_body_storage
private String[] readRequestHashRefs(Connection conn, int requestId) throws SQLException {
    String sql = "SELECT domain_hash, path_hash, query_hash, req_header_hash, " +
                 "req_body_hash, req_body_storage, api_hash, " +
                 "resp_header_hash, resp_body_hash, resp_body_storage " +
                 "FROM requests WHERE id = ?";
    ...
    return new String[]{
        rs.getString("domain_hash"), rs.getString("path_hash"),
        rs.getString("query_hash"), rs.getString("req_header_hash"),
        rs.getString("req_body_hash"), rs.getString("req_body_storage"),
        rs.getString("api_hash"),
        rs.getString("resp_header_hash"),   // 新增 [7]
        rs.getString("resp_body_hash"),       // 新增 [8]
        rs.getString("resp_body_storage")     // 新增 [9]
    };
}

// 2. releaseOldRefs 增加响应引用释放
private void releaseOldRefs(Connection conn, String[] refs) throws SQLException {
    if (refs == null) return;
    // ... 原有7个释放 ...
    // 新增：释放响应基线引用
    poolManager.releaseHeader(conn, refs[7]);         // resp_header_hash
    poolManager.releaseBody(conn, refs[8], refs[9]);  // resp_body_hash + storage
}
```

**预防措施**

- 对比 `HistoryUpdateDAO` 的实现，统一引用释放模式
- 添加单元测试：保存请求+响应基线 → 删除请求 → 验证所有pool的ref_count归零

---

## BUG-003

### GC全量重算遗漏requests表响应字段导致基线数据被误删（高）

**问题描述**

`GarbageCollectorService` 的 `recalculateBodyPoolRefCount()` 和 `recalculateFilePoolRefCount()` 在统计引用时，**没有计入 `requests.resp_body_hash`**。这导致当 `fullReclamation()` 被调用时（如清空历史记录后），仍存在于 `requests` 表中的响应基线body的 `ref_count` 被错误地置为 0，进而被 GC 回收删除。

**涉及文件**

- `src/main/java/oxff/top/service/GarbageCollectorService.java` — [recalculateBodyPoolRefCount()](src/main/java/oxff/top/service/GarbageCollectorService.java) L386-409、[recalculateFilePoolRefCount()](src/main/java/oxff/top/service/GarbageCollectorService.java) L411-434

**复现场景**

1. 从 Proxy History 发送若干请求到 Repeater Manager（触发 `saveOriginalResponseAsBaseline` 保存响应基线到 `requests.resp_body_hash`）
2. 在数据面板执行"清空历史记录"（调用 `HistoryUpdateDAO.clearAllHistory()` → `gcService.fullReclamation()`）
3. fullReclamation 重算 body_pool ref_count 时，不统计 `requests.resp_body_hash`
4. 基线响应body的 ref_count 被错误地设为 0
5. 被加入 gc_queue 并被删除
6. 点击请求 → `getOriginalResponseData()` 返回 null → 响应区域空白

**代码证据**

```java
// GarbageCollectorService.java L386-392 — body_pool 引用统计（已修复）
// 修复前缺少第2行 UNION ALL SELECT resp_body_hash FROM requests ...
String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
    "SELECT req_body_hash AS hash FROM requests WHERE req_body_hash IS NOT NULL AND req_body_storage = 'inline' " +
    "UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'inline' " +
    "UNION ALL SELECT req_body_hash FROM history WHERE req_body_hash IS NOT NULL AND req_body_storage = 'inline' " +
    "UNION ALL SELECT resp_body_hash FROM history WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'inline'" +
    ") GROUP BY hash";

// GarbageCollectorService.java L411-417 — file_pool 引用统计（已修复）
// 修复前缺少第2行 UNION ALL SELECT resp_body_hash FROM requests ...
String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
    "SELECT req_body_hash AS hash FROM requests WHERE req_body_hash IS NOT NULL AND req_body_storage = 'file' " +
    "UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'file' " +
    "UNION ALL SELECT req_body_hash FROM history WHERE req_body_hash IS NOT NULL AND req_body_storage = 'file' " +
    "UNION ALL SELECT resp_body_hash FROM history WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'file'" +
    ") GROUP BY hash";
```

**根因分析（5-Why）**

```
现象：清空历史后请求的响应基线丢失
→ 为什么？fullReclamation将基线body的ref_count重算为0并删除
→ 为什么算为0？统计SQL未包含requests.resp_body_hash的引用
→ 为什么遗漏？requests表的响应字段(resp_*)是v10新增的，GC重算逻辑未同步更新
→ 根因：Schema演进时GC引用统计SQL未同步更新，缺少"新增列是否需要GC统计"的检查流程
```

**影响范围**

- 任何调用 `fullReclamation()` 时，`requests` 表中存在的响应基线body（<8KB 在 body_pool，>=8KB 在 file_pool）都会被误删
- `clearAllHistory()` 会触发此问题
- 数据永久丢失

**修复方案（已实施）**

在 body_pool 和 file_pool 的引用统计 SQL 中增加 `requests.resp_body_hash` 的统计：

```sql
-- body_pool 统计增加（已修复）：
UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'inline'

-- file_pool 统计增加（已修复）：
UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'file'
```

同时 `recalculateHeaderPoolRefCount()` 也已增加 `requests.resp_header_hash` 的统计（已修复）：

```sql
-- header_pool 统计增加（已实施）：
UNION ALL SELECT resp_header_hash FROM requests WHERE resp_header_hash IS NOT NULL
```

对应代码见 `GarbageCollectorService.java` L362-367，统计 SQL 包含 `requests` 表的 `req_header_hash` 和 `resp_header_hash` 以及 `history` 表的两个对应字段。

---

## BUG-004

### incrementRefCount未校验影响行数，GC删除后静默失败（高）

**问题描述**

`PoolManager.incrementRefCount()` 是缓存命中时的快速路径——直接 `UPDATE ref_count = ref_count + 1`。但如果该条目已被 GC 删除（而内存缓存 `existenceCache` 仍标记为存在），UPDATE 影响 0 行但代码不检查返回值，调用方误以为数据已存储。结果：`requests`/`history` 表记录了 hash，但 pool 中实际不存在数据 → 读取时返回空。

**涉及文件**

- `src/main/java/oxff/top/db/pool/PoolManager.java` — [incrementRefCount()](src/main/java/oxff/top/db/pool/PoolManager.java) L334-346

**代码证据**

```java
// PoolManager.java L334-346（已修复）
private boolean incrementRefCount(Connection conn, String tableName, String hash) throws SQLException {
    String sql = "UPDATE " + tableName + " SET ref_count = ref_count + 1 WHERE hash = ?";
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, hash);
        int affected = pstmt.executeUpdate();
        if (affected == 0) {
            // 条目已被 GC 回收，缓存过期
            BurpExtender.printOutput("[*] 缓存命中但池条目不存在，可能已被 GC 回收: " + tableName + "/" + hash);
            return false;
        }
        return true;
    }
}
```

**根因分析（5-Why）**

```
现象：保存的请求数据读取时为空
→ 为什么？pool表中对应hash的条目不存在
→ 为什么不存在？被GC回收了
→ 为什么保存时没有重新创建？ensureString()走了缓存快速路径，只调incrementRefCount
→ incrementRefCount不检查返回值，GC删除后静默失败
→ 根因：existenceCache与DB状态可能不一致（GC异步删除），缓存快速路径缺少回退到完整UPSERT的机制
```

**触发条件**

1. existenceCache 缓存了 `"string:" + hash → true`
2. GC 回收了该 hash 对应的 pool 条目（ref_count 归零后被删除）
3. 但 GC 删除后没有清除 existenceCache 中对应的缓存项（releasePoolEntry 会清除，但 fullReclamation 的批量删除不会清除内存缓存）
4. 下次保存相同 hash 的数据时，缓存命中 → incrementRefCount → 0行影响 → 静默失败

**影响范围**

- 在 `fullReclamation()` 之后（它直接 DELETE pool 条目，不清除 PoolManager.existenceCache），新保存的相同内容数据可能丢失
- 不同 PoolManager 实例（RequestDAO、HistoryWriteDAO 各创建一个）的缓存互相隔离，一个实例的 GC 删除不影响另一个实例的缓存

**修复方案（已实施）**

```java
// 已修复：incrementRefCount 返回 boolean，调用方处理缓存过期
private boolean incrementRefCount(Connection conn, String tableName, String hash) throws SQLException {
    String sql = "UPDATE " + tableName + " SET ref_count = ref_count + 1 WHERE hash = ?";
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, hash);
        int affected = pstmt.executeUpdate();
        if (affected == 0) {
            // 条目已被GC删除，缓存过期
            BurpExtender.printOutput("[*] 缓存命中但池条目不存在，可能已被 GC 回收: " + tableName + "/" + hash);
            return false;
        }
        return true;
    }
}

// 调用方（ensureString / ensureHeader / ensureBodyInline / ensureBodyFile）
if (existenceCache.containsKey("string:" + hash)) {
    if (incrementRefCount(conn, "string_pool", hash)) {
        return hash;
    }
    // 缓存过期，清除缓存并继续执行完整 INSERT
    existenceCache.remove("string:" + hash);
}
```

更优方案：将 existenceCache 的清理集成到 `fullReclamation()` 中，调用 `poolManager.clearCache()`。

---

## BUG-005

### 状态栏对含body的错误响应误显示为成功（中）

**问题描述**

`RequestDispatchHandler.handleResponseSuccess()` 中，`statusPanel.updateStatus()` 的第一个参数（success标志）被硬编码为 `true`，不区分 HTTP 状态码。这导致 HTTP 4xx/5xx 错误响应（只要响应体非空）在状态栏中显示为"成功"（绿色）。

**涉及文件**

- `src/main/java/oxff/top/RequestDispatchHandler.java` — [handleResponseSuccess()](src/main/java/oxff/top/RequestDispatchHandler.java) L298-447（状态码判断在 L315-317）

**代码证据**

```java
// RequestDispatchHandler.java L298-317（已修复）
public void handleResponseSuccess(byte[] requestBytes, byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
    if (response != null && response.length > 0) {
        // ...
        HttpResponse responseInfo = HttpResponse.httpResponse(ByteArray.byteArray(response));
        int statusCode = responseInfo.statusCode();
        // 状态栏使用实际状态码判断成功/失败（BUG-005：原硬编码为 true）
        boolean success = statusCode >= 100 && statusCode < 400;
        statusPanel.updateStatus(success, response.length, requestTimeMs, responseTimeMs, durationMs);
```

对比：`updateStatusFromRecord()` 正确使用了状态码判断：
```java
boolean success = statusCode >= 100 && statusCode < 400;
statusPanel.updateStatus(success, responseSize, ...);
```

**影响范围**

- HTTP 500/404/403 等错误响应（有body）在状态栏显示为成功
- 用户可能误以为请求成功，忽略错误

**修复方案（已实施）**

将 `updateStatus` 调用移到 statusCode 解析之后，使用实际状态码：

```java
if (response != null && response.length > 0) {
    try {
        responsePanel.setResponse(response);
        HttpResponse responseInfo = HttpResponse.httpResponse(ByteArray.byteArray(response));
        int statusCode = responseInfo.statusCode();
        boolean success = statusCode >= 100 && statusCode < 400;
        statusPanel.updateStatus(success, response.length, requestTimeMs, responseTimeMs, durationMs);
        // ... 后续逻辑
```

---

## BUG-006

### Content-Length修正后DB与UI存储的请求体不一致（中）

**问题描述**

`RequestManager.makeHttpRequestAsync()` 在发送前会调用 `RequestDataHelper.fixContentLength()` 修正 Content-Length。修正后的 `fixedBytes` 被传给 `HistoryRecordingService.recordSuccess()` 保存到 DB，但回传给 UI 的 `callback.onSuccess()` 携带的是 response（未携带 fixedBytes）。而 `RequestDispatchHandler.handleResponseSuccess()` 使用的是**原始** `requestBytes`（未修正）来构造 UI 记录和内存映射。

结果：DB 中存储的是修正后的请求体，UI/内存中存储的是原始请求体，二者不一致。

**涉及文件**

- `src/main/java/oxff/top/http/RequestManager.java` — [makeHttpRequestAsync()](src/main/java/oxff/top/http/RequestManager.java) L367
- `src/main/java/oxff/top/RequestDispatchHandler.java` — [sendRequest()](src/main/java/oxff/top/RequestDispatchHandler.java) L224-231（统一修正 Content-Length）

**代码证据**

```java
// RequestDispatchHandler.java L224-231 — 统一在发送前修正 Content-Length（BUG-006 已修复）
final byte[] finalRequestBytes;
if (currentHttpService != null) {
    finalRequestBytes = RequestDataHelper.fixContentLength(requestBytes, currentHttpService);
} else {
    finalRequestBytes = requestBytes;
}
// ...
requestManager.makeHttpRequestAsync(finalRequestBytes, timeout, currentRequestId, currentHttpService, ...);

// RequestManager.java L367 — DB存储修正后的fixedBytes
byte[] fixedBytes = RequestDataHelper.fixContentLength(requestBytes, service);
// ...
if (requestId > 0) {
    recordingService.recordSuccess(requestId, fixedBytes, proxyResponse, requestInfo, httpResponse, responseTime, service);
}
// 回调仍只传response（UI层已统一使用修正后的bytes）
callback.onSuccess(proxyResponse, startTime, System.currentTimeMillis(), responseTime);
```

**影响范围**

- 当 Content-Length 被修正时，重启后从 DB 加载的历史记录与当前 UI 显示的请求体不同
- DB 报告中展示的请求可能与用户实际编辑的请求不一致
- 影响较小（Content-Length 修正通常不改变请求语义），但违反数据一致性原则

**修复方案（已实施）**

在 `sendRequest()` 中统一调用 `RequestDataHelper.fixContentLength()` 修正 Content-Length，将修正后的 `finalRequestBytes` 同时传给 `makeHttpRequestAsync()` 和 `handleResponseSuccess()`，确保 DB 与 UI 使用同一份修正后的字节：

```java
// RequestDispatchHandler.sendRequest() L224-231（已修复）
final byte[] finalRequestBytes;
if (currentHttpService != null) {
    finalRequestBytes = RequestDataHelper.fixContentLength(requestBytes, currentHttpService);
} else {
    finalRequestBytes = requestBytes;
}
// finalRequestBytes 同时用于：
// 1. makeHttpRequestAsync() → RequestManager 内部 recordSuccess(fixedBytes, ...) 存入 DB
// 2. handleResponseSuccess(finalRequestBytes, response, ...) 构造 UI 记录和内存映射
```

由于 `fixContentLength` 为幂等操作，`RequestManager` 内部的重复调用不会产生副作用。

---

## BUG-007

### 响应体提取使用UTF-8字符串转换导致二进制数据截断风险（中）

**问题描述**

`ReplayEngine.extractResponseBody()` 和 `extractResponseHeaders()` 将 **二进制响应字节数组** 转换为 UTF-8 字符串来查找 `\r\n\r\n` 分隔符。如果响应体包含无法用 UTF-8 解码的字节序列（如图片、压缩数据），String 转换可能导致字符替换，使 `indexOf` 找到错误的位置或找不到分隔符，从而截断或错位响应体。

**涉及文件**

- `src/main/java/oxff/top/privilege/ReplayEngine.java` — [extractResponseBody()](src/main/java/oxff/top/privilege/ReplayEngine.java) L455-470、[extractResponseHeaders()](src/main/java/oxff/top/privilege/ReplayEngine.java) L416-428、[findHeaderBodySeparator()](src/main/java/oxff/top/privilege/ReplayEngine.java) L434-448

**代码证据**

```java
// ReplayEngine.java L416-428（已修复）
private String extractResponseHeaders(byte[] responseBytes) {
    if (responseBytes == null || responseBytes.length == 0) return "";
    try {
        int separatorPos = findHeaderBodySeparator(responseBytes);
        if (separatorPos < 0) {
            return new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
        }
        return new String(responseBytes, 0, separatorPos, java.nio.charset.StandardCharsets.UTF_8);
    } catch (Exception e) {
        return "";
    }
}

// ReplayEngine.java L434-448 — 字节级查找分隔符（BUG-007 已修复）
private static int findHeaderBodySeparator(byte[] data) {
    // 优先查找 \r\n\r\n
    for (int i = 0; i < data.length - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
            return i;
        }
    }
    // 回退查找 \n\n
    for (int i = 0; i < data.length - 1; i++) {
        if (data[i] == '\n' && data[i+1] == '\n') {
            return i;
        }
    }
    return -1;
}
```

**影响范围**

- 二进制响应（图片、PDF、gzip）的相似度计算可能基于错误截取的响应体
- 越权判决结果可能不准确
- 注意：`ContentSplitter`（用于DB存储）使用的是字节级查找，不受此问题影响

**修复方案（已实施）**

使用字节级查找替代字符串查找（参考 `ContentSplitter` 的实现方式），包含 `\r\n\r\n` 优先查找和 `\n\n` 回退查找：

```java
// ReplayEngine.java L434-448（已修复）
private static int findHeaderBodySeparator(byte[] data) {
    // 优先查找 \r\n\r\n
    for (int i = 0; i < data.length - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
            return i;
        }
    }
    // 回退查找 \n\n
    for (int i = 0; i < data.length - 1; i++) {
        if (data[i] == '\n' && data[i+1] == '\n') {
            return i;
        }
    }
    return -1;
}
```

---

## BUG-008

### ensureBodyFile在缓存检查前写文件导致冗余I/O与ref_count潜在错位（低）

**问题描述**

`PoolManager.ensureBodyFile()` 先执行 `fileStorageManager.writeBodyFile()` 写入磁盘文件，然后才检查 `existenceCache` 判断条目是否已存在。如果已存在（缓存命中），文件写入是多余的。虽然不影响数据正确性（文件被覆盖为相同内容），但造成不必要的磁盘 I/O。

更严重的是：如果文件写入"成功"返回了 relativePath，但随后发现条目已存在于 file_pool 中（缓存未命中但DB已有），代码执行 `INSERT...ON CONFLICT DO UPDATE` 时，`relative_path` 不会被更新（ON CONFLICT 只更新 ref_count）。这意味着如果 FileStorageManager 的存储路径发生变化，旧的 relative_path 不会被刷新。

**涉及文件**

- `src/main/java/oxff/top/db/pool/PoolManager.java` — [ensureBodyFile()](src/main/java/oxff/top/db/pool/PoolManager.java) L297-328

**代码证据**

```java
// PoolManager.java L297-328 — ensureBodyFile()（BUG-008 已修复）
private BodyStorageRoute ensureBodyFile(Connection conn, String hash, byte[] body) throws SQLException {
    // 1. 先检查缓存，避免冗余文件写入
    if (existenceCache.containsKey("file:" + hash)) {
        if (incrementRefCount(conn, "file_pool", hash)) {
            return BodyStorageRoute.FILE;
        }
        // 缓存过期（条目已被 GC 回收），清除缓存并继续
        existenceCache.remove("file:" + hash);
    }

    // 2. 写入文件
    String relativePath = fileStorageManager.writeBodyFile(body, hash);
    if (relativePath == null) {
        BurpExtender.printError("[!] 写入 Body 文件失败，hash: " + hash);
        ensureBodyInline(conn, hash, body);  // 回退到行内存储（见BUG-001）
        return BodyStorageRoute.INLINE;
    }

    // 3. INSERT OR INCREMENT
    String sql = "INSERT INTO file_pool (hash, relative_path, size, ref_count, is_binary) VALUES (?, ?, ?, 1, 1) " +
                 "ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1";
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, hash);
        pstmt.setString(2, relativePath);
        pstmt.setInt(3, body.length);
        pstmt.executeUpdate();
    }

    existenceCache.put("file:" + hash, true);
    trimExistenceCacheIfNeeded();
    return BodyStorageRoute.FILE;
}
```

**修复方案（已实施）**

将缓存检查移至文件写入之前（见上方代码证据），关键变更：
1. 缓存命中时先调用 `incrementRefCount()`，仅当返回 `true` 时跳过文件写入
2. 返回 `false` 表示缓存过期（条目已被 GC 回收），清除缓存后继续执行完整写入流程
3. 文件写入失败时回退到行内存储并返回 `BodyStorageRoute.INLINE`（与 BUG-001 修复联动）

---

## 10. 问题汇总矩阵

| 编号 | 严重级别 | 类型 | 问题描述 | 影响 |
|------|---------|------|---------|------|
| BUG-001 | 严重 | 数据存储 | Body文件存储回退路由标记不一致 | 大Body永久丢失 |
| BUG-002 | 高 | 数据存储 | 删除请求未释放响应基线pool引用 | ref_count泄漏，存储膨胀 |
| BUG-003 | 高 | 数据存储 | GC全量重算遗漏requests表响应字段 | 基线响应被误删 |
| BUG-004 | 高 | 数据存储 | incrementRefCount未校验影响行数 | GC后静默丢失新数据 |
| BUG-005 | 中 | 数据展示 | 状态栏对错误响应误显示为成功 | 用户误判请求状态 |
| BUG-006 | 中 | 数据一致性 | DB与UI存储的请求体不一致 | Content-Length修正后数据分叉 |
| BUG-007 | 中 | 逻辑错误 | 二进制响应体提取使用UTF-8字符串转换 | 相似度计算不准 |
| BUG-008 | 低 | 性能/逻辑 | 文件写入在缓存检查前执行 | 冗余I/O |

---

## 附录：审查覆盖的文件清单

| 文件 | 行数 | 审查重点 |
|------|------|----------|
| `RequestDispatchHandler.java` | 918 | 请求调度、响应处理、批量操作 |
| `RequestDAO.java` | 781 | 请求CRUD、pool引用管理 |
| `PoolManager.java` | 432 | 池化去重、ref_count管理、缓存 |
| `ContentReconstructor.java` | 162 | 数据重构、存储路由 |
| `HistoryWriteDAO.java` | 226 | 历史记录写入、pool去重 |
| `HistoryReadDAO.java` | 386 | 历史记录读取、映射 |
| `HistoryUpdateDAO.java` | 171 | 历史删除、引用释放 |
| `RequestManager.java` | 866 | HTTP发送、异步回调 |
| `ReplayEngine.java` | 485 | 越权重放、判决 |
| `GarbageCollectorService.java` | 471 | GC回收、ref_count重算 |
| `RepeaterManagerUI.java` | 913 | 主UI、请求接收、数据刷新 |
| `SchemaInitializer.java` | 313 | 数据库表结构 |
| `SessionDAO.java` | 549 | 会话/字段持久化（路径：`privilege/dao/SessionDAO.java`） |
| `BodyStorageRoute.java` | 40 | 存储路由枚举 |
| `HistoryRecordingService.java` | 448 | 异步历史录制 |

---

*本报告基于代码静态审查生成，建议按严重级别从高到低依次修复，每个修复均需补充对应的回归测试。*
