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
| 越权测试重放 | `ReplayEngine.replay()` → `TokenReplacementEngine` → `JudgmentEngine` |
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
| `SessionDAO.java` | 549 | 会话/令牌持久化（路径：`privilege/dao/SessionDAO.java`） |
| `BodyStorageRoute.java` | 40 | 存储路由枚举 |
| `HistoryRecordingService.java` | 448 | 异步历史录制 |

---

*本报告基于代码静态审查生成，建议按严重级别从高到低依次修复，每个修复均需补充对应的回归测试。*
