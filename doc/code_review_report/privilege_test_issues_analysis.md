# 越权判决引擎问题根因分析报告

> 基于四份测试日志 `repeater_manager_log-2026-06-30_1632/1642/1651/1722.txt` 的交叉分析

---

## 问题总览

| # | 问题 | 严重程度 | 影响范围 | 根因定位 |
|---|------|----------|----------|----------|
| 1 | JSON TreeDiff 对结构相同值不同的 JSON 返回相似度 0.0 | **高** | 所有 JSON API 越权判决 | `JsonSimilarityCalculator.computeValueSimilarity()` |
| 2 | 代理模式下并发重放导致日志严重交错 | 中 | 代理模式调试体验 | `ReplayEngine.replay()` 异步提交 |
| 3 | 批量进度日志显示枚举名 `NOT_ESCALATED` 而非中文 `安全` | 中 | 批量权限测试 UI | `RequestDispatchHandler.batchPrivilegeTest()` L807-L810 |
| 4 | 批量进度日志中基准用户错误显示判决结果 | 中 | 批量权限测试 UI | 同上，未检查 `isFirst` |
| 5 | 从请求数据解析相对路径 URL 反复失败 | 中 | 历史记录加载 | `HistoryReadDAO.supplementFromRequestData()` L360 |
| 6 | 请求选中回调每次单击触发两次 | 低 | UI 事件处理 | `RequestListPanel` 的 `ListSelectionListener` + `MouseAdapter` 双重触发 |
| 7 | AutoTestEngine 判决日志使用枚举原名 `NOT_ESCALATED` 而非中文 `安全` | 中 | 代理自动化测试日志 | `AutoTestEngine.java` L260-L262 |
| 8 | AutoTestEngine 缺少判决调试日志 | 中 | 代理自动化测试调试体验 | `AutoTestEngine.java` L196-L213 |
| 9 | AutoTestEngine 硬编码 `useHttp2=false` | 低 | 代理自动化测试 HTTP/2 兼容性 | `AutoTestEngine.java` L304 |

---

## 问题 1：JSON TreeDiff 对结构相同值不同的 JSON 返回相似度 0.0

### 现象

三次测试日志中共复现 **10 次**，典型案例如下：

| 基准响应 | 测试响应(zero) | JSON 结构 | 相似度 |
|----------|---------------|-----------|--------|
| `{"code":0,"message":"VPS started"}` | `{"code":401,"message":"Missing authorization header"}` | `{code, message}` | **0.0000** |
| `{"code":0,"message":"VPS stopped"}` | `{"code":401,"message":"Missing authorization header"}` | `{code, message}` | **0.0000** |
| `{"code":0,"message":"success","data":{VPS详情}}` | `{"code":401,"message":"Missing authorization header"}` | 不同结构 | **0.0000** |
| `{"code":0,"message":"success","data":[{VPS列表}]}` | `{"code":401,"message":"Missing authorization header"}` | 不同结构 | **0.0000** |

### 根因推导

`JsonSimilarityCalculator` 的算法流程分三步，问题出在第三步：

#### 第一步：展平 JSON 为 path→value 映射

```
基准 {"code":0,"message":"VPS started"} → {"code"→"0", "message"→"vps started"}
测试 {"code":401,"message":"Missing authorization header"} → {"code"→"401", "message"→"missing authorization header"}
```

`NoiseFilter.normalize()` 对以上值均**无效**——"0"只有 1 位数字、"401"只有 3 位数字、"vps started"和"missing authorization header"不含任何模式——所有值原样通过。

> **文件**: `src/main/java/org/oxff/repeater/privilege/JsonSimilarityCalculator.java` L64-L76

#### 第二步：计算 key 并集

```java
allKeys = {"code", "message"}    // totalKeys = 2
```

两个 JSON 都有 `code` 和 `message` 两个 key，结构完全相同。

> **文件**: `JsonSimilarityCalculator.java` L119-L123

#### 第三步：逐 key 比较值 —— 🔴 根因所在

```java
// L130-L138
if (v1 != null && v2 != null) {
    if (v1.equals(v2)) {
        matchedKeys++;           // 值相同 → 得 1 分
    } else {
        double valueSim = computeValueSimilarity(v1, v2);
        matchedKeys += valueSim; // 值不同 → 按相似度给部分分
    }
}
```

关键在于 `computeValueSimilarity()` 方法：

```java
// L150-L155
private static double computeValueSimilarity(String v1, String v2) {
    if (v1.equals(v2)) return 1.0;
    if (v1.length() <= 50 && v2.length() <= 50) {
        return 0.0;  // 🔴 短值不同 → 0 分，不给任何部分分！
    }
    return JaccardSimilarityCalculator.similarity(v1, v2);
}
```

**具体计算过程**：

| key | v1 (基准) | v2 (测试) | ≤50字符? | 结果 |
|-----|-----------|-----------|----------|------|
| `code` | `"0"` (1字符) | `"401"` (3字符) | 是 | **0.0** |
| `message` | `"vps started"` (11字符) | `"missing authorization header"` (27字符) | 是 | **0.0** |

```
matchedKeys = 0.0 + 0.0 = 0.0
similarity = 0.0 / 2 = 0.0000
```

### 为什么这是问题

`computeValueSimilarity` 的设计假设是：**短值（≤50字符）如果不同，就完全无关**。这个假设在大多数场景下合理（如 userId=1 vs userId=2 确实应该判为不同），但对越权判决场景存在两个致命缺陷：

1. **结构相同的 JSON 被完全判为无关**（相似度 0.0），导致基于相似度阈值的默认判决逻辑完全失效——永远是 `0.0 < 0.70 → 安全`，无论实际风险如何。

2. **`NoiseFilter` 无法归一化短标量值**。其内置正则（`\b\d{6,19}\b` 等）要求至少 6 位数字，而 `code: 0`、`status: 200`、`count: 5` 这类常见 API 返回值中的短数字完全无法匹配。

### 修复建议

**方案 A（推荐）：引入 key 级权重——区分"结构分"和"值分"**

修改 `computeMapSimilarity()`，将相似度拆分为两段：

```java
// 伪代码
int totalKeys = allKeys.size();
double structuralScore = 0;  // key 存在即得分
double valueScore = 0;       // 值相同才得分

for (String key : allKeys) {
    if (map1.containsKey(key) && map2.containsKey(key)) {
        structuralScore += 1.0;  // 两边都有这个 key → 结构分+1
        if (map1.get(key).equals(map2.get(key))) {
            valueScore += 1.0;   // 值也相同 → 值分+1
        } else {
            valueScore += computeValueSimilarity(v1, v2); // 不同给部分分
        }
    }
    // 单边独有的 key → 两个分数都不加
}

double structureSimilarity = structuralScore / totalKeys;
double valueSimilarity = valueScore / structuralScore; // 仅在共有 key 上比较值
return 0.3 * structureSimilarity + 0.7 * valueSimilarity; // 加权混合
```

这样 `{code, message}` vs `{code, message}` 的结构分 = 2/2 = 1.0，即使值分 = 0，最终相似度也有 0.3，不再永远是 0.0。

**方案 B：为 `computeValueSimilarity` 的短值分支设置保底分**

```java
if (v1.length() <= 50 && v2.length() <= 50) {
    return 0.1;  // 给 10% 保底分，而非 0
}
```

优点是最小改动，但语义不够精确。

**方案 C：增强 NoiseFilter，归一化短数字和短文本**

在内置 pattern 中增加通用归一化规则：
```java
Pattern.compile("\\b\\d+\\b"),         // 所有纯数字 → __NOISE__
Pattern.compile("\\b[a-z_]+\\b"),      // 所有 snake_case 文本 → __NOISE__
```

风险较高——过度归一化可能导致真正不同的响应也被判为相同。

---

## 问题 2：代理模式下并发重放导致日志严重交错

### 现象

`1632` 日志（2 批并发）和 `1642` 日志（4 批并发）中，所有 `[D-判决]` 日志完全交织，无法追踪单次判决链路。以 `1642` 日志为例：

```
第25行 [D-判决] baselineBodyLen=34, currentStatusCode=401    ← 批次A第3条
第26行 [D-判决] baselineBodyLen=1329, currentStatusCode=401  ← 批次B第2条
第27行 [D-判决] baselineBodyLen=34, currentStatusCode=401    ← 批次C第1条
第28行 [D-判决] 基准响应体前200字: {...VPS列表...}            ← 批次B
第29行 [D-判决] 基准响应体前200字: {"code":0,"message":"VPS stopped"} ← 批次C
第30行 [D-判决] baselineBodyLen=361, currentStatusCode=401   ← 批次D
```

### 根因推导

代理模式下，每个被 Scope 匹配的请求都会**立即、异步**调用 `ReplayEngine.replay()`：

> **文件**: `src/main/java/org/oxff/repeater/privilege/ReplayEngine.java` L105

```java
executor.submit(() -> {
    // 每个请求在这个 lambda 中独立执行全部用户会话的重放
    for (int i = 0; i < enabledSessions.size(); i++) {
        // ... 发送请求、计算相似度、判决 ...
    }
});
```

`executor` 是 `Executors.newCachedThreadPool()`（L41），不限制并发数。当代理连续拦截到 N 个请求时，N 个 lambda 同时在线程池中执行，所有 `LogManager.judgmentDebug()` 输出进入同一个日志通道，产生交错。

**数据安全说明**：`baselineResponse` 是在 lambda 内部定义的局部变量（L109），每个并发 lambda 有自己独立的副本，不会互相覆盖。问题仅限于**日志输出的可读性**，不影响判决结果的正确性。

### 修复建议

**方案 A（推荐）：在每条 `[D-判决]` 日志前加上请求标识前缀**

修改 `LogManager.judgmentDebug()` 或在调用处增加前缀：

```java
LogManager.getInstance().judgmentDebug(String.format(
    "[判决][req=%d][user=%s] 判决前数据: baselineBodyLen=%d, ...",
    requestId, session.getName(), ...));
```

这样即使日志交错，也能按 `[req=1]` 过滤还原单次链路。`requestId` 需要从 `ReplayEngine.replay()` 的参数传入到判决相关的内部方法中。

**方案 B：代理模式也改为串行队列**

将 `CachedThreadPool` 替换为单线程 `ExecutorService`：
```java
this.executor = Executors.newSingleThreadExecutor(r -> {
    Thread t = new Thread(r, "PrivilegeTest-Replay");
    t.setDaemon(true);
    return t;
});
```

代价是代理模式下多个请求不能并行重放，可能影响实时性。

---

## 问题 3：批量进度日志显示枚举名 `NOT_ESCALATED` 而非中文 `安全`

### 现象

```
第36行: [*] 批量权限测试 [1/4]: 用户=globex_viewer, 判决=NOT_ESCALATED
第57行: [*] 批量权限测试 [1/4]: 用户=zero, 判决=NOT_ESCALATED
```

对比非批量路径（正常）：
```
第62行: [*] 权限测试重放完成: requestId=3, 用户=zero, 判决=安全, 相似度=0.00
```

### 根因推导

> **文件**: `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` L806-L810

```java
// 批量路径（有问题）
LogManager.getInstance().printOutput(String.format(
    "[*] 批量权限测试 [%d/%d]: 用户=%s, 判决=%s",
    completedCount.get() + 1, totalCount,
    rec.getUserSessionName(),
    rec.getJudgment()));   // ← rec.getJudgment() 返回 "NOT_ESCALATED"（枚举常量名）
```

`rec.getJudgment()` 存储的是 `ReplayEngine` 中通过 `JudgmentResult.NOT_ESCALATED.name()` 写入的原始枚举名。

对比非批量路径（正确）：

> **文件**: `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` L679-L686

```java
// 非批量路径（正确）
JudgmentResult judgment = JudgmentResult.fromString(record.getJudgment());
LogManager.getInstance().printOutput(String.format(
    "[*] 权限测试重放完成: ... 判决=%s ...",
    judgment.getDisplayName()));  // ← 调用 getDisplayName() 返回 "安全"
```

`JudgmentResult` 已有现成的转换工具：
- `JudgmentResult.fromString("NOT_ESCALATED")` → 枚举值
- `.getDisplayName()` → `"安全"`

> **文件**: `src/main/java/org/oxff/repeater/privilege/model/JudgmentResult.java` L23-L25

### 修复建议

修改 `RequestDispatchHandler.java` L810，使用 `JudgmentResult.toDisplayName()`：

```java
LogManager.getInstance().printOutput(String.format(
    "[*] 批量权限测试 [%d/%d]: 用户=%s, 判决=%s",
    completedCount.get() + 1, totalCount,
    rec.getUserSessionName(),
    JudgmentResult.toDisplayName(rec.getJudgment())));  // "NOT_ESCALATED" → "安全"
```

`JudgmentResult.toDisplayName()` 方法（L54-L60）已经封装了 `fromString()` + `getDisplayName()` 的逻辑，可直接使用。

---

## 问题 4：批量进度日志中基准用户错误显示判决结果

### 现象

```
第36行: [*] 批量权限测试 [1/4]: 用户=globex_viewer, 判决=NOT_ESCALATED
```

基准用户 `globex_viewer` 不应该有"判决"——它只是参照物，不参与比较。

### 根因推导

> **文件**: `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` L806-L810

批量路径的 `onReplayComplete` 回调**没有检查 `isFirst` 参数**：

```java
@Override
public void onReplayComplete(RequestResponseRecord rec, boolean isFirst) {
    // ... 添加历史记录、持久化 ...
    
    // ❌ 缺失 isFirst 判断 — 基准用户和测试用户走同一日志路径
    LogManager.getInstance().printOutput(String.format(
        "[*] 批量权限测试 [%d/%d]: 用户=%s, 判决=%s",
        completedCount.get() + 1, totalCount,
        rec.getUserSessionName(),
        rec.getJudgment()));
}
```

对比非批量路径（已正确修复）：

> **文件**: `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` L673-L686

```java
if (isFirst) {
    LogManager.getInstance().printOutput(String.format(
        "[*] 权限测试重放完成: requestId=%d, 用户=%s, 判决=基准用户(不参与比较)",
        record.getRequestId(), record.getUserSessionName()));
} else {
    // 正常判决日志
}
```

### 修复建议

在批量路径的 `onReplayComplete` 中增加 `isFirst` 分支：

```java
if (isFirst) {
    LogManager.getInstance().printOutput(String.format(
        "[*] 批量权限测试 [%d/%d]: 用户=%s (基准用户，不参与比较)",
        completedCount.get() + 1, totalCount,
        rec.getUserSessionName()));
} else {
    LogManager.getInstance().printOutput(String.format(
        "[*] 批量权限测试 [%d/%d]: 用户=%s, 判决=%s",
        completedCount.get() + 1, totalCount,
        rec.getUserSessionName(),
        JudgmentResult.toDisplayName(rec.getJudgment())));
}
```

---

## 问题 5：从请求数据解析相对路径 URL 反复失败

### 现象

三个日志中频繁出现（每个请求 2 次）：

```
从请求数据解析URL失败，跳过补充: no protocol: /api/v1/vps/6/start
从请求数据解析URL失败，跳过补充: no protocol: /api/v1/vps/6/stop
从请求数据解析URL失败，跳过补充: no protocol: /api/v1/vps
```

### 根因推导

> **文件**: `src/main/java/org/oxff/repeater/db/history/HistoryReadDAO.java` L357-L360

```java
String urlStr = httpRequest.url();
if (urlStr != null && !urlStr.isEmpty()) {
    try {
        java.net.URL url = new java.net.URL(urlStr);  // 🔴 抛出 MalformedURLException
```

**触发条件**：从数据库加载历史记录时，`LEFT JOIN requests` 表可能因 hash 不匹配或 GC 误删返回 NULL。此时调用 `supplementFromRequestData()` 尝试从原始请求字节恢复元数据。但 `httpRequest.url()` 在缺少 `HttpService` 上下文时，Montoya API 返回的是**纯路径**（如 `/api/v1/vps/6/start`），不含协议前缀。`new URL(pathOnly)` 抛出 `MalformedURLException: no protocol`。

**为什么每个请求触发两次**：日志中每条请求都记录了两次此错误，对应 `supplementFromRequestData()` 被调用两次——与问题 6 的"选中回调触发两次"直接相关。

**为什么已有 catch 但仍是问题**：虽然异常被捕获且日志说"跳过补充"（不影响功能），但每次加载历史记录都触发两次 `new URL()` 异常构造（包括堆栈填充），在高频操作下产生不必要的 CPU 开销。

### 修复建议

在调用 `new URL()` 之前增加协议检测：

```java
String urlStr = httpRequest.url();
if (urlStr != null && !urlStr.isEmpty()) {
    // 相对路径无法被 new URL() 解析，直接提取 path
    if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
        // 相对路径：直接作为 path 使用，跳过协议/域名解析
        if (record.getPath() == null || record.getPath().isEmpty()) {
            record.setPath(urlStr.startsWith("/") ? urlStr : "/" + urlStr);
        }
        return; // 不再尝试 new URL()
    }
    try {
        java.net.URL url = new java.net.URL(urlStr);
        // ... 正常解析 ...
    }
}
```

或者利用 `URI` 类对相对路径的更好支持：
```java
java.net.URI uri = new java.net.URI(urlStr);
if (uri.isAbsolute()) {
    java.net.URL url = uri.toURL();
    // 正常解析
} else {
    record.setPath(uri.getPath());
}
```

---

## 问题 6：请求选中回调每次单击触发两次

### 现象

```
16:50:43.488 [*] 请求选中回调触发，请求ID: 4
16:50:43.598 [*] 请求选中回调触发，请求ID: 4   ← 同一 ID，110ms 后再次触发
16:50:44.024 [*] 请求选中回调触发，请求ID: 3
16:50:44.141 [*] 请求选中回调触发，请求ID: 3
16:50:44.615 [*] 请求选中回调触发，请求ID: 2
16:50:44.741 [*] 请求选中回调触发，请求ID: 2
16:50:45.127 [*] 请求选中回调触发，请求ID: 1
16:50:45.230 [*] 请求选中回调触发，请求ID: 1
```

每个请求 ID 在约 100-120ms 内连续触发两次。

### 根因推导

`RequestListPanel` 中有**两个**相互独立的回调触发源：

#### 触发源 1：ListSelectionListener（L121-L132）

```java
requestTable.getSelectionModel().addListSelectionListener(e -> {
    if (!e.getValueIsAdjusting() && !batchAddMode) {
        // 选中行变化时触发
        requestSelectedCallback.onRequestSelected(requestId, requestData);
    }
});
```

选中行变化时触发。使用 `!e.getValueIsAdjusting()` 过滤掉选择过程中的中间事件。

#### 触发源 2：MouseAdapter（L136-L152）

```java
requestTable.addMouseListener(new MouseAdapter() {
    public void mousePressed(MouseEvent e) {
        if (batchAddMode) return;
        int row = requestTable.rowAtPoint(e.getPoint());
        if (row == requestTable.getSelectedRow()) { // 🔴 点击已选中行时触发
            requestSelectedCallback.onRequestSelected(requestId, requestData);
        }
    }
});
```

这个 MouseAdapter 的设计意图是处理"单击已选中行"场景（Swing 的 ListSelectionListener 在选中行未变化时不触发），让用户从其他面板切回请求表后点击同一行时能重新加载数据。

#### 🔴 竞合根因

问题出在 **`mousePressed` 事件先于 `ListSelectionListener` 触发**，但 Swing 在 `mousePressed` 阶段尚未完成选择模型更新。具体时序：

```
用户点击行 X（当前选中行 Y，X ≠ Y）
│
├─ mousePressed 触发
│   └─ rowAtPoint = X, getSelectedRow() = Y
│       X ≠ Y → MouseAdapter 不触发 ✅
│
├─ ListSelectionListener.valueChanged(e) 触发
│   └─ getValueIsAdjusting() = false
│       触发 onRequestSelected(X) → 回调 #1
│
└─ historyPanel.clearHistory() + loadHistoryForRequest(X)
    └─ 加载历史记录时，historyPanel 内部操作可能触发
       父组件重新布局或焦点恢复事件
       └─ 这可能间接触发额外的 selection 事件
           └─ 或将焦点还给请求表，Swing 再次触发 ListSelectionListener
               └─ 触发 onRequestSelected(X) → 回调 #2 (110ms 后)
```

更可能的直接原因：**`loadHistoryForRequest()` 内部调用 `historyPanel.clearHistory()` 后立即添加历史行，触发历史表格的 UI 更新。这个更新可能通过 Swing 的焦点/选择恢复机制间接触发请求表的选择事件再次发射**。两次回调间约 110ms 的间隔正好是 `clearHistory + DB 查询 + UI 渲染` 的时间。

### 修复建议

**方案 A（推荐）：在 `onRequestSelected` 入口处增加防抖**

> **文件**: `src/main/java/org/oxff/repeater/RepeaterManagerUI.java` L400

```java
private volatile int lastSelectedRequestId = -1;
private volatile long lastSelectTime = 0;
private static final long DEBOUNCE_MS = 300;

private void onRequestSelected(int requestId, byte[] requestData) {
    // 防抖：同一 requestId 在 300ms 内不重复处理
    long now = System.currentTimeMillis();
    if (requestId == lastSelectedRequestId && (now - lastSelectTime) < DEBOUNCE_MS) {
        return;
    }
    lastSelectedRequestId = requestId;
    lastSelectTime = now;
    
    LogManager.getInstance().printOutput("[*] 请求选中回调触发，请求ID: " + requestId);
    // ... 原有逻辑 ...
}
```

**方案 B：排查 `loadHistoryForRequest` 中是否触发了请求表选择事件**

在 `historyPanel.clearHistory()` 和加载历史记录时，检查是否有代码间接修改了请求表的选择模型。

---

## 问题 7：AutoTestEngine 判决日志使用枚举原名而非中文

### 现象

代理自动化测试路径的日志输出：

```
[*] 自动化测试: 用户=zero, 判决=NOT_ESCALATED, 相似度=0.00
```

对比 `ReplayEngine` 路径（通过 `RequestDispatchHandler` 回调，已修复）：

```
[*] 权限测试重放完成: requestId=1, 用户=zero, 判决=安全, 相似度=0.00
```

### 根因推导

> **文件**: `src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java` L260-L262

```java
LogManager.getInstance().printOutput(String.format(
        "[*] 自动化测试: 用户=%s, 判决=%s, 相似度=%.2f",
        session.getName(), judgment, similarity));
//                         ^^^^^^^^ 直接输出枚举名 "NOT_ESCALATED"
```

`judgment` 变量的值来自：
- `JudgmentResult.NOT_ESCALATED.name()` → `"NOT_ESCALATED"`（L201）
- `outcome.result.name()` → `"NOT_ESCALATED"`（L209）

两者都是 Java 枚举的原始名称，未经过 `JudgmentResult.toDisplayName()` 转换。

而 `ReplayEngine` 路径通过回调进入 `RequestDispatchHandler`，该处已正确使用 `judgment.getDisplayName()`（L684），故输出"安全"。

### 修复建议

使用 `JudgmentResult.toDisplayName()` 转换：

```java
LogManager.getInstance().printOutput(String.format(
        "[*] 自动化测试: 用户=%s, 判决=%s, 相似度=%.2f",
        session.getName(),
        JudgmentResult.toDisplayName(judgment),  // "NOT_ESCALATED" → "安全"
        similarity));
```

---

## 问题 8：AutoTestEngine 缺少判决调试日志

### 现象

用户开启调试模式后，`ReplayEngine` 路径可输出完整的 `[D-判决]` 日志（如1722日志第30-45行），但代理自动化测试路径 (`AutoTestEngine`) 即使在调试模式下也无任何判决细节输出，导致代理模式下的判决问题无法诊断。

### 根因推导

对比两个引擎的判决路径：

**ReplayEngine（有调试日志）** — `ReplayEngine.java` L204-L214：

```java
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 判决前数据: baselineBodyLen=%d, currentBodyLen=%d, ...", ...));
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 基准响应体前200字: %s", truncateForLog(baselineResponse, 200)));
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 当前响应体前200字: %s", truncateForLog(responseBodyOnly, 200)));
```

**AutoTestEngine（无调试日志）** — `AutoTestEngine.java` L196-L213：

```java
if (holder.response != null && holder.response.length > 0) {
    if (isFirst) {
        baselineResponse = HttpMessageParser.extractResponseBody(holder.response);
        baselineStatusCode = holder.statusCode;
        baselineValid = true;
        judgment = JudgmentResult.NOT_ESCALATED.name();
    } else {
        // ... 直接调用 JudgmentEngine.judge() ...
        // ❌ 缺少 judgmentDebug() 调用
    }
}
```

### 修复建议

在 `AutoTestEngine.java` 的非基准用户判决分支（L202-L213）中，于 `JudgmentEngine.judge()` 调用前添加与 `ReplayEngine` 一致的调试日志：

```java
// === 判决前诊断日志 ===
if (baselineResponse == null || baselineResponse.length == 0) {
    LogManager.getInstance().printError(String.format(
            "[!] 基准响应体为空(用户=%s),相似度计算不可靠", session.getName()));
}
if (responseBodyOnly == null || responseBodyOnly.length == 0) {
    LogManager.getInstance().printError(String.format(
            "[!] 当前响应体为空(用户=%s),相似度计算不可靠", session.getName()));
}
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 判决前数据: baselineBodyLen=%d, currentBodyLen=%d, baselineStatusCode=%d, currentStatusCode=%d, threshold=%.2f",
        baselineResponse != null ? baselineResponse.length : -1,
        responseBodyOnly != null ? responseBodyOnly.length : -1,
        baselineStatusCode, holder.statusCode, threshold));
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 基准响应体前200字: %s", truncateForLog(baselineResponse, 200)));
LogManager.getInstance().judgmentDebug(String.format(
        "[判决] 当前响应体前200字: %s", truncateForLog(responseBodyOnly, 200)));
```

> **注意**：`truncateForLog()` 目前是 `ReplayEngine` 的私有方法，需要抽取为公共工具方法或复制到 `AutoTestEngine`。

---

## 问题 9：AutoTestEngine 硬编码 useHttp2=false

### 现象

代理拦截到 HTTP/2 请求后，AutoTestEngine 重放时始终使用 HTTP/1.1，可能导致不支持 HTTP/1.1 的服务端拒绝请求或行为差异。

### 根因推导

> **文件**: `src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java` L301-L305

```java
private SyncHttpSender.Result sendSyncRequestWithRetry(byte[] requestBytes, HttpService httpService,
                                                         RequestManager requestManager,
                                                         int timeoutSeconds, int retryCount, int retryDelayMs) {
    return SyncHttpSender.sendWithRetry(requestBytes, httpService, requestManager,
            false, timeoutSeconds, retryCount, retryDelayMs, "自动化测试");
    //      ^^^^^ 硬编码为 false
}
```

对比 `ReplayEngine`（正确传递）：

> **文件**: `src/main/java/org/oxff/repeater/privilege/ReplayEngine.java` L315-L319

```java
private SyncHttpSender.Result sendSyncWithRetry(byte[] requestBytes, HttpService httpService,
                                              RequestManager requestManager, boolean useHttp2,
                                              int timeoutSeconds, int retryCount, int retryDelayMs) {
    return SyncHttpSender.sendWithRetry(requestBytes, httpService, requestManager,
            useHttp2, timeoutSeconds, retryCount, retryDelayMs, "重放");
    //      ^^^^^^^ 从调用方传入
}
```

`ReplayEngine` 的 `sendSyncWithRetry` 接受 `useHttp2` 参数并透传给 `SyncHttpSender`，而 `AutoTestEngine` 的对应方法不接受此参数，直接硬编码 `false`。

**注意**：这是重构前就存在的问题（旧版 `AutoTestEngine.sendSyncRequestOnce()` 调用 `makeHttpRequestAsync` 时同样未传 HTTP/2 标志），`SyncHttpSender` 重构使其显式化，但未修复。

### 修复建议

从 `InterceptedRequest` 或 `HttpService` 提取 HTTP/2 信息并传递：

```java
// 方案：通过 HttpService 或 Burp API 判断
// Montoya API 中 HttpService 目前无直接 isHttp2() 方法，
// 但可从 interceptedRequest 的注释/标记中获取，或使用 Burp 扩展 API

// 短期方案：通过请求字节中的协议指示符判断
boolean useHttp2 = detectHttp2FromRequest(requestBytes, httpService);

private SyncHttpSender.Result sendSyncRequestWithRetry(byte[] requestBytes, HttpService httpService,
                                                         RequestManager requestManager,
                                                         int timeoutSeconds, int retryCount, int retryDelayMs,
                                                         boolean useHttp2) {
    return SyncHttpSender.sendWithRetry(requestBytes, httpService, requestManager,
            useHttp2, timeoutSeconds, retryCount, retryDelayMs, "自动化测试");
}
```

---

## 附录：各日志的测试环境差异

| 维度 | 1632 日志 | 1642 日志 | 1651 日志 | 1722 日志 |
|------|----------|----------|----------|----------|
| 模式 | 代理实时拦截 | 代理实时拦截 | 批量权限测试 | 代理实时拦截 |
| 并发度 | 2 批 | 4 批 | 串行 | 1 批（串行） |
| 测试 API | start/stop | start/stop/list/detail | start/stop/list/detail | start |
| 基准用户 | globex_viewer | globex_viewer | globex_viewer | globex_viewer |
| 测试用户 | zero | zero | zero | zero |
| 判决规则 | 测试 + 默认相似度规则 | 测试 + 默认相似度规则 | 测试 + 默认相似度规则 | 测试 + 默认相似度规则 |
| 相似度阈值 | 0.70 | 0.70 | 0.70 | 0.85 |
| 调试模式 | 开启 | 开启 | 开启 | 开启 |
| 全部判决结果 | 安全 (相似度=0.00) | 安全 (相似度=0.00) | 安全 (NOT_ESCALATED) | 安全 (相似度=0.00) |
| 判决是否正确 | ✅ 正确 (401 确实安全) | ✅ 正确 | ✅ 正确 | ✅ 正确 |
| 相似度是否正确 | 🔴 0.0 不合理 | 🔴 0.0 不合理 | 🔴 0.0 不合理 | 🔴 0.0 不合理 |
| 问题3/4（枚举名/基准） | 触发 | 触发 | 触发 | 未触发（非批量路径已正确） |
| 问题6（双重回调） | 未明确 | 未明确 | 触发（每次2次） | 触发（每次2次） |
| 问题5（URL解析） | 触发（每次2次） | 触发（每次2次） | 触发（每次2次） | 触发（每次2次） |
| 问题7/8/9（AutoTestEngine） | 未检测 | 未检测 | 未检测 | 本次代码分析发现 |

**核心结论**：

1. **判决结果正确性**：所有四次测试的判决结果（安全/未越权）都是**正确的**——测试用户 `zero` 缺少有效的 Authorization header，服务器正确返回 401。

2. **相似度计算的根本缺陷**（问题1）：`computeValueSimilarity()` 对短不同值返回 0.0，导致**结构完全相同的 JSON 被判为完全不相似**，使得基于相似度阈值的判决机制形同虚设。四次测试中复现此问题共 **11 次**（1632:3次, 1642:4次, 1651:3次, 1722:1次）。

3. **路径不一致**（问题3、7）：非批量路径（`RequestDispatchHandler`）已正确使用 `getDisplayName()`，但批量路径和 `AutoTestEngine` 路径仍输出枚举原名。

4. **调试覆盖不全**（问题8）：`ReplayEngine` 有完整的 `judgmentDebug()` 调用链，但 `AutoTestEngine` 完全缺失，导致代理自动化测试路径的判决问题无法诊断。

5. **历史遗留问题累积**：问题5、6、9 均为长期存在的低优先级问题，低频操作下影响有限但持续复现。
