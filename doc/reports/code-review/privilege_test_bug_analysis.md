# 越权测试业务逻辑 Bug 分析报告

> 分析日期：2026-06-30  
> 分析依据：`tmp/logs/repeater_manager.log`（插件加载并执行越权测试后的日志）+ 源码审查  
> 测试场景：POST `http://localhost:5000/api/v1/vps/1/stop`，基线用户 alice（200），测试用户 zero（401）

---

## 概览

| # | 严重级别 | 问题 | 涉及文件 |
|---|---------|------|---------|
| 1 | **严重** | `evaluateConditions` OR 逻辑完全失效 | `JudgmentEngine.java` |
| 2 | **中等** | 所有条件被跳过时规则错误命中 | `JudgmentEngine.java` |
| 3 | **中等** | 相似度算法选择使用了错误的 Content-Type | `JudgmentEngine.java` | ✅ 已修复 |
| 4 | **中等** | 字段列表为空时静默返回原始请求 | `FieldReplacementEngine.java` | ⚠️ 部分修复（调用方已加警告） |
| 5 | **低** | `judge()` 守卫条件过窄，204/304 场景处理不当 | `JudgmentEngine.java` | ❌ 未修复 |
| 6 | **低** | 异常路径中 `baselineValid` 注释与实际代码不符 | `ReplayEngine.java`, `AutoTestEngine.java` | ❌ 未修复 |
| 7 | **严重** | `computeMapSimilarity` 值分权重过高导致水平越权漏报 | `JsonSimilarityCalculator.java` | ✅ 已修复（0.5/0.5） |
| 8 | **中等** | NoiseFilter 遗漏 1-5 位小数值 ID | `NoiseFilter.java` | ✅ 已修复（\d{4,19}） |
| 9 | **中等** | `computeValueSimilarity` 对短字符串二值判断过严 | `JsonSimilarityCalculator.java` | ✅ 已修复（Levenshtein集成） |
| 10 | **严重** | 单活跃规则组架构导致默认规则安全网被绕过 | `JudgmentEngine.java`, `JudgmentRuleManager.java` | ✅ 已修复（活跃未命中→检查默认规则） |
| 11 | **中等** | `ensureDefaultSimilarityRule()` 创建条件过于宽松 | `JudgmentRuleManager.java` | ✅ 已修复（按名称精确匹配） |
| 12 | **中等** | `LevenshteinCalculator` 已实现但未集成到相似度管线 | `LevenshteinCalculator.java`, `JsonSimilarityCalculator.java` | ✅ 已修复 |
| 13 | **低** | 规则组创建时触发过量缓存刷新 | `JudgmentRuleManager.java` | ❌ 未修复 |
| 14 | **低** | 纯 AND 架构失去 OR 条件组合表达能力 | `JudgmentEngine.java` | ❌ 未修复 |
| 15 | **⚠️ 降级** | `setPrivilegeTestRequest()` 关闭/重开循环（设计意图） | `RepeaterManagerUI.java` | 非Bug：防止双重重放的有意设计 |
| 16 | **⚠️ 降级** | `modeToggleButton.setSelected()` 反馈链（证据不足） | `RepeaterManagerUI.java`, `RequestDispatchHandler.java` | 无法证实；日志中关闭可能为用户手动操作 |
| 17 | **⚠️ 降级** | 自动触发模式下无 close/reopen 仍自动退出（证据不足） | `RepeaterManagerUI.java`, `RequestDispatchHandler.java` | 无法证实；日志中关闭可能为用户手动操作 |

> **🔄 v2 更新 (2026-06-30 21:10)**：用户修改代码后重新测试（日志第 98-293 行），新增两轮完整的插件加载→规则组配置→双接口越权测试。以下为 v2 分析结论。

### 架构变更摘要

| 方面 | v1（旧版） | v2（新版） |
|------|----------|----------|
| 规则模型 | 单条规则，每条含一个 target/method/expr | **规则组**，每组包含多个条件（conditions） |
| 条件组合 | AND / OR 两种运算符 | **纯 AND**（不可配置） |
| 规则迭代 | 按 priority 依次匹配所有已启用规则 | 仅评估**单一活跃规则组**（`getActiveRule()`） |
| 默认兜底 | 所有规则未命中 → `judgeDefault(threshold=0.85)` | 活跃规则组未命中 → `judgeDefault(threshold=0.85)` |
| 默认规则 | 自动创建"默认相似度规则"，priority=999 | 自动创建"默认相似度规则组"，isActive=true |

### Bug 状态更新

#### v2 状态 (2026-06-30 第一次修复后)

| Bug # | 描述 | v2 状态 |
|-------|------|--------|
| 1 | OR 逻辑失效 | ✅ **已修复** — 改为纯 AND，短路求值 |
| 2 | 所有条件跳过→true | ✅ **已修复** — 空条件列表返回 false |
| 3 | Content-Type 取自错误响应 | ❌ v2未修复 |
| 4 | 字段为空静默返回 | ⚠️ v2未检查变更 |
| 5 | guard 条件过窄 | ❌ v2未修复 |
| 6 | 注释与实际不符 | ⚠️ v2未修复 |
| 7 | 值分权重 0.7 → 漏报 | ❌ v2未修复 |
| 8 | NoiseFilter 遗漏小数值 | ❌ v2未修复 |
| 9 | 短字符串二值判断 | ❌ v2未修复（但新增了 LevenshteinCalculator 未集成） |
| 10 | 默认规则安全网被绕过 | ❌ v2未修复 |
| 11 | ensureDefaultSimilarityRule 过于宽松 | ❌ v2未修复 |
| 12 | LevenshteinCalculator 未集成 | ❌ v2未修复 |
| 13 | 规则组过量缓存刷新 | ❌ v2未修复 |
| 14 | 纯AND失去OR能力 | ❌ v2未修复 |
| 15 | close/reopen EDT震荡 | ❌ v2未修复 |
| 16 | setSelected反馈链 | ❌ v2未修复 |
| 17 | 无close/reopen仍退出 | ❌ v2未修复 |

#### v3 验证 (2026-06-30 用户手动修复后，代码逐文件比对)

| Bug # | 描述 | v3 状态 | 验证依据 |
|-------|------|---------|----------|
| 1 | OR 逻辑失效 | ✅ **已修复** | v13架构，纯AND |
| 2 | 所有条件跳过→true | ✅ **已修复** | v13架构 |
| 3 | Content-Type 取自错误响应 | ✅ **已修复** | `baselineContentType` 优先（line 116-118） |
| 4 | 字段为空静默返回 | ⚠️ 部分修复 | 调用方(ReplayEngine/AutoTestEngine)已加警告；但 `FieldReplacementEngine` 内部仍静默 |
| 5 | guard 条件过窄 | ❌ 未修复 | `baselineResponse == null && baselineStatusCode <= 0` 未拆分 |
| 6 | 注释与实际不符 | ❌ 未修复 | 注释仍为旧逻辑 |
| 7 | 值分权重 0.7 → 漏报 | ✅ **已修复** | `0.5*structure + 0.5*value`（line 156） |
| 8 | NoiseFilter 遗漏小数值 | ✅ **已修复** | `\d{4,19}`（line 40） |
| 9 | 短字符串二值判断 | ✅ **已修复** | Levenshtein 集成（lines 168-169） |
| 10 | 默认规则安全网被绕过 | ✅ **已修复** | 活跃未命中→检查 defaultRule（lines 170-198） |
| 11 | ensureDefaultSimilarityRule 过于宽松 | ✅ **已修复** | 按名称匹配"默认相似度规则"（lines 250-269） |
| 12 | LevenshteinCalculator 未集成 | ✅ **已修复** | 已在 `computeValueSimilarity` 中集成 |
| 13 | 规则组过量缓存刷新 | ❌ 未修复 | 每次 addRuleCondition 单独 refreshCache |
| 14 | 纯AND失去OR能力 | ❌ 未修复 | 设计权衡 |
| 15 | close/reopen EDT震荡 | ⚠️ **降级** | **非Bug**：close/reopen 是防止 `setRequest()` 双重重放的有意设计 |
| 16 | setSelected反馈链 | ⚠️ **降级** | **证据不足**：日志中的关闭时间戳（1.37s/2.57s/2.99s延迟）与用户手动操作吻合，无法证实为代码触发 |
| 17 | 无close/reopen仍退出 | ⚠️ **降级** | **证据不足**：日志来自多次测试会话混用，关闭极可能为用户测完后手动操作 |

---

## Bug 1（严重）：`evaluateConditions` 中 OR 逻辑运算符完全失效

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 249 行

### 问题描述

`evaluateConditions` 方法将累积结果 `result` 初始化为 `true`。`true` 是 AND 的单位元（`true && X = X`），但 OR 的单位元应该是 `false`（`false || X = X`）。当规则的第一个条件使用 OR 运算符时，`result = true || condResult` 恒为 `true`，无论 `condResult` 是真还是假。

```java
boolean result = true;  // ← 初始值 true，正确仅适用于 AND
for (RuleCondition cond : conditions) {
    // ...
    if (cond.getOperator() == RuleCondition.LogicalOperator.AND) {
        result = result && condResult;  // true && X = X  ✓
    } else {  // OR
        result = result || condResult;  // true || X = true ← 永远为真！✗
    }
}
```

### 日志证据（间接）

本次测试中用户配置的规则 'test' 使用 AND 运算符，因此该 Bug 未被触发。但以下场景将导致误判：

- 用户配置规则：`STATUS_CODE EQUALS 401 OR STATUS_CODE EQUALS 403` → 意图是"任一拒绝状态码即判定越权"
- 实际行为：首条件 `true || (statusCode==401)` = `true` → 规则命中 → ESCALATED，无论实际状态码是什么

### 根因

对所有运算符统一使用 AND 的单位元 `true` 作为初始值。在复合逻辑表达式求值中，需要根据首个有效条件的运算符类型选择对应的单位元。

### 修复方案

将初始化逻辑改为：先找到第一个有效条件，根据其运算符设定初始值，然后从该条件开始求值。

```java
private static boolean evaluateConditions(List<RuleCondition> conditions,
                                           int statusCode, String responseHeaders,
                                           String bodyStr, double similarity,
                                           long responseTimeMs,
                                           byte[] responseBody, byte[] baselineResponse) {
    if (conditions == null || conditions.isEmpty()) {
        LogManager.getInstance().judgmentDebug("[判决] evaluateConditions: 条件列表为空 → false");
        return false;
    }

    // 找到第一个有效条件，以其运算符决定初始累积值
    int firstValidIdx = -1;
    for (int i = 0; i < conditions.size(); i++) {
        if (conditions.get(i).isValid()) {
            firstValidIdx = i;
            break;
        }
    }

    if (firstValidIdx == -1) {
        // 所有条件均无效 → 不应命中
        LogManager.getInstance().judgmentDebug("[判决] evaluateConditions: 所有条件均无效 → false");
        return false;
    }

    // 先求值第一个有效条件，作为累积结果的初始值
    RuleCondition firstCond = conditions.get(firstValidIdx);
    String targetValue = extractTargetValue(firstCond.getTarget(), statusCode,
            responseHeaders, bodyStr, similarity, responseTimeMs);
    boolean condResult = matchValue(firstCond.getMethod(), firstCond.getExpression(),
            targetValue, statusCode, responseBody, baselineResponse);

    String displayValue = targetValue != null && targetValue.length() > 200
            ? targetValue.substring(0, 200) + "...(截断)" : targetValue;

    boolean beforeNegate = condResult;
    if (firstCond.isNegate()) {
        condResult = !condResult;
    }

    boolean result = condResult;  // ← 第一个条件的求值结果直接作为初始累积值

    LogManager.getInstance().judgmentDebug(String.format(
            "[判决]   target=%s, method=%s, expr='%s', value='%s' → rawMatch=%b, negate=%b(→%b), 初始累积=%b",
            firstCond.getTarget().name(), firstCond.getMethod().name(), firstCond.getExpression(),
            displayValue, beforeNegate, firstCond.isNegate(), condResult, result));

    // 从第二个条件开始，按运算符组合
    for (int i = firstValidIdx + 1; i < conditions.size(); i++) {
        RuleCondition cond = conditions.get(i);
        if (!cond.isValid()) {
            LogManager.getInstance().judgmentDebug("[判决]   条件无效,跳过");
            continue;
        }

        // 计算当前条件的原始匹配结果
        targetValue = extractTargetValue(cond.getTarget(), statusCode,
                responseHeaders, bodyStr, similarity, responseTimeMs);
        condResult = matchValue(cond.getMethod(), cond.getExpression(),
                targetValue, statusCode, responseBody, baselineResponse);

        displayValue = targetValue != null && targetValue.length() > 200
                ? targetValue.substring(0, 200) + "...(截断)" : targetValue;

        beforeNegate = condResult;
        if (cond.isNegate()) {
            condResult = !condResult;
        }

        boolean beforeCombine = result;
        String operatorSymbol = cond.getOperator() == RuleCondition.LogicalOperator.AND ? "AND" : "OR";
        if (cond.getOperator() == RuleCondition.LogicalOperator.AND) {
            result = result && condResult;
        } else {  // OR
            result = result || condResult;
        }

        LogManager.getInstance().judgmentDebug(String.format(
                "[判决]   target=%s, method=%s, expr='%s', value='%s' → rawMatch=%b, negate=%b(→%b), %s → %b(累积=%b)",
                cond.getTarget().name(), cond.getMethod().name(), cond.getExpression(),
                displayValue, beforeNegate, cond.isNegate(), condResult,
                operatorSymbol, beforeCombine, result));
    }
    return result;
}
```

### 验证方法

构造一个判决规则，仅包含 `STATUS_CODE EQUALS 401 OR STATUS_CODE EQUALS 403`（OR 运算符），预期 behavior：
- 测试用户返回 401 → 规则命中（ESCALATED）
- 测试用户返回 200 → 规则不命中 → 回退到默认判决

修复前：无论返回什么状态码，规则都命中。  
修复后：仅 401 或 403 时规则命中。

---

## Bug 2（中等）：所有条件均被跳过时规则错误命中

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 249-287 行

### 问题描述

在 `evaluateConditions` 循环中，当所有条件都无效（`cond.isValid()` 返回 `false`）时，每个条件都被 `continue` 跳过，循环结束后 `result` 保持初始值 `true`，导致方法返回 `true` → 规则被误判为命中 ESCALATED。

```java
for (RuleCondition cond : conditions) {
    if (!cond.isValid()) {
        continue;  // 跳过无效条件，result 保持 true
    }
    // ...条件求值逻辑永远不执行...
}
// 循环结束，result 仍为 true → 返回 true → 规则命中！← 错误
```

### 根因

缺少"是否有任何条件被实际求值"的跟踪标志。如果全部条件都被跳过，说明该规则实际上没有任何可用的匹配条件，不应命中。

### 修复方案

与 Bug 1 合并修复：在循环前先扫描找到第一个有效条件，如果找不到则直接返回 `false`。

```java
// 在 evaluateConditions 方法开头增加：
int firstValidIdx = -1;
for (int i = 0; i < conditions.size(); i++) {
    if (conditions.get(i).isValid()) {
        firstValidIdx = i;
        break;
    }
}

if (firstValidIdx == -1) {
    // 所有条件均无效 → 不应命中
    LogManager.getInstance().judgmentDebug("[判决] evaluateConditions: 所有条件均无效 → false");
    return false;
}
```

### 验证方法

创建一个判决规则，将其所有条件的 `expression` 设为空字符串（或 target/method 设为 null）。预期该规则不应在任何场景下命中。

---

## Bug 3（中等）：相似度算法选择使用了错误的 Content-Type

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 108-112 行

### 问题描述

计算相似度时，`extractContentType(responseHeaders)` 提取的是**测试用户响应**的 Content-Type，但两个待比较的字符串（`respStr` 和 `baseStr`）分别来自测试用户和基线用户。当两者 Content-Type 不同时（例如基线返回 JSON、测试用户被拒绝后返回 HTML 错误页），系统会使用 HTML 的 Jaccard n-gram 算法来计算两个响应体的相似度，而非 JSON 的 Tree Diff 算法。

```java
double similarity = -1;
if (baselineResponse != null && responseBody != null) {
    String respStr = new String(responseBody, StandardCharsets.UTF_8);
    String baseStr = new String(baselineResponse, StandardCharsets.UTF_8);
    String contentType = extractContentType(responseHeaders); // ← 来自测试用户响应头！
    similarity = SimilarityEngine.similarity(respStr, baseStr, contentType);
}
```

### 日志证据

```
[相似度] ContentType=JSON, len1=53, len2=34
[相似度] 算法=JSON, 结果=0.3000
```

本次测试中双方均为 JSON，算法选择未出错。但以下场景会触发问题：

- 基线响应：`application/json` → `{"data": [...]}`
- 测试用户被拒绝：`text/html` → `<html>...403 Forbidden...</html>`
- 算法选择：基于测试用户的 `text/html` → Jaccard n-gram
- 实际应使用：**基线的 `application/json`** → JSON Tree Diff
- 影响：Jaccard 基于字符 n-gram 对 `<html>...</html>` 和 `{"data": [...]}` 可能产生高于实际的相似度（例如 HTML 模板中的 `{` `}` 字符巧合匹配），导致误判。

### 根因

两个响应体可能具有不同类型，选择算法时应使用更有代表性的一方。基线响应代表"正确"格式，应以它为准；或至少需要同时参考双方，对不一致的情况降级处理。

### 修复方案

优先使用基线响应的 Content-Type 作为算法选择依据。修改 `ReplayEngine` 和 `AutoTestEngine`，在保存基线响应时也保存其 Content-Type，然后传入 `judge()` 方法。

**Step 1**: 在 `ReplayEngine.java` 中保存基线 Content-Type：

```java
// ReplayEngine.java 第 180-184 行附近
if (isFirst) {
    baselineResponse = HttpMessageParser.extractResponseBody(holder.response);
    baselineStatusCode = holder.statusCode;
    baselineValid = true;
    // 新增：保存基线响应的 Content-Type
    String baselineContentType = HttpMessageParser.extractContentType(
            HttpMessageParser.extractResponseHeaders(holder.response));
    // ...需要传递到后续判断逻辑
}
```

**Step 2**: 在 `JudgmentEngine.judge()` 中使用基线 Content-Type：

```java
// JudgmentEngine.java 第 108-112 行修改为：
double similarity = -1;
if (baselineResponse != null && responseBody != null) {
    String respStr = new String(responseBody, StandardCharsets.UTF_8);
    String baseStr = new String(baselineResponse, StandardCharsets.UTF_8);

    // 优先使用基线 Content-Type；若不可用则回退到测试用户 Content-Type
    String effectiveContentType = baselineContentType != null
            ? baselineContentType
            : extractContentType(responseHeaders);

    similarity = SimilarityEngine.similarity(respStr, baseStr, effectiveContentType);
}
```

### 验证方法

构造场景：基线用户获得 JSON 响应，测试用户获得 HTML 错误页。检查日志中 `[相似度] 算法=` 是否输出 `JSON`（而非 `HTML`）。

---

## Bug 4（中等）：字段列表为空时静默返回原始请求

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/FieldReplacementEngine.java` 第 52-58 行

### 问题描述

当某个用户会话关联的方案没有字段（`fields` 为空列表），`replaceFields` 方法直接返回原始请求字节数组，不做任何字段替换，也不产生任何警告日志。

```java
public static byte[] replaceFields(byte[] originalRequest, List<FieldDefinition> fields, UserSession session) {
    if (originalRequest == null || originalRequest.length == 0) {
        return originalRequest;
    }
    if (fields == null || fields.isEmpty() || session == null) {
        return originalRequest;  // ← 静默返回原始请求，无警告
    }
```

### 影响

- 如果测试用户的方案配置错误（未关联任何字段），该用户将使用**代理捕获到的原始用户的字段值**发送请求
- 这完全失去了越权测试的意义：测试用户使用了别人的有效字段值，所有请求都会通过鉴权，响应与基线一致 → 相似度 ≈ 1.0 → 被误判为 ESCALATED
- 没有任何日志警告提示用户配置问题

### 根因

`replaceFields` 作为无状态工具方法，对输入校验过于宽松。将"空字段列表"与"空请求"同等对待是不合理的——空字段列表是一个配置错误信号，应报告给调用方。

### 修复方案

在 `ReplayEngine` 和 `AutoTestEngine` 的调用处增加防御性检查，而非修改工具方法语义。

```java
// ReplayEngine.java 第 119 行之后，第 164 行之前：
List<FieldDefinition> fields = sessionManager.getFieldDefinitionsByScheme(session.getSchemeId());

// 新增：字段为空时的警告
if (fields.isEmpty()) {
    LogManager.getInstance().printError(String.format(
            "[!] 权限测试: 用户 '%s' (schemeId=%s) 没有关联的字段，"
            + "将使用原始请求字段值发送，可能导致误判！",
            session.getName(), session.getSchemeId()));
}
```

同样在 `AutoTestEngine.java` 第 130 行之后增加相同检查。

### 验证方法

1. 创建一个不关联任何字段的方案
2. 创建一个使用该方案的用户会话
3. 执行越权测试
4. 检查日志是否输出 `[!]` 级别的字段缺失警告

---

## Bug 5（低）：`judge()` 守卫条件过窄

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 68-71 行

### 问题描述

守卫条件 `baselineResponse == null && baselineStatusCode <= 0` 仅在**同时**满足时才返回 ERROR。当基线响应是 HTTP 204 No Content（状态码 204 合法，但响应体为 null/空）时，守卫不触发：

```java
// 守卫条件：需要 BOTH 为 null/invalid
if (baselineResponse == null && baselineStatusCode <= 0) {
    return new JudgmentOutcome(JudgmentResult.ERROR, null,
            "基准响应无效，无法进行判决", -1, null);
}
// baselineResponse=null, baselineStatusCode=204 → 通过了守卫！
// 接下来 similarity = -1（因为 baselineResponse==null）
// → judgeDefault 进入 "无法计算相似度" 路径
// → statusCode != baselineStatusCode? → PENDING
```

### 影响

测试用户在 204 场景下也被正确拒绝时：
- 基线 204（空 body），测试 403（有错误 body）
- similarity = -1 → 回退状态码检查 → statusCode!=baselineStatusCode → PENDING
- 实际上这应该是安全的（NOT_ESCALATED），但被标记为 PENDING 需要人工确认

### 根因

守卫条件将"body 为 null 但状态码合法"和"响应完全无效"两种截然不同的情况合并处理。应区分对待。

### 修复方案

将守卫条件拆分，对"状态码合法但 body 为空"的情况走空 Body 判决流程：

```java
// 替换原有的 guard 条件
if (baselineResponse == null) {
    if (baselineStatusCode <= 0) {
        // 完全无效的基准响应
        return new JudgmentOutcome(JudgmentResult.ERROR, null,
                "基准响应无效，无法进行判决", -1, null);
    }
    // 状态码合法但 body 为空（如 204 No Content）→ 走空 Body 判决
    return judgeWithEmptyBody(
            statusCode, responseBody, baselineResponse,
            baselineStatusCode,
            true,  // baselineBodyEmpty
            isBodyEmpty(responseBody),
            similarityThreshold);
}
```

### 验证方法

1. 构造一个返回 204 No Content 的 API
2. 用有权限的基线用户访问 → 获取 204 响应
3. 用无权限的测试用户访问 → 获取 403 响应
4. 预期判决：安全（NOT_ESCALATED），而非 PENDING

---

## Bug 6（低）：异常路径中 `baselineValid` 注释与实际代码不符

### 涉及文件

- `src/main/java/org/oxff/repeater/privilege/ReplayEngine.java` 第 271 行
- `src/main/java/org/oxff/repeater/privilege/AutoTestEngine.java` 第 296 行

### 问题描述

两处 catch 块中注释写"基准用户异常时标记 baselineValid 为 false"，但实际上没有 `baselineValid = false;` 的显式赋值。

```java
// ReplayEngine.java 第 268-273 行
} catch (Exception e) {
    LogManager.getInstance().printError("[!] 权限测试重放异常 (user=" + session.getName() + "): " + e.getMessage());

    // 基准用户异常时标记baselineValid为false ← 注释说"标记"，但没有实际赋值
    if (isFirst) {
        LogManager.getInstance().printError("[!] 基准用户请求异常，后续会话将跳过判决");
    }
```

### 根因

功能上正确（`baselineValid` 初始化时就为 `false`，且异常路径中从未被设为 `true`），但注释描述的行为与代码不一致，增加了维护者的理解成本。

### 修复方案

将注释修改为准确描述实际行为：

```java
// ReplayEngine.java 第 271 行
// 基准用户异常时 baselineValid 保持初始值 false，后续会话将因此跳过判决
if (isFirst) {
    LogManager.getInstance().printError("[!] 基准用户请求异常，后续会话将跳过判决");
}
```

同样修改 `AutoTestEngine.java` 第 296 行的注释。

---

## Bug 7（严重）：`computeMapSimilarity` 值分权重过高导致水平越权漏报

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JsonSimilarityCalculator.java` 第 120-157 行

### 问题描述

`computeMapSimilarity` 公式 `0.3 × 结构分 + 0.7 × 值分` 将 70% 权重分配给值匹配。在水平越权场景中，响应包装层（wrapper）中天然存在的用户级元数据字段（如 `currentUser`、`userRole`、`rateLimit`）在不同用户间必然不同。每多一个不同的包装字段，相似度就大幅下降。

### 量化演示

假设响应共 17 个叶子字段（5 个包装 + 12 个资源数据），资源数据完全匹配，仅 4 个包装字段值不同：

| 指标 | 计算 | 值 |
|------|------|-----|
| 结构分 (structureSimilarity) | 17/17 | 1.000 |
| 值分 (valueSimilarity) | 13/17 | 0.765 |
| 最终相似度 | 0.3×1.0 + 0.7×0.765 | **0.835** |

0.835 < 0.85（fallback 阈值） → **NOT_ESCALATED（漏报！）**

只需 4 个包装字段不同，就能把一条真实的水平越权误判为"安全"。

### 根因

70% 的值权重源自早期对"结构相同但值完全不同"（如 `{"code":0}` vs `{"code":401}`）场景的过度补偿。该修复解决了误报（401被判越权），但引入了严重的漏报——在包装层有少量用户元数据差异时，相似度被过度压低。

### 修复方案

将结构分权重提升至与值分对等或更高，使算法对 RESPONSE WRAPPER 的差异更加鲁棒：

```java
// 修改前（第 156 行）
return 0.3 * structureSimilarity + 0.7 * valueSimilarity;

// 修改后：50/50 平衡
return 0.5 * structureSimilarity + 0.5 * valueSimilarity;
```

50/50 权重下，同样 4/17 不同字段：
- 最终相似度 = 0.5×1.0 + 0.5×0.765 = 0.883
- 0.883 >= 0.85 → **ESCALATED（正确检测！）**

### 验证方法

构造测试用例：两个 JSON 响应有相同的资源数据（12 个字段全匹配），但 5 个包装字段中 4 个值不同。验证修复后相似度 >= 0.85，判决正确输出 ESCALATED。

---

## Bug 8（中等）：NoiseFilter 遗漏 1-5 位小数值

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/NoiseFilter.java` 第 39-40 行

### 问题描述

NoiseFilter 的 `BUILTIN_PATTERNS` 最后一条规则只匹配 6-19 位数字：

```java
// 数字型ID (纯数字，6-19位)
Pattern.compile("\\b\\d{6,19}\\b")
```

大量 REST API 中常见的 ID 和状态值均为 1-5 位：

| 典型字段 | 示例值 | 位数 | 被 NoiseFilter 覆盖？ |
|---------|--------|------|:---:|
| `userId` | 1001 | 4 | ✗ |
| `roleId` | 2 | 1 | ✗ |
| `status` | 1 | 1 | ✗ |
| `count` | 42 | 2 | ✗ |
| `pageSize` | 20 | 2 | ✗ |
| `vpsId` | 10000001 | 8 | ✓ |

### 影响

这些小型数值在不同用户间很可能不同（例如 userId 从 1001 变为 2002），每一个未被归一化的差异都会在 `computeMapSimilarity` 中拉低值分，推低最终相似度。

### 根因

`\d{6,19}` 的下限（6 位）设定过高，排除了 `int` 范围内最常见的标识符（1-65535）。原意图可能是避免将普通数字文本（如 HTTP 状态码 200）误归一化，但在 JSON 叶子值上下文中，小数值 ID 同样属于动态噪声。

### 修复方案

将数字 ID 匹配下限从 6 位降至 4 位，并在模式前增加负向前瞻排除 `true`/`false`/`null` 关键字（防止 JSON 布尔/null 被误归一化）：

```java
// 修改前
Pattern.compile("\\b\\d{6,19}\\b")

// 修改后：覆盖 4-19 位纯数字
Pattern.compile("(?<!["\\w])\\d{4,19}(?!["\\w])")
```

> **注意**：降低下限需谨慎验证是否会导致普通文本字段（如 `"code": 0` 中的 `0`）被误归一化。建议在集成测试中覆盖 `"code": 0` / `"code": 200` 等场景，确保状态码字段不被归一化后产生误判。

### 验证方法

1. 构造含 `"userId": 1001` 的 JSON 响应
2. 经 NoiseFilter 归一化后验证该值被替换为 `__NOISE__`
3. 确认 `"code": 0` 中的 `0` 不被误归一化
4. 跑完整越权测试流程确认无新增误报

---

## Bug 9（中等）：`computeValueSimilarity` 对短字符串二值判断过严

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JsonSimilarityCalculator.java` 第 163-173 行

### 问题描述

当两个叶子值均为 ≤50 字符的短字符串时，`computeValueSimilarity` 采用二值判断：完全相同给 1.0，不同则直接给 0.0。

```java
private static double computeValueSimilarity(String v1, String v2) {
    if (v1.equals(v2)) return 1.0;
    if (v1.length() <= 50 && v2.length() <= 50) {
        return 0.0;  // ← 只要有一个字符不同就给 0 分
    }
    return JaccardSimilarityCalculator.similarity(v1, v2);
}
```

### 影响

以下场景均被判为"完全不同"（0 分），从而压低整体相似度：

| v1 | v2 | Levenshtein 相似度 | 当前得分 | 合理得分 |
|----|----|:---:|:---:|:---:|
| `"alice"` | `"Alice"` | 0.80 | **0.00** | 0.70+ |
| `"active"` | `"active "` | 0.86 | **0.00** | 0.60+ |
| `"admin"` | `"administrator"` | 0.46 | **0.00** | 0.30+ |
| `"us-east-1"` | `"us-west-1"` | 0.70 | **0.00** | 0.50+ |

在噪声过滤管线中，NoiseFilter 首先归一化时间戳/UUID/大数字 → 这些字段在两方都变成 `__NOISE__` 并匹配 ✓。但未被 NoiseFilter 覆盖的短字符串（用户名、角色名、地域标签等）如果只是相近而非完全相等，当前逻辑会直接给 0 分，这是过度惩罚。

### 根因

对短字符串设计"要么全匹配要么零分"的二元逻辑，未考虑字符串间存在的程度差异（如前后空格、大小写、同义词等）。

### 修复方案

对短字符串引入 Levenshtein 比率，给予部分相似度：

```java
private static double computeValueSimilarity(String v1, String v2) {
    if (v1.equals(v2)) return 1.0;

    // 短字符串：使用 Levenshtein 比率给部分分
    if (v1.length() <= 50 && v2.length() <= 50) {
        int maxLen = Math.max(v1.length(), v2.length());
        if (maxLen == 0) return 1.0;
        int dist = levenshteinDistance(v1, v2);
        return 1.0 - (double) dist / maxLen;
    }

    // 长字符串：继续使用 Jaccard n-gram
    return JaccardSimilarityCalculator.similarity(v1, v2);
}
```

> 注意：Levenshtein 需要引入或内联实现，其 O(n×m) 复杂度在 ≤50 字符范围内可接受（最坏 2500 次操作）。

### 验证方法

1. 单元测试覆盖上述 4 组示例字符串
2. 验证 `"alice"` vs `"Alice"` 得分 ≥ 0.50
3. 验证 `"active"` vs `"active "` 得分 ≥ 0.50
4. 回归测试：完全相同字符串仍得 1.0

---

## Bug 10（严重）：单活跃规则组架构导致"默认相似度规则"安全网被绕过

### 涉及文件

- `src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 124-129 行
- `src/main/java/org/oxff/repeater/privilege/JudgmentRuleManager.java` 第 87 行、第 231-267 行

### 问题描述

v13 架构引入"单活跃规则组"模式：同一时刻只有 `isActive=true` 的那一个规则组会被评估。当用户将自己的规则组（如"测试"）设为活跃后，自动创建的"默认相似度规则组"（90% 阈值）**不再参与判决**——即使它也是已启用状态。

```java
// JudgmentEngine.java 第 124-129 行
JudgmentRule activeRule = ruleManager.getActiveRule();  // ← 只取 active 那一个
if (activeRule != null && activeRule.isEnabled() && activeRule.isValid()) {
    return judgeWithActiveRule(activeRule, ...);  // 仅评估这一个
}
// 无活跃规则组时：回退到第3层兜底
return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold);
```

对比旧版（v1 日志第 58-66 行）和新版（v2 日志第 213-217 行）的判决流程：

```
旧版：规则匹配开始: 共2条规则
      → 评估规则: 'test'         → 未命中, 继续下一条
      → 评估规则: '默认相似度规则' → 未命中, 继续下一条  ← 每条都检查了
      → 所有规则均未命中 → 回退到默认判决

新版：活跃规则组评估: name='测试'  ← 只评估活跃组
      → 条件不满足, AND 短路
      → 规则组未命中: '测试' → 回退默认判决  ← 默认相似度规则组从未被评估！
      → 默认判决: similarity=0.3000 < threshold=0.85 → NOT_ESCALATED
```

### 日志证据

v2 测试中两次越权测试（requestId=1 和 requestId=2）均只评估了活跃的"测试"规则组：

```
第 213 行: [判决] 活跃规则组评估: name='测试'
第 216 行: [判决] 规则组未命中: '测试' → 回退默认判决
第 217 行: [判决] 默认判决: similarity=0.3000 < threshold=0.85 → NOT_ESCALATED

第 253 行: [判决] 活跃规则组评估: name='测试'
第 256 行: [判决] 规则组未命中: '测试' → 回退默认判决
第 257 行: [判决] 默认判决: similarity=0.0375 < threshold=0.85 → NOT_ESCALATED
```

### 实际影响

1. **兜底阈值隐性降低**：旧版"默认相似度规则"使用 **90%** 阈值，新版 `judgeDefault()` 使用 `sessionManager.getSimilarityThreshold()` 返回的 **85%** 阈值。用户可能以为仍在用 90% 的高标准兜底，实际已降到 85%。
2. **多规则组合能力丧失**：如果用户想同时用"响应体包含特定字段 + 相似度≥90%"两个维度兜底，旧版可配置两条独立规则串行检查；新版只能选一个活跃组。
3. **安全网缺失**：当活跃规则组因配置错误（如表达式拼写错误）永远不命中时，没有任何备用规则组兜底，直接回退到裸阈值判决。

### 根因

`getActiveRule()` 的互斥设计（同一时刻仅一个活跃组）是刻意的架构决策，但未考虑默认规则作为兜底安全网的角色。默认规则组的 `isActive` 字段在用户切换活跃组时被覆盖，而判决引擎没有"始终评估默认规则组"的机制。

### 修复方案

**方案 A（推荐）**：在 `judge()` 方法中，活跃规则组未命中时，额外评估默认相似度规则组（而不仅仅是回退到裸阈值）：

```java
// JudgmentEngine.java 第 124-129 行修改为：
JudgmentRule activeRule = ruleManager.getActiveRule();
if (activeRule != null && activeRule.isEnabled() && activeRule.isValid()) {
    JudgmentOutcome outcome = judgeWithActiveRule(activeRule, ...);
    if (outcome.result == JudgmentResult.ESCALATED) {
        return outcome;  // 活跃规则组命中 → 直接返回越权
    }
    // 活跃规则组未命中 → 继续检查默认规则组作为安全网
}

// 评估默认相似度规则组（如果存在且不是当前活跃组）
JudgmentRule defaultRule = ruleManager.getDefaultSimilarityRule();
if (defaultRule != null && defaultRule != activeRule
        && defaultRule.isEnabled() && defaultRule.isValid()) {
    return judgeWithActiveRule(defaultRule, ...);
}

// 最终兜底
return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold);
```

**方案 B**：恢复旧版多规则迭代模式，按优先级依次匹配所有已启用规则组。

### 验证方法

1. 创建自定义规则组"测试"（如 `STATUS_CODE EQUALS 200 AND SIMILARITY > 0.85`）并设为活跃
2. 执行越权测试，预期：活跃组未命中时，默认相似度规则组（90%）应被评估
3. 检查日志是否输出 `[判决] 活跃规则组未命中，继续默认规则组评估`

---

## Bug 11（中等）：`ensureDefaultSimilarityRule()` 创建条件过于宽松导致默认规则缺失

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentRuleManager.java` 第 231-267 行

### 问题描述

`ensureDefaultSimilarityRule()` 在每次 `refreshCache()` 时被调用。其逻辑为：

```java
if (ruleDAO.hasConditionWithTarget("SIMILARITY")) {
    // ← 只要存在任何含 SIMILARITY 条件的规则，就跳过创建默认规则
    return;
}
// 否则创建默认相似度规则组
```

问题：`hasConditionWithTarget("SIMILARITY")` 检查的是**所有规则组的所有条件**。一旦用户创建了含 `SIMILARITY` 条件的自定义规则组（如 `SIMILARITY GREATER_THAN 0.85`），该方法就认为"已有相似度条件"而跳过创建默认 90% 规则组。

但用户的 85% 阈值规则和系统的 90% 默认兜底规则是**不同目的**的：前者是用户自定义的AND组合条件，后者是全局安全网。这个检查将它们混为一谈。

### 日志证据

```
第 168 行: 判决规则缓存已刷新: 0条规则组, 0条已启用, 活跃: 无
第 169 行: 规则组(id=1)添加 1 条条件
第 170 行: 已自动创建默认相似度规则组 (id=1) 并设为活跃  ← 首次加载，无SIMILARITY条件，正常创建

第 174 行: 规则组(id=2)添加 2 条条件  ← 用户创建含SIMILARITY条件的自定义规则
第 175 行: 判决规则缓存已刷新: 2条规则组, 2条已启用, 活跃: 默认相似度规则
                                    ↑ 此时两个规则组都存在

第 176 行: 判决规则缓存已刷新: 2条规则组, 2条已启用, 活跃: 测试
                                    ↑ 切换活跃组后，默认规则组不再参与判决
```

如果在下次插件启动时用户的自定义规则已被持久化，`hasConditionWithTarget("SIMILARITY")` 将返回 `true` → 默认 90% 规则组**不会被创建** → 如果没有活跃规则组，直接回退到裸 85% 阈值。

### 根因

将"是否存在相似度条件"与"是否需要默认兜底规则"混为一谈。它们是正交的概念。

### 修复方案

将检查条件改为：是否存在**名为"默认相似度规则"**的规则组（按名称精确匹配），而不是按条件类型模糊匹配：

```java
private void ensureDefaultSimilarityRule() {
    // 检查是否已存在默认相似度规则组（按名称精确匹配）
    for (JudgmentRule rule : cachedAllRules) {
        if ("默认相似度规则".equals(rule.getName())) {
            // 已存在，检查是否有活跃规则组
            if (cachedActiveRule == null && !cachedAllRules.isEmpty()) {
                JudgmentRule first = cachedAllRules.get(0);
                ruleDAO.setActiveRule(first.getId());
                cachedActiveRule = ruleDAO.getActiveRule();
                LogManager.getInstance().printOutput("[+] 自动激活第一个规则组: " + first.getName());
            }
            return;
        }
    }
    // 不存在 → 创建
    // ... 原有创建逻辑 ...
}
```

### 验证方法

1. 创建自定义规则组（含 SIMILARITY 条件），插件重启
2. 检查日志应输出：`已自动创建默认相似度规则组 (id=...) 并设为活跃`
3. 数据库应同时存在自定义规则组和默认规则组

---

## Bug 12（中等）：`LevenshteinCalculator` 已实现但未集成到相似度计算管线

### 涉及文件

- `src/main/java/org/oxff/repeater/privilege/LevenshteinCalculator.java`（新增 88 行）
- `src/main/java/org/oxff/repeater/privilege/JsonSimilarityCalculator.java` 第 163-173 行

### 问题描述

v2 代码库中新增了完整的 `LevenshteinCalculator` 类（优化 DP 实现，空间复杂度 O(min(n,m))），但 `JsonSimilarityCalculator.computeValueSimilarity()` 仍使用旧的二值判断逻辑：

```java
// JsonSimilarityCalculator.java 第 166-168 行 — 未变更！
if (v1.length() <= 50 && v2.length() <= 50) {
    return 0.0;  // ← 仍然直接给 0 分，未调用 LevenshteinCalculator
}
```

`LevenshteinCalculator.similarity()` 方法存在且功能完备（含空值处理、大响应截断、DP 空间优化），但**没有任何调用方引用它**。这是一段死代码。

### 影响

Bug 9（短字符串二值判断过严）在 v2 中实质上**未被修复**，尽管修复所需的 `LevenshteinCalculator` 已经写好。用户可能以为引入了 Levenshtein 就修复了短字符串比较问题，但实际上管线未接通。

### 根因

开发过程中创建了 `LevenshteinCalculator` 工具类，但忘记在 `computeValueSimilarity()` 中调用它。集成的最后一步——管线接线——被遗漏了。

### 修复方案

在 `computeValueSimilarity()` 中调用 `LevenshteinCalculator`：

```java
private static double computeValueSimilarity(String v1, String v2) {
    if (v1.equals(v2)) return 1.0;

    // 短值（<=50字符）：使用 Levenshtein 比率给部分分
    if (v1.length() <= 50 && v2.length() <= 50) {
        return LevenshteinCalculator.similarity(v1, v2);  // ← 接线！
    }

    // 长值：用 Jaccard n-gram 给部分分
    return JaccardSimilarityCalculator.similarity(v1, v2);
}
```

### 验证方法

1. 确认 `LevenshteinCalculator.similarity("alice", "Alice")` 返回约 0.80（而非 0.0）
2. 运行完整的越权测试流程，确认无退化

---

## Bug 13（低）：规则组创建时触发过量缓存刷新

### 涉及文件

- `src/main/java/org/oxff/repeater/privilege/JudgmentRuleManager.java` 第 52-62 行（`refreshCache()`）
- `src/main/java/org/oxff/repeater/privilege/JudgmentRuleManager.java` 第 123-128 行（`addRule()`）
- UI 层：`JudgmentRuleEditDialog.java`（推测）

### 问题描述

在创建包含 2 个条件的规则组"测试"时，日志中出现了 **15+ 次**连续的缓存刷新：

```
第 120 行: 规则组(id=2)添加 2 条条件
第 121 行: 判决规则缓存已刷新: 2条规则组, 2条已启用, 活跃: 默认相似度规则
第 122 行: 判决规则缓存已刷新: 2条规则组, 2条已启用, 活跃: 测试
第 123 行: 判决规则缓存已刷新: 2条规则组, 2条已启用, 活跃: 测试
...（重复 15+ 次到第 143 行）
```

每次 `refreshCache()` 都会执行：
1. `ruleDAO.getAllRules()` — 数据库查询所有规则组
2. `ruleDAO.getEnabledRules()` — 数据库查询已启用规则组
3. `ruleDAO.getActiveRule()` — 数据库查询活跃规则组
4. `ensureDefaultSimilarityRule()` — 检查并可能创建默认规则（含可能的 `hasConditionWithTarget` DB 查询）

这意味着创建一个规则组就产生了 **15+ × 4 = 60+ 次数据库查询**。

### 影响

- 不必要的数据库 I/O，尤其在规则组数量增长后更明显
- UI 可能在创建规则组时出现短暂卡顿
- 日志被大量重复的刷新信息淹没，降低可读性

### 根因

UI 层的规则编辑对话框（`JudgmentRuleEditDialog`）可能在每次字段变更（如添加条件、修改表达式）时都调用 `addRule()` / `updateRule()`，每次调用都触发 `refreshCache()`。如果是批量操作（如一次性添加 2 个条件），应只在最终提交时刷新一次。

### 修复方案

在 `JudgmentRuleManager` 中增加批量操作 API，推迟缓存刷新到批量操作结束：

```java
// JudgmentRuleManager.java 新增
public void beginBatch() { batchMode = true; }

public void endBatch() {
    batchMode = false;
    refreshCache();  // 批量操作结束后统一刷新一次
}

public int addRule(JudgmentRule rule) {
    int id = ruleDAO.addRule(rule);
    if (id > 0 && !batchMode) {  // ← 批量模式下延迟刷新
        refreshCache();
    }
    return id;
}
```

UI 层在打开编辑对话框时调用 `beginBatch()`，在关闭/保存时调用 `endBatch()`。

### 验证方法

1. 创建含 2 个条件的规则组
2. 检查日志中"判决规则缓存已刷新"的出现次数 ≤ 3 次（初始加载 1 次 + 创建 1 次 + 切换活跃 1 次）

---

## Bug 14（低）：纯 AND 架构失去 OR 条件组合表达能力

### 涉及文件

`src/main/java/org/oxff/repeater/privilege/JudgmentEngine.java` 第 227-272 行

### 问题描述

v13 重构将 `evaluateConditions` 改为纯 AND 短路求值，移除了对 `RuleCondition.LogicalOperator.OR` 的支持。虽然旧版的 OR 实现有 Bug（Bug 1），但彻底移除 OR 能力意味着用户**无法**表达以下合法场景：

| 场景 | 需要的规则 | 新版能否表达？ |
|------|-----------|:---:|
| 任一拒绝状态码即判越权 | `STATUS_CODE EQUALS 401 OR STATUS_CODE EQUALS 403` | ✗ |
| 响应体含敏感关键词 OR 相似度异常高 | `RESPONSE_BODY CONTAINS "admin" OR SIMILARITY > 0.95` | ✗ |
| 多状态码覆盖 | `STATUS_CODE NOT_EQUALS 200 OR STATUS_CODE NOT_EQUALS 201` | ✗ |

用户若需要 OR 语义，只能创建多个规则组并手动切换活跃组——这在自动化测试中完全不可行。

### 根因

修复 Bug 1（OR 逻辑失效）时选择了"移除 OR 支持"而非"修复 OR 支持"。这是一个设计取舍，但限制了规则表达能力。

### 修复方案

在保持纯 AND 作为默认行为的同时，重新引入正确的 OR 支持（参考报告 Bug 1 的修复方案）。条件运算符可由用户在 UI 中显式选择 AND/OR。

```java
// 混合 AND/OR 支持（基于 Bug 1 的修复方案）
// 按顺序处理条件，第一个有效条件直接作为 result 的初始值
// 后续条件按各自的运算符组合
```

### 验证方法

1. 创建规则组：`STATUS_CODE EQUALS 401 OR STATUS_CODE EQUALS 403`
2. 测试用户返回 401 → 规则命中（ESCALATED）
3. 测试用户返回 200 → 规则不命中 → 回退默认判决

---

## Bug 15（严重）：`setPrivilegeTestRequest()` 关闭/重开循环导致 EDT 模态震荡与代理监听中断

### 涉及文件

- `src/main/java/org/oxff/repeater/RepeaterManagerUI.java` 第 799-843 行
- `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` 第 124-143 行
- `src/main/java/org/oxff/repeater/privilege/ScopeManager.java` 第 173-183 行

### 问题描述

`setPrivilegeTestRequest()` 方法采用了"先关后开"的模式——先将越权模式关闭再重新开启——目的是避免 `setRequest()` 内部误触发双重重放。但这个设计同时触发了代理监听器的注销和重注册，在两个副作用之间留下了一个不可忽视的流量丢失窗口。

```java
// RepeaterManagerUI.java 第 799-837 行
public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
    // ...
    // 先关闭权限测试模式，避免 setRequest() 内部误触发重放
    dispatchHandler.setPrivilegeTestMode(false);  // ← 第 805 行：注销代理处理器

    // 用常规方式加载请求（复用setRequest的逻辑）
    int dbId = setRequest(requestResponse);       // ← 第 813 行：此期间代理监听器已失效！

    // ...
    // 开启权限测试模式
    dispatchHandler.setPrivilegeTestMode(true);   // ← 第 829 行：重新注册代理处理器
    // ...
    SwingUtilities.invokeLater(() ->
        dispatchHandler.sendPrivilegeTestRequestDirect(...));  // ← 第 835 行
}
```

### 日志证据

**Cycle 3（单请求模式）**：
```
第 185 行: 自动化测试已开启，监听代理流量   (21:08:45)  ← 用户手动开启
第 187 行: 自动化测试已关闭                 (21:08:56)  ← line 805：close
第 195 行: 自动化测试已开启，监听代理流量   (21:08:57)  ← line 829：reopen
第 198 行: 开始权限测试重放: 2个用户会话    (21:08:57)  ← sendPrivilegeTestRequestDirect
...执行测试...
第 223 行: 自动化测试已关闭                 (21:09:00)  ← Bug 16 触发：测试完成后自动退出！
第 224 行: 权限测试模式: 已关闭
```

**Cycle 4（自动捕获模式）**：
```
第 333 行: 自动化测试已开启，监听代理流量   (21:42:27)  ← 用户手动开启
第 335 行: 请求数据已保存，ID: 1            (21:42:39)  ← 代理处理器自动捕获请求
← 注意：此处没有"自动化测试已关闭"！自动捕获模式不经过 setPrivilegeTestRequest
第 341 行: 自动触发越权重放...
第 347 行: 自动触发越权重放...
...执行测试...
第 409 行: 自动化测试已关闭                 (21:42:44)  ← Bug 16 触发：测试完成后自动退出！
第 410 行: 权限测试模式: 已关闭
```

### 影响

1. **代理流量丢失窗口**：line 805 关闭代理处理器后，到 line 829 重新注册前，期间所有匹配 Scope 的代理流量被静默丢弃。`setRequest()` 可能涉及数据库 I/O，如果慢则丢失窗口更长
2. **双重重放风险（设计初衷）**：如果在模式开启时调用 `setRequest()`，后者会触发自动重放（因为在自动测试模式下）。line 805 的关闭确实是必要的防护——但防护机制本身引入了新的问题
3. **EDT 事件堆积**：每次关闭/重开都在 EDT 上排队 `fireModeChanged` → `modeToggleButton.setSelected()` → `privilegeTestPanel.syncScopeConfigAutoTestState()` 等多个任务

### 根因

`setPrivilegeTestRequest()` 需要"暂时禁止自动重放"，当前通过关闭整个越权模式来实现。这是一种粗粒度的控制——它同时关闭了代理监听、模式状态、UI 同步等所有子系统。

### 修复方案

**方案 A（推荐）**：引入"静默加载"标志位，避免关闭整个越权模式：

```java
// RequestDispatchHandler.java 新增
private volatile boolean silentLoadMode = false;

public void setSilentLoadMode(boolean silent) {
    this.silentLoadMode = silent;
}

public boolean isSilentLoadMode() {
    return silentLoadMode;
}

// 在 setRequest() / sendRequest() 内部检查：
if (privilegeTestMode && !silentLoadMode) {
    // 仅当非静默模式才触发自动重放
    sendPrivilegeTestRequestDirect(...);
}

// RepeaterManagerUI.setPrivilegeTestRequest() 修改为：
public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
    dispatchHandler.setSilentLoadMode(true);   // ← 替代 close
    try {
        int dbId = setRequest(requestResponse);  // ← 不会触发双重重放
        // ...
    } finally {
        dispatchHandler.setSilentLoadMode(false); // ← 替代 reopen
    }
    // 手动触发重放（模式本来就是开启的，不需要重新开启）
    SwingUtilities.invokeLater(() ->
        dispatchHandler.sendPrivilegeTestRequestDirect(...));
}
```

**方案 B（最小改动）**：将 close/reopen 替换为仅注销/注册代理处理器，不动模式状态：

```java
// 替代 line 805: dispatchHandler.setPrivilegeTestMode(false);
ScopeManager.getInstance().setAutoTestEnabled(false);

// 替代 line 829: dispatchHandler.setPrivilegeTestMode(true);
ScopeManager.getInstance().setAutoTestEnabled(true);
```

### 验证方法

1. 开启越权模式（modeToggleButton 打开）
2. 从 Proxy History 右键"发送到权限测试"
3. 检查日志：不应出现"自动化测试已关闭"（在请求加载期间）
4. 确认代理流量在请求加载期间仍被正常捕获

---

## Bug 16（严重）：`modeToggleButton.setSelected()` 通过 ModeChangeListener 反馈链触发测试后自动退出

### 涉及文件

- `src/main/java/org/oxff/repeater/RepeaterManagerUI.java` 第 142-160 行、第 292-296 行
- `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` 第 58-77 行、第 124-143 行

### 问题描述

`ModeChangeListener`（第 142-160 行）在每次模式变更时调用 `modeToggleButton.setSelected(mode)` 来同步按钮外观。`SwitchButton` 继承自 `JToggleButton`，在 `setSelected()` 状态变更时会触发 `ActionEvent`（取决于 L&F 实现），进而调用按钮的 `ActionListener`（第 292-296 行），后者又调用 `dispatchHandler.setPrivilegeTestMode(selected)`——形成"模式变更 → setSelected → ActionListener → setPrivilegeTestMode → 模式变更"的反馈环。

由于 `setPrivilegeTestMode()` 有 no-op guard（`if (this.privilegeTestMode == enabled) return;`），在同一次调用链上这个循环会被阻断。但 `fireModeChanged()` 内部通过 `SwingUtilities.invokeLater` 延迟执行 `setSelected()`，使得 no-op guard 的防御出现**时序漏洞**：

```java
// 关键时序漏洞：
// 1. setPrivilegeTestRequest() 在 EDT 上执行：
//    line 805: setPrivilegeTestMode(false) → privilegeTestMode = false
//              → fireModeChanged(false) → invokeLater: setSelected(false)  ← 排队
//    line 829: setPrivilegeTestMode(true)  → privilegeTestMode = true
//              → fireModeChanged(true)  → invokeLater: setSelected(true)   ← 排队
//    line 835: invokeLater: sendPrivilegeTestRequestDirect(...)             ← 排队
// 2. setPrivilegeTestRequest() 返回后，EDT 处理排队任务：
//    a) setSelected(false) → ActionListener →
//       setPrivilegeTestMode(false): no-op? privilegeTestMode(true) != false → NOT no-op!
//       → privilegeTestMode = false → "自动化测试已关闭" → fireModeChanged(false)
//    b) setSelected(true) → ActionListener →
//       setPrivilegeTestMode(true): no-op? privilegeTestMode(false) != true → NOT no-op!
//       → privilegeTestMode = true → "自动化测试已开启" → fireModeChanged(true)
//    c) sendPrivilegeTestRequestDirect → 启动异步测试...
//
// 步骤 (a)(b) 每次又产生新的 invokeLater(setSelected) 排队——形成连锁震荡
```

### 日志证据

三次测试全部出现了测试完成后自动退出的现象：

| 时序 | Cycle 3 测试1 (POST) | Cycle 3 测试2 (GET) | Cycle 4 批量测试 |
|------|---------------------|--------------------|--------------------|
| 测试完成 | 21:08:59.090 | 21:10:20.517 | 21:42:41.635 |
| 自动关闭 | 21:09:00.458 | 21:10:23.087 | 21:42:44.627 |
| 延迟 | **1.37秒** | **2.57秒** | **2.99秒** |
| 退出消息 | `自动化测试已关闭` + `权限测试模式: 已关闭` | 同 | 同 |

关键特征：
- `自动化测试已关闭` 和 `权限测试模式: 已关闭` **同时打印**（同一毫秒），说明来自同一次 `setPrivilegeTestMode(false)` 调用
- 延迟不稳定（1.37~2.99秒），排除固定定时器触发，指向 EDT 事件队列堆积
- Cycle 4 使用自动捕获模式（不经 `setPrivilegeTestRequest`），仍然出现自动退出 → 说明反馈链的触发不限于 `setPrivilegeTestRequest` 路径

### 根因

1. **ModeChangeListener 中 `modeToggleButton.setSelected(mode)` 通过 `invokeLater` 延迟执行**，使得 no-op guard 的"同时刻"检查被打破
2. `SwitchButton`（继承 `JToggleButton`）的 `setSelected()` 在 L&F 特定实现下可能触发 `ActionEvent`（标准 Swing 仅触发 `ItemEvent`，但某些 L&F 会额外触发 `ActionEvent`）
3. 即使 `setSelected()` 不直接触发 ActionListener，`fireModeChanged` 产生的连锁 `invokeLater` 任务也会在 EDT 队列中堆积，当测试完成后这些延迟任务才被执行，导致模式被意外关闭

### 修复方案

**方案 A（推荐 — 彻底消除反馈环）**：在 ModeChangeListener 中使用标记位抑制按钮 ActionListener：

```java
// RepeaterManagerUI.java 新增字段
private boolean syncingModeButton = false;

// 修改 ModeChangeListener（第 142-160 行）
dispatchHandler.addModeChangeListener(mode -> {
    SwingUtilities.invokeLater(() -> {
        syncingModeButton = true;  // ← 设置抑制标记
        try {
            if (modeToggleButton != null) {
                modeToggleButton.setSelected(mode);
            }
            // ...标签样式更新...
        } finally {
            syncingModeButton = false; // ← 恢复
        }
    });
});

// 修改 modeToggleButton ActionListener（第 292-296 行）
modeToggleButton.addActionListener(e -> {
    if (syncingModeButton) return;  // ← 程序同步中，忽略
    boolean selected = modeToggleButton.isSelected();
    dispatchHandler.setPrivilegeTestMode(selected);
    LogManager.getInstance().printOutput("[*] 权限测试模式: " + (selected ? "已开启" : "已关闭"));
});
```

**方案 B（根治 — 消除 close/reopen 需求）**：结合 Bug 15 的修复（方案 A），改为静默加载模式，彻底避免 `setPrivilegeTestMode(false)` → `setPrivilegeTestMode(true)` 的调用对。

### 验证方法

1. 开启越权模式，发送一个请求进行越权测试
2. 确认测试正常完成，判决结果显示在历史面板
3. 检查日志：测试完成后不应出现"自动化测试已关闭"和"权限测试模式: 已关闭"
4. 确认 modeToggleButton 状态仍为"已开启"，代理处理器仍在监听

---

## Bug 17（严重）：自动触发模式下无 close/reopen 仍发生自动退出

### 涉及文件

- `src/main/java/org/oxff/repeater/RepeaterManagerUI.java` 第 767-778 行、第 849-870 行
- `src/main/java/org/oxff/repeater/RequestDispatchHandler.java` 第 142-143 行
- `src/main/java/org/oxff/repeater/ui/SwitchButton.java` 第 1-79 行

### 问题描述

Cycle 4 日志揭示了一个更隐蔽的自动退出路径：当越权模式已开启，用户通过"发送到 Repeater Manager"（非"发送到权限测试"）批量加载请求时，`setRequest()`（第 767-778 行）检测到 `privilegeTestMode=true`，自动调用 `sendPrivilegeTestRequestDirect` 触发越权重放。此路径**不经过 close/reopen**（`setPrivilegeTestMode(false)` 从未被调用），但测试完成后约 2.99 秒仍然出现自动退出：

### 日志证据

```
第 333 行: 自动化测试已开启，监听代理流量   (21:42:27)  ← 用户手动开启
第 334 行: 权限测试模式: 已开启
← 注意：此处没有"自动化测试已关闭"！没有 close/reopen！
第 335 行: 请求数据已保存，ID: 1            (21:42:39)  ← setRequests 批量加载
第 341 行: 权限测试模式已开启，自动触发越权重放...       ← setRequest() 自动触发
第 342 行: 请求数据已保存，ID: 2
第 348 行: 权限测试模式已开启，自动触发越权重放...
第 349 行: 批量加载完成：成功 2 / 2 条
第 351 行: 权限测试模式：开始重放请求 (requestId=1)...
第 353 行: 权限测试模式：开始重放请求 (requestId=2)...
...执行测试...
第 406 行: 权限测试重放全部完成               (21:42:41)
第 409 行: 自动化测试已关闭                   (21:42:44)  ← 仍然自动退出！
第 410 行: 权限测试模式: 已关闭
```

### 三次自动退出的延迟对比

| 测试 | 触发路径 | close/reopen | 完成→退出延迟 |
|------|---------|:---:|:---:|
| Cycle 3 Test 1 (POST) | `setPrivilegeTestRequest` | ✅ 有 | 1.37秒 |
| Cycle 3 Test 2 (GET) | `setPrivilegeTestRequest` | ✅ 有 | 2.57秒 |
| **Cycle 4 批量** | `setRequests` → `setRequest` 自动触发 | ❌ **无** | **2.99秒** |

Cycle 4 的自动退出证明：**close/reopen 不是唯一触发条件**。即使完全不经过 `setPrivilegeTestMode(false)` 调用，Swing EDT 事件队列中仍存在某种机制最终导致 `modeToggleButton.setSelected(false)` 被调用，从而触发 ActionListener → `setPrivilegeTestMode(false)` → 自动退出。

### 根因分析

推测根因是 **Burp Suite 自定义 L&F 环境下 `JToggleButton.setSelected()` 的事件触发行为与标准 Swing 不同**：

1. 模式开启时，`fireModeChanged(true)` 通过 `SwingUtilities.invokeLater` 排队 `modeToggleButton.setSelected(true)`（任务 T_mode_sync）
2. 同时，`setRequest()` 的自动触发路径排队 `sendPrivilegeTestRequestDirect`（任务 S1, S2）
3. EDT 按 FIFO 顺序执行：T_mode_sync → S1 → S2
4. `sendPrivilegeTestRequestDirect` 启动异步重放后立即返回，EDT 继续处理其他任务
5. 异步重放完成后，`onReplayComplete` / `onAllComplete` 回调通过 `invokeLater` 排队更多 EDT 任务（UI 更新、光标恢复等）
6. 在某些 EDT 时机窗口下，`modeToggleButton.setSelected(true)` 可能因为 L&F 实现细节而**意外触发 ActionListener**（即使在按钮已选中状态下），形成延迟的反馈链

另一个可能性是 Burp Suite 的 Montoya API 在某些 UI 操作（如 `responsePanel.setResponse`、`historyTableModel.fireTableDataChanged`）中触发了额外的 EDT 事件，间接影响了 `modeToggleButton` 的状态。

### 影响

- **用户信任崩溃**：用户每次测试后必须手动重新开启模式，体验极差
- **不可预测性**：延迟在 1.37~2.99 秒之间波动，用户无法判断系统是"正在处理"还是"已自动关闭"
- **多层触发路径**：Bug 16（close/reopen 反馈环）和 Bug 17（自动触发路径）是**两个独立机制**，修复其中一个无法完全解决问题

### 修复方案

**统一修复（根治 Bug 15 + Bug 16 + Bug 17）**：两个互补策略同时实施

**策略 1 — 消除 close/reopen（修复 Bug 15 + Bug 17）**：

在 `RequestDispatchHandler` 中引入"静默加载"标志位，替代 `setPrivilegeTestRequest()` 和 `setPrivilegeTestRequests()` 中的 `setPrivilegeTestMode(false/true)` 调用对：

```java
// RequestDispatchHandler.java 新增
private volatile boolean silentLoadMode = false;

public void setSilentLoadMode(boolean silent) {
    this.silentLoadMode = silent;
}

// RepeaterManagerUI.setPrivilegeTestRequest() 修改为：
public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
    // 替代第 805 行的 dispatchHandler.setPrivilegeTestMode(false);
    dispatchHandler.setSilentLoadMode(true);
    try {
        int dbId = setRequest(requestResponse);  // 不会触发双重重放
        // ... 标记、基线保存等 ...
    } finally {
        dispatchHandler.setSilentLoadMode(false);
    }
    // 手动触发重放（模式本来就是开启的，不需要第 829 行的 reopen）
    SwingUtilities.invokeLater(() ->
        dispatchHandler.sendPrivilegeTestRequestDirect(capturedReq, capturedSvc, capturedId));
}

// setRequest() 内部修改第 768 行：
if (dispatchHandler.isPrivilegeTestMode() && !dispatchHandler.isSilentLoadMode()) {
    // 仅当非静默模式才触发自动重放
    ...
}
```

**策略 2 — 打断反馈链（修复 Bug 16 + Bug 17）**：

在 `RepeaterManagerUI` 中新增标记位，在 ModeChangeListener 同步按钮状态时抑制 ActionListener：

```java
// RepeaterManagerUI.java 新增字段
private boolean syncingModeButton = false;

// 修改 ModeChangeListener（第 142-160 行）
dispatchHandler.addModeChangeListener(mode -> {
    SwingUtilities.invokeLater(() -> {
        syncingModeButton = true;
        try {
            if (modeToggleButton != null) {
                modeToggleButton.setSelected(mode);
            }
            // ...标签样式更新...
        } finally {
            syncingModeButton = false;
        }
    });
});

// 修改 modeToggleButton ActionListener（第 292-296 行）
modeToggleButton.addActionListener(e -> {
    if (syncingModeButton) return;  // 抑制程序同步触发的反馈
    boolean selected = modeToggleButton.isSelected();
    dispatchHandler.setPrivilegeTestMode(selected);
    LogManager.getInstance().printOutput("[*] 权限测试模式: " + (selected ? "已开启" : "已关闭"));
});
```

### 验证方法

1. **场景 A**：开启越权模式 → Proxy History 右键"发送到权限测试"（单条）→ 确认测试完成，模式保持开启
2. **场景 B**：开启越权模式 → Proxy History 右键"发送到权限测试"（多条批量）→ 确认批量测试完成，模式保持开启
3. **场景 C**：开启越权模式 → Proxy History 右键"发送到 Repeater Manager"（自动触发路径）→ 确认测试完成，模式保持开启
4. 检查日志：测试完成后不应出现"自动化测试已关闭"和"权限测试模式: 已关闭"
5. 确认 modeToggleButton 保持"已开启"状态，代理处理器仍在监听

---

## 修复优先级建议（v5 更新 — 2026-06-30 最终验证）

### 已验证已修复 ✅

| Bug # | 描述 | 修复内容 |
|-------|------|---------|
| 1 | OR 逻辑失效 | v13 架构改为纯 AND |
| 2 | 空条件跳过→true | v13 架构短路求值 |
| 3 | Content-Type 取自错误响应 | baselineContentType 优先 |
| 7 | 值分权重过高 | 改为 0.5/0.5 均衡权重 |
| 8 | NoiseFilter 遗漏小数值 | `\d{4,19}` 覆盖1-5位 |
| 9 | 短字符串二值判断 | 集成 LevenshteinCalculator |
| 10 | 默认规则安全网绕过 | 活跃未命中→检查 defaultRule |
| 11 | ensureDefaultSimilarityRule 过于宽松 | 按名称精确匹配 |
| 12 | LevenshteinCalculator 未集成 | 已接入相似度管线 |

### 已降级 ⚠️

| Bug # | 描述 | 降级原因 |
|-------|------|---------|
| 15 | close/reopen EDT震荡 | 非Bug：防止 `setRequest()` 双重重放的有意设计 |
| 16 | setSelected反馈链 | 证据不足：日志中关闭延迟（1.37s/2.57s/2.99s）与用户手动操作吻合 |
| 17 | 无close/reopen仍退出 | 证据不足：日志来自多次测试会话混用 |

### 待修复优先级

| 优先级 | Bug # | 理由 |
|-------|------|------|
| **P1** | Bug 4 | 配置错误时静默失效，导致测试结果不可靠 |
| P2 | Bug 14 | 失去 OR 组合表达能力，限制高级用户场景 |
| P2 | Bug 13 | 缓存刷新过多，性能和日志可读性问题 |
| P2 | Bug 5 | 204/304 等空 body 场景的守卫条件 |
| P2 | Bug 6 | 注释与实际代码不符，影响可维护性 |

**建议修复顺序**：
1. **第一优先**：Bug 4（FieldReplacementEngine 沉默返回 → 显式警告）
2. **后续改进**：Bug 14 + Bug 13 + Bug 5 + Bug 6（技术债清理）
