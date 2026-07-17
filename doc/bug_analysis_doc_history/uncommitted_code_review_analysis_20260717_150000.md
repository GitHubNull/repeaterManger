# 未提交代码变更审查分析报告

> **审查时间**: 2026-07-17 15:00:00
> **审查范围**: 17 个文件（13 个修改 + 4 个新增）
> **变更主题**: 新增"测试信息配置"模块（TestInfoConfig），支持越权测试报告的目标元信息存储与展示
> **审查维度**: 功能问题 / 业务逻辑问题 / 设计问题

---

## 一、变更概览

### 1.1 修改文件（13 个）

| 文件 | 变更性质 |
|------|----------|
| `db/schema/SchemaInitializer.java` | Schema 版本 v16→v17，新增两张表 |
| `db/schema/SchemaMigrator.java` | LATEST_VERSION 15→17，注册 v16→v17 迁移 |
| `privilege/SessionManager.java` | 新增 TestInfoConfig 的 CRUD + 缓存 |
| `privilege/report/ReportData.java` | 新增 testInfoConfig 字段及其截图数据字段 |
| `privilege/report/ReportGenerator.java` | 阶段 G：收集测试信息配置并编码截图 |
| `privilege/report/HtmlReportGenerator.java` | 渲染测试信息配置 + 截图写入 |
| `privilege/report/MarkdownReportGenerator.java` | FreeMarker 模型注入测试信息配置 |
| `privilege/report/PdfReportGenerator.java` | PDF 中渲染测试信息配置 section |
| `ui/privilege/PrivilegeTestPanel.java` | 越权测试面板新增"测试信息配置"子Tab |
| `templates/report/controller.js` | 前端渲染测试信息配置区域 + 灯箱增强 |
| `templates/report/html_css.ftl` | 测试信息配置 CSS + 灯箱增强样式 |
| `templates/report/html_report.ftl` | HTML 模板新增测试信息配置区域 |
| `templates/report/md_report.ftl` | Markdown 模板新增测试信息配置区域 |

### 1.2 新增文件（4 个）

| 文件 | 说明 |
|------|------|
| `privilege/model/TestInfoConfig.java` | 测试信息配置模型（目标名称/入口/截图/时间段/人员） |
| `privilege/dao/TestInfoConfigDAO.java` | 单例 DAO（INSERT OR REPLACE 语义，截图先删后插） |
| `ui/privilege/TestInfoConfigTab.java` | Swing UI 表单（文本字段 + 截图列表管理 + 预览） |
| `db/schema/MigrationsV16ToV17.java` | v16→v17 迁移步骤 |

---

## 二、功能问题

### F1. [严重] v15→v16 Schema 迁移步骤缺失——已存在 v15 数据库无法获取 user_info 表

**定位**: `SchemaMigrator.java` + `MigrationsV12ToV15.java`

**问题描述**:
当前迁移链为：
```
v2→v3→v4→v5→v6  (MigrationsV2ToV6)
v6→v7→v8→v9→v10→v11  (MigrationsV7ToV11)
v11→v12→v13→v14→v15  (MigrationsV12ToV15)
v16→v17  (MigrationsV16ToV17) ← 新增
```

可以看到 v15→v16 迁移步骤**完全缺失**。而 v16 引入了 `user_info` 和 `user_info_screenshots` 两张表（参见 `SchemaInitializer.createV6PrivilegeTables()` 中的 CREATE TABLE 语句）。这意味着：

1. **全新安装**：SchemaInitializer 直接初始化到 v17，所有表（包括 user_info）正常创建 → 无影响
2. **v16→v17 升级**：执行 MigrationsV16ToV17，正常迁移 → 无影响
3. **v15→v17 升级**：迁移循环会匹配 v16→v17（`currentVersion < step.toVersion()`），但 v15→v16 步骤不存在，`user_info` 和 `user_info_screenshots` 表被跳过 → **表缺失，涉及用户信息的报告功能将报错**

**业务影响**：
- 从 v15 数据库升级的用户，报告中的用户信息（角色/用户名/匿名标记/截图）将完全丢失
- `SessionManager.getUserInfo()` / `UserInfoDAO` 操作 `user_info` 表时将抛出 SQLException
- 严重程度：**高**（数据完整性受损，用户无感知）

**根因分析**：
v15→v16 迁移步骤在 v16 发布时被遗漏，本次变更又新增了 v16→v17 而非补齐缺失的 v15→v16，使问题延续。

**修复建议**：
1. 创建 `MigrationsV15ToV16.java` 类，实现 v15→v16 迁移：
```java
// 迁移内容：
// 1. CREATE TABLE user_info (...)
// 2. CREATE TABLE user_info_screenshots (...)
// 3. UPDATE schema_meta SET value = '16'
```
2. 在 `SchemaMigrator.java` 中注册该迁移类
3. 调整迁移链顺序：`MigrationsV15ToV16` → `MigrationsV16ToV17`

---

### F2. [严重] TestInfoConfigDAO 中 `created_at` 列的类型不匹配——首次保存后加载会抛异常

**定位**: `TestInfoConfigDAO.java` 第 24-48 行（load 方法）和第 53-103 行（save 方法）

**问题描述**:
1. 数据库 Schema 定义：
```sql
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
```
SQLite 的 `TIMESTAMP` 不是一个强类型，`CURRENT_TIMESTAMP` 产生的是**文本字符串**（如 `"2026-07-17 10:30:00"`）

2. `save()` 方法的 INSERT 语句**未包含** `created_at` 列：
```java
String upsertSql = "INSERT INTO test_info_config (id, target_name, target_entry, 
    test_time_range, test_personnel, updated_at) VALUES (?, ?, ?, ?, ?, ?) ..."
```
因此首次 INSERT 时，`created_at` 由 DEFAULT 填充为**文本时间戳**。

3. `save()` 的 `updated_at` 通过 `setLong(6, System.currentTimeMillis())` 写入，类型为**整数**。

4. `load()` 方法中：
```java
config.setCreatedAt(rs.getLong("created_at"));  // ← 试图将文本 "2026-07-17..." 转为 long
```
SQLite JDBC 驱动对 `getLong()` 调用非纯数字的文本值将抛出 `SQLException`。

**复现步骤**：
1. 全新安装插件（数据库全新初始化到 v17）
2. 在"测试信息配置"Tab 中填写信息并保存
3. 再次打开该 Tab 或生成报告 → `TestInfoConfigDAO.load()` 失败
4. 异常被 catch 后返回空的 `new TestInfoConfig()`，用户之前保存的数据丢失

**业务影响**：
- 保存的测试信息配置在下次加载时丢失
- 报告中将不显示测试信息配置部分
- 严重程度：**高**（核心新增功能不可用）

**根因分析**：
SQLite 的弱类型系统与 Java `long` 类型假定不兼容。同一列在不同写入路径（DEFAULT vs setLong）产生不同类型的数据，而读取路径未做类型适配。

**修复建议**：
方案 A（推荐）：统一使用 Java 毫秒时间戳，不使用 SQLite DEFAULT
```java
// save() 的 INSERT 中包含 created_at，由 Java 端提供时间戳
String upsertSql = "INSERT INTO test_info_config (id, target_name, target_entry, 
    test_time_range, test_personnel, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ..."
pstmt.setLong(6, System.currentTimeMillis()); // created_at
pstmt.setLong(7, System.currentTimeMillis()); // updated_at
```
同时将 Schema 的 `DEFAULT CURRENT_TIMESTAMP` 改为 `DEFAULT 0` 或直接移除 DEFAULT。

方案 B：在 load() 中兼容两种类型
```java
Object rawCreatedAt = rs.getObject("created_at");
if (rawCreatedAt instanceof Number) {
    config.setCreatedAt(((Number) rawCreatedAt).longValue());
} else if (rawCreatedAt instanceof String) {
    // 尝试解析 SQLite 文本时间戳为 epoch millis
    config.setCreatedAt(parseTimestamp((String) rawCreatedAt));
}
```

---

## 三、业务逻辑问题

### B1. [中等] 目标入口 URL 缺乏协议前缀自动补全——可能导致报告中的链接失效

**定位**: `controller.js` 第 28-30 行

**问题描述**:
```javascript
if (config.targetEntry) {
    html += '<tr><td class="test-info-label">目标入口</td><td><a href="' + escapeHtml(config.targetEntry)
        + '" target="_blank">' + escapeHtml(config.targetEntry) + '</a></td></tr>';
}
```
用户输入 `example.com` 时，生成的 HTML 为：
```html
<a href="example.com" target="_blank">example.com</a>
```
浏览器会将 `example.com` 解析为**相对路径**（相对当前 HTML 文件的路径），而非跳转到 `https://example.com`，导致链接完全失效。

同样的问题也存在于 `html_report.ftl` 第 31 行：
```html
<a href="${testInfoConfig.targetEntry}" target="_blank">
```

**业务影响**：
- 报告中的"目标入口"链接指向错误地址
- 用户体验差，测试人员无法快速导航到测试目标

**修复建议**：
在前端和后端模板中统一加协议检测逻辑：
```javascript
// controller.js
function sanitizeUrl(url) {
    if (!url) return '';
    // 如果已有协议前缀，直接返回
    if (/^https?:\/\//i.test(url)) return url;
    // 自动补全 https://
    return 'https://' + url;
}
```
同时在 `TestInfoConfigTab.saveConfig()` 中可考虑做服务端校验/补全提示。

---

### B2. [低] 目标入口 URL 潜在的 XSS 风险——`javascript:` 伪协议未过滤

**定位**: `controller.js` 第 29 行

**问题描述**:
```javascript
html += '...<a href="' + escapeHtml(config.targetEntry) + '" ...';
```
`escapeHtml()` 函数只转义 HTML 特殊字符（`<`, `>`, `&`, `"`, `'`），不处理 URL Scheme。如果用户输入 `javascript:alert(document.cookie)` 作为目标入口，生成的链接为：
```html
<a href="javascript:alert(document.cookie)" target="_blank">
```
用户点击后会在报告页面的上下文中执行 JavaScript。

**风险评估**：
- 报告是本地文件（`file://` 协议），攻击面有限
- 但若报告被分享给他人，则存在社会工程利用可能
- 危害程度：**低**（需要用户主动输入恶意 payload，且报告在本地上下文运行）

**修复建议**：
```javascript
function sanitizeUrl(url) {
    if (!url) return '';
    // 黑名单：危险协议
    if (/^\s*(javascript|data|vbscript):/i.test(url)) return '#blocked';
    if (/^https?:\/\//i.test(url)) return url;
    return 'https://' + url;
}
```

---

### B3. [中等] 截图文件绝对路径存储在数据库中——跨机器移植后数据不可用

**定位**: `TestInfoConfigTab.java` 第 200-216 行 + `TestInfoConfigDAO.java`

**问题描述**:
`addScreenshot()` 方法将截图的绝对路径（如 `C:\Users\xxx\Desktop\screenshot.png`）存入数据库。该数据随 ERM 导出/导入时，路径在其他机器上**必然失效**。

虽然截图在报告生成时会被 `ScreenshotEncoder.encode()` 读取并编码为 base64 嵌入报告（不依赖运行时文件），但：
1. 用户在另一台机器上打开配置 Tab 时会看到无效的截图路径列表
2. "预览"和"删除"操作将无法正常工作
3. 路径数据成为无意义的垃圾数据

**修复建议**：
在 ERM 导出时，可选择将截图文件也打包进存档；在 DAO 层保存时，检查文件是否存在并给出警告。长期可考虑将截图二进制存入 blobs 目录。

---

## 四、设计问题

### D1. [高] v17 新表放置于 `createV6PrivilegeTables()` 方法——方法命名与实际职责严重不符

**定位**: `SchemaInitializer.java` 第 316-339 行

**问题描述**:
`test_info_config` 和 `test_info_screenshots` 两张 v17 新增的表，被创建在 `createV6PrivilegeTables()` 方法内部（位于 `user_info_screenshots` 和 `judgment_rule_groups` 之间）。

`createV6PrivilegeTables()` 方法名明确表示"创建 v6 权限测试相关表"，但现在其实际内容包含了：
- v6 表：field_definitions, user_sessions, field_values
- v9 表：（field_definitions 的 v9 结构变更）
- v11 表：schemes, scheme_fields, （user_sessions 的 v11 结构变更）
- v13 表：judgment_rule_groups, judgment_rule_conditions
- v14 表：（重命名相关）
- v16 表：user_info, user_info_screenshots
- v17 表：test_info_config, test_info_screenshots

这个方法已膨胀为"所有非核心表的创建方法"，方法名与实际职责完全脱节。

**修复建议**：
1. 将 v17 表移出 `createV6PrivilegeTables()`，创建独立方法如 `createV17TestInfoTables()`
2. 长期重构：按版本号拆分表创建方法，或将所有表创建统一到 `initializeV3Schema()` 中按版本分组注释

---

### D2. [中等] 灯箱关闭后 `mousemove`/`mouseup` 事件监听器泄漏

**定位**: `controller.js` 第 237-249 行

**问题描述**:
```javascript
// 鼠标拖拽平移 - 在 document 上注册了全局事件
document.addEventListener('mousemove', function(e) { ... });
document.addEventListener('mouseup', function() { ... });
```
灯箱的 `close()` 函数只清理了 `keydown` 监听器：
```javascript
function close() {
    document.body.removeChild(overlay);
    document.removeEventListener('keydown', onKeyDown);  // ← 只清理了 keydown
    // mousemove 和 mouseup 未清理！
}
```

每次打开灯箱会添加两个匿名函数作为全局事件监听器，关闭后它们仍然存在于 document 上。如果用户多次打开灯箱（例如浏览多个截图），这些孤儿监听器会不断累积。

**修复建议**：
将 mousemove/mouseup 的处理函数提取为命名函数并保存引用，在 close() 中一并移除：
```javascript
function onMouseMove(e) {
    if (!isDragging) return;
    translateX = dragTranslateStartX + (e.clientX - dragStartX);
    translateY = dragTranslateStartY + (e.clientY - dragStartY);
    applyTransform();
}
function onMouseUp() {
    if (isDragging) {
        isDragging = false;
        imgWrap.style.cursor = scale > 1 ? 'grab' : 'default';
    }
}
document.addEventListener('mousemove', onMouseMove);
document.addEventListener('mouseup', onMouseUp);

function close() {
    document.body.removeChild(overlay);
    document.removeEventListener('keydown', onKeyDown);
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
}
```

---

### D3. [低] DAO 层 `save()` 的截图同步策略（先删后插）缺乏幂等性保护

**定位**: `TestInfoConfigDAO.java` 第 77-92 行

**问题描述**:
```java
// 同步截图：先删后插
String deleteScreenshotsSql = "DELETE FROM test_info_screenshots WHERE config_id = ?";
// ...
for (String path : config.getTargetScreenshots()) {
    // INSERT ...
}
```
在事务中使用 `DELETE ALL + INSERT ALL` 策略同步截图，这在正常流程中是正确的。但如果 `save()` 在极端并发场景下被多次调用（例如用户快速双击保存按钮），第二个事务可能在第一个事务 COMMIT 前读到旧数据，导致数据不一致。

**修复建议**：
在 UI 层增加防抖（当前保存按钮无防抖保护），或将并发控制下沉到 DAO 层。

---

### D4. [低] Schema 版本号 `'17'` 在多处硬编码——增加未来维护成本

**定位**: `SchemaInitializer.java` 第 42 行 + `SchemaMigrator.java` 第 25 行 + `MigrationsV16ToV17.java` 第 59 行

**问题描述**:
Schema 版本字符串 `'17'` 出现在三个不同位置。如果未来升级到 v18，开发者必须同时修改这三处，遗漏任何一处都会导致版本不一致。

**修复建议**：
将 `LATEST_VERSION` 作为字符串来源统一引用。在 `SchemaInitializer` 和 `MigrationsV16ToV17` 中使用 `SchemaMigrator.LATEST_VERSION`：
```java
// SchemaInitializer.java
stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '" 
    + SchemaMigrator.LATEST_VERSION + "')");

// MigrationsV16ToV17.java  
stmt.execute("UPDATE schema_meta SET value = '" + SchemaMigrator.LATEST_VERSION 
    + "' WHERE key = 'schema_version'");
```

---

## 五、问题汇总与优先级

| 编号 | 问题 | 类别 | 严重度 | 影响范围 |
|------|------|------|--------|----------|
| F1 | v15→v16 Schema 迁移缺失 | 功能 | 🔴 高 | 从 v15 升级的用户，user_info 表缺失 |
| F2 | `created_at` 类型不匹配导致加载失败 | 功能 | 🔴 高 | 核心新增功能的保存/加载环路断裂 |
| B1 | 目标入口 URL 无协议自动补全 | 业务逻辑 | 🟡 中 | 报告链接失效 |
| B3 | 截图绝对路径跨机器不可移植 | 业务逻辑 | 🟡 中 | ERM 导入后截图数据不可用 |
| B2 | 目标入口 `javascript:` 伪协议未过滤 | 业务逻辑 | 🟢 低 | 本地报告 XSS（需主动构造） |
| D1 | v17 表放在 `createV6PrivilegeTables` 中 | 设计 | 🔴 高 | 代码可维护性恶化 |
| D2 | 灯箱 mousemove/mouseup 监听器泄漏 | 设计 | 🟡 中 | 多次开灯箱后内存泄漏 |
| D4 | Schema 版本号多处硬编码 | 设计 | 🟢 低 | 未来维护风险 |
| D3 | 截图同步缺乏并发保护 | 设计 | 🟢 低 | 极端并发场景下数据不一致 |

---

## 六、总体评价

本次变更实现了"测试信息配置"功能的完整链路（模型 → DAO → 缓存 → UI → 报告生成 → 模板渲染），整体架构思路清晰，符合项目现有 MVC 分层模式。新增的灯箱缩放/拖拽功能提升了报告截图浏览体验。

但存在 **两个阻塞级功能缺陷**（F1、F2），其中 F2 会导致核心新增功能在首次保存后不可用。建议在合并前必须修复 F1 和 F2，其余问题可在后续迭代中逐步优化。

---

> **审查人**: Qoder AI Code Review
> **审查基准**: Repeater Manager 分离式架构 PRD v2.0 + 项目编码规范
