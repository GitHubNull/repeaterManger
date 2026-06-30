# AGENT.md

> 本文档为 AI 编码助手（如 Claude Code、Cursor 等）提供项目上下文和开发指南。

## 项目概述

**Repeater Manager** 是一个 Burp Suite Professional 扩展插件，提供增强的 HTTP 请求重放管理、API 规则提取和自动化越权测试功能。项目使用 Java 17 编写，基于 Montoya SDK（`burp.api.montoya.*`），采用 MVC 架构。

- **版本**: 2.31.0
- **Java 版本**: 17（source/target 兼容）
- **构建工具**: Maven
- **许可证**: Apache License 2.0

## 架构概览

```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording / ApiExtraction / PrivilegeTest
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager / ApiExtractionRuleDAO
+---------------------+
|   Data Storage      |  SQLite + File Blobs (Pool 去重架构) + YAML (全局规则)
+---------------------+
```

### 核心组件

| 组件 | 文件 | 职责 |
|------|------|------|
| 扩展入口 | `org/oxff/repeater/RepeaterManagerExtension.java` | 实现 Montoya `BurpExtension` 接口，管理插件生命周期 |
| API 持有者 | `org/oxff/repeater/api/MontoyaApiHolder.java` | MontoyaApi 静态持有者 |
| 主 UI 控制器 | `org/oxff/repeater/RepeaterManagerUI.java` | 协调所有 UI 面板和功能组件 |
| UI 桥接 | `org/oxff/repeater/UIRequestDispatcher.java` | 解耦入口类与 UI 操作 |
| 数据库管理 | `org/oxff/repeater/db/DatabaseManager.java` | SQLite 连接池、Schema 初始化、会话管理 |
| Schema 迁移 | `org/oxff/repeater/db/schema/SchemaMigrator.java` | 数据库 Schema 版本化迁移 |
| Pool 去重 | `org/oxff/repeater/db/pool/PoolManager.java` | 字符串/头部/Body 内容 SHA-256 去重存储 |
| 请求管理 | `org/oxff/repeater/http/RequestManager.java` | 异步 HTTP 请求发送（Montoya API） |
| 请求调度 | `org/oxff/repeater/RequestDispatchHandler.java` | 统一请求调度（普通/越权测试模式路由） |
| 历史录制 | `org/oxff/repeater/service/HistoryRecordingService.java` | 异步队列化历史记录保存 |
| 垃圾回收 | `org/oxff/repeater/service/GarbageCollectorService.java` | 自动清理零引用 Pool 数据（10分钟间隔），支持自动/手动模式切换 |
| 自动保存 | `org/oxff/repeater/service/AutoSaveService.java` | 定时数据库检查点 |
| 日志管理 | `org/oxff/repeater/logging/LogManager.java` | 多通道日志分发和级别过滤，内置 GC 定时调度器 |
| ERM 存档 | `org/oxff/repeater/io/ErmArchiveWriter.java` / `ErmArchiveReader.java` | 加密存档导入导出（AES-256-CBC + HMAC-SHA256） |
| 数据导入导出 | `org/oxff/repeater/io/DataExporter.java` / `DataImporter.java` | 统一导入导出调度 |
| API 提取引擎 | `org/oxff/repeater/api/ApiExtractionEngine.java` | 无状态规则引擎（4种源 × 4种方法） |
| 全局规则管理 | `org/oxff/repeater/api/GlobalRuleManager.java` | 全局 API 提取规则管理（YAML 文件） |
| 项目规则管理 | `org/oxff/repeater/api/ApiRuleManager.java` | 项目级 API 提取规则管理（SQLite） |
| 越权测试引擎 | `org/oxff/repeater/privilege/AutoTestEngine.java` | 自动化越权测试（拦截代理 → 重放 → 判断） |
| Token 替换 | `org/oxff/repeater/privilege/TokenReplacementEngine.java` | 请求中 Token 自动替换 |
| 判断引擎 | `org/oxff/repeater/privilege/JudgmentEngine.java` | 响应判断引擎（三层：基准无效→活跃规则组→兜底相似度） |
| 规则条件模型 | `org/oxff/repeater/privilege/model/RuleCondition.java` | 规则条件（target + method + expression + AND/OR/NOT） |
| 令牌方案模型 | `org/oxff/repeater/privilege/model/TokenScheme.java` | 令牌方案（一组令牌位置的组合，会话-方案关联） |
| 全局令牌方案管理 | `org/oxff/repeater/privilege/GlobalTokenSchemeManager.java` | 跨会话全局令牌方案 CRUD 与 YAML 持久化 |
| 去重配置管理 | `org/oxff/repeater/privilege/DedupConfigManager.java` | 多配置优先级链式去重（6策略 × 3保留策略） |
| API 去重引擎 | `org/oxff/repeater/privilege/ApiDedupEngine.java` | 从 HTTP 请求中提取去重键 |
| 会话解析 | `org/oxff/repeater/privilege/FetchRequestParser.java` | Chrome DevTools fetch 格式报文解析 |
| 相似度引擎 | `org/oxff/repeater/privilege/SimilarityEngine.java` | 内容感知相似度计算（JSON/XML/通用文本） |
| 同步 HTTP 发送 | `org/oxff/repeater/privilege/SyncHttpSender.java` | 带重试的同步 HTTP 请求发送 |
| HTTP 消息解析 | `org/oxff/repeater/http/HttpMessageParser.java` | 统一提取响应体/响应头 |
| 配置管理 | `org/oxff/repeater/config/DatabaseConfig.java` | 存储模式/日志/代理配置 |
| 报文比对引擎 | `org/oxff/repeater/ui/history/DiffEngine.java` / `DiffPane.java` | LCS 行级/字符级差异算法与 RSyntaxTextArea 渲染面板 |
| 比对对话框 | `org/oxff/repeater/ui/history/ComparisonDialog.java` | 全功能报文比对（标签页/四分格布局） |
| 差异导航器 | `org/oxff/repeater/ui/history/DiffNavigator.java` | 差异区域上一处/下一处跳转导航 |
| 报告生成引擎 | `org/oxff/repeater/privilege/report/ReportGenerator.java` (abstract) | PDF/HTML/Markdown 报告生成基类 |
| PDF 报告 | `org/oxff/repeater/privilege/report/PdfReportGenerator.java` | 原生 PDF 报告 (Apache PDFBox，内嵌中文字体) |
| HTML/MD 报告 | `org/oxff/repeater/privilege/report/HtmlReportGenerator.java` / `MarkdownReportGenerator.java` | FreeMarker 模板渲染报告 |
| 身体渲染器 | `org/oxff/repeater/privilege/report/BodyRenderer.java` / `BinaryContentRenderer.java` | 请求/响应体渲染与二进制内容转换 |
| 全局Token管理 | `org/oxff/repeater/privilege/GlobalTokenLocationManager.java` | 跨会话全局 Token 位置管理 |
| 用户会话导入导出 | `org/oxff/repeater/privilege/UserSessionYamlIO.java` | 用户会话 YAML 导入导出 |
| 文件选择器 | `org/oxff/repeater/utils/FileChooserHelper.java` | 统一文件选择器工具 |

## 关键设计决策

### Montoya SDK 集成

项目使用 Montoya SDK（`burp.api.montoya.*` v2025.12）而非旧的 Burp Extender API：
- 入口类实现 `BurpExtension` 接口（非 `IBurpExtender`）
- 使用 `MontoyaApi` 替代 `IBurpExtenderCallbacks`
- HTTP 请求/响应使用 `HttpRequest`/`HttpResponse` 工厂方法
- UI 编辑器使用 `HttpRequestEditor`/`HttpResponseEditor`
- 右键菜单实现 `ContextMenuItemsProvider`

### Pool 去重架构

数据库采用 Pool 架构，将 HTTP 请求/响应的内容拆分为多个去重组件：

- **string_pool**: 域名、路径、查询参数通过 SHA-256 哈希去重
- **header_pool**: HTTP 头部数据去重
- **body_pool**: 小体积 Body 行内存储（SQLite BLOB）
- **file_pool**: 大体积 Body 外置文件存储（blobs/ 目录）
- **gc_queue**: 垃圾回收队列

每个 Pool 条目维护 `ref_count` 引用计数。删除请求时减少引用，GC 服务定期清理零引用条目。

### 连接池

`DatabaseManager` 使用 `BlockingQueue<Connection>` 实现简易连接池，通过 JDK 动态代理拦截 `close()` 调用将连接归还池中，使现有 `try-with-resources` 代码无需修改。

### API 提取引擎

`ApiExtractionEngine` 采用无状态设计，支持 first-match-wins 策略：
- **提取源**（`ApiRuleSource`）：`URL_PATH`、`URL_QUERY`、`HEADER`、`BODY`
- **提取方法**（`ApiRuleMethod`）：`REGEX`、`SUBSTR`、`JSON_PATH`、`XPATH`
- **规则存储**：全局规则（`~/.burp/repeater_manager/api_extraction_rules.yaml`，负数 ID）+ 项目规则（SQLite，正数 ID）

### 越权测试模块

自动化越权测试工作流（v2.30.0 规则组重构）：
1. 定义令牌方案（Token Scheme）— 一组令牌位置的组合
2. 定义令牌位置（Token Location）— Token 在请求中的位置（6 种类型）
3. 创建用户会话（User Session）— 关联令牌方案，填充各位置的 Token 值
4. 配置判断规则组（Judgment Rule Group）— 设置活跃规则组（全局唯一活跃），组内条件纯 AND 组合
5. 设置请求范围（Scope）— URL 匹配模式
6. 配置去重规则（Dedup Config）— 避免同一 API 重复测试
7. `AutoTestEngine` 拦截匹配范围的代理流量
8. `TokenReplacementEngine` 注入不同用户 Token
9. `JudgmentEngine` 按三层逻辑判决：基准无效→ERROR → 活跃规则组匹配 → 兜底相似度
10. 结果在越权测试面板展示（颜色标记：红=越权/绿=安全）

### 令牌方案系统（v2.21.0）

- `TokenScheme` 作为令牌位置与用户会话之间的中间层
- 支持多方案管理，不同方案对应不同安全测试目标
- `GlobalTokenSchemeManager` 单例管理跨会话全局方案持久化（YAML）
- 用户会话通过 `schemeId` 一对一关联方案
- 匿名用户创建时智能匹配方案（v2.31.0）

### 去重配置系统（v2.20.0）

- `DedupConfigManager` 管理多配置优先级链式匹配
- `ApiDedupEngine` 支持 6 种去重策略（PATH/API/JSON_BODY_FIELD/XML_BODY_FIELD/FORM_FIELD/URL_PARAM）
- 支持 3 种保留策略（FIRST/LAST/MIDDLE）
- 双重存储：全局 YAML 持久化 + 会话级内存

### 会话解析系统（v2.25.x~v2.26.0）

- `FetchRequestParser` 支持 Chrome DevTools "Copy as fetch" 格式解析
- 自动检测剪贴板内容格式（原始 HTTP / fetch browser / fetch Node.js）
- `SessionParserEngine` 从报文自动提取 Token 值和位置
- 方案匹配：无匹配方案时弹出 `SelectSchemeDialog`

### 会话目录

每次加载插件创建新的会话目录（时间戳命名），包含：
- `repeater_manager.sqlite3` — 数据库文件
- `blobs/` — 外置 Body 数据
- `logs/` — 日志文件

### ERM 存档格式

自定义二进制存档格式，支持可选的 AES-256-CBC + HMAC-SHA256 加密：
- 32 字节文件头（魔法数字 + 格式版本 + 标志 + 条目数 + manifest 偏移 + CRC）
- 数据条目（路径 + 压缩方式 + 数据 + CRC）
- manifest JSON 条目
- 16 字节文件尾（魔法数字 + data CRC + footer CRC）

### 日志系统

`LogManager` 单例统一管理三个输出通道：
- `BurpConsoleHandler` → Burp Suite 输出面板（Montoya Logging API）
- `RollingFileHandler` → 滚动文件日志
- `UIHandler` → 插件日志面板

支持级别过滤：DEBUG / INFO / SUCCESS / WARN / ERROR

### 报告生成架构

报告生成采用 Template Method 模式，`ReportGenerator` 为抽象基类：
1. `ReportExporter` 负责收集数据并构建 `ReportData` 对象
2. `BodyRenderer` / `BinaryContentRenderer` 负责将请求/响应体渲染为可展示格式（含 hex/base64/图片预览）
3. 具体生成器 (`PdfReportGenerator` / `HtmlReportGenerator` / `MarkdownReportGenerator`) 实现 `generate()` 方法
4. HTML/Markdown 报告通过 FreeMarker 模板 (`src/main/resources/templates/report/`) 渲染
5. PDF 报告通过 Apache PDFBox 原生 API 构建，支持内嵌中文字体（`PdfReportGenerator` 内置字体资源）
6. `ReportContainerWriter/Reader` 提供报告容器的序列化/反序列化
7. `CurlBuilder` / `PostmanSnippetBuilder` 为每个请求生成 cURL 命令和 Postman 代码片段

### 报文比对模块

报文比对工作流：
1. `ComparisonDialog` 提供标签页式/四分格布局的比对界面
2. `DiffEngine` 实现基于 LCS 变体的行级差异算法，支持行内字符级差异
3. `DiffPane` 使用 RSyntaxTextArea 渲染差异结果，支持语法高亮（绿色=新增、红色=删除、黄色=修改、行内差异=深色高亮）
4. `DiffNavigator` 提供差异区域导航（上一处/下一处），合并左右面板差异区域
5. `SynchronizedScrollPanel` 保证原始/修改两端面板同步滚动
6. `SearchBar` 提供可折叠的搜索栏，支持关键字/正则匹配、大小写敏感

### 全局 Token 位置管理

`GlobalTokenLocationManager` 单例管理跨会话共享的 Token 位置配置：
1. Token 位置通过 `TokenLocationYamlIO` 序列化到 YAML 文件
2. 支持 4 种位置类型：HEADER、COOKIE、BODY、URL_PARAM
3. 全局 Token 位置可用于所有用户会话的自动填充

## 构建命令

```bash
mvn clean package
```

构建产物：
- `target/repeater-manager-2.31.0.jar` — 开发版本
- `target/releases/repeater-manager-2.31.0-YYYYMMDD-HHMMSS.jar` — 带时间戳发布版本

## 数据库 Schema

两个主表 + 四个 Pool 表 + 功能表 + GC 队列表 + 元数据表：

```sql
-- 主表
requests (id, protocol, domain_hash, path_hash, query_hash, method, add_time, comment, color, req_header_hash, req_body_hash, req_body_storage)
history  (id, request_id, method, protocol, domain_hash, path_hash, query_hash, status_code, response_length, response_time, timestamp, comment, color, req_header_hash, req_body_hash, req_body_storage, resp_header_hash, resp_body_hash, resp_body_storage)

-- Pool 表
string_pool (hash, value, ref_count)
header_pool (hash, data, size, ref_count)
body_pool   (hash, data, size, ref_count, is_binary)
file_pool   (hash, relative_path, size, ref_count, is_binary)

-- API 提取规则表
api_extraction_rules (id, name, source, method, expression, enabled, priority, persistent, is_global)

-- 越权测试表
user_sessions (id, name, scheme_id, request_timeout, max_concurrent, retry_count, retry_delay, replay_delay, ...)
token_schemes (id, name, description, enabled, persist_to_global, ...)
scheme_token_locations (scheme_id, token_location_id)
token_locations (id, type, expression, enabled, persist_to_global, ...)
judgment_rules (id, name, enabled, is_active, success_color, failure_color, ...)
judgment_rule_conditions (id, group_id, target, method, expression, negate, operator, sort_order, enabled, ...)
scopes (id, pattern, ...)
dedup_configs (全局 YAML: ~/.burp/repeater_manager/dedup_configs.yaml)

-- GC 队列
gc_queue (id, pool_type, hash, enqueued_at)

-- 元数据
schema_meta (key, value)
```

## 依赖版本

| 依赖 | 版本 | Maven 坐标 |
|------|------|-----------|
| Montoya API | 2025.12 | `net.portswigger.burp.extensions:montoya-api` (provided scope) |
| RSyntaxTextArea | 3.3.3 | `com.fifesoft:rsyntaxtextarea` |
| SQLite JDBC | 3.42.0.0 | `org.xerial:sqlite-jdbc` |
| HikariCP | 5.0.1 | `com.zaxxer:HikariCP` (declared, not actively used) |
| Gson | 2.10.1 | `com.google.code.gson:gson` |
| SnakeYAML | 2.2 | `org.yaml:snakeyaml` |
| Commons IO | 2.11.0 | `commons-io:commons-io` |
| Commons Lang | 3.12.0 | `org.apache.commons:commons-lang3` |
| Apache PDFBox | 3.0.1 | `org.apache.pdfbox:pdfbox` |
| FreeMarker | 2.3.33 | `org.freemarker:freemarker` |
| CommonMark | 0.22.0 | `org.commonmark:commonmark` |

## 编码约定

- **语言**: Java 17（可使用 Lambda、文本块、密封类、记录类等特性）
- **API**: 使用 `burp.api.montoya.*` Montoya SDK，不使用旧的 `burp.I*` 接口
- **包结构**: `burp` 包仅含入口点，业务代码在 `org.oxff.repeater` 下
- **日志**: 使用 `BurpExtender.printOutput()` / `printError()` 或 `LogManager` 方法
- **数据库访问**: 通过 DAO 类（RequestDAO / HistoryDAO / ApiExtractionRuleDAO），使用 `try-with-resources` 管理连接
- **UI 线程**: Swing UI 操作必须在 EDT 中执行（`SwingUtilities.invokeLater`）
- **单例模式**: DatabaseManager / LogManager / HistoryRecordingService / ProxyConfig / GlobalRuleManager 等使用单例
- **异步操作**: HTTP 请求发送、数据加载、历史记录保存、API 提取、越权测试均在后台线程执行
- **MontoyaApi 访问**: 优先使用构造函数注入；静态上下文中使用 `MontoyaApiHolder.getApi()`（位于 `org.oxff.repeater.api` 包）
- **ByteArray 封装**: Montoya API 方法需要 `ByteArray.byteArray(bytes)` 而非原始 `byte[]`
- **API 规则 ID**: 全局规则使用负数 ID，项目规则使用正数 ID

## 注意事项

1. **不要修改 `burp` 包路径**：Burp Suite 要求入口类在 `burp` 包下
2. **SQLite 限制**：SQLite 不支持真正的并发写入，写操作需串行化
3. **内存管理**：Body 数据可能很大，使用 Pool 去重和文件外置减少内存占用
4. **Burp API 兼容性**：使用 Montoya SDK（`burp.api.montoya.*`），不要混用旧 API
5. **HTTPS 协议保留**：发送请求时需通过 `HttpService` 保留 HTTPS 协议信息
6. **错误过滤**：`BurpExtender.shouldFilterError()` 过滤 IntelliJ 相关的无害 ClassNotFoundException
7. **GC 依赖**：删除请求后需触发 GC 清理关联的 Pool 数据
8. **YAML 文件**：全局 API 规则和判断规则使用 SnakeYAML 序列化，注意 YAML 格式正确性
9. **Schema 迁移**：数据库结构变更需通过 SchemaMigrator 进行版本化迁移

## CI/CD

项目使用 GitHub Actions（`.github/workflows/release.yml`）：

- **触发条件**: 推送 `v*` 格式标签（如 `v2.31.0`）或手动触发
- **构建**: JDK 17 + Maven
- **发布**: 自动创建 GitHub Release，附带构建的 JAR 文件
- **预发布**: 标签包含 `-` 后缀（如 `v2.31.0-beta`）时标记为预发布
