# 高级开发指南

> 面向需要深入理解和修改核心子系统的贡献者

---

## 目录

- [1. Montoya SDK 深层集成](#1-montoya-sdk-深层集成)
- [2. 越权测试引擎架构](#2-越权测试引擎架构)
- [3. 报告生成子系统](#3-报告生成子系统)
- [4. 报文比对子系统](#4-报文比对子系统)
- [5. 异步服务设计](#5-异步服务设计)
- [6. 全局 YAML 规则持久化与跨会话共享](#6-全局-yaml-规则持久化与跨会话共享)

---

## 1. Montoya SDK 深层集成

### 1.1 扩展入口与生命周期

```java
// RepeaterManagerExtension.java
public class RepeaterManagerExtension implements BurpExtension {
    private final LogManager logManager = LogManager.getInstance();

    @Override
    public void initialize(MontoyaApi api) {
        // 1. 保存 API 引用并设置插件名
        MontoyaApiHolder.setApi(api);
        api.extension().setName("repeaterManger");

        // 2. 阶段1：初始化日志管理器（仅 BurpConsoleHandler）
        logManager.initialize(api);

        // 3. 阶段2：加载早期配置（日志级别、UI、控制台、代理，不含文件 Handler）
        loadLogConfigEarly();

        // 4. 阶段3：初始化数据库（创建会话目录 + SQLite，写入示例数据并检查状态）
        if (DatabaseManager.getInstance().initialize()) {
            DatabaseManager.getInstance().testDatabaseWithSampleData();
            DatabaseManager.getInstance().checkDatabaseStatus();
        }

        // 5. 阶段4：加载晚期配置（文件日志 Handler → 会话目录 logs/）
        loadLogConfigLate();

        // 6. 阶段4.5~4.7：加载全局规则（API 提取 / 字段定义 / 方案 / 判决规则 / 去重配置）
        GlobalRuleManager.getInstance().loadRules();
        GlobalFieldDefinitionManager.getInstance().loadFields();
        SessionManager.getInstance().loadGlobalSchemes();
        GlobalJudgmentRuleManager.getInstance().loadRules();
        DedupConfigManager.getInstance().loadGlobalConfigs();

        // 7. 阶段4.8：初始化国际化（必须在创建任何 UI 之前，否则语言切换不生效）
        I18nManager.getInstance().initialize();

        // 8. 创建 UI（8 个顶级选项卡），注入请求调度器并注册 Suite Tab
        RepeaterManagerUI repeaterUI = new RepeaterManagerUI(api);
        UIRequestDispatcher.getInstance().setRepeaterUI(repeaterUI);
        api.userInterface().registerSuiteTab("Repeater Manager", repeaterUI.getUiComponent());

        // 9. 注册上下文菜单（PopMenu 为无参构造）
        api.userInterface().registerContextMenuItemsProvider(new PopMenu());

        // 10. 注册卸载监听器（UI 资源 → 数据库连接池 → 日志系统，按序关闭）
        api.extension().registerUnloadingHandler(() -> {
            repeaterUI.close();
            DatabaseManager.getInstance().closeConnections();
            logManager.shutdown();
        });
    }
}
```

### 1.2 关键 Montoya API 映射

| 操作 | Montoya API |
|------|-------------|
| 发送 HTTP 请求 | `api.http().sendRequest(httpRequest)` |
| 创建请求编辑器 | `api.userInterface().createHttpRequestEditor()` |
| 创建响应编辑器 | `api.userInterface().createHttpResponseEditor()` |
| 注册 Suite Tab | `api.userInterface().registerSuiteTab(title, component)` |
| 注册右键菜单 | `api.userInterface().registerContextMenuItemsProvider(provider)` |
| 日志输出 | `api.logging().logToOutput(message)` |
| 构建 HTTP 请求 | `HttpRequest.httpRequest(byteArray)` |
| 构建 HTTP 服务 | `HttpService.httpService(host, port, isHttps)` |

### 1.3 ByteArray 封装

Montoya API 方法要求 `ByteArray` 而非原始 `byte[]`：

```java
// 正确
httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(rawBytes));

// 错误
httpRequest = HttpRequest.httpRequest(rawBytes);  // 编译错误
```

### 1.4 HTTPS 协议保留

发送请求时必须通过 `HttpService` 保留原始协议信息：

```java
HttpService service = HttpService.httpService(
    originalRequest.httpService().host(),
    originalRequest.httpService().port(),
    originalRequest.httpService().secure()  // HTTPS = true
);
HttpRequest request = HttpRequest.httpRequest(service, bodyBytes);
```

---

## 2. 越权测试引擎架构

### 2.1 三层数据架构

```
FieldDefinition (字段定义)
    ↓ 多对多
Scheme (方案)
    ↓ 一对一
UserSession (用户会话)
```

- **FieldDefinition**：定义字段在请求中的位置（6 种类型）和提取表达式
- **Scheme**：一组字段的组合，实现字段与用户会话的解耦
- **UserSession**：关联一个方案，填充各字段的具体值

### 2.2 自动化测试流程

```
AutoTestEngine
  ├── 1. 拦截代理流量（ScopeManager 匹配范围）
  ├── 2. 遍历用户会话
  │    ├── FieldReplacementEngine 替换字段值
  │    │    ├── 非空值 → 替换为会话中的值
  │    │    └── 空值（匿名用户）→ 移除字段（Header删除/JSON移除属性/URL移除参数）
  │    ├── ReplayEngine 重放请求（SyncHttpSender 同步发送，带重试）
  │    └── JudgmentEngine 三层判决
  │         ├── 层1：基准响应无效？→ ERROR
  │         ├── 层1.5：空 Body 感知（基线/测试 body 为空且活跃规则组无 body 依赖条件 → 空 Body 专门判决）
  │         ├── 层2：活跃规则组评估（AND/OR 混合逻辑，条件组合命中 → ESCALATED）
  │         └── 层3：兜底链：活跃规则组自身最小阈值 → 默认相似度规则组（SIMILARITY > 0.90）→ 全局阈值相似度判决（默认 0.70，含状态码差异语义）→ 状态码/体长联合判决
  └── 3. 去重检查（ApiDedupEngine）
```

### 2.3 关键组件

| 组件 | 职责 | 关键方法 |
|------|------|----------|
| `AutoTestEngine` | 自动化测试编排 | `processProxyRequest()` |
| `FieldReplacementEngine` | 字段值替换/移除 | `replaceFields()`, `removeField()` |
| `ReplayEngine` | 请求重放调度 | `replay()` |
| `JudgmentEngine` | 三层分层判决 | `judge()` |
| `SessionManager` | 会话生命周期管理 | `createSession()`, `deleteSession()` |
| `JudgmentRuleManager` | 规则组 CRUD + 活跃状态管理 | `setActiveRuleGroup()` |
| `DedupConfigManager` | 去重配置优先级链式管理 | `matchDedupConfig()` |
| `ApiDedupEngine` | 从请求提取去重键 | `extractDedupKey()` |

### 2.4 规则组判决机制（v2.30.0+ 规则组，v2.37.0+ AND/OR 混合）

- **规则组（Rule Group）**：一组条件的集合，组内条件按 AND/OR 混合组合求值
- **单活跃规则集**：全局同时只有一个规则组处于活跃状态
- **条件运算符**：AND / OR / NOT（取反复选框）；schema v19 起 `judgment_rule_conditions` 表持久化 `operator` 列（默认 AND）
- **求值顺序**：按 `sort_order` 从左到右；编辑对话框首行不显示连接符（固定按 AND 参与组合）
- **兜底链**：活跃规则组未命中时依次尝试——① 若活跃规则组含 `SIMILARITY GREATER_THAN` 条件且实际相似度低于其阈值，用活跃规则组自身最小阈值进行默认判决（防止默认规则组用更低阈值覆盖判决意图）；② 默认相似度规则组（`SIMILARITY > 0.90`）作为安全网；③ 全局阈值相似度判决（默认 0.70，含状态码差异语义：基准 2xx vs 测试 401/403 时区分"未登录被拒=安全"与"疑似字段未配置=待确认"）；④ 相似度无法计算时回退状态码/体长联合判决

### 2.5 匿名用户语义

匿名用户的所有字段值为空字符串，重放时执行"移除"操作：
- HEADER → 删除该 Header
- JSON_BODY → 移除 JSON 属性
- XML_BODY → 移除 XML 节点
- FORM_FIELD / MULTIPART_FIELD → 移除表单字段
- URL_PARAM → 移除 URL 查询参数

### 2.6 会话解析

`FetchRequestParser` 支持从剪贴板解析三种格式：
1. 原始 HTTP 报文
2. Chrome "Copy as fetch" 格式
3. Chrome "Copy as fetch (Node.js)" 格式

---

## 3. 报告生成子系统

### 3.1 Template Method 模式

```
ReportGenerator (abstract)
├── PdfReportGenerator    → Apache PDFBox 3.0.1 原生生成
├── HtmlReportGenerator   → FreeMarker 模板渲染
└── MarkdownReportGenerator → FreeMarker 模板渲染
```

### 3.2 生成流程

```
ReportExporter
  ├── 1. 收集数据 → ReportData 对象
  ├── 2. BodyRenderer / BinaryContentRenderer 渲染请求/响应体
  ├── 3. CurlBuilder / PostmanSnippetBuilder 生成复现代码
  ├── 4. 调用具体生成器 generate()
  └── 5. 可选：ReportContainerWriter 加密打包为 ERMR
```

### 3.3 PDF 报告特点

- Apache PDFBox 原生 API 构建（非 HTML 转 PDF）
- 内嵌中文字体资源（`PdfReportGenerator` 内置）
- 超长文本（如 Base64）自动截断，提示查看 HTML 报告

### 3.4 FreeMarker 模板

模板文件位于 `src/main/resources/templates/report/`：
- `html_report.ftl` — HTML 报告模板
- `md_report.ftl` — Markdown 报告模板
- `html_css.ftl` — 报告 CSS 样式

---

## 4. 报文比对子系统

### 4.1 组件架构

```
ComparisonDialog (比对对话框)
├── 标签页模式
│   ├── 请求差异标签页 → DiffPane
│   └── 响应差异标签页 → DiffPane
├── 四分格模式
│   ├── 原始请求 / 替换请求
│   └── 原始响应 / 替换响应
├── DiffNavigator (导航器)
│   ├── 上一处差异 / 下一处差异
│   └── 差异区域高亮
├── SearchBar (搜索栏)
│   ├── 关键字/正则搜索
│   └── 大小写敏感
└── SynchronizedScrollPanel (同步滚动)
```

### 4.2 DiffEngine 算法

- 基于 LCS（最长公共子序列）变体
- 行级差异：识别新增/删除/修改行
- 字符级行内差异：在修改行内进一步标注具体变化字符
- 颜色编码：
  - **绿色**：新增内容
  - **红色**：删除内容
  - **黄色**：修改内容

### 4.3 DiffPane 渲染

- 使用 RSyntaxTextArea 作为差异显示组件
- 自定义语法高亮 Token 实现差异着色
- 支持行号显示和代码折叠

### 4.4 SynchronizedScrollPanel

- 两个 JScrollPane 之间的滚动同步
- 通过共享 `AdjustmentListener` 实现
- 适合并排对比场景（原始 vs 替换）

---

## 5. 异步服务设计

### 5.1 后台服务总览

| 服务 | 类 | 调度方式 | 默认间隔 |
|------|----|----------|----------|
| 自动保存 | `AutoSaveService` | 独立 `ScheduledExecutorService`（间隔可配置） | 5 分钟 |
| 垃圾回收 | `GarbageCollectorService` | 独立 `ScheduledExecutorService`（首次延迟 2 分钟，批处理 100 条/轮） | 10 分钟 |
| 历史录制 | `HistoryRecordingService` | 异步队列（生产者-消费者） | 实时 |

### 5.2 HistoryRecordingService

- 生产者-消费者模式
- `BlockingQueue` 缓冲历史记录写入请求
- 后台线程批量写入数据库
- 避免 HTTP 响应处理线程阻塞

### 5.3 GarbageCollectorService

- 扫描 `gc_queue` 表
- 删除 `string_pool`/`header_pool`/`body_pool`/`file_pool` 中 `ref_count = 0` 的条目
- 文件池条目同时删除磁盘文件
- 支持手动触发和全量 `ref_count` 重算

---

## 6. 全局 YAML 规则持久化与跨会话共享

### 6.1 全局规则类型

| 类型 | 存储路径 | 管理类 |
|------|----------|--------|
| API 提取规则 | `~/.burp/repeater_manager/api_extraction_rules.yaml` | `GlobalRuleManager` |
| 判断规则组 | `~/.burp/repeater_manager/judgment_rules.yaml` | `GlobalJudgmentRuleManager`（读写经 `JudgmentRuleYamlIO`） |
| 字段定义 | `~/.burp/repeater_manager/field_definitions.yaml` | `GlobalFieldDefinitionManager`（读写经 `FieldDefinitionYamlIO`） |
| 方案 | `~/.burp/repeater_manager/schemes.yaml` | `GlobalSchemeManager` |
| 去重配置 | `~/.burp/repeater_manager/dedup_configs.yaml` | `DedupConfigManager`（读写经 `DedupConfigYamlIO`） |
| 用户会话 | 仅会话级 SQLite；`user_sessions.yaml` 为手动导入/导出格式 | `UserSessionYamlIO`（工具类，无全局自动持久化） |

### 6.2 双重存储策略

多数配置支持两种存储模式：
- **全局持久化**：YAML 文件，跨会话共享
- **会话级存储**：SQLite 数据库，仅当前会话有效

### 6.3 启动同步流程

```
插件启动
  ├── 加载全局 YAML 配置（api_extraction_rules / judgment_rules / field_definitions / schemes / dedup_configs）
  ├── 同步到当前会话 SQLite 数据库（judgment_rules 中标记"持久化"的规则自动恢复到新会话库）
  ├── 去重检查（按 type+expression 去重，judgment_rules 条件去重另纳入 operator 维度）
  └── 启用标记为全局（global/持久化）的配置
```

### 6.4 SnakeYAML 使用

各 YAML IO 工具类（如 `ApiRuleYamlIO`、`JudgmentRuleYamlIO`）统一采用"根 Map + version 字段"结构：

```java
// 读取：load 为 Map 后按键取值（无 TypeReference 泛型反序列化）
Yaml yaml = new Yaml();
Map<String, Object> root = yaml.load(yamlContent);
List<Map<String, Object>> ruleMaps = (List<Map<String, Object>>) root.get("rules");

// 写入：BLOCK 风格 + pretty + 允许 Unicode，首字段写入版本号
DumperOptions options = new DumperOptions();
options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
options.setPrettyFlow(true);
options.setAllowUnicode(true);
Yaml yaml = new Yaml(options);
Map<String, Object> root = new LinkedHashMap<>();
root.put("version", YAML_VERSION);
root.put("rules", ruleList);
yaml.dump(root, new FileWriter(file));
```

---

> 本文档涵盖 Repeater Manager 核心子系统的高级实现细节。建议结合实际代码阅读，以获取最准确的信息。
>
> 返回 [开发文档索引](index.md)
