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
    @Override
    public void initialize(MontoyaApi api) {
        // 1. 保存 API 引用
        MontoyaApiHolder.setApi(api);
        
        // 2. 初始化日志系统
        LogManager.getInstance().initialize(api);
        
        // 3. 初始化数据库（异步）
        DatabaseManager.getInstance().initialize();
        
        // 4. 注册 Suite Tab
        api.userInterface().registerSuiteTab("Repeater Manager", new RepeaterManagerUI(api));
        
        // 5. 注册右键菜单
        api.userInterface().registerContextMenuItemsProvider(new PopMenu(api));
        
        // 6. 启动后台服务
        AutoSaveService.getInstance().start();
        GarbageCollectorService.getInstance().start();
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
  │    └── JudgmentEngine 三方判决
  │         ├── 层1：基准响应无效？→ ERROR
  │         ├── 层2：活跃规则组全部条件命中？→ ESCALATED/NOT_ESCALATED
  │         └── 层3：无活跃规则组或未命中 → 相似度兜底（>= 0.90 → ESCALATED）
  └── 3. 去重检查（ApiDedupEngine）
```

### 2.3 关键组件

| 组件 | 职责 | 关键方法 |
|------|------|----------|
| `AutoTestEngine` | 自动化测试编排 | `processProxyRequest()` |
| `FieldReplacementEngine` | 字段值替换/移除 | `replaceFields()`, `removeField()` |
| `ReplayEngine` | 请求重放调度 | `replay()` |
| `JudgmentEngine` | 三方分层判决 | `judge()` |
| `SessionManager` | 会话生命周期管理 | `createSession()`, `deleteSession()` |
| `JudgmentRuleManager` | 规则组 CRUD + 活跃状态管理 | `setActiveRuleGroup()` |
| `DedupConfigManager` | 去重配置优先级链式管理 | `matchDedupConfig()` |
| `ApiDedupEngine` | 从请求提取去重键 | `extractDedupKey()` |

### 2.4 规则组判决机制（v2.30.0+）

- **规则组（Rule Group）**：一组条件的集合，组内条件 AND 组合求值
- **单活跃规则集**：全局同时只有一个规则组处于活跃状态
- **条件运算符**：AND / OR / NOT（取反复选框）
- **求值顺序**：按 `sort_order` 从左到右
- **兜底机制**：无活跃规则组时使用默认相似度规则（`SIMILARITY >= 0.90`）

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
| 自动保存 | `AutoSaveService` | `ScheduledExecutorService` | 5 分钟 |
| 垃圾回收 | `GarbageCollectorService` | `LogManager` 内置调度器 | 10 分钟 |
| 历史录制 | `HistoryRecordingService` | 异步队列（生产者-消费者） | 实时 |
| GC 调度器 | `LogManager` 内置 | Daemon 线程轮询 | 30 秒检查 |

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
| 判断规则组 | `~/.burp/repeater_manager/judgment_rules.yaml` | `JudgmentRuleYamlIO` |
| 用户会话 | `~/.burp/repeater_manager/user_sessions.yaml` | `UserSessionYamlIO` |
| 字段定义 | `~/.burp/repeater_manager/field_definitions.yaml` | `FieldDefinitionYamlIO` |
| 方案 | `~/.burp/repeater_manager/schemes.yaml` | `GlobalSchemeManager` |
| 去重配置 | `~/.burp/repeater_manager/dedup_configs.yaml` | `DedupConfigManager` |

### 6.2 双重存储策略

多数配置支持两种存储模式：
- **全局持久化**：YAML 文件，跨会话共享
- **会话级存储**：SQLite 数据库，仅当前会话有效

### 6.3 启动同步流程

```
插件启动
  ├── 加载全局 YAML 配置
  ├── 同步到当前会话 SQLite 数据库
  ├── 去重检查（按 type+expression 去重）
  └── 启用标记为 persist_to_global 的配置
```

### 6.4 SnakeYAML 使用

```java
// 读取
Yaml yaml = new Yaml();
List<ApiExtractionRule> rules = yaml.loadAs(
    new FileInputStream(file),
    new TypeReference<List<ApiExtractionRule>>() {}.getType()
);

// 写入
yaml.dump(rules, new FileWriter(file));
```

---

> 本文档涵盖 Repeater Manager 核心子系统的高级实现细节。建议结合实际代码阅读，以获取最准确的信息。
>
> 返回 [开发文档索引](index.md)
