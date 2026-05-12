# Repeater Manager - Burp Suite 请求重放管理插件

<p align="center">
  <strong>面向安全测试人员的 Burp Suite 高级请求重放管理与越权测试插件</strong>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> | 中文
</p>

---

## 项目介绍

Repeater Manager 是一个为 Burp Suite Professional 设计的高级 HTTP 请求重放管理插件。相比原生 Repeater，它提供了更强大的功能，包括请求的分类管理、响应历史自动记录与比对、SQLite 本地持久化、内容去重存储、多条件高级搜索、API 规则提取、自动化越权测试、多种格式导入导出（ERM 加密存档 / Postman Collection）以及定时自动保存防丢机制。本插件特别适合安全测试人员和渗透测试专家使用，可有效提高 HTTP/HTTPS 请求测试的效率和组织性。

> **当前版本**: v2.16.2 | **最低要求**: Burp Suite Professional 2024+ (Montoya 扩展 API) + Java 17+

## 核心功能

| 功能 | 说明 |
|------|------|
| 请求管理 | 组织和分类 HTTP 请求，支持颜色标记和备注功能 |
| 历史记录 | 自动记录每次请求的响应历史，方便比对不同时间的测试结果 |
| 数据持久化 | 所有请求和历史记录保存到 SQLite 数据库，重启 Burp Suite 后不会丢失 |
| 内容去重存储 | 采用 Pool 架构（字符串池/头部池/Body池/文件池），通过 SHA-256 自动去重节省存储空间 |
| 高级搜索 | 支持多条件复合筛选，快速定位特定请求或响应 |
| 列显示控制 | 自定义表格中显示的列，提高信息密度和可读性 |
| API 规则提取 | 可配置的 API 提取规则引擎，支持 4 种提取源 × 4 种提取方法，自动从不规则请求中提取 API 路径 |
| 越权测试 | 自动化越权漏洞测试框架，通过用户会话 Token 替换和响应对比判断越权风险 |
| 数据导入导出 | 支持 ERM 加密存档（AES-256-CBC + HMAC-SHA256）、Postman Collection v2.1 等多种格式 |
| 自动保存 | 定时将内存中的数据同步到磁盘，防止数据丢失 |
| 垃圾回收 | 后台自动清理零引用的池数据，回收存储空间（10分钟间隔） |
| 日志系统 | 多通道日志输出（Burp 控制台/滚动文件/UI 面板），支持级别过滤（DEBUG/INFO/SUCCESS/WARN/ERROR） |
| 代理调试 | 支持配置 HTTP 代理用于调试请求 |
| 布局切换 | 请求/响应面板支持左右、上下、仅请求、仅响应四种布局模式 |
| 报文比对 | 支持请求/响应报文字符串级和字节级差异对比，语法高亮差异展示，同步滚动与差异导航 |
| 报告生成 | 支持将越权测试结果导出为 PDF/HTML/Markdown 格式的正式报告，内嵌请求/响应详情和 cURL/Postman 代码片段 |
| 批量操作 | 历史面板多选支持，提供批量重放、批量越权测试、批量删除功能 |

## 功能架构

```
Repeater Manager
├── 插件集成（Montoya SDK）
├── 请求管理
│   ├── 请求列表（搜索/过滤/颜色标记/备注）
│   ├── 请求编辑（语法高亮）
│   └── 请求重放（异步发送/超时控制）
├── 响应管理
│   ├── 响应展示（语法高亮）
│   └── 布局切换（左右/上下/仅请求/仅响应）
├── 历史记录
│   ├── 成功请求记录
│   ├── 失败请求记录
│   ├── 历史回放
│   ├── 报文比对（新增）
│   │   ├── 字符串/字节级差异对比
│   │   ├── 差异导航与同步滚动
│   │   └── 可折叠搜索栏
│   └── 高级搜索（多条件复合筛选）
├── API 提取引擎
│   ├── 提取源：URL_PATH / URL_QUERY / HEADER / BODY
│   ├── 提取方法：REGEX / SUBSTR / JSON_PATH / XPATH
│   ├── 全局规则（YAML 共享配置）
│   └── 项目规则（SQLite 独立存储）
├── 越权测试模块
│   ├── 多用户会话管理
│   ├── Token 位置配置（Header/Cookie/Body/URL参数）
│   ├── Token 自动替换引擎
│   ├── 判断规则配置（状态码/响应体/响应头/响应时间）
│   ├── 自动化检测引擎（拦截代理流量 → 重放 → 判断）
│   ├── 结果展示与颜色标记
│   └── 报告生成（新增）
│       ├── PDF 报告 (Apache PDFBox)
│       ├── HTML 报告 (FreeMarker 模板)
│       └── Markdown 报告 (FreeMarker 模板)
├── 数据持久化
│   ├── SQLite 存储（自定义连接池）
│   ├── 内容分片（Pool 去重架构）
│   ├── 文件存储（大 Body 外置）
│   └── SHA-256 哈希校验
├── 导入导出
│   ├── ERM 存档（AES-256-CBC + HMAC-SHA256 加密）
│   ├── Postman Collection v2.1
│   └── 智能格式检测
├── 后台服务
│   ├── 自动保存服务
│   ├── 垃圾回收服务
│   └── 历史记录录制服务（异步队列）
├── 日志系统
│   ├── Burp 控制台输出
│   ├── 滚动文件日志
│   └── UI 日志面板
└── 配置管理
    ├── 存储配置（自动/指定目录/指定文件）
    ├── 日志配置（级别/通道开关）
    ├── 代理配置
    └── API 规则配置（全局+项目级）
```

## 安装方法

### 前置条件

- Burp Suite Professional 2024.1 或更高版本
- Java 17 或更高版本

### 安装步骤

1. 从 [Releases](../../releases) 页面下载最新的 JAR 文件
2. 打开 Burp Suite Professional
3. 转到 `Extensions` → `Installed` 选项卡
4. 点击 `Add` 按钮
5. 在 `Extension file` 中选择下载的 JAR 文件
6. 点击 `Next` 完成安装

> 首次加载后，插件会自动在 `~/.burp/` 目录下创建会话目录（以时间戳命名），内含数据库文件、Body 数据目录和日志目录。全局 API 提取规则存储在 `~/.burp/repeater_manager/api_extraction_rules.yaml`。

## 快速开始

### 基本使用流程

1. 在 Burp Suite 的任何位置（如 Proxy、Intruder），右键点击请求
2. 选择 **"发送到 Repeater Manager"**
3. 切换到 **"Repeater Manager"** 标签页查看和管理请求
4. 编辑请求内容，点击 **"发送"** 按钮重放
5. 在左侧下方的历史记录面板查看每次重放的响应
6. 使用颜色标记和备注功能对请求进行分类管理

### 界面与布局

- 切换 **布局模式**（左右/上下/仅请求/仅响应）以适应不同工作场景
- 通过 **列控制** 自定义请求列表显示的字段

### 数据管理

- 所有数据自动保存到 SQLite 数据库，重启后不会丢失
- 通过 **配置面板** 调整存储模式、日志级别和自动保存间隔
- 使用 **ERM 存档** 或 **Postman Collection** 导入导出数据

### 高级功能

- **API 规则提取**：配置提取规则，自动从不规则请求中提取标准 API 路径
- **越权测试**：配置多用户会话和判断规则，自动检测水平/垂直越权漏洞

详细使用说明请参考：
- [快速入门教程](doc/usage_quick_zh.md)

## 技术架构

```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording / ApiExtraction / PrivilegeTest
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager / ApiExtractionRuleDAO
+---------------------+
|   Data Storage      |  SQLite + File Blobs (Pool 去重) + YAML (全局规则)
+---------------------+
```

**核心技术栈**：

- **Burp 集成**: Montoya SDK (`burp.api.montoya.*`) v2025.12 — 现代 Burp Suite 扩展接口
- **前端界面**: Java Swing + RSyntaxTextArea 语法高亮组件 (v3.3.3)
- **数据存储**: SQLite (JDBC v3.42.0.0) + 自定义连接池（BlockingQueue + JDK Proxy）
- **序列化**: Gson (v2.10.1) + SnakeYAML (v2.2)
- **工具库**: Apache Commons IO (v2.11.0) + Commons Lang3 (v3.12.0)
- **核心模式**: MVC 架构、单例模式、连接池代理模式、Pool 去重模式、规则引擎模式

## 项目结构

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Burp 扩展入口点 (Montoya BurpExtension 接口)
└── oxff/top/
    ├── RepeaterManagerUI.java          # 主 UI 控制器
    ├── api/                            # API 提取子系统
    │   ├── MontoyaApiHolder.java       # MontoyaApi 静态持有者
    │   ├── ApiExtractionEngine.java    # 无状态规则提取引擎
    │   ├── ApiExtractionRule.java      # 提取规则模型
    │   ├── ApiExtractionRuleDAO.java   # 项目级规则 CRUD (SQLite)
    │   ├── ApiRuleManager.java         # 项目级规则管理器
    │   ├── GlobalRuleManager.java      # 全局规则管理器 (YAML)
    │   ├── ApiRuleYamlIO.java          # 规则 YAML 序列化
    │   ├── ApiRuleSource.java          # 枚举: URL_PATH/URL_QUERY/HEADER/BODY
    │   └── ApiRuleMethod.java          # 枚举: REGEX/SUBSTR/JSON_PATH/XPATH
    ├── config/
    │   ├── DatabaseConfig.java         # 数据库配置（存储模式/日志/代理）
    │   └── SessionDirectory.java       # 会话目录管理
    ├── controller/
    │   └── PopMenu.java               # 右键菜单（ContextMenuItemsProvider）
    ├── db/
    │   ├── DatabaseManager.java        # 数据库连接管理（连接池/Schema初始化）
    │   ├── RequestDAO.java             # 请求数据访问对象
    │   ├── schema/                     # Schema 管理
    │   │   ├── SchemaInitializer.java  # Schema 创建
    │   │   └── SchemaMigrator.java     # Schema 版本化迁移
    │   ├── history/                    # 历史记录 DAO（读写更新分离）
    │   │   ├── HistoryReadDAO.java     # 历史读操作
    │   │   ├── HistoryWriteDAO.java    # 历史写操作
    │   │   └── HistoryUpdateDAO.java   # 历史更新操作
    │   └── pool/
    │       ├── PoolManager.java        # Pool 去重管理器
    │       ├── BodyStorageRoute.java   # Body 存储路由（inline/file）
    │       ├── ContentHasher.java      # 内容哈希计算（SHA-256）
    │       ├── ContentSplitter.java    # 请求/响应内容分割
    │       ├── ContentReconstructor.java # 内容重建
    │       ├── FileStorageManager.java # 文件型 Body 存储
    │       ├── HttpEnum.java           # HTTP 枚举类型
    │       └── SplitResult.java        # 分割结果
    ├── http/
    │   ├── ProxyConfig.java            # HTTP 代理配置（单例）
    │   ├── RequestManager.java         # HTTP 请求管理（Montoya API 异步发送）
    │   ├── HttpRequestHelper.java      # HTTP 请求解析工具（Montoya 类型）
    │   ├── RequestDataHelper.java      # 请求数据验证/修复工具
    │   └── RequestResponseRecord.java  # 请求响应记录模型
    ├── io/
    │   ├── DataExporter.java           # 导出调度器
    │   ├── DataImporter.java           # 导入调度器（智能格式检测）
    │   ├── ErmArchiveWriter.java       # ERM 存档导出（AES-256 加密）
    │   ├── ErmArchiveReader.java       # ERM 存档导入
    │   ├── ErmCryptoHelper.java        # ERM 加密辅助（PBKDF2/AES-CBC/HMAC）
    │   ├── ErmFormatConstants.java     # ERM 格式常量
    │   ├── FormatDetector.java         # 格式自动检测
    │   ├── PostmanExporter.java        # Postman Collection v2.1 导出
    │   └── PostmanImporter.java        # Postman Collection v2.1 导入
    ├── logging/
    │   ├── LogManager.java             # 日志管理器（多通道/级别过滤）
    │   ├── LogEntry.java               # 日志条目
    │   ├── LogHandler.java             # 日志 Handler 基类
    │   ├── LogLevel.java               # 日志级别枚举
    │   ├── BurpConsoleHandler.java     # Burp 控制台日志 Handler
    │   ├── RollingFileHandler.java     # 滚动文件日志 Handler
    │   └── UIHandler.java              # UI 面板日志 Handler
    ├── model/
    │   ├── HistoryRecord.java          # 历史记录模型
    │   ├── RequestRecord.java          # 请求记录模型
    │   └── RequestResponseRecord.java  # 请求响应记录模型
    ├── privilege/                      # 越权测试子系统
    │   ├── AutoTestEngine.java         # 自动化测试引擎（拦截代理 → 重放 → 判断）
    │   ├── ReplayEngine.java           # 请求重放引擎
    │   ├── JudgmentEngine.java         # 响应判断引擎
    │   ├── TokenReplacementEngine.java # Token 替换引擎
    │   ├── LevenshteinCalculator.java  # 字符串相似度计算
    │   ├── SessionManager.java         # 用户会话管理器
    │   ├── JudgmentRuleManager.java    # 判断规则管理器
    │   ├── ScopeManager.java           # 请求范围管理器
    │   ├── JudgmentRuleYamlIO.java     # 判断规则 YAML 序列化
    │   ├── model/                      # 越权测试模型
    │   │   ├── UserSession.java        # 用户会话（凭证/Token）
    │   │   ├── JudgmentRule.java       # 判断规则
    │   │   ├── JudgmentResult.java     # 测试结果
    │   │   ├── TokenLocation.java      # Token 位置
    │   │   ├── TokenLocationType.java  # 枚举: HEADER/COOKIE/BODY/URL_PARAM
    │   │   ├── RuleTarget.java         # 枚举: STATUS_CODE/RESPONSE_BODY/等
    │   │   ├── RuleMethod.java         # 枚举: CONTAINS/NOT_CONTAINS/REGEX/LENGTH_DIFF
    │   │   └── ScopeEntry.java         # 范围配置
    │   └── dao/
    │       ├── SessionDAO.java         # 用户会话 CRUD
    │       ├── JudgmentRuleDAO.java    # 判断规则 CRUD
    │       └── ScopeDAO.java           # 范围 CRUD
    │   ├── report/                      # 报告生成子系统
    │   │   ├── ReportGenerator.java     # 报告生成器抽象基类
    │   │   ├── PdfReportGenerator.java  # PDF 报告生成 (Apache PDFBox)
    │   │   ├── HtmlReportGenerator.java # HTML 报告生成 (FreeMarker)
    │   │   ├── MarkdownReportGenerator.java # Markdown 报告生成 (FreeMarker)
    │   │   ├── ReportExporter.java      # 报告导出调度
    │   │   ├── ReportData.java          # 报告数据模型
    │   │   ├── ReportContainerWriter.java # 报告容器序列化
    │   │   ├── ReportContainerReader.java # 报告容器反序列化
    │   │   ├── BodyRenderer.java        # Body 渲染器
    │   │   ├── BinaryContentRenderer.java # 二进制内容渲染 (hex/base64/图片)
    │   │   ├── CurlBuilder.java         # cURL 命令构建
    │   │   ├── PostmanSnippetBuilder.java # Postman 代码片段构建
    │   │   └── FreeMarkerConfig.java    # FreeMarker 配置
    │   ├── UserSessionYamlIO.java       # 用户会话 YAML 导入导出
    │   ├── TokenLocationYamlIO.java     # Token 位置 YAML 导入导出
    │   └── GlobalTokenLocationManager.java # 全局 Token 位置管理器
    ├── service/
    │   ├── AutoSaveService.java        # 自动保存服务
    │   ├── GarbageCollectorService.java # 垃圾回收服务（Pool 零引用清理）
    │   └── HistoryRecordingService.java # 历史记录录制服务（异步队列）
    ├── ui/
    │   ├── MainUI.java                 # 主 UI 界面
    │   ├── RequestListPanel.java       # 请求列表面板（搜索/过滤/颜色）
    │   ├── RequestPanel.java           # 请求详情面板
    │   ├── RequestPanelSender.java     # 请求发送处理器（Montoya API）
    │   ├── ResponsePanel.java          # 响应面板
    │   ├── LogPanel.java               # 日志面板
    │   ├── StatusPanel.java            # 底部状态栏
    │   ├── editor/
    │   │   ├── BurpRequestPanel.java   # Montoya HttpRequestEditor 封装
    │   │   ├── BurpResponsePanel.java  # Montoya HttpResponseEditor 封装
    │   │   ├── HttpEditorPanel.java    # HTTP 编辑器面板基类
    │   │   ├── EnhancedRequestPanel.java  # 增强请求面板
    │   │   ├── EnhancedResponsePanel.java # 增强响应面板
    │   │   └── HttpViewerPanel.java    # HTTP 查看器面板
    │   ├── viewer/
    │   │   ├── HttpViewer.java         # HTTP 查看器
    │   │   ├── HttpViewerPanel.java    # HTTP 查看器面板
    │   │   └── ViewMode.java           # 查看模式枚举
    │   ├── config/
    │   │   ├── ConfigPanel.java        # 多标签页配置面板
    │   │   ├── StorageConfigTab.java   # 存储配置标签页
    │   │   ├── ApiRuleConfigTab.java   # API 提取规则配置标签页
    │   │   ├── ApiRuleEditDialog.java  # 规则编辑对话框
    │   │   ├── ApiRuleTableModel.java  # 规则表格模型
    │   │   └── ApiReExtractWorker.java # 规则重提取后台 Worker
    │   ├── history/
    │   │   ├── HistoryPanel.java       # 历史记录面板（搜索/过滤/多选）
    │   │   ├── HistoryContextMenu.java # 历史记录右键菜单（批量操作、报文比对）
    │   │   ├── HistoryTableRenderer.java # 历史表格渲染器
    │   │   ├── AdvancedSearchDialog.java # 高级搜索对话框
    │   │   ├── ColumnControlDialog.java  # 列控制对话框
    │   │   ├── ComparisonDialog.java   # 报文比对对话框（标签页/四分格布局）
    │   │   ├── DiffEngine.java         # 差异算法引擎（基于 LCS，行内字符级差异）
    │   │   ├── DiffPane.java           # 自包含差异显示面板 (RSyntaxTextArea)
    │   │   ├── DiffNavigator.java      # 差异区域导航器（上/下一处差异）
    │   │   ├── SearchBar.java          # 可折叠搜索栏（差异化内容搜索）
    │   │   └── SynchronizedScrollPanel.java # 同步滚动面板（并排对比联动）
    │   ├── layout/
    │   │   └── LayoutManager.java      # 布局管理器
    │   └── privilege/                  # 越权测试 UI
    │       ├── PrivilegeTestPanel.java # 越权测试主面板
    │       ├── SessionConfigTab.java   # 用户会话配置标签页
    │       ├── JudgmentRuleConfigTab.java # 判断规则配置标签页
    │       ├── ScopeConfigTab.java     # 范围配置标签页
    │       ├── UserSessionTableModel.java
    │       ├── JudgmentRuleTableModel.java
    │       ├── TokenLocationTableModel.java
    │       ├── UserSessionEditDialog.java
    │       ├── JudgmentRuleEditDialog.java
    │       ├── TokenLocationEditDialog.java
    │       └── TokenValueCellRenderer.java # Token 值单元格渲染器
    ├── RequestDispatchHandler.java     # 统一请求调度处理器
    └── utils/
        ├── TextLineNumber.java         # 文本行号工具
        └── FileChooserHelper.java      # 统一文件选择器工具
```

## 项目依赖

| 依赖 | 版本 | Maven 坐标 | 说明 |
|------|------|-----------|------|
| Montoya API | 2025.12 | `net.portswigger.burp.extensions:montoya-api` | 现代 Burp Suite 扩展接口（provided scope） |
| RSyntaxTextArea | 3.3.3 | `com.fifesoft:rsyntaxtextarea` | 语法高亮编辑器组件 |
| SQLite JDBC | 3.42.0.0 | `org.xerial:sqlite-jdbc` | SQLite JDBC 驱动 |
| HikariCP | 5.0.1 | `com.zaxxer:HikariCP` | 数据库连接池（声明但未使用，项目使用自定义连接池） |
| Gson | 2.10.1 | `com.google.code.gson:gson` | JSON 序列化/反序列化 |
| SnakeYAML | 2.2 | `org.yaml:snakeyaml` | YAML 序列化（API 提取规则、判断规则、用户会话、Token 位置） |
| Commons IO | 2.11.0 | `commons-io:commons-io` | Apache 文件操作工具 |
| Commons Lang3 | 3.12.0 | `org.apache.commons:commons-lang3` | Apache 通用工具类 |
| Apache PDFBox | 3.0.1 | `org.apache.pdfbox:pdfbox` | 原生 PDF 报告生成（内嵌中文字体） |
| FreeMarker | 2.3.33 | `org.freemarker:freemarker` | HTML/Markdown 报告模板渲染 |
| CommonMark | 0.22.0 | `org.commonmark:commonmark` | Markdown 转 HTML（使用教程渲染） |

## 编译与构建

项目使用 Maven 进行构建：

```bash
# 使用构建脚本
./script/build.sh        # Linux/macOS
script\build.bat         # Windows

# 或直接使用 Maven
mvn clean package
```

构建产物：
- 开发版本: `target/repeater-manager-2.16.2.jar`
- 带时间戳发布版本: `target/releases/repeater-manager-2.16.2-YYYYMMDD-HHMMSS.jar`

## 使用场景

1. **API 安全测试**：持续测试同一 API 的不同参数组合，并保存所有测试结果
2. **API 路径整理**：配合 API 提取引擎，从大量不规则请求中自动提取标准 API 路径列表
3. **越权漏洞检测**：配置多用户会话，自动检测水平/垂直越权漏洞
4. **漏洞复现**：记录漏洞利用过程中的所有请求和响应，便于后期复现
5. **安全评估**：整理大型应用的 API 集合，系统化进行安全测试
6. **团队协作**：通过 ERM 存档和全局 YAML 规则实现团队间的数据与规则共享
7. **渗透测试记录**：记录渗透测试过程中的关键请求，便于编写报告

## 数据持久化说明

### 存储模式

| 模式 | 说明 |
|------|------|
| 自动（默认） | 在 `~/.burp/` 下自动创建以时间戳命名的会话目录 |
| 指定目录 | 在指定目录下创建以时间戳命名的会话目录 |
| 指定文件 | 直接使用指定的数据库文件，不创建时间戳子目录 |

### 会话目录结构

```
~/.burp/
├── repeater_manager_config.properties     # 插件配置文件
├── repeater_manager/
│   └── api_extraction_rules.yaml          # 全局 API 提取规则（跨会话共享）
└── session_20240101_120000/               # 会话目录（时间戳命名）
    ├── repeater_manager.sqlite3           # SQLite 数据库文件
    ├── blobs/                             # 外置 Body 数据目录
    └── logs/                              # 日志文件目录
```

### Pool 去重架构

数据库采用 Pool 架构实现内容去重存储，通过 SHA-256 哈希 + 引用计数管理：

- **string_pool**: 域名/路径/查询参数等字符串去重
- **header_pool**: HTTP 请求/响应头部去重
- **body_pool**: 小体积 Body 数据去重（行内存储，SQLite BLOB）
- **file_pool**: 大体积 Body 数据去重（文件外置存储，blobs/ 目录）
- **gc_queue**: 垃圾回收队列，自动清理零引用数据

### API 提取规则存储

- **全局规则**: 存储在 `~/.burp/repeater_manager/api_extraction_rules.yaml`，跨会话共享，使用负数 ID
- **项目规则**: 存储在会话 SQLite 数据库的 `api_extraction_rules` 表中，使用正数 ID
- 规则优先级：全局规则和项目规则按 priority 排序，first-match-wins 策略

## 开发计划

- [x] 报文比对功能（v2.15.0 新增，v2.16.0 增强）
- [x] 报告生成功能（v2.10.0 新增 PDF/HTML/Markdown 格式）
- [x] 批量操作支持（v2.13.0 新增）
- [ ] 添加请求序列功能，支持多步骤请求流程
- [ ] 添加请求模板功能，快速创建类似请求
- [ ] 支持更多数据格式的导入导出
- [ ] 添加团队规则共享云端同步功能

## 贡献指南

欢迎提交 Issue 和 Pull Request。请确保：

1. 代码风格与现有代码一致（遵循 Java 17 规范）
2. 新功能需附带说明
3. 使用 Montoya SDK API（不使用 legacy Burp Extender API）
4. 提交前运行 `mvn clean package` 确保构建成功

## 许可证

本项目使用 [Apache License 2.0](LICENSE) 许可证。

## 安全免责声明

本项目仅供合法的安全测试和研究使用。详见 [SECURITY.md](SECURITY.md)。
