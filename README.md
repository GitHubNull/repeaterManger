# Repeater Manager - Burp Suite 请求重放管理插件

<p align="center">
  <strong>面向安全测试人员的 Burp Suite 高级请求重放管理插件</strong>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> | 中文
</p>

---

## 项目介绍

Repeater Manager 是一个为 Burp Suite Professional 设计的高级 HTTP 请求重放管理插件。它提供了比原生 Repeater 更强大的功能，包括请求的分类管理、响应历史自动记录与比对、SQLite 本地持久化、内容去重存储、多条件高级搜索、多种格式导入导出（ERM 加密存档 / Postman Collection）以及定时自动保存防丢机制。本插件特别适合安全测试人员和渗透测试专家使用，可有效提高 HTTP/HTTPS 请求测试的效率和组织性。

> **当前版本**: v1.5.1 | **最低要求**: Burp Suite Professional + Java 8+

## 核心功能

| 功能 | 说明 |
|------|------|
| 请求管理 | 组织和分类 HTTP 请求，支持颜色标记和备注功能 |
| 历史记录 | 自动记录每次请求的响应历史，方便比对不同时间的测试结果 |
| 数据持久化 | 所有请求和历史记录保存到 SQLite 数据库，重启 Burp Suite 后不会丢失 |
| 内容去重存储 | 采用 Pool 架构（字符串池/头部池/Body池/文件池），自动去重节省存储空间 |
| 高级搜索 | 支持多条件复合筛选，快速定位特定请求或响应 |
| 列显示控制 | 自定义表格中显示的列，提高信息密度和可读性 |
| 数据导入导出 | 支持 ERM 加密存档、Postman Collection v2.1 等多种格式 |
| 自动保存 | 定时将内存中的数据同步到磁盘，防止数据丢失 |
| 垃圾回收 | 后台自动清理零引用的池数据，回收存储空间 |
| 日志系统 | 多通道日志输出（Burp 控制台/滚动文件/UI 面板），支持级别过滤 |
| 代理调试 | 支持配置 HTTP 代理用于调试请求 |
| 布局切换 | 请求/响应面板支持左右、上下、仅请求、仅响应四种布局模式 |

## 功能架构

```
Repeater Manager
├── 插件集成（Burp Extender API）
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
│   └── 历史回放与比对
├── 数据持久化
│   ├── SQLite 存储
│   ├── 内容分片（Pool 去重架构）
│   ├── 文件存储（大 Body 外置）
│   └── 哈希校验
├── 导入导出
│   ├── ERM 存档（支持 AES-256 加密）
│   ├── Postman Collection v2.1
│   └── 智能格式检测
├── 后台服务
│   ├── 自动保存服务
│   ├── 垃圾回收服务
│   └── 历史记录录制服务
├── 日志系统
│   ├── Burp 控制台输出
│   ├── 滚动文件日志
│   └── UI 日志面板
└── 配置管理
    ├── 存储配置（自动/指定目录/指定文件）
    ├── 日志配置
    └── 代理配置
```

## 安装方法

### 前置条件

- Burp Suite Professional
- Java 8 或更高版本

### 安装步骤

1. 从 [Releases](../../releases) 页面下载最新的 JAR 文件
2. 打开 Burp Suite Professional
3. 转到 `Extender` → `Extensions` 选项卡
4. 点击 `Add` 按钮
5. 在 `Extension file` 中选择下载的 JAR 文件
6. 点击 `Next` 完成安装

> 首次加载后，插件会自动在 `~/.burp/` 目录下创建会话目录（以时间戳命名），内含数据库文件、Body 数据目录和日志目录。

## 快速开始

1. 在 Burp Suite 的任何位置（如 Proxy、Intruder），右键点击请求
2. 选择 **"发送到 Repeater Manager"**
3. 切换到 **"Repeater Manager"** 标签页查看和管理请求
4. 编辑请求内容，点击 **"发送"** 按钮重放
5. 在左侧下方的历史记录面板查看每次重放的响应

详细使用说明请参考：
- [快速入门教程](doc/usage_quick_zh.md)
- [详细使用教程](doc/usage_detailed_zh.md)

## 技术架构

```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager
+---------------------+
|   Data Storage      |  SQLite + File Blobs
+---------------------+
```

**核心技术栈**：

- **前端界面**: Java Swing（含 RSyntaxTextArea 语法高亮组件）
- **数据存储**: SQLite（JDBC v3.42.0.0）+ HikariCP 连接池（v5.0.1）
- **序列化**: Gson（v2.10.1）
- **核心模式**: MVC 架构、单例模式、观察者模式、Pool 去重模式

## 项目结构

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Burp 扩展入口点
└── oxff/top/
    ├── RepeaterManagerUI.java          # 主 UI 控制器
    ├── config/
    │   ├── DatabaseConfig.java         # 数据库配置（存储模式/日志/代理）
    │   └── SessionDirectory.java       # 会话目录管理
    ├── controller/
    │   └── PopMenu.java               # 右键菜单（"Send to Repeater Manager"）
    ├── db/
    │   ├── DatabaseManager.java        # 数据库连接管理（连接池/Schema初始化）
    │   ├── HistoryDAO.java             # 历史记录数据访问对象
    │   ├── RequestDAO.java             # 请求数据访问对象
    │   └── pool/
    │       ├── PoolManager.java        # Pool 去重管理器
    │       ├── BodyStorageRoute.java   # Body 存储路由（inline/file）
    │       ├── ContentHasher.java      # 内容哈希计算
    │       ├── ContentSplitter.java    # 请求/响应内容分割
    │       ├── ContentReconstructor.java # 内容重建
    │       ├── FileStorageManager.java # 文件型 Body 存储
    │       ├── HttpEnum.java           # HTTP 枚举类型
    │       └── SplitResult.java        # 分割结果
    ├── http/
    │   ├── ProxyConfig.java            # HTTP 代理配置
    │   ├── RequestManager.java         # HTTP 请求管理（异步发送）
    │   └── RequestResponseRecord.java  # 请求响应记录模型
    ├── io/
    │   ├── DataExporter.java           # 导出调度器
    │   ├── DataImporter.java           # 导入调度器（智能格式检测）
    │   ├── ErmArchiveWriter.java       # ERM 存档导出（AES-256 加密）
    │   ├── ErmArchiveReader.java       # ERM 存档导入
    │   ├── ErmCryptoHelper.java        # ERM 加密辅助（PBKDF2/AES-CBC/HMAC）
    │   ├── ErmFormatConstants.java     # ERM 格式常量
    │   ├── FormatDetector.java         # 格式自动检测
    │   ├── PostmanExporter.java        # Postman Collection 导出
    │   └── PostmanImporter.java        # Postman Collection 导入
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
    ├── service/
    │   ├── AutoSaveService.java        # 自动保存服务
    │   ├── GarbageCollectorService.java # 垃圾回收服务（Pool 零引用清理）
    │   └── HistoryRecordingService.java # 历史记录录制服务（异步队列）
    ├── ui/
    │   ├── BurpRequestPanel.java       # Burp 风格请求编辑面板
    │   ├── BurpResponsePanel.java      # Burp 风格响应展示面板
    │   ├── ConfigPanel.java            # 配置面板（存储/日志/代理/导入导出）
    │   ├── EnhancedRequestPanel.java   # 增强请求面板
    │   ├── EnhancedResponsePanel.java  # 增强响应面板
    │   ├── HistoryPanel.java           # 历史记录面板
    │   ├── HttpEditorPanel.java        # HTTP 编辑器面板基类
    │   ├── HttpViewerPanel.java        # HTTP 查看器面板
    │   ├── LogPanel.java               # 日志面板
    │   ├── MainUI.java                 # 主 UI 界面
    │   ├── RequestListPanel.java       # 请求列表面板
    │   ├── RequestPanel.java           # 请求详情面板
    │   ├── ResponsePanel.java          # 响应面板
    │   ├── StatusPanel.java            # 底部状态栏
    │   ├── viewer/
    │   │   ├── HttpViewer.java         # HTTP 查看器
    │   │   ├── HttpViewerPanel.java    # HTTP 查看器面板
    │   │   └── ViewMode.java           # 查看模式枚举
    │   └── layout/
    │       └── LayoutManager.java      # 布局管理器（左右/上下/仅请求/仅响应）
    └── utils/
        └── TextLineNumber.java         # 文本行号工具
```

## 项目依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| burp-extender-api | 2.1 | Burp Suite 扩展 API |
| rsyntaxtextarea | 3.3.3 | 语法高亮编辑器组件 |
| sqlite-jdbc | 3.42.0.0 | SQLite JDBC 驱动 |
| HikariCP | 5.0.1 | 高性能数据库连接池 |
| gson | 2.10.1 | JSON 序列化/反序列化 |
| commons-io | 2.11.0 | Apache 文件操作工具 |
| commons-lang3 | 3.12.0 | Apache 通用工具类 |

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
- 开发版本: `target/repeater-manager-1.5.1.jar`
- 带时间戳发布版本: `target/releases/repeater-manager-1.5.1-YYYYMMDD-HHMMSS.jar`

## 使用场景

1. **API 安全测试**：持续测试同一 API 的不同参数组合，并保存所有测试结果
2. **漏洞复现**：记录漏洞利用过程中的所有请求和响应，便于后期复现
3. **安全评估**：整理大型应用的 API 集合，系统化进行安全测试
4. **团队协作**：通过 ERM 存档导出测试数据，分享给团队其他成员继续测试
5. **渗透测试记录**：记录渗透测试过程中的关键请求，便于编写报告
6. **报告编写**：导出为 Postman Collection 格式，方便与报告工具集成

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
└── session_20240101_120000/     # 会话目录（时间戳命名）
    ├── repeater_manager.sqlite3 # SQLite 数据库文件
    ├── blobs/                   # 外置 Body 数据目录
    └── logs/                    # 日志文件目录
```

### Pool 去重架构

数据库采用 Pool 架构实现内容去重存储：

- **string_pool**: 域名/路径/查询参数等字符串去重
- **header_pool**: HTTP 请求/响应头部去重
- **body_pool**: 小体积 Body 数据去重（行内存储）
- **file_pool**: 大体积 Body 数据去重（文件外置存储）
- **gc_queue**: 垃圾回收队列，自动清理零引用数据

## 开发计划

- [ ] 添加团队共享功能，支持多人协作
- [ ] 集成自动化测试脚本支持
- [ ] 提供请求模板功能，快速创建类似请求
- [ ] 支持更多数据格式的导入导出
- [ ] 添加请求序列功能，支持多步骤请求流程

## 贡献指南

欢迎提交 Issue 和 Pull Request。请确保：

1. 代码风格与现有代码一致
2. 新功能需附带说明
3. 提交前运行 `mvn clean package` 确保构建成功

## 许可证

本项目使用 [Apache License 2.0](LICENSE) 许可证。

## 安全免责声明

本项目仅供合法的安全测试和研究使用。详见 [SECURITY.md](SECURITY.md)。
