# 基础级开发指南

> 面向初次接触本项目的新贡献者

---

## 目录

- [1. 开发环境搭建](#1-开发环境搭建)
- [2. 项目导入 IDEA](#2-项目导入-idea)
- [3. 构建与打包](#3-构建与打包)
- [4. 项目结构总览](#4-项目结构总览)
- [5. 编码约定](#5-编码约定)
- [6. 插件安装与调试](#6-插件安装与调试)
- [7. 版本号管理](#7-版本号管理)

---

## 1. 开发环境搭建

### 1.1 必需组件

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| JDK | 17+ | 项目 source/target 兼容 Java 17 |
| Maven | 3.6+ | 构建工具 |
| Burp Suite Professional | 2024.1+ | 目标运行平台（Community 版不支持扩展） |
| Git | 任意版本 | 版本控制 |

### 1.2 克隆仓库

```bash
# 克隆主仓库（含子模块）
git clone --recurse-submodules https://github.com/GitHubNull/repeaterManger.git
cd repeaterManger

# 如果已克隆主仓库，手动初始化子模块
git submodule update --init --recursive
```

> 子模块 `oversteplab/` 包含越权测试靶场项目，用于功能验证测试。

---

## 2. 项目导入 IDEA

1. 打开 IntelliJ IDEA → `File` → `Open`
2. 选择项目根目录（包含 `pom.xml`）
3. 选择 "Open as Project"
4. IDEA 自动识别 Maven 项目并加载依赖

> 注意：Montoya API 依赖 scope 为 `provided`，IDEA 会自动识别但打包时不会包含。

---

## 3. 构建与打包

### 3.1 构建命令

```bash
# Windows
script\build.bat

# Linux/macOS
./script/build.sh

# 直接使用 Maven
mvn clean package
```

### 3.2 构建产物

| 文件 | 路径 | 说明 |
|------|------|------|
| 开发版本 | `target/repeater-manager-{version}.jar` | 可直接在 Burp 中加载 |
| 发布版本 | `target/releases/repeater-manager-{version}-{timestamp}.jar` | 带时间戳的发布包 |

### 3.3 构建流程说明

项目使用 `maven-assembly-plugin` 打包为 `jar-with-dependencies`，将所有第三方依赖（除 Montoya API 外）打包进单个 JAR：

- Montoya API（provided scope）— 由 Burp Suite 运行时提供
- RSyntaxTextArea、SQLite JDBC、Gson、SnakeYAML、PDFBox、FreeMarker、CommonMark — 打包进 JAR
- `doc/tutorials/*.md` — 作为资源打包进 JAR，供内置使用教程面板加载

---

## 4. 项目结构总览

```
repeaterManger/
├── oversteplab/                  # Git 子模块：越权测试靶场
├── src/main/java/org/oxff/repeater/
│   ├── api/                      # API 提取子系统
│   ├── config/                   # 配置管理（数据库/会话）
│   ├── controller/               # 右键菜单等控制逻辑
│   ├── db/                       # 数据库访问层（DAO/Pool/Schema）
│   ├── http/                     # HTTP 请求处理
│   ├── io/                       # 数据导入导出（ERM/Postman）
│   ├── logging/                  # 日志子系统
│   ├── model/                    # 数据模型
│   ├── privilege/                # 越权测试子系统
│   │   ├── model/                # 越权测试数据模型
│   │   ├── dao/                  # 越权测试 DAO
│   │   └── report/               # 报告生成子系统
│   ├── service/                  # 后台服务（自动保存/GC/历史录制）
│   ├── ui/                       # UI 组件（Swing）
│   │   ├── editor/               # 编辑器组件
│   │   ├── history/              # 历史面板（含报文比对）
│   │   ├── config/               # 配置面板
│   │   ├── layout/               # 布局管理
│   │   └── privilege/            # 越权测试 UI
│   ├── utils/                    # 工具类
│   ├── RepeaterManagerExtension.java  # 插件入口（Montoya BurpExtension）
│   └── RepeaterManagerUI.java         # 主 UI 控制器
├── src/main/resources/
│   └── templates/report/         # FreeMarker 报告模板
├── doc/                          # 项目文档
│   ├── tutorials/                # 使用教程
│   ├── development/              # 开发文档
│   ├── design/                   # 架构设计文档
│   ├── reports/                  # 分析报告
│   └── ...
├── pom.xml                       # Maven 构建配置
└── README.md                     # 项目介绍
```

### 4.1 分层架构

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

---

## 5. 编码约定

### 5.1 Java 版本

- 使用 Java 17 语法特性（Lambda、文本块、密封类、记录类等）
- 避免使用 Java 17+ 预览特性

### 5.2 Montoya SDK

- **必须**使用 `burp.api.montoya.*` Montoya SDK
- **禁止**使用旧的 `burp.I*` Legacy API（如 `IBurpExtender`、`IBurpExtenderCallbacks`）
- 入口类实现 `BurpExtension` 接口
- 使用 `ByteArray.byteArray(bytes)` 包装原始 `byte[]`

### 5.3 Swing UI 线程

- **所有 UI 操作必须在 EDT 中执行**
- 使用 `SwingUtilities.invokeLater(() -> { ... })` 从后台线程更新 UI
- 长时间操作（HTTP 请求、数据库查询）在后台线程执行

### 5.4 数据库访问

- 通过 DAO 类访问数据库
- 使用 `try-with-resources` 管理连接（连接池自动回收）
- SQLite 写操作需串行化（SQLite 限制）

### 5.5 日志

- 使用 `LogManager.getInstance().log(level, message)` 输出日志
- 日志级别：DEBUG / INFO / SUCCESS / WARN / ERROR

### 5.6 单例模式

以下类使用单例模式：
- `DatabaseManager`
- `LogManager`
- `HistoryRecordingService`
- `ProxyConfig`
- `GlobalRuleManager`

### 5.7 MontoyaApi 访问

- **优先使用构造函数注入** 传入 `MontoyaApi`
- 静态上下文使用 `MontoyaApiHolder.getApi()` 作为兜底

### 5.8 API 规则 ID

- 全局规则：负数 ID
- 项目规则：正数 ID（SQLite 自增）

---

## 6. 插件安装与调试

### 6.1 加载开发版本

1. 执行 `mvn clean package` 构建
2. 打开 Burp Suite Professional
3. `Extensions` → `Installed` → `Add`
4. 选择 `target/repeater-manager-{version}.jar`
5. 点击 `Next` 完成加载
6. 在 Burp 输出面板查看加载日志

### 6.2 调试技巧

- **输出面板**：插件使用 `BurpConsoleHandler` 输出到 Burp 控制台
- **日志面板**：插件内置 LogPanel 标签页，实时显示运行日志
- **日志文件**：查看会话目录 `logs/` 下的滚动日志文件
- **重新加载**：修改代码后，重新执行 `mvn clean package`，在 Burp 中移除旧插件并加载新 JAR

### 6.3 会话数据

- 首次加载自动在 `~/.burp/` 下创建会话目录（时间戳命名）
- 每次重新加载创建新会话，旧会话数据保留
- 可通过 ERM 存档跨会话迁移数据

---

## 7. 版本号管理

项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范：

- **MAJOR**：不兼容的 API 变更
- **MINOR**：向后兼容的功能新增
- **PATCH**：向后兼容的问题修复

版本号在 `pom.xml` 的 `<version>` 标签中定义。GitHub Actions 自动发布流程在推送 `v*` 标签时触发。

---

> 下一步：阅读 [intermediate-level.md](intermediate-level.md) 了解核心架构实现细节。
