# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.8.0] - 2026-05-09

### Added
- 新增 UserSessionYamlIO 工具类，支持用户会话的 YAML 序列化/反序列化与原子文件写入
- 新增用户会话导出功能：将用户会话及令牌值导出为 YAML 文件
- 新增用户会话导入功能：支持合并导入（按名称去重）和替换导入两种模式
- SessionManager 新增 `importUserSessionsMerge()` 和 `importUserSessionsReplace()` 方法
- SessionConfigTab 新增导入/导出按钮，集成文件选择器和导入模式选择对话框
- SessionConfigTab 新增鼠标右键点击时自动选中行的交互优化

## [2.7.0] - 2026-05-09

### Added
- 新增全局令牌位置管理器（GlobalTokenLocationManager），支持令牌位置跨项目持久化到 ~/.burp/repeater_manager/token_locations.yaml
- 新增 TokenLocationYamlIO 工具类，实现令牌位置的 YAML 序列化/反序列化与原子文件写入
- SessionManager 新增全局YAML同步逻辑：增删改令牌位置时自动同步到全局配置
- 启动时自动加载全局令牌位置到项目数据库（自动按 type+expression 去重）
- SessionConfigTab 令牌位置表格新增双击编辑功能

### Fixed
- 移除 ReportGenerator 中未使用的 sessionBreakdowns 变量

## [2.6.0] - 2026-05-09

### Added
- 新增权限测试报告生成系统，支持 HTML、Markdown、PDF 三种格式导出
- 新增 ReportGenerator 报告生成器接口及多格式实现（HtmlReportGenerator、MarkdownReportGenerator、PdfReportGenerator）
- 新增 ReportData 数据模型，封装报告元数据、摘要、端点统计和会话分析
- 新增 ReportExporter 统一导出入口，自动根据文件扩展名选择格式
- 新增 CurlBuilder，生成 curl 命令片段用于报告中的请求复现
- 新增 PostmanSnippetBuilder，生成 Postman 代码片段用于报告中的请求复现
- 新增 PDFBox 依赖，支持原生 PDF 报告生成
- 历史记录 DAO（HistoryReadDAO）新增按请求 ID 批量查询方法
- 请求分发处理器新增权限测试模式支持
- 主界面和状态面板新增权限测试相关 UI 集成
- PrivilegeTestPanel 新增报告导出交互入口

## [2.5.1] - 2026-05-09

### Changed
- 优化 AutoTestEngine：内联 sendSync 替代反射调用 ReplayEngine 私有方法

### Fixed
- 自动化测试请求失败时增强错误信息捕获与日志输出

## [2.5.0] - 2026-05-09

### Added
- 新增使用教程面板（UsageTutorialPanel），支持中英文切换和快速入门/详细教程切换
- 新增关于面板（AboutPanel），展示项目元数据、版本信息和技术栈
- 新增 CommonMark 依赖，支持 Markdown 转 HTML 渲染（含 GFM 表格扩展）
- Maven 构建配置新增 doc 目录资源打包，支持插件内嵌入文档

### Removed
- 移除临时文件 doc/todo/todo1.md 和 doc/todo/todo2.md

## [2.4.1] - 2026-05-09

### Changed
- 重构 README.md 快速开始章节，结构更清晰
- 重写中英文快速使用指南和详细使用教程，内容更完整、排版更规范

### Fixed
- 移除 ConfigPanel 中未使用的 `burp.BurpExtender` import
- 移除 SessionConfigTab 中多余的 `@SuppressWarnings("unchecked")` 注解

## [2.4.0] - 2026-05-09

### Added
- 新增数据面板（DataPanel），从配置面板中拆分数据管理功能
- TokenLocation 新增 `persistToGlobal`（持久化到全局）和 `enabled`（启用）字段
- 数据库 Schema v10 迁移，为 token_locations 表添加 persist_to_global 和 enabled 列
- TokenLocationEditDialog 新增持久化到全局和启用复选框
- TokenLocationTableModel 新增持久化到全局和启用列
- SessionConfigTab 新增令牌位置的 JSON 导入/导出功能

### Changed
- ConfigPanel 中的数据管理功能拆分至独立的 DataPanel
- SessionManager 和 SessionDAO 适配 TokenLocation 新字段

## [2.3.0] - 2026-05-08

### Added
- 历史记录面板新增"越权测试"列，显示请求是否为越权测试请求
- 高级搜索对话框新增越权测试状态过滤功能
- 越权测试列渲染器，"是"显示绿色高亮
- 数据库Schema扩展，新增越权测试相关字段及迁移支持
- `setRequest` 方法返回数据库生成的请求ID，支持越权测试请求标记

### Changed
- 历史记录表格列索引调整（备注列从第11列移至第14列）
- 列宽配置优化（用户列、判决列、越权测试列、备注列）
