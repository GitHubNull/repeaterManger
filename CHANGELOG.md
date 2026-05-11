# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.15.0] - 2026-05-12

### Added
- 新增报文比对功能（ComparisonDialog），支持基线记录与会话记录的并排比对
- 新增 DiffEngine 差异比较引擎，支持 HTTP 报文行级 diff 高亮显示
- 新增 SynchronizedScrollPanel 同步滚动面板，比对时左右面板联动滚动
- 新增 RequestColumnControlDialog 列显示控制对话框，支持自定义请求列表列可见性和宽度
- 新增 RequestListContextMenu 请求列表右键菜单类
- 新增 RequestListTableRenderer 表格渲染器，支持备注列等自定义渲染
- RequestListPanel 新增备注列，支持通过注释同步更新表格显示
- RequestListPanel 新增列显示控制按钮
- HistoryContextMenu 新增"比对报文"右键菜单项
- HistoryReadDAO 新增 getBaselineRecord 方法，获取指定请求的基线记录
- TokenReplacementEngine 增强，支持更多 Token 位置类型替换
- TokenLocationType 新增枚举值

## [2.14.0] - 2026-05-11

### Added
- 新增 FileChooserHelper 统一文件选择器工具类，支持打开/保存/目录三种对话框类型
- 新增文件选择器操作类型枚举（OP_ERM_IMPORT, OP_POSTMAN_IMPORT, OP_RESPONSE_SAVE 等），支持按操作类型记忆上次浏览目录
- RequestListPanel 新增可折叠高级搜索面板，支持按 URL/Header/Body 范围搜索
- RequestListPanel 新增搜索配置类 SearchConfig，支持关键词/正则/大小写敏感等搜索选项

### Changed
- 重构 DataImporter/ErmArchiveReader/ErmArchiveWriter/PostmanExporter/PostmanImporter，使用 FileChooserHelper 替代原生 JFileChooser
- 重构 ReportContainerReader/ReportExporter，使用 FileChooserHelper 统一文件对话框
- 重构 LogPanel/ResponsePanel/ConfigPanel/StorageConfigTab，使用 FileChooserHelper 替代原生 JFileChooser
- 重构 SessionConfigTab 令牌位置导出、用户会话导入/导出，使用 FileChooserHelper 替代原生 JFileChooser
- 重构 ApiRuleConfigTab/JudgmentRuleConfigTab，使用 FileChooserHelper 替代原生 JFileChooser
- 重构 BurpResponsePanel/EnhancedResponsePanel，使用 FileChooserHelper 替代原生 JFileChooser

## [2.13.0] - 2026-05-11

### Added
- 历史面板新增多选模式（MULTIPLE_INTERVAL_SELECTION），支持 Shift/Ctrl 多行选择
- 历史面板右键菜单新增批量重放功能：逐条重放选中的多条历史记录
- 历史面板右键菜单新增批量权限测试功能：逐条对选中的多条记录进行越权测试
- 历史面板右键菜单新增批量删除功能：支持一次性删除多条历史记录（含数据库同步）
- 状态栏新增批量进度显示支持（showBatchProgress / clearBatchProgress）
- BurpExtender 新增批量请求入口方法（setRepeaterUIRequests / setPrivilegeTestRequests）

### Changed
- 重构代理右键菜单（PopMenu）：过滤无效请求，支持多选时批量发送到 Repeater Manager 和权限测试
- 重构历史面板右键菜单（HistoryContextMenu）：每次弹出时动态构建菜单项，根据选中数量自适应菜单文本
- 重构 RequestDispatchHandler：新增 batchPrivilegeTest 和 batchSendRequests 方法，使用 CountDownLatch 顺序处理
- 备注编辑后自动同步到数据库（HistoryUpdateDAO）

## [2.12.0] - 2026-05-11

### Added
- 新增 TokenValueCellRenderer 令牌值列渲染器，支持悬停 tooltip 查看完整令牌值

### Changed
- 重构 UserSessionEditDialog 令牌值编辑交互：单行 JTextField 替换为多行 JTextArea，支持行号显示、自动折行、右键上下文菜单（复制/粘贴/剪切/全选/清空）
- 优化 UserSession.getTokenValuesSummary() 令牌摘要：两层截断（单值30字符/整体80字符），换行符替换为可见符号保证表格渲染安全
- 优化令牌值摘要列宽与最小宽度配置

### Fixed
- TokenReplacementEngine 新增 sanitizeNewlines() 安全过滤，替换时将令牌值中的换行符转换为空格，防止 HTTP header 注入和 body 结构破坏

## [2.11.2] - 2026-05-11

### Changed
- 优化 PdfReportGenerator PDF 布局间距，增大各元素间 vertical spacing 与 ensureSpace 余量

## [2.11.1] - 2026-05-11

### Fixed
- PdfReportGenerator 新增 base64 长字符串截断逻辑，避免 PDF 页面被无意义编码撑满

### Changed
- 简化 ReportGenerator 端点迭代循环，移除未使用的 key 变量

## [2.11.0] - 2026-05-11

### Added
- 引入 FreeMarker 模板引擎，新增 FreeMarkerConfig 配置与 BodyRenderer 渲染器
- 新增 HTML/Markdown 报告 FreeMarker 模板（html_report.ftl / md_report.ftl / html_css.ftl）
- ReportData 新增请求/响应 body 预渲染字段（requestHtml/responseHtml/requestMd/responseMd）

### Changed
- 重构 HtmlReportGenerator，使用 FreeMarker 模板替代内联 HTML 拼接
- 重构 MarkdownReportGenerator，使用 FreeMarker 模板替代内联 Markdown 拼接
- 重构 PdfReportGenerator，优化二进制内容渲染与布局
- 增强 BinaryContentRenderer 分级渲染能力
- ReportGenerator 新增阶段 D：body 内容预渲染逻辑
- 精简 ReportGenerator 基类，移除已迁移到 BodyRenderer 的 sanitizeBody/isBinaryBody 等方法
- 优化 AutoTestEngine/BurpExtender/RepeaterManagerUI 相关逻辑

## [2.10.2] - 2026-05-10

### Fixed
- 修复 setPrivilegeTestRequest() 在权限测试模式下调用 setRequest() 导致双重重放的问题

## [2.10.1] - 2026-05-09

### Fixed
- 修正越权测试报告统计逻辑，基准（baseline）记录不再计入测试统计数据
- 修正非基准记录未关联基准信息的问题

### Changed
- 重构 ReportGenerator 统计逻辑，按阶段分组处理（端点分组→基准识别关联→修正计数）
- 增强 HtmlReportGenerator/MarkdownReportGenerator/PdfReportGenerator，支持基准记录的视觉标识与基准信息展示

## [2.10.0] - 2026-05-09

### Added
- 新增 BinaryContentRenderer 二进制内容渲染器，支持在报告中渲染图片等二进制响应内容
- 新增 ReportContainerReader/ReportContainerWriter，支持报告容器的序列化读写

### Changed
- 增强 HtmlReportGenerator/MarkdownReportGenerator/PdfReportGenerator，集成二进制内容渲染支持
- 增强 ReportExporter 和 ReportGenerator 接口，扩展报告导出能力
- 增强 PrivilegeTestPanel 面板交互与功能

## [2.9.0] - 2026-05-09

### Added
- 令牌位置表格和用户会话表格新增搜索/筛选功能，支持正则表达式和大小写匹配
- 表格列头排序功能，通过 TableRowSorter 实现点击列头排序

### Fixed
- 修复表格启用排序/筛选后，编辑、删除、启用切换等操作的视图行索引未转换为模型行索引的问题

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
