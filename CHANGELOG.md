# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.26.3] - 2026-06-29

### Fixed
- 判决引擎规则回退逻辑修正：所有规则不匹配时回退到默认判决（状态码+相似度），而非错误标记为安全
- 表格行颜色渲染器覆盖 Number 列：补充 `Number.class` 渲染器注册，修复 Swing `NumberRenderer` 绕过默认渲染器导致整数列无背景色的问题

### Changed
- 表格渲染器增强：新增透明背景色支持（alpha blending），基于行颜色标记生成半透明底色
- `TokenSchemeEditDialog` 布局重构：从 `GridBagLayout` 升级为 `BorderLayout`+`GridBagLayout` 组合，修复穿梭框左右面板等比例伸缩问题，窗口尺寸调整为 1052×684

## [2.26.2] - 2026-06-29

### Changed
- 清理未使用的 import 和局部变量：
  - `UIRequestDispatcher` 删除未使用的 `java.awt.*` import
  - `AutoTestEngine` 删除未使用的局部变量 `requestBytes`、`api`
  - `FetchRequestParser` 删除未使用的局部变量 `quote`
  - `SessionParserEngine` 删除未使用的 `TokenLocationType`、`NodeList` import
  - `HistoryStatsBar` 删除未使用的 `javax.swing.border.Border` import
  - `ParseSessionFromClipboardDialog` 添加 `@SuppressWarnings("unused")` 注解

## [2.26.1] - 2026-06-29

### Fixed
- 优化越权测试引擎与UI配置：
  - `AutoTestEngine` 精简重复逻辑，优化变量命名与流程控制
  - `JudgmentEngine` 增强判空与异常处理健壮性
  - `ReplayEngine` 优化重放逻辑与资源管理
  - `FreeMarkerConfig` 修复模板配置初始化问题
  - `JudgmentRuleConfigTab` 和 `ReplayConfigTab` 修正UI配置项绑定
- `RepeaterManagerUI` 优化面板布局与交互逻辑

### Changed
- 更新中文使用文档 (`usage_quick_zh.md`, `usage_detailed_zh.md`) 补充最新功能说明

## [2.26.0] - 2026-06-26

### Added
- 新增 Chrome DevTools fetch 格式报文解析支持：
  - 新增 `FetchRequestParser` 工具类，支持识别和转换 Chrome "Copy as fetch" / "Copy as fetch (Node.js)" 格式为原始 HTTP 报文
  - 支持自动检测剪贴板内容格式（原始 HTTP / fetch browser / fetch Node.js）
  - 支持单双引号、转义序列、嵌套对象等复杂 JS 语法解析
  - `ParseSessionWorker` 集成格式检测与转换流程，用户可直接粘贴 fetch 代码片段进行会话解析
- 新增 JUnit 5 单元测试依赖（`junit-jupiter` 5.10.0），为 `FetchRequestParser` 提供测试覆盖

## [2.25.3] - 2026-06-26

### Changed
- 重构 BurpExtender 入口类，消除 God Class 反模式：
  - 将插件生命周期逻辑提取到 `RepeaterManagerExtension`，`BurpExtender` 仅作为空壳代理
  - 将 UI 桥接方法提取到 `UIRequestDispatcher`，解耦入口类与 UI 操作
  - 将会话解析逻辑提取到 `SessionParser`，集中管理会话解析流程
- 删除 `burp.BurpExtender.java` 空壳文件：Montoya SDK 不强制要求类名/包名，直接以 `RepeaterManagerExtension` 作为插件入口
- 统一替换 `BurpExtender.printOutput/printError` 静态调用为 `LogManager.getInstance()` 实例调用

### Fixed
- `LogManager.printError` 新增已知无害错误信息过滤（IntelliJ 剪贴板相关 ClassNotFoundException）

## [2.25.2] - 2026-06-26

### Fixed
- 修复全局令牌方案持久化时未同步令牌位置信息的问题：
  - `GlobalTokenSchemeManager.saveSchemes/addScheme/removeScheme/syncScheme` 新增 `List<TokenLocation>` 参数，用于将 `tokenLocationId` 解析为 `type+expression` 写入全局 YAML
  - `SessionManager` 在删除/同步/保存方案令牌位置时，传入当前项目的令牌位置列表，确保全局 YAML 中持久化的方案包含完整的位置关联信息

## [2.25.1] - 2026-06-26

### Fixed
- 修复会话解析时无启用方案或方案不匹配导致无法继续的问题：新增 SelectSchemeDialog 对话框，允许用户手动选择并自动启用方案
- 修复 ParseSessionFromClipboardDialog 下拉框逻辑：移除"自动选择最佳方案"占位项，改为加载所有方案并默认选中已匹配方案
- 修复 ParseSessionWorker 在无匹配方案时直接跳过确认对话框的问题，增加用户交互选择流程

## [2.25.0] - 2026-06-26

### Added
- 启动时自动从全局YAML加载令牌方案到项目数据库，支持按名称去重避免重复插入

## [2.24.0] - 2026-06-24

### Fixed
- 修复 HistoryStatsBar 收缩/展开视图标签共享导致的显示异常：将共用 JLabel 拆分为独立的收缩视图和展开视图实例
- 修复统计面板方差显示错误：将"方差"修正为"标准差"，并计算 `Math.sqrt(data.getVariance())`

## [2.23.0] - 2026-06-22

### Changed
- 将项目包名从 `oxff.top` 重构为 `org.oxff.repeater`，统一包命名规范
- 改进构建脚本（build.bat/build.sh）：使用通配符匹配 JAR 文件名，不再硬编码版本号
- 同步 AGENT.md、CLAUDE.md 中的包名引用
- 同步 pom.xml、AboutPanel、ReportData 版本号至 2.23.0

## [2.22.4] - 2026-06-22

### Changed
- 将权限测试模式切换按钮替换为类 HTML 风格的 Switch 开关组件，并增加“普通模式/权限测试”状态标签
- 同步 pom.xml、AboutPanel、ReportData 版本号至 2.22.4

## [2.22.3] - 2026-06-21

### Fixed
- 修复批量越权测试概率性失败问题：
  - `sendSyncOnce` 超时不触发重试：超时后显式设置 `holder.errorMessage`，使 `sendSyncWithRetry` 重试逻辑正确触发
  - `makeHttpRequestAsync` 异步路径无超时控制：使用独立线程执行 `sendRequest`，主线程 `join(timeout)` 等待，超时中断线程并回调 `onFailure`，防止批量场景下累积阻塞线程
  - `ReplayEngine.useHttp2` 实例字段竞态：将 `useHttp2` 改为方法参数传递，避免并发 `replay()` 调用时协议标志被覆盖
  - `latch.await()` 无超时：批量重放中添加基于会话数和请求超时的动态超时，超时后跳过当前请求继续下一条

### Changed
- 同步 pom.xml 版本号至 2.22.3

## [2.22.2] - 2026-06-21

### Fixed
- 修复 HTTP/2 请求重放时降级为 HTTP/1.1 的问题：新增 httpVersionMap 跟踪每个请求的原始协议版本，重放时根据协议版本选择正确的构建方式
- 修复 HTTP/2 请求缺少伪头部（:method, :path, :scheme, :authority）导致服务端拒绝的问题：RequestManager.buildRequestToSend() 新增 HTTP/2 专用构建逻辑，构造伪头部并过滤 HTTP/1 专有头部（Host, Connection 等）
- 修复 RequestPanelSender 发送 HTTP/2 请求时未构造伪头部的问题：检测原始请求协议版本，HTTP/2 时使用 http2Request 重建请求
- 修复 ReplayEngine 重放时未传递 HTTP/2 标志的问题：replay 方法新增 useHttp2 参数，确保权限测试模式下的 HTTP/2 请求正确重放

### Changed
- 同步 pom.xml 版本号至 2.22.2

## [2.22.1] - 2026-06-19

### Fixed
- 修复 Content-Length 不一致导致 DB 与 UI 数据不同步的问题（BUG-006）：统一在发送前修正 Content-Length，使 DB 与 UI 使用同一份修正后的字节
- 修复响应头/体提取时 UTF-8 多字节字符导致字符索引与字节偏移错位的问题（BUG-007）：ReplayEngine.extractResponseHeaders/extractResponseBody 改为字节级查找分隔符
- 修复 GarbageCollectorService 引用计数统计遗漏 api_hash、resp_header_hash、resp_body_hash 的问题，避免 GC 误删仍被引用的池条目
- 修复 PoolManager 缓存命中但池条目已被 GC 回收时的空指针异常，增加 affected == 0 的守卫处理
- 修复 ContentReconstructor 中缓存过期条目未正确释放引用的问题

### Changed
- 同步 pom.xml 版本号至 2.22.1
- 同步 AboutPanel 版本号至 2.22.1
- 同步 ReportData pluginVersion 至 2.22.1

## [2.22.0] - 2026-06-16

### Added
- 新增插件全链路数据流分析文档（doc/data_flow_analysis.md），涵盖 MVC 架构、连接池、异步处理、Pool 去重、Montoya SDK 集成等技术原理

### Changed
- 同步 pom.xml 版本号至 2.22.0
- 同步 AboutPanel 版本号至 2.22.0
- 同步 ReportData pluginVersion 至 2.22.0

## [2.21.0] - 2026-05-30

### Added
- 新增令牌方案（TokenScheme）系统，支持多方案管理令牌位置，每个用户会话关联一个方案
- 新增 GlobalTokenSchemeManager 令牌方案管理器，支持方案 CRUD 及全局持久化（YAML）
- 新增 TokenSchemeYamlIO 方案序列化工具
- 新增 ReplayConfig 重放配置模型，从 SessionManager 中提取重放模式/相似度阈值/重试/延迟等参数
- 新增 ReplayConfigTab 重放配置独立面板
- 新增 TokenSchemeTab 令牌方案独立面板（含方案列表和编辑对话框）
- 新增 TokenLocationTab 令牌位置独立面板
- 新增 UserSessionTab 用户会话独立面板
- 数据库 schema 升级至 v11：新增 token_schemes/scheme_token_locations 表，user_sessions 增加 scheme_id 和重放配置列
- SchemaMigrator 新增 v10→v11 迁移逻辑，自动创建默认方案并关联现有数据

### Changed
- 重构 SessionConfigTab：拆分为 TokenSchemeTab、TokenLocationTab、UserSessionTab、ReplayConfigTab 四个独立 Tab
- SessionManager 新增令牌方案缓存和 CRUD 方法，重放配置委托至 ReplayConfig
- SessionDAO 扩展支持方案 CRUD、方案-令牌位置关联、用户会话 scheme_id 和重放配置字段
- UserSession 模型新增 schemeId/requestTimeout/maxConcurrent/retryCount/retryDelay/replayDelay 字段
- UserSessionEditDialog 支持方案选择和重放配置编辑
- AutoTestEngine/ReplayEngine 适配新的会话-方案关联机制

## [2.20.1] - 2026-05-30

### Fixed
- 修复域名+端口解析逻辑不一致问题，统一提取为 HttpRequestHelper.resolveDomainWithPort/resolveDomainFromService 方法，消除多处重复代码
- 修复 requestId <= 0 时 RequestManager 仍记录历史导致异常的问题，增加 requestId 守卫条件
- 修复基准用户请求失败时后续会话仍执行比对判决导致误判的问题，AutoTestEngine/ReplayEngine 基准失败后跳过判决并标记 ERROR
- 修复权限测试模式开启时 EDT 队列竞态导致 currentRequestId 被覆盖的问题

### Changed
- RequestListPanel 添加"基准报文表（原始报文）"标题边框，强化语义标识

## [2.20.0] - 2026-05-21

### Added
- 新增 DedupConfigManager 去重配置管理器，支持多规则优先级链式去重（按优先级遍历配置列表，首个成功提取即返回）
- 新增 DedupConfig 模型，封装去重策略/表达式/保留策略/优先级/存储类型，支持全局持久化与会话临时双存储
- 新增 DedupConfigYamlIO YAML 序列化工具，支持去重配置的全局持久化（~/.burp/repeater_manager/dedup_configs.yaml）
- 新增 DedupConfigTab 独立去重配置面板，从 SessionConfigTab 中拆分为独立 Tab，支持增删改查
- 新增 DedupConfigEditDialog 去重配置编辑对话框

### Changed
- 重构 SessionManager，移除内联 dedupStrategy/dedupExpression/dedupKeepPolicy/dedupEnabled 字段，职责转移至 DedupConfigManager
- 重构 SessionConfigTab，移除去重配置 UI 控件，重放配置面板精简为模式选择和相似度阈值
- 重构 ReplayEngine，去重检查从 SessionManager 单规则改为 DedupConfigManager 多规则优先级链式匹配
- BurpExtender 启动时自动加载全局去重配置

## [2.19.0] - 2026-05-21

### Added
- 新增 ApiDedupEngine API 去重引擎，支持 6 种可配置去重策略（PATH/API/JSON_BODY_FIELD/XML_BODY_FIELD/FORM_FIELD/URL_PARAM）
- 新增 DedupStrategy 枚举，定义去重策略类型及中文显示名称
- 新增 DedupKeepPolicy 枚举，定义重复请求保留策略（FIRST/LAST/MIDDLE）
- SessionConfigTab 重放配置面板新增去重标准、表达式字段、保留策略三个 UI 控件
- SessionManager 新增 dedupStrategy/dedupExpression/dedupKeepPolicy 字段及读写方法

### Changed
- ReplayEngine API 去重检查从硬编码 PATH 策略重构为调用 ApiDedupEngine 可配置策略
- AutoTestEngine 适配新去重引擎，支持策略回退（主策略失败时回退到 PATH 策略）

## [2.18.0] - 2026-05-21

### Added
- TokenReplacementEngine 空值语义增强：空令牌值时移除 JSON 属性 / XML 节点，而非设置空字符串，支持未授权测试场景（模拟请求中不存在此参数）
- 新增 removeJsonValueAtPath() 方法，支持按 JSON 路径递归移除属性或数组元素

### Fixed
- 修复 replaceHeader() 删除 Header 时遗留空白行的问题，重构为 List<String> 收集再 join 的方式
- XML Body 替换空值时，改为移除节点的文本内容子节点而非设置空文本

## [2.17.3] - 2026-05-21

### Changed
- 重构 RequestDispatchHandler DB 持久化为异步后台线程执行，避免 saveHistory 阻塞 EDT 导致 UI 卡顿
- 数据库连接池大小从 5 增至 15，提升批量越权测试场景并发 DB 写能力
- GarbageCollectorService 新增暂停/恢复机制，批量操作期间自动暂停 GC 避免抢占连接池
- RequestListPanel 新增静默退出批量添加模式（exitBatchModeQuiet），避免无效 DB 查询和告警

### Fixed
- 修复批量越权测试时 EDT 线程被 DB 写操作阻塞导致的 UI 转圈问题
- 修复 Maven 构建中 maven-antrun-plugin 1.8 弃用 tasks/echo 语法，升级至 3.1.0 并迁移至 target 语法

## [2.17.2] - 2026-05-20

### Added
- 越权模式切换时联动 ScopeConfigTab 自动测试复选框同步状态
- RequestListPanel 批量添加模式（batchAddMode），批量导入时静默日志输出
- RequestDispatchHandler 模式变更监听器（addModeChangeListener）

### Fixed
- 修复越权模式按钮切换后 ScopeConfigTab 复选框状态不同步问题
- 修复批量添加请求时产生大量噪音日志问题
- 修复 ScopeConfigTab 同步复选框状态时触发 ActionListener 递归调用问题

## [2.17.1] - 2026-05-20

### Changed
- 重构 AboutPanel，将关于页面 HTML 从内联代码提取为外部模板文件

### Removed
- 移除未使用的依赖：HikariCP 5.0.1、Apache Commons IO 2.11.0、Apache Commons Lang 3.12.0

## [2.17.0] - 2026-05-20

### Added
- 新增结构化响应相似度引擎 SimilarityEngine，替代原有单一 Levenshtein 距离算法
- 新增 JaccardSimilarityCalculator 通用文本相似度计算器
- 新增 JsonSimilarityCalculator JSON 结构化响应相似度计算器（基于 key 集合和值内容双重比对）
- 新增 XmlSimilarityCalculator XML 结构化响应相似度计算器（基于标签集合和文本内容双重比对）
- 新增 ContentTypeDetector 自动检测响应 Content-Type（支持 JSON/XML/表单/文本等类型）
- 新增 NoiseFilter 噪声过滤器，自动移除响应中的时间戳、随机数等动态内容
- ReplayEngine 新增 API 去重检查，避免同一接口重复测试

### Changed
- JudgmentEngine 相似度计算升级为内容感知算法，根据 Content-Type 自动选择最优策略
- AutoTestEngine 基线响应采集改为纯响应体（排除响应头），提升比对精度
- ReplayEngine 相似度比对升级为纯响应体比对（排除响应头）
- DiffEngine 相似度计算复用 SimilarityEngine 混合算法

## [2.16.5] - 2026-05-13

### Changed
- 更新推广文案：补充报文比对、报告生成、批量操作等 v2.16.x 功能介绍
- 新增毕导风格推广文案（doc/promotion_script_bidao_style.md）
- 同步 AboutPanel 版本号至 v2.16.5

## [2.16.4] - 2026-05-13

### Fixed
- 修复报文比对中原始响应报文与用户会话响应报文完全一致的问题：原始响应基线现存储于 requests 表，不再错误借用 history 表中的会话响应冒充基线

### Added
- requests 表新增基线响应字段（resp_header_hash/resp_body_hash/resp_body_storage/resp_status_code/resp_length/resp_time）
- RequestDAO 新增 saveOriginalResponse()/getOriginalResponseData()/getOriginalResponseStatusCode() 方法
- Schema v9→v10 迁移，为已有数据库自动添加基线响应字段
- 从 Proxy History 等模块"发送到权限测试"时，自动保存原始响应到 requests 表作为基线

### Changed
- buildBaselineFromRequestsTable() 改为从 requests 表读取基线响应，无基线时留空而非借用 history 会话响应

## [2.16.3] - 2026-05-12

### Added
- TokenLocationType 新增 URL_PARAM 枚举值，支持 URL 查询参数中替换 Token
- RuleTarget 新增 RESPONSE_TIME 枚举值，支持基于响应时间的判断规则
- RuleMethod 新增 NOT_CONTAINS、NOT_EQUALS、LENGTH_DIFF 枚举值，扩展判断方法
- TokenReplacementEngine 增强 URL 查询参数替换能力，支持增删改查 URL 编码键值对
- JudgmentRuleEditDialog LENGTH_DIFF 方法自动联动目标为 RESPONSE_BODY

### Changed
- JudgmentEngine 适配新增判断方法（NOT_CONTAINS/NOT_EQUALS/LENGTH_DIFF/RESPONSE_TIME）
- 同步更新 CLAUDE.md/README.md/usage_detailed_zh.md 文档至最新枚举值

## [2.16.2] - 2026-05-12

### Fixed
- 修复插件卸载时资源未完全释放（数据库连接池、GC服务、RequestManager线程池、HistoryRecordingService）
- 修复 GC 服务批量删除使用 ID 范围导致并发场景下误删未处理条目，改为逐条按 ID 删除
- 修复 RequestDispatchHandler 核心状态字段（currentRequestId/currentHttpService/privilegeTestMode）缺少 volatile 导致跨线程可见性问题
- 修复 RequestDispatchHandler 中 requestHistoryMap/httpServiceMap 使用 HashMap 导致并发访问不安全，改为 ConcurrentHashMap
- 修复 ReplayEngine.processedApis 使用 HashSet 非线程安全，改为 ConcurrentHashMap.newKeySet()
- 修复 HistoryWriteDAO.saveHistory() 冗余 isConnectionValid() 检查浪费连接池资源
- 修复 TokenReplacementEngine JSON 替换丢失原始值类型（数字/布尔值被转为字符串）
- 修复 ErmArchiveReader 通过反射访问 BurpExtender 私有字段，改为调用公开静态方法 refreshUIData()
- 修复 RequestManager 代理模式响应流未使用 try-with-resources 导致异常时流泄漏

## [2.16.1] - 2026-05-12

### Fixed
- 移除 ErmArchiveReader/ErmArchiveWriter/PostmanExporter/PostmanImporter 中未使用的 JFileChooser import
- 移除 ReportContainerReader/ReportExporter 中未使用的 FileNameExtensionFilter import
- 移除 RequestListPanel/SearchBar 中未使用的 ActionEvent import
- 移除 DiffPane 中未使用的搜索高亮常量和 isOriginalSide 字段
- 移除 HistoryContextMenu 中未使用的 finalBatchReplayItem 变量

## [2.16.0] - 2026-05-12

### Added
- 新增 DiffPane 自包含差异显示面板，封装差异渲染、行号显示、差异区域追踪
- 新增 SearchBar 可折叠搜索栏，支持关键字/正则匹配、大小写敏感、上/下一个导航
- 新增 DiffNavigator 差异区域导航器，合并左右面板差异区域，支持上/下一个差异跳转
- DiffEngine 新增行内字符级差异对比，支持字符粒度的高亮着色
- HistoryReadDAO 新增 getBaselineRecordWithoutFallback 方法，专门获取无会话关联的基线记录
- SynchronizedScrollPanel 新增 DiffPane 构造函数重载，直接接受 DiffPane 组件

### Changed
- 重构 ComparisonDialog，使用 DiffPane 替代原有 JTextPane 进行差异显示
- 重构 SynchronizedScrollPanel，提取 setupSyncListeners 公共方法
- 增强 HistoryContextMenu 比对报文菜单项，集成 DiffNavigator 导航功能

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
