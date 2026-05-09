# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
