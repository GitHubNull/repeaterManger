# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
