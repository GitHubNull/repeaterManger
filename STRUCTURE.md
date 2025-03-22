# Enhanced Repeater Manager 项目结构说明

本文档详细说明 Enhanced Repeater Manager 插件的项目结构、技术实现和代码组织。适合开发者了解项目架构和贡献代码。

## 目录

1. [整体架构](#整体架构)
2. [模块划分](#模块划分)
3. [核心流程](#核心流程)
4. [数据结构](#数据结构)
5. [扩展指南](#扩展指南)

## 整体架构

Enhanced Repeater Manager 采用了模块化的架构设计，主要分为以下几个层次：

```
+---------------------------+
|        用户界面 (UI)       |
+---------------------------+
              |
+---------------------------+
|      业务逻辑 (Service)    |
+---------------------------+
              |
+---------------------------+
|     数据访问 (DAO/DB)      |
+---------------------------+
              |
+---------------------------+
|       数据存储 (SQLite)     |
+---------------------------+
```

### 技术栈选择

1. **UI层**：Java Swing 作为界面构建框架
2. **数据库**：SQLite 作为轻量级数据库
3. **连接池**：HikariCP 提供高性能数据库连接
4. **序列化**：Gson 处理 JSON 数据格式化
5. **HTTP解析**：依赖 Burp Suite API 进行 HTTP 数据处理

## 模块划分

项目按功能划分为以下主要模块：

### 1. 核心模块 (Core)

**主要文件**:
- `BurpExtender.java`: 插件入口点，实现 Burp 扩展接口
- `EnhancedRepeaterUI.java`: 主界面管理类

**职责**:
- 初始化插件
- 注册 Burp 回调
- 加载主界面
- 处理插件生命周期（加载/卸载）

### 2. 配置模块 (Config)

**主要文件**:
- `DatabaseConfig.java`: 数据库配置管理类

**职责**:
- 管理数据库路径和文件名
- 提供配置保存和加载功能
- 维护自动保存设置

### 3. 数据库模块 (DB)

**主要文件**:
- `DatabaseManager.java`: 数据库连接和初始化
- `RequestDAO.java`: 请求数据访问对象
- `HistoryDAO.java`: 历史记录数据访问对象

**职责**:
- 管理数据库连接池
- 提供表创建和升级
- 实现数据访问方法
- 处理事务和并发

### 4. HTTP处理模块 (HTTP)

**主要文件**:
- `RequestResponseRecord.java`: 请求和响应数据模型

**职责**:
- 封装 HTTP 请求和响应
- 提供请求解析和构建方法
- 维护请求元数据

### 5. 数据导入导出模块 (IO)

**主要文件**:
- `DataExporter.java`: 数据导出功能
- `DataImporter.java`: 数据导入功能

**职责**:
- 提供 SQLite 格式数据导出
- 提供 JSON 格式数据导出
- 实现数据导入和合并策略

### 6. 服务模块 (Service)

**主要文件**:
- `AutoSaveService.java`: 自动保存服务

**职责**:
- 定时将内存数据保存到数据库
- 管理保存间隔和触发条件
- 处理保存过程中的异常

### 7. 用户界面模块 (UI)

**主要文件**:
- `MainUI.java`: 主界面容器
- `RequestListPanel.java`: 请求列表面板
- `RequestPanel.java`: 请求详情面板
- `ResponsePanel.java`: 响应显示面板
- `HistoryPanel.java`: 历史记录面板
- `ConfigPanel.java`: 配置面板

**职责**:
- 构建用户界面组件
- 处理用户交互事件
- 显示数据和状态
- 提供界面布局管理

## 核心流程

### 1. 插件初始化流程

```
BurpExtender.registerExtenderCallbacks()
    ↓
配置加载 (DatabaseConfig)
    ↓
数据库初始化 (DatabaseManager)
    ↓
创建主界面 (MainUI)
    ↓
注册扩展功能
    ↓
启动自动保存服务 (AutoSaveService)
```

### 2. 请求处理流程

```
用户编辑请求 (RequestPanel)
    ↓
发送请求 (Burp API)
    ↓
接收响应
    ↓
创建记录 (RequestResponseRecord)
    ↓
更新界面 (ResponsePanel)
    ↓
添加到历史记录 (HistoryPanel)
    ↓
保存到数据库 (HistoryDAO)
```

### 3. 数据保存流程

```
触发保存 (手动/自动)
    ↓
收集内存中的数据
    ↓
构建SQL语句
    ↓
执行数据库事务
    ↓
更新UI状态
```

### 4. 导入导出流程

```
用户选择导出格式和位置
    ↓
检查数据库状态
    ↓
读取数据 (DAO)
    ↓
根据格式处理数据 (SQLite/JSON)
    ↓
写入目标文件
```

## 数据结构

### 1. 数据库表结构

#### `requests` 表
```sql
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    method TEXT,
    protocol TEXT,
    host TEXT,
    port INTEGER,
    request_data BLOB,
    comment TEXT,
    color TEXT,
    last_updated TIMESTAMP,
    create_time TIMESTAMP
);
```

#### `history` 表
```sql
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    status_code INTEGER,
    response_data BLOB,
    response_length INTEGER,
    response_time INTEGER,
    response_date TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
);
```

### 2. 核心类数据结构

#### `RequestResponseRecord` 类
```java
public class RequestResponseRecord {
    private int id;                     // 数据库ID
    private byte[] request;             // 完整请求数据
    private byte[] response;            // 完整响应数据
    private String url;                 // URL
    private String method;              // HTTP方法
    private String host;                // 主机名
    private int port;                   // 端口
    private String protocol;            // 协议(http/https)
    private int statusCode;             // 响应状态码
    private long responseTime;          // 响应时间(ms)
    private long responseLength;        // 响应长度
    private Date responseDate;          // 响应日期时间
    private String comment;             // 用户备注
    private Color color;                // 颜色标记
    private Date createTime;            // 创建时间
    private Date lastUpdated;           // 最后更新时间
    
    // 构造函数、getter和setter方法
    // HTTP解析相关的辅助方法
}
```

## 扩展指南

### 添加新功能

1. **添加新列**:
   - 修改 `RequestListPanel.java` 中的表格模型
   - 更新 `DatabaseManager.java` 中的表结构
   - 添加相应的DAO方法
   - 实现数据迁移（如果需要）

2. **添加新过滤器**:
   - 在高级搜索对话框中添加新的条件选项
   - 实现过滤逻辑
   - 更新UI组件

3. **添加新的导出格式**:
   - 在 `DataExporter.java` 中添加新的导出方法
   - 更新配置面板中的选项
   - 实现数据格式转换逻辑

### 数据库迁移

当更改数据库结构时，需要实现数据库迁移。在 `DatabaseManager.java` 中：

1. 增加数据库版本号
2. 在 `upgradeDatabase()` 方法中添加迁移逻辑
3. 使用 `ALTER TABLE` 等SQL语句修改表结构
4. 确保兼容性处理

### 自定义UI主题

项目使用Swing UI，可以通过以下方式自定义主题：

1. 修改 `MainUI.java` 中的初始化部分
2. 使用 `UIManager.setLookAndFeel()` 设置不同的外观
3. 实现自定义颜色和字体

### 添加国际化支持

如需添加多语言支持：

1. 创建资源束文件 (`.properties`)
2. 使用 `ResourceBundle` 加载语言资源
3. 将UI中的硬编码文本替换为资源引用
4. 添加语言切换选项

## 性能优化

### 数据库优化

1. **索引**:
   ```sql
   CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);
   CREATE INDEX IF NOT EXISTS idx_history_request_id ON history(request_id);
   CREATE INDEX IF NOT EXISTS idx_history_response_date ON history(response_date);
   ```

2. **批量操作**:
   使用批处理和事务减少数据库操作开销。

3. **连接池配置**:
   ```java
   hikariConfig.setMaximumPoolSize(10);
   hikariConfig.setMinimumIdle(5);
   hikariConfig.setIdleTimeout(30000);
   ```

### UI优化

1. **虚拟化列表**:
   对于大量数据，使用虚拟化技术只渲染可见项。

2. **延迟加载**:
   响应内容延迟加载，减少内存占用。

3. **后台线程**:
   耗时操作（如数据库查询、网络请求）放入后台线程。

## 测试策略

1. **单元测试**:
   - DAO层方法测试
   - 数据处理逻辑测试
   - 配置管理测试

2. **集成测试**:
   - 数据库操作测试
   - 导入导出功能测试
   - 界面交互测试

3. **性能测试**:
   - 大量数据处理性能
   - 自动保存性能
   - UI响应性能 