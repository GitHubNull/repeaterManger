# 中级开发指南

> 面向已经理解项目结构、准备贡献代码的开发者

---

## 目录

- [1. Pool 去重架构详解](#1-pool-去重架构详解)
- [2. 自定义连接池实现](#2-自定义连接池实现)
- [3. Schema 版本化迁移机制](#3-schema-版本化迁移机制)
- [4. 添加新功能的标准流程](#4-添加新功能的标准流程)
- [5. 日志系统多通道设计](#5-日志系统多通道设计)
- [6. ERM 存档格式规范](#6-erm-存档格式规范)

---

## 1. Pool 去重架构详解

### 1.1 设计动机

HTTP 请求/响应中包含大量重复内容（相同的域名、相同的认证 Header、相同的错误页面 Body），直接存储会造成严重的磁盘空间浪费。Pool 去重架构通过 SHA-256 哈希 + 引用计数，确保相同内容只存储一次。

### 1.2 四大池

| 池 | 表名 | 内容 | 存储方式 |
|----|------|------|----------|
| 字符串池 | `string_pool` | 域名、路径、查询参数 | SQLite TEXT |
| 头部池 | `header_pool` | HTTP 请求/响应头部 | SQLite BLOB |
| Body 池 | `body_pool` | 小体积 Body（< 阈值） | SQLite BLOB |
| 文件池 | `file_pool` | 大体积 Body（>= 阈值） | 文件系统 `blobs/` |

### 1.3 核心组件

| 类 | 职责 |
|----|------|
| `PoolManager` | 池管理器，提供统一的增删查接口 |
| `ContentHasher` | SHA-256 哈希计算 |
| `ContentSplitter` | 将请求/响应拆分为域名、路径、Header、Body 等组件 |
| `ContentReconstructor` | 从池中重建完整请求/响应 |
| `BodyStorageRoute` | 根据 Body 大小决定行内存储或文件外置 |
| `FileStorageManager` | 管理 `blobs/` 目录下的文件存储 |

### 1.4 引用计数与 GC

- 每个池条目维护 `ref_count` 字段
- 插入重复内容时递增 `ref_count`
- 删除请求/历史记录时递减相关池条目的 `ref_count`
- 当 `ref_count` 归零，条目进入 `gc_queue`
- `GarbageCollectorService` 每 10 分钟清理零引用条目

### 1.5 数据流

```
HTTP 请求 → ContentSplitter
              ├── domain → SHA-256 → string_pool (INSERT OR IGNORE, ref_count++)
              ├── path   → SHA-256 → string_pool
              ├── header → SHA-256 → header_pool
              └── body   → SHA-256 → BodyStorageRoute
                                      ├── 小 Body → body_pool (BLOB)
                                      └── 大 Body → file_pool (blobs/)
```

---

## 2. 自定义连接池实现

### 2.1 实现方式

项目使用 `BlockingQueue<Connection>` + JDK 动态代理实现连接池，而非 HikariCP（pom.xml 声明但未使用）。

```java
// DatabaseManager.java 核心逻辑（简化示意）
BlockingQueue<Connection> pool = new ArrayBlockingQueue<>(POOL_SIZE);

// 获取连接
Connection getConnection() {
    Connection conn = pool.poll(timeout, TimeUnit.SECONDS);
    return (Connection) Proxy.newProxyInstance(..., (proxy, method, args) -> {
        if ("close".equals(method.getName())) {
            pool.offer((Connection) proxy);  // 归还池中
            return null;
        }
        return method.invoke(conn, args);
    });
}
```

### 2.2 设计要点

- **连接复用**：通过动态代理拦截 `close()` 调用，归还连接到池中
- **try-with-resources 兼容**：现有代码无需修改
- **池大小**：默认 5 个连接
- **PRAGMA 配置**：`journal_mode=DELETE`, `synchronous=NORMAL`, `foreign_keys=ON`
- **SQLite 限制**：不支持真正的并发写入，写操作需串行化

---

## 3. Schema 版本化迁移机制

### 3.1 设计理念

数据库结构随版本演进，需要安全地升级现有用户数据。`SchemaMigrator` 实现版本化迁移。

### 3.2 核心组件

| 类 | 职责 |
|----|------|
| `SchemaInitializer` | 首次创建完整 Schema |
| `SchemaMigrator` | 从旧版本迁移到新版本 |
| `schema_meta` 表 | 存储当前 Schema 版本号 |

### 3.3 迁移流程

1. 读取 `schema_meta` 中的 `schema_version`
2. 对比当前代码版本
3. 按顺序执行增量迁移脚本（如 v1→v2, v2→v3）
4. 更新 `schema_meta` 中的版本号

### 3.4 添加迁移示例

```java
// SchemaMigrator.java
if (currentVersion < 3) {
    // v2 → v3: 新增 judgment_rule_conditions 表
    stmt.execute("CREATE TABLE IF NOT EXISTS judgment_rule_conditions (...)");
    currentVersion = 3;
}
```

---

## 4. 添加新功能的标准流程

### 4.1 开发步骤

```
1. 定义数据模型   → model/ 包
2. 创建 DAO       → db/ 包（如需持久化）
3. 实现服务逻辑   → service/ 包或对应子系统包
4. 构建 UI 组件   → ui/ 包
5. 集成到主面板   → RepeaterManagerUI.java
6. Schema 迁移    → SchemaMigrator.java（如需新表）
7. 更新 AGENT.md  → 记录新组件
```

### 4.2 示例：添加配置面板的新标签页

1. **创建标签页类**：`src/main/java/org/oxff/repeater/ui/config/NewFeatureTab.java`
   - 继承自合适的容器（如 `JPanel`）
   - 在 EDT 中创建所有 UI 组件
2. **创建数据模型**：`src/main/java/org/oxff/repeater/model/NewFeatureConfig.java`
3. **创建 DAO**：`src/main/java/org/oxff/repeater/db/NewFeatureDAO.java`
4. **更新 Schema**：在 `SchemaMigrator` 中添加新表的迁移逻辑
5. **集成到 ConfigPanel**：在 `ConfigPanel.java` 中添加新标签页
6. **更新 AGENT.md**：添加新组件的描述

### 4.3 检查清单

- [ ] 所有 UI 操作在 EDT 中执行
- [ ] 数据库操作在后台线程执行
- [ ] 使用 `try-with-resources` 获取数据库连接
- [ ] 添加了必要的日志输出
- [ ] 新表已添加到 Schema 迁移逻辑
- [ ] `AGENT.md` 已更新

---

## 5. 日志系统多通道设计

### 5.1 架构

```
LogManager (单例)
├── BurpConsoleHandler  → Burp Suite 输出面板（Montoya Logging API）
├── RollingFileHandler  → 会话目录 logs/ 下的滚动日志文件
└── UIHandler           → 插件 LogPanel 标签页
```

### 5.2 日志级别

| 级别 | 前缀 | 用途 |
|------|------|------|
| DEBUG | `[D]` | 开发调试信息 |
| INFO | `[*]` | 常规操作信息 |
| SUCCESS | `[+]` | 操作成功信息 |
| WARN | `[!]` | 警告信息 |
| ERROR | `[!]` | 错误信息 |

### 5.3 使用方式

```java
LogManager logManager = LogManager.getInstance();
logManager.log(LogLevel.INFO, "插件加载成功");
logManager.log(LogLevel.ERROR, "数据库连接失败: " + e.getMessage());
```

### 5.4 配置

- 在配置面板中可独立开关三个通道
- 文件日志支持大小滚动和备份数量配置
- UI 日志支持最大条目数限制

---

## 6. ERM 存档格式规范

### 6.1 格式概述

ERM（Repeater Manager）是插件专用二进制存档格式，包含完整数据库和 Body 数据。

### 6.2 文件结构

```
+------------------+
| 32 字节文件头    |  魔法数字 + 版本 + 标志 + 条目数 + manifest 偏移 + CRC
+------------------+
| 数据条目区       |  路径 + 压缩方式 + 数据 + CRC
+------------------+
| manifest JSON    |  元数据（加密状态、创建时间、条目清单）
+------------------+
| 16 字节文件尾    |  魔法数字 + data CRC + footer CRC
+------------------+
```

### 6.3 加密方案（AES-256-CBC + HMAC-SHA256）

1. 用户密码 → PBKDF2 派生 256 位密钥
2. 数据使用 AES-256-CBC 加密（随机 IV）
3. HMAC-SHA256 验证数据完整性
4. 加密标志存储在 manifest 中

### 6.4 核心类

| 类 | 职责 |
|----|------|
| `ErmArchiveWriter` | 序列化并写入 ERM 存档 |
| `ErmArchiveReader` | 解析并读取 ERM 存档 |
| `ErmCryptoHelper` | 加密/解密辅助（PBKDF2/AES/HMAC） |
| `ErmFormatConstants` | 格式常量定义（魔法数字、偏移量、大小） |
| `FormatDetector` | 自动检测导入文件格式（.erm vs .json） |

---

> 下一步：阅读 [advanced-level.md](advanced-level.md) 了解深层架构实现细节。
