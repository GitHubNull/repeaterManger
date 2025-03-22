# Enhanced Repeater Manager - Burp Suite 增强重放插件

## 项目介绍

Enhanced Repeater Manager 是一个为 Burp Suite 设计的高级请求重放管理插件，它提供了比原生 Repeater 更强大的功能，包括请求的分类管理、历史记录跟踪和数据持久化等。这个插件特别适合安全测试人员和渗透测试专家使用，可以有效提高 HTTP/HTTPS 请求测试的效率和组织性。

## 核心功能

- **请求管理**：组织和分类 HTTP 请求，支持颜色标记和备注功能
- **历史记录**：自动记录请求的响应历史，方便比对不同时间的测试结果
- **数据持久化**：所有请求和历史记录保存到 SQLite 数据库，重启 Burp Suite 后不会丢失
- **高级搜索**：支持多条件复合筛选，快速定位特定请求或响应
- **列显示控制**：自定义表格中显示的列，提高信息密度和可读性
- **数据导出导入**：支持 SQLite 和 JSON 格式的数据备份和恢复
- **自动保存**：定时将内存中的数据同步到磁盘，防止数据丢失

## 安装方法

1. 下载最新的 `enhanced-repeater-1.0-SNAPSHOT.jar` 文件
2. 打开 Burp Suite Professional
3. 转到 `Extender` -> `Extensions` 选项卡
4. 点击 `Add` 按钮
5. 在 `Extension file` 中选择下载的 jar 文件
6. 点击 `Next` 完成安装

## 使用方法概览

插件界面主要包含两个选项卡：

1. **请求管理**：主界面，包含左侧请求列表和右侧详情区域
   - 左侧：HTTP请求列表，支持搜索、过滤和管理
   - 右上：选中请求的详情和编辑区域
   - 右下：请求响应和历史记录

2. **配置**：设置数据库存储路径、自动保存参数和导入导出功能

### 基本操作流程

1. 将 Burp 代理截获的请求发送到 Enhanced Repeater
2. 在左侧列表中管理和组织请求
3. 选择请求进行编辑和重放
4. 查看右下方的历史记录区域，对比不同时间的响应结果
5. 使用右键菜单对请求和响应进行更多操作

## 技术架构

- **前端**：Java Swing 构建用户界面
- **数据存储**：SQLite 提供本地持久化支持
- **连接池**：HikariCP 高性能数据库连接池
- **数据序列化**：Gson 用于 JSON 格式数据处理
- **核心设计模式**：MVC 架构，单例模式，观察者模式

## 项目结构概览

```
src/main/java/burp/
├── BurpExtender.java         # Burp扩展入口点
├── config/                   # 配置管理
│   └── DatabaseConfig.java   # 数据库配置类
├── db/                       # 数据库访问层
│   ├── DatabaseManager.java  # 数据库连接管理
│   ├── HistoryDAO.java       # 历史记录数据访问对象
│   └── RequestDAO.java       # 请求数据访问对象
├── http/                     # HTTP 处理
│   └── RequestResponseRecord.java # 请求响应记录实体类
├── io/                       # 数据导入导出
│   ├── DataExporter.java     # 数据导出功能
│   └── DataImporter.java     # 数据导入功能
├── service/                  # 业务逻辑服务
│   └── AutoSaveService.java  # 自动保存服务
└── ui/                       # 用户界面
    ├── ConfigPanel.java      # 配置面板
    ├── HistoryPanel.java     # 历史记录面板
    ├── MainUI.java           # 主界面
    ├── RequestListPanel.java # 请求列表面板
    ├── RequestPanel.java     # 请求详情面板
    └── ResponsePanel.java    # 响应面板
```

## 项目依赖

```xml
<dependencies>
    <!-- Burp扩展API -->
    <dependency>
        <groupId>net.portswigger.burp.extender</groupId>
        <artifactId>burp-extender-api</artifactId>
        <version>2.1</version>
    </dependency>
    
    <!-- 语法高亮组件 -->
    <dependency>
        <groupId>com.fifesoft</groupId>
        <artifactId>rsyntaxtextarea</artifactId>
        <version>3.3.3</version>
    </dependency>
    
    <!-- SQLite驱动 -->
    <dependency>
        <groupId>org.xerial</groupId>
        <artifactId>sqlite-jdbc</artifactId>
        <version>3.40.1.0</version>
    </dependency>
    
    <!-- 高性能连接池 -->
    <dependency>
        <groupId>com.zaxxer</groupId>
        <artifactId>HikariCP</artifactId>
        <version>4.0.3</version>
    </dependency>
    
    <!-- JSON处理库 -->
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.10.1</version>
    </dependency>
</dependencies>
```

## 使用场景

1. **API安全测试**：持续测试同一API的不同参数组合，并保存所有测试结果
2. **漏洞复现**：记录漏洞利用过程中的所有请求和响应，便于后期复现
3. **安全评估**：整理大型应用的API集合，系统化进行安全测试
4. **团队协作**：导出测试好的请求集合，分享给团队其他成员继续测试
5. **渗透测试记录**：记录渗透测试过程中的关键请求，便于编写报告

## 数据持久化说明

数据默认保存在用户主目录的 `.burp` 文件夹下：
- 配置文件: `~/.burp/repeater_manager_config.properties`
- 数据库文件: `~/.burp/repeater_manager.db`

可以通过配置面板修改数据库的存储位置和自动保存参数。

---

详细使用说明和代码结构分析请参考：
- [使用指南](USAGE.md)
- [项目结构说明](STRUCTURE.md)

## 编译与构建

项目使用Maven进行构建，执行以下命令可以生成插件JAR文件：

```bash
mvn clean package
```

生成的JAR文件将位于 `target/releases/` 目录下，文件名包含版本号和时间戳。

## 开发计划

- [ ] 添加团队共享功能，支持多人协作
- [ ] 集成自动化测试脚本支持
- [ ] 提供请求模板功能，快速创建类似请求
- [ ] 支持更多数据格式的导入导出
- [ ] 添加请求序列功能，支持多步骤请求流程

## 许可证

本项目使用 MIT 许可证
