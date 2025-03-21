# BurpSuite Enhanced Repeater Plugin 
[![GitHub License](https://img.shields.io/github/license/githubnull/BurpSuite-Enhanced-Repeater)](https://github.com/githubnull/BurpSuite-Enhanced-Repeater/blob/main/LICENSE)

> 基于 Burp Extender API 开发的增强型中继器插件，提供比原生模块更强大的功能 

## ✨ 功能特性
### 核心功能模块
1. **智能重放引擎**  
   - 可配置请求超时时间（0-60秒）
   - 毫秒级响应耗时统计（精度±1ms）
   - 自动历史记录存储（保留最近1000条）

2. **高级搜索系统**
   ```text
   └─ 请求报文
      ├─ 方法过滤 (GET/POST/PUT...)
      ├─ 路径匹配 (支持正则表达式)
      └─ 内容检索 (Header/Body 关键字)
   └─ 响应报文
      ├─ 状态码范围过滤
      └─ 内容模式匹配 [31](@ref)[60](@ref)
   ```

3. **异常处理机制**
    - 网络超时自动重试（最大3次）
    - 无效响应自动标记（HTTP 500+）
    - 错误日志分级记录（INFO/WARN/ERROR）

### 扩展功能
| 模块         | 功能描述                            |
|--------------|-----------------------------------|
| 数据持久化   | SQLite 本地存储历史记录            |
| 主题切换     | 深色/浅色模式支持                  |
| 导入导出     | HAR/JSON 格式转换                  |

## 🛠️ 安装指南
### 环境要求
- JDK 1.8+
- Burp Suite Pro 2023.6+
- Maven 3.8+

### 构建步骤
```bash
mvn clean package
```
生成的 `target/enhanced-repeater-1.0.jar` 通过 Burp 的 Extender 模块加载

## 🎨 界面设计原则
1. **布局方案**
   ```text
   +-----------------------+
   | 控制栏 [超时设置|主题切换] |
   +-----------+-----------+
   | 请求面板  | 响应面板   |
   +-----------+-----------+
   | 历史记录管理            |
   +-----------------------+
   ```

2. **交互细节**
    - 彩色状态码标识（绿色2xx/红色5xx）
    - 请求耗时动态进度条
    - 智能语法高亮（JSON/XML/HTML）

## ⚠️ 异常处理
```java
// 使用 Burp 原生日志接口
callbacks.printError("Timeout occurred: " + e.getMessage());
callbacks.getStderr().write(("Stacktrace: " + Arrays.toString(e.getStackTrace())).getBytes());

// 自定义错误代码映射
public enum ErrorCode {
  NETWORK_TIMEOUT(1001),
  INVALID_RESPONSE(2001),
  STORAGE_FAILURE(3001);
}
```

## 📄 开源协议
Apache License 2.0 © [githubnull](https://github.com/githubnull)



### 关键实现要点说明：
1. **日志系统**：同时使用 `printOutput()` 和 `getStderr()` 实现分级日志 [51](@ref)
2. **性能优化**：采用线程池管理请求队列，避免界面卡顿
3. **数据安全**：SQLite 数据库加密存储敏感历史记录
4. **兼容性**：通过 `@SuppressWarnings("deprecation")` 处理旧版API兼容
5. **可扩展性**：插件架构支持通过 SPI 机制加载扩展模块

建议结合 Burp 的 `IExtensionHelpers` 和 `IHttpService` 接口实现核心网络功能 [60](@ref)[74](@ref)，使用 `JTabbedPane` 构建多标签界面 [2](@ref)，并通过 `SwingWorker` 实现异步操作防止界面冻结。
