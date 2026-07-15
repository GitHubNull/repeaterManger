# RepeaterManager 业务逻辑缺陷修复方案报告

**生成时间**: 2026-07-15  
**对应分析报告**: `business_logic_defect_analysis_20260715_114050.md`  
**说明**: 本报告仅提供修复方案，不修改源码

---

## 目录

1. [修复优先级总览](#修复优先级总览)
2. [高危缺陷修复方案](#高危缺陷修复方案)
3. [中危缺陷修复方案](#中危缺陷修复方案)
4. [低危缺陷修复方案](#低危缺陷修复方案)
5. [设计层面问题修复方案](#设计层面问题修复方案)

---

## 修复优先级总览

| 优先级 | 缺陷编号 | 缺陷名称 | 预计工作量 | 风险 |
|--------|---------|---------|-----------|------|
| P0 | #1 | DatabaseManager SQL注入 | 小 | 低 |
| P0 | #2 | processedApis 内存泄漏 | 中 | 中 |
| P1 | #3 | SimilarityEngine 二进制相似度 | 中 | 低 |
| P1 | #5 | FieldReplacementEngine XXE | 小 | 低 |
| P1 | #6 | FieldReplacementEngine 二进制损坏 | 中 | 中 |
| P1 | #8 | RequestDispatchHandler 异常处理 | 中 | 低 |
| P2 | #9 | AutoTestEngine 基准响应覆盖 | 中 | 中 |
| P2 | #4 | JudgmentEngine 相似度-1 | 小 | 低 |
| P3 | #7 | PoolManager 缓存键不一致 | 小 | 低 |
| P3 | #10 | ContentReconstructor 空数组 | 小 | 低 |

---

## 高危缺陷修复方案

### 缺陷 #1: DatabaseManager SQL注入风险

**文件**: `db/DatabaseManager.java`  
**方法**: `setCleanShutdown(boolean)`

#### 问题根因

使用字符串拼接构建SQL语句，而非参数化查询。

#### 修复方案

**方案 A: 使用 PreparedStatement（推荐）**

```java
public void setCleanShutdown(boolean clean) {
    String sql = "UPDATE config SET value = ? WHERE key = 'clean_shutdown'";
    try (Connection conn = getConnection();
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, clean ? "1" : "0");
        pstmt.executeUpdate();
    } catch (SQLException e) {
        LogManager.getInstance().printError("[!] 设置clean_shutdown失败: " + e.getMessage());
    }
}
```

**方案 B: 如果必须保留字符串拼接，添加输入校验（不推荐，仅作备选）**

```java
public void setCleanShutdown(boolean clean) {
    // 仅允许布尔值，绝不接受外部字符串输入
    String value = clean ? "1" : "0";
    // 添加断言确保不是用户输入
    if (!value.equals("1") && !value.equals("0")) {
        throw new IllegalArgumentException("Invalid clean shutdown value");
    }
    // ... 即使如此，仍建议改为 PreparedStatement
}
```

#### 验证方法

1. 检查 `setCleanShutdown` 的所有调用点，确认传入的是布尔字面量
2. 搜索项目中所有使用 `Statement.executeUpdate(String)` 拼接SQL的地方，统一修复
3. 添加静态代码分析规则（如 SpotBugs SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE）

---

### 缺陷 #2: ReplayEngine / AutoTestEngine processedApis 内存泄漏

**文件**: `privilege/ReplayEngine.java`, `privilege/AutoTestEngine.java`

#### 问题根因

`processedApis` 是实例级别的 `ConcurrentHashMap.newKeySet()`，元素只增不减，无自动淘汰机制。

#### 修复方案

**方案 A: 使用 Guava Cache 或 Caffeine 带过期时间（推荐）**

```java
// 引入 Guava 或 Caffeine 依赖
// 修改 ReplayEngine.java 和 AutoTestEngine.java

private final Cache<String, Boolean> processedApis = Caffeine.newBuilder()
    .maximumSize(10000)           // 最大条目数
    .expireAfterWrite(30, TimeUnit.MINUTES)  // 30分钟过期
    .build();

// 检查是否已处理
public boolean isApiProcessed(String api) {
    return processedApis.getIfPresent(api) != null;
}

// 标记为已处理
public void markApiProcessed(String api) {
    processedApis.put(api, Boolean.TRUE);
}
```

**方案 B: 使用 LinkedHashMap 实现 LRU（不引入外部依赖）**

```java
private final Set<String> processedApis = Collections.newSetFromMap(
    new LinkedHashMap<String, Boolean>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > 10000;  // 最大保留10000条
        }
    }
);
```

**注意**: `LinkedHashMap` 的 LRU 实现需要访问顺序模式（`accessOrder = true`），上述代码需要调整。

**方案 C: 定时清理 + 大小限制（最小改动）**

```java
// 在 ReplayEngine / AutoTestEngine 中添加
private static final int MAX_PROCESSED_APIS = 50000;
private final AtomicInteger apiCounter = new AtomicInteger(0);

private void ensureProcessedApisNotLeaking() {
    if (apiCounter.incrementAndGet() > MAX_PROCESSED_APIS) {
        synchronized (processedApis) {
            if (processedApis.size() > MAX_PROCESSED_APIS) {
                processedApis.clear();
                apiCounter.set(0);
                LogManager.getInstance().printOutput("[*] processedApis 已达到上限，执行清理");
            }
        }
    }
}
```

#### 验证方法

1. 运行长时间压力测试，监控内存占用
2. 使用 JProfiler 或 VisualVM 检查 `ConcurrentHashMap$KeySetView` 的实例大小
3. 确认清理后去重功能仍然正常（不应重复处理同一API）

---

## 中危缺陷修复方案

### 缺陷 #3: SimilarityEngine 二进制相似度计算错误

**文件**: `privilege/SimilarityEngine.java`  
**方法**: `computeBinarySimilarity(String, String)`

#### 问题根因

二进制数据被强制转为 `String` 后，使用 `String.length()`（字符数）代替原始字节长度，导致长度计算失真。

#### 修复方案

**方案 A: 保留原始字节数组计算相似度（推荐，需修改接口）**

修改 `SimilarityEngine` 的调用链，在二进制场景下保留原始字节长度信息：

```java
// 在 JudgmentEngine 中，调用 SimilarityEngine 时传入原始字节长度
public static double similarity(byte[] data1, byte[] data2) {
    if (data1 == null && data2 == null) return 1.0;
    if (data1 == null || data2 == null) return 0.0;
    if (data1.length == 0 && data2.length == 0) return 1.0;
    if (data1.length == 0 || data2.length == 0) return 0.0;
    if (Arrays.equals(data1, data2)) return 1.0;
    
    int len1 = data1.length;
    int len2 = data2.length;
    int maxLen = Math.max(len1, len2);
    int minLen = Math.min(len1, len2);
    return (double) minLen / maxLen;
}
```

**方案 B: 在现有接口基础上增加字节长度参数（兼容性好）**

```java
public static double similarity(String s1, String s2, String contentTypeHeader, 
                                 int originalBytesLen1, int originalBytesLen2) {
    ContentTypeDetector.ContentType type = ContentTypeDetector.detect(contentTypeHeader, s1);
    if (type == ContentTypeDetector.ContentType.BINARY) {
        return computeBinarySimilarity(originalBytesLen1, originalBytesLen2);
    }
    return computeByType(s1, s2, type);
}

private static double computeBinarySimilarity(int len1, int len2) {
    if (len1 == 0 && len2 == 0) return 1.0;
    int maxLen = Math.max(len1, len2);
    if (maxLen == 0) return 1.0;
    int minLen = Math.min(len1, len2);
    return (double) minLen / maxLen;
}
```

**方案 C: 使用 Base64 编码后比较（简单但性能差）**

```java
private static double computeBinarySimilarity(String s1, String s2) {
    // 将字符串视为UTF-8字节数组重新计算长度
    int len1 = s1.getBytes(StandardCharsets.UTF_8).length;
    int len2 = s2.getBytes(StandardCharsets.UTF_8).length;
    // ... 后续相同
}
```

**注意**: 方案 C 仍有缺陷，因为原始字节中无法解码的部分已被替换为 U+FFFD，信息已丢失。

#### 验证方法

1. 构造测试用例：两个不同内容的二进制文件（如两个不同的PNG），但UTF-8解码后字符数相同
2. 验证修复后相似度计算反映真实字节长度差异
3. 对比修复前后的相似度值，确保二进制场景更准确

---

### 缺陷 #5: FieldReplacementEngine XML外部实体注入(XXE)风险

**文件**: `privilege/FieldReplacementEngine.java`  
**方法**: `replaceXmlBody()`

#### 问题根因

`DocumentBuilderFactory` 和 `TransformerFactory` 未禁用外部实体解析。

#### 修复方案

```java
private static DocumentBuilderFactory createSecureDocumentBuilderFactory() 
        throws ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // 禁用 DTD
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // 禁用外部实体
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    // 禁用 XInclude
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    return factory;
}

// TransformerFactory 同样需要安全设置
private static TransformerFactory createSecureTransformerFactory() {
    TransformerFactory factory = TransformerFactory.newInstance();
    try {
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    } catch (IllegalArgumentException e) {
        // 某些旧版本实现不支持此属性，记录日志
        LogManager.getInstance().printError("[!] TransformerFactory 安全属性设置失败: " + e.getMessage());
    }
    return factory;
}
```

#### 验证方法

1. 构造包含 XXE payload 的 XML 请求体测试：
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```
2. 验证替换操作抛出异常而非解析外部实体
3. 确认正常XML替换功能不受影响

---

### 缺陷 #6: FieldReplacementEngine 二进制数据UTF-8解码损坏

**文件**: `privilege/FieldReplacementEngine.java`

#### 问题根因

统一使用 `new String(requestBytes, StandardCharsets.UTF_8)` 解码请求体，不区分文本和二进制内容。

#### 修复方案

**方案 A: 根据 Content-Type 区分处理（推荐）**

```java
public static byte[] replaceFields(byte[] requestBytes, List<FieldDefinition> locations, 
                                    UserSession session) {
    // 1. 解析请求头部，获取 Content-Type
    String contentType = extractContentType(requestBytes);
    
    // 2. 判断是否为二进制内容
    boolean isBinary = isBinaryContentType(contentType);
    
    if (isBinary) {
        // 二进制内容：仅替换 Header/URL 中的字段，不修改 body
        return replaceFieldsInBinaryRequest(requestBytes, locations, session);
    } else {
        // 文本内容：按原有逻辑处理
        return replaceFieldsInTextRequest(requestBytes, locations, session);
    }
}

private static boolean isBinaryContentType(String contentType) {
    if (contentType == null) return false;
    String ct = contentType.toLowerCase();
    // 常见的二进制类型
    return ct.contains("image/") || ct.contains("audio/") || ct.contains("video/") 
        || ct.contains("application/octet-stream") || ct.contains("application/pdf")
        || ct.contains("application/zip") || ct.contains("application/gzip")
        || ct.contains("multipart/form-data");  // multipart 需要特殊处理
}
```

**方案 B: multipart/form-data 特殊处理**

```java
private static byte[] replaceMultipartFields(byte[] requestBytes, List<FieldDefinition> locations,
                                               UserSession session, String boundary) {
    // 按 boundary 分割 part
    // 对每个 part：
    //   - 如果是文本 part（Content-Type: text/plain 或没有 Content-Type），进行字段替换
    //   - 如果是二进制 part（文件上传），跳过不修改
    // 重新组装请求体
}

private static boolean isBinaryPart(byte[] partBytes) {
    // 从 part 头部解析 Content-Type
    String partContentType = extractPartContentType(partBytes);
    if (partContentType == null) return false;  // 默认视为文本
    return !partContentType.toLowerCase().startsWith("text/");
}
```

**方案 C: 使用字节级替换（最精确但复杂）**

对于已知字段值，直接在字节数组中搜索并替换，不经过字符串转换：

```java
private static byte[] replaceBytes(byte[] source, byte[] target, byte[] replacement) {
    // 使用 KMP 或 Boyer-Moore 算法在字节数组中搜索 target
    // 替换为 replacement
    // 处理多字节编码（UTF-8）的边界问题
}
```

#### 验证方法

1. 构造包含非UTF-8字节（如 0xFF, 0xFE）的请求体测试
2. 验证替换后原始字节未被修改
3. 测试文件上传场景（multipart/form-data），确认文件内容完整性

---

### 缺陷 #8: RequestDispatchHandler 线程池异常处理缺失

**文件**: `RequestDispatchHandler.java`  
**字段**: `dbPersistExecutor`

#### 问题根因

`dbPersistExecutor.submit()` 提交的任务无异常处理，失败静默。

#### 修复方案

**方案 A: 使用 CompletableFuture 处理异常（推荐）**

```java
// 修改 dbPersistExecutor 提交方式
CompletableFuture.runAsync(() -> {
    try {
        requestDAO.updateRequest(...);
    } catch (Exception e) {
        LogManager.getInstance().printError("[!] DB持久化失败: " + e.getMessage());
        // 可选：通知UI显示错误
        UIRequestDispatcher.showErrorNotification("数据库保存失败: " + e.getMessage());
    }
}, dbPersistExecutor);
```

**方案 B: 自定义 ThreadPoolExecutor 的 afterExecute**

```java
this.dbPersistExecutor = new ThreadPoolExecutor(
    corePoolSize, maxPoolSize, keepAliveTime, TimeUnit.SECONDS,
    new LinkedBlockingQueue<>(),
    new ThreadFactoryBuilder().setNameFormat("DB-Persist-%d").build(),
    new ThreadPoolExecutor.CallerRunsPolicy()
) {
    @Override
    protected void afterExecute(Runnable r, Throwable t) {
        super.afterExecute(r, t);
        if (t == null && r instanceof Future<?>) {
            try {
                ((Future<?>) r).get();
            } catch (ExecutionException ee) {
                t = ee.getCause();
            } catch (CancellationException | InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        if (t != null) {
            LogManager.getInstance().printError("[!] DB持久化线程异常: " + t.getMessage());
        }
    }
};
```

**方案 C: 包装 Runnable 统一处理（最小改动）**

```java
private void submitDbTask(Runnable task) {
    dbPersistExecutor.submit(() -> {
        try {
            task.run();
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] DB任务执行失败: " + e.getMessage());
            LogManager.getInstance().printError(ExceptionUtils.getStackTrace(e));
        }
    });
}

// 使用方式
submitDbTask(() -> requestDAO.updateRequest(...));
```

#### 验证方法

1. 模拟数据库连接失败场景（如临时断开SQLite）
2. 验证异常被正确捕获并记录，而非静默丢失
3. 确认UI能收到错误通知（如果实现了通知机制）

---

### 缺陷 #9: AutoTestEngine 基准响应覆盖逻辑缺陷

**文件**: `privilege/AutoTestEngine.java`

#### 问题根因

AutoTestEngine 直接使用首个会话的实时响应作为基准，没有持久化，也没有从数据库加载存储基准。

#### 修复方案

**方案 A: 与 ReplayEngine 统一，使用数据库存储基准（推荐）**

```java
// 在 AutoTestEngine.executeAutoTestSessions() 中

// 1. 尝试从数据库加载存储的基准响应
byte[] storedBaseline = requestDAO.getOriginalResponseData(requestId);
if (storedBaseline != null && storedBaseline.length > 0) {
    // 使用数据库基准
    baselineResponse = HttpMessageParser.extractResponseBody(storedBaseline);
    baselineStatusCode = requestDAO.getOriginalResponseStatusCode(requestId);
    baselineValid = true;
    hasStoredBaseline = true;
} else {
    // 2. 无存储基准时，首个会话响应同时保存到数据库
    hasStoredBaseline = false;
}

// 在首个会话获取响应后
if (isFirst && !hasStoredBaseline) {
    // 保存基准响应到数据库
    requestDAO.saveOriginalResponse(requestId, holder.response, holder.statusCode);
    baselineResponse = HttpMessageParser.extractResponseBody(holder.response);
    baselineStatusCode = holder.statusCode;
    baselineValid = true;
}
```

**方案 B: 添加独立的基准响应存储表**

```sql
-- 新增表存储基准响应
CREATE TABLE IF NOT EXISTS baseline_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_hash TEXT NOT NULL UNIQUE,
    response_data BLOB,
    status_code INTEGER,
    content_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**方案 C: 使用内存缓存 + 定时持久化（折中）**

```java
// 使用 ConcurrentHashMap 缓存基准，定期批量保存到数据库
private final Map<String, BaselineData> baselineCache = new ConcurrentHashMap<>();

// 定时任务每5分钟保存
ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
scheduler.scheduleAtFixedRate(this::persistBaselineCache, 5, 5, TimeUnit.MINUTES);
```

#### 验证方法

1. 首次自动测试：确认基准响应被保存
2. 第二次自动测试同一API：确认加载存储基准而非重新获取
3. 验证基准响应与原始响应一致（无损坏）

---

### 缺陷 #4: JudgmentEngine 相似度-1导致误判

**文件**: `privilege/JudgmentEngine.java`  
**方法**: `judgeDefault()`

#### 问题根因

相似度初始值 `-1` 作为"未计算"标记，但退化为仅状态码判断时准确性不足。

#### 修复方案

```java
// 修改 judgeDefault() 方法
private static JudgmentOutcome judgeDefault(...) {
    double similarity = -1;
    // ... 尝试计算相似度 ...
    
    if (similarity >= 0) {
        // 正常基于相似度判断
        return judgeBySimilarity(similarity, statusCodeDiff, ...);
    } else {
        // 相似度计算失败时，增强退化逻辑
        LogManager.getInstance().printError(
            "[!] 相似度计算失败，退化为增强状态码判断");
        
        // 不仅比较状态码，还比较响应体长度差异
        int bodyLenDiff = Math.abs(currentBodyLen - baselineBodyLen);
        double lenRatio = (double) Math.min(currentBodyLen, baselineBodyLen) 
                          / Math.max(currentBodyLen, baselineBodyLen);
        
        if (statusCodeDiff != 0) {
            // 状态码不同，标记为可疑
            return new JudgmentOutcome(JudgmentResult.ESCALATED, 0.0, ...);
        } else if (lenRatio < 0.5) {
            // 响应体长度差异超过50%，标记为可疑
            return new JudgmentOutcome(JudgmentResult.ESCALATED, lenRatio, ...);
        } else {
            // 状态码相同且长度相近，标记为未越权（但置信度低）
            return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, lenRatio, ...);
        }
    }
}
```

#### 验证方法

1. 构造相似度计算失败的场景（如空响应体）
2. 验证退化逻辑能正确区分明显不同的响应
3. 确保不会大量误报或漏报

---

## 低危缺陷修复方案

### 缺陷 #7: PoolManager existenceCache 缓存键不一致

**文件**: `db/pool/PoolManager.java`

#### 修复方案

统一缓存键格式，添加常量定义：

```java
public class PoolManager {
    private static final String CACHE_PREFIX_STRING = "str:";
    private static final String CACHE_PREFIX_HEADER = "hdr:";
    private static final String CACHE_PREFIX_BODY = "body:";
    private static final String CACHE_PREFIX_FILE = "file:";
    
    // 统一使用带前缀的键
    private String buildExistenceCacheKey(String type, String hash) {
        return type + ":" + hash;
    }
    
    // 或统一不使用前缀，直接用 hash（因为不同类型的 hash 空间不重叠）
}
```

---

### 缺陷 #10: ContentReconstructor 空字节数组拼接问题

**文件**: `db/pool/ContentReconstructor.java`

#### 修复方案

添加更严格的校验：

```java
private byte[] reconstruct(byte[] headerBytes, byte[] bodyBytes) {
    if (headerBytes == null || headerBytes.length == 0) {
        LogManager.getInstance().printError("[!] 重组失败：头部为空");
        return null;  // 或抛出异常
    }
    if (bodyBytes == null) {
        bodyBytes = new byte[0];
    }
    
    byte[] result = new byte[headerBytes.length + bodyBytes.length + 4]; // +4 for \r\n\r\n
    // ... 复制数据
}
```

---

## 设计层面问题修复方案

### 问题 A: 单例模式线程安全

**涉及文件**: `ReplayEngine.java`, `AutoTestEngine.java`, `ApiRuleManager.java`, `DatabaseManager.java`

#### 修复方案

统一使用枚举单例或静态内部类模式：

```java
// 方案 1: 枚举单例（最简洁，防反射和序列化）
public enum DatabaseManager {
    INSTANCE;
    // ... 实例方法
}

// 方案 2: 静态内部类（延迟加载，线程安全）
public class ReplayEngine {
    private ReplayEngine() {}
    
    private static class Holder {
        static final ReplayEngine INSTANCE = new ReplayEngine();
    }
    
    public static ReplayEngine getInstance() {
        return Holder.INSTANCE;
    }
}

// 方案 3: 如果保留现有模式，添加 volatile
public class AutoTestEngine {
    private static volatile AutoTestEngine instance;
    
    public static AutoTestEngine getInstance() {
        if (instance == null) {
            synchronized (AutoTestEngine.class) {
                if (instance == null) {
                    instance = new AutoTestEngine();
                }
            }
        }
        return instance;
    }
}
```

---

### 问题 B: 异常处理不一致

#### 修复方案

定义统一异常体系：

```java
// 定义业务异常
public class RepeaterException extends Exception {
    private final ErrorCode errorCode;
    public RepeaterException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}

public enum ErrorCode {
    DB_CONNECTION_FAILED("DB001", "数据库连接失败"),
    DB_QUERY_FAILED("DB002", "数据库查询失败"),
    HTTP_SEND_FAILED("HTTP001", "HTTP请求发送失败"),
    SIMILARITY_CALC_FAILED("JUDGE001", "相似度计算失败");
    
    private final String code;
    private final String description;
    // ...
}

// 使用方式
try {
    // ...
} catch (SQLException e) {
    throw new RepeaterException(ErrorCode.DB_QUERY_FAILED, "查询请求失败", e);
}
```

---

### 问题 C: 资源关闭不规范

#### 修复方案

统一使用 try-with-resources：

```java
// 修改前
Connection conn = null;
PreparedStatement pstmt = null;
ResultSet rs = null;
try {
    conn = getConnection();
    pstmt = conn.prepareStatement(sql);
    rs = pstmt.executeQuery();
    // ...
} catch (SQLException e) {
    // ...
} finally {
    if (rs != null) try { rs.close(); } catch (SQLException e) { /* ignore */ }
    if (pstmt != null) try { pstmt.close(); } catch (SQLException e) { /* ignore */ }
    if (conn != null) try { conn.close(); } catch (SQLException e) { /* ignore */ }
}

// 修改后
try (Connection conn = getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sql);
     ResultSet rs = pstmt.executeQuery()) {
    // ...
} catch (SQLException e) {
    // ...
}
```

---

## 总结

本修复方案报告针对分析报告中识别的 10 个具体缺陷和 3 个设计层面问题，提供了详细的修复代码示例和验证方法。

**实施建议**:
1. 按优先级 P0 → P1 → P2 → P3 顺序修复
2. 每个缺陷修复后运行对应验证方法确认
3. 高危缺陷（#1, #2）建议立即修复
4. 设计层面问题（A, B, C）可在功能迭代中逐步重构

---

*报告结束*
