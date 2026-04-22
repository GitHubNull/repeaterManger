package oxff.top.db;

import burp.BurpExtender;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiRuleManager;
import oxff.top.api.ApiExtractionRule;
import oxff.top.db.pool.*;
import oxff.top.service.GarbageCollectorService;

import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 请求数据访问对象
 * 适配去重存储架构（v2 Schema）
 */
public class RequestDAO {
    private final DatabaseManager dbManager;
    private final Map<Integer, Boolean> requestValidationCache;
    private long lastCacheCleanup = 0;
    private static final long CACHE_CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes

    private final PoolManager poolManager;
    private final ContentReconstructor reconstructor;

    public RequestDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestValidationCache = new ConcurrentHashMap<>();
        this.poolManager = new PoolManager();
        this.reconstructor = new ContentReconstructor();
    }

    /**
     * 保存请求数据
     */
    public int saveRequest(String protocol, String domain, String path, String query, String method, byte[] requestData) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 字符串池操作
                String domainHash = domain != null ? poolManager.ensureString(conn, domain) : null;
                String pathHash = path != null ? poolManager.ensureString(conn, path) : null;
                String queryHash = (query != null && !query.isEmpty()) ? poolManager.ensureString(conn, query) : null;

                // 枚举转换
                int protocolInt = HttpEnum.protocolToInt(protocol);
                int methodInt = HttpEnum.methodToInt(method);

                // 分割请求
                String reqHeaderHash = null;
                String reqBodyHash = null;
                String reqBodyStorage = BodyStorageRoute.NONE.getDbValue();
                String apiHash = null;

                if (requestData != null && requestData.length > 0) {
                    SplitResult split = poolManager.getSplitter().splitRequest(requestData);
                    reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());

                    if (split.hasBody()) {
                        String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                        reqBodyHash = bodyResult[0];
                        reqBodyStorage = bodyResult[1];
                    }

                    // Extract headers for API extraction
                    java.util.List<String> headerList = new java.util.ArrayList<>();
                    String contentType = null;
                    if (split.getHeaders() != null) {
                        String headersStr = new String(split.getHeaders(), java.nio.charset.StandardCharsets.UTF_8);
                        for (String line : headersStr.split("\r\n")) {
                            if (!line.isEmpty()) headerList.add(line);
                            if (line.toLowerCase().startsWith("content-type:")) {
                                contentType = line.substring("content-type:".length()).trim();
                            }
                        }
                    }

                    // Compute API value
                    java.util.List<ApiExtractionRule> activeRules = ApiRuleManager.getInstance().getActiveRules();
                    String apiValue = ApiExtractionEngine.extractApi(path, query, headerList,
                            (split.hasBody() ? split.getBody() : null),
                            contentType, activeRules);
                    apiHash = (apiValue != null && !apiValue.isEmpty()) ? poolManager.ensureString(conn, apiValue) : null;
                }

                // 插入记录
                String sql = "INSERT INTO requests (protocol, domain_hash, path_hash, query_hash, method, " +
                        "add_time, req_header_hash, req_body_hash, req_body_storage, api_hash) " +
                        "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)";

                try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
                    pstmt.setInt(1, protocolInt);
                    pstmt.setString(2, domainHash);
                    pstmt.setString(3, pathHash);
                    pstmt.setString(4, queryHash);
                    pstmt.setInt(5, methodInt);
                    pstmt.setString(6, reqHeaderHash);
                    pstmt.setString(7, reqBodyHash);
                    pstmt.setString(8, reqBodyStorage);
                    pstmt.setString(9, apiHash);

                    int affectedRows = pstmt.executeUpdate();
                    if (affectedRows > 0) {
                        try (ResultSet rs = pstmt.getGeneratedKeys()) {
                            if (rs.next()) {
                                int id = rs.getInt(1);
                                conn.commit();
                                BurpExtender.printOutput("[+] 请求数据已保存，ID: " + id);
                                return id;
                            }
                        }
                    }

                    conn.rollback();
                    BurpExtender.printError("[!] 保存请求数据失败：未生成ID");
                    return -1;
                }
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存请求数据失败: " + e.getMessage());
            return -1;
        }
    }

    /**
     * 更新请求
     */
    public boolean updateRequest(int requestId, String protocol, String domain,
                                 String path, String query, String method, byte[] requestData) {
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 读取旧引用
                String[] oldRefs = readRequestHashRefs(conn, requestId);

                // 新引用
                String domainHash = domain != null ? poolManager.ensureString(conn, domain) : null;
                String pathHash = path != null ? poolManager.ensureString(conn, path) : null;
                String queryHash = (query != null && !query.isEmpty()) ? poolManager.ensureString(conn, query) : null;
                int protocolInt = HttpEnum.protocolToInt(protocol);
                int methodInt = HttpEnum.methodToInt(method);

                String reqHeaderHash = null;
                String reqBodyHash = null;
                String reqBodyStorage = BodyStorageRoute.NONE.getDbValue();
                String apiHash = null;

                if (requestData != null && requestData.length > 0) {
                    SplitResult split = poolManager.getSplitter().splitRequest(requestData);
                    reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
                    if (split.hasBody()) {
                        String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                        reqBodyHash = bodyResult[0];
                        reqBodyStorage = bodyResult[1];
                    }

                    // Extract headers for API extraction
                    java.util.List<String> headerList = new java.util.ArrayList<>();
                    String contentType = null;
                    if (split.getHeaders() != null) {
                        String headersStr = new String(split.getHeaders(), java.nio.charset.StandardCharsets.UTF_8);
                        for (String line : headersStr.split("\r\n")) {
                            if (!line.isEmpty()) headerList.add(line);
                            if (line.toLowerCase().startsWith("content-type:")) {
                                contentType = line.substring("content-type:".length()).trim();
                            }
                        }
                    }

                    // Compute API value
                    java.util.List<ApiExtractionRule> activeRules = ApiRuleManager.getInstance().getActiveRules();
                    String apiValue = ApiExtractionEngine.extractApi(path, query, headerList,
                            (split.hasBody() ? split.getBody() : null),
                            contentType, activeRules);
                    apiHash = (apiValue != null && !apiValue.isEmpty()) ? poolManager.ensureString(conn, apiValue) : null;
                }

                // 更新记录
                String sql = "UPDATE requests SET protocol=?, domain_hash=?, path_hash=?, " +
                        "query_hash=?, method=?, req_header_hash=?, req_body_hash=?, req_body_storage=?, api_hash=? WHERE id=?";
                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setInt(1, protocolInt);
                    pstmt.setString(2, domainHash);
                    pstmt.setString(3, pathHash);
                    pstmt.setString(4, queryHash);
                    pstmt.setInt(5, methodInt);
                    pstmt.setString(6, reqHeaderHash);
                    pstmt.setString(7, reqBodyHash);
                    pstmt.setString(8, reqBodyStorage);
                    pstmt.setString(9, apiHash);
                    pstmt.setInt(10, requestId);

                    int affectedRows = pstmt.executeUpdate();
                    if (affectedRows > 0) {
                        // 释放旧引用
                        releaseOldRefs(conn, oldRefs);
                        conn.commit();
                        return true;
                    }

                    conn.rollback();
                    return false;
                }
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新请求失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除请求
     */
    public boolean deleteRequest(int requestId) {
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 读取引用
                String[] refs = readRequestHashRefs(conn, requestId);

                String sql = "DELETE FROM requests WHERE id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setInt(1, requestId);
                    int affectedRows = pstmt.executeUpdate();
                    if (affectedRows > 0) {
                        // 释放引用
                        releaseOldRefs(conn, refs);
                        removeFromValidationCache(requestId);
                        conn.commit();
                        return true;
                    }
                    conn.rollback();
                    return false;
                }
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除请求失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 获取所有请求
     */
    public List<Map<String, Object>> getAllRequests() {
        // 使用 JOIN string_pool 展开 domain/path/query/api
        String sql = "SELECT r.id, r.protocol, r.domain_hash, r.path_hash, r.query_hash, r.method, " +
                "r.add_time, r.comment, r.color, " +
                "r.req_header_hash, r.req_body_hash, r.req_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query, sa.value as api " +
                "FROM requests r " +
                "LEFT JOIN string_pool sd ON r.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON r.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON r.query_hash = sq.hash " +
                "LEFT JOIN string_pool sa ON r.api_hash = sa.hash " +
                "ORDER BY r.id DESC";

        List<Map<String, Object>> requests = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                try {
                    Map<String, Object> request = new HashMap<>();
                    int id = rs.getInt("id");
                    request.put("id", id);
                    request.put("protocol", HttpEnum.intToProtocol(rs.getInt("protocol")));
                    request.put("domain", getStringWithDefault(rs, "domain", "example.com"));
                    request.put("path", getStringWithDefault(rs, "path", "/"));
                    request.put("query", getStringWithDefault(rs, "query", ""));
                    request.put("method", HttpEnum.intToMethod(rs.getInt("method")));
                    request.put("add_time", getStringWithDefault(rs, "add_time", ""));
                    request.put("comment", getStringWithDefault(rs, "comment", ""));

                    // 处理API值（如果api为null，使用path作为默认值）
                    String apiValue = rs.getString("api");
                    request.put("api", (apiValue != null) ? apiValue : getStringWithDefault(rs, "path", "/"));

                    // 处理颜色
                    String colorStr = rs.getString("color");
                    if (colorStr != null && !colorStr.isEmpty()) {
                        try {
                            request.put("color", Color.decode(colorStr));
                        } catch (NumberFormatException e) {
                            request.put("color", null);
                        }
                    } else {
                        request.put("color", null);
                    }

                    // 重构请求数据
                    String reqHeaderHash = rs.getString("req_header_hash");
                    String reqBodyHash = rs.getString("req_body_hash");
                    String reqBodyStorage = rs.getString("req_body_storage");

                    byte[] requestData = reconstructor.reconstructRequest(conn, reqHeaderHash, reqBodyHash, reqBodyStorage);
                    if (requestData != null && requestData.length > 0) {
                        request.put("request_data", requestData);
                    } else {
                        String basicRequest = createBasicRequest(
                                (String) request.get("method"),
                                (String) request.get("protocol"),
                                (String) request.get("domain"),
                                (String) request.get("path"),
                                (String) request.get("query")
                        );
                        request.put("request_data", basicRequest.getBytes());
                    }

                    requests.add(request);
                } catch (Exception e) {
                    BurpExtender.printError("[!] 处理请求记录时出错: " + e.getMessage());
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取请求列表失败: " + e.getMessage());
        }

        return requests;
    }

    /**
     * 获取单个请求
     */
    public Map<String, Object> getRequest(int requestId) {
        String sql = "SELECT r.id, r.protocol, r.domain_hash, r.path_hash, r.query_hash, r.method, " +
                "r.add_time, r.comment, r.color, " +
                "r.req_header_hash, r.req_body_hash, r.req_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query, sa.value as api " +
                "FROM requests r " +
                "LEFT JOIN string_pool sd ON r.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON r.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON r.query_hash = sq.hash " +
                "LEFT JOIN string_pool sa ON r.api_hash = sa.hash " +
                "WHERE r.id = ?";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, requestId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    try {
                        Map<String, Object> request = new HashMap<>();
                        request.put("id", rs.getInt("id"));
                        request.put("protocol", HttpEnum.intToProtocol(rs.getInt("protocol")));
                        request.put("domain", getStringWithDefault(rs, "domain", "example.com"));
                        request.put("path", getStringWithDefault(rs, "path", "/"));
                        request.put("query", getStringWithDefault(rs, "query", ""));
                        request.put("method", HttpEnum.intToMethod(rs.getInt("method")));
                        request.put("add_time", getStringWithDefault(rs, "add_time", ""));
                        request.put("comment", getStringWithDefault(rs, "comment", ""));

                        // 处理API值（如果api为null，使用path作为默认值）
                        String apiValue = rs.getString("api");
                        request.put("api", (apiValue != null) ? apiValue : getStringWithDefault(rs, "path", "/"));

                        String colorStr = rs.getString("color");
                        if (colorStr != null && !colorStr.isEmpty()) {
                            try {
                                request.put("color", Color.decode(colorStr));
                            } catch (NumberFormatException e) {
                                request.put("color", null);
                            }
                        } else {
                            request.put("color", null);
                        }

                        String reqHeaderHash = rs.getString("req_header_hash");
                        String reqBodyHash = rs.getString("req_body_hash");
                        String reqBodyStorage = rs.getString("req_body_storage");

                        byte[] requestData = reconstructor.reconstructRequest(conn, reqHeaderHash, reqBodyHash, reqBodyStorage);
                        if (requestData != null && requestData.length > 0) {
                            request.put("request_data", requestData);
                        } else {
                            String basicRequest = createBasicRequest(
                                    (String) request.get("method"),
                                    (String) request.get("protocol"),
                                    (String) request.get("domain"),
                                    (String) request.get("path"),
                                    (String) request.get("query")
                            );
                            request.put("request_data", basicRequest.getBytes());
                        }

                        return request;
                    } catch (Exception e) {
                        BurpExtender.printError("[!] 处理请求ID: " + requestId + " 时出错: " + e.getMessage());
                    }
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取请求失败: " + e.getMessage());
        }

        return null;
    }

    /**
     * 更新请求备注
     */
    public boolean updateRequestComment(int requestId, String comment) {
        String sql = "UPDATE requests SET comment = ? WHERE id = ?";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, comment);
            pstmt.setInt(2, requestId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新请求备注失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 更新请求颜色
     */
    public boolean updateRequestColor(int requestId, Color color) {
        String sql = "UPDATE requests SET color = ? WHERE id = ?";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            if (color != null) {
                pstmt.setString(1, String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue()));
            } else {
                pstmt.setNull(1, java.sql.Types.VARCHAR);
            }
            pstmt.setInt(2, requestId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新请求颜色失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 清空所有请求
     */
    public boolean clearAllRequests() {
        try (Connection conn = dbManager.getConnection()) {
            String sql = "DELETE FROM requests";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.executeUpdate();
            }
            clearValidationCache();

            // 重置 AUTOINCREMENT 序列
            try (java.sql.Statement stmt = conn.createStatement()) {
                stmt.execute("DELETE FROM sqlite_sequence WHERE name = 'requests'");
            }

            // 触发全量 ref_count 重算
            GarbageCollectorService gcService = dbManager.getGcService();
            if (gcService != null) {
                gcService.fullReclamation();
            }

            return true;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 清空请求失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 验证请求ID是否存在（带缓存）
     */
    public boolean isValidRequestId(int requestId) {
        if (requestId <= 0) return false;
        cleanupCacheIfNeeded();

        Boolean cachedResult = requestValidationCache.get(requestId);
        if (cachedResult != null) return cachedResult;

        String sql = "SELECT COUNT(*) FROM requests WHERE id = ?";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, requestId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    boolean exists = rs.getInt(1) > 0;
                    requestValidationCache.put(requestId, exists);
                    return exists;
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 验证请求ID失败: " + e.getMessage());
        }
        return false;
    }

    public void clearValidationCache() {
        requestValidationCache.clear();
        lastCacheCleanup = System.currentTimeMillis();
    }

    public void removeFromValidationCache(int requestId) {
        requestValidationCache.remove(requestId);
    }

    // ========== 内部辅助方法 ==========

    private String getStringWithDefault(ResultSet rs, String columnName, String defaultValue) throws SQLException {
        String value = rs.getString(columnName);
        return (value != null) ? value : defaultValue;
    }

    private String createBasicRequest(String method, String protocol, String domain, String path, String query) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ");
        sb.append(path);
        if (query != null && !query.isEmpty()) {
            sb.append("?").append(query);
        }
        sb.append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(domain).append("\r\n");
        sb.append("User-Agent: Mozilla/5.0\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        return sb.toString();
    }

    private void cleanupCacheIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - lastCacheCleanup > CACHE_CLEANUP_INTERVAL) {
            if (requestValidationCache.size() > 1000) {
                requestValidationCache.clear();
            }
            lastCacheCleanup = now;
        }
    }

    /**
     * 读取请求记录的 hash 引用
     * 返回 [domainHash, pathHash, queryHash, reqHeaderHash, reqBodyHash, reqBodyStorage, apiHash]
     */
    private String[] readRequestHashRefs(Connection conn, int requestId) throws SQLException {
        String sql = "SELECT domain_hash, path_hash, query_hash, req_header_hash, req_body_hash, req_body_storage, api_hash FROM requests WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, requestId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new String[]{
                            rs.getString("domain_hash"),
                            rs.getString("path_hash"),
                            rs.getString("query_hash"),
                            rs.getString("req_header_hash"),
                            rs.getString("req_body_hash"),
                            rs.getString("req_body_storage"),
                            rs.getString("api_hash")
                    };
                }
            }
        }
        return new String[7];
    }

    /**
     * 释放旧引用
     */
    private void releaseOldRefs(Connection conn, String[] refs) throws SQLException {
        if (refs == null) return;

        // 释放字符串引用
        poolManager.releaseString(conn, refs[0]); // domain_hash
        poolManager.releaseString(conn, refs[1]); // path_hash
        poolManager.releaseString(conn, refs[2]); // query_hash

        // 释放头部引用
        poolManager.releaseHeader(conn, refs[3]);

        // 释放 Body 引用
        poolManager.releaseBody(conn, refs[4], refs[5]);

        // 释放 API 引用
        poolManager.releaseString(conn, refs[6]); // api_hash
    }
}
