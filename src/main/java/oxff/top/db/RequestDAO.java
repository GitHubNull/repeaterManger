package oxff.top.db;

import burp.BurpExtender;
import burp.IRequestInfo;
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
 */
public class RequestDAO {
    private final DatabaseManager dbManager;
    private final Map<Integer, Boolean> requestValidationCache;
    private long lastCacheCleanup = 0;
    private static final long CACHE_CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
    
    public RequestDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestValidationCache = new ConcurrentHashMap<>();
    }
    
    /**
     * 保存请求数据
     */
    public int saveRequest(IRequestInfo requestInfo, byte[] requestData) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            
            String url = requestInfo.getUrl().toString();
            String method = requestInfo.getMethod();
            
            // 解析URL组件
            String protocol = url.startsWith("https://") ? "https" : "http";
            String remaining = url.substring(protocol.length() + 3); // 跳过 "://"
            
            String domain;
            String path;
            String query = "";
            
            int pathStart = remaining.indexOf('/');
            if (pathStart > 0) {
                domain = remaining.substring(0, pathStart);
                remaining = remaining.substring(pathStart);
            } else {
                domain = remaining;
                remaining = "/";
            }
            
            int queryStart = remaining.indexOf('?');
            if (queryStart > 0) {
                path = remaining.substring(0, queryStart);
                query = remaining.substring(queryStart + 1);
            } else {
                path = remaining;
            }
            
            String sql = "INSERT INTO requests (protocol, domain, path, query, method, request_data, add_time) " +
                        "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
            
            try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, protocol);
                pstmt.setString(2, domain);
                pstmt.setString(3, path);
                pstmt.setString(4, query);
                pstmt.setString(5, method);
                pstmt.setBytes(6, requestData);
                
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
            BurpExtender.printError("[!] 保存请求数据失败: " + e.getMessage());
            return -1;
        }
    }
    
    /**
     * 保存请求数据
     */
    public int saveRequest(String protocol, String domain, String path, String query, String method, byte[] requestData) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            
            String sql = "INSERT INTO requests (protocol, domain, path, query, method, request_data) VALUES (?, ?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, protocol);
                pstmt.setString(2, domain);
                pstmt.setString(3, path);
                pstmt.setString(4, query);
                pstmt.setString(5, method);
                pstmt.setBytes(6, requestData);
                
                int affectedRows = pstmt.executeUpdate();
                if (affectedRows > 0) {
                    try (ResultSet rs = pstmt.getGeneratedKeys()) {
                        if (rs.next()) {
                            int id = rs.getInt(1);
                            conn.commit();
                            return id;
                        }
                    }
                }
                
                conn.rollback();
                return -1;
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
        String sql = "UPDATE requests SET protocol = ?, domain = ?, path = ?, " +
                   "query = ?, method = ?, request_data = ? WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, protocol);
            pstmt.setString(2, domain);
            pstmt.setString(3, path);
            pstmt.setString(4, query);
            pstmt.setString(5, method);
            pstmt.setBytes(6, requestData);
            pstmt.setInt(7, requestId);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新请求失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 删除请求
     */
    public boolean deleteRequest(int requestId) {
        String sql = "DELETE FROM requests WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, requestId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                removeFromValidationCache(requestId);
            }
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除请求失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取所有请求
     */
    public List<Map<String, Object>> getAllRequests() {
        String sql = "SELECT id, protocol, domain, path, query, method, add_time, comment, color, request_data " +
                   "FROM requests ORDER BY id DESC";
        
        List<Map<String, Object>> requests = new ArrayList<>();
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            
            while (rs.next()) {
                try {
                    Map<String, Object> request = new HashMap<>();
                    int id = rs.getInt("id");
                    request.put("id", id);
                    request.put("protocol", getStringWithDefault(rs, "protocol", "http"));
                    request.put("domain", getStringWithDefault(rs, "domain", "example.com"));
                    request.put("path", getStringWithDefault(rs, "path", "/"));
                    request.put("query", getStringWithDefault(rs, "query", ""));
                    request.put("method", getStringWithDefault(rs, "method", "GET"));
                    request.put("add_time", getStringWithDefault(rs, "add_time", ""));
                    request.put("comment", getStringWithDefault(rs, "comment", ""));
                    
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
                    
                    // 处理请求数据
                    byte[] requestData = rs.getBytes("request_data");
                    if (requestData != null && requestData.length > 0) {
                        request.put("request_data", requestData);
                        BurpExtender.printOutput("[*] 加载请求ID: " + id + ", 数据大小: " + requestData.length + " 字节");
                    } else {
                        // 如果请求数据为空，创建一个简单的请求
                        String basicRequest = createBasicRequest(
                            (String)request.get("method"), 
                            (String)request.get("protocol"), 
                            (String)request.get("domain"),
                            (String)request.get("path"),
                            (String)request.get("query")
                        );
                        request.put("request_data", basicRequest.getBytes());
                        BurpExtender.printError("[!] 请求ID: " + id + " 没有有效数据，已创建基本请求");
                    }
                    
                    requests.add(request);
                } catch (Exception e) {
                    BurpExtender.printError("[!] 处理请求记录时出错: " + e.getMessage());
                    // 继续处理下一条记录，不让一条错误记录影响整个列表
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
        String sql = "SELECT id, protocol, domain, path, query, method, add_time, comment, color, request_data " +
                   "FROM requests WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, requestId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    try {
                        Map<String, Object> request = new HashMap<>();
                        request.put("id", rs.getInt("id"));
                        request.put("protocol", getStringWithDefault(rs, "protocol", "http"));
                        request.put("domain", getStringWithDefault(rs, "domain", "example.com"));
                        request.put("path", getStringWithDefault(rs, "path", "/"));
                        request.put("query", getStringWithDefault(rs, "query", ""));
                        request.put("method", getStringWithDefault(rs, "method", "GET"));
                        request.put("add_time", getStringWithDefault(rs, "add_time", ""));
                        request.put("comment", getStringWithDefault(rs, "comment", ""));
                        
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
                        
                        // 处理请求数据
                        byte[] requestData = rs.getBytes("request_data");
                        if (requestData != null && requestData.length > 0) {
                            request.put("request_data", requestData);
                            BurpExtender.printOutput("[*] 加载请求ID: " + requestId + ", 数据大小: " + requestData.length + " 字节");
                        } else {
                            // 如果请求数据为空，创建一个简单的请求
                            String basicRequest = createBasicRequest(
                                (String)request.get("method"), 
                                (String)request.get("protocol"), 
                                (String)request.get("domain"),
                                (String)request.get("path"),
                                (String)request.get("query")
                            );
                            request.put("request_data", basicRequest.getBytes());
                            BurpExtender.printError("[!] 请求ID: " + requestId + " 没有有效数据，已创建基本请求");
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
     * 安全地从ResultSet获取字符串，如果为null则返回默认值
     */
    private String getStringWithDefault(ResultSet rs, String columnName, String defaultValue) throws SQLException {
        String value = rs.getString(columnName);
        return (value != null) ? value : defaultValue;
    }
    
    /**
     * 创建基本的HTTP请求
     */
    private String createBasicRequest(String method, String protocol, String domain, String path, String query) {
        StringBuilder sb = new StringBuilder();
        
        // 构建请求行
        sb.append(method).append(" ");
        sb.append(path);
        if (query != null && !query.isEmpty()) {
            sb.append("?").append(query);
        }
        sb.append(" HTTP/1.1\r\n");
        
        // 添加头部
        sb.append("Host: ").append(domain).append("\r\n");
        sb.append("User-Agent: Mozilla/5.0\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        
        return sb.toString();
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
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
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
                String colorHex = String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
                pstmt.setString(1, colorHex);
            } else {
                pstmt.setNull(1, java.sql.Types.VARCHAR);
            }
            
            pstmt.setInt(2, requestId);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新请求颜色失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 清空所有请求
     */
    public boolean clearAllRequests() {
        String sql = "DELETE FROM requests";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.executeUpdate();
            clearValidationCache();
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
        if (requestId <= 0) {
            return false;
        }
        
        // 清理过期缓存
        cleanupCacheIfNeeded();
        
        // 检查缓存
        Boolean cachedResult = requestValidationCache.get(requestId);
        if (cachedResult != null) {
            return cachedResult;
        }
        
        // 查询数据库
        String sql = "SELECT COUNT(*) FROM requests WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, requestId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    boolean exists = rs.getInt(1) > 0;
                    // 缓存结果
                    requestValidationCache.put(requestId, exists);
                    return exists;
                }
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 验证请求ID失败: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * 清理验证缓存
     */
    public void clearValidationCache() {
        requestValidationCache.clear();
        lastCacheCleanup = System.currentTimeMillis();
    }
    
    /**
     * 按需清理缓存
     */
    private void cleanupCacheIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - lastCacheCleanup > CACHE_CLEANUP_INTERVAL) {
            // 清理超过一半的缓存条目以避免内存泄漏
            if (requestValidationCache.size() > 1000) {
                requestValidationCache.clear();
            }
            lastCacheCleanup = now;
        }
    }
    
    /**
     * 从缓存中移除指定的请求ID
     */
    public void removeFromValidationCache(int requestId) {
        requestValidationCache.remove(requestId);
    }
} 