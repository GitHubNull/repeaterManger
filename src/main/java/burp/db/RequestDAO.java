package burp.db;

import burp.BurpExtender;
import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 请求数据访问对象
 */
public class RequestDAO {
    private final DatabaseManager dbManager;
    
    public RequestDAO() {
        this.dbManager = DatabaseManager.getInstance();
    }
    
    /**
     * 保存请求到数据库
     * 
     * @param protocol 协议
     * @param domain 域名
     * @param path 路径
     * @param query 查询参数
     * @param method 请求方法
     * @param requestData 请求数据
     * @return 新插入记录的ID
     */
    public int saveRequest(String protocol, String domain, String path, 
                         String query, String method, byte[] requestData) {
        String sql = "INSERT INTO requests (protocol, domain, path, query, method, request_data) " +
                   "VALUES (?, ?, ?, ?, ?, ?)";
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = dbManager.getConnection();
            
            // 关闭自动提交
            boolean originalAutoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            
            pstmt.setString(1, protocol);
            pstmt.setString(2, domain);
            pstmt.setString(3, path);
            pstmt.setString(4, query);
            pstmt.setString(5, method);
            pstmt.setBytes(6, requestData);
            
            int affectedRows = pstmt.executeUpdate();
            
            int generatedId = -1;
            if (affectedRows > 0) {
                rs = pstmt.getGeneratedKeys();
                if (rs.next()) {
                    generatedId = rs.getInt(1);
                }
            }
            
            // 手动提交事务
            conn.commit();
            
            // 恢复原始的自动提交设置
            conn.setAutoCommit(originalAutoCommit);
            
            BurpExtender.printOutput("[+] 已保存请求到数据库，ID: " + generatedId + 
                ", 大小: " + (requestData != null ? requestData.length : 0) + " 字节");
            
            // 执行PRAGMA wal_checkpoint确保数据已写入磁盘
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA wal_checkpoint(FULL)");
            } catch (SQLException e) {
                BurpExtender.printError("[!] 执行WAL检查点失败: " + e.getMessage());
                // 继续执行而不是抛出异常
            }
            
            return generatedId;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存请求失败: " + e.getMessage());
            
            // 如果发生错误，尝试回滚事务
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    BurpExtender.printError("[!] 回滚事务失败: " + ex.getMessage());
                }
            }
            
            return -1;
        } finally {
            // 关闭资源
            try {
                if (rs != null) rs.close();
                if (pstmt != null) pstmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                BurpExtender.printError("[!] 关闭数据库资源失败: " + e.getMessage());
            }
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
            return true;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 清空请求失败: " + e.getMessage());
            return false;
        }
    }
} 