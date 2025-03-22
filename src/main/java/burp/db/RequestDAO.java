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
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
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
                        return rs.getInt(1);
                    }
                }
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存请求失败: " + e.getMessage());
        }
        
        return -1;
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
                Map<String, Object> request = new HashMap<>();
                request.put("id", rs.getInt("id"));
                request.put("protocol", rs.getString("protocol"));
                request.put("domain", rs.getString("domain"));
                request.put("path", rs.getString("path"));
                request.put("query", rs.getString("query"));
                request.put("method", rs.getString("method"));
                request.put("add_time", rs.getString("add_time"));
                request.put("comment", rs.getString("comment"));
                
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
                
                request.put("request_data", rs.getBytes("request_data"));
                requests.add(request);
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
                    Map<String, Object> request = new HashMap<>();
                    request.put("id", rs.getInt("id"));
                    request.put("protocol", rs.getString("protocol"));
                    request.put("domain", rs.getString("domain"));
                    request.put("path", rs.getString("path"));
                    request.put("query", rs.getString("query"));
                    request.put("method", rs.getString("method"));
                    request.put("add_time", rs.getString("add_time"));
                    request.put("comment", rs.getString("comment"));
                    
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
                    
                    request.put("request_data", rs.getBytes("request_data"));
                    return request;
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