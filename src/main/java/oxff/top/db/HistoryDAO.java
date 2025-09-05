package oxff.top.db;

import burp.BurpExtender;
import burp.IRequestInfo;
import oxff.top.http.RequestResponseRecord;
import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * 历史记录数据访问对象
 */
public class HistoryDAO {
    private final DatabaseManager dbManager;
    
    public HistoryDAO() {
        this.dbManager = DatabaseManager.getInstance();
    }
    
    /**
     * 保存历史记录
     */
    public int saveHistory(int requestId, IRequestInfo requestInfo, byte[] requestData, byte[] responseData) {
        Connection conn = null;
        try {
            conn = DatabaseManager.getInstance().getConnection();
            conn.setAutoCommit(false);
            
            String url = requestInfo.getUrl().toString();
            String method = requestInfo.getMethod();
            int statusCode = BurpExtender.helpers.analyzeResponse(responseData).getStatusCode();
            
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
            
            String sql = "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                        "response_length, response_time, timestamp, request_data, response_data) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setInt(1, requestId);
                pstmt.setString(2, method);
                pstmt.setString(3, protocol);
                pstmt.setString(4, domain);
                pstmt.setString(5, path);
                pstmt.setString(6, query);
                pstmt.setInt(7, statusCode);
                pstmt.setInt(8, responseData.length);
                pstmt.setInt(9, 0); // response_time 默认为0
                pstmt.setTimestamp(10, new java.sql.Timestamp(System.currentTimeMillis()));
                pstmt.setBytes(11, requestData);
                pstmt.setBytes(12, responseData);
                
                int affectedRows = pstmt.executeUpdate();
                if (affectedRows > 0) {
                    try (ResultSet rs = pstmt.getGeneratedKeys()) {
                        if (rs.next()) {
                            int id = rs.getInt(1);
                            conn.commit();
                            BurpExtender.printOutput("[+] 历史记录已保存，ID: " + id);
                            return id;
                        }
                    }
                }
                
                conn.rollback();
                return -1;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    BurpExtender.printError("[!] 回滚事务失败: " + ex.getMessage());
                }
            }
            return -1;
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    BurpExtender.printError("[!] 关闭数据库连接失败: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * 保存历史记录
     */
    public int saveHistory(RequestResponseRecord record) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            
            String sql = "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                        "response_length, response_time, timestamp, request_data, response_data) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
                pstmt.setInt(1, record.getRequestId());
                pstmt.setString(2, record.getMethod());
                pstmt.setString(3, record.getProtocol());
                pstmt.setString(4, record.getDomain());
                pstmt.setString(5, record.getPath());
                pstmt.setString(6, record.getQueryParameters());
                pstmt.setInt(7, record.getStatusCode());
                pstmt.setInt(8, record.getResponseLength());
                pstmt.setInt(9, record.getResponseTime());
                pstmt.setTimestamp(10, new java.sql.Timestamp(record.getTimestamp().getTime()));
                pstmt.setBytes(11, record.getRequestData());
                pstmt.setBytes(12, record.getResponseData());
                
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
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());
            return -1;
        }
    }
    
    /**
     * 获取所有历史记录
     */
    public List<RequestResponseRecord> getAllHistory() {
        String sql = "SELECT id, request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, timestamp, comment, color, request_data, response_data " +
                   "FROM history ORDER BY id DESC";
        
        List<RequestResponseRecord> records = new ArrayList<>();
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            
            while (rs.next()) {
                RequestResponseRecord record = new RequestResponseRecord();
                record.setId(rs.getInt("id"));
                record.setRequestId(rs.getInt("request_id"));
                record.setMethod(rs.getString("method"));
                record.setProtocol(rs.getString("protocol"));
                record.setDomain(rs.getString("domain"));
                record.setPath(rs.getString("path"));
                record.setQueryParameters(rs.getString("query"));
                record.setStatusCode(rs.getInt("status_code"));
                record.setResponseLength(rs.getInt("response_length"));
                record.setResponseTime(rs.getInt("response_time"));
                record.setTimestamp(rs.getTimestamp("timestamp"));
                record.setComment(rs.getString("comment"));
                
                // 处理颜色
                String colorStr = rs.getString("color");
                if (colorStr != null && !colorStr.isEmpty()) {
                    try {
                        record.setColor(Color.decode(colorStr));
                    } catch (NumberFormatException e) {
                        record.setColor(null);
                    }
                }
                
                record.setRequestData(rs.getBytes("request_data"));
                record.setResponseData(rs.getBytes("response_data"));
                
                records.add(record);
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取历史记录失败: " + e.getMessage());
        }
        
        return records;
    }
    
    /**
     * 获取单个历史记录
     */
    public RequestResponseRecord getHistory(int historyId) {
        String sql = "SELECT id, request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, timestamp, comment, color, request_data, response_data " +
                   "FROM history WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, historyId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    RequestResponseRecord record = new RequestResponseRecord();
                    record.setId(rs.getInt("id"));
                    record.setRequestId(rs.getInt("request_id"));
                    record.setMethod(rs.getString("method"));
                    record.setProtocol(rs.getString("protocol"));
                    record.setDomain(rs.getString("domain"));
                    record.setPath(rs.getString("path"));
                    record.setQueryParameters(rs.getString("query"));
                    record.setStatusCode(rs.getInt("status_code"));
                    record.setResponseLength(rs.getInt("response_length"));
                    record.setResponseTime(rs.getInt("response_time"));
                    record.setTimestamp(rs.getTimestamp("timestamp"));
                    record.setComment(rs.getString("comment"));
                    
                    // 处理颜色
                    String colorStr = rs.getString("color");
                    if (colorStr != null && !colorStr.isEmpty()) {
                        try {
                            record.setColor(Color.decode(colorStr));
                        } catch (NumberFormatException e) {
                            record.setColor(null);
                        }
                    }
                    
                    record.setRequestData(rs.getBytes("request_data"));
                    record.setResponseData(rs.getBytes("response_data"));
                    
                    return record;
                }
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取历史记录失败: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 更新历史记录备注
     */
    public boolean updateHistoryComment(int historyId, String comment) {
        String sql = "UPDATE history SET comment = ? WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, comment);
            pstmt.setInt(2, historyId);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新历史记录备注失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 更新历史记录颜色
     */
    public boolean updateHistoryColor(int historyId, Color color) {
        String sql = "UPDATE history SET color = ? WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            if (color != null) {
                String colorHex = String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
                pstmt.setString(1, colorHex);
            } else {
                pstmt.setNull(1, java.sql.Types.VARCHAR);
            }
            
            pstmt.setInt(2, historyId);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新历史记录颜色失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 删除历史记录
     */
    public boolean deleteHistory(int historyId) {
        String sql = "DELETE FROM history WHERE id = ?";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, historyId);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除历史记录失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 清空所有历史记录
     */
    public boolean clearAllHistory() {
        String sql = "DELETE FROM history";
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.executeUpdate();
            return true;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 清空历史记录失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 根据请求ID获取历史记录
     */
    public List<RequestResponseRecord> getHistoryByRequestId(int requestId) {
        String sql = "SELECT id, request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, timestamp, comment, color, request_data, response_data " +
                   "FROM history WHERE request_id = ? ORDER BY id DESC";
        
        List<RequestResponseRecord> records = new ArrayList<>();
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, requestId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    RequestResponseRecord record = new RequestResponseRecord();
                    record.setId(rs.getInt("id"));
                    record.setRequestId(rs.getInt("request_id"));
                    record.setMethod(rs.getString("method"));
                    record.setProtocol(rs.getString("protocol"));
                    record.setDomain(rs.getString("domain"));
                    record.setPath(rs.getString("path"));
                    record.setQueryParameters(rs.getString("query"));
                    record.setStatusCode(rs.getInt("status_code"));
                    record.setResponseLength(rs.getInt("response_length"));
                    record.setResponseTime(rs.getInt("response_time"));
                    record.setTimestamp(rs.getTimestamp("timestamp"));
                    record.setComment(rs.getString("comment"));
                    
                    // 处理颜色
                    String colorStr = rs.getString("color");
                    if (colorStr != null && !colorStr.isEmpty()) {
                        try {
                            record.setColor(Color.decode(colorStr));
                        } catch (NumberFormatException e) {
                            record.setColor(null);
                        }
                    }
                    
                    record.setRequestData(rs.getBytes("request_data"));
                    record.setResponseData(rs.getBytes("response_data"));
                    
                    records.add(record);
                }
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取历史记录失败: " + e.getMessage());
        }
        
        return records;
    }
} 