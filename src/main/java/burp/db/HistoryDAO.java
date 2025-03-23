package burp.db;

import burp.BurpExtender;
import burp.http.RequestResponseRecord;
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
     * 
     * @param record 历史记录对象
     * @return 新插入记录的ID
     */
    public int saveHistory(RequestResponseRecord record) {
        String sql = "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, comment, request_data, response_data) " +
                   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = dbManager.getConnection();
            
            // 关闭自动提交，启用事务控制
            boolean originalAutoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            
            pstmt.setInt(1, record.getRequestId());
            pstmt.setString(2, record.getMethod());
            pstmt.setString(3, record.getProtocol());
            pstmt.setString(4, record.getDomain());
            pstmt.setString(5, record.getPath());
            pstmt.setString(6, record.getQueryParameters());
            pstmt.setInt(7, record.getStatusCode());
            pstmt.setInt(8, record.getResponseLength());
            pstmt.setInt(9, record.getResponseTime());
            pstmt.setString(10, record.getComment());
            pstmt.setBytes(11, record.getRequestData());
            pstmt.setBytes(12, record.getResponseData());
            
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
            
            BurpExtender.printOutput("[+] 已保存历史记录到数据库，ID: " + generatedId + 
                ", 请求ID: " + record.getRequestId() + 
                ", 请求大小: " + (record.getRequestData() != null ? record.getRequestData().length : 0) + " 字节" +
                ", 响应大小: " + (record.getResponseData() != null ? record.getResponseData().length : 0) + " 字节");
            
            // 执行PRAGMA wal_checkpoint确保数据已写入磁盘
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA wal_checkpoint(FULL)");
            } catch (SQLException e) {
                BurpExtender.printError("[!] 执行WAL检查点失败: " + e.getMessage());
                // 继续执行而不是抛出异常
            }
            
            return generatedId;
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());
            
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