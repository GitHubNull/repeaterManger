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
    private final RequestDAO requestDAO;
    
    public HistoryDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
    }
    
    /**
     * 内部历史记录保存方法（用于IRequestInfo参数）
     */
    private int saveHistoryInternal(Connection conn, int requestId, IRequestInfo requestInfo, byte[] requestData, byte[] responseData) throws SQLException {
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
        
        // 验证request_id是否存在，如果不存在则设置为NULL
        if (requestId > 0 && !requestDAO.isValidRequestId(requestId)) {
            BurpExtender.printOutput("[*] 请求ID " + requestId + " 不存在，将使用NULL作为外键");
            requestId = -1; // 设置为无效ID，后续会转换为NULL
        }
        
        String sql = "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                    "response_length, response_time, timestamp, request_data, response_data) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            // Handle NULL request_id for unsaved requests or invalid request IDs
            if (requestId <= 0) {
                pstmt.setNull(1, java.sql.Types.INTEGER);
            } else {
                pstmt.setInt(1, requestId);
            }
            
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
                        return rs.getInt(1);
                    }
                }
            }
            
            return -1;
        }
    }
    
    /**
     * 保存历史记录（IRequestInfo版本）
     */
    public int saveHistory(int requestId, IRequestInfo requestInfo, byte[] requestData, byte[] responseData) {
        Connection conn = null;
        try {
            conn = DatabaseManager.getInstance().getConnection();
            
            // 简化事务管理，直接使用自动提交模式
            BurpExtender.printOutput("[*] 开始保存历史记录（IRequestInfo）");
            
            int historyId = saveHistoryInternal(conn, requestId, requestInfo, requestData, responseData);
            
            if (historyId > 0) {
                BurpExtender.printOutput("[+] 历史记录已保存，ID: " + historyId);
                return historyId;
            } else {
                BurpExtender.printError("[!] 保存历史记录失败：没有受影响的行");
                return -1;
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());
            
            // 特殊处理外键约束错误
            if (e.getMessage().contains("FOREIGN KEY constraint failed")) {
                BurpExtender.printError("[!] 外键约束失败，尝试使用NULL请求ID重新保存");
                
                // 创建新的记录对象并重新尝试
                RequestResponseRecord fallbackRecord = new RequestResponseRecord();
                fallbackRecord.setRequestId(-1);
                fallbackRecord.setMethod(requestInfo.getMethod());
                fallbackRecord.setProtocol(requestInfo.getUrl().toString().startsWith("https://") ? "https" : "http");
                
                // 解析URL组件
                String url = requestInfo.getUrl().toString();
                String protocol = url.startsWith("https://") ? "https" : "http";
                String remaining = url.substring(protocol.length() + 3);
                
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
                
                fallbackRecord.setDomain(domain);
                fallbackRecord.setPath(path);
                fallbackRecord.setQueryParameters(query);
                fallbackRecord.setStatusCode(BurpExtender.helpers.analyzeResponse(responseData).getStatusCode());
                fallbackRecord.setResponseLength(responseData.length);
                fallbackRecord.setResponseTime(0);
                fallbackRecord.setTimestamp(new java.util.Date());
                fallbackRecord.setRequestData(requestData);
                fallbackRecord.setResponseData(responseData);
                
                // 重新尝试保存，使用NULL request_id
                return saveHistory(fallbackRecord);
            }
            
            return -1;
        } finally {
            // 确保连接关闭
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
     * 内部历史记录保存方法（不带事务管理）
     */
    private int saveHistoryInternal(Connection conn, RequestResponseRecord record) throws SQLException {
        // 验证request_id是否存在，如果不存在则设置为NULL
        int requestId = record.getRequestId();
        if (requestId > 0 && !requestDAO.isValidRequestId(requestId)) {
            BurpExtender.printOutput("[*] 请求ID " + requestId + " 不存在，将使用NULL作为外键");
            requestId = -1; // 设置为无效ID，后续会转换为NULL
        }
        
        String sql = "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                    "response_length, response_time, timestamp, request_data, response_data, comment, color) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
            // Handle NULL request_id for unsaved requests or invalid request IDs
            if (requestId <= 0) {
                pstmt.setNull(1, java.sql.Types.INTEGER);
            } else {
                pstmt.setInt(1, requestId);
            }
            
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
            
            // 设置备注和颜色
            if (record.getComment() != null && !record.getComment().isEmpty()) {
                pstmt.setString(13, record.getComment());
            } else {
                pstmt.setNull(13, java.sql.Types.VARCHAR);
            }
            
            if (record.getColor() != null) {
                String colorHex = String.format("#%02x%02x%02x", 
                    record.getColor().getRed(), 
                    record.getColor().getGreen(), 
                    record.getColor().getBlue());
                pstmt.setString(14, colorHex);
            } else {
                pstmt.setNull(14, java.sql.Types.VARCHAR);
            }
            
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            }
            
            return -1;
        }
    }

    /**
     * 保存历史记录
     */
    public int saveHistory(RequestResponseRecord record) {
        Connection conn = null;
        try {
            // 验证数据库连接
            if (!dbManager.isConnectionValid()) {
                BurpExtender.printError("[!] 保存历史记录失败: 数据库连接无效");
                return -1;
            }
            
            conn = dbManager.getConnection();
            
            // 简化事务管理，直接使用自动提交模式
            BurpExtender.printOutput("[*] 开始保存历史记录");
            
            int historyId = saveHistoryInternal(conn, record);
            
            if (historyId > 0) {
                BurpExtender.printOutput("[+] 历史记录已保存，ID: " + historyId);
                return historyId;
            } else {
                BurpExtender.printError("[!] 保存历史记录失败：没有受影响的行");
                return -1;
            }
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());
            
            // 特殊处理外键约束错误
            if (e.getMessage().contains("FOREIGN KEY constraint failed")) {
                BurpExtender.printError("[!] 外键约束失败，尝试使用NULL请求ID重新保存");
                
                // 创建新的记录对象并设置NULL request_id
                RequestResponseRecord fallbackRecord = new RequestResponseRecord();
                fallbackRecord.setRequestId(-1);
                fallbackRecord.setMethod(record.getMethod());
                fallbackRecord.setProtocol(record.getProtocol());
                fallbackRecord.setDomain(record.getDomain());
                fallbackRecord.setPath(record.getPath());
                fallbackRecord.setQueryParameters(record.getQueryParameters());
                fallbackRecord.setStatusCode(record.getStatusCode());
                fallbackRecord.setResponseLength(record.getResponseLength());
                fallbackRecord.setResponseTime(record.getResponseTime());
                fallbackRecord.setTimestamp(record.getTimestamp());
                fallbackRecord.setRequestData(record.getRequestData());
                fallbackRecord.setResponseData(record.getResponseData());
                fallbackRecord.setComment(record.getComment());
                fallbackRecord.setColor(record.getColor());
                
                // 重新尝试保存，使用NULL request_id
                return saveHistory(fallbackRecord);
            }
            
            return -1;
        } finally {
            // 确保连接关闭
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
     * 获取所有历史记录
     */
    public List<RequestResponseRecord> getAllHistory() {
        String sql = "SELECT id, request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, timestamp, comment, color, request_data, response_data " +
                   "FROM history ORDER BY id DESC";
        
        List<RequestResponseRecord> records = new ArrayList<>();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = dbManager.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            
            while (rs.next()) {
                RequestResponseRecord record = new RequestResponseRecord();
                record.setId(rs.getInt("id"));
                
                // Handle NULL request_id from database
                int requestId = rs.getInt("request_id");
                if (rs.wasNull()) {
                    requestId = -1; // Use -1 to represent unsaved requests
                }
                record.setRequestId(requestId);
                
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
        } finally {
            // 确保所有资源都被正确关闭
            try {
                if (rs != null) rs.close();
                if (pstmt != null) pstmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                BurpExtender.printError("[!] 关闭数据库资源失败: " + e.getMessage());
            }
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
                    
                    // Handle NULL request_id from database
                    int reqId = rs.getInt("request_id");
                    if (rs.wasNull()) {
                        reqId = -1; // Use -1 to represent unsaved requests
                    }
                    record.setRequestId(reqId);
                    
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
                    
                    // Handle NULL request_id from database
                    int reqId = rs.getInt("request_id");
                    if (rs.wasNull()) {
                        reqId = -1; // Use -1 to represent unsaved requests
                    }
                    record.setRequestId(reqId);
                    
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
    
    /**
     * 根据请求ID获取最新的N条历史记录
     * @param requestId 请求ID
     * @param limit 获取记录数量限制
     * @return 历史记录列表，按时间倒序排列
     */
    public List<RequestResponseRecord> getLatestHistoryByRequestId(int requestId, int limit) {
        String sql = "SELECT id, request_id, method, protocol, domain, path, query, status_code, " +
                   "response_length, response_time, timestamp, comment, color, request_data, response_data " +
                   "FROM history WHERE request_id = ? ORDER BY id DESC LIMIT ?";
        
        List<RequestResponseRecord> records = new ArrayList<>();
        
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, requestId);
            pstmt.setInt(2, limit);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    RequestResponseRecord record = new RequestResponseRecord();
                    record.setId(rs.getInt("id"));
                    
                    // Handle NULL request_id from database
                    int reqId = rs.getInt("request_id");
                    if (rs.wasNull()) {
                        reqId = -1; // Use -1 to represent unsaved requests
                    }
                    record.setRequestId(reqId);
                    
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
            BurpExtender.printError("[!] 获取最新历史记录失败: " + e.getMessage());
        }
        
        return records;
    }
} 