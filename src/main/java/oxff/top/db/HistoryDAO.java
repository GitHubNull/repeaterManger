package oxff.top.db;

import burp.BurpExtender;
import burp.IRequestInfo;
import oxff.top.db.pool.*;
import oxff.top.http.RequestResponseRecord;
import oxff.top.service.GarbageCollectorService;

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
 * 适配去重存储架构（v2 Schema）
 */
public class HistoryDAO {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final PoolManager poolManager;
    private final ContentReconstructor reconstructor;

    public HistoryDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.poolManager = new PoolManager();
        this.reconstructor = new ContentReconstructor();
    }

    /**
     * 内部历史记录保存方法（用于IRequestInfo参数）
     */
    private int saveHistoryInternal(Connection conn, int requestId, IRequestInfo requestInfo,
                                    byte[] requestData, byte[] responseData, long responseTime) throws SQLException {
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        int statusCode = BurpExtender.helpers.analyzeResponse(responseData).getStatusCode();

        // 解析URL组件
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

        // 验证request_id是否存在
        if (requestId > 0 && !requestDAO.isValidRequestId(requestId)) {
            BurpExtender.printOutput("[*] 请求ID " + requestId + " 不存在，将使用NULL作为外键");
            requestId = -1;
        }

        // 字符串池操作
        String domainHash = domain != null ? poolManager.ensureString(conn, domain) : null;
        String pathHash = path != null ? poolManager.ensureString(conn, path) : null;
        String queryHash = (query != null && !query.isEmpty()) ? poolManager.ensureString(conn, query) : null;

        // 枚举转换
        int protocolInt = HttpEnum.protocolToInt(protocol);
        int methodInt = HttpEnum.methodToInt(method);

        // 分割请求数据
        String reqHeaderHash = null;
        String reqBodyHash = null;
        String reqBodyStorage = BodyStorageRoute.NONE.getDbValue();

        if (requestData != null && requestData.length > 0) {
            SplitResult split = poolManager.getSplitter().splitRequest(requestData);
            reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
            if (split.hasBody()) {
                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                reqBodyHash = bodyResult[0];
                reqBodyStorage = bodyResult[1];
            }
        }

        // 分割响应数据
        String respHeaderHash = null;
        String respBodyHash = null;
        String respBodyStorage = BodyStorageRoute.NONE.getDbValue();

        if (responseData != null && responseData.length > 0) {
            SplitResult split = poolManager.getSplitter().splitResponse(responseData);
            respHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
            if (split.hasBody()) {
                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                respBodyHash = bodyResult[0];
                respBodyStorage = bodyResult[1];
            }
        }

        // 插入记录
        String sql = "INSERT INTO history (request_id, method, protocol, domain_hash, path_hash, query_hash, " +
                "status_code, response_length, response_time, timestamp, comment, color, " +
                "req_header_hash, req_body_hash, req_body_storage, " +
                "resp_header_hash, resp_body_hash, resp_body_storage) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            if (requestId <= 0) {
                pstmt.setNull(1, java.sql.Types.INTEGER);
            } else {
                pstmt.setInt(1, requestId);
            }

            pstmt.setInt(2, methodInt);
            pstmt.setInt(3, protocolInt);
            pstmt.setString(4, domainHash);
            pstmt.setString(5, pathHash);
            pstmt.setString(6, queryHash);
            pstmt.setInt(7, statusCode);
            pstmt.setInt(8, responseData != null ? responseData.length : 0);
            pstmt.setInt(9, (int) responseTime);
            pstmt.setTimestamp(10, new java.sql.Timestamp(System.currentTimeMillis()));
            pstmt.setNull(11, java.sql.Types.VARCHAR); // comment
            pstmt.setNull(12, java.sql.Types.VARCHAR); // color
            pstmt.setString(13, reqHeaderHash);
            pstmt.setString(14, reqBodyHash);
            pstmt.setString(15, reqBodyStorage);
            pstmt.setString(16, respHeaderHash);
            pstmt.setString(17, respBodyHash);
            pstmt.setString(18, respBodyStorage);

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
    public int saveHistory(int requestId, IRequestInfo requestInfo, byte[] requestData,
                           byte[] responseData, long responseTime) {
        Connection conn = null;
        try {
            conn = DatabaseManager.getInstance().getConnection();
            conn.setAutoCommit(false);

            try {
                int historyId = saveHistoryInternal(conn, requestId, requestInfo, requestData, responseData, responseTime);

                if (historyId > 0) {
                    conn.commit();
                    BurpExtender.printOutput("[+] 历史记录已保存，ID: " + historyId);
                    return historyId;
                } else {
                    conn.rollback();
                    BurpExtender.printError("[!] 保存历史记录失败：没有受影响的行");
                    return -1;
                }
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());

            // 特殊处理外键约束错误
            if (e.getMessage().contains("FOREIGN KEY constraint failed")) {
                BurpExtender.printError("[!] 外键约束失败，尝试使用NULL请求ID重新保存");

                RequestResponseRecord fallbackRecord = new RequestResponseRecord();
                fallbackRecord.setRequestId(-1);
                fallbackRecord.setMethod(requestInfo.getMethod());
                String url = requestInfo.getUrl().toString();
                fallbackRecord.setProtocol(url.startsWith("https://") ? "https" : "http");

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
                fallbackRecord.setResponseTime((int) responseTime);
                fallbackRecord.setTimestamp(new java.util.Date());
                fallbackRecord.setRequestData(requestData);
                fallbackRecord.setResponseData(responseData);

                return saveHistory(fallbackRecord);
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
     * 内部历史记录保存方法（RequestResponseRecord版本）
     */
    private int saveHistoryInternal(Connection conn, RequestResponseRecord record) throws SQLException {
        // 验证request_id是否存在
        int requestId = record.getRequestId();
        if (requestId > 0 && !requestDAO.isValidRequestId(requestId)) {
            BurpExtender.printOutput("[*] 请求ID " + requestId + " 不存在，将使用NULL作为外键");
            requestId = -1;
        }

        // 字符串池操作
        String domainHash = record.getDomain() != null ? poolManager.ensureString(conn, record.getDomain()) : null;
        String pathHash = record.getPath() != null ? poolManager.ensureString(conn, record.getPath()) : null;
        String queryHash = (record.getQueryParameters() != null && !record.getQueryParameters().isEmpty())
                ? poolManager.ensureString(conn, record.getQueryParameters()) : null;

        // 枚举转换
        int protocolInt = HttpEnum.protocolToInt(record.getProtocol());
        int methodInt = HttpEnum.methodToInt(record.getMethod());

        // 分割请求数据
        String reqHeaderHash = null;
        String reqBodyHash = null;
        String reqBodyStorage = BodyStorageRoute.NONE.getDbValue();

        byte[] requestData = record.getRequestData();
        if (requestData != null && requestData.length > 0) {
            SplitResult split = poolManager.getSplitter().splitRequest(requestData);
            reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
            if (split.hasBody()) {
                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                reqBodyHash = bodyResult[0];
                reqBodyStorage = bodyResult[1];
            }
        }

        // 分割响应数据
        String respHeaderHash = null;
        String respBodyHash = null;
        String respBodyStorage = BodyStorageRoute.NONE.getDbValue();

        byte[] responseData = record.getResponseData();
        if (responseData != null && responseData.length > 0) {
            SplitResult split = poolManager.getSplitter().splitResponse(responseData);
            respHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
            if (split.hasBody()) {
                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                respBodyHash = bodyResult[0];
                respBodyStorage = bodyResult[1];
            }
        }

        // 插入记录
        String sql = "INSERT INTO history (request_id, method, protocol, domain_hash, path_hash, query_hash, " +
                "status_code, response_length, response_time, timestamp, comment, color, " +
                "req_header_hash, req_body_hash, req_body_storage, " +
                "resp_header_hash, resp_body_hash, resp_body_storage) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
            if (requestId <= 0) {
                pstmt.setNull(1, java.sql.Types.INTEGER);
            } else {
                pstmt.setInt(1, requestId);
            }

            pstmt.setInt(2, methodInt);
            pstmt.setInt(3, protocolInt);
            pstmt.setString(4, domainHash);
            pstmt.setString(5, pathHash);
            pstmt.setString(6, queryHash);
            pstmt.setInt(7, record.getStatusCode());
            pstmt.setInt(8, record.getResponseLength());
            pstmt.setInt(9, record.getResponseTime());
            pstmt.setTimestamp(10, new java.sql.Timestamp(record.getTimestamp().getTime()));

            // 设置备注
            if (record.getComment() != null && !record.getComment().isEmpty()) {
                pstmt.setString(11, record.getComment());
            } else {
                pstmt.setNull(11, java.sql.Types.VARCHAR);
            }

            // 设置颜色
            if (record.getColor() != null) {
                String colorHex = String.format("#%02x%02x%02x",
                        record.getColor().getRed(),
                        record.getColor().getGreen(),
                        record.getColor().getBlue());
                pstmt.setString(12, colorHex);
            } else {
                pstmt.setNull(12, java.sql.Types.VARCHAR);
            }

            pstmt.setString(13, reqHeaderHash);
            pstmt.setString(14, reqBodyHash);
            pstmt.setString(15, reqBodyStorage);
            pstmt.setString(16, respHeaderHash);
            pstmt.setString(17, respBodyHash);
            pstmt.setString(18, respBodyStorage);

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
     * 保存历史记录（RequestResponseRecord版本）
     */
    public int saveHistory(RequestResponseRecord record) {
        Connection conn = null;
        try {
            if (!dbManager.isConnectionValid()) {
                BurpExtender.printError("[!] 保存历史记录失败: 数据库连接无效");
                return -1;
            }

            conn = dbManager.getConnection();
            conn.setAutoCommit(false);

            try {
                int historyId = saveHistoryInternal(conn, record);

                if (historyId > 0) {
                    conn.commit();
                    BurpExtender.printOutput("[+] 历史记录已保存，ID: " + historyId);
                    return historyId;
                } else {
                    conn.rollback();
                    BurpExtender.printError("[!] 保存历史记录失败：没有受影响的行");
                    return -1;
                }
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存历史记录失败: " + e.getMessage());

            // 特殊处理外键约束错误
            if (e.getMessage().contains("FOREIGN KEY constraint failed")) {
                BurpExtender.printError("[!] 外键约束失败，尝试使用NULL请求ID重新保存");

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

                return saveHistory(fallbackRecord);
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
     * 获取所有历史记录
     */
    public List<RequestResponseRecord> getAllHistory() {
        String sql = "SELECT h.id, h.request_id, h.method, h.protocol, " +
                "h.domain_hash, h.path_hash, h.query_hash, " +
                "h.status_code, h.response_length, h.response_time, h.timestamp, " +
                "h.comment, h.color, " +
                "h.req_header_hash, h.req_body_hash, h.req_body_storage, " +
                "h.resp_header_hash, h.resp_body_hash, h.resp_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query " +
                "FROM history h " +
                "LEFT JOIN string_pool sd ON h.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON h.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON h.query_hash = sq.hash " +
                "ORDER BY h.id DESC";

        List<RequestResponseRecord> records = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                RequestResponseRecord record = mapResultSetToRecord(conn, rs);
                if (record != null) {
                    records.add(record);
                }
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
        String sql = "SELECT h.id, h.request_id, h.method, h.protocol, " +
                "h.domain_hash, h.path_hash, h.query_hash, " +
                "h.status_code, h.response_length, h.response_time, h.timestamp, " +
                "h.comment, h.color, " +
                "h.req_header_hash, h.req_body_hash, h.req_body_storage, " +
                "h.resp_header_hash, h.resp_body_hash, h.resp_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query " +
                "FROM history h " +
                "LEFT JOIN string_pool sd ON h.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON h.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON h.query_hash = sq.hash " +
                "WHERE h.id = ?";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, historyId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRecord(conn, rs);
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
            return pstmt.executeUpdate() > 0;
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
                pstmt.setString(1, String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue()));
            } else {
                pstmt.setNull(1, java.sql.Types.VARCHAR);
            }
            pstmt.setInt(2, historyId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新历史记录颜色失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除历史记录
     */
    public boolean deleteHistory(int historyId) {
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 读取引用
                String[] refs = readHistoryHashRefs(conn, historyId);

                String sql = "DELETE FROM history WHERE id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setInt(1, historyId);
                    int affectedRows = pstmt.executeUpdate();
                    if (affectedRows > 0) {
                        // 释放引用
                        releaseOldRefs(conn, refs);
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
            BurpExtender.printError("[!] 删除历史记录失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 清空所有历史记录
     */
    public boolean clearAllHistory() {
        try (Connection conn = dbManager.getConnection()) {
            String sql = "DELETE FROM history";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.executeUpdate();
            }

            // 重置 AUTOINCREMENT 序列
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("DELETE FROM sqlite_sequence WHERE name = 'history'");
            }

            // 触发全量 ref_count 重算
            GarbageCollectorService gcService = dbManager.getGcService();
            if (gcService != null) {
                gcService.fullReclamation();
            }

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
        String sql = "SELECT h.id, h.request_id, h.method, h.protocol, " +
                "h.domain_hash, h.path_hash, h.query_hash, " +
                "h.status_code, h.response_length, h.response_time, h.timestamp, " +
                "h.comment, h.color, " +
                "h.req_header_hash, h.req_body_hash, h.req_body_storage, " +
                "h.resp_header_hash, h.resp_body_hash, h.resp_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query " +
                "FROM history h " +
                "LEFT JOIN string_pool sd ON h.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON h.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON h.query_hash = sq.hash " +
                "WHERE h.request_id = ? ORDER BY h.id DESC";

        List<RequestResponseRecord> records = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, requestId);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    RequestResponseRecord record = mapResultSetToRecord(conn, rs);
                    if (record != null) {
                        records.add(record);
                    }
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取历史记录失败: " + e.getMessage());
        }

        return records;
    }

    /**
     * 根据请求ID获取最新的N条历史记录
     */
    public List<RequestResponseRecord> getLatestHistoryByRequestId(int requestId, int limit) {
        String sql = "SELECT h.id, h.request_id, h.method, h.protocol, " +
                "h.domain_hash, h.path_hash, h.query_hash, " +
                "h.status_code, h.response_length, h.response_time, h.timestamp, " +
                "h.comment, h.color, " +
                "h.req_header_hash, h.req_body_hash, h.req_body_storage, " +
                "h.resp_header_hash, h.resp_body_hash, h.resp_body_storage, " +
                "sd.value as domain, sp.value as path, sq.value as query " +
                "FROM history h " +
                "LEFT JOIN string_pool sd ON h.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON h.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON h.query_hash = sq.hash " +
                "WHERE h.request_id = ? ORDER BY h.id DESC LIMIT ?";

        List<RequestResponseRecord> records = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, requestId);
            pstmt.setInt(2, limit);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    RequestResponseRecord record = mapResultSetToRecord(conn, rs);
                    if (record != null) {
                        records.add(record);
                    }
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取最新历史记录失败: " + e.getMessage());
        }

        return records;
    }

    // ========== 内部辅助方法 ==========

    /**
     * 将 ResultSet 映射为 RequestResponseRecord，并重构 request_data / response_data
     */
    private RequestResponseRecord mapResultSetToRecord(Connection conn, ResultSet rs) throws SQLException {
        try {
            RequestResponseRecord record = new RequestResponseRecord();
            record.setId(rs.getInt("id"));

            // Handle NULL request_id
            int requestId = rs.getInt("request_id");
            if (rs.wasNull()) {
                requestId = -1;
            }
            record.setRequestId(requestId);

            // 枚举转换
            record.setMethod(HttpEnum.intToMethod(rs.getInt("method")));
            record.setProtocol(HttpEnum.intToProtocol(rs.getInt("protocol")));

            // 从 JOIN 结果读取字符串值
            record.setDomain(getStringWithDefault(rs, "domain", ""));
            record.setPath(getStringWithDefault(rs, "path", "/"));
            record.setQueryParameters(getStringWithDefault(rs, "query", ""));

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

            // 重构请求数据
            String reqHeaderHash = rs.getString("req_header_hash");
            String reqBodyHash = rs.getString("req_body_hash");
            String reqBodyStorage = rs.getString("req_body_storage");

            byte[] requestData = reconstructor.reconstructRequest(conn, reqHeaderHash, reqBodyHash, reqBodyStorage);
            record.setRequestData(requestData);

            // 重构响应数据
            String respHeaderHash = rs.getString("resp_header_hash");
            String respBodyHash = rs.getString("resp_body_hash");
            String respBodyStorage = rs.getString("resp_body_storage");

            byte[] responseData = reconstructor.reconstructResponse(conn, respHeaderHash, respBodyHash, respBodyStorage);
            record.setResponseData(responseData);

            return record;
        } catch (Exception e) {
            BurpExtender.printError("[!] 映射历史记录时出错: " + e.getMessage());
            return null;
        }
    }

    private String getStringWithDefault(ResultSet rs, String columnName, String defaultValue) throws SQLException {
        String value = rs.getString(columnName);
        return (value != null) ? value : defaultValue;
    }

    /**
     * 读取历史记录的 hash 引用
     * 返回 [domainHash, pathHash, queryHash,
     *        reqHeaderHash, reqBodyHash, reqBodyStorage,
     *        respHeaderHash, respBodyHash, respBodyStorage]
     */
    private String[] readHistoryHashRefs(Connection conn, int historyId) throws SQLException {
        String sql = "SELECT domain_hash, path_hash, query_hash, " +
                "req_header_hash, req_body_hash, req_body_storage, " +
                "resp_header_hash, resp_body_hash, resp_body_storage " +
                "FROM history WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, historyId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new String[]{
                            rs.getString("domain_hash"),
                            rs.getString("path_hash"),
                            rs.getString("query_hash"),
                            rs.getString("req_header_hash"),
                            rs.getString("req_body_hash"),
                            rs.getString("req_body_storage"),
                            rs.getString("resp_header_hash"),
                            rs.getString("resp_body_hash"),
                            rs.getString("resp_body_storage")
                    };
                }
            }
        }
        return new String[9];
    }

    /**
     * 释放旧引用
     * 索引对应：[0]=domainHash, [1]=pathHash, [2]=queryHash,
     *          [3]=reqHeaderHash, [4]=reqBodyHash, [5]=reqBodyStorage,
     *          [6]=respHeaderHash, [7]=respBodyHash, [8]=respBodyStorage
     */
    private void releaseOldRefs(Connection conn, String[] refs) throws SQLException {
        if (refs == null) return;

        // 释放字符串引用
        poolManager.releaseString(conn, refs[0]); // domain_hash
        poolManager.releaseString(conn, refs[1]); // path_hash
        poolManager.releaseString(conn, refs[2]); // query_hash

        // 释放请求头部引用
        poolManager.releaseHeader(conn, refs[3]);

        // 释放请求 Body 引用
        poolManager.releaseBody(conn, refs[4], refs[5]);

        // 释放响应头部引用
        poolManager.releaseHeader(conn, refs[6]);

        // 释放响应 Body 引用
        poolManager.releaseBody(conn, refs[7], refs[8]);
    }
}
