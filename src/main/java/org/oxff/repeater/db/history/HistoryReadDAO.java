package org.oxff.repeater.db.history;

import burp.BurpExtender;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.db.pool.ContentReconstructor;
import org.oxff.repeater.db.pool.HttpEnum;
import org.oxff.repeater.http.RequestResponseRecord;

import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 历史记录读取DAO
 * 负责查询历史记录和ResultSet映射
 */
public class HistoryReadDAO {
    private final DatabaseManager dbManager;
    private final ContentReconstructor reconstructor;

    public HistoryReadDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.reconstructor = new ContentReconstructor();
    }

    /**
     * 获取所有历史记录
     */
    public List<RequestResponseRecord> getAllHistory() {
        String sql = buildHistorySelectQuery() + " ORDER BY h.id DESC";

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
        String sql = buildHistorySelectQuery() + " WHERE h.id = ?";

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
     * 根据请求ID获取历史记录
     */
    public List<RequestResponseRecord> getHistoryByRequestId(int requestId) {
        String sql = buildHistorySelectQuery() + " WHERE h.request_id = ? ORDER BY h.id DESC";

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
        String sql = buildHistorySelectQuery() + " WHERE h.request_id = ? ORDER BY h.id DESC LIMIT ?";

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

    /**
     * 获取指定requestId的基线记录（原始请求）
     * 基线记录定义：user_session_name为NULL或空字符串的最早一条历史记录
     * 如果没有基线记录，则返回该requestId下的第一条记录
     */
    public RequestResponseRecord getBaselineRecord(int requestId) {
        // 先尝试查找user_session_name为NULL或空的记录
        String sql = buildHistorySelectQuery()
            + " WHERE h.request_id = ? AND (h.user_session_name IS NULL OR h.user_session_name = '')"
            + " ORDER BY h.id ASC LIMIT 1";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, requestId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRecord(conn, rs);
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取基线记录失败: " + e.getMessage());
        }

        // 没有找到基线记录，尝试返回第一条记录
        String fallbackSql = buildHistorySelectQuery()
            + " WHERE h.request_id = ? ORDER BY h.id ASC LIMIT 1";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(fallbackSql)) {

            pstmt.setInt(1, requestId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRecord(conn, rs);
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取基线记录（回退查询）失败: " + e.getMessage());
        }

        return null;
    }

    /**
     * 获取指定requestId的基线记录（仅查找 user_session_name 为 NULL 的记录，不回退）
     * 用于比对对话框：先尝试此方法，找不到再从 requests 表构造基线
     */
    public RequestResponseRecord getBaselineRecordWithoutFallback(int requestId) {
        String sql = buildHistorySelectQuery()
            + " WHERE h.request_id = ? AND (h.user_session_name IS NULL OR h.user_session_name = '')"
            + " ORDER BY h.id ASC LIMIT 1";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, requestId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRecord(conn, rs);
                }
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取基线记录失败: " + e.getMessage());
        }

        return null;
    }

    // ========== 内部辅助方法 ==========

    /**
     * 构建历史记录查询的公共SELECT部分
     */
    private String buildHistorySelectQuery() {
        return "SELECT h.id, h.request_id, h.method, h.protocol, " +
                "h.domain_hash, h.path_hash, h.query_hash, " +
                "h.status_code, h.response_length, h.response_time, h.timestamp, " +
                "h.comment, h.color, " +
                "h.req_header_hash, h.req_body_hash, h.req_body_storage, " +
                "h.resp_header_hash, h.resp_body_hash, h.resp_body_storage, " +
                "h.user_session_name, h.judgment, h.similarity, " +
                "sd.value as domain, sp.value as path, sq.value as query, sa.value as api " +
                "FROM history h " +
                "LEFT JOIN string_pool sd ON h.domain_hash = sd.hash " +
                "LEFT JOIN string_pool sp ON h.path_hash = sp.hash " +
                "LEFT JOIN string_pool sq ON h.query_hash = sq.hash " +
                "LEFT JOIN string_pool sa ON h.api_hash = sa.hash";
    }

    /**
     * 将 ResultSet 映射为 RequestResponseRecord，并重构 request_data / response_data
     */
    RequestResponseRecord mapResultSetToRecord(Connection conn, ResultSet rs) throws SQLException {
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

            // 从重构的请求数据中回退补充缺失的元数据字段
            // 当 LEFT JOIN 返回 NULL（hash 不匹配或 GC 误删）时，从原始请求中恢复
            if (requestData != null && requestData.length > 0) {
                supplementFromRequestData(record, requestData);
            }

            // Set API value
            String api = rs.getString("api");
            if (api == null || api.isEmpty()) {
                api = record.getPath() != null ? record.getPath() : "/";
            }
            record.setApi(api);

            // 权限测试相关字段（兼容v5旧数据库，列可能不存在）
            try {
                record.setUserSessionName(rs.getString("user_session_name"));
            } catch (SQLException e) {
                record.setUserSessionName(null);
            }

            try {
                record.setJudgment(rs.getString("judgment"));
            } catch (SQLException e) {
                record.setJudgment(null);
            }

            try {
                record.setSimilarity(rs.getDouble("similarity"));
                if (rs.wasNull()) {
                    record.setSimilarity(-1);
                }
            } catch (SQLException e) {
                record.setSimilarity(-1);
            }

            return record;
        } catch (Exception e) {
            BurpExtender.printError("[!] 映射历史记录时出错: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从重构的请求数据中补充缺失的元数据字段
     * 当 LEFT JOIN 返回 NULL（hash 不匹配或 GC 误删）时，从原始请求字节中恢复 method/protocol/domain/path/query
     */
    private void supplementFromRequestData(RequestResponseRecord record, byte[] requestData) {
        try {
            burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            burp.api.montoya.core.ByteArray.byteArray(requestData));

            // 补充 method（仅当当前值为 null 或 "OTHER" 回退值时）
            if (record.getMethod() == null || record.getMethod().isEmpty()) {
                record.setMethod(httpRequest.method());
            }

            // 尝试从 URL 解析补充 protocol/domain/path/query
            String urlStr = httpRequest.url();
            if (urlStr != null && !urlStr.isEmpty()) {
                try {
                    java.net.URL url = new java.net.URL(urlStr);

                    if (record.getProtocol() == null || record.getProtocol().isEmpty()) {
                        record.setProtocol(url.getProtocol());
                    }

                    if (record.getDomain() == null || record.getDomain().isEmpty()) {
                        String host = url.getHost();
                        int port = url.getPort();
                        if (port != -1 && port != url.getDefaultPort()) {
                            host = host + ":" + port;
                        }
                        record.setDomain(host);
                    }

                    if (record.getPath() == null || record.getPath().isEmpty() || "/".equals(record.getPath())) {
                        String urlPath = url.getPath();
                        if (urlPath != null && !urlPath.isEmpty()) {
                            record.setPath(urlPath);
                        }
                    }

                    if (record.getQueryParameters() == null || record.getQueryParameters().isEmpty()) {
                        String query = url.getQuery();
                        record.setQueryParameters(query != null ? query : "");
                    }
                } catch (Exception e) {
                    BurpExtender.printOutput("[*] 从请求数据解析URL失败，跳过补充: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            BurpExtender.printOutput("[*] 从请求数据补充元数据失败: " + e.getMessage());
        }
    }

    String getStringWithDefault(ResultSet rs, String columnName, String defaultValue) throws SQLException {
        String value = rs.getString(columnName);
        return (value != null) ? value : defaultValue;
    }

    // ========== 权限测试报告查询方法 ==========

    /**
     * 获取所有越权测试结果记录
     */
    public List<RequestResponseRecord> getPrivilegeTestResults() {
        String sql = buildHistorySelectQuery()
                + " WHERE h.user_session_name IS NOT NULL AND h.judgment IS NOT NULL"
                + " ORDER BY h.domain_hash, h.path_hash, h.user_session_name, h.id DESC";

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
            BurpExtender.printError("[!] 获取越权测试结果失败: " + e.getMessage());
        }

        return records;
    }

    /**
     * 获取越权测试统计（按判决结果分组）
     */
    public Map<String, Integer> getPrivilegeTestStats() {
        String sql = "SELECT judgment, COUNT(*) as cnt FROM history"
                + " WHERE user_session_name IS NOT NULL AND judgment IS NOT NULL"
                + " GROUP BY judgment";

        Map<String, Integer> stats = new HashMap<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                stats.put(rs.getString("judgment"), rs.getInt("cnt"));
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取越权测试统计失败: " + e.getMessage());
        }

        return stats;
    }

    /**
     * 获取越权测试按会话分布统计
     */
    public List<Map<String, Object>> getPrivilegeTestStatsBySession() {
        String sql = "SELECT user_session_name, judgment, COUNT(*) as cnt FROM history"
                + " WHERE user_session_name IS NOT NULL AND judgment IS NOT NULL"
                + " GROUP BY user_session_name, judgment"
                + " ORDER BY user_session_name, judgment";

        List<Map<String, Object>> stats = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("user_session_name", rs.getString("user_session_name"));
                row.put("judgment", rs.getString("judgment"));
                row.put("cnt", rs.getInt("cnt"));
                stats.add(row);
            }

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取越权测试会话统计失败: " + e.getMessage());
        }

        return stats;
    }
}
