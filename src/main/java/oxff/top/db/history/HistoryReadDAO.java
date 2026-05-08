package oxff.top.db.history;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;
import oxff.top.db.pool.ContentReconstructor;
import oxff.top.db.pool.HttpEnum;
import oxff.top.http.RequestResponseRecord;

import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

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

            // Set API value
            String api = rs.getString("api");
            if (api == null || api.isEmpty()) {
                api = record.getPath(); // Default to path
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

    String getStringWithDefault(ResultSet rs, String columnName, String defaultValue) throws SQLException {
        String value = rs.getString(columnName);
        return (value != null) ? value : defaultValue;
    }
}
