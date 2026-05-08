package oxff.top.db.history;

import burp.BurpExtender;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiRuleManager;
import oxff.top.api.ApiExtractionRule;
import oxff.top.db.DatabaseManager;
import oxff.top.db.RequestDAO;
import oxff.top.db.pool.*;
import oxff.top.http.RequestResponseRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * 历史记录写入DAO
 * 负责保存历史记录
 */
public class HistoryWriteDAO {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final PoolManager poolManager;

    public HistoryWriteDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.poolManager = new PoolManager();
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
     * 统一的历史记录保存内部方法
     * 消除了原来两个重载中约80行的重复代码
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
        SplitResult reqSplit = null;

        byte[] requestData = record.getRequestData();
        if (requestData != null && requestData.length > 0) {
            reqSplit = poolManager.getSplitter().splitRequest(requestData);
            reqHeaderHash = poolManager.ensureHeader(conn, reqSplit.getHeaders());
            if (reqSplit.hasBody()) {
                String[] bodyResult = poolManager.ensureBody(conn, reqSplit.getBody());
                reqBodyHash = bodyResult[0];
                reqBodyStorage = bodyResult[1];
            }
        }

        // 提取头部信息用于API提取
        List<String> headerList = new ArrayList<>();
        String contentType = null;
        if (reqSplit != null) {
            String headersStr = new String(reqSplit.getHeaders(), java.nio.charset.StandardCharsets.UTF_8);
            for (String line : headersStr.split("\r\n")) {
                if (!line.isEmpty()) headerList.add(line);
                if (line.toLowerCase().startsWith("content-type:")) {
                    contentType = line.substring("content-type:".length()).trim();
                }
            }
        }

        // 计算API值
        String recordQuery = record.getQueryParameters();
        List<ApiExtractionRule> activeRules = ApiRuleManager.getInstance().getActiveRules();
        String apiValue = ApiExtractionEngine.extractApi(record.getPath(), recordQuery, headerList, reqSplit != null ? reqSplit.getBody() : null, contentType, activeRules);
        String apiHash = (apiValue != null && !apiValue.isEmpty()) ? poolManager.ensureString(conn, apiValue) : null;

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
                "resp_header_hash, resp_body_hash, resp_body_storage, api_hash, " +
                "user_session_name, judgment, similarity) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

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

            // 时间戳
            if (record.getTimestamp() != null) {
                pstmt.setTimestamp(10, new java.sql.Timestamp(record.getTimestamp().getTime()));
            } else {
                pstmt.setTimestamp(10, new java.sql.Timestamp(System.currentTimeMillis()));
            }

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
            pstmt.setString(19, apiHash);

            // 权限测试相关字段
            if (record.getUserSessionName() != null) {
                pstmt.setString(20, record.getUserSessionName());
            } else {
                pstmt.setNull(20, java.sql.Types.VARCHAR);
            }

            if (record.getJudgment() != null) {
                pstmt.setString(21, record.getJudgment());
            } else {
                pstmt.setNull(21, java.sql.Types.VARCHAR);
            }

            pstmt.setDouble(22, record.getSimilarity());

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
}
