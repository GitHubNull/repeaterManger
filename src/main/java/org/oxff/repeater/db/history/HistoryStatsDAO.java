package org.oxff.repeater.db.history;

import burp.BurpExtender;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.ui.history.HistoryStatsData;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 历史记录统计查询DAO
 * 负责SQL聚合查询和内存统计计算
 */
public class HistoryStatsDAO {
    private final DatabaseManager dbManager;

    public HistoryStatsDAO() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * 获取全局历史记录统计（所有请求）
     */
    public HistoryStatsData getGlobalStats() {
        HistoryStatsData stats = new HistoryStatsData();

        try (Connection conn = dbManager.getConnection()) {
            // 1. SQL聚合查询基础统计
            queryBasicStats(conn, stats, null);

            // 2. 查询全量response_time列表，计算方差、众数、中位数
            if (stats.getTotalCount() > 0) {
                List<Integer> responseTimes = queryResponseTimes(conn, null);
                computeAdvancedStats(stats, responseTimes);
            }

            // 3. 查询重试次数
            stats.setRetryCount(queryRetryCount(conn, null));

            // 4. 查询基准报文表总数
            stats.setRequestCount(queryRequestCount(conn));

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取全局统计失败: " + e.getMessage());
        }

        return stats;
    }

    /**
     * 获取指定requestId的历史记录统计
     */
    public HistoryStatsData getStatsByRequestId(int requestId) {
        HistoryStatsData stats = new HistoryStatsData();

        try (Connection conn = dbManager.getConnection()) {
            // 1. SQL聚合查询基础统计
            queryBasicStats(conn, stats, requestId);

            // 2. 查询该requestId的response_time列表
            if (stats.getTotalCount() > 0) {
                List<Integer> responseTimes = queryResponseTimes(conn, requestId);
                computeAdvancedStats(stats, responseTimes);
            }

            // 3. 查询该requestId的重试次数
            stats.setRetryCount(queryRetryCount(conn, requestId));

            // 4. 查询基准报文表总数
            stats.setRequestCount(queryRequestCount(conn));

        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取请求统计失败 (requestId=" + requestId + "): " + e.getMessage());
        }

        return stats;
    }

    /**
     * SQL聚合查询：总数、成功数、失败数、最大/最小/平均耗时
     */
    private void queryBasicStats(Connection conn, HistoryStatsData stats, Integer requestId) throws SQLException {
        StringBuilder sql = new StringBuilder(
            "SELECT " +
            "  COUNT(*) as total_count, " +
            "  SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) as success_count, " +
            "  SUM(CASE WHEN status_code < 200 OR status_code >= 300 THEN 1 ELSE 0 END) as failure_count, " +
            "  MIN(response_time) as min_time, " +
            "  MAX(response_time) as max_time, " +
            "  AVG(CAST(response_time AS REAL)) as avg_time " +
            "FROM history"
        );

        if (requestId != null) {
            sql.append(" WHERE request_id = ?");
        }

        try (PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {
            if (requestId != null) {
                pstmt.setInt(1, requestId);
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    stats.setTotalCount(rs.getInt("total_count"));
                    stats.setSuccessCount(rs.getInt("success_count"));
                    stats.setFailureCount(rs.getInt("failure_count"));
                    stats.setMinResponseTime(rs.getInt("min_time"));
                    stats.setMaxResponseTime(rs.getInt("max_time"));
                    stats.setAvgResponseTime(rs.getDouble("avg_time"));
                }
            }
        }
    }

    /**
     * 查询response_time列表（用于计算方差、众数、中位数）
     */
    private List<Integer> queryResponseTimes(Connection conn, Integer requestId) throws SQLException {
        List<Integer> times = new ArrayList<>();
        String sql = "SELECT response_time FROM history" +
                     (requestId != null ? " WHERE request_id = ?" : "");

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            if (requestId != null) {
                pstmt.setInt(1, requestId);
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    times.add(rs.getInt("response_time"));
                }
            }
        }

        return times;
    }

    /**
     * 内存计算：方差、众数、中位数
     */
    private void computeAdvancedStats(HistoryStatsData stats, List<Integer> responseTimes) {
        if (responseTimes == null || responseTimes.isEmpty()) {
            return;
        }

        // 计算方差（总体方差：Σ(xi - μ)² / N）
        double avg = stats.getAvgResponseTime();
        double sumSquaredDiff = 0.0;
        for (int time : responseTimes) {
            double diff = time - avg;
            sumSquaredDiff += diff * diff;
        }
        stats.setVariance(sumSquaredDiff / responseTimes.size());

        // 计算众数
        stats.setModeResponseTime(computeMode(responseTimes));

        // 计算中位数
        stats.setMedianResponseTime(computeMedian(responseTimes));
    }

    /**
     * 计算众数：出现频率最高的值
     */
    private int computeMode(List<Integer> values) {
        Map<Integer, Integer> frequencyMap = new HashMap<>();
        for (int value : values) {
            frequencyMap.put(value, frequencyMap.getOrDefault(value, 0) + 1);
        }

        int mode = values.get(0);
        int maxFreq = 0;
        for (Map.Entry<Integer, Integer> entry : frequencyMap.entrySet()) {
            if (entry.getValue() > maxFreq) {
                maxFreq = entry.getValue();
                mode = entry.getKey();
            }
        }

        return mode;
    }

    /**
     * 计算中位数
     */
    private double computeMedian(List<Integer> values) {
        List<Integer> sorted = new ArrayList<>(values);
        Collections.sort(sorted);

        int size = sorted.size();
        if (size % 2 == 1) {
            return sorted.get(size / 2);
        } else {
            return (sorted.get(size / 2 - 1) + sorted.get(size / 2)) / 2.0;
        }
    }

    /**
     * 查询重试次数
     * 按request_id分组，每个request_id的第一次不算重试，从第二条开始每条算一次重试
     * 公式：SUM(MAX(0, count_per_request_id - 1))
     */
    private int queryRetryCount(Connection conn, Integer requestId) throws SQLException {
        StringBuilder sql = new StringBuilder(
            "SELECT request_id, COUNT(*) as cnt FROM history"
        );

        if (requestId != null) {
            sql.append(" WHERE request_id = ?");
        }

        sql.append(" GROUP BY request_id");

        int retryCount = 0;

        try (PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {
            if (requestId != null) {
                pstmt.setInt(1, requestId);
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    int count = rs.getInt("cnt");
                    if (count > 1) {
                        retryCount += (count - 1);
                    }
                }
            }
        }

        return retryCount;
    }

    /**
     * 查询基准报文表（requests表）总请求数
     */
    private int queryRequestCount(Connection conn) throws SQLException {
        String sql = "SELECT COUNT(*) as cnt FROM requests";

        try (PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                return rs.getInt("cnt");
            }
        }

        return 0;
    }
}
