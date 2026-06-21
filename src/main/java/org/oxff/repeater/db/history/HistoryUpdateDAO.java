package org.oxff.repeater.db.history;

import burp.BurpExtender;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.db.pool.PoolManager;
import org.oxff.repeater.service.GarbageCollectorService;

import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 历史记录更新/删除DAO
 * 负责更新备注/颜色、删除记录、引用释放
 */
public class HistoryUpdateDAO {
    private final DatabaseManager dbManager;
    private final PoolManager poolManager;

    public HistoryUpdateDAO() {
        this.dbManager = DatabaseManager.getInstance();
        this.poolManager = new PoolManager();
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

    // ========== 内部辅助方法 ==========

    /**
     * 读取历史记录的 hash 引用
     * 返回 [domainHash, pathHash, queryHash,
     *        reqHeaderHash, reqBodyHash, reqBodyStorage,
     *        respHeaderHash, respBodyHash, respBodyStorage,
     *        apiHash]
     */
    private String[] readHistoryHashRefs(Connection conn, int historyId) throws SQLException {
        String sql = "SELECT domain_hash, path_hash, query_hash, " +
                "req_header_hash, req_body_hash, req_body_storage, " +
                "resp_header_hash, resp_body_hash, resp_body_storage, " +
                "api_hash " +
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
                            rs.getString("resp_body_storage"),
                            rs.getString("api_hash")
                    };
                }
            }
        }
        return new String[10];
    }

    /**
     * 释放旧引用
     * 索引对应：[0]=domainHash, [1]=pathHash, [2]=queryHash,
     *          [3]=reqHeaderHash, [4]=reqBodyHash, [5]=reqBodyStorage,
     *          [6]=respHeaderHash, [7]=respBodyHash, [8]=respBodyStorage,
     *          [9]=apiHash
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

        // 释放 API 字符串引用
        poolManager.releaseString(conn, refs[9]); // api_hash
    }
}
