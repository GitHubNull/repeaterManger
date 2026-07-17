package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.TestInfoConfig;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 测试信息配置数据访问对象
 * 管理 test_info_config 和 test_info_screenshots 两张表
 * 单例模式：表中最多一条记录
 */
public class TestInfoConfigDAO {

    /** 固定的配置记录ID（单例模式） */
    private static final int CONFIG_ID = 1;

    /**
     * 加载配置（始终返回一条记录，不存在时返回空对象）
     */
    public TestInfoConfig load() {
        String sql = "SELECT id, target_name, target_entry, test_time_range, test_personnel, created_at, updated_at "
                + "FROM test_info_config WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, CONFIG_ID);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    TestInfoConfig config = new TestInfoConfig();
                    config.setId(rs.getInt("id"));
                    config.setTargetName(rs.getString("target_name"));
                    config.setTargetEntry(rs.getString("target_entry"));
                    config.setTestTimeRange(rs.getString("test_time_range"));
                    config.setTestPersonnel(rs.getString("test_personnel"));
                    config.setCreatedAt(rs.getLong("created_at"));
                    config.setUpdatedAt(rs.getLong("updated_at"));
                    config.setTargetScreenshots(loadScreenshots(conn, config.getId()));
                    return config;
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 加载测试信息配置失败: " + e.getMessage());
        }
        return new TestInfoConfig();
    }

    /**
     * 保存配置（INSERT OR REPLACE，同步截图）
     */
    public boolean save(TestInfoConfig config) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                // INSERT OR REPLACE（created_at 由 Java 端提供毫秒时间戳，避免 SQLite TEXT 默认值类型不匹配）
                long now = System.currentTimeMillis();
                String upsertSql = "INSERT INTO test_info_config (id, target_name, target_entry, test_time_range, test_personnel, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?) "
                        + "ON CONFLICT(id) DO UPDATE SET "
                        + "target_name = excluded.target_name, "
                        + "target_entry = excluded.target_entry, "
                        + "test_time_range = excluded.test_time_range, "
                        + "test_personnel = excluded.test_personnel, "
                        + "updated_at = excluded.updated_at";
                try (PreparedStatement pstmt = conn.prepareStatement(upsertSql)) {
                    pstmt.setInt(1, CONFIG_ID);
                    pstmt.setString(2, config.getTargetName());
                    pstmt.setString(3, config.getTargetEntry());
                    pstmt.setString(4, config.getTestTimeRange());
                    pstmt.setString(5, config.getTestPersonnel());
                    pstmt.setLong(6, now);
                    pstmt.setLong(7, now);
                    pstmt.executeUpdate();
                }

                // 同步截图：先删后插
                String deleteScreenshotsSql = "DELETE FROM test_info_screenshots WHERE config_id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(deleteScreenshotsSql)) {
                    pstmt.setInt(1, CONFIG_ID);
                    pstmt.executeUpdate();
                }

                if (config.getTargetScreenshots() != null && !config.getTargetScreenshots().isEmpty()) {
                    String insertScreenshotSql = "INSERT INTO test_info_screenshots (config_id, file_path) VALUES (?, ?)";
                    try (PreparedStatement pstmt = conn.prepareStatement(insertScreenshotSql)) {
                        for (String path : config.getTargetScreenshots()) {
                            pstmt.setInt(1, CONFIG_ID);
                            pstmt.setString(2, path);
                            pstmt.executeUpdate();
                        }
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                LogManager.getInstance().printError("[!] 保存测试信息配置失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 保存测试信息配置数据库操作失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除配置（清空所有数据）
     */
    public boolean delete() {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                // 先删截图
                try (PreparedStatement pstmt = conn.prepareStatement(
                        "DELETE FROM test_info_screenshots WHERE config_id = ?")) {
                    pstmt.setInt(1, CONFIG_ID);
                    pstmt.executeUpdate();
                }
                // 再删主记录
                try (PreparedStatement pstmt = conn.prepareStatement(
                        "DELETE FROM test_info_config WHERE id = ?")) {
                    pstmt.setInt(1, CONFIG_ID);
                    pstmt.executeUpdate();
                }
                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                LogManager.getInstance().printError("[!] 删除测试信息配置失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除测试信息配置数据库操作失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 加载截图路径列表
     */
    private List<String> loadScreenshots(Connection conn, int configId) throws SQLException {
        List<String> paths = new ArrayList<>();
        String sql = "SELECT file_path FROM test_info_screenshots WHERE config_id = ? ORDER BY id ASC";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, configId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    paths.add(rs.getString("file_path"));
                }
            }
        }
        return paths;
    }
}
