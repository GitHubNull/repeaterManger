package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.UserInfo;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 用户信息数据访问对象
 * 管理 user_info 和 user_info_screenshots 两张表的 CRUD
 */
public class UserInfoDAO {

    /**
     * 根据会话ID获取用户信息（含截图路径）
     */
    public UserInfo getBySessionId(int sessionId) {
        String sql = "SELECT id, session_id, role, username, is_anonymous, created_at FROM user_info WHERE session_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    UserInfo info = new UserInfo();
                    info.setId(rs.getInt("id"));
                    info.setSessionId(rs.getInt("session_id"));
                    info.setRole(rs.getString("role"));
                    info.setUsername(rs.getString("username"));
                    info.setAnonymous(rs.getInt("is_anonymous") == 1);
                    info.setCreatedAt(rs.getLong("created_at"));
                    // 加载截图路径
                    info.setScreenshotPaths(loadScreenshots(conn, info.getId()));
                    return info;
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取用户信息失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 保存用户信息（INSERT OR REPLACE 模式，同时同步截图）
     */
    public boolean save(UserInfo info) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                int userInfoId;
                
                // 检查是否已存在
                UserInfo existing = getBySessionIdInternal(conn, info.getSessionId());
                if (existing != null) {
                    // 更新
                    String updateSql = "UPDATE user_info SET role = ?, username = ?, is_anonymous = ? WHERE id = ?";
                    try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                        pstmt.setString(1, info.getRole());
                        pstmt.setString(2, info.getUsername());
                        pstmt.setInt(3, info.isAnonymous() ? 1 : 0);
                        pstmt.setInt(4, existing.getId());
                        pstmt.executeUpdate();
                    }
                    userInfoId = existing.getId();
                } else {
                    // 插入
                    String insertSql = "INSERT INTO user_info (session_id, role, username, is_anonymous) VALUES (?, ?, ?, ?)";
                    try (PreparedStatement pstmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                        pstmt.setInt(1, info.getSessionId());
                        pstmt.setString(2, info.getRole());
                        pstmt.setString(3, info.getUsername());
                        pstmt.setInt(4, info.isAnonymous() ? 1 : 0);
                        pstmt.executeUpdate();
                        try (ResultSet rs = pstmt.getGeneratedKeys()) {
                            if (rs.next()) {
                                userInfoId = rs.getInt(1);
                            } else {
                                conn.rollback();
                                return false;
                            }
                        }
                    }
                }

                // 同步截图：先删后插
                String deleteScreenshotsSql = "DELETE FROM user_info_screenshots WHERE user_info_id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(deleteScreenshotsSql)) {
                    pstmt.setInt(1, userInfoId);
                    pstmt.executeUpdate();
                }

                if (info.getScreenshotPaths() != null && !info.getScreenshotPaths().isEmpty()) {
                    String insertScreenshotSql = "INSERT INTO user_info_screenshots (user_info_id, file_path) VALUES (?, ?)";
                    try (PreparedStatement pstmt = conn.prepareStatement(insertScreenshotSql)) {
                        for (String path : info.getScreenshotPaths()) {
                            pstmt.setInt(1, userInfoId);
                            pstmt.setString(2, path);
                            pstmt.executeUpdate();
                        }
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                LogManager.getInstance().printError("[!] 保存用户信息失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 保存用户信息数据库操作失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 根据会话ID删除用户信息（级联删除截图）
     */
    public boolean deleteBySessionId(int sessionId) {
        String sql = "DELETE FROM user_info WHERE session_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除用户信息失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 内部方法：在同一连接中查询用户信息（不含截图），用于 save() 事务中
     */
    private UserInfo getBySessionIdInternal(Connection conn, int sessionId) throws SQLException {
        String sql = "SELECT id, session_id, role, username, is_anonymous, created_at FROM user_info WHERE session_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    UserInfo info = new UserInfo();
                    info.setId(rs.getInt("id"));
                    info.setSessionId(rs.getInt("session_id"));
                    info.setRole(rs.getString("role"));
                    info.setUsername(rs.getString("username"));
                    info.setAnonymous(rs.getInt("is_anonymous") == 1);
                    info.setCreatedAt(rs.getLong("created_at"));
                    return info;
                }
            }
        }
        return null;
    }

    /**
     * 加载指定用户信息的截图路径列表
     */
    private List<String> loadScreenshots(Connection conn, int userInfoId) throws SQLException {
        List<String> paths = new ArrayList<>();
        String sql = "SELECT file_path FROM user_info_screenshots WHERE user_info_id = ? ORDER BY id ASC";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userInfoId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    paths.add(rs.getString("file_path"));
                }
            }
        }
        return paths;
    }

    /**
     * 获取所有用户信息（含截图路径）
     */
    public List<UserInfo> getAll() {
        List<UserInfo> all = new ArrayList<>();
        String sql = "SELECT id, session_id, role, username, is_anonymous, created_at FROM user_info ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                UserInfo info = new UserInfo();
                info.setId(rs.getInt("id"));
                info.setSessionId(rs.getInt("session_id"));
                info.setRole(rs.getString("role"));
                info.setUsername(rs.getString("username"));
                info.setAnonymous(rs.getInt("is_anonymous") == 1);
                info.setCreatedAt(rs.getLong("created_at"));
                info.setScreenshotPaths(loadScreenshots(conn, info.getId()));
                all.add(info);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取所有用户信息失败: " + e.getMessage());
        }
        return all;
    }
}
