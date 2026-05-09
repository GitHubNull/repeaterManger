package oxff.top.privilege.dao;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenLocationType;
import oxff.top.privilege.model.UserSession;

import java.awt.Color;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 会话数据访问对象
 * 管理 token_locations、user_sessions、token_values 三张表的 CRUD
 */
public class SessionDAO {

    // ==================== TokenLocation CRUD ====================

    /**
     * 获取所有令牌位置
     */
    public List<TokenLocation> getAllTokenLocations() {
        List<TokenLocation> locations = new ArrayList<>();
        String sql = "SELECT id, type, expression, description, persist_to_global, enabled FROM token_locations ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                TokenLocation location = new TokenLocation();
                location.setId(rs.getInt("id"));
                location.setType(TokenLocationType.fromString(rs.getString("type")));
                location.setExpression(rs.getString("expression"));
                location.setDescription(rs.getString("description"));
                location.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                location.setEnabled(rs.getInt("enabled") == 1);
                locations.add(location);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取令牌位置列表失败: " + e.getMessage());
        }
        return locations;
    }

    /**
     * 添加令牌位置
     * @return 新记录ID，失败返回-1
     */
    public int addTokenLocation(TokenLocationType type, String expression, String description,
                                boolean persistToGlobal, boolean enabled) {
        String sql = "INSERT INTO token_locations (type, expression, description, persist_to_global, enabled) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, type.name());
            pstmt.setString(2, expression);
            pstmt.setString(3, description != null ? description : "");
            pstmt.setInt(4, persistToGlobal ? 1 : 0);
            pstmt.setInt(5, enabled ? 1 : 0);
            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 添加令牌位置失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新令牌位置
     */
    public boolean updateTokenLocation(int id, TokenLocationType type, String expression, String description,
                                       boolean persistToGlobal, boolean enabled) {
        String sql = "UPDATE token_locations SET type = ?, expression = ?, description = ?, persist_to_global = ?, enabled = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, type.name());
            pstmt.setString(2, expression);
            pstmt.setString(3, description != null ? description : "");
            pstmt.setInt(4, persistToGlobal ? 1 : 0);
            pstmt.setInt(5, enabled ? 1 : 0);
            pstmt.setInt(6, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新令牌位置失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除令牌位置（级联删除关联的token_values）
     */
    public boolean deleteTokenLocation(int id) {
        String sql = "DELETE FROM token_locations WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除令牌位置失败: " + e.getMessage());
        }
        return false;
    }

    // ==================== UserSession CRUD ====================

    /**
     * 获取所有用户会话（含令牌值）
     */
    public List<UserSession> getAllUserSessions() {
        List<UserSession> sessions = new ArrayList<>();
        String sql = "SELECT id, name, color, enabled FROM user_sessions ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                UserSession session = new UserSession();
                session.setId(rs.getInt("id"));
                session.setName(rs.getString("name"));
                String colorHex = rs.getString("color");
                if (colorHex != null && !colorHex.isEmpty()) {
                    try {
                        session.setColor(Color.decode(colorHex));
                    } catch (NumberFormatException e) {
                        // 忽略无效颜色
                    }
                }
                session.setEnabled(rs.getInt("enabled") == 1);
                // 加载令牌值
                session.setTokenValues(loadTokenValues(conn, session.getId()));
                sessions.add(session);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取用户会话列表失败: " + e.getMessage());
        }
        return sessions;
    }

    /**
     * 获取所有已启用的用户会话
     */
    public List<UserSession> getEnabledUserSessions() {
        List<UserSession> sessions = new ArrayList<>();
        String sql = "SELECT id, name, color, enabled FROM user_sessions WHERE enabled = 1 ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                UserSession session = new UserSession();
                session.setId(rs.getInt("id"));
                session.setName(rs.getString("name"));
                String colorHex = rs.getString("color");
                if (colorHex != null && !colorHex.isEmpty()) {
                    try {
                        session.setColor(Color.decode(colorHex));
                    } catch (NumberFormatException e) {
                        // 忽略无效颜色
                    }
                }
                session.setEnabled(true);
                session.setTokenValues(loadTokenValues(conn, session.getId()));
                sessions.add(session);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取已启用用户会话列表失败: " + e.getMessage());
        }
        return sessions;
    }

    /**
     * 添加用户会话
     * @return 新记录ID，失败返回-1
     */
    public int addUserSession(String name, String colorHex, boolean enabled) {
        String sql = "INSERT INTO user_sessions (name, color, enabled) VALUES (?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, name);
            pstmt.setString(2, colorHex);
            pstmt.setInt(3, enabled ? 1 : 0);
            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 添加用户会话失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新用户会话基本信息
     */
    public boolean updateUserSession(int id, String name, String colorHex, boolean enabled) {
        String sql = "UPDATE user_sessions SET name = ?, color = ?, enabled = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, colorHex);
            pstmt.setInt(3, enabled ? 1 : 0);
            pstmt.setInt(4, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新用户会话失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除用户会话（级联删除关联的token_values）
     */
    public boolean deleteUserSession(int id) {
        String sql = "DELETE FROM user_sessions WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除用户会话失败: " + e.getMessage());
        }
        return false;
    }

    // ==================== TokenValue CRUD ====================

    /**
     * 加载指定用户会话的所有令牌值
     */
    private Map<Integer, String> loadTokenValues(Connection conn, int userSessionId) {
        Map<Integer, String> values = new LinkedHashMap<>();
        String sql = "SELECT token_location_id, value FROM token_values WHERE user_session_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userSessionId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    values.put(rs.getInt("token_location_id"), rs.getString("value"));
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 加载令牌值失败: " + e.getMessage());
        }
        return values;
    }

    /**
     * 保存指定用户会话的所有令牌值（先删后插）
     */
    public boolean saveTokenValues(int userSessionId, Map<Integer, String> tokenValues) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                // 删除旧的令牌值
                String deleteSql = "DELETE FROM token_values WHERE user_session_id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(deleteSql)) {
                    pstmt.setInt(1, userSessionId);
                    pstmt.executeUpdate();
                }

                // 插入新的令牌值
                String insertSql = "INSERT INTO token_values (token_location_id, user_session_id, value) VALUES (?, ?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    for (Map.Entry<Integer, String> entry : tokenValues.entrySet()) {
                        pstmt.setInt(1, entry.getKey());
                        pstmt.setInt(2, userSessionId);
                        pstmt.setString(3, entry.getValue() != null ? entry.getValue() : "");
                        pstmt.executeUpdate();
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                BurpExtender.printError("[!] 保存令牌值失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存令牌值数据库操作失败: " + e.getMessage());
        }
        return false;
    }
}
