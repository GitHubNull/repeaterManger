package org.oxff.repeater.privilege.dao;

import burp.BurpExtender;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.privilege.model.UserSession;

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
 * 管理 token_locations、token_schemes、scheme_token_locations、user_sessions、token_values 五张表的 CRUD
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
     * 删除令牌位置（级联删除关联的token_values和scheme_token_locations）
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

    /**
     * 获取引用指定令牌位置的方案数量
     */
    public int getSchemeReferenceCountByTokenLocation(int tokenLocationId) {
        String sql = "SELECT COUNT(DISTINCT scheme_id) FROM scheme_token_locations WHERE token_location_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, tokenLocationId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取令牌位置引用方案数失败: " + e.getMessage());
        }
        return 0;
    }

    // ==================== TokenScheme CRUD ====================

    /**
     * 获取所有令牌方案（含关联的令牌位置ID列表）
     */
    public List<TokenScheme> getAllTokenSchemes() {
        List<TokenScheme> schemes = new ArrayList<>();
        String sql = "SELECT id, name, description, persist_to_global, enabled FROM token_schemes ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                TokenScheme scheme = new TokenScheme();
                scheme.setId(rs.getInt("id"));
                scheme.setName(rs.getString("name"));
                scheme.setDescription(rs.getString("description"));
                scheme.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                scheme.setEnabled(rs.getInt("enabled") == 1);
                scheme.setTokenLocationIds(loadSchemeTokenLocationIds(conn, scheme.getId()));
                schemes.add(scheme);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取令牌方案列表失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 获取所有已启用的令牌方案
     */
    public List<TokenScheme> getEnabledTokenSchemes() {
        List<TokenScheme> schemes = new ArrayList<>();
        String sql = "SELECT id, name, description, persist_to_global, enabled FROM token_schemes WHERE enabled = 1 ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                TokenScheme scheme = new TokenScheme();
                scheme.setId(rs.getInt("id"));
                scheme.setName(rs.getString("name"));
                scheme.setDescription(rs.getString("description"));
                scheme.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                scheme.setEnabled(true);
                scheme.setTokenLocationIds(loadSchemeTokenLocationIds(conn, scheme.getId()));
                schemes.add(scheme);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取已启用令牌方案列表失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 添加令牌方案
     * @return 新记录ID，失败返回-1
     */
    public int addTokenScheme(String name, String description, boolean persistToGlobal, boolean enabled) {
        String sql = "INSERT INTO token_schemes (name, description, persist_to_global, enabled) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, name);
            pstmt.setString(2, description != null ? description : "");
            pstmt.setInt(3, persistToGlobal ? 1 : 0);
            pstmt.setInt(4, enabled ? 1 : 0);
            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 添加令牌方案失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新令牌方案
     */
    public boolean updateTokenScheme(int id, String name, String description, boolean persistToGlobal, boolean enabled) {
        String sql = "UPDATE token_schemes SET name = ?, description = ?, persist_to_global = ?, enabled = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, description != null ? description : "");
            pstmt.setInt(3, persistToGlobal ? 1 : 0);
            pstmt.setInt(4, enabled ? 1 : 0);
            pstmt.setInt(5, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新令牌方案失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除令牌方案（级联删除关联的scheme_token_locations）
     */
    public boolean deleteTokenScheme(int id) {
        String sql = "DELETE FROM token_schemes WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除令牌方案失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 保存方案关联的令牌位置（先删后插）
     */
    public boolean saveSchemeTokenLocations(int schemeId, List<Integer> tokenLocationIds) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                // 删除旧的关联
                String deleteSql = "DELETE FROM scheme_token_locations WHERE scheme_id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(deleteSql)) {
                    pstmt.setInt(1, schemeId);
                    pstmt.executeUpdate();
                }

                // 插入新的关联
                String insertSql = "INSERT INTO scheme_token_locations (scheme_id, token_location_id) VALUES (?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    for (int locationId : tokenLocationIds) {
                        pstmt.setInt(1, schemeId);
                        pstmt.setInt(2, locationId);
                        pstmt.executeUpdate();
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                BurpExtender.printError("[!] 保存方案令牌位置关联失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存方案令牌位置关联数据库操作失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 加载指定方案关联的令牌位置ID列表
     */
    private List<Integer> loadSchemeTokenLocationIds(Connection conn, int schemeId) {
        List<Integer> locationIds = new ArrayList<>();
        String sql = "SELECT token_location_id FROM scheme_token_locations WHERE scheme_id = ? ORDER BY token_location_id ASC";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, schemeId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    locationIds.add(rs.getInt("token_location_id"));
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 加载方案令牌位置关联失败: " + e.getMessage());
        }
        return locationIds;
    }

    /**
     * 获取引用指定方案的会话数量
     */
    public int getSessionReferenceCountByScheme(int schemeId) {
        String sql = "SELECT COUNT(*) FROM user_sessions WHERE scheme_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, schemeId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取方案引用会话数失败: " + e.getMessage());
        }
        return 0;
    }

    // ==================== UserSession CRUD ====================

    /**
     * 获取所有用户会话（含令牌值）
     */
    public List<UserSession> getAllUserSessions() {
        List<UserSession> sessions = new ArrayList<>();
        String sql = "SELECT id, name, color, enabled, scheme_id, request_timeout, max_concurrent, retry_count, retry_delay, replay_delay FROM user_sessions ORDER BY id ASC";
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
                // scheme_id 可能为 NULL
                int schemeId = rs.getInt("scheme_id");
                session.setSchemeId(rs.wasNull() ? null : schemeId);
                session.setRequestTimeout(rs.getInt("request_timeout"));
                session.setMaxConcurrent(rs.getInt("max_concurrent"));
                session.setRetryCount(rs.getInt("retry_count"));
                session.setRetryDelay(rs.getInt("retry_delay"));
                session.setReplayDelay(rs.getInt("replay_delay"));
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
        String sql = "SELECT id, name, color, enabled, scheme_id, request_timeout, max_concurrent, retry_count, retry_delay, replay_delay FROM user_sessions WHERE enabled = 1 ORDER BY id ASC";
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
                int schemeId = rs.getInt("scheme_id");
                session.setSchemeId(rs.wasNull() ? null : schemeId);
                session.setRequestTimeout(rs.getInt("request_timeout"));
                session.setMaxConcurrent(rs.getInt("max_concurrent"));
                session.setRetryCount(rs.getInt("retry_count"));
                session.setRetryDelay(rs.getInt("retry_delay"));
                session.setReplayDelay(rs.getInt("replay_delay"));
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
    public int addUserSession(String name, String colorHex, boolean enabled, Integer schemeId,
                              int requestTimeout, int maxConcurrent, int retryCount, int retryDelay, int replayDelay) {
        String sql = "INSERT INTO user_sessions (name, color, enabled, scheme_id, request_timeout, max_concurrent, retry_count, retry_delay, replay_delay) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, name);
            pstmt.setString(2, colorHex);
            pstmt.setInt(3, enabled ? 1 : 0);
            if (schemeId != null) {
                pstmt.setInt(4, schemeId);
            } else {
                pstmt.setNull(4, java.sql.Types.INTEGER);
            }
            pstmt.setInt(5, requestTimeout);
            pstmt.setInt(6, maxConcurrent);
            pstmt.setInt(7, retryCount);
            pstmt.setInt(8, retryDelay);
            pstmt.setInt(9, replayDelay);
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
     * 更新用户会话信息
     */
    public boolean updateUserSession(int id, String name, String colorHex, boolean enabled, Integer schemeId,
                                     int requestTimeout, int maxConcurrent, int retryCount, int retryDelay, int replayDelay) {
        String sql = "UPDATE user_sessions SET name = ?, color = ?, enabled = ?, scheme_id = ?, request_timeout = ?, max_concurrent = ?, retry_count = ?, retry_delay = ?, replay_delay = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, colorHex);
            pstmt.setInt(3, enabled ? 1 : 0);
            if (schemeId != null) {
                pstmt.setInt(4, schemeId);
            } else {
                pstmt.setNull(4, java.sql.Types.INTEGER);
            }
            pstmt.setInt(5, requestTimeout);
            pstmt.setInt(6, maxConcurrent);
            pstmt.setInt(7, retryCount);
            pstmt.setInt(8, retryDelay);
            pstmt.setInt(9, replayDelay);
            pstmt.setInt(10, id);
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

    /**
     * 删除所有用户会话（级联删除关联的token_values）
     */
    public boolean deleteAllUserSessions() {
        String sql = "DELETE FROM user_sessions";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除所有用户会话失败: " + e.getMessage());
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
