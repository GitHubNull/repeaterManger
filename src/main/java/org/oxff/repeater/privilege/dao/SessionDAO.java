package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.FieldType;
import org.oxff.repeater.privilege.model.Scheme;
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
 * 管理 field_definitions、schemes、scheme_fields、user_sessions、field_values 五张表的 CRUD
 */
public class SessionDAO {

    // ==================== FieldDefinition CRUD ====================

    /**
     * 获取所有字段
     */
    public List<FieldDefinition> getAllFieldDefinitions() {
        List<FieldDefinition> fields = new ArrayList<>();
        String sql = "SELECT id, type, expression, description, persist_to_global, enabled FROM field_definitions ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                FieldDefinition field = new FieldDefinition();
                field.setId(rs.getInt("id"));
                field.setType(FieldType.fromString(rs.getString("type")));
                field.setExpression(rs.getString("expression"));
                field.setDescription(rs.getString("description"));
                field.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                field.setEnabled(rs.getInt("enabled") == 1);
                fields.add(field);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取字段列表失败: " + e.getMessage());
        }
        return fields;
    }

    /**
     * 添加字段
     * @return 新记录ID，失败返回-1
     */
    public int addFieldDefinition(FieldType type, String expression, String description,
                                   boolean persistToGlobal, boolean enabled) {
        String sql = "INSERT INTO field_definitions (type, expression, description, persist_to_global, enabled) VALUES (?, ?, ?, ?, ?)";
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
            LogManager.getInstance().printError("[!] 添加字段失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新字段
     */
    public boolean updateFieldDefinition(int id, FieldType type, String expression, String description,
                                          boolean persistToGlobal, boolean enabled) {
        String sql = "UPDATE field_definitions SET type = ?, expression = ?, description = ?, persist_to_global = ?, enabled = ? WHERE id = ?";
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
            LogManager.getInstance().printError("[!] 更新字段失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除字段（级联删除关联的field_values和scheme_fields）
     */
    public boolean deleteFieldDefinition(int id) {
        String sql = "DELETE FROM field_definitions WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除字段失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 获取引用指定字段的方案数量
     */
    public int getSchemeReferenceCountByField(int fieldId) {
        String sql = "SELECT COUNT(DISTINCT scheme_id) FROM scheme_fields WHERE field_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, fieldId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取字段引用方案数失败: " + e.getMessage());
        }
        return 0;
    }

    // ==================== Scheme CRUD ====================

    /**
     * 获取所有方案（含关联的字段ID列表）
     */
    public List<Scheme> getAllSchemes() {
        List<Scheme> schemes = new ArrayList<>();
        String sql = "SELECT id, name, description, persist_to_global, enabled FROM schemes ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                Scheme scheme = new Scheme();
                scheme.setId(rs.getInt("id"));
                scheme.setName(rs.getString("name"));
                scheme.setDescription(rs.getString("description"));
                scheme.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                scheme.setEnabled(rs.getInt("enabled") == 1);
                scheme.setFieldIds(loadSchemeFieldIds(conn, scheme.getId()));
                schemes.add(scheme);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取方案列表失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 获取所有已启用的方案
     */
    public List<Scheme> getEnabledSchemes() {
        List<Scheme> schemes = new ArrayList<>();
        String sql = "SELECT id, name, description, persist_to_global, enabled FROM schemes WHERE enabled = 1 ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                Scheme scheme = new Scheme();
                scheme.setId(rs.getInt("id"));
                scheme.setName(rs.getString("name"));
                scheme.setDescription(rs.getString("description"));
                scheme.setPersistToGlobal(rs.getInt("persist_to_global") == 1);
                scheme.setEnabled(true);
                scheme.setFieldIds(loadSchemeFieldIds(conn, scheme.getId()));
                schemes.add(scheme);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取已启用方案列表失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 添加方案
     * @return 新记录ID，失败返回-1
     */
    public int addScheme(String name, String description, boolean persistToGlobal, boolean enabled) {
        String sql = "INSERT INTO schemes (name, description, persist_to_global, enabled) VALUES (?, ?, ?, ?)";
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
            LogManager.getInstance().printError("[!] 添加方案失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新方案
     */
    public boolean updateScheme(int id, String name, String description, boolean persistToGlobal, boolean enabled) {
        String sql = "UPDATE schemes SET name = ?, description = ?, persist_to_global = ?, enabled = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, description != null ? description : "");
            pstmt.setInt(3, persistToGlobal ? 1 : 0);
            pstmt.setInt(4, enabled ? 1 : 0);
            pstmt.setInt(5, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 更新方案失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除方案（级联删除关联的scheme_fields）
     */
    public boolean deleteScheme(int id) {
        String sql = "DELETE FROM schemes WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除方案失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 保存方案关联的字段（先删后插）
     */
    public boolean saveSchemeFields(int schemeId, List<Integer> fieldIds) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                // 删除旧的关联
                String deleteSql = "DELETE FROM scheme_fields WHERE scheme_id = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(deleteSql)) {
                    pstmt.setInt(1, schemeId);
                    pstmt.executeUpdate();
                }

                // 插入新的关联
                String insertSql = "INSERT INTO scheme_fields (scheme_id, field_id) VALUES (?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    for (int fid : fieldIds) {
                        pstmt.setInt(1, schemeId);
                        pstmt.setInt(2, fid);
                        pstmt.executeUpdate();
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                LogManager.getInstance().printError("[!] 保存方案字段关联失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 保存方案字段关联数据库操作失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 加载指定方案关联的字段ID列表
     */
    private List<Integer> loadSchemeFieldIds(Connection conn, int schemeId) {
        List<Integer> ids = new ArrayList<>();
        String sql = "SELECT field_id FROM scheme_fields WHERE scheme_id = ? ORDER BY field_id ASC";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, schemeId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    ids.add(rs.getInt("field_id"));
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 加载方案字段关联失败: " + e.getMessage());
        }
        return ids;
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
            LogManager.getInstance().printError("[!] 获取方案引用会话数失败: " + e.getMessage());
        }
        return 0;
    }

    // ==================== UserSession CRUD ====================

    /**
     * 获取所有用户会话（含字段值）
     */
    public List<UserSession> getAllUserSessions() {
        List<UserSession> sessions = new ArrayList<>();
        String sql = "SELECT id, name, color, enabled, scheme_id, request_timeout, max_concurrent, retry_count, retry_delay, replay_delay FROM user_sessions ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                UserSession session = buildUserSession(rs, conn);
                sessions.add(session);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取用户会话列表失败: " + e.getMessage());
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
                UserSession session = buildUserSession(rs, conn);
                sessions.add(session);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取已启用用户会话列表失败: " + e.getMessage());
        }
        return sessions;
    }

    /**
     * 从 ResultSet 构建 UserSession 对象（含字段值加载）
     */
    private UserSession buildUserSession(ResultSet rs, Connection conn) throws SQLException {
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
        // 加载字段值
        session.setFieldValues(loadFieldValues(conn, session.getId()));
        return session;
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
            LogManager.getInstance().printError("[!] 添加用户会话失败: " + e.getMessage());
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
            LogManager.getInstance().printError("[!] 更新用户会话失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除用户会话（级联删除关联的field_values）
     */
    public boolean deleteUserSession(int id) {
        String sql = "DELETE FROM user_sessions WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除用户会话失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除所有用户会话（级联删除关联的field_values）
     */
    public boolean deleteAllUserSessions() {
        String sql = "DELETE FROM user_sessions";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除所有用户会话失败: " + e.getMessage());
        }
        return false;
    }

    // ==================== FieldValue CRUD ====================

    /**
     * 加载指定用户会话的所有字段值
     */
    private Map<Integer, String> loadFieldValues(Connection conn, int userSessionId) {
        Map<Integer, String> values = new LinkedHashMap<>();
        String sql = "SELECT field_id, value FROM field_values WHERE user_session_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userSessionId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    values.put(rs.getInt("field_id"), rs.getString("value"));
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 加载字段值失败: " + e.getMessage());
        }
        return values;
    }

    /**
     * 保存指定用户会话的所有字段值。
     *
     * 使用 INSERT OR REPLACE 逐条 upsert + 清理旧值，替代先删后插模式。
     * 利用 field_values(field_id, user_session_id) UNIQUE 约束实现幂等写入，
     * 避免 DELETE 回滚时丢失全部旧值的风险。
     */
    public boolean saveFieldValues(int userSessionId, Map<Integer, String> fieldValues) {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try {
                String upsertSql = "INSERT OR REPLACE INTO field_values (field_id, user_session_id, value) VALUES (?, ?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(upsertSql)) {
                    for (Map.Entry<Integer, String> entry : fieldValues.entrySet()) {
                        pstmt.setInt(1, entry.getKey());
                        pstmt.setInt(2, userSessionId);
                        pstmt.setString(3, entry.getValue() != null ? entry.getValue() : "");
                        pstmt.executeUpdate();
                    }
                }

                // 清理不再存在于新集合中的旧字段值（如被移除的 field）
                if (!fieldValues.isEmpty()) {
                    StringBuilder deleteSql = new StringBuilder("DELETE FROM field_values WHERE user_session_id = ? AND field_id NOT IN (");
                    for (int i = 0; i < fieldValues.size(); i++) {
                        if (i > 0) deleteSql.append(",");
                        deleteSql.append("?");
                    }
                    deleteSql.append(")");
                    try (PreparedStatement pstmt = conn.prepareStatement(deleteSql.toString())) {
                        pstmt.setInt(1, userSessionId);
                        int idx = 2;
                        for (Integer fid : fieldValues.keySet()) {
                            pstmt.setInt(idx++, fid);
                        }
                        pstmt.executeUpdate();
                    }
                }

                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                LogManager.getInstance().printError("[!] 保存字段值失败: " + e.getMessage());
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 保存字段值数据库操作失败: " + e.getMessage());
        }
        return false;
    }
}
