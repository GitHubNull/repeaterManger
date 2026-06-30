package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentRule;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则组数据访问对象（v13）
 * 管理 judgment_rule_groups 表的 CRUD
 */
public class JudgmentRuleGroupDAO {

    /**
     * 获取所有规则组
     */
    public List<JudgmentRule> getAllGroups() {
        List<JudgmentRule> groups = new ArrayList<>();
        String sql = "SELECT id, name, is_active, enabled, success_color, failure_color, " +
                "success_note, failure_note, remark, global " +
                "FROM judgment_rule_groups ORDER BY id ASC";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                groups.add(mapRowToGroup(rs));
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取规则组列表失败: " + e.getMessage());
        }
        return groups;
    }

    /**
     * 获取已启用的规则组
     */
    public List<JudgmentRule> getEnabledGroups() {
        List<JudgmentRule> groups = new ArrayList<>();
        String sql = "SELECT id, name, is_active, enabled, success_color, failure_color, " +
                "success_note, failure_note, remark, global " +
                "FROM judgment_rule_groups WHERE enabled = 1 ORDER BY id ASC";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                groups.add(mapRowToGroup(rs));
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取已启用规则组失败: " + e.getMessage());
        }
        return groups;
    }

    /**
     * 获取当前活跃规则组（is_active=1，全局唯一）
     */
    public JudgmentRule getActiveGroup() {
        String sql = "SELECT id, name, is_active, enabled, success_color, failure_color, " +
                "success_note, failure_note, remark, global " +
                "FROM judgment_rule_groups WHERE is_active = 1 AND enabled = 1 LIMIT 1";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return mapRowToGroup(rs);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取活跃规则组失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 根据ID获取规则组
     */
    public JudgmentRule getGroupById(int id) {
        String sql = "SELECT id, name, is_active, enabled, success_color, failure_color, " +
                "success_note, failure_note, remark, global " +
                "FROM judgment_rule_groups WHERE id = ?";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapRowToGroup(rs);
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取规则组失败 (id=" + id + "): " + e.getMessage());
        }
        return null;
    }

    /**
     * 添加规则组
     * @return 新记录ID，失败返回-1
     */
    public int addGroup(JudgmentRule group) {
        String sql = "INSERT INTO judgment_rule_groups " +
                "(name, is_active, enabled, success_color, failure_color, " +
                "success_note, failure_note, remark, global) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, group.getName() != null ? group.getName() : "");
            pstmt.setInt(2, group.isActive() ? 1 : 0);
            pstmt.setInt(3, group.isEnabled() ? 1 : 0);
            pstmt.setString(4, group.getSuccessColorHex());
            pstmt.setString(5, group.getFailureColorHex());
            pstmt.setString(6, group.getSuccessNote());
            pstmt.setString(7, group.getFailureNote());
            pstmt.setString(8, group.getRemark());
            pstmt.setInt(9, group.isGlobal() ? 1 : 0);
            pstmt.executeUpdate();

            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 添加规则组失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新规则组
     */
    public boolean updateGroup(JudgmentRule group) {
        String sql = "UPDATE judgment_rule_groups SET " +
                "name = ?, is_active = ?, enabled = ?, success_color = ?, failure_color = ?, " +
                "success_note = ?, failure_note = ?, remark = ?, global = ?, " +
                "updated_at = CURRENT_TIMESTAMP " +
                "WHERE id = ?";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, group.getName() != null ? group.getName() : "");
            pstmt.setInt(2, group.isActive() ? 1 : 0);
            pstmt.setInt(3, group.isEnabled() ? 1 : 0);
            pstmt.setString(4, group.getSuccessColorHex());
            pstmt.setString(5, group.getFailureColorHex());
            pstmt.setString(6, group.getSuccessNote());
            pstmt.setString(7, group.getFailureNote());
            pstmt.setString(8, group.getRemark());
            pstmt.setInt(9, group.isGlobal() ? 1 : 0);
            pstmt.setInt(10, group.getId());
            int rows = pstmt.executeUpdate();
            return rows > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 更新规则组失败 (id=" + group.getId() + "): " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除规则组（级联删除条件由 FK ON DELETE CASCADE 保证）
     */
    public boolean deleteGroup(int id) {
        String sql = "DELETE FROM judgment_rule_groups WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            int rows = pstmt.executeUpdate();
            return rows > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除规则组失败 (id=" + id + "): " + e.getMessage());
            return false;
        }
    }

    /**
     * 设置活跃规则组（事务中互斥：先将所有记录 is_active=0，再设置目标为 1）
     */
    public boolean setActiveGroup(int groupId) {
        Connection conn = null;
        try {
            conn = DatabaseManager.getInstance().getConnection();
            conn.setAutoCommit(false);

            try (Statement stmt = conn.createStatement()) {
                // 先将所有规则组置为非活跃
                stmt.executeUpdate("UPDATE judgment_rule_groups SET is_active = 0");
                // 设置目标规则组为活跃
                String sql = "UPDATE judgment_rule_groups SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = " + groupId;
                int rows = stmt.executeUpdate(sql);
                conn.commit();
                return rows > 0;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 设置活跃规则组失败 (id=" + groupId + "): " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除所有规则组（用于替换导入）
     */
    public void deleteAllGroups() {
        String sql = "DELETE FROM judgment_rule_groups";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除所有规则组失败: " + e.getMessage());
        }
    }

    /**
     * 检查是否存在包含指定目标的条件（用于 ensureDefaultSimilarityRule）
     */
    public boolean hasConditionWithTarget(String targetName) {
        String sql = "SELECT COUNT(*) FROM judgment_rule_conditions WHERE target = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, targetName);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 检查条件目标失败: " + e.getMessage());
        }
        return false;
    }

    // ==================== 内部方法 ====================

    private JudgmentRule mapRowToGroup(ResultSet rs) throws SQLException {
        JudgmentRule group = new JudgmentRule();
        group.setId(rs.getInt("id"));
        group.setName(rs.getString("name"));
        group.setActive(rs.getInt("is_active") == 1);
        group.setEnabled(rs.getInt("enabled") == 1);
        group.setSuccessColor(JudgmentRule.hexToColor(rs.getString("success_color")));
        group.setFailureColor(JudgmentRule.hexToColor(rs.getString("failure_color")));
        group.setSuccessNote(rs.getString("success_note"));
        group.setFailureNote(rs.getString("failure_note"));
        group.setRemark(rs.getString("remark"));
        group.setGlobal(rs.getInt("global") == 1);
        return group;
    }
}
