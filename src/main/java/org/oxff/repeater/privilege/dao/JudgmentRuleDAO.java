package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则数据访问对象
 * 管理 judgment_rules 表的 CRUD
 */
public class JudgmentRuleDAO {

    /**
     * 获取所有判决规则
     */
    public List<JudgmentRule> getAllRules() {
        List<JudgmentRule> rules = new ArrayList<>();
        String sql = "SELECT id, name, target, method, expression, enabled, priority, " +
                "success_color, failure_color, success_note, failure_note, remark, global " +
                "FROM judgment_rules ORDER BY priority ASC, id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                rules.add(mapRowToRule(rs));
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取判决规则列表失败: " + e.getMessage());
        }
        return rules;
    }

    /**
     * 获取所有已启用的判决规则（按优先级排序）
     */
    public List<JudgmentRule> getEnabledRules() {
        List<JudgmentRule> rules = new ArrayList<>();
        String sql = "SELECT id, name, target, method, expression, enabled, priority, " +
                "success_color, failure_color, success_note, failure_note, remark, global " +
                "FROM judgment_rules WHERE enabled = 1 ORDER BY priority ASC, id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                rules.add(mapRowToRule(rs));
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取已启用判决规则列表失败: " + e.getMessage());
        }
        return rules;
    }

    /**
     * 根据ID获取规则
     */
    public JudgmentRule getRuleById(int id) {
        String sql = "SELECT id, name, target, method, expression, enabled, priority, " +
                "success_color, failure_color, success_note, failure_note, remark, global " +
                "FROM judgment_rules WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapRowToRule(rs);
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取判决规则失败 (id=" + id + "): " + e.getMessage());
        }
        return null;
    }

    /**
     * 添加判决规则
     * @return 新记录ID，失败返回-1
     */
    public int addRule(JudgmentRule rule) {
        String sql = "INSERT INTO judgment_rules (name, target, method, expression, enabled, priority, " +
                "success_color, failure_color, success_note, failure_note, remark, global) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            setRuleParameters(pstmt, rule);
            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 添加判决规则失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新判决规则
     */
    public boolean updateRule(JudgmentRule rule) {
        String sql = "UPDATE judgment_rules SET name = ?, target = ?, method = ?, expression = ?, " +
                "enabled = ?, priority = ?, success_color = ?, failure_color = ?, " +
                "success_note = ?, failure_note = ?, remark = ?, global = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            setRuleParameters(pstmt, rule);
            pstmt.setInt(13, rule.getId());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 更新判决规则失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除判决规则
     */
    public boolean deleteRule(int id) {
        String sql = "DELETE FROM judgment_rules WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除判决规则失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除所有规则
     */
    public boolean deleteAllRules() {
        String sql = "DELETE FROM judgment_rules";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除所有判决规则失败: " + e.getMessage());
        }
        return false;
    }

    // ==================== 私有辅助方法 ====================

    private JudgmentRule mapRowToRule(ResultSet rs) throws SQLException {
        JudgmentRule rule = new JudgmentRule();
        rule.setId(rs.getInt("id"));
        rule.setName(rs.getString("name"));
        rule.setTarget(RuleTarget.fromString(rs.getString("target")));
        rule.setMethod(RuleMethod.fromString(rs.getString("method")));
        rule.setExpression(rs.getString("expression"));
        rule.setEnabled(rs.getInt("enabled") == 1);
        rule.setPriority(rs.getInt("priority"));
        rule.setSuccessColor(JudgmentRule.hexToColor(rs.getString("success_color")));
        rule.setFailureColor(JudgmentRule.hexToColor(rs.getString("failure_color")));
        rule.setSuccessNote(rs.getString("success_note"));
        rule.setFailureNote(rs.getString("failure_note"));
        rule.setRemark(rs.getString("remark"));
        rule.setGlobal(rs.getInt("global") == 1);
        return rule;
    }

    private void setRuleParameters(PreparedStatement pstmt, JudgmentRule rule) throws SQLException {
        pstmt.setString(1, rule.getName() != null ? rule.getName() : "");
        pstmt.setString(2, rule.getTarget() != null ? rule.getTarget().name() : RuleTarget.STATUS_CODE.name());
        pstmt.setString(3, rule.getMethod() != null ? rule.getMethod().name() : RuleMethod.REGEX.name());
        pstmt.setString(4, rule.getExpression() != null ? rule.getExpression() : "");
        pstmt.setInt(5, rule.isEnabled() ? 1 : 0);
        pstmt.setInt(6, rule.getPriority());
        pstmt.setString(7, rule.getSuccessColorHex());
        pstmt.setString(8, rule.getFailureColorHex());
        pstmt.setString(9, rule.getSuccessNote());
        pstmt.setString(10, rule.getFailureNote());
        pstmt.setString(11, rule.getRemark());
        pstmt.setInt(12, rule.isGlobal() ? 1 : 0);
    }
}
