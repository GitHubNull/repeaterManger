package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则条件数据访问对象（v13）
 * 管理 judgment_rule_conditions 表的 CRUD
 */
public class JudgmentRuleConditionDAO {

    /**
     * 获取指定规则组的所有条件（按 sort_order 排序）
     */
    public List<RuleCondition> getConditionsByGroupId(int groupId) {
        List<RuleCondition> conditions = new ArrayList<>();
        String sql = "SELECT id, group_id, target, method, expression, negate, sort_order, enabled, remark " +
                "FROM judgment_rule_conditions WHERE group_id = ? ORDER BY sort_order ASC, id ASC";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, groupId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    conditions.add(mapRowToCondition(rs));
                }
            }
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 获取条件列表失败 (groupId=" + groupId + "): " + e.getMessage());
        }
        return conditions;
    }

    /**
     * 批量添加条件到指定规则组
     * @return 实际添加数量
     */
    public int addConditions(int groupId, List<RuleCondition> conditions) {
        if (conditions == null || conditions.isEmpty()) return 0;

        String sql = "INSERT INTO judgment_rule_conditions " +
                "(group_id, target, method, expression, negate, sort_order, enabled, remark) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        int count = 0;
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            for (int i = 0; i < conditions.size(); i++) {
                RuleCondition cond = conditions.get(i);
                pstmt.setInt(1, groupId);
                pstmt.setString(2, cond.getTarget() != null ? cond.getTarget().name() : RuleTarget.STATUS_CODE.name());
                pstmt.setString(3, cond.getMethod() != null ? cond.getMethod().name() : RuleMethod.REGEX.name());
                pstmt.setString(4, cond.getExpression() != null ? cond.getExpression() : "");
                pstmt.setInt(5, cond.isNegate() ? 1 : 0);
                pstmt.setInt(6, cond.getSortOrder() > 0 ? cond.getSortOrder() : i);
                pstmt.setInt(7, cond.isEnabled() ? 1 : 0);
                pstmt.setString(8, cond.getRemark() != null ? cond.getRemark() : "");
                pstmt.addBatch();
                count++;
            }
            pstmt.executeBatch();
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 批量添加条件失败 (groupId=" + groupId + "): " + e.getMessage());
            return 0;
        }
        return count;
    }

    /**
     * 删除指定规则组的所有条件
     */
    public void deleteConditionsByGroupId(int groupId) {
        String sql = "DELETE FROM judgment_rule_conditions WHERE group_id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, groupId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 删除条件失败 (groupId=" + groupId + "): " + e.getMessage());
        }
    }

    /**
     * 替换指定规则组的所有条件（先删后插）
     */
    public boolean replaceConditions(int groupId, List<RuleCondition> conditions) {
        Connection conn = null;
        try {
            conn = DatabaseManager.getInstance().getConnection();
            conn.setAutoCommit(false);

            // 先删
            try (PreparedStatement delStmt = conn.prepareStatement(
                    "DELETE FROM judgment_rule_conditions WHERE group_id = ?")) {
                delStmt.setInt(1, groupId);
                delStmt.executeUpdate();
            }

            // 再插
            if (conditions != null && !conditions.isEmpty()) {
                try (PreparedStatement insStmt = conn.prepareStatement(
                        "INSERT INTO judgment_rule_conditions " +
                        "(group_id, target, method, expression, negate, sort_order, enabled, remark) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {

                    for (int i = 0; i < conditions.size(); i++) {
                        RuleCondition cond = conditions.get(i);
                        insStmt.setInt(1, groupId);
                        insStmt.setString(2, cond.getTarget() != null ? cond.getTarget().name() : RuleTarget.STATUS_CODE.name());
                        insStmt.setString(3, cond.getMethod() != null ? cond.getMethod().name() : RuleMethod.REGEX.name());
                        insStmt.setString(4, cond.getExpression() != null ? cond.getExpression() : "");
                        insStmt.setInt(5, cond.isNegate() ? 1 : 0);
                        insStmt.setInt(6, cond.getSortOrder() > 0 ? cond.getSortOrder() : i);
                        insStmt.setInt(7, cond.isEnabled() ? 1 : 0);
                        insStmt.setString(8, cond.getRemark() != null ? cond.getRemark() : "");
                        insStmt.addBatch();
                    }
                    insStmt.executeBatch();
                }
            }

            conn.commit();
            return true;
        } catch (SQLException e) {
            LogManager.getInstance().printError("[!] 替换条件失败 (groupId=" + groupId + "): " + e.getMessage());
            try {
                if (conn != null) conn.rollback();
            } catch (SQLException ex) {
                // ignore
            }
            return false;
        } finally {
            try {
                if (conn != null) conn.setAutoCommit(true);
            } catch (SQLException e) {
                // ignore
            }
        }
    }

    // ==================== 内部方法 ====================

    private RuleCondition mapRowToCondition(ResultSet rs) throws SQLException {
        RuleCondition cond = new RuleCondition();
        cond.setId(rs.getInt("id"));
        cond.setGroupId(rs.getInt("group_id"));
        cond.setTarget(RuleTarget.fromString(rs.getString("target")));
        cond.setMethod(RuleMethod.fromString(rs.getString("method")));
        cond.setExpression(rs.getString("expression"));
        cond.setNegate(rs.getInt("negate") == 1);
        cond.setSortOrder(rs.getInt("sort_order"));
        cond.setEnabled(rs.getInt("enabled") == 1);
        cond.setRemark(rs.getString("remark"));
        return cond;
    }
}
