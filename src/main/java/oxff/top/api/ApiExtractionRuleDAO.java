package oxff.top.api;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * API提取规则数据访问对象
 */
public class ApiExtractionRuleDAO {

    /**
     * 获取所有规则（按优先级升序）
     */
    public List<ApiExtractionRule> getAllRules() {
        String sql = "SELECT id, name, source, method, expression, enabled, priority, remark " +
                "FROM api_extraction_rules ORDER BY priority ASC, id ASC";

        List<ApiExtractionRule> rules = new ArrayList<>();
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                ApiExtractionRule rule = mapResultSetToRule(rs);
                rules.add(rule);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取API提取规则失败: " + e.getMessage());
        }
        return rules;
    }

    /**
     * 根据ID获取规则
     */
    public ApiExtractionRule getRuleById(int id) {
        String sql = "SELECT id, name, source, method, expression, enabled, priority, remark " +
                "FROM api_extraction_rules WHERE id = ?";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRule(rs);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取API提取规则失败(id=" + id + "): " + e.getMessage());
        }
        return null;
    }

    /**
     * 保存新规则
     *
     * @return 生成的ID，失败返回-1
     */
    public int saveRule(ApiExtractionRule rule) {
        String sql = "INSERT INTO api_extraction_rules (name, source, method, expression, enabled, priority, remark) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, rule.getName());
            pstmt.setString(2, rule.getSource().toDbValue());
            pstmt.setString(3, rule.getMethod().toDbValue());
            pstmt.setString(4, rule.getExpression());
            pstmt.setInt(5, rule.isEnabled() ? 1 : 0);
            pstmt.setInt(6, rule.getPriority());
            pstmt.setString(7, rule.getRemark());

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int id = rs.getInt(1);
                        BurpExtender.printOutput("[+] API提取规则已保存，ID: " + id);
                        return id;
                    }
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 保存API提取规则失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新规则
     */
    public boolean updateRule(ApiExtractionRule rule) {
        String sql = "UPDATE api_extraction_rules SET name = ?, source = ?, method = ?, " +
                "expression = ?, enabled = ?, priority = ?, remark = ? WHERE id = ?";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, rule.getName());
            pstmt.setString(2, rule.getSource().toDbValue());
            pstmt.setString(3, rule.getMethod().toDbValue());
            pstmt.setString(4, rule.getExpression());
            pstmt.setInt(5, rule.isEnabled() ? 1 : 0);
            pstmt.setInt(6, rule.getPriority());
            pstmt.setString(7, rule.getRemark());
            pstmt.setInt(8, rule.getId());

            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                BurpExtender.printOutput("[+] API提取规则已更新，ID: " + rule.getId());
            }
            return result;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新API提取规则失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除规则
     */
    public boolean deleteRule(int id) {
        String sql = "DELETE FROM api_extraction_rules WHERE id = ?";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                BurpExtender.printOutput("[+] API提取规则已删除，ID: " + id);
            }
            return result;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除API提取规则失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除所有规则
     */
    public boolean deleteAllRules() {
        String sql = "DELETE FROM api_extraction_rules";

        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.executeUpdate();
            BurpExtender.printOutput("[+] 所有API提取规则已删除");
            return true;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除所有API提取规则失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 映射ResultSet到规则对象
     */
    private ApiExtractionRule mapResultSetToRule(ResultSet rs) throws SQLException {
        ApiExtractionRule rule = new ApiExtractionRule();
        rule.setId(rs.getInt("id"));
        rule.setName(rs.getString("name"));
        rule.setSource(ApiRuleSource.fromDbValue(rs.getString("source")));
        rule.setMethod(ApiRuleMethod.fromDbValue(rs.getString("method")));
        rule.setExpression(rs.getString("expression"));
        rule.setEnabled(rs.getInt("enabled") == 1);
        rule.setPriority(rs.getInt("priority"));
        rule.setRemark(rs.getString("remark"));
        return rule;
    }
}
