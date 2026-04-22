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
        // 先尝试带 name/remark 列的查询（v4 schema）
        String sqlV4 = "SELECT id, name, source, method, expression, enabled, priority, remark " +
                "FROM api_extraction_rules ORDER BY priority ASC, id ASC";
        String sqlV3 = "SELECT id, source, method, expression, enabled, priority " +
                "FROM api_extraction_rules ORDER BY priority ASC, id ASC";

        List<ApiExtractionRule> rules = new ArrayList<>();
        // 优先尝试v4查询
        boolean useV4 = true;
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV4);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                rules.add(mapResultSetToRule(rs));
            }
        } catch (SQLException e) {
            // v4查询失败（可能是旧schema没有name/remark列），回退到v3查询
            BurpExtender.printOutput("[*] v4规则查询失败，尝试v3兼容查询: " + e.getMessage());
            useV4 = false;
        }

        if (!useV4) {
            try (Connection conn = DatabaseManager.getInstance().getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sqlV3);
                 ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    rules.add(mapResultSetToRuleV3(rs));
                }
            } catch (SQLException e) {
                BurpExtender.printError("[!] 获取API提取规则失败: " + e.getMessage());
            }
        }
        return rules;
    }

    /**
     * 根据ID获取规则
     */
    public ApiExtractionRule getRuleById(int id) {
        String sqlV4 = "SELECT id, name, source, method, expression, enabled, priority, remark " +
                "FROM api_extraction_rules WHERE id = ?";
        String sqlV3 = "SELECT id, source, method, expression, enabled, priority " +
                "FROM api_extraction_rules WHERE id = ?";

        // 优先尝试v4查询
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV4)) {
            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRule(rs);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printOutput("[*] v4规则查询失败，尝试v3兼容查询: " + e.getMessage());
        }

        // 回退到v3查询
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV3)) {
            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRuleV3(rs);
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
        // 先尝试v4 schema（含name/remark）
        String sqlV4 = "INSERT INTO api_extraction_rules (name, source, method, expression, enabled, priority, remark) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        String sqlV3 = "INSERT INTO api_extraction_rules (source, method, expression, enabled, priority) " +
                "VALUES (?, ?, ?, ?, ?)";

        // 优先尝试v4插入
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV4, PreparedStatement.RETURN_GENERATED_KEYS)) {

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
            // v4插入失败，尝试v3
            BurpExtender.printOutput("[*] v4规则插入失败，尝试v3兼容插入: " + e.getMessage());
        }

        // 回退到v3插入
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV3, PreparedStatement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, rule.getSource().toDbValue());
            pstmt.setString(2, rule.getMethod().toDbValue());
            pstmt.setString(3, rule.getExpression());
            pstmt.setInt(4, rule.isEnabled() ? 1 : 0);
            pstmt.setInt(5, rule.getPriority());

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int id = rs.getInt(1);
                        BurpExtender.printOutput("[+] API提取规则已保存(v3)，ID: " + id);
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
        // 先尝试v4 schema（含name/remark）
        String sqlV4 = "UPDATE api_extraction_rules SET name = ?, source = ?, method = ?, " +
                "expression = ?, enabled = ?, priority = ?, remark = ? WHERE id = ?";
        String sqlV3 = "UPDATE api_extraction_rules SET source = ?, method = ?, " +
                "expression = ?, enabled = ?, priority = ? WHERE id = ?";

        // 优先尝试v4更新
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV4)) {

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
                return result;
            }
        } catch (SQLException e) {
            BurpExtender.printOutput("[*] v4规则更新失败，尝试v3兼容更新: " + e.getMessage());
        }

        // 回退到v3更新
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlV3)) {

            pstmt.setString(1, rule.getSource().toDbValue());
            pstmt.setString(2, rule.getMethod().toDbValue());
            pstmt.setString(3, rule.getExpression());
            pstmt.setInt(4, rule.isEnabled() ? 1 : 0);
            pstmt.setInt(5, rule.getPriority());
            pstmt.setInt(6, rule.getId());

            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                BurpExtender.printOutput("[+] API提取规则已更新(v3)，ID: " + rule.getId());
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
     * 映射ResultSet到规则对象（v4 schema，含name/remark）
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

    /**
     * 映射ResultSet到规则对象（v3 schema，不含name/remark）
     */
    private ApiExtractionRule mapResultSetToRuleV3(ResultSet rs) throws SQLException {
        ApiExtractionRule rule = new ApiExtractionRule();
        rule.setId(rs.getInt("id"));
        rule.setName("");
        rule.setSource(ApiRuleSource.fromDbValue(rs.getString("source")));
        rule.setMethod(ApiRuleMethod.fromDbValue(rs.getString("method")));
        rule.setExpression(rs.getString("expression"));
        rule.setEnabled(rs.getInt("enabled") == 1);
        rule.setPriority(rs.getInt("priority"));
        rule.setRemark("");
        return rule;
    }
}
