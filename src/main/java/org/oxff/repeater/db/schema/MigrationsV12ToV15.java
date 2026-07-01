package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v12→v15 Schema 迁移步骤集合。
 * 包含4个迁移：v11→v12, v12→v13, v13→v14, v14→v15
 */
public final class MigrationsV12ToV15 {

    private MigrationsV12ToV15() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV11ToV12());
        steps.add(new MigrateV12ToV13());
        steps.add(new MigrateV13ToV14());
        steps.add(new MigrateV14ToV15());
        return steps;
    }

    // ==================== v11→v12 ====================

    static class MigrateV11ToV12 implements MigrationStep {
        @Override public int fromVersion() { return 11; }
        @Override public int toVersion() { return 12; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v11→v12迁移...");

                try {
                    stmt.execute("ALTER TABLE judgment_rules ADD COLUMN conditions_json TEXT DEFAULT NULL");
                    LogManager.getInstance().printOutput("[+] judgment_rules表添加conditions_json列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] judgment_rules表添加conditions_json列失败: " + e.getMessage());
                    }
                }

                try {
                    int migrated = stmt.executeUpdate(
                        "UPDATE judgment_rules SET conditions_json = " +
                        "'[' || '{\"target\":\"' || target || '\",\"method\":\"' || method || " +
                        "'\",\"expression\":\"' || REPLACE(expression, '\"', '\\\"') || '\",' || " +
                        "'\"operator\":\"AND\",\"negate\":false}' || ']' " +
                        "WHERE conditions_json IS NULL AND expression IS NOT NULL AND expression != ''"
                    );
                    LogManager.getInstance().printOutput("[+] 迁移 " + migrated + " 条现有规则到 conditions_json 完成");
                } catch (SQLException e) {
                    LogManager.getInstance().printError("[!] 迁移现有规则到 conditions_json 失败: " + e.getMessage());
                }

                stmt.execute("UPDATE schema_meta SET value = '12' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '12')");

                LogManager.getInstance().printOutput("[+] v11→v12 迁移完成");
            }
        }
    }

    // ==================== v12→v13 ====================

    static class MigrateV12ToV13 implements MigrationStep {
        @Override public int fromVersion() { return 12; }
        @Override public int toVersion() { return 13; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v12→v13迁移（judgment_rules → 双表）...");

                // 1. 创建新表
                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS judgment_rule_groups (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "name TEXT NOT NULL DEFAULT '', " +
                    "is_active INTEGER NOT NULL DEFAULT 0, " +
                    "enabled INTEGER NOT NULL DEFAULT 1, " +
                    "success_color TEXT DEFAULT '#FF0000', " +
                    "failure_color TEXT DEFAULT '#90EE90', " +
                    "success_note TEXT DEFAULT '', " +
                    "failure_note TEXT DEFAULT '', " +
                    "remark TEXT DEFAULT '', " +
                    "global INTEGER NOT NULL DEFAULT 1, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
                );

                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS judgment_rule_conditions (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "group_id INTEGER NOT NULL, " +
                    "target TEXT NOT NULL, " +
                    "method TEXT NOT NULL, " +
                    "expression TEXT NOT NULL, " +
                    "negate INTEGER NOT NULL DEFAULT 0, " +
                    "sort_order INTEGER NOT NULL DEFAULT 0, " +
                    "enabled INTEGER NOT NULL DEFAULT 1, " +
                    "remark TEXT DEFAULT '', " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (group_id) REFERENCES judgment_rule_groups(id) ON DELETE CASCADE" +
                    ")"
                );

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_rule_groups_active ON judgment_rule_groups(is_active)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_conditions_group ON judgment_rule_conditions(group_id, sort_order)");

                LogManager.getInstance().printOutput("[+] v13 新表创建成功");

                // 2. 检查旧表是否存在
                boolean oldTableExists = false;
                try (ResultSet rs = stmt.executeQuery(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='judgment_rules'")) {
                    oldTableExists = rs.next();
                }

                if (!oldTableExists) {
                    LogManager.getInstance().printOutput("[*] 旧 judgment_rules 表不存在，跳过数据迁移");
                    stmt.execute("UPDATE schema_meta SET value = '13' WHERE key = 'schema_version'");
                    stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '13')");
                    LogManager.getInstance().printOutput("[+] v12→v13 迁移完成（无旧数据）");
                    return;
                }

                // 3. 遍历旧规则，逐条迁移
                int groupCount = 0;
                int condCount = 0;
                boolean firstGroup = true;

                String insertGroupSql = "INSERT INTO judgment_rule_groups " +
                        "(name, is_active, enabled, success_color, failure_color, " +
                        "success_note, failure_note, remark, global) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

                String insertCondFromJsonSql = "INSERT INTO judgment_rule_conditions " +
                        "(group_id, target, method, expression, negate, sort_order, enabled) " +
                        "SELECT ?, " +
                        "COALESCE(json_extract(value, '$.target'), 'STATUS_CODE'), " +
                        "COALESCE(json_extract(value, '$.method'), 'REGEX'), " +
                        "COALESCE(json_extract(value, '$.expression'), ''), " +
                        "COALESCE(json_extract(value, '$.negate'), 0), " +
                        "(rowid - 1), " +
                        "1 " +
                        "FROM json_each(?)";

                String insertSingleCondSql = "INSERT INTO judgment_rule_conditions " +
                        "(group_id, target, method, expression, negate, sort_order, enabled) " +
                        "VALUES (?, ?, ?, ?, 0, 0, 1)";

                try (ResultSet rs = stmt.executeQuery(
                        "SELECT id, name, target, method, expression, conditions_json, enabled, priority, " +
                        "success_color, failure_color, success_note, failure_note, remark, global " +
                        "FROM judgment_rules ORDER BY priority ASC, id ASC")) {

                    while (rs.next()) {
                        int newGroupId;
                        try (PreparedStatement ps = conn.prepareStatement(insertGroupSql, Statement.RETURN_GENERATED_KEYS)) {
                            ps.setString(1, nvl(rs.getString("name"), ""));
                            ps.setInt(2, firstGroup ? 1 : 0);
                            ps.setInt(3, rs.getInt("enabled"));
                            ps.setString(4, nvl(rs.getString("success_color"), "#FF0000"));
                            ps.setString(5, nvl(rs.getString("failure_color"), "#90EE90"));
                            ps.setString(6, nvl(rs.getString("success_note"), ""));
                            ps.setString(7, nvl(rs.getString("failure_note"), ""));
                            ps.setString(8, nvl(rs.getString("remark"), ""));
                            ps.setInt(9, rs.getInt("global"));
                            ps.executeUpdate();

                            try (ResultSet keys = ps.getGeneratedKeys()) {
                                newGroupId = keys.next() ? keys.getInt(1) : -1;
                            }
                        }

                        if (newGroupId <= 0) {
                            try (ResultSet lastId = stmt.executeQuery("SELECT last_insert_rowid()")) {
                                newGroupId = lastId.next() ? lastId.getInt(1) : -1;
                            }
                        }

                        if (newGroupId <= 0) {
                            LogManager.getInstance().printError("[!] 无法获取新插入规则组的ID，跳过条件迁移");
                            continue;
                        }

                        groupCount++;

                        String conditionsJson = rs.getString("conditions_json");
                        if (conditionsJson != null && !conditionsJson.isEmpty()) {
                            try {
                                try (PreparedStatement ps = conn.prepareStatement(insertCondFromJsonSql)) {
                                    ps.setInt(1, newGroupId);
                                    ps.setString(2, conditionsJson);
                                    int inserted = ps.executeUpdate();
                                    condCount += inserted;
                                }
                            } catch (SQLException e) {
                                LogManager.getInstance().printError(
                                    "[!] JSON条件迁移失败(group_id=" + newGroupId + "): " + e.getMessage() +
                                    ", 回退到单条件模式");
                                condCount += migrateLegacyCondition(conn, insertSingleCondSql, newGroupId, rs);
                            }
                        } else {
                            condCount += migrateLegacyCondition(conn, insertSingleCondSql, newGroupId, rs);
                        }

                        firstGroup = false;
                    }
                }

                LogManager.getInstance().printOutput(
                    "[+] v12→v13 数据迁移完成: " + groupCount + " 个规则组, " + condCount + " 条条件");

                stmt.execute("UPDATE schema_meta SET value = '13' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '13')");

                LogManager.getInstance().printOutput("[+] v12→v13 迁移完成");
            }
        }
    }

    // ==================== v13→v14 ====================

    /**
     * v13→v14 迁移：表重命名（token_locations→field_definitions, token_schemes→schemes 等）。
     * <p>
     * 注意：此迁移不执行实际 DDL，原因如下：
     * <ol>
     *   <li>SQLite 不支持 ALTER TABLE RENAME COLUMN（v14 之前的旧列名已废弃）</li>
     *   <li>实际部署中，v13 用户已通过 SchemaInitializer 重建数据库</li>
     *   <li>仅更新版本号以避免后续迁移被跳过</li>
     * </ol>
     */
    static class MigrateV13ToV14 implements MigrationStep {
        @Override public int fromVersion() { return 13; }
        @Override public int toVersion() { return 14; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v13→v14迁移...");

                stmt.execute("UPDATE schema_meta SET value = '14' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '14')");

                LogManager.getInstance().printOutput("[+] v13→v14 迁移完成");
            }
        }
    }

    // ==================== v14→v15 ====================

    static class MigrateV14ToV15 implements MigrationStep {
        @Override public int fromVersion() { return 14; }
        @Override public int toVersion() { return 15; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v14→v15迁移...");

                try {
                    stmt.execute("ALTER TABLE history ADD COLUMN baseline_response_data BLOB DEFAULT NULL");
                    LogManager.getInstance().printOutput("[+] history表添加baseline_response_data列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        throw e;
                    }
                    LogManager.getInstance().printOutput("[*] baseline_response_data列已存在，跳过");
                }

                stmt.execute("UPDATE schema_meta SET value = '15' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '15')");

                LogManager.getInstance().printOutput("[+] v14→v15 迁移完成");
            }
        }
    }

    // ==================== 共享工具方法 ====================

    /** null 安全替代 */
    static String nvl(String value, String defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * 从旧的 target/method/expression 字段迁移单条条件（使用预编译SQL）
     */
    static int migrateLegacyCondition(Connection conn, String insertSql, int groupId, ResultSet rs) throws SQLException {
        String target = nvl(rs.getString("target"), "STATUS_CODE");
        String method = nvl(rs.getString("method"), "REGEX");
        String expression = nvl(rs.getString("expression"), "");

        if (expression.isEmpty()) {
            return 0;
        }

        try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
            ps.setInt(1, groupId);
            ps.setString(2, target);
            ps.setString(3, method);
            ps.setString(4, expression);
            ps.executeUpdate();
        }
        return 1;
    }
}
