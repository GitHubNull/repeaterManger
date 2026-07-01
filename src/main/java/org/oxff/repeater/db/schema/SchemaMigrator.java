package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 数据库Schema迁移器
 * 负责处理数据库版本升级迁移逻辑
 */
public class SchemaMigrator {

    /** 当前支持的最高 Schema 版本 */
    public static final int LATEST_VERSION = 14;

    /**
     * 执行所有必要的数据库迁移
     */
    public static void migrateIfNeeded(Connection conn) throws SQLException {
        // 获取当前schema版本
        int currentVersion = getCurrentSchemaVersion(conn);

        // v2→v3 迁移
        if (currentVersion < 3) {
            migrateV2ToV3(conn);
        }

        // v3→v4 迁移
        if (currentVersion < 4) {
            migrateV3ToV4(conn);
        }

        // v4→v5 迁移
        if (currentVersion < 5) {
            migrateV4ToV5(conn);
        }

        // v5→v6 迁移
        if (currentVersion < 6) {
            migrateV5ToV6(conn);
        }

        // v6→v7 迁移
        if (currentVersion < 7) {
            migrateV6ToV7(conn);
        }

        // v7→v8 迁移
        if (currentVersion < 8) {
            migrateV7ToV8(conn);
        }

        // v8→v9 迁移
        if (currentVersion < 9) {
            migrateV8ToV9(conn);
        }

        // v9→v10 迁移
        if (currentVersion < 10) {
            migrateV9ToV10(conn);
        }

        // v10→v11 迁移
        if (currentVersion < 11) {
            migrateV10ToV11(conn);
        }

        // v11→v12 迁移：judgment_rules 新增 conditions_json 列，现有规则自动迁移
        if (currentVersion < 12) {
            migrateV11ToV12(conn);
        }

        // v12→v13 迁移：judgment_rules → judgment_rule_groups + judgment_rule_conditions 双表
        if (currentVersion < 13) {
            migrateV12ToV13(conn);
        }

        // v13→v14 迁移：token_locations→field_definitions, token_schemes→schemes 等表重命名
        if (currentVersion < 14) {
            migrateV13ToV14(conn);
        }
    }

    /**
     * 获取当前schema版本
     */
    public static int getCurrentSchemaVersion(Connection conn) {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT value FROM schema_meta WHERE key = 'schema_version'")) {
            if (rs.next()) {
                try {
                    return Integer.parseInt(rs.getString("value"));
                } catch (NumberFormatException e) {
                    // schema_meta 值损坏，假设已是当前最新版，跳过所有迁移
                    return LATEST_VERSION;
                }
            }
        } catch (SQLException e) {
            // schema_meta 表可能不存在（极旧版本），忽略
        }
        // schema_meta 缺失，假设已是当前最新版，避免重复执行 ALTER TABLE
        return LATEST_VERSION;
    }

    /**
     * v2→v3 迁移：为旧数据库添加 api_hash 列和 api_extraction_rules 表
     */
    private static void migrateV2ToV3(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v2→v3迁移...");

            // 为 requests 表添加 api_hash 列
            try {
                stmt.execute("ALTER TABLE requests ADD COLUMN api_hash TEXT");
                LogManager.getInstance().printOutput("[+] requests表添加api_hash列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] requests表添加api_hash列失败: " + e.getMessage());
                }
            }

            // 为 history 表添加 api_hash 列
            try {
                stmt.execute("ALTER TABLE history ADD COLUMN api_hash TEXT");
                LogManager.getInstance().printOutput("[+] history表添加api_hash列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] history表添加api_hash列失败: " + e.getMessage());
                }
            }

            // 创建 api_extraction_rules 表（v3结构，不含name/remark，v4迁移会添加）
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS api_extraction_rules (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "source TEXT NOT NULL, " +
                "method TEXT NOT NULL, " +
                "expression TEXT NOT NULL, " +
                "enabled INTEGER NOT NULL DEFAULT 1, " +
                "priority INTEGER NOT NULL DEFAULT 1, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // 创建v3新增索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_api_hash ON requests(api_hash)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_api_hash ON history(api_hash)");

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '3' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '3')");

            LogManager.getInstance().printOutput("[+] v2→v3 迁移完成");
        }
    }

    /**
     * v3→v4 迁移：为 api_extraction_rules 表添加 name 和 remark 列
     */
    private static void migrateV3ToV4(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v3→v4迁移...");

            // 为 api_extraction_rules 表添加 name 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''");
                LogManager.getInstance().printOutput("[+] api_extraction_rules表添加name列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] api_extraction_rules表添加name列失败: " + e.getMessage());
                }
            }

            // 为 api_extraction_rules 表添加 remark 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN remark TEXT NOT NULL DEFAULT ''");
                LogManager.getInstance().printOutput("[+] api_extraction_rules表添加remark列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] api_extraction_rules表添加remark列失败: " + e.getMessage());
                }
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '4' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '4')");

            LogManager.getInstance().printOutput("[+] v3→v4 迁移完成");
        }
    }

    /**
     * v4→v5 迁移：为 api_extraction_rules 表添加 global 列
     */
    private static void migrateV4ToV5(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v4→v5迁移...");

            // 为 api_extraction_rules 表添加 global 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN global INTEGER NOT NULL DEFAULT 1");
                LogManager.getInstance().printOutput("[+] api_extraction_rules表添加global列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] api_extraction_rules表添加global列失败: " + e.getMessage());
                }
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '5' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '5')");

            LogManager.getInstance().printOutput("[+] v4→v5 迁移完成");
        }
    }

    /**
     * v5→v6 迁移：新增权限测试相关表和history表扩展列
     */
    private static void migrateV5ToV6(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v5→v6迁移...");

            // 创建令牌位置表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS token_locations (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "type TEXT NOT NULL, " +
                "expression TEXT NOT NULL, " +
                "description TEXT DEFAULT '', " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // 创建用户会话表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS user_sessions (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL, " +
                "color TEXT, " +
                "enabled INTEGER NOT NULL DEFAULT 1, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // 创建令牌值关联表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS token_values (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "token_location_id INTEGER NOT NULL, " +
                "user_session_id INTEGER NOT NULL, " +
                "value TEXT NOT NULL, " +
                "FOREIGN KEY (token_location_id) REFERENCES token_locations(id) ON DELETE CASCADE, " +
                "FOREIGN KEY (user_session_id) REFERENCES user_sessions(id) ON DELETE CASCADE, " +
                "UNIQUE (token_location_id, user_session_id)" +
                ")"
            );

            // 创建判决规则表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS judgment_rules (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL DEFAULT '', " +
                "target TEXT NOT NULL, " +
                "method TEXT NOT NULL, " +
                "expression TEXT NOT NULL, " +
                "enabled INTEGER NOT NULL DEFAULT 1, " +
                "priority INTEGER NOT NULL DEFAULT 1, " +
                "success_color TEXT DEFAULT '#FF0000', " +
                "failure_color TEXT DEFAULT '#00FF00', " +
                "success_note TEXT DEFAULT '', " +
                "failure_note TEXT DEFAULT '', " +
                "remark TEXT DEFAULT '', " +
                "global INTEGER NOT NULL DEFAULT 1, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // history表新增3列
            try {
                stmt.execute("ALTER TABLE history ADD COLUMN user_session_name TEXT DEFAULT NULL");
                LogManager.getInstance().printOutput("[+] history表添加user_session_name列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] history表添加user_session_name列失败: " + e.getMessage());
                }
            }

            try {
                stmt.execute("ALTER TABLE history ADD COLUMN judgment TEXT DEFAULT NULL");
                LogManager.getInstance().printOutput("[+] history表添加judgment列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] history表添加judgment列失败: " + e.getMessage());
                }
            }

            try {
                stmt.execute("ALTER TABLE history ADD COLUMN similarity REAL DEFAULT -1");
                LogManager.getInstance().printOutput("[+] history表添加similarity列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] history表添加similarity列失败: " + e.getMessage());
                }
            }

            // 创建v6新增索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_token_values_location ON token_values(token_location_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_token_values_session ON token_values(user_session_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_judgment ON history(judgment)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_session ON history(user_session_name)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_judgment_rules_enabled ON judgment_rules(enabled, priority)");

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '6' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '6')");

            LogManager.getInstance().printOutput("[+] v5→v6 迁移完成");
        }
    }

    /**
     * v6→v7 迁移：新增 scope_entries 表
     */
    private static void migrateV6ToV7(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v6→v7迁移...");

            // 创建Scope条目表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS scope_entries (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL DEFAULT '', " +
                "url_pattern TEXT NOT NULL, " +
                "enabled INTEGER NOT NULL DEFAULT 1, " +
                "description TEXT DEFAULT '', " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // 创建索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scope_entries_enabled ON scope_entries(enabled)");

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '7' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '7')");

            LogManager.getInstance().printOutput("[+] v6→v7 迁移完成");
        }
    }

    /**
     * v7→v8 迁移：为 requests 表添加 is_privilege_test 列
     */
    private static void migrateV7ToV8(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v7→v8迁移...");

            // 为 requests 表添加 is_privilege_test 列
            try {
                stmt.execute("ALTER TABLE requests ADD COLUMN is_privilege_test INTEGER NOT NULL DEFAULT 0");
                LogManager.getInstance().printOutput("[+] requests表添加is_privilege_test列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] requests表添加is_privilege_test列失败: " + e.getMessage());
                }
            }

            // 回填：将已有越权测试历史记录对应的请求标记为越权测试
            try {
                int updated = stmt.executeUpdate(
                    "UPDATE requests SET is_privilege_test = 1 " +
                    "WHERE id IN (" +
                    "  SELECT DISTINCT request_id FROM history " +
                    "  WHERE user_session_name IS NOT NULL AND request_id > 0" +
                    ")"
                );
                LogManager.getInstance().printOutput("[+] 回填is_privilege_test完成，更新 " + updated + " 条记录");
            } catch (SQLException e) {
                LogManager.getInstance().printError("[!] 回填is_privilege_test失败: " + e.getMessage());
            }

            // 创建索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_is_privilege_test ON requests(is_privilege_test)");

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '8' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '8')");

            LogManager.getInstance().printOutput("[+] v7→v8 迁移完成");
        }
    }

    /**
     * v8→v9 迁移：为 token_locations 表添加 persist_to_global 和 enabled 列
     */
    private static void migrateV8ToV9(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v8→v9迁移...");

            // 为 token_locations 表添加 persist_to_global 列
            try {
                stmt.execute("ALTER TABLE token_locations ADD COLUMN persist_to_global INTEGER NOT NULL DEFAULT 1");
                LogManager.getInstance().printOutput("[+] token_locations表添加persist_to_global列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] token_locations表添加persist_to_global列失败: " + e.getMessage());
                }
            }

            // 为 token_locations 表添加 enabled 列
            try {
                stmt.execute("ALTER TABLE token_locations ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1");
                LogManager.getInstance().printOutput("[+] token_locations表添加enabled列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] token_locations表添加enabled列失败: " + e.getMessage());
                }
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '9' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '9')");

            LogManager.getInstance().printOutput("[+] v8→v9 迁移完成");
        }
    }

    /**
     * v9→v10 迁移：为 requests 表添加原始响应字段
     * 用于存储"发送到权限测试"时的原始基线响应报文
     */
    private static void migrateV9ToV10(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v9→v10迁移...");

            // 为 requests 表添加响应相关列
            String[] columns = {
                "ALTER TABLE requests ADD COLUMN resp_header_hash TEXT",
                "ALTER TABLE requests ADD COLUMN resp_body_hash TEXT",
                "ALTER TABLE requests ADD COLUMN resp_body_storage TEXT DEFAULT 'none'",
                "ALTER TABLE requests ADD COLUMN resp_status_code INTEGER DEFAULT 0",
                "ALTER TABLE requests ADD COLUMN resp_length INTEGER DEFAULT 0",
                "ALTER TABLE requests ADD COLUMN resp_time INTEGER DEFAULT 0"
            };

            for (String ddl : columns) {
                try {
                    stmt.execute(ddl);
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] v9→v10迁移列添加失败: " + e.getMessage());
                    }
                }
            }

            LogManager.getInstance().printOutput("[+] requests表添加响应字段成功");

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '10' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '10')");

            LogManager.getInstance().printOutput("[+] v9→v10 迁移完成");
        }
    }

    /**
     * v10→v11 迁移：新增令牌方案表、方案-令牌位置关联表，
     * 为 user_sessions 添加 scheme_id 和重放配置列，
     * 自动迁移旧数据（创建默认方案，关联所有现有令牌位置和用户会话）
     */
    private static void migrateV10ToV11(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v10→v11迁移...");

            // 创建令牌方案表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS token_schemes (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL, " +
                "description TEXT DEFAULT '', " +
                "persist_to_global INTEGER NOT NULL DEFAULT 1, " +
                "enabled INTEGER NOT NULL DEFAULT 1, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")"
            );

            // 创建方案-令牌位置关联表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS scheme_token_locations (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "scheme_id INTEGER NOT NULL, " +
                "token_location_id INTEGER NOT NULL, " +
                "FOREIGN KEY (scheme_id) REFERENCES token_schemes(id) ON DELETE CASCADE, " +
                "FOREIGN KEY (token_location_id) REFERENCES token_locations(id) ON DELETE CASCADE, " +
                "UNIQUE (scheme_id, token_location_id)" +
                ")"
            );

            // 为 user_sessions 添加 scheme_id 列
            try {
                stmt.execute("ALTER TABLE user_sessions ADD COLUMN scheme_id INTEGER DEFAULT NULL");
                LogManager.getInstance().printOutput("[+] user_sessions表添加scheme_id列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] user_sessions表添加scheme_id列失败: " + e.getMessage());
                }
            }

            // 为 user_sessions 添加重放配置列
            String[] replayColumns = {
                "ALTER TABLE user_sessions ADD COLUMN request_timeout INTEGER DEFAULT 30",
                "ALTER TABLE user_sessions ADD COLUMN max_concurrent INTEGER DEFAULT 1",
                "ALTER TABLE user_sessions ADD COLUMN retry_count INTEGER DEFAULT 0",
                "ALTER TABLE user_sessions ADD COLUMN retry_delay INTEGER DEFAULT 1000",
                "ALTER TABLE user_sessions ADD COLUMN replay_delay INTEGER DEFAULT 0"
            };

            for (String ddl : replayColumns) {
                try {
                    stmt.execute(ddl);
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] v10→v11迁移列添加失败: " + e.getMessage());
                    }
                }
            }
            LogManager.getInstance().printOutput("[+] user_sessions表添加重放配置列成功");

            // 创建v11新增索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_token_locations_scheme ON scheme_token_locations(scheme_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_token_locations_location ON scheme_token_locations(token_location_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_scheme ON user_sessions(scheme_id)");

            // 自动迁移：创建默认方案，关联所有现有令牌位置
            try {
                // 创建默认方案
                stmt.execute("INSERT INTO token_schemes (name, description, persist_to_global, enabled) VALUES ('默认方案', '自动创建的默认令牌方案，包含所有令牌位置', 1, 1)");
                try (ResultSet rs = stmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int defaultSchemeId = rs.getInt(1);

                        // 将所有现有令牌位置关联到默认方案
                        int linkedLocations = stmt.executeUpdate(
                            "INSERT INTO scheme_token_locations (scheme_id, token_location_id) " +
                            "SELECT " + defaultSchemeId + ", id FROM token_locations"
                        );
                        LogManager.getInstance().printOutput("[+] 默认方案创建成功(id=" + defaultSchemeId + ")，关联 " + linkedLocations + " 个令牌位置");

                        // 将所有现有用户会话关联到默认方案
                        int linkedSessions = stmt.executeUpdate(
                            "UPDATE user_sessions SET scheme_id = " + defaultSchemeId + " WHERE scheme_id IS NULL"
                        );
                        LogManager.getInstance().printOutput("[+] " + linkedSessions + " 个用户会话已关联到默认方案");
                    }
                }
            } catch (SQLException e) {
                LogManager.getInstance().printError("[!] 自动迁移创建默认方案失败: " + e.getMessage());
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '11' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '11')");

            LogManager.getInstance().printOutput("[+] v10→v11 迁移完成");
        }
    }

    /**
     * v11→v12 迁移：judgment_rules 新增 conditions_json 列
     * 将现有单条件规则的 target+method+expression 自动包装为 conditions JSON
     */
    private static void migrateV11ToV12(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v11→v12迁移...");

            // 添加 conditions_json 列
            try {
                stmt.execute("ALTER TABLE judgment_rules ADD COLUMN conditions_json TEXT DEFAULT NULL");
                LogManager.getInstance().printOutput("[+] judgment_rules表添加conditions_json列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    LogManager.getInstance().printError("[!] judgment_rules表添加conditions_json列失败: " + e.getMessage());
                }
            }

            // 将现有单条件规则迁移为 conditions JSON
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
                // 失败的规则将在 DAO 层通过 getEffectiveConditions() 自动包装，不影响使用
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '12' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '12')");

            LogManager.getInstance().printOutput("[+] v11→v12 迁移完成");
        }
    }

    /**
     * v12→v13 迁移：从旧 judgment_rules 单表迁移到 judgment_rule_groups + judgment_rule_conditions 双表
     * <p>
     * 迁移策略：
     * 1. 创建新表 judgment_rule_groups 和 judgment_rule_conditions
     * 2. 将旧 judgment_rules 每条记录转为：1个 group + N个 conditions
     * 3. 条件来源优先 conditions_json，回退到 target/method/expression 单条件包装
     * 4. 第一条迁移的规则组设为 is_active=1
     * 5. 保留旧表不删除，确保可回滚
     */
    private static void migrateV12ToV13(Connection conn) throws SQLException {
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

            // 创建新索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_rule_groups_active ON judgment_rule_groups(is_active)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_conditions_group ON judgment_rule_conditions(group_id, sort_order)");

            LogManager.getInstance().printOutput("[+] v13 新表创建成功");

            // 2. 迁移数据：读取旧 judgment_rules 表
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

            // 3. 遍历旧规则，逐条迁移（使用 PreparedStatement 避免字符串拼接风险）
            int groupCount = 0;
            int condCount = 0;
            boolean firstGroup = true;

            // 预编译规则组插入语句
            String insertGroupSql = "INSERT INTO judgment_rule_groups " +
                    "(name, is_active, enabled, success_color, failure_color, " +
                    "success_note, failure_note, remark, global) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

            // 预编译条件插入语句（json_each 展开）
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

            // 预编译单条件插入语句
            String insertSingleCondSql = "INSERT INTO judgment_rule_conditions " +
                    "(group_id, target, method, expression, negate, sort_order, enabled) " +
                    "VALUES (?, ?, ?, ?, 0, 0, 1)";

            try (ResultSet rs = stmt.executeQuery(
                    "SELECT id, name, target, method, expression, conditions_json, enabled, priority, " +
                    "success_color, failure_color, success_note, failure_note, remark, global " +
                    "FROM judgment_rules ORDER BY priority ASC, id ASC")) {

                while (rs.next()) {
                    // 插入规则组（PreparedStatement）
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
                        // 回退：用 last_insert_rowid
                        try (ResultSet lastId = stmt.executeQuery("SELECT last_insert_rowid()")) {
                            newGroupId = lastId.next() ? lastId.getInt(1) : -1;
                        }
                    }

                    if (newGroupId <= 0) {
                        LogManager.getInstance().printError("[!] 无法获取新插入规则组的ID，跳过条件迁移");
                        continue;
                    }

                    groupCount++;

                    // 迁移条件：优先 conditions_json
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
                            // JSON 解析失败，回退到单条件模式
                            LogManager.getInstance().printError(
                                "[!] JSON条件迁移失败(group_id=" + newGroupId + "): " + e.getMessage() +
                                ", 回退到单条件模式");
                            condCount += migrateLegacyCondition(conn, insertSingleCondSql, newGroupId, rs);
                        }
                    } else {
                        // 无 conditions_json，从 target/method/expression 创建单条件
                        condCount += migrateLegacyCondition(conn, insertSingleCondSql, newGroupId, rs);
                    }

                    firstGroup = false;
                }
            }

            LogManager.getInstance().printOutput(
                "[+] v12→v13 数据迁移完成: " + groupCount + " 个规则组, " + condCount + " 条条件");

            // 4. 更新 schema 版本
            stmt.execute("UPDATE schema_meta SET value = '13' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '13')");

            LogManager.getInstance().printOutput("[+] v12→v13 迁移完成");
        }
    }

    /**
     * 从旧的 target/method/expression 字段迁移单条条件（使用预编译SQL）
     */
    private static int migrateLegacyCondition(Connection conn, String insertSql, int groupId, ResultSet rs) throws SQLException {
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

    /**
     * v13→v14 迁移：token_locations→field_definitions, token_schemes→schemes 等表重命名
     * <p>
     * 当前版本假定所有表已按新结构存在，仅更新 schema 版本号。
     */
    private static void migrateV13ToV14(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            LogManager.getInstance().printOutput("[*] 开始v13→v14迁移...");

            // 更新 schema 版本
            stmt.execute("UPDATE schema_meta SET value = '14' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '14')");

            LogManager.getInstance().printOutput("[+] v13→v14 迁移完成");
        }
    }

    /** null 安全替代 */
    private static String nvl(String value, String defaultValue) {
        return value != null ? value : defaultValue;
    }
}
