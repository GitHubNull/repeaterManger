package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v7→v11 Schema 迁移步骤集合。
 * <p>
 * 类名 {@code MigrationsV7ToV11} 表示目标版本范围（从 v7 迁移到 v11），
 * 内部第一个迁移步骤的起始版本为 v6（即 v6→v7），这是因为每个 MigrationStep
 * 的 fromVersion 指向迁移前的版本。
 * 包含5个迁移：v6→v7, v7→v8, v8→v9, v9→v10, v10→v11
 */
public final class MigrationsV7ToV11 {

    private MigrationsV7ToV11() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV6ToV7());
        steps.add(new MigrateV7ToV8());
        steps.add(new MigrateV8ToV9());
        steps.add(new MigrateV9ToV10());
        steps.add(new MigrateV10ToV11());
        return steps;
    }

    // ==================== v6→v7 ====================

    static class MigrateV6ToV7 implements MigrationStep {
        @Override public int fromVersion() { return 6; }
        @Override public int toVersion() { return 7; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v6→v7迁移...");

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

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_scope_entries_enabled ON scope_entries(enabled)");

                stmt.execute("UPDATE schema_meta SET value = '7' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '7')");

                LogManager.getInstance().printOutput("[+] v6→v7 迁移完成");
            }
        }
    }

    // ==================== v7→v8 ====================

    static class MigrateV7ToV8 implements MigrationStep {
        @Override public int fromVersion() { return 7; }
        @Override public int toVersion() { return 8; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v7→v8迁移...");

                try {
                    stmt.execute("ALTER TABLE requests ADD COLUMN is_privilege_test INTEGER NOT NULL DEFAULT 0");
                    LogManager.getInstance().printOutput("[+] requests表添加is_privilege_test列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] requests表添加is_privilege_test列失败: " + e.getMessage());
                    }
                }

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

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_is_privilege_test ON requests(is_privilege_test)");

                stmt.execute("UPDATE schema_meta SET value = '8' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '8')");

                LogManager.getInstance().printOutput("[+] v7→v8 迁移完成");
            }
        }
    }

    // ==================== v8→v9 ====================

    static class MigrateV8ToV9 implements MigrationStep {
        @Override public int fromVersion() { return 8; }
        @Override public int toVersion() { return 9; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v8→v9迁移...");

                try {
                    stmt.execute("ALTER TABLE token_locations ADD COLUMN persist_to_global INTEGER NOT NULL DEFAULT 1");
                    LogManager.getInstance().printOutput("[+] token_locations表添加persist_to_global列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] token_locations表添加persist_to_global列失败: " + e.getMessage());
                    }
                }

                try {
                    stmt.execute("ALTER TABLE token_locations ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1");
                    LogManager.getInstance().printOutput("[+] token_locations表添加enabled列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] token_locations表添加enabled列失败: " + e.getMessage());
                    }
                }

                stmt.execute("UPDATE schema_meta SET value = '9' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '9')");

                LogManager.getInstance().printOutput("[+] v8→v9 迁移完成");
            }
        }
    }

    // ==================== v9→v10 ====================

    static class MigrateV9ToV10 implements MigrationStep {
        @Override public int fromVersion() { return 9; }
        @Override public int toVersion() { return 10; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v9→v10迁移...");

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

                stmt.execute("UPDATE schema_meta SET value = '10' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '10')");

                LogManager.getInstance().printOutput("[+] v9→v10 迁移完成");
            }
        }
    }

    // ==================== v10→v11 ====================

    static class MigrateV10ToV11 implements MigrationStep {
        @Override public int fromVersion() { return 10; }
        @Override public int toVersion() { return 11; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v10→v11迁移...");

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

                try {
                    stmt.execute("ALTER TABLE user_sessions ADD COLUMN scheme_id INTEGER DEFAULT NULL");
                    LogManager.getInstance().printOutput("[+] user_sessions表添加scheme_id列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] user_sessions表添加scheme_id列失败: " + e.getMessage());
                    }
                }

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

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_token_locations_scheme ON scheme_token_locations(scheme_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_token_locations_location ON scheme_token_locations(token_location_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_scheme ON user_sessions(scheme_id)");

                try {
                    stmt.execute("INSERT INTO token_schemes (name, description, persist_to_global, enabled) VALUES ('默认方案', '自动创建的默认令牌方案，包含所有令牌位置', 1, 1)");
                    try (ResultSet rs = stmt.getGeneratedKeys()) {
                        if (rs.next()) {
                            int defaultSchemeId = rs.getInt(1);
                            int linkedLocations = stmt.executeUpdate(
                                "INSERT INTO scheme_token_locations (scheme_id, token_location_id) " +
                                "SELECT " + defaultSchemeId + ", id FROM token_locations"
                            );
                            LogManager.getInstance().printOutput("[+] 默认方案创建成功(id=" + defaultSchemeId + ")，关联 " + linkedLocations + " 个令牌位置");

                            int linkedSessions = stmt.executeUpdate(
                                "UPDATE user_sessions SET scheme_id = " + defaultSchemeId + " WHERE scheme_id IS NULL"
                            );
                            LogManager.getInstance().printOutput("[+] " + linkedSessions + " 个用户会话已关联到默认方案");
                        }
                    }
                } catch (SQLException e) {
                    LogManager.getInstance().printError("[!] 自动迁移创建默认方案失败: " + e.getMessage());
                }

                stmt.execute("UPDATE schema_meta SET value = '11' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '11')");

                LogManager.getInstance().printOutput("[+] v10→v11 迁移完成");
            }
        }
    }
}
