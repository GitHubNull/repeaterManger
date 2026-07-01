package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v2→v6 Schema 迁移步骤集合。
 * 包含4个迁移：v2→v3, v3→v4, v4→v5, v5→v6
 */
public final class MigrationsV2ToV6 {

    private MigrationsV2ToV6() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV2ToV3());
        steps.add(new MigrateV3ToV4());
        steps.add(new MigrateV4ToV5());
        steps.add(new MigrateV5ToV6());
        return steps;
    }

    // ==================== v2→v3 ====================

    static class MigrateV2ToV3 implements MigrationStep {
        @Override public int fromVersion() { return 2; }
        @Override public int toVersion() { return 3; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v2→v3迁移...");

                try {
                    stmt.execute("ALTER TABLE requests ADD COLUMN api_hash TEXT");
                    LogManager.getInstance().printOutput("[+] requests表添加api_hash列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] requests表添加api_hash列失败: " + e.getMessage());
                    }
                }

                try {
                    stmt.execute("ALTER TABLE history ADD COLUMN api_hash TEXT");
                    LogManager.getInstance().printOutput("[+] history表添加api_hash列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] history表添加api_hash列失败: " + e.getMessage());
                    }
                }

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

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_api_hash ON requests(api_hash)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_api_hash ON history(api_hash)");

                stmt.execute("UPDATE schema_meta SET value = '3' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '3')");

                LogManager.getInstance().printOutput("[+] v2→v3 迁移完成");
            }
        }
    }

    // ==================== v3→v4 ====================

    static class MigrateV3ToV4 implements MigrationStep {
        @Override public int fromVersion() { return 3; }
        @Override public int toVersion() { return 4; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v3→v4迁移...");

                try {
                    stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''");
                    LogManager.getInstance().printOutput("[+] api_extraction_rules表添加name列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] api_extraction_rules表添加name列失败: " + e.getMessage());
                    }
                }

                try {
                    stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN remark TEXT NOT NULL DEFAULT ''");
                    LogManager.getInstance().printOutput("[+] api_extraction_rules表添加remark列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] api_extraction_rules表添加remark列失败: " + e.getMessage());
                    }
                }

                stmt.execute("UPDATE schema_meta SET value = '4' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '4')");

                LogManager.getInstance().printOutput("[+] v3→v4 迁移完成");
            }
        }
    }

    // ==================== v4→v5 ====================

    static class MigrateV4ToV5 implements MigrationStep {
        @Override public int fromVersion() { return 4; }
        @Override public int toVersion() { return 5; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v4→v5迁移...");

                try {
                    stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN global INTEGER NOT NULL DEFAULT 1");
                    LogManager.getInstance().printOutput("[+] api_extraction_rules表添加global列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        LogManager.getInstance().printError("[!] api_extraction_rules表添加global列失败: " + e.getMessage());
                    }
                }

                stmt.execute("UPDATE schema_meta SET value = '5' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '5')");

                LogManager.getInstance().printOutput("[+] v4→v5 迁移完成");
            }
        }
    }

    // ==================== v5→v6 ====================

    static class MigrateV5ToV6 implements MigrationStep {
        @Override public int fromVersion() { return 5; }
        @Override public int toVersion() { return 6; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v5→v6迁移...");

                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS token_locations (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "type TEXT NOT NULL, " +
                    "expression TEXT NOT NULL, " +
                    "description TEXT DEFAULT '', " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
                );

                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS user_sessions (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "name TEXT NOT NULL, " +
                    "color TEXT, " +
                    "enabled INTEGER NOT NULL DEFAULT 1, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
                );

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

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_token_values_location ON token_values(token_location_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_token_values_session ON token_values(user_session_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_judgment ON history(judgment)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_session ON history(user_session_name)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_judgment_rules_enabled ON judgment_rules(enabled, priority)");

                stmt.execute("UPDATE schema_meta SET value = '6' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '6')");

                LogManager.getInstance().printOutput("[+] v5→v6 迁移完成");
            }
        }
    }
}
