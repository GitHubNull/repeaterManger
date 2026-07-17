package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;

/**
 * v15→v16 Schema 迁移步骤。
 * 新增 user_info 和 user_info_screenshots 两张表。
 */
public final class MigrationsV15ToV16 {

    private MigrationsV15ToV16() {}

    public static List<MigrationStep> getSteps() {
        return Collections.singletonList(new MigrateV15ToV16());
    }

    static class MigrateV15ToV16 implements MigrationStep {
        @Override public int fromVersion() { return 15; }
        @Override public int toVersion() { return 16; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v15→v16迁移（用户信息表）...");

                // 用户信息表
                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS user_info (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "session_id INTEGER NOT NULL UNIQUE, " +
                    "role TEXT DEFAULT '', " +
                    "username TEXT DEFAULT '', " +
                    "is_anonymous INTEGER NOT NULL DEFAULT 0, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (session_id) REFERENCES user_sessions(id) ON DELETE CASCADE" +
                    ")"
                );

                // 用户信息截图表
                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS user_info_screenshots (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "user_info_id INTEGER NOT NULL, " +
                    "file_path TEXT NOT NULL, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (user_info_id) REFERENCES user_info(id) ON DELETE CASCADE" +
                    ")"
                );

                stmt.execute("UPDATE schema_meta SET value = '16' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '16')");

                LogManager.getInstance().printOutput("[+] v15→v16 迁移完成");
            }
        }
    }
}
