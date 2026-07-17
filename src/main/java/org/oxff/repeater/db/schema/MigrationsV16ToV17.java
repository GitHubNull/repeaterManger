package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v16→v17 Schema 迁移步骤。
 * 新增 test_info_config 和 test_info_screenshots 两张表。
 */
public final class MigrationsV16ToV17 {

    private MigrationsV16ToV17() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV16ToV17());
        return steps;
    }

    static class MigrateV16ToV17 implements MigrationStep {
        @Override public int fromVersion() { return 16; }
        @Override public int toVersion() { return 17; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v16→v17迁移（测试信息配置表）...");

                // 测试信息配置主表
                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS test_info_config (" +
                    "id INTEGER PRIMARY KEY, " +
                    "target_name TEXT DEFAULT '', " +
                    "target_entry TEXT DEFAULT '', " +
                    "test_time_range TEXT DEFAULT '', " +
                    "test_personnel TEXT DEFAULT '', " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
                );

                // 测试信息截图表
                stmt.execute(
                    "CREATE TABLE IF NOT EXISTS test_info_screenshots (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "config_id INTEGER NOT NULL, " +
                    "file_path TEXT NOT NULL, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (config_id) REFERENCES test_info_config(id) ON DELETE CASCADE" +
                    ")"
                );

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_test_info_shots_config ON test_info_screenshots(config_id)");

                stmt.execute("UPDATE schema_meta SET value = '" + SchemaMigrator.LATEST_VERSION + "' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '" + SchemaMigrator.LATEST_VERSION + "')");

                LogManager.getInstance().printOutput("[+] v16→v17 迁移完成");
            }
        }
    }
}
