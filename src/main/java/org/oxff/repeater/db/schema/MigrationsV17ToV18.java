package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v17→v18 Schema 迁移步骤。
 * 为 test_info_config 表新增 report_title、use_default_title、report_subtitle 列。
 */
public final class MigrationsV17ToV18 {

    private MigrationsV17ToV18() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV17ToV18());
        return steps;
    }

    static class MigrateV17ToV18 implements MigrationStep {
        @Override public int fromVersion() { return 17; }
        @Override public int toVersion() { return 18; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v17→v18迁移（报告标题/副标题字段）...");

                stmt.execute("ALTER TABLE test_info_config ADD COLUMN report_title TEXT DEFAULT ''");
                stmt.execute("ALTER TABLE test_info_config ADD COLUMN use_default_title INTEGER DEFAULT 1");
                stmt.execute("ALTER TABLE test_info_config ADD COLUMN report_subtitle TEXT DEFAULT ''");

                stmt.execute("UPDATE schema_meta SET value = '" + SchemaMigrator.LATEST_VERSION + "' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '" + SchemaMigrator.LATEST_VERSION + "')");

                LogManager.getInstance().printOutput("[+] v17→v18 迁移完成");
            }
        }
    }
}
