package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * v18→v19 Schema 迁移步骤。
 * 为 judgment_rule_conditions 表新增 operator 列，支持 AND/OR 逻辑运算符持久化。
 */
public final class MigrationsV18ToV19 {

    private MigrationsV18ToV19() {}

    public static List<MigrationStep> getSteps() {
        List<MigrationStep> steps = new ArrayList<>();
        steps.add(new MigrateV18ToV19());
        return steps;
    }

    static class MigrateV18ToV19 implements MigrationStep {
        @Override public int fromVersion() { return 18; }
        @Override public int toVersion() { return 19; }
        @Override
        public void migrate(Connection conn) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                LogManager.getInstance().printOutput("[*] 开始v18→v19迁移（judgment_rule_conditions添加operator列）...");

                try {
                    stmt.execute("ALTER TABLE judgment_rule_conditions ADD COLUMN operator TEXT NOT NULL DEFAULT 'AND'");
                    LogManager.getInstance().printOutput("[+] judgment_rule_conditions表添加operator列成功");
                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate column name")) {
                        throw e;
                    }
                    LogManager.getInstance().printOutput("[*] operator列已存在，跳过");
                }

                stmt.execute("UPDATE schema_meta SET value = '" + SchemaMigrator.LATEST_VERSION + "' WHERE key = 'schema_version'");
                stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '" + SchemaMigrator.LATEST_VERSION + "')");

                LogManager.getInstance().printOutput("[+] v18→v19 迁移完成");
            }
        }
    }
}
