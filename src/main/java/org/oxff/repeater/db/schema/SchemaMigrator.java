package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据库Schema迁移器 — 纯编排器。
 * 各版本迁移步骤已拆分为独立类：
 * <ul>
 *   <li>{@link MigrationsV2ToV6} — v2→v3, v3→v4, v4→v5, v5→v6</li>
 *   <li>{@link MigrationsV7ToV11} — v6→v7, v7→v8, v8→v9, v9→v10, v10→v11</li>
 *   <li>{@link MigrationsV12ToV15} — v11→v12, v12→v13, v13→v14, v14→v15</li>
 *   <li>{@link MigrationsV15ToV16} — v15→v16</li>
 *   <li>{@link MigrationsV16ToV17} — v16→v17</li>
 * </ul>
 */
public class SchemaMigrator {

    /** 当前支持的最高 Schema 版本 */
    public static final int LATEST_VERSION = 17;

    /**
     * 执行所有必要的数据库迁移
     */
    public static void migrateIfNeeded(Connection conn) throws SQLException {
        int currentVersion = getCurrentSchemaVersion(conn);

        List<MigrationStep> allSteps = new ArrayList<>();
        allSteps.addAll(MigrationsV2ToV6.getSteps());
        allSteps.addAll(MigrationsV7ToV11.getSteps());
        allSteps.addAll(MigrationsV12ToV15.getSteps());
        allSteps.addAll(MigrationsV15ToV16.getSteps());
        allSteps.addAll(MigrationsV16ToV17.getSteps());

        for (MigrationStep step : allSteps) {
            if (currentVersion < step.toVersion()) {
                try {
                    step.migrate(conn);
                } catch (SQLException e) {
                    LogManager.getInstance().printError(
                        "[!] 迁移 v" + step.fromVersion() + "→v" + step.toVersion()
                        + " 失败: " + e.getMessage());
                    // 不中断循环，尝试继续后续迁移
                }
            }
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
                    LogManager.getInstance().printError("[!] schema_meta值损坏，假设为最新版本");
                    return LATEST_VERSION;
                }
            }
        } catch (SQLException e) {
            // schema_meta 表可能不存在（极旧版本），忽略
        }
        // schema_meta 缺失，假设已是当前最新版，避免重复执行 ALTER TABLE
        return LATEST_VERSION;
    }
}
