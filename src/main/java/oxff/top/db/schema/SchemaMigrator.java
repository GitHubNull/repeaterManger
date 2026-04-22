package oxff.top.db.schema;

import burp.BurpExtender;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 数据库Schema迁移器
 * 负责处理数据库版本升级迁移逻辑
 */
public class SchemaMigrator {

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
                    return 2;
                }
            }
        } catch (SQLException e) {
            // schema_meta 表可能不存在（极旧版本），忽略
        }
        return 2;
    }

    /**
     * v2→v3 迁移：为旧数据库添加 api_hash 列和 api_extraction_rules 表
     */
    private static void migrateV2ToV3(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            BurpExtender.printOutput("[*] 开始v2→v3迁移...");

            // 为 requests 表添加 api_hash 列
            try {
                stmt.execute("ALTER TABLE requests ADD COLUMN api_hash TEXT");
                BurpExtender.printOutput("[+] requests表添加api_hash列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    BurpExtender.printError("[!] requests表添加api_hash列失败: " + e.getMessage());
                }
            }

            // 为 history 表添加 api_hash 列
            try {
                stmt.execute("ALTER TABLE history ADD COLUMN api_hash TEXT");
                BurpExtender.printOutput("[+] history表添加api_hash列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    BurpExtender.printError("[!] history表添加api_hash列失败: " + e.getMessage());
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

            BurpExtender.printOutput("[+] v2→v3 迁移完成");
        }
    }

    /**
     * v3→v4 迁移：为 api_extraction_rules 表添加 name 和 remark 列
     */
    private static void migrateV3ToV4(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            BurpExtender.printOutput("[*] 开始v3→v4迁移...");

            // 为 api_extraction_rules 表添加 name 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''");
                BurpExtender.printOutput("[+] api_extraction_rules表添加name列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    BurpExtender.printError("[!] api_extraction_rules表添加name列失败: " + e.getMessage());
                }
            }

            // 为 api_extraction_rules 表添加 remark 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN remark TEXT NOT NULL DEFAULT ''");
                BurpExtender.printOutput("[+] api_extraction_rules表添加remark列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    BurpExtender.printError("[!] api_extraction_rules表添加remark列失败: " + e.getMessage());
                }
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '4' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '4')");

            BurpExtender.printOutput("[+] v3→v4 迁移完成");
        }
    }

    /**
     * v4→v5 迁移：为 api_extraction_rules 表添加 global 列
     */
    private static void migrateV4ToV5(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            BurpExtender.printOutput("[*] 开始v4→v5迁移...");

            // 为 api_extraction_rules 表添加 global 列
            try {
                stmt.execute("ALTER TABLE api_extraction_rules ADD COLUMN global INTEGER NOT NULL DEFAULT 1");
                BurpExtender.printOutput("[+] api_extraction_rules表添加global列成功");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    BurpExtender.printError("[!] api_extraction_rules表添加global列失败: " + e.getMessage());
                }
            }

            // 更新schema版本
            stmt.execute("UPDATE schema_meta SET value = '5' WHERE key = 'schema_version'");
            stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '5')");

            BurpExtender.printOutput("[+] v4→v5 迁移完成");
        }
    }
}
