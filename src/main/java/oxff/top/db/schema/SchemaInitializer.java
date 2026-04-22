package oxff.top.db.schema;

import burp.BurpExtender;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 数据库Schema初始化器
 * 负责创建新数据库的所有表结构和索引
 */
public class SchemaInitializer {

    /**
     * 使用现有连接初始化表结构
     * 直接确保 v3 Schema 完整存在，并执行必要的迁移
     */
    public static void initializeTablesWithConnection(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            initializeV3Schema(stmt);
            // 检查是否需要从旧版本迁移
            SchemaMigrator.migrateIfNeeded(conn);
            BurpExtender.printOutput("[+] 数据库表结构初始化成功");
        }
    }

    /**
     * 初始化 v3 Schema（新数据库）
     * 包含 v2 基础结构 + v3 新增的 api_hash 列和规则表
     */
    private static void initializeV3Schema(Statement stmt) throws SQLException {
        // 元数据表
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS schema_meta (" +
            "key TEXT PRIMARY KEY, " +
            "value TEXT NOT NULL" +
            ")"
        );

        // 初始化元数据（v5）
        stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '5')");
        stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('clean_shutdown', '1')");

        // 创建池表
        createPoolTables(stmt);

        // GC 队列表
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS gc_queue (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "pool_type TEXT NOT NULL, " +
            "hash TEXT NOT NULL, " +
            "enqueued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_gc_queue_pool ON gc_queue(pool_type, hash)");

        // 请求表（v3 结构：v2 + api_hash）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS requests (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "protocol INTEGER NOT NULL DEFAULT 0, " +
            "domain_hash TEXT, " +
            "path_hash TEXT, " +
            "query_hash TEXT, " +
            "method INTEGER NOT NULL DEFAULT 0, " +
            "add_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "comment TEXT, " +
            "color TEXT, " +
            "req_header_hash TEXT, " +
            "req_body_hash TEXT, " +
            "req_body_storage TEXT DEFAULT 'inline', " +
            "api_hash TEXT" +
            ")"
        );

        // 历史记录表（v3 结构：v2 + api_hash）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS history (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "request_id INTEGER, " +
            "method INTEGER NOT NULL DEFAULT 0, " +
            "protocol INTEGER NOT NULL DEFAULT 0, " +
            "domain_hash TEXT, " +
            "path_hash TEXT, " +
            "query_hash TEXT, " +
            "status_code INTEGER, " +
            "response_length INTEGER, " +
            "response_time INTEGER, " +
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "comment TEXT, " +
            "color TEXT, " +
            "req_header_hash TEXT, " +
            "req_body_hash TEXT, " +
            "req_body_storage TEXT DEFAULT 'inline', " +
            "resp_header_hash TEXT, " +
            "resp_body_hash TEXT, " +
            "resp_body_storage TEXT DEFAULT 'inline', " +
            "api_hash TEXT, " +
            "FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE SET NULL" +
            ")"
        );

        // API提取规则表（v5 结构：v4 + global）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS api_extraction_rules (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL DEFAULT '', " +
            "source TEXT NOT NULL, " +
            "method TEXT NOT NULL, " +
            "expression TEXT NOT NULL, " +
            "enabled INTEGER NOT NULL DEFAULT 1, " +
            "priority INTEGER NOT NULL DEFAULT 1, " +
            "remark TEXT NOT NULL DEFAULT '', " +
            "global INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        // 创建索引
        createV3Indexes(stmt);

        BurpExtender.printOutput("[+] v5 Schema 初始化完成");
    }

    /**
     * 创建池表
     */
    private static void createPoolTables(Statement stmt) throws SQLException {
        // 字符串池
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS string_pool (" +
            "hash TEXT PRIMARY KEY, " +
            "value TEXT NOT NULL, " +
            "ref_count INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_string_pool_ref ON string_pool(ref_count)");

        // 头部池
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS header_pool (" +
            "hash TEXT PRIMARY KEY, " +
            "data BLOB NOT NULL, " +
            "size INTEGER NOT NULL, " +
            "ref_count INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_header_pool_ref ON header_pool(ref_count)");

        // 行内 Body 池
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS body_pool (" +
            "hash TEXT PRIMARY KEY, " +
            "data BLOB NOT NULL, " +
            "size INTEGER NOT NULL, " +
            "ref_count INTEGER NOT NULL DEFAULT 1, " +
            "is_binary INTEGER NOT NULL DEFAULT 0, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_body_pool_ref ON body_pool(ref_count)");

        // 文件型 Body 池
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS file_pool (" +
            "hash TEXT PRIMARY KEY, " +
            "relative_path TEXT NOT NULL, " +
            "size INTEGER NOT NULL, " +
            "ref_count INTEGER NOT NULL DEFAULT 1, " +
            "is_binary INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_file_pool_ref ON file_pool(ref_count)");
    }

    /**
     * 创建 v3 索引
     */
    private static void createV3Indexes(Statement stmt) throws SQLException {
        // v2 索引
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_domain_hash ON requests(domain_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_method ON requests(method)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_req_header ON requests(req_header_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_req_body ON requests(req_body_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_request_id ON history(request_id)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_domain_hash ON history(domain_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_status_code ON history(status_code)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_req_header ON history(req_header_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_resp_header ON history(resp_header_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_req_body ON history(req_body_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_resp_body ON history(resp_body_hash)");
        // v3 新增索引
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_api_hash ON requests(api_hash)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_api_hash ON history(api_hash)");
    }
}
