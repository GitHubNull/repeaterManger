package org.oxff.repeater.db.schema;

import org.oxff.repeater.logging.LogManager;

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
            LogManager.getInstance().printOutput("[+] 数据库表结构初始化成功");
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

        // 初始化元数据（v15 — 与下方 DDL 中 history 表包含 baseline_response_data 列保持一致）
        stmt.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '15')");
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

        // 请求表（v10 结构：v8 + 响应字段）
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
            "api_hash TEXT, " +
            "is_privilege_test INTEGER NOT NULL DEFAULT 0, " +
            "resp_header_hash TEXT, " +
            "resp_body_hash TEXT, " +
            "resp_body_storage TEXT DEFAULT 'none', " +
            "resp_status_code INTEGER DEFAULT 0, " +
            "resp_length INTEGER DEFAULT 0, " +
            "resp_time INTEGER DEFAULT 0" +
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
            "user_session_name TEXT DEFAULT NULL, " +
            "judgment TEXT DEFAULT NULL, " +
            "similarity REAL DEFAULT -1, " +
            "baseline_response_data BLOB DEFAULT NULL, " +
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

        // 创建v6权限测试相关表（v14 已重命名：token_locations→field_definitions 等）
        createV6PrivilegeTables(stmt);

        // 创建v7 Scope表
        createV7ScopeTables(stmt);

        LogManager.getInstance().printOutput("[+] v15 Schema 初始化完成");
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
        // v8 新增索引
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_is_privilege_test ON requests(is_privilege_test)");
    }

    /**
     * 创建 v6 权限测试相关表（v14：表名已从 token_* 迁移为 field_* 和 schemes）
     */
    private static void createV6PrivilegeTables(Statement stmt) throws SQLException {
        // 字段定义表（v9 结构：v6 + persist_to_global + enabled，v14 从 token_locations 重命名）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS field_definitions (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "type TEXT NOT NULL, " +
            "expression TEXT NOT NULL, " +
            "description TEXT DEFAULT '', " +
            "persist_to_global INTEGER NOT NULL DEFAULT 1, " +
            "enabled INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        // 方案表（v11 新增，v14 从 token_schemes 重命名）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS schemes (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL, " +
            "description TEXT DEFAULT '', " +
            "persist_to_global INTEGER NOT NULL DEFAULT 1, " +
            "enabled INTEGER NOT NULL DEFAULT 1, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        // 方案-字段关联表（v11 新增，v14 从 scheme_token_locations 重命名）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS scheme_fields (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "scheme_id INTEGER NOT NULL, " +
            "field_id INTEGER NOT NULL, " +
            "FOREIGN KEY (scheme_id) REFERENCES schemes(id) ON DELETE CASCADE, " +
            "FOREIGN KEY (field_id) REFERENCES field_definitions(id) ON DELETE CASCADE, " +
            "UNIQUE (scheme_id, field_id)" +
            ")"
        );

        // 用户会话表（v11 结构：v6 + scheme_id + 重放配置列）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS user_sessions (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL, " +
            "color TEXT, " +
            "enabled INTEGER NOT NULL DEFAULT 1, " +
            "scheme_id INTEGER DEFAULT NULL, " +
            "request_timeout INTEGER DEFAULT 30, " +
            "max_concurrent INTEGER DEFAULT 1, " +
            "retry_count INTEGER DEFAULT 0, " +
            "retry_delay INTEGER DEFAULT 1000, " +
            "replay_delay INTEGER DEFAULT 0, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        // 字段值关联表（v14 从 token_values 重命名）
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS field_values (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "field_id INTEGER NOT NULL, " +
            "user_session_id INTEGER NOT NULL, " +
            "value TEXT NOT NULL, " +
            "FOREIGN KEY (field_id) REFERENCES field_definitions(id) ON DELETE CASCADE, " +
            "FOREIGN KEY (user_session_id) REFERENCES user_sessions(id) ON DELETE CASCADE, " +
            "UNIQUE (field_id, user_session_id)" +
            ")"
        );

        // 判决规则组表（v13：替代旧 judgment_rules，单活跃规则集模式）
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

        // 判决规则条件表（v13：规范化条件存储，FK 关联规则组）
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

        // v6 新增索引（v14 重命名对应索引）
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_field_values_field ON field_values(field_id)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_field_values_session ON field_values(user_session_id)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_judgment ON history(judgment)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_session ON history(user_session_name)");
        // v13 新索引
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_rule_groups_active ON judgment_rule_groups(is_active)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_conditions_group ON judgment_rule_conditions(group_id, sort_order)");
        // v11 新增索引（v14 重命名）
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_fields_scheme ON scheme_fields(scheme_id)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_scheme_fields_field ON scheme_fields(field_id)");
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_scheme ON user_sessions(scheme_id)");
    }

    /**
     * 创建 v7 Scope相关表
     */
    private static void createV7ScopeTables(Statement stmt) throws SQLException {
        // Scope条目表
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

        // v7 新增索引
        stmt.execute("CREATE INDEX IF NOT EXISTS idx_scope_entries_enabled ON scope_entries(enabled)");
    }
}
