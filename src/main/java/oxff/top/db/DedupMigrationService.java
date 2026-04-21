package oxff.top.db;

import burp.BurpExtender;
import oxff.top.db.pool.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 去重存储迁移服务
 * 负责从旧版 Schema (v1) 迁移到新版 Schema (v2)
 */
public class DedupMigrationService {

    private static final int BATCH_SIZE = 50;

    @SuppressWarnings("unused")
    private final ContentHasher hasher;
    private final ContentSplitter splitter;
    private final PoolManager poolManager;

    public DedupMigrationService() {
        this.hasher = new ContentHasher();
        this.splitter = new ContentSplitter();
        this.poolManager = new PoolManager();
    }

    /**
     * 执行迁移
     *
     * @return true 如果迁移成功
     */
    public boolean migrate() {
        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 1. 确保池表和 gc_queue 存在
                ensurePoolTablesExist(conn);

                // 2. 给主表添加新列
                addNewColumns(conn);

                // 3. 设置迁移中标记
                setMetaValue(conn, "migration_in_progress", "1");
                conn.commit();

                // 4. 迁移 requests 表
                int requestOffset = getMetaIntValue(conn, "migration_batch_offset", 0);
                int lastRequestId = migrateRequests(conn, requestOffset);
                if (lastRequestId >= 0) {
                    setMetaValue(conn, "migration_batch_offset", String.valueOf(lastRequestId));
                    conn.commit();
                }

                // 5. 迁移 history 表
                int historyOffset = getMetaIntValue(conn, "migration_batch_offset_history", 0);
                int lastHistoryId = migrateHistory(conn, historyOffset);
                if (lastHistoryId >= 0) {
                    setMetaValue(conn, "migration_batch_offset_history", String.valueOf(lastHistoryId));
                    conn.commit();
                }

                // 6. 验证数据完整性（抽样检查）
                boolean valid = verifyMigration(conn);
                if (!valid) {
                    BurpExtender.printError("[!] 迁移数据验证失败，保留旧列不删除");
                } else {
                    // 7. 删除旧列
                    dropLegacyColumns(conn);
                    conn.commit();
                }

                // 8. 创建 v2 索引
                createV2Indexes(conn);
                conn.commit();

                // 9. 更新版本号
                setMetaValue(conn, "schema_version", String.valueOf(DatabaseManager.CURRENT_SCHEMA_VERSION));
                setMetaValue(conn, "migration_in_progress", "0");
                conn.commit();

                return true;

            } catch (SQLException e) {
                conn.rollback();
                BurpExtender.printError("[!] 迁移失败，已回滚: " + e.getMessage());
                return false;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 迁移服务获取连接失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 确保池表存在
     */
    private void ensurePoolTablesExist(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            // schema_meta
            stmt.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");

            // string_pool
            stmt.execute("CREATE TABLE IF NOT EXISTS string_pool (" +
                    "hash TEXT PRIMARY KEY, value TEXT NOT NULL, " +
                    "ref_count INTEGER NOT NULL DEFAULT 1, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_string_pool_ref ON string_pool(ref_count)");

            // header_pool
            stmt.execute("CREATE TABLE IF NOT EXISTS header_pool (" +
                    "hash TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL, " +
                    "ref_count INTEGER NOT NULL DEFAULT 1, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_header_pool_ref ON header_pool(ref_count)");

            // body_pool
            stmt.execute("CREATE TABLE IF NOT EXISTS body_pool (" +
                    "hash TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL, " +
                    "ref_count INTEGER NOT NULL DEFAULT 1, is_binary INTEGER NOT NULL DEFAULT 0, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_body_pool_ref ON body_pool(ref_count)");

            // file_pool
            stmt.execute("CREATE TABLE IF NOT EXISTS file_pool (" +
                    "hash TEXT PRIMARY KEY, relative_path TEXT NOT NULL, size INTEGER NOT NULL, " +
                    "ref_count INTEGER NOT NULL DEFAULT 1, is_binary INTEGER NOT NULL DEFAULT 1, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_file_pool_ref ON file_pool(ref_count)");

            // gc_queue
            stmt.execute("CREATE TABLE IF NOT EXISTS gc_queue (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, pool_type TEXT NOT NULL, hash TEXT NOT NULL, " +
                    "enqueued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_gc_queue_pool ON gc_queue(pool_type, hash)");
        }
    }

    /**
     * 给主表添加新列
     */
    private void addNewColumns(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            // requests 表新列
            addColumnIfNotExists(stmt, "requests", "domain_hash", "TEXT");
            addColumnIfNotExists(stmt, "requests", "path_hash", "TEXT");
            addColumnIfNotExists(stmt, "requests", "query_hash", "TEXT");
            addColumnIfNotExists(stmt, "requests", "req_header_hash", "TEXT");
            addColumnIfNotExists(stmt, "requests", "req_body_hash", "TEXT");
            addColumnIfNotExists(stmt, "requests", "req_body_storage", "TEXT DEFAULT 'inline'");

            // history 表新列
            addColumnIfNotExists(stmt, "history", "domain_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "path_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "query_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "req_header_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "req_body_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "req_body_storage", "TEXT DEFAULT 'inline'");
            addColumnIfNotExists(stmt, "history", "resp_header_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "resp_body_hash", "TEXT");
            addColumnIfNotExists(stmt, "history", "resp_body_storage", "TEXT DEFAULT 'inline'");
        }
    }

    private void addColumnIfNotExists(Statement stmt, String table, String column, String definition) {
        try {
            stmt.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
        } catch (SQLException e) {
            // 列已存在，忽略
            if (!e.getMessage().contains("duplicate column")) {
                BurpExtender.printError("[!] 添加列失败 " + table + "." + column + ": " + e.getMessage());
            }
        }
    }

    /**
     * 迁移 requests 表数据
     *
     * @return 最后处理的 ID，-1 表示完成或无数据
     */
    private int migrateRequests(Connection conn, int offset) throws SQLException {
        String selectSql = "SELECT id, protocol, domain, path, query, method, request_data " +
                "FROM requests WHERE id > ? ORDER BY id LIMIT " + BATCH_SIZE;

        int lastId = offset;
        boolean hasMore = true;

        while (hasMore) {
            hasMore = false;

            try (PreparedStatement pstmt = conn.prepareStatement(selectSql)) {
                pstmt.setInt(1, lastId);

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        hasMore = true;
                        int id = rs.getInt("id");
                        @SuppressWarnings("unused")
                        String protocol = rs.getString("protocol");
                        String domain = rs.getString("domain");
                        String path = rs.getString("path");
                        String query = rs.getString("query");
                        @SuppressWarnings("unused")
                        String method = rs.getString("method");
                        byte[] requestData = rs.getBytes("request_data");

                        // 字符串池
                        String domainHash = domain != null ? poolManager.ensureString(conn, domain) : null;
                        String pathHash = path != null ? poolManager.ensureString(conn, path) : null;
                        String queryHash = (query != null && !query.isEmpty()) ? poolManager.ensureString(conn, query) : null;

                        // 分割请求
                        String reqHeaderHash = null;
                        String reqBodyHash = null;
                        String reqBodyStorage = "none";

                        if (requestData != null && requestData.length > 0) {
                            SplitResult split = splitter.splitRequest(requestData);
                            reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());

                            if (split.hasBody()) {
                                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                                reqBodyHash = bodyResult[0];
                                reqBodyStorage = bodyResult[1];
                            }
                        }

                        // 更新记录
                        String updateSql = "UPDATE requests SET domain_hash=?, path_hash=?, query_hash=?, " +
                                "req_header_hash=?, req_body_hash=?, req_body_storage=? WHERE id=?";
                        try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                            updateStmt.setString(1, domainHash);
                            updateStmt.setString(2, pathHash);
                            updateStmt.setString(3, queryHash);
                            updateStmt.setString(4, reqHeaderHash);
                            updateStmt.setString(5, reqBodyHash);
                            updateStmt.setString(6, reqBodyStorage);
                            updateStmt.setInt(7, id);
                            updateStmt.executeUpdate();
                        }

                        lastId = id;
                    }
                }
            }

            conn.commit();

            if (hasMore) {
                BurpExtender.printOutput("[*] requests 迁移进度: 已处理到 ID " + lastId);
            }
        }

        return lastId;
    }

    /**
     * 迁移 history 表数据
     */
    private int migrateHistory(Connection conn, int offset) throws SQLException {
        String selectSql = "SELECT id, protocol, domain, path, query, method, " +
                "request_data, response_data FROM history WHERE id > ? ORDER BY id LIMIT " + BATCH_SIZE;

        int lastId = offset;
        boolean hasMore = true;

        while (hasMore) {
            hasMore = false;

            try (PreparedStatement pstmt = conn.prepareStatement(selectSql)) {
                pstmt.setInt(1, lastId);

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        hasMore = true;
                        int id = rs.getInt("id");
                        String domain = rs.getString("domain");
                        String path = rs.getString("path");
                        String query = rs.getString("query");
                        byte[] requestData = rs.getBytes("request_data");
                        byte[] responseData = rs.getBytes("response_data");

                        // 字符串池
                        String domainHash = domain != null ? poolManager.ensureString(conn, domain) : null;
                        String pathHash = path != null ? poolManager.ensureString(conn, path) : null;
                        String queryHash = (query != null && !query.isEmpty()) ? poolManager.ensureString(conn, query) : null;

                        // 分割请求
                        String reqHeaderHash = null;
                        String reqBodyHash = null;
                        String reqBodyStorage = "none";

                        if (requestData != null && requestData.length > 0) {
                            SplitResult split = splitter.splitRequest(requestData);
                            reqHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
                            if (split.hasBody()) {
                                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                                reqBodyHash = bodyResult[0];
                                reqBodyStorage = bodyResult[1];
                            }
                        }

                        // 分割响应
                        String respHeaderHash = null;
                        String respBodyHash = null;
                        String respBodyStorage = "none";

                        if (responseData != null && responseData.length > 0) {
                            SplitResult split = splitter.splitResponse(responseData);
                            respHeaderHash = poolManager.ensureHeader(conn, split.getHeaders());
                            if (split.hasBody()) {
                                String[] bodyResult = poolManager.ensureBody(conn, split.getBody());
                                respBodyHash = bodyResult[0];
                                respBodyStorage = bodyResult[1];
                            }
                        }

                        // 更新记录
                        String updateSql = "UPDATE history SET domain_hash=?, path_hash=?, query_hash=?, " +
                                "req_header_hash=?, req_body_hash=?, req_body_storage=?, " +
                                "resp_header_hash=?, resp_body_hash=?, resp_body_storage=? WHERE id=?";
                        try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                            updateStmt.setString(1, domainHash);
                            updateStmt.setString(2, pathHash);
                            updateStmt.setString(3, queryHash);
                            updateStmt.setString(4, reqHeaderHash);
                            updateStmt.setString(5, reqBodyHash);
                            updateStmt.setString(6, reqBodyStorage);
                            updateStmt.setString(7, respHeaderHash);
                            updateStmt.setString(8, respBodyHash);
                            updateStmt.setString(9, respBodyStorage);
                            updateStmt.setInt(10, id);
                            updateStmt.executeUpdate();
                        }

                        lastId = id;
                    }
                }
            }

            conn.commit();

            if (hasMore) {
                BurpExtender.printOutput("[*] history 迁移进度: 已处理到 ID " + lastId);
            }
        }

        return lastId;
    }

    /**
     * 验证迁移数据完整性：随机抽检，重构后与旧 BLOB 对比
     */
    private boolean verifyMigration(Connection conn) throws SQLException {
        ContentReconstructor reconstructor = new ContentReconstructor();
        int checked = 0;
        int failed = 0;

        // 抽检 requests
        String sql = "SELECT id, request_data, req_header_hash, req_body_hash, req_body_storage " +
                "FROM requests WHERE req_header_hash IS NOT NULL ORDER BY RANDOM() LIMIT 10";
        try (PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                byte[] originalData = rs.getBytes("request_data");
                String headerHash = rs.getString("req_header_hash");
                String bodyHash = rs.getString("req_body_hash");
                String bodyStorage = rs.getString("req_body_storage");

                byte[] reconstructed = reconstructor.reconstructRequest(conn, headerHash, bodyHash, bodyStorage);

                if (!java.util.Arrays.equals(originalData, reconstructed)) {
                    failed++;
                    BurpExtender.printError("[!] 验证失败 - request ID: " + rs.getInt("id"));
                }
                checked++;
            }
        }

        // 抽检 history
        sql = "SELECT id, request_data, response_data, req_header_hash, req_body_hash, req_body_storage, " +
                "resp_header_hash, resp_body_hash, resp_body_storage " +
                "FROM history WHERE req_header_hash IS NOT NULL ORDER BY RANDOM() LIMIT 10";
        try (PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                // 验证请求数据
                byte[] origReqData = rs.getBytes("request_data");
                byte[] reconReqData = reconstructor.reconstructRequest(conn,
                        rs.getString("req_header_hash"), rs.getString("req_body_hash"), rs.getString("req_body_storage"));
                if (!java.util.Arrays.equals(origReqData, reconReqData)) {
                    failed++;
                    BurpExtender.printError("[!] 验证失败 - history request ID: " + rs.getInt("id"));
                }

                // 验证响应数据
                byte[] origRespData = rs.getBytes("response_data");
                byte[] reconRespData = reconstructor.reconstructResponse(conn,
                        rs.getString("resp_header_hash"), rs.getString("resp_body_hash"), rs.getString("resp_body_storage"));
                if (!java.util.Arrays.equals(origRespData, reconRespData)) {
                    failed++;
                    BurpExtender.printError("[!] 验证失败 - history response ID: " + rs.getInt("id"));
                }
                checked++;
            }
        }

        BurpExtender.printOutput("[*] 迁移验证: 检查 " + checked + " 条，失败 " + failed + " 条");
        return failed == 0;
    }

    /**
     * 删除旧列
     */
    private void dropLegacyColumns(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            // requests 表旧列
            dropColumnIfExists(stmt, "requests", "request_data");
            dropColumnIfExists(stmt, "requests", "protocol");
            dropColumnIfExists(stmt, "requests", "domain");
            dropColumnIfExists(stmt, "requests", "path");
            dropColumnIfExists(stmt, "requests", "query");
            dropColumnIfExists(stmt, "requests", "method");

            // history 表旧列
            dropColumnIfExists(stmt, "history", "request_data");
            dropColumnIfExists(stmt, "history", "response_data");
            dropColumnIfExists(stmt, "history", "protocol");
            dropColumnIfExists(stmt, "history", "domain");
            dropColumnIfExists(stmt, "history", "path");
            dropColumnIfExists(stmt, "history", "query");
            dropColumnIfExists(stmt, "history", "method");

            BurpExtender.printOutput("[+] 旧列已删除");
        }
    }

    private void dropColumnIfExists(Statement stmt, String table, String column) {
        try {
            stmt.execute("ALTER TABLE " + table + " DROP COLUMN " + column);
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除列失败 " + table + "." + column + ": " + e.getMessage());
        }
    }

    /**
     * 创建 v2 索引
     */
    private void createV2Indexes(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
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
        }
    }

    private void setMetaValue(Connection conn, String key, String value) throws SQLException {
        String sql = "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, key);
            pstmt.setString(2, value);
            pstmt.executeUpdate();
        }
    }

    private int getMetaIntValue(Connection conn, String key, int defaultValue) {
        try {
            String sql = "SELECT value FROM schema_meta WHERE key = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, key);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        return Integer.parseInt(rs.getString("value"));
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
        return defaultValue;
    }
}
