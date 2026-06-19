package oxff.top.service;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;
import oxff.top.db.pool.FileStorageManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 垃圾回收服务
 * 后台定期清理零引用的池表条目
 */
public class GarbageCollectorService {

    private ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);

    /** 批量操作期间暂停GC，避免与高并发DB写操作竞争连接池 */
    private final AtomicBoolean paused = new AtomicBoolean(false);

    /** 默认 GC 运行间隔（分钟） */
    private static final int DEFAULT_INTERVAL_MINUTES = 10;

    /** 首次延迟（分钟） */
    private static final int INITIAL_DELAY_MINUTES = 2;

    /** 每次 GC 批处理大小 */
    private static final int BATCH_SIZE = 100;

    private final FileStorageManager fileStorageManager;

    public GarbageCollectorService() {
        this.fileStorageManager = new FileStorageManager();
    }

    /**
     * 启动 GC 服务
     */
    public void start() {
        if (running.get()) {
            return;
        }

        try {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "DedupStorage-GC");
                t.setDaemon(true);
                return t;
            });

            scheduler.scheduleWithFixedDelay(
                    this::processQueue,
                    INITIAL_DELAY_MINUTES,
                    DEFAULT_INTERVAL_MINUTES,
                    TimeUnit.MINUTES
            );

            running.set(true);
            BurpExtender.printOutput("[+] 垃圾回收服务已启动，间隔: " + DEFAULT_INTERVAL_MINUTES + " 分钟");
        } catch (Exception e) {
            BurpExtender.printError("[!] 垃圾回收服务启动失败: " + e.getMessage());
        }
    }

    /**
     * 停止 GC 服务
     */
    public void stop() {
        if (!running.get()) {
            return;
        }

        try {
            if (scheduler != null) {
                scheduler.shutdown();
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        running.set(false);
        BurpExtender.printOutput("[*] 垃圾回收服务已停止");
    }

    /**
     * 暂停GC服务（批量操作期间调用，避免GC抢占DB连接池）
     */
    public void pause() {
        paused.set(true);
        BurpExtender.printOutput("[*] GC 服务已暂停（批量操作期间）");
    }

    /**
     * 恢复GC服务
     */
    public void resume() {
        paused.set(false);
        BurpExtender.printOutput("[*] GC 服务已恢复");
    }

    /**
     * 立即触发一次 GC（用于批量操作后）
     */
    public void triggerNow() {
        new Thread(this::processQueue, "DedupStorage-GC-Manual").start();
    }

    /**
     * 处理 GC 队列
     */
    public void processQueue() {
        if (paused.get()) {
            BurpExtender.printOutput("[*] GC 已暂停，跳过本次处理");
            return;
        }

        if (!DatabaseManager.getInstance().isConnectionValid()) {
            return;
        }

        try {
            int totalProcessed = 0;
            int totalDeleted = 0;

            while (true) {
                List<GcEntry> batch = fetchNextBatch();
                if (batch.isEmpty()) {
                    break;
                }

                int deleted = processBatch(batch);
                totalProcessed += batch.size();
                totalDeleted += deleted;
            }

            if (totalProcessed > 0) {
                BurpExtender.printOutput("[*] GC 完成: 处理 " + totalProcessed + " 条，删除 " + totalDeleted + " 条");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] GC 处理失败: " + e.getMessage());
        }
    }

    /**
     * 全量 ref_count 重算并清理零引用条目
     */
    public void fullReclamation() {
        if (!DatabaseManager.getInstance().isConnectionValid()) {
            return;
        }

        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 重算 string_pool ref_count
                recalculateStringPoolRefCount(conn);

                // 重算 header_pool ref_count
                recalculateHeaderPoolRefCount(conn);

                // 重算 body_pool ref_count
                recalculateBodyPoolRefCount(conn);

                // 重算 file_pool ref_count
                recalculateFilePoolRefCount(conn);

                // 将零引用条目加入 GC 队列
                enqueueZeroRefCount(conn);

                conn.commit();

                // 立即处理 GC 队列
                processQueue();

                BurpExtender.printOutput("[+] 全量 ref_count 重算完成");
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 全量 ref_count 重算失败: " + e.getMessage());
        }
    }

    // ========== 内部方法 ==========

    private List<GcEntry> fetchNextBatch() {
        List<GcEntry> entries = new ArrayList<>();

        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            String sql = "SELECT id, pool_type, hash FROM gc_queue ORDER BY id LIMIT ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, BATCH_SIZE);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        entries.add(new GcEntry(
                                rs.getInt("id"),
                                rs.getString("pool_type"),
                                rs.getString("hash")
                        ));
                    }
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] GC 队列读取失败: " + e.getMessage());
        }

        return entries;
    }

    private int processBatch(List<GcEntry> batch) {
        int deleted = 0;

        try (Connection conn = DatabaseManager.getInstance().getConnection()) {
            conn.setAutoCommit(false);

            try {
                for (GcEntry entry : batch) {
                    if (tryDeletePoolEntry(conn, entry.poolType, entry.hash)) {
                        deleted++;
                    }
                }

                // 删除已处理的 GC 队列条目
                deleteProcessedEntries(conn, batch);

                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] GC 批处理失败: " + e.getMessage());
        }

        return deleted;
    }

    /**
     * 尝试删除池条目：先检查 ref_count 是否为 0
     */
    private boolean tryDeletePoolEntry(Connection conn, String poolType, String hash) throws SQLException {
        String tableName;
        switch (poolType) {
            case "string":
                tableName = "string_pool";
                break;
            case "header":
                tableName = "header_pool";
                break;
            case "body":
                tableName = "body_pool";
                break;
            case "file":
                tableName = "file_pool";
                break;
            default:
                return false;
        }

        // 再次确认 ref_count 为 0
        String checkSql = "SELECT ref_count FROM " + tableName + " WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(checkSql)) {
            pstmt.setString(1, hash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int refCount = rs.getInt("ref_count");
                    if (refCount > 0) {
                        // 仍有引用，跳过
                        return false;
                    }
                } else {
                    // 条目已不存在
                    return false;
                }
            }
        }

        // 对于 file 类型，先删除磁盘文件
        if ("file".equals(poolType)) {
            String pathSql = "SELECT relative_path FROM file_pool WHERE hash = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(pathSql)) {
                pstmt.setString(1, hash);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String relativePath = rs.getString("relative_path");
                        fileStorageManager.deleteBodyFile(relativePath);
                    }
                }
            }
        }

        // 删除池条目
        String deleteSql = "DELETE FROM " + tableName + " WHERE hash = ? AND ref_count <= 0";
        try (PreparedStatement pstmt = conn.prepareStatement(deleteSql)) {
            pstmt.setString(1, hash);
            return pstmt.executeUpdate() > 0;
        }
    }

    private void deleteProcessedEntries(Connection conn, List<GcEntry> batch) throws SQLException {
        if (batch.isEmpty()) return;

        // 逐条按ID删除，避免 ID 范围删除在并发写入时误删尚未处理的新条目
        String sql = "DELETE FROM gc_queue WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (GcEntry entry : batch) {
                pstmt.setInt(1, entry.id);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        }
    }

    private void recalculateStringPoolRefCount(Connection conn) throws SQLException {
        // 统计引用次数（含 api_hash：来自 requests 和 history 两个表）
        String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
                "SELECT domain_hash AS hash FROM requests WHERE domain_hash IS NOT NULL " +
                "UNION ALL SELECT path_hash FROM requests WHERE path_hash IS NOT NULL " +
                "UNION ALL SELECT query_hash FROM requests WHERE query_hash IS NOT NULL " +
                "UNION ALL SELECT api_hash FROM requests WHERE api_hash IS NOT NULL " +
                "UNION ALL SELECT domain_hash FROM history WHERE domain_hash IS NOT NULL " +
                "UNION ALL SELECT path_hash FROM history WHERE path_hash IS NOT NULL " +
                "UNION ALL SELECT query_hash FROM history WHERE query_hash IS NOT NULL " +
                "UNION ALL SELECT api_hash FROM history WHERE api_hash IS NOT NULL " +
                ") GROUP BY hash";

        // 重置所有 ref_count 为 0
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("UPDATE string_pool SET ref_count = 0");
        }

        // 根据统计结果更新
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            String updateSql = "UPDATE string_pool SET ref_count = ? WHERE hash = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    pstmt.setInt(1, rs.getInt("cnt"));
                    pstmt.setString(2, rs.getString("hash"));
                    pstmt.executeUpdate();
                }
            }
        }
    }

    private void recalculateHeaderPoolRefCount(Connection conn) throws SQLException {
        String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
                "SELECT req_header_hash AS hash FROM requests WHERE req_header_hash IS NOT NULL " +
                "UNION ALL SELECT resp_header_hash FROM requests WHERE resp_header_hash IS NOT NULL " +
                "UNION ALL SELECT req_header_hash FROM history WHERE req_header_hash IS NOT NULL " +
                "UNION ALL SELECT resp_header_hash FROM history WHERE resp_header_hash IS NOT NULL" +
                ") GROUP BY hash";

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("UPDATE header_pool SET ref_count = 0");
        }

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            String updateSql = "UPDATE header_pool SET ref_count = ? WHERE hash = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    pstmt.setInt(1, rs.getInt("cnt"));
                    pstmt.setString(2, rs.getString("hash"));
                    pstmt.executeUpdate();
                }
            }
        }
    }

    private void recalculateBodyPoolRefCount(Connection conn) throws SQLException {
        String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
                "SELECT req_body_hash AS hash FROM requests WHERE req_body_hash IS NOT NULL AND req_body_storage = 'inline' " +
                "UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'inline' " +
                "UNION ALL SELECT req_body_hash FROM history WHERE req_body_hash IS NOT NULL AND req_body_storage = 'inline' " +
                "UNION ALL SELECT resp_body_hash FROM history WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'inline'" +
                ") GROUP BY hash";

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("UPDATE body_pool SET ref_count = 0");
        }

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            String updateSql = "UPDATE body_pool SET ref_count = ? WHERE hash = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    pstmt.setInt(1, rs.getInt("cnt"));
                    pstmt.setString(2, rs.getString("hash"));
                    pstmt.executeUpdate();
                }
            }
        }
    }

    private void recalculateFilePoolRefCount(Connection conn) throws SQLException {
        String countSql = "SELECT hash, COUNT(*) as cnt FROM (" +
                "SELECT req_body_hash AS hash FROM requests WHERE req_body_hash IS NOT NULL AND req_body_storage = 'file' " +
                "UNION ALL SELECT resp_body_hash FROM requests WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'file' " +
                "UNION ALL SELECT req_body_hash FROM history WHERE req_body_hash IS NOT NULL AND req_body_storage = 'file' " +
                "UNION ALL SELECT resp_body_hash FROM history WHERE resp_body_hash IS NOT NULL AND resp_body_storage = 'file'" +
                ") GROUP BY hash";

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("UPDATE file_pool SET ref_count = 0");
        }

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            String updateSql = "UPDATE file_pool SET ref_count = ? WHERE hash = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                while (rs.next()) {
                    pstmt.setInt(1, rs.getInt("cnt"));
                    pstmt.setString(2, rs.getString("hash"));
                    pstmt.executeUpdate();
                }
            }
        }
    }

    private void enqueueZeroRefCount(Connection conn) throws SQLException {
        String[] poolTypes = {"string_pool", "header_pool", "body_pool", "file_pool"};
        String[] poolTypeNames = {"string", "header", "body", "file"};

        String insertSql = "INSERT INTO gc_queue (pool_type, hash) VALUES (?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
            for (int i = 0; i < poolTypes.length; i++) {
                String selectSql = "SELECT hash FROM " + poolTypes[i] + " WHERE ref_count <= 0";
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(selectSql)) {
                    while (rs.next()) {
                        pstmt.setString(1, poolTypeNames[i]);
                        pstmt.setString(2, rs.getString("hash"));
                        pstmt.executeUpdate();
                    }
                }
            }
        }
    }

    /**
     * GC 队列条目值对象
     */
    private static class GcEntry {
        final int id;
        final String poolType;
        final String hash;

        GcEntry(int id, String poolType, String hash) {
            this.id = id;
            this.poolType = poolType;
            this.hash = hash;
        }
    }
}
