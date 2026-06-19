package oxff.top.db.pool;

import burp.BurpExtender;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 池表管理器
 * 管理所有池表（string_pool, header_pool, body_pool, file_pool）的 CRUD 操作
 * 处理 ref_count 的增减、INSERT-or-increment 模式
 */
public class PoolManager {

    private final ContentHasher hasher;
    private final ContentSplitter splitter;
    private final FileStorageManager fileStorageManager;

    // 内存缓存：hash → 是否存在于池中
    private final ConcurrentHashMap<String, Boolean> existenceCache = new ConcurrentHashMap<>();
    // 字符串池缓存：hash → 字符串值
    private final ConcurrentHashMap<String, String> stringCache = new ConcurrentHashMap<>();
    // 头部缓存：hash → 头部字节数据
    private final ConcurrentHashMap<String, byte[]> headerCache = new ConcurrentHashMap<>();

    /** existenceCache 的最大条目数（覆盖所有池类型） */
    private static final int MAX_CACHE_SIZE = 2000;
    /** stringCache 的最大条目数 */
    private static final int MAX_STRING_CACHE_SIZE = 1000;
    /** headerCache 的最大条目数 */
    private static final int MAX_HEADER_CACHE_SIZE = 500;
    /** 缓存淘汰时保留的比例（淘汰最旧的25%） */
    private static final double CACHE_EVICT_RATIO = 0.75;

    public PoolManager() {
        this.hasher = new ContentHasher();
        this.splitter = new ContentSplitter();
        this.fileStorageManager = new FileStorageManager();
    }

    // ========== 字符串池操作 ==========

    /**
     * 确保字符串存在于 string_pool 中，增加 ref_count
     *
     * @param conn   数据库连接
     * @param value  字符串值
     * @return 哈希值
     */
    public String ensureString(Connection conn, String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            return null;
        }

        String hash = hasher.hashString(value);

        // 检查缓存
        if (existenceCache.containsKey("string:" + hash)) {
            // 已存在，仅增加 ref_count
            if (incrementRefCount(conn, "string_pool", hash)) {
                return hash;
            }
            // 缓存过期（条目已被 GC 回收），清除缓存并继续执行完整 INSERT
            existenceCache.remove("string:" + hash);
        }

        // INSERT OR INCREMENT
        String sql = "INSERT INTO string_pool (hash, value, ref_count) VALUES (?, ?, 1) " +
                     "ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            pstmt.setString(2, value);
            pstmt.executeUpdate();
        }

        existenceCache.put("string:" + hash, true);
        trimExistenceCacheIfNeeded();
        stringCache.put(hash, value);
        trimStringCacheIfNeeded();

        return hash;
    }

    /**
     * 从 string_pool 读取字符串值
     *
     * @param conn 数据库连接
     * @param hash 哈希值
     * @return 字符串值，未找到返回 null
     */
    public String readString(Connection conn, String hash) throws SQLException {
        if (hash == null || hash.isEmpty()) {
            return null;
        }

        // 检查缓存
        String cached = stringCache.get(hash);
        if (cached != null) {
            return cached;
        }

        String sql = "SELECT value FROM string_pool WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String value = rs.getString("value");
                    stringCache.put(hash, value);
                    trimStringCacheIfNeeded();
                    return value;
                }
            }
        }

        return null;
    }

    /**
     * 释放字符串引用，减少 ref_count
     */
    public void releaseString(Connection conn, String hash) throws SQLException {
        if (hash == null || hash.isEmpty()) {
            return;
        }
        releasePoolEntry(conn, "string_pool", hash, "string");
        // 引用释放后清除字符串缓存，避免 GC 回收后返回已删除的数据
        stringCache.remove(hash);
    }

    // ========== 头部池操作 ==========

    /**
     * 确保头部数据存在于 header_pool 中，增加 ref_count
     *
     * @param conn       数据库连接
     * @param headerData 头部字节数据
     * @return 哈希值
     */
    public String ensureHeader(Connection conn, byte[] headerData) throws SQLException {
        if (headerData == null || headerData.length == 0) {
            return null;
        }

        String hash = hasher.hashBytes(headerData);

        // 检查缓存
        if (existenceCache.containsKey("header:" + hash)) {
            if (incrementRefCount(conn, "header_pool", hash)) {
                return hash;
            }
            // 缓存过期（条目已被 GC 回收），清除缓存并继续执行完整 INSERT
            existenceCache.remove("header:" + hash);
        }

        String sql = "INSERT INTO header_pool (hash, data, size, ref_count) VALUES (?, ?, ?, 1) " +
                     "ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            pstmt.setBytes(2, headerData);
            pstmt.setInt(3, headerData.length);
            pstmt.executeUpdate();
        }

        existenceCache.put("header:" + hash, true);
        trimExistenceCacheIfNeeded();
        headerCache.put(hash, headerData);
        trimHeaderCacheIfNeeded();

        return hash;
    }

    /**
     * 释放头部引用，减少 ref_count
     */
    public void releaseHeader(Connection conn, String hash) throws SQLException {
        if (hash == null || hash.isEmpty()) {
            return;
        }
        releasePoolEntry(conn, "header_pool", hash, "header");
        headerCache.remove(hash);
    }

    // ========== Body 池操作 ==========

    /**
     * 确保 Body 数据存在于相应的池中（body_pool 或 file_pool），增加 ref_count
     *
     * @param conn 数据库连接
     * @param body Body 字节数据
     * @return [hash, storageRoute] 数组
     */
    public String[] ensureBody(Connection conn, byte[] body) throws SQLException {
        if (body == null || body.length == 0) {
            return new String[]{null, BodyStorageRoute.NONE.getDbValue()};
        }

        BodyStorageRoute route = hasher.routeBody(body);
        String hash = hasher.hashBytes(body);

        switch (route) {
            case INLINE:
                ensureBodyInline(conn, hash, body);
                return new String[]{hash, BodyStorageRoute.INLINE.getDbValue()};
            case FILE:
                BodyStorageRoute actualRoute = ensureBodyFile(conn, hash, body);
                return new String[]{hash, actualRoute.getDbValue()};
            default:
                return new String[]{null, BodyStorageRoute.NONE.getDbValue()};
        }
    }

    /**
     * 释放 Body 引用，减少 ref_count
     *
     * @param conn        数据库连接
     * @param hash        哈希值
     * @param bodyStorage 存储类型
     */
    public void releaseBody(Connection conn, String hash, String bodyStorage) throws SQLException {
        if (hash == null || hash.isEmpty()) {
            return;
        }

        BodyStorageRoute route = BodyStorageRoute.fromDbValue(bodyStorage);
        switch (route) {
            case INLINE:
                releasePoolEntry(conn, "body_pool", hash, "body");
                break;
            case FILE:
                releasePoolEntry(conn, "file_pool", hash, "file");
                break;
            default:
                break;
        }
    }

    /**
     * 获取 ContentSplitter 实例
     */
    public ContentSplitter getSplitter() {
        return splitter;
    }

    /**
     * 获取 ContentHasher 实例
     */
    public ContentHasher getHasher() {
        return hasher;
    }

    /**
     * 获取 FileStorageManager 实例
     */
    public FileStorageManager getFileStorageManager() {
        return fileStorageManager;
    }

    /**
     * 清除所有内存缓存
     */
    public void clearCache() {
        existenceCache.clear();
        stringCache.clear();
        headerCache.clear();
    }

    // ========== 内部方法 ==========

    private void ensureBodyInline(Connection conn, String hash, byte[] body) throws SQLException {
        if (existenceCache.containsKey("body:" + hash)) {
            if (incrementRefCount(conn, "body_pool", hash)) {
                return;
            }
            // 缓存过期（条目已被 GC 回收），清除缓存并继续执行完整 INSERT
            existenceCache.remove("body:" + hash);
        }

        String sql = "INSERT INTO body_pool (hash, data, size, ref_count, is_binary) VALUES (?, ?, ?, 1, 0) " +
                     "ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            pstmt.setBytes(2, body);
            pstmt.setInt(3, body.length);
            pstmt.executeUpdate();
        }

        existenceCache.put("body:" + hash, true);
        trimExistenceCacheIfNeeded();
    }

    /**
     * 确保 Body 数据以文件方式存储，增加 ref_count
     * @return 实际存储路由（FILE 成功，INLINE 表示文件写入失败已回退）
     */
    private BodyStorageRoute ensureBodyFile(Connection conn, String hash, byte[] body) throws SQLException {
        // 先检查缓存，避免冗余文件写入（BUG-008）
        if (existenceCache.containsKey("file:" + hash)) {
            if (incrementRefCount(conn, "file_pool", hash)) {
                return BodyStorageRoute.FILE;
            }
            // 缓存过期（条目已被 GC 回收），清除缓存并继续
            existenceCache.remove("file:" + hash);
        }

        // 写入文件
        String relativePath = fileStorageManager.writeBodyFile(body, hash);
        if (relativePath == null) {
            BurpExtender.printError("[!] 写入 Body 文件失败，hash: " + hash);
            // 回退到行内存储
            ensureBodyInline(conn, hash, body);
            return BodyStorageRoute.INLINE;
        }

        String sql = "INSERT INTO file_pool (hash, relative_path, size, ref_count, is_binary) VALUES (?, ?, ?, 1, 1) " +
                     "ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            pstmt.setString(2, relativePath);
            pstmt.setInt(3, body.length);
            pstmt.executeUpdate();
        }

        existenceCache.put("file:" + hash, true);
        trimExistenceCacheIfNeeded();
        return BodyStorageRoute.FILE;
    }

    /**
     * 增加池条目的 ref_count
     * @return true 如果成功增加；false 如果条目不存在（可能已被 GC 回收）
     */
    private boolean incrementRefCount(Connection conn, String tableName, String hash) throws SQLException {
        String sql = "UPDATE " + tableName + " SET ref_count = ref_count + 1 WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            int affected = pstmt.executeUpdate();
            if (affected == 0) {
                // 条目已被 GC 回收，缓存过期
                BurpExtender.printOutput("[*] 缓存命中但池条目不存在，可能已被 GC 回收: " + tableName + "/" + hash);
                return false;
            }
            return true;
        }
    }

    /**
     * 释放池条目引用：减少 ref_count，如果降为 0 则加入 GC 队列
     */
    private void releasePoolEntry(Connection conn, String tableName, String hash, String poolType) throws SQLException {
        // 减少 ref_count
        String updateSql = "UPDATE " + tableName + " SET ref_count = ref_count - 1 WHERE hash = ? AND ref_count > 0";
        try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
            pstmt.setString(1, hash);
            int affected = pstmt.executeUpdate();

            if (affected == 0) {
                // ref_count 已经是 0 或条目不存在
                return;
            }
        }

        // 检查 ref_count 是否降为 0
        String checkSql = "SELECT ref_count FROM " + tableName + " WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(checkSql)) {
            pstmt.setString(1, hash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next() && rs.getInt("ref_count") <= 0) {
                    // 加入 GC 队列
                    enqueueForGC(conn, poolType, hash);
                }
            }
        }

        // 更新存在性缓存
        existenceCache.remove(poolType + ":" + hash);
    }

    /**
     * 将零引用条目加入 GC 队列
     */
    private void enqueueForGC(Connection conn, String poolType, String hash) throws SQLException {
        String sql = "INSERT INTO gc_queue (pool_type, hash) VALUES (?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, poolType);
            pstmt.setString(2, hash);
            pstmt.executeUpdate();
        }
    }

    /**
     * 缓存大小控制 - 使用部分淘汰策略，避免一次性清除所有缓存
     */
    private void trimStringCacheIfNeeded() {
        if (stringCache.size() > MAX_STRING_CACHE_SIZE) {
            evictCache(stringCache, (int) (MAX_STRING_CACHE_SIZE * CACHE_EVICT_RATIO));
        }
    }

    private void trimHeaderCacheIfNeeded() {
        if (headerCache.size() > MAX_HEADER_CACHE_SIZE) {
            evictCache(headerCache, (int) (MAX_HEADER_CACHE_SIZE * CACHE_EVICT_RATIO));
        }
    }

    private void trimExistenceCacheIfNeeded() {
        if (existenceCache.size() > MAX_CACHE_SIZE) {
            evictCache(existenceCache, (int) (MAX_CACHE_SIZE * CACHE_EVICT_RATIO));
        }
    }

    /**
     * 通用缓存淘汰：保留 targetSize 条目，移除多余条目
     * ConcurrentHashMap 无序，所以这里是随机淘汰（近似 FIFO）
     */
    private <K, V> void evictCache(ConcurrentHashMap<K, V> cache, int targetSize) {
        int toRemove = cache.size() - targetSize;
        if (toRemove <= 0) {
            return;
        }
        int removed = 0;
        for (K key : cache.keySet()) {
            if (removed >= toRemove) {
                break;
            }
            cache.remove(key);
            removed++;
        }
    }
}
