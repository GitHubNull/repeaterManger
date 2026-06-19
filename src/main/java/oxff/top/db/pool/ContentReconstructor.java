package oxff.top.db.pool;

import burp.BurpExtender;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * 内容重构器
 * 从池表条目重构完整的 HTTP 字节数据
 */
public class ContentReconstructor {

    private final FileStorageManager fileStorageManager;

    public ContentReconstructor() {
        this.fileStorageManager = new FileStorageManager();
    }

    /**
     * 重构请求数据
     *
     * @param conn         数据库连接
     * @param headerHash   头部哈希
     * @param bodyHash     主体哈希（可为 null）
     * @param bodyStorage  主体存储类型 ("inline", "file", "none")
     * @return 重构的完整请求字节数据
     */
    public byte[] reconstructRequest(Connection conn, String headerHash, String bodyHash, String bodyStorage) {
        return reconstruct(conn, headerHash, bodyHash, bodyStorage);
    }

    /**
     * 重构响应数据
     *
     * @param conn         数据库连接
     * @param headerHash   头部哈希
     * @param bodyHash     主体哈希（可为 null）
     * @param bodyStorage  主体存储类型 ("inline", "file", "none")
     * @return 重构的完整响应字节数据
     */
    public byte[] reconstructResponse(Connection conn, String headerHash, String bodyHash, String bodyStorage) {
        return reconstruct(conn, headerHash, bodyHash, bodyStorage);
    }

    /**
     * 通用重构逻辑
     */
    private byte[] reconstruct(Connection conn, String headerHash, String bodyHash, String bodyStorage) {
        try {
            byte[] headerBytes = readHeader(conn, headerHash);
            if (headerBytes == null) {
                headerBytes = new byte[0];
            }

            byte[] bodyBytes = readBody(conn, bodyHash, bodyStorage);
            if (bodyBytes == null) {
                bodyBytes = new byte[0];
            }

            // 拼接头部 + 主体
            byte[] result = new byte[headerBytes.length + bodyBytes.length];
            System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
            System.arraycopy(bodyBytes, 0, result, headerBytes.length, bodyBytes.length);

            return result;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 重构数据失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从 header_pool 读取头部数据
     */
    private byte[] readHeader(Connection conn, String headerHash) throws SQLException {
        if (headerHash == null || headerHash.isEmpty()) {
            return new byte[0];
        }

        String sql = "SELECT data FROM header_pool WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, headerHash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getBytes("data");
                }
            }
        }
        return null;
    }

    /**
     * 根据存储类型读取主体数据
     */
    private byte[] readBody(Connection conn, String bodyHash, String bodyStorage) throws SQLException {
        if (bodyHash == null || bodyHash.isEmpty() || "none".equals(bodyStorage)) {
            return new byte[0];
        }

        BodyStorageRoute route = BodyStorageRoute.fromDbValue(bodyStorage);

        switch (route) {
            case INLINE:
                return readBodyFromPool(conn, bodyHash);
            case FILE:
                return readBodyFromFile(conn, bodyHash);
            default:
                return new byte[0];
        }
    }

    /**
     * 从 body_pool 读取行内主体数据
     */
    private byte[] readBodyFromPool(Connection conn, String bodyHash) throws SQLException {
        String sql = "SELECT data FROM body_pool WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, bodyHash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getBytes("data");
                }
            }
        }
        return null;
    }

    /**
     * 从文件读取主体数据
     * 防御性兑底：如果 file_pool 找不到，尝试从 body_pool 回退读取（BUG-001 场景）
     */
    private byte[] readBodyFromFile(Connection conn, String bodyHash) throws SQLException {
        String sql = "SELECT relative_path FROM file_pool WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, bodyHash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String relativePath = rs.getString("relative_path");
                    byte[] data = fileStorageManager.readBodyFile(relativePath);
                    if (data == null) {
                        BurpExtender.printError("[!] 文件读取失败: " + relativePath);
                    }
                    return data;
                }
            }
        }

        // 防御性兑底：file_pool 中找不到该 hash，尝试从 body_pool 读取
        // （历史数据可能因 BUG-001 的路由标记不一致而误存为 file 路由）
        byte[] fallbackData = readBodyFromPool(conn, bodyHash);
        if (fallbackData != null) {
            BurpExtender.printOutput("[*] 路由标记为 file 但 file_pool 未找到，从 body_pool 回退读取成功: " + bodyHash);
        }
        return fallbackData;
    }

    /**
     * 从 string_pool 读取字符串值
     *
     * @param conn 数据库连接
     * @param hash 字符串哈希
     * @return 字符串值，如果未找到返回 null
     */
    public String readString(Connection conn, String hash) throws SQLException {
        if (hash == null || hash.isEmpty()) {
            return null;
        }

        String sql = "SELECT value FROM string_pool WHERE hash = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, hash);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("value");
                }
            }
        }
        return null;
    }
}
