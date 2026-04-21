package oxff.top.db.pool;

/**
 * 内容哈希工具类
 * 使用 SHA-256 对内容进行哈希，检测二进制数据，决策存储路由
 */
public class ContentHasher {

    private static final String ALGORITHM = "SHA-256";

    /** Body 存储阈值：超过此大小使用文件存储 */
    private static final int DEFAULT_BODY_INLINE_THRESHOLD = 65536;

    private int bodyInlineThreshold = DEFAULT_BODY_INLINE_THRESHOLD;

    /**
     * 计算字节数组的 SHA-256 哈希值
     *
     * @param data 原始字节数据
     * @return 64位小写十六进制哈希字符串
     */
    public String hashBytes(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(data);
            return bytesToHex(hashBytes);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * 计算字符串的 SHA-256 哈希值（UTF-8 编码）
     *
     * @param value 原始字符串
     * @return 64位小写十六进制哈希字符串
     */
    public String hashString(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return hashBytes(value.getBytes("UTF-8"));
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not available", e);
        }
    }

    /**
     * 检测字节数组是否为二进制数据（包含 null 字节 0x00）
     *
     * @param data 字节数组
     * @return true 如果包含 null 字节
     */
    public boolean isBinary(byte[] data) {
        if (data == null) {
            return false;
        }
        for (byte b : data) {
            if (b == 0x00) {
                return true;
            }
        }
        return false;
    }

    /**
     * 确定 Body 数据的存储路由
     *
     * @param body Body 字节数据，可为 null 或空
     * @return 存储路由枚举
     */
    public BodyStorageRoute routeBody(byte[] body) {
        if (body == null || body.length == 0) {
            return BodyStorageRoute.NONE;
        }
        if (body.length > bodyInlineThreshold || isBinary(body)) {
            return BodyStorageRoute.FILE;
        }
        return BodyStorageRoute.INLINE;
    }

    /**
     * 获取 Body 行内存储阈值
     */
    public int getBodyInlineThreshold() {
        return bodyInlineThreshold;
    }

    /**
     * 设置 Body 行内存储阈值
     */
    public void setBodyInlineThreshold(int threshold) {
        this.bodyInlineThreshold = threshold;
    }

    /**
     * 将字节数组转换为小写十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
