package oxff.top.io;

/**
 * ERM (Repeater Manager) 存档格式常量定义
 *
 * ERM 文件布局：
 * [FILE HEADER  32 bytes] - 魔法数字 + 版本 + 偏移量
 * [CRYPTO HEADER 48 bytes] - 仅加密模式：盐 + IV + HMAC
 * [DATA ENTRIES ...]       - 压缩的数据条目（或加密后的数据）
 * [FILE FOOTER  16 bytes] - 魔法数字 + 全局校验
 */
public final class ErmFormatConstants {

    private ErmFormatConstants() {}

    // ========== 文件头常量 ==========

    /** 文件头魔法数字: 0x89 ERM (借鉴 PNG 的 0x89 高位检测 7-bit 传输损坏) */
    public static final byte[] MAGIC_HEADER = {(byte) 0x89, 0x45, 0x52, 0x4D};

    /** 文件尾魔法数字: ERME (与头部区分，检测截断) */
    public static final byte[] MAGIC_FOOTER = {0x45, 0x52, 0x4D, 0x45};

    /** 当前格式版本号 */
    public static final int FORMAT_VERSION = 1;

    /** 文件头大小（字节） */
    public static final int HEADER_SIZE = 32;

    /** 文件尾大小（字节） */
    public static final int FOOTER_SIZE = 16;

    // ========== 标志位 ==========

    /** flags bit 0: 加密标志 */
    public static final int FLAG_ENCRYPTED = 0x00000001;

    // ========== 压缩方式（沿用 ZIP 约定） ==========

    /** 存储模式（不压缩） */
    public static final byte COMPRESSION_STORED = 0;

    /** DEFLATE 压缩 */
    public static final byte COMPRESSION_DEFLATED = 8;

    // ========== 条目路径约定 ==========

    /** 清单条目路径 */
    public static final String MANIFEST_ENTRY_PATH = ".erm/MANIFEST";

    /** 数据库条目路径 */
    public static final String DB_ENTRY_PATH = "database.sqlite3";

    /** Blob 目录前缀 */
    public static final String BLOB_DIR_PREFIX = "blobs/";

    // ========== 压缩阈值 ==========

    /** 小于此值的文件不压缩（字节），避免对小文件增加压缩开销 */
    public static final int STORED_THRESHOLD = 4096;

    // ========== I/O 缓冲区 ==========

    /** 读写缓冲区大小 */
    public static final int BUFFER_SIZE = 8192;

    // ========== 加密相关常量 ==========

    /** 加密头大小（字节）: salt(16) + iv(16) + hmac(32) = 64 */
    public static final int CRYPTO_HEADER_SIZE = 64;

    /** PBKDF2 迭代次数 */
    public static final int PBKDF2_ITERATIONS = 100000;

    /** PBKDF2 输出密钥材料长度（字节）: AES密钥(32) + HMAC密钥(32) */
    public static final int PBKDF2_KEY_MATERIAL_LENGTH = 64;

    /** 盐值大小（字节） */
    public static final int SALT_SIZE = 16;

    /** AES-CBC 初始化向量大小（字节） */
    public static final int IV_SIZE = 16;

    /** HMAC-SHA256 输出大小（字节） */
    public static final int HMAC_SIZE = 32;

    /** AES 密钥大小（字节）: 256 bits */
    public static final int AES_KEY_SIZE = 32;

    /** HMAC 密钥大小（字节） */
    public static final int HMAC_KEY_SIZE = 32;

    /** AES 加密算法 */
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";

    /** HMAC 算法 */
    public static final String HMAC_ALGORITHM = "HmacSHA256";

    /** PBKDF2 算法 */
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    // ========== 数据库 Schema ==========

    /** 当前数据库 Schema 版本 */
    public static final int CURRENT_SCHEMA_VERSION = 5;
}
