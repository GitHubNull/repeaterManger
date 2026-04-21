package oxff.top.db.pool;

/**
 * Body 存储路由枚举
 * 决定 Body 数据存储在哪个池中
 */
public enum BodyStorageRoute {
    /** 行内存储：数据 <= 阈值且非二进制，存入 body_pool */
    INLINE("inline"),
    /** 文件存储：数据 > 阈值或含 null 字节，存入 file_pool + 磁盘文件 */
    FILE("file"),
    /** 无 Body：数据为 null 或空 */
    NONE("none");

    private final String dbValue;

    BodyStorageRoute(String dbValue) {
        this.dbValue = dbValue;
    }

    /**
     * 获取数据库存储值
     */
    public String getDbValue() {
        return dbValue;
    }

    /**
     * 从数据库值解析枚举
     */
    public static BodyStorageRoute fromDbValue(String dbValue) {
        if (dbValue == null) {
            return NONE;
        }
        switch (dbValue) {
            case "inline":
                return INLINE;
            case "file":
                return FILE;
            case "none":
            default:
                return NONE;
        }
    }
}
