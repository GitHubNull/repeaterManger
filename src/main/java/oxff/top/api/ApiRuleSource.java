package oxff.top.api;

/**
 * API提取规则来源枚举
 */
public enum ApiRuleSource {
    URL_PATH("URL路径"),
    URL_QUERY("URL参数"),
    HEADER("请求头"),
    BODY("请求体");

    private final String displayName;

    ApiRuleSource(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从数据库存储值解析枚举
     */
    public static ApiRuleSource fromDbValue(String value) {
        if (value == null) return URL_PATH;
        try {
            return valueOf(value);
        } catch (IllegalArgumentException e) {
            return URL_PATH;
        }
    }

    /**
     * 获取数据库存储值
     */
    public String toDbValue() {
        return name();
    }
}
