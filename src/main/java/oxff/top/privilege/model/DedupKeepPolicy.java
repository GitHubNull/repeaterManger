package oxff.top.privilege.model;

/**
 * 去重保留策略枚举
 * 当多条请求具有相同的去重键时，决定保留哪一条
 */
public enum DedupKeepPolicy {
    /** 保留第一条（默认） */
    FIRST("第一条"),
    /** 保留最后一条 */
    LAST("最后一条"),
    /** 保留中间那条（当有奇数条时取正中间，偶数条时取偏后那条） */
    MIDDLE("中间条");

    private final String displayName;

    DedupKeepPolicy(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从字符串解析枚举值
     */
    public static DedupKeepPolicy fromString(String text) {
        if (text == null) {
            return FIRST;
        }
        for (DedupKeepPolicy policy : DedupKeepPolicy.values()) {
            if (policy.name().equalsIgnoreCase(text) || policy.displayName.equalsIgnoreCase(text)) {
                return policy;
            }
        }
        return FIRST;
    }
}
