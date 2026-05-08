package oxff.top.privilege.model;

/**
 * 判决规则匹配方法
 */
public enum RuleMethod {
    /** 正则表达式匹配 */
    REGEX("正则匹配"),
    /** 精确包含匹配 */
    CONTAINS("包含匹配"),
    /** 精确相等匹配 */
    EQUALS("相等匹配"),
    /** 数值比较（大于） */
    GREATER_THAN("大于"),
    /** 数值比较（小于） */
    LESS_THAN("小于"),
    /** 数值比较（等于） */
    NUMERIC_EQUALS("数值等于");

    private final String displayName;

    RuleMethod(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static RuleMethod fromString(String text) {
        if (text == null) return REGEX;
        for (RuleMethod method : RuleMethod.values()) {
            if (method.name().equalsIgnoreCase(text)) {
                return method;
            }
        }
        return REGEX;
    }
}
