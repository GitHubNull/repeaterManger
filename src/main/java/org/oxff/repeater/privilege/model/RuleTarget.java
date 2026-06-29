package org.oxff.repeater.privilege.model;

/**
 * 判决规则目标 - 规则应用于响应的哪个部分
 */
public enum RuleTarget {
    /** 响应状态码 */
    STATUS_CODE("状态码"),
    /** 响应头 */
    RESPONSE_HEADER("响应头"),
    /** 响应体 */
    RESPONSE_BODY("响应体"),
    /** 响应时间（毫秒） */
    RESPONSE_TIME("响应时间"),
    /** 响应相似度（与基准响应的相似度，0.0~1.0） */
    SIMILARITY("相似度");

    private final String displayName;

    RuleTarget(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static RuleTarget fromString(String text) {
        if (text == null) return STATUS_CODE;
        for (RuleTarget target : RuleTarget.values()) {
            if (target.name().equalsIgnoreCase(text)) {
                return target;
            }
        }
        return STATUS_CODE;
    }
}
