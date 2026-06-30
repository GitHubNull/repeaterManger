package org.oxff.repeater.privilege.model;

/**
 * 判决结果枚举
 * 表示权限测试中每个用户请求的越权检测结果
 */
public enum JudgmentResult {
    /** 待判定（尚未完成判决） */
    PENDING("待判定"),
    /** 检测到越权（响应与基准用户差异显著） */
    ESCALATED("越权"),
    /** 未检测到越权（响应与基准用户相似） */
    NOT_ESCALATED("安全"),
    /** 判决过程出错 */
    ERROR("错误");

    private final String displayName;

    JudgmentResult(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从字符串解析枚举值（支持英文名称和中文显示名）
     */
    public static JudgmentResult fromString(String text) {
        if (text == null) {
            return PENDING;
        }
        // 先按英文名称匹配
        for (JudgmentResult result : JudgmentResult.values()) {
            if (result.name().equalsIgnoreCase(text)) {
                return result;
            }
        }
        // 再按中文显示名匹配
        for (JudgmentResult result : JudgmentResult.values()) {
            if (result.displayName.equals(text)) {
                return result;
            }
        }
        return PENDING;
    }

    /**
     * 将英文枚举名或中文显示名统一转换为中文显示名
     * @param text 英文枚举名（如 "ESCALATED"）或中文显示名（如 "越权"）
     * @return 中文显示名，无法识别时返回原文本
     */
    public static String toDisplayName(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        JudgmentResult result = fromString(text);
        return result.getDisplayName();
    }
}
