package org.oxff.repeater.privilege.model;

import org.oxff.repeater.i18n.I18nManager;

/**
 * 去重保留策略枚举
 * 当多条请求具有相同的去重键时，决定保留哪一条
 */
public enum DedupKeepPolicy {
    /** 保留第一条（默认） */
    FIRST("dedup.keep.first"),
    /** 保留最后一条 */
    LAST("dedup.keep.last"),
    /** 保留中间那条（当有奇数条时取正中间，偶数条时取偏后那条） */
    MIDDLE("dedup.keep.middle");

    private final String displayNameKey;

    DedupKeepPolicy(String displayNameKey) {
        this.displayNameKey = displayNameKey;
    }

    public String getDisplayName() {
        return I18nManager.tr(displayNameKey);
    }

    /**
     * 从字符串解析枚举值
     */
    public static DedupKeepPolicy fromString(String text) {
        if (text == null) {
            return FIRST;
        }
        for (DedupKeepPolicy policy : DedupKeepPolicy.values()) {
            if (policy.name().equalsIgnoreCase(text) || policy.getDisplayName().equalsIgnoreCase(text)) {
                return policy;
            }
        }
        return FIRST;
    }
}
