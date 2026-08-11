package org.oxff.repeater.api;

import org.oxff.repeater.i18n.I18nManager;

/**
 * API提取规则来源枚举
 */
public enum ApiRuleSource {
    URL_PATH("api.rule.source.urlPath"),
    URL_QUERY("api.rule.source.urlParam"),
    HEADER("api.rule.source.header"),
    BODY("api.rule.source.body");

    private final String displayNameKey;

    ApiRuleSource(String displayNameKey) {
        this.displayNameKey = displayNameKey;
    }

    public String getDisplayName() {
        return I18nManager.tr(displayNameKey);
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
