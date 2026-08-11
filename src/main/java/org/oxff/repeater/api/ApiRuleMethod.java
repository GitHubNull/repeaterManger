package org.oxff.repeater.api;

import org.oxff.repeater.i18n.I18nManager;

import java.util.Arrays;
import java.util.List;

/**
 * API提取规则方法枚举
 */
public enum ApiRuleMethod {
    REGEX("api.rule.method.regex"),
    SUBSTR("api.rule.method.substring"),
    JSON_PATH("api.rule.method.jsonPath"),
    XPATH("api.rule.method.xpath");

    private final String displayNameKey;

    ApiRuleMethod(String displayNameKey) {
        this.displayNameKey = displayNameKey;
    }

    public String getDisplayName() {
        return I18nManager.tr(displayNameKey);
    }

    /**
     * 从数据库存储值解析枚举
     */
    public static ApiRuleMethod fromDbValue(String value) {
        if (value == null) return REGEX;
        try {
            return valueOf(value);
        } catch (IllegalArgumentException e) {
            return REGEX;
        }
    }

    /**
     * 获取数据库存储值
     */
    public String toDbValue() {
        return name();
    }

    /**
     * 获取指定来源支持的方法列表
     */
    public static List<ApiRuleMethod> getMethodsForSource(ApiRuleSource source) {
        switch (source) {
            case URL_PATH:
            case URL_QUERY:
            case HEADER:
                return Arrays.asList(REGEX, SUBSTR);
            case BODY:
                return Arrays.asList(REGEX, SUBSTR, JSON_PATH, XPATH);
            default:
                return Arrays.asList(REGEX, SUBSTR);
        }
    }

    /**
     * 判断方法是否适用于指定来源
     */
    public static boolean isValidForSource(ApiRuleMethod method, ApiRuleSource source) {
        return getMethodsForSource(source).contains(method);
    }
}
