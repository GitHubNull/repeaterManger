package org.oxff.repeater.api;

import java.util.Arrays;
import java.util.List;

/**
 * API提取规则方法枚举
 */
public enum ApiRuleMethod {
    REGEX("正则匹配"),
    SUBSTR("子串截取"),
    JSON_PATH("JSON路径"),
    XPATH("XPath");

    private final String displayName;

    ApiRuleMethod(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
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
