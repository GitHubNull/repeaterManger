package org.oxff.repeater.privilege.model;

import org.oxff.repeater.i18n.I18nManager;

/**
 * API去重策略枚举
 * 定义越权测试时对HTTP请求进行去重所依据的标准
 */
public enum DedupStrategy {
    /** 按URL路径去重（默认），如 /api/users */
    PATH("dedup.strategy.path"),
    /** 按API提取规则计算值去重（含path+query+规则） */
    API("dedup.strategy.api"),
    /** 按JSON Body中指定字段值去重 */
    JSON_BODY_FIELD("dedup.strategy.jsonBodyField"),
    /** 按XML Body中指定XPath节点值去重 */
    XML_BODY_FIELD("dedup.strategy.xmlBodyField"),
    /** 按x-www-form-urlencoded Body中指定字段值去重 */
    FORM_FIELD("dedup.strategy.formField"),
    /** 按URL查询参数中指定参数值去重 */
    URL_PARAM("dedup.strategy.urlParam");

    private final String displayNameKey;

    DedupStrategy(String displayNameKey) {
        this.displayNameKey = displayNameKey;
    }

    public String getDisplayName() {
        return I18nManager.tr(displayNameKey);
    }

    /**
     * 从字符串解析枚举值
     */
    public static DedupStrategy fromString(String text) {
        if (text == null) {
            return PATH;
        }
        for (DedupStrategy strategy : DedupStrategy.values()) {
            if (strategy.name().equalsIgnoreCase(text) || strategy.getDisplayName().equalsIgnoreCase(text)) {
                return strategy;
            }
        }
        return PATH;
    }
}
