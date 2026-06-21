package org.oxff.repeater.privilege.model;

/**
 * API去重策略枚举
 * 定义越权测试时对HTTP请求进行去重所依据的标准
 */
public enum DedupStrategy {
    /** 按URL路径去重（默认），如 /api/users */
    PATH("路径 (Path)"),
    /** 按API提取规则计算值去重（含path+query+规则） */
    API("API值"),
    /** 按JSON Body中指定字段值去重 */
    JSON_BODY_FIELD("JSON字段"),
    /** 按XML Body中指定XPath节点值去重 */
    XML_BODY_FIELD("XML字段"),
    /** 按x-www-form-urlencoded Body中指定字段值去重 */
    FORM_FIELD("表单字段"),
    /** 按URL查询参数中指定参数值去重 */
    URL_PARAM("URL参数");

    private final String displayName;

    DedupStrategy(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从字符串解析枚举值
     */
    public static DedupStrategy fromString(String text) {
        if (text == null) {
            return PATH;
        }
        for (DedupStrategy strategy : DedupStrategy.values()) {
            if (strategy.name().equalsIgnoreCase(text) || strategy.displayName.equalsIgnoreCase(text)) {
                return strategy;
            }
        }
        return PATH;
    }
}
