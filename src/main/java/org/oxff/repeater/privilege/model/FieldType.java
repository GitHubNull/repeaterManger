package org.oxff.repeater.privilege.model;

/**
 * 字段类型枚举
 * 定义会话凭证字段在HTTP请求中可能出现的位置
 */
public enum FieldType {
    /** HTTP请求头中，如 Authorization、Cookie */
    HEADER("Header"),
    /** JSON请求体中，如 $.data.token */
    JSON_BODY("JSON Body"),
    /** XML请求体中，如 //session/token */
    XML_BODY("XML Body"),
    /** 表单字段中，如 session_id */
    FORM_FIELD("Form Field"),
    /** Multipart表单字段中，如 file_upload中的session_id */
    MULTIPART_FIELD("Multipart Field"),
    /** URL查询参数中，如 ?token=xxx */
    URL_PARAM("URL Parameter");

    private final String displayName;

    FieldType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从字符串解析枚举值
     */
    public static FieldType fromString(String text) {
        if (text == null) {
            return HEADER;
        }
        for (FieldType type : FieldType.values()) {
            if (type.name().equalsIgnoreCase(text) || type.displayName.equalsIgnoreCase(text)) {
                return type;
            }
        }
        return HEADER;
    }
}
