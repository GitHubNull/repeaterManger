package oxff.top.privilege.model;

/**
 * 令牌位置类型枚举
 * 定义会话令牌在HTTP请求中可能出现的位置
 */
public enum TokenLocationType {
    /** HTTP请求头中，如 Authorization、Cookie */
    HEADER("Header"),
    /** JSON请求体中，如 $.data.token */
    JSON_BODY("JSON Body"),
    /** XML请求体中，如 //session/token */
    XML_BODY("XML Body"),
    /** 表单字段中，如 session_id */
    FORM_FIELD("Form Field"),
    /** Multipart表单字段中，如 file_upload中的session_id */
    MULTIPART_FIELD("Multipart Field");

    private final String displayName;

    TokenLocationType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 从字符串解析枚举值
     */
    public static TokenLocationType fromString(String text) {
        if (text == null) {
            return HEADER;
        }
        for (TokenLocationType type : TokenLocationType.values()) {
            if (type.name().equalsIgnoreCase(text) || type.displayName.equalsIgnoreCase(text)) {
                return type;
            }
        }
        return HEADER;
    }
}
