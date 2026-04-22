package oxff.top.api;

/**
 * API提取规则模型
 */
public class ApiExtractionRule {
    private int id;
    private String name;
    private ApiRuleSource source;
    private ApiRuleMethod method;
    private String expression;
    private boolean enabled;
    private int priority;
    private String remark;

    public ApiExtractionRule() {
        this.name = "";
        this.source = ApiRuleSource.URL_PATH;
        this.method = ApiRuleMethod.REGEX;
        this.expression = "";
        this.enabled = true;
        this.priority = 1;
        this.remark = "";
    }

    public ApiExtractionRule(int id, String name, ApiRuleSource source, ApiRuleMethod method,
                             String expression, boolean enabled, int priority, String remark) {
        this.id = id;
        this.name = name != null ? name : "";
        this.source = source;
        this.method = method;
        this.expression = expression;
        this.enabled = enabled;
        this.priority = priority;
        this.remark = remark != null ? remark : "";
    }

    public ApiExtractionRule(String name, ApiRuleSource source, ApiRuleMethod method,
                             String expression, boolean enabled, int priority, String remark) {
        this.name = name != null ? name : "";
        this.source = source;
        this.method = method;
        this.expression = expression;
        this.enabled = enabled;
        this.priority = priority;
        this.remark = remark != null ? remark : "";
    }

    /**
     * 校验规则是否有效（方法是否适用于来源、表达式是否非空）
     */
    public boolean isValid() {
        if (expression == null || expression.trim().isEmpty()) {
            return false;
        }
        return ApiRuleMethod.isValidForSource(method, source);
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public ApiRuleSource getSource() {
        return source;
    }

    public void setSource(ApiRuleSource source) {
        this.source = source;
    }

    public ApiRuleMethod getMethod() {
        return method;
    }

    public void setMethod(ApiRuleMethod method) {
        this.method = method;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark != null ? remark : "";
    }

    @Override
    public String toString() {
        return String.format("ApiExtractionRule{id=%d, name='%s', source=%s, method=%s, expression='%s', enabled=%b, priority=%d, remark='%s'}",
                id, name, source, method, expression, enabled, priority, remark);
    }
}
