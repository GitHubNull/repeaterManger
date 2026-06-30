package org.oxff.repeater.privilege.model;

/**
 * 判决规则条件模型（v14：恢复 AND/OR 混合支持）
 *
 * 每个条件由 target + method + expression 三元组定义匹配语义，
 * 通过 negate 控制是否取反。同一规则组内条件支持 AND/OR 组合。
 */
public class RuleCondition {

    private int id;
    private int groupId;                    // 所属规则组ID
    private RuleTarget target;              // 条件应用于响应的哪个部分
    private RuleMethod method;              // 匹配方法
    private String expression;              // 匹配表达式
    private boolean negate;                 // 是否取反（NOT）
    private int sortOrder;                  // 组内排序
    private boolean enabled = true;         // 是否启用
    private String remark;                  // 条件备注
    private LogicalOperator operator = LogicalOperator.AND;  // 条件间逻辑运算符（默认 AND）

    public RuleCondition() {
        this.negate = false;
        this.enabled = true;
        this.operator = LogicalOperator.AND;
    }

    public RuleCondition(RuleTarget target, RuleMethod method, String expression) {
        this();
        this.target = target;
        this.method = method;
        this.expression = expression;
    }

    // ==================== Getters & Setters ====================

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public int getGroupId() { return groupId; }
    public void setGroupId(int groupId) { this.groupId = groupId; }

    public RuleTarget getTarget() { return target; }
    public void setTarget(RuleTarget target) { this.target = target; }

    public RuleMethod getMethod() { return method; }
    public void setMethod(RuleMethod method) { this.method = method; }

    public String getExpression() { return expression; }
    public void setExpression(String expression) { this.expression = expression; }

    public boolean isNegate() { return negate; }
    public void setNegate(boolean negate) { this.negate = negate; }

    public int getSortOrder() { return sortOrder; }
    public void setSortOrder(int sortOrder) { this.sortOrder = sortOrder; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getRemark() { return remark; }
    public void setRemark(String remark) { this.remark = remark != null ? remark : ""; }

    // ==================== 逻辑运算符（v14：恢复 AND/OR 支持） ====================

    public enum LogicalOperator {
        AND("且"),
        OR("或");

        private final String displayName;
        LogicalOperator(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
        public static LogicalOperator fromString(String text) {
            if (text == null) return AND;
            for (LogicalOperator op : values()) {
                if (op.name().equalsIgnoreCase(text)) return op;
            }
            return AND;
        }
    }

    public LogicalOperator getOperator() { return operator; }

    public void setOperator(LogicalOperator operator) {
        this.operator = operator != null ? operator : LogicalOperator.AND;
    }

    // ==================== 工具方法 ====================

    /** 检查条件是否有效（目标、方法、表达式均非空） */
    public boolean isValid() {
        return target != null && method != null && expression != null && !expression.trim().isEmpty();
    }
}
