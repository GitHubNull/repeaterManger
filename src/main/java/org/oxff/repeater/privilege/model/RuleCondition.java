package org.oxff.repeater.privilege.model;

/**
 * 判决规则内的单个匹配条件，支持 AND/OR/NOT 逻辑组合
 *
 * 每个条件由 target + method + expression 三元组定义匹配语义，
 * 通过 operator + negate 控制与累积结果的组合方式。
 * 整个规则的条件列表从左到右求值（无括号优先级）。
 */
public class RuleCondition {

    /** 逻辑运算符：AND / OR，控制当前条件与累积结果如何组合 */
    public enum LogicalOperator {
        AND("且"),
        OR("或");

        private final String displayName;

        LogicalOperator(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        public static LogicalOperator fromString(String text) {
            if (text == null) return AND;
            for (LogicalOperator op : values()) {
                if (op.name().equalsIgnoreCase(text)) return op;
            }
            return AND;
        }
    }

    private RuleTarget target;              // 条件应用于响应的哪个部分
    private RuleMethod method;              // 匹配方法
    private String expression;              // 匹配表达式
    private LogicalOperator operator;       // 逻辑运算符：AND（默认）/ OR
    private boolean negate;                 // 是否取反（NOT）

    public RuleCondition() {
        this.operator = LogicalOperator.AND;
        this.negate = false;
    }

    public RuleCondition(RuleTarget target, RuleMethod method, String expression) {
        this();
        this.target = target;
        this.method = method;
        this.expression = expression;
    }

    // ==================== Getters & Setters ====================

    public RuleTarget getTarget() {
        return target;
    }

    public void setTarget(RuleTarget target) {
        this.target = target;
    }

    public RuleMethod getMethod() {
        return method;
    }

    public void setMethod(RuleMethod method) {
        this.method = method;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public LogicalOperator getOperator() {
        return operator;
    }

    public void setOperator(LogicalOperator operator) {
        this.operator = operator != null ? operator : LogicalOperator.AND;
    }

    public boolean isNegate() {
        return negate;
    }

    public void setNegate(boolean negate) {
        this.negate = negate;
    }

    // ==================== 工具方法 ====================

    /** 检查条件是否有效（目标、方法、表达式均非空） */
    public boolean isValid() {
        return target != null && method != null && expression != null && !expression.trim().isEmpty();
    }
}
