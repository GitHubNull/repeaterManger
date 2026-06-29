package org.oxff.repeater.privilege.model;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则模型
 * 一条规则 = 针对某个测试目标的条件合集
 *
 * 匹配逻辑：
 * - 规则内条件：按列表顺序从左到右求值，支持 AND/OR/NOT 逻辑组合
 * - 规则间：按 priority 升序排列，首个所有条件满足的规则命中 → ESCALATED
 * - 无规则命中 → PENDING（需人工确认）
 */
public class JudgmentRule {

    private int id;
    private String name;
    private RuleTarget target;       // 规则应用于响应的哪个部分（向后兼容单条件场景）
    private RuleMethod method;       // 匹配方法（向后兼容单条件场景）
    private String expression;       // 匹配表达式（向后兼容单条件场景）
    private List<RuleCondition> conditions; // 多条件列表（优先于单条件 target/method/expression）
    private boolean enabled = true;
    private int priority = 1;
    private Color successColor;      // 匹配成功时的标记颜色（默认红色=越权）
    private Color failureColor;      // 匹配失败时的标记颜色（默认绿色=安全）
    private String successNote;      // 匹配成功时的备注
    private String failureNote;      // 匹配失败时的备注
    private String remark;           // 规则备注说明
    private boolean global = true;

    public JudgmentRule() {
        this.successColor = Color.RED;
        this.failureColor = new Color(144, 238, 144); // 浅绿色
        this.successNote = "";
        this.failureNote = "";
        this.remark = "";
        this.conditions = new ArrayList<>();
    }

    // ==================== Getters & Setters ====================

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
        this.name = name;
    }

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

    public List<RuleCondition> getConditions() {
        return conditions;
    }

    public void setConditions(List<RuleCondition> conditions) {
        this.conditions = conditions != null ? conditions : new ArrayList<>();
    }

    /**
     * 获取有效条件列表
     * 优先返回 conditions（多条件模式），若为空则回退到单条件 target/method/expression 自动包装
     */
    public List<RuleCondition> getEffectiveConditions() {
        if (conditions != null && !conditions.isEmpty()) {
            return conditions;
        }
        // 向后兼容：从单条件字段自动包装
        if (target != null && method != null && expression != null && !expression.trim().isEmpty()) {
            return List.of(new RuleCondition(target, method, expression));
        }
        return new ArrayList<>();
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

    public Color getSuccessColor() {
        return successColor;
    }

    public void setSuccessColor(Color successColor) {
        this.successColor = successColor;
    }

    public String getSuccessColorHex() {
        return colorToHex(successColor);
    }

    public Color getFailureColor() {
        return failureColor;
    }

    public void setFailureColor(Color failureColor) {
        this.failureColor = failureColor;
    }

    public String getFailureColorHex() {
        return colorToHex(failureColor);
    }

    public String getSuccessNote() {
        return successNote;
    }

    public void setSuccessNote(String successNote) {
        this.successNote = successNote != null ? successNote : "";
    }

    public String getFailureNote() {
        return failureNote;
    }

    public void setFailureNote(String failureNote) {
        this.failureNote = failureNote != null ? failureNote : "";
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark != null ? remark : "";
    }

    public boolean isGlobal() {
        return global;
    }

    public void setGlobal(boolean global) {
        this.global = global;
    }

    /**
     * 检查规则是否有效
     * 优先检查多条件模式，回退到单条件模式
     */
    public boolean isValid() {
        List<RuleCondition> effective = getEffectiveConditions();
        if (!effective.isEmpty()) {
            // 多条件模式：至少有一条有效条件
            for (RuleCondition cond : effective) {
                if (cond.isValid()) return true;
            }
            return false;
        }
        // 单条件模式（向后兼容）
        return target != null && method != null && expression != null && !expression.trim().isEmpty();
    }

    // ==================== 工具方法 ====================

    private static String colorToHex(Color color) {
        if (color == null) return null;
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }

    public static Color hexToColor(String hex) {
        if (hex == null || hex.trim().isEmpty()) return null;
        try {
            return Color.decode(hex.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
