package org.oxff.repeater.privilege.model;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则组模型（v13：单活跃规则集模式）
 * 一个规则组 = 一组条件的 AND 集合
 *
 * 匹配逻辑：
 * - 组内条件：全部满足（纯 AND）才算规则组命中
 * - 全局唯一活跃规则组：每次判决仅使用 isActive=true 的那一条
 * - 无活跃规则组或不匹配 → 回退默认相似度判决
 */
public class JudgmentRule {

    private int id;
    private String name;

    /** @deprecated 向后兼容，v13 后不再从 DB 映射 */
    @Deprecated
    private RuleTarget target;
    /** @deprecated 向后兼容，v13 后不再从 DB 映射 */
    @Deprecated
    private RuleMethod method;
    /** @deprecated 向后兼容，v13 后不再从 DB 映射 */
    @Deprecated
    private String expression;

    private List<RuleCondition> conditions; // 条件列表（从 judgment_rule_conditions 表加载）
    private boolean enabled = true;
    private boolean isActive = false;       // 是否为当前活跃规则组（全局唯一）
    private Color successColor;             // 匹配成功时的标记颜色（默认红色=越权）
    private Color failureColor;             // 匹配失败时的标记颜色（默认绿色=安全）
    private String successNote;             // 匹配成功时的备注
    private String failureNote;             // 匹配失败时的备注
    private String remark;                  // 规则备注说明
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
     * 获取有效条件列表（v13：直接返回 conditions，不再从遗留字段包装）
     */
    public List<RuleCondition> getEffectiveConditions() {
        if (conditions == null || conditions.isEmpty()) {
            return new ArrayList<>();
        }
        // 仅返回已启用的条件
        List<RuleCondition> enabled = new ArrayList<>();
        for (RuleCondition cond : conditions) {
            if (cond.isEnabled()) {
                enabled.add(cond);
            }
        }
        return enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    // ==================== 向后兼容的 priority（已废弃） ====================

    /** @deprecated v13 后使用 isActive 替代 */
    @Deprecated
    public int getPriority() {
        return 1;
    }

    /** @deprecated v13 后使用 setActive 替代 */
    @Deprecated
    public void setPriority(int priority) {
        // no-op: v13 移除了 priority 字段
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
     * 检查规则组是否有效（至少有一条有效条件）
     */
    public boolean isValid() {
        List<RuleCondition> effective = getEffectiveConditions();
        if (effective.isEmpty()) return false;
        for (RuleCondition cond : effective) {
            if (cond.isValid()) return true;
        }
        return false;
    }

    /**
     * 获取条件摘要（用于 UI 表格展示）
     */
    public String getConditionSummary() {
        List<RuleCondition> effective = getEffectiveConditions();
        if (effective.isEmpty()) return "（无）";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(effective.size(), 3); i++) {
            RuleCondition cond = effective.get(i);
            if (i > 0) sb.append(" AND ");
            String prefix = cond.isNegate() ? "NOT " : "";
            sb.append(prefix)
              .append(cond.getTarget() != null ? cond.getTarget().getDisplayName() : "?")
              .append(" ")
              .append(cond.getMethod() != null ? cond.getMethod().getDisplayName() : "?")
              .append(" ")
              .append(truncate(cond.getExpression(), 20));
        }
        if (effective.size() > 3) {
            sb.append(" ...+").append(effective.size() - 3);
        }
        return sb.toString();
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
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
