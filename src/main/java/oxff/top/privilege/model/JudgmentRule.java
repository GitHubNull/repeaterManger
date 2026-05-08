package oxff.top.privilege.model;

import java.awt.Color;

/**
 * 判决规则模型
 * 规则用于判断响应是否表示越权成功
 *
 * 匹配逻辑：规则按priority升序排列，匹配到第一条规则即决定判决结果
 * - 规则匹配成功 → 使用 success_color + success_note
 * - 规则匹配失败 → 使用 failure_color + failure_note
 * - 无规则时 → 回退到默认的相似度+状态码判决
 */
public class JudgmentRule {

    private int id;
    private String name;
    private RuleTarget target;       // 规则应用于响应的哪个部分
    private RuleMethod method;       // 匹配方法
    private String expression;       // 匹配表达式
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
     * 检查规则是否有效（有表达式且有目标和方法）
     */
    public boolean isValid() {
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
