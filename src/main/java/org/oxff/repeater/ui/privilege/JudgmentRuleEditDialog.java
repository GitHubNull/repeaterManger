package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则编辑对话框（支持多条件 AND 组合编辑）
 */
public class JudgmentRuleEditDialog extends JDialog {

    private boolean confirmed = false;
    private JudgmentRule editingRule;

    private JTextField nameField;
    private JCheckBox enabledCheckbox;
    private JButton successColorButton;
    private JButton failureColorButton;
    private JTextField successNoteField;
    private JTextField failureNoteField;
    private JTextArea remarkArea;

    private Color successColor;
    private Color failureColor;

    /** 条件列表面板（动态行） */
    private JPanel conditionsPanel;
    /** 条件行组件列表 */
    private final List<ConditionRow> conditionRows = new ArrayList<>();

    public JudgmentRuleEditDialog(Frame owner, String title, JudgmentRule rule) {
        super(owner, title, true);
        this.editingRule = rule;
        initComponents();
        if (rule != null) {
            populateFields(rule);
        }
        pack();
        setLocationRelativeTo(owner);
        setResizable(true);
    }

    // ==================== UI初始化 ====================

    private void initComponents() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // 名称
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("名称:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        nameField = new JTextField(30);
        mainPanel.add(nameField, gbc);
        gbc.gridwidth = 1;

        row++;
        // 条件列表标签
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.gridwidth = 4;
        mainPanel.add(new JLabel("判决条件（组内纯 AND，支持 NOT 取反）:"), gbc);
        gbc.gridwidth = 1;

        row++;
        // 条件列表面板（可滚动）
        conditionsPanel = new JPanel();
        conditionsPanel.setLayout(new BoxLayout(conditionsPanel, BoxLayout.Y_AXIS));
        JScrollPane conditionsScroll = new JScrollPane(conditionsPanel);
        conditionsScroll.setPreferredSize(new Dimension(780, 180));
        conditionsScroll.setBorder(BorderFactory.createEtchedBorder());
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 0.3;
        mainPanel.add(conditionsScroll, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weighty = 0;
        gbc.gridwidth = 1;

        row++;
        // 添加条件按钮
        JPanel addButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addConditionButton = new JButton("+ 添加条件");
        addConditionButton.addActionListener(e -> addConditionRow(null));
        addButtonPanel.add(addConditionButton);
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 4;
        mainPanel.add(addButtonPanel, gbc);
        gbc.gridwidth = 1;

        row++;
        // 启用
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        enabledCheckbox = new JCheckBox();
        enabledCheckbox.setSelected(true);
        mainPanel.add(enabledCheckbox, gbc);
        gbc.gridwidth = 1;

        row++;
        // 越权颜色 + 安全颜色
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("越权颜色:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        successColor = Color.RED;
        successColorButton = new JButton("  ");
        successColorButton.setBackground(successColor);
        successColorButton.setOpaque(true);
        successColorButton.setBorderPainted(false);
        successColorButton.addActionListener(e -> chooseColor(successColorButton, "越权标记颜色", true));
        mainPanel.add(successColorButton, gbc);

        gbc.gridx = 2; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("安全颜色:"), gbc);
        gbc.gridx = 3; gbc.gridy = row; gbc.weightx = 1;
        failureColor = new Color(144, 238, 144);
        failureColorButton = new JButton("  ");
        failureColorButton.setBackground(failureColor);
        failureColorButton.setOpaque(true);
        failureColorButton.setBorderPainted(false);
        failureColorButton.addActionListener(e -> chooseColor(failureColorButton, "安全标记颜色", false));
        mainPanel.add(failureColorButton, gbc);

        row++;
        // 越权备注
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("越权备注:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        successNoteField = new JTextField(30);
        mainPanel.add(successNoteField, gbc);
        gbc.gridwidth = 1;

        row++;
        // 安全备注
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("安全备注:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        failureNoteField = new JTextField(30);
        mainPanel.add(failureNoteField, gbc);
        gbc.gridwidth = 1;

        row++;
        // 备注
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(new JLabel("备注:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 0.2;
        remarkArea = new JTextArea(3, 30);
        remarkArea.setLineWrap(true);
        mainPanel.add(new JScrollPane(remarkArea), gbc);
        gbc.gridwidth = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weighty = 0;

        row++;
        // 按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");
        okButton.addActionListener(e -> onOk());
        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4; gbc.weightx = 1;
        mainPanel.add(buttonPanel, gbc);

        setContentPane(new JScrollPane(mainPanel));
        setMinimumSize(new Dimension(850, 550));
    }

    // ==================== 条件行构建 ====================

    /**
     * 构建一条条件行（v13：移除 operator，纯 AND）
     */
    private JPanel buildConditionRow(int index, RuleCondition condition) {
        JPanel rowPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(2, 3, 2, 3);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.NONE;
        gc.weighty = 0;

        // NOT 复选框
        JCheckBox negateCheckbox = new JCheckBox("非");
        negateCheckbox.setToolTipText("勾选后取反当前条件的匹配结果");

        // 目标
        JComboBox<RuleTarget> targetCombo = new JComboBox<>(RuleTarget.values());
        targetCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int idx,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, idx, isSelected, cellHasFocus);
                if (value instanceof RuleTarget t) {
                    setText(t.getDisplayName());
                }
                return this;
            }
        });
        targetCombo.setPrototypeDisplayValue(RuleTarget.RESPONSE_TIME);

        // 方法
        JComboBox<RuleMethod> methodCombo = new JComboBox<>(RuleMethod.values());
        methodCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int idx,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, idx, isSelected, cellHasFocus);
                if (value instanceof RuleMethod m) {
                    setText(m.getDisplayName());
                }
                return this;
            }
        });
        methodCombo.setPrototypeDisplayValue(RuleMethod.REGEX);

        // LENGTH_DIFF 联动
        methodCombo.addActionListener(e -> {
            if (methodCombo.getSelectedItem() == RuleMethod.LENGTH_DIFF) {
                if (targetCombo.getSelectedItem() != RuleTarget.RESPONSE_BODY) {
                    targetCombo.setSelectedItem(RuleTarget.RESPONSE_BODY);
                }
            }
        });

        // 目标联动方法过滤
        targetCombo.addActionListener(e -> filterMethodsForTarget(targetCombo, methodCombo));

        // 表达式（自动填充剩余空间）
        JTextField expressionField = new JTextField(20);

        // 删除按钮
        JButton deleteButton = new JButton("✕");
        deleteButton.setToolTipText("删除此条件");
        deleteButton.setMargin(new Insets(0, 0, 0, 0));

        // === GridBagLayout 布局：固定列宽度自适应，表达式列自动填充 ===
        gc.gridx = 0; gc.weightx = 0;
        rowPanel.add(negateCheckbox, gc);
        gc.gridx = 1; gc.weightx = 0;
        rowPanel.add(targetCombo, gc);
        gc.gridx = 2; gc.weightx = 0;
        rowPanel.add(methodCombo, gc);
        gc.gridx = 3; gc.weightx = 1; gc.fill = GridBagConstraints.HORIZONTAL;
        rowPanel.add(expressionField, gc);
        gc.fill = GridBagConstraints.NONE;
        gc.gridx = 4; gc.weightx = 0;
        rowPanel.add(deleteButton, gc);

        // 设置初始值
        if (condition != null) {
            negateCheckbox.setSelected(condition.isNegate());
            if (condition.getTarget() != null) targetCombo.setSelectedItem(condition.getTarget());
            if (condition.getMethod() != null) methodCombo.setSelectedItem(condition.getMethod());
            if (condition.getExpression() != null) expressionField.setText(condition.getExpression());
            filterMethodsForTarget(targetCombo, methodCombo);
        }

        ConditionRow row = new ConditionRow(index, rowPanel, negateCheckbox,
                targetCombo, methodCombo, expressionField, deleteButton);
        conditionRows.add(row);

        deleteButton.addActionListener(e -> {
            if (conditionRows.size() <= 1) {
                JOptionPane.showMessageDialog(this, "至少需要保留一条条件", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            removeConditionRow(row);
        });

        return rowPanel;
    }

    /**
     * 添加一条条件行
     */
    private void addConditionRow(RuleCondition condition) {
        int index = conditionRows.size();
        JPanel row = buildConditionRow(index, condition);
        conditionsPanel.add(row);
        conditionsPanel.revalidate();
        conditionsPanel.repaint();
    }

    /**
     * 删除一条条件行
     */
    private void removeConditionRow(ConditionRow row) {
        conditionsPanel.remove(row.rowPanel);
        conditionRows.remove(row);
        for (int i = 0; i < conditionRows.size(); i++) {
            conditionRows.get(i).rowPanel.revalidate();
        }
        conditionsPanel.revalidate();
        conditionsPanel.repaint();
    }

    /**
     * 根据目标过滤方法列表
     */
    private void filterMethodsForTarget(JComboBox<RuleTarget> targetCombo, JComboBox<RuleMethod> methodCombo) {
        RuleTarget target = (RuleTarget) targetCombo.getSelectedItem();
        if (target == null) return;

        RuleMethod currentMethod = (RuleMethod) methodCombo.getSelectedItem();
        methodCombo.removeAllItems();

        switch (target) {
            case SIMILARITY:
            case RESPONSE_TIME:
                // 仅数值方法
                methodCombo.addItem(RuleMethod.GREATER_THAN);
                methodCombo.addItem(RuleMethod.LESS_THAN);
                methodCombo.addItem(RuleMethod.NUMERIC_EQUALS);
                break;
            case STATUS_CODE:
                // 排除 LENGTH_DIFF
                for (RuleMethod m : RuleMethod.values()) {
                    if (m != RuleMethod.LENGTH_DIFF) {
                        methodCombo.addItem(m);
                    }
                }
                break;
            case RESPONSE_BODY:
            case RESPONSE_HEADER:
                // 所有方法
                for (RuleMethod m : RuleMethod.values()) {
                    methodCombo.addItem(m);
                }
                break;
        }

        // 恢复选中
        if (currentMethod != null) {
            for (int i = 0; i < methodCombo.getItemCount(); i++) {
                if (methodCombo.getItemAt(i) == currentMethod) {
                    methodCombo.setSelectedIndex(i);
                    break;
                }
            }
        }

        // 重建模型后重新设置原型值，确保宽度不缩水
        methodCombo.setPrototypeDisplayValue(RuleMethod.REGEX);
    }

    // ==================== 数据加载与保存 ====================

    private void populateFields(JudgmentRule rule) {
        if (rule.getName() != null) nameField.setText(rule.getName());
        enabledCheckbox.setSelected(rule.isEnabled());
        if (rule.getSuccessColor() != null) {
            successColor = rule.getSuccessColor();
            successColorButton.setBackground(successColor);
        }
        if (rule.getFailureColor() != null) {
            failureColor = rule.getFailureColor();
            failureColorButton.setBackground(failureColor);
        }
        if (rule.getSuccessNote() != null) successNoteField.setText(rule.getSuccessNote());
        if (rule.getFailureNote() != null) failureNoteField.setText(rule.getFailureNote());
        if (rule.getRemark() != null) remarkArea.setText(rule.getRemark());

        // 加载条件列表
        List<RuleCondition> conditions = rule.getEffectiveConditions();
        if (conditions != null && !conditions.isEmpty()) {
            for (RuleCondition cond : conditions) {
                addConditionRow(cond);
            }
        }

        // 确保至少有一行
        if (conditionRows.isEmpty()) {
            addConditionRow(null);
        }
    }

    private void chooseColor(JButton button, String title, boolean isSuccessColor) {
        Color current = isSuccessColor ? successColor : failureColor;
        Color chosen = JColorChooser.showDialog(this, title, current);
        if (chosen != null) {
            button.setBackground(chosen);
            if (isSuccessColor) {
                successColor = chosen;
            } else {
                failureColor = chosen;
            }
        }
    }

    private void onOk() {
        // 校验：至少一条条件
        if (conditionRows.isEmpty()) {
            JOptionPane.showMessageDialog(this, "至少需要一条判决条件", "验证错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 校验：每条条件的表达式非空
        for (int i = 0; i < conditionRows.size(); i++) {
            ConditionRow row = conditionRows.get(i);
            String expr = row.expressionField.getText().trim();
            if (expr.isEmpty()) {
                JOptionPane.showMessageDialog(this, "第 " + (i + 1) + " 条条件的表达式不能为空",
                        "验证错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // SIMILARITY 校验
            RuleTarget target = (RuleTarget) row.targetCombo.getSelectedItem();
            if (target == RuleTarget.SIMILARITY) {
                try {
                    double val = Double.parseDouble(expr);
                    if (val < 0.0 || val > 1.0) {
                        JOptionPane.showMessageDialog(this, "相似度条件表达式必须在 0.0~1.0 范围内",
                                "验证错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                } catch (NumberFormatException e) {
                    JOptionPane.showMessageDialog(this, "相似度条件表达式必须为数值（如 0.90）",
                            "验证错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
        }

        // LENGTH_DIFF 防御性校验
        for (ConditionRow row : conditionRows) {
            if (row.methodCombo.getSelectedItem() == RuleMethod.LENGTH_DIFF
                    && row.targetCombo.getSelectedItem() != RuleTarget.RESPONSE_BODY) {
                row.targetCombo.setSelectedItem(RuleTarget.RESPONSE_BODY);
            }
        }

        confirmed = true;
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    // ==================== 公开获取方法 ====================

    public String getRuleName() {
        return nameField.getText().trim();
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }

    public Color getSuccessColor() {
        return successColor;
    }

    public Color getFailureColor() {
        return failureColor;
    }

    public String getSuccessNote() {
        return successNoteField.getText().trim();
    }

    public String getFailureNote() {
        return failureNoteField.getText().trim();
    }

    public String getRemark() {
        return remarkArea.getText().trim();
    }

    /**
     * 获取所有条件列表
     */
    public List<RuleCondition> getConditions() {
        List<RuleCondition> conditions = new ArrayList<>();
        for (ConditionRow row : conditionRows) {
            conditions.add(row.toCondition());
        }
        return conditions;
    }

    /**
     * 从对话框创建规则对象
     */
    public JudgmentRule toRule() {
        JudgmentRule rule = new JudgmentRule();
        rule.setName(getRuleName());
        rule.setConditions(getConditions());
        rule.setEnabled(isEnabled());
        rule.setSuccessColor(getSuccessColor());
        rule.setFailureColor(getFailureColor());
        rule.setSuccessNote(getSuccessNote());
        rule.setFailureNote(getFailureNote());
        rule.setRemark(getRemark());
        if (editingRule != null) {
            rule.setId(editingRule.getId());
            rule.setGlobal(editingRule.isGlobal());
        }
        return rule;
    }
}
