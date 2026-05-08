package oxff.top.ui.privilege;

import oxff.top.privilege.model.JudgmentRule;
import oxff.top.privilege.model.RuleMethod;
import oxff.top.privilege.model.RuleTarget;

import javax.swing.*;
import java.awt.*;

/**
 * 判决规则编辑对话框
 * 用于添加/编辑判决规则
 */
public class JudgmentRuleEditDialog extends JDialog {

    private boolean confirmed = false;
    private JudgmentRule editingRule;

    private JTextField nameField;
    private JComboBox<RuleTarget> targetCombo;
    private JComboBox<RuleMethod> methodCombo;
    private JTextField expressionField;
    private JCheckBox enabledCheckbox;
    private JSpinner prioritySpinner;
    private JButton successColorButton;
    private JButton failureColorButton;
    private JTextField successNoteField;
    private JTextField failureNoteField;
    private JTextArea remarkArea;

    private Color successColor;
    private Color failureColor;

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
        // 目标
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("目标:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        targetCombo = new JComboBox<>(RuleTarget.values());
        targetCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof RuleTarget t) {
                    setText(t.getDisplayName());
                }
                return this;
            }
        });
        mainPanel.add(targetCombo, gbc);

        // 方法
        gbc.gridx = 2; gbc.gridy = row; gbc.weightx = 1;
        methodCombo = new JComboBox<>(RuleMethod.values());
        methodCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof RuleMethod m) {
                    setText(m.getDisplayName());
                }
                return this;
            }
        });
        mainPanel.add(methodCombo, gbc);

        row++;
        // 表达式
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("表达式:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 3;
        expressionField = new JTextField(30);
        mainPanel.add(expressionField, gbc);
        gbc.gridwidth = 1;

        row++;
        // 启用 + 优先级
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 0;
        enabledCheckbox = new JCheckBox();
        enabledCheckbox.setSelected(true);
        mainPanel.add(enabledCheckbox, gbc);

        gbc.gridx = 2; gbc.gridy = row; gbc.weightx = 0;
        mainPanel.add(new JLabel("优先级:"), gbc);
        gbc.gridx = 3; gbc.gridy = row; gbc.weightx = 1;
        prioritySpinner = new JSpinner(new SpinnerNumberModel(1, 1, 100, 1));
        mainPanel.add(prioritySpinner, gbc);

        row++;
        // 成功颜色 + 按钮
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
        gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 1;
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
        setMinimumSize(new Dimension(500, 400));
    }

    private void populateFields(JudgmentRule rule) {
        if (rule.getName() != null) nameField.setText(rule.getName());
        if (rule.getTarget() != null) targetCombo.setSelectedItem(rule.getTarget());
        if (rule.getMethod() != null) methodCombo.setSelectedItem(rule.getMethod());
        if (rule.getExpression() != null) expressionField.setText(rule.getExpression());
        enabledCheckbox.setSelected(rule.isEnabled());
        prioritySpinner.setValue(rule.getPriority());
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
        String expr = expressionField.getText().trim();
        if (expr.isEmpty()) {
            JOptionPane.showMessageDialog(this, "表达式不能为空", "验证错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        confirmed = true;
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    // ==================== 获取编辑结果 ====================

    public String getRuleName() {
        return nameField.getText().trim();
    }

    public RuleTarget getRuleTarget() {
        return (RuleTarget) targetCombo.getSelectedItem();
    }

    public RuleMethod getRuleMethod() {
        return (RuleMethod) methodCombo.getSelectedItem();
    }

    public String getExpression() {
        return expressionField.getText().trim();
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }

    public int getPriority() {
        return (Integer) prioritySpinner.getValue();
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
     * 从对话框创建规则对象
     */
    public JudgmentRule toRule() {
        JudgmentRule rule = new JudgmentRule();
        rule.setName(getRuleName());
        rule.setTarget(getRuleTarget());
        rule.setMethod(getRuleMethod());
        rule.setExpression(getExpression());
        rule.setEnabled(isEnabled());
        rule.setPriority(getPriority());
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
