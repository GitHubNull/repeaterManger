package org.oxff.repeater.ui.config;

import org.oxff.repeater.api.ApiExtractionRule;
import org.oxff.repeater.api.ApiRuleMethod;
import org.oxff.repeater.api.ApiRuleSource;
import org.oxff.repeater.i18n.I18nManager;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.regex.Pattern;

/**
 * API规则编辑对话框 - 用于添加或编辑API提取规则
 */
public class ApiRuleEditDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private boolean confirmed = false;
    private final ApiExtractionRule rule;

    // 表单组件
    private JSpinner prioritySpinner;
    private JTextField nameField;
    private JComboBox<ApiRuleSource> sourceCombo;
    private JComboBox<ApiRuleMethod> methodCombo;
    private JTextField expressionField;
    private JCheckBox enabledCheckbox;
    private JTextField remarkField;
    private JCheckBox persistentCheckbox;
    private JCheckBox globalCheckbox;

    /**
     * 显示规则编辑对话框
     *
     * @param parent  父组件
     * @param rule    要编辑的规则对象
     * @param isNew   是否为新建规则
     * @return true表示用户点击了确定
     */
    public static boolean showDialog(Component parent, ApiExtractionRule rule, boolean isNew) {
        ApiRuleEditDialog dialog = new ApiRuleEditDialog(parent, rule, isNew);
        dialog.setVisible(true);
        return dialog.confirmed;
    }

    private ApiRuleEditDialog(Component parent, ApiExtractionRule rule, boolean isNew) {
        super((Frame) SwingUtilities.getWindowAncestor(parent),
                isNew ? I18nManager.tr("api.rule.dialog.add") : I18nManager.tr("api.rule.dialog.edit"), true);
        this.rule = rule;
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel formPanel = createFormPanel();
        JPanel btnPanel = createButtonPanel();

        add(formPanel, BorderLayout.CENTER);
        add(btnPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(getOwner());
    }

    private JPanel createFormPanel() {
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints fc = new GridBagConstraints();
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.insets = new Insets(5, 5, 5, 5);

        // 优先级
        fc.gridx = 0; fc.gridy = 0; fc.weightx = 0;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.priority")), fc);
        fc.gridx = 1; fc.gridy = 0; fc.weightx = 1.0; fc.gridwidth = 2;
        prioritySpinner = new JSpinner(new SpinnerNumberModel(rule.getPriority(), 1, 999, 1));
        formPanel.add(prioritySpinner, fc);

        // 名称
        fc.gridx = 0; fc.gridy = 1; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.name")), fc);
        fc.gridx = 1; fc.gridy = 1; fc.weightx = 1.0; fc.gridwidth = 2;
        nameField = new JTextField(rule.getName(), 30);
        nameField.setToolTipText(I18nManager.tr("api.rule.dialog.name.tooltip"));
        formPanel.add(nameField, fc);

        // 来源
        fc.gridx = 0; fc.gridy = 2; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.source")), fc);
        fc.gridx = 1; fc.gridy = 2; fc.weightx = 1.0; fc.gridwidth = 2;
        sourceCombo = new JComboBox<>(ApiRuleSource.values());
        sourceCombo.setRenderer(new DefaultListCellRenderer() {
            private static final long serialVersionUID = 1L;
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof ApiRuleSource) {
                    setText(((ApiRuleSource) value).getDisplayName());
                }
                return this;
            }
        });
        sourceCombo.setSelectedItem(rule.getSource());
        formPanel.add(sourceCombo, fc);

        // 方法
        fc.gridx = 0; fc.gridy = 3; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.method")), fc);
        fc.gridx = 1; fc.gridy = 3; fc.weightx = 1.0; fc.gridwidth = 2;
        methodCombo = new JComboBox<>();
        methodCombo.setRenderer(new DefaultListCellRenderer() {
            private static final long serialVersionUID = 1L;
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof ApiRuleMethod) {
                    setText(((ApiRuleMethod) value).getDisplayName());
                }
                return this;
            }
        });
        updateMethodCombo(methodCombo, (ApiRuleSource) sourceCombo.getSelectedItem(), rule.getMethod());
        sourceCombo.addActionListener(e -> {
            ApiRuleSource selected = (ApiRuleSource) sourceCombo.getSelectedItem();
            updateMethodCombo(methodCombo, selected, null);
        });
        formPanel.add(methodCombo, fc);

        // 表达式
        fc.gridx = 0; fc.gridy = 4; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.expression")), fc);
        fc.gridx = 1; fc.gridy = 4; fc.weightx = 1.0; fc.gridwidth = 2;
        expressionField = new JTextField(rule.getExpression(), 30);
        formPanel.add(expressionField, fc);

        // 表达式提示
        fc.gridx = 1; fc.gridy = 5; fc.weightx = 1.0; fc.gridwidth = 2;
        JLabel expressionHintLabel = new JLabel(" ");
        expressionHintLabel.setForeground(new Color(120, 120, 120));
        expressionHintLabel.setFont(expressionHintLabel.getFont().deriveFont(Font.PLAIN, 11f));
        formPanel.add(expressionHintLabel, fc);
        methodCombo.addActionListener(e -> {
            ApiRuleMethod selected = (ApiRuleMethod) methodCombo.getSelectedItem();
            updateExpressionHintLabel(expressionHintLabel, selected);
        });
        updateExpressionHintLabel(expressionHintLabel, rule.getMethod());

        // 启用
        fc.gridx = 0; fc.gridy = 6; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.enabled")), fc);
        fc.gridx = 1; fc.gridy = 6; fc.weightx = 1.0; fc.gridwidth = 2;
        enabledCheckbox = new JCheckBox(I18nManager.tr("api.rule.dialog.enable"), rule.isEnabled());
        formPanel.add(enabledCheckbox, fc);

        // 备注
        fc.gridx = 0; fc.gridy = 7; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.remark")), fc);
        fc.gridx = 1; fc.gridy = 7; fc.weightx = 1.0; fc.gridwidth = 2;
        remarkField = new JTextField(rule.getRemark(), 30);
        remarkField.setToolTipText(I18nManager.tr("api.rule.dialog.remark.tooltip"));
        formPanel.add(remarkField, fc);

        // 持久化选项
        fc.gridx = 0; fc.gridy = 8; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel(I18nManager.tr("api.rule.dialog.persist")), fc);
        fc.gridx = 1; fc.gridy = 8; fc.weightx = 1.0; fc.gridwidth = 2;
        JPanel persistPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        persistentCheckbox = new JCheckBox(I18nManager.tr("api.rule.dialog.persistProject"), rule.isPersistent());
        persistentCheckbox.setToolTipText(I18nManager.tr("api.rule.dialog.persistProject.tooltip"));
        globalCheckbox = new JCheckBox(I18nManager.tr("api.rule.dialog.persistGlobal"), rule.isGlobal());
        globalCheckbox.setToolTipText(I18nManager.tr("api.rule.dialog.persistGlobal.tooltip"));
        persistPanel.add(persistentCheckbox);
        persistPanel.add(globalCheckbox);
        formPanel.add(persistPanel, fc);

        // 持久化提示
        fc.gridx = 1; fc.gridy = 9; fc.weightx = 1.0; fc.gridwidth = 2;
        JLabel persistHintLabel = new JLabel(I18nManager.tr("api.rule.dialog.persistHint"));
        persistHintLabel.setForeground(new Color(120, 120, 120));
        persistHintLabel.setFont(persistHintLabel.getFont().deriveFont(Font.PLAIN, 11f));
        formPanel.add(persistHintLabel, fc);

        return formPanel;
    }

    private JPanel createButtonPanel() {
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton okBtn = new JButton(I18nManager.tr("common.ok"));
        okBtn.addActionListener(e -> {
            // 校验
            ApiRuleSource source = (ApiRuleSource) sourceCombo.getSelectedItem();
            ApiRuleMethod method = (ApiRuleMethod) methodCombo.getSelectedItem();
            String expression = expressionField.getText().trim();

            if (expression.isEmpty()) {
                JOptionPane.showMessageDialog(ApiRuleEditDialog.this,
                        I18nManager.tr("api.rule.dialog.expr.empty"),
                        I18nManager.tr("api.rule.dialog.validation.failed"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (method != null && !ApiRuleMethod.isValidForSource(method, source)) {
                JOptionPane.showMessageDialog(ApiRuleEditDialog.this,
                        I18nManager.tr("api.rule.dialog.method.not.applicable", method.getDisplayName(), source.getDisplayName()),
                        I18nManager.tr("api.rule.dialog.validation.failed"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 正则预校验
            if (method == ApiRuleMethod.REGEX) {
                try {
                    Pattern.compile(expression);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ApiRuleEditDialog.this,
                            I18nManager.tr("api.rule.dialog.regex.error", ex.getMessage()),
                            I18nManager.tr("api.rule.dialog.validation.failed"), JOptionPane.WARNING_MESSAGE);
                    return;
                }
            }

            rule.setPriority((Integer) prioritySpinner.getValue());
            rule.setName(nameField.getText().trim());
            rule.setSource(source);
            rule.setMethod(method);
            rule.setExpression(expression);
            rule.setEnabled(enabledCheckbox.isSelected());
            rule.setRemark(remarkField.getText().trim());
            rule.setPersistent(persistentCheckbox.isSelected());
            rule.setGlobal(globalCheckbox.isSelected());
            confirmed = true;
            dispose();
        });
        JButton cancelBtn = new JButton(I18nManager.tr("common.cancel"));
        cancelBtn.addActionListener(e -> dispose());
        btnPanel.add(okBtn);
        btnPanel.add(cancelBtn);
        return btnPanel;
    }

    /**
     * 根据来源更新方法下拉框选项
     */
    static void updateMethodCombo(JComboBox<ApiRuleMethod> methodCombo, ApiRuleSource source, ApiRuleMethod currentMethod) {
        methodCombo.removeAllItems();
        List<ApiRuleMethod> methods = ApiRuleMethod.getMethodsForSource(source);
        for (ApiRuleMethod m : methods) {
            methodCombo.addItem(m);
        }
        if (currentMethod != null && methods.contains(currentMethod)) {
            methodCombo.setSelectedItem(currentMethod);
        }
    }

    /**
     * 更新表达式提示标签
     */
    static void updateExpressionHintLabel(JLabel label, ApiRuleMethod method) {
        if (method == null) {
            label.setText(" ");
            return;
        }
        switch (method) {
            case REGEX:
                label.setText(I18nManager.tr("api.rule.dialog.hint.regex"));
                break;
            case SUBSTR:
                label.setText(I18nManager.tr("api.rule.dialog.hint.substr"));
                break;
            case JSON_PATH:
                label.setText(I18nManager.tr("api.rule.dialog.hint.jsonPath"));
                break;
            case XPATH:
                label.setText(I18nManager.tr("api.rule.dialog.hint.xpath"));
                break;
            default:
                label.setText(" ");
        }
    }

    /**
     * 判断表达式是否为占位符文本
     */
    static boolean isExpressionPlaceholder(String text) {
        return text.equals("正则表达式") || text.equals("START,END") ||
                text.equals("$.field.name") || text.equals("/root/element");
    }
}
