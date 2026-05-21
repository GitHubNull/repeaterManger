package oxff.top.ui.privilege;

import oxff.top.privilege.model.DedupConfig;
import oxff.top.privilege.model.DedupKeepPolicy;
import oxff.top.privilege.model.DedupStrategy;

import javax.swing.*;
import java.awt.*;

/**
 * 去重配置编辑对话框
 * 用于添加或编辑单条去重配置规则
 */
public class DedupConfigEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JComboBox<DedupStrategy> strategyCombo;
    private final JTextField expressionField;
    private final JComboBox<DedupKeepPolicy> keepPolicyCombo;
    private final JSpinner prioritySpinner;
    private final JCheckBox enabledCheckbox;
    private final JRadioButton globalRadio;
    private final JRadioButton sessionRadio;

    public DedupConfigEditDialog(Frame owner, String title, DedupConfig existingConfig) {
        super(owner, title, true);
        setLayout(new BorderLayout(10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        int row = 0;

        // 策略
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("去重策略:"), gbc);
        strategyCombo = new JComboBox<>(DedupStrategy.values());
        strategyCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof DedupStrategy) {
                    setText(((DedupStrategy) value).getDisplayName());
                }
                return this;
            }
        });
        strategyCombo.addActionListener(e -> updateExpressionFieldState());
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(strategyCombo, gbc);
        row++;

        // 表达式
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("表达式:"), gbc);
        expressionField = new JTextField(20);
        expressionField.setToolTipText("当策略为JSON/XML/表单/URL参数时，输入字段名或路径");
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(expressionField, gbc);
        row++;

        // 保留策略
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("保留策略:"), gbc);
        keepPolicyCombo = new JComboBox<>(DedupKeepPolicy.values());
        keepPolicyCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof DedupKeepPolicy) {
                    setText(((DedupKeepPolicy) value).getDisplayName());
                }
                return this;
            }
        });
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(keepPolicyCombo, gbc);
        row++;

        // 优先级
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("优先级:"), gbc);
        prioritySpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 1));
        prioritySpinner.setToolTipText("数字越小优先级越高，1为最高优先级");
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(prioritySpinner, gbc);
        row++;

        // 启用
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("启用:"), gbc);
        enabledCheckbox = new JCheckBox();
        enabledCheckbox.setSelected(true);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(enabledCheckbox, gbc);
        row++;

        // 存储类型
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("存储类型:"), gbc);
        JPanel storagePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        globalRadio = new JRadioButton("全局持久化", true);
        sessionRadio = new JRadioButton("会话级（内存）");
        ButtonGroup storageGroup = new ButtonGroup();
        storageGroup.add(globalRadio);
        storageGroup.add(sessionRadio);
        storagePanel.add(globalRadio);
        storagePanel.add(sessionRadio);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        formPanel.add(storagePanel, gbc);
        row++;

        // 说明标签
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        JLabel tipLabel = new JLabel("提示：全局持久化配置在下次加载插件时自动生效；会话级配置仅在当前会话有效");
        tipLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        formPanel.add(tipLabel, gbc);

        // 填充已有数据
        if (existingConfig != null) {
            strategyCombo.setSelectedItem(existingConfig.getStrategy());
            expressionField.setText(existingConfig.getExpression());
            keepPolicyCombo.setSelectedItem(existingConfig.getKeepPolicy());
            prioritySpinner.setValue(existingConfig.getPriority());
            enabledCheckbox.setSelected(existingConfig.isEnabled());
            if (existingConfig.getStorageType() == DedupConfig.StorageType.GLOBAL) {
                globalRadio.setSelected(true);
            } else {
                sessionRadio.setSelected(true);
            }
        }

        updateExpressionFieldState();

        add(formPanel, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton okButton = new JButton("确定");
        okButton.addActionListener(e -> {
            // 验证：需要表达式的策略不能为空
            DedupStrategy selectedStrategy = (DedupStrategy) strategyCombo.getSelectedItem();
            if (needsExpression(selectedStrategy) && expressionField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "当前去重策略需要填写表达式/字段名", "验证失败", JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // ESC 键关闭
        getRootPane().registerKeyboardAction(
                e -> dispose(),
                KeyStroke.getKeyStroke("ESCAPE"),
                JComponent.WHEN_IN_FOCUSED_WINDOW);

        pack();
        setLocationRelativeTo(owner);
        setMinimumSize(new Dimension(450, getHeight()));
    }

    private void updateExpressionFieldState() {
        DedupStrategy selected = (DedupStrategy) strategyCombo.getSelectedItem();
        boolean needsExpr = needsExpression(selected);
        expressionField.setEnabled(needsExpr);
        if (!needsExpr) {
            expressionField.setText("");
        }
    }

    private boolean needsExpression(DedupStrategy strategy) {
        return strategy == DedupStrategy.JSON_BODY_FIELD
                || strategy == DedupStrategy.XML_BODY_FIELD
                || strategy == DedupStrategy.FORM_FIELD
                || strategy == DedupStrategy.URL_PARAM;
    }

    // ==================== 获取编辑结果 ====================

    public boolean isConfirmed() {
        return confirmed;
    }

    public DedupConfig getConfig() {
        DedupConfig config = new DedupConfig();
        config.setStrategy((DedupStrategy) strategyCombo.getSelectedItem());
        config.setExpression(expressionField.getText().trim());
        config.setKeepPolicy((DedupKeepPolicy) keepPolicyCombo.getSelectedItem());
        config.setPriority((Integer) prioritySpinner.getValue());
        config.setEnabled(enabledCheckbox.isSelected());
        config.setStorageType(globalRadio.isSelected()
                ? DedupConfig.StorageType.GLOBAL : DedupConfig.StorageType.SESSION);
        return config;
    }
}
