package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;

import javax.swing.*;
import java.awt.*;

/**
 * 令牌位置编辑对话框
 */
public class TokenLocationEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JComboBox<TokenLocationType> typeCombo;
    private final JTextField expressionField;
    private final JTextField descriptionField;
    private final JCheckBox persistToGlobalCheckbox;
    private final JCheckBox enabledCheckbox;

    public TokenLocationEditDialog(Frame owner, String title, TokenLocation existing) {
        super(owner, title, true);
        setSize(500, 280);
        setLocationRelativeTo(owner);
        setResizable(true);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 类型
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("类型:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        typeCombo = new JComboBox<>(TokenLocationType.values());
        mainPanel.add(typeCombo, gbc);

        // 表达式
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        mainPanel.add(new JLabel("表达式:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        expressionField = new JTextField(25);
        mainPanel.add(expressionField, gbc);

        // 描述
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        mainPanel.add(new JLabel("描述:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        descriptionField = new JTextField(25);
        mainPanel.add(descriptionField, gbc);

        // 持久化到全局
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        mainPanel.add(new JLabel("持久化到全局:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        persistToGlobalCheckbox = new JCheckBox("是", true);
        mainPanel.add(persistToGlobalCheckbox, gbc);

        // 是否启用
        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0;
        mainPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        enabledCheckbox = new JCheckBox("是", true);
        mainPanel.add(enabledCheckbox, gbc);

        // 按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");
        okBtn.addActionListener(e -> {
            if (expressionField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "表达式不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);

        // 填充现有数据
        if (existing != null) {
            typeCombo.setSelectedItem(existing.getType());
            expressionField.setText(existing.getExpression());
            descriptionField.setText(existing.getDescription());
            persistToGlobalCheckbox.setSelected(existing.isPersistToGlobal());
            enabledCheckbox.setSelected(existing.isEnabled());
        }

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(mainPanel, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public TokenLocationType getLocationType() {
        return (TokenLocationType) typeCombo.getSelectedItem();
    }

    public String getExpression() {
        return expressionField.getText().trim();
    }

    public String getDescription() {
        return descriptionField.getText().trim();
    }

    public boolean isPersistToGlobal() {
        return persistToGlobalCheckbox.isSelected();
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }
}
