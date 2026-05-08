package oxff.top.ui.privilege;

import oxff.top.privilege.SessionManager;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户会话编辑对话框
 * 允许编辑用户名称、颜色、启用状态，以及为每个令牌位置设置值
 */
public class UserSessionEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JCheckBox enabledCheckbox;
    private final JLabel colorPreview;
    private Color selectedColor;

    /** 令牌值输入框映射：tokenLocationId -> JTextField */
    private final Map<Integer, JTextField> tokenValueFields = new LinkedHashMap<>();

    /** 最终的令牌值 */
    private Map<Integer, String> tokenValues = new LinkedHashMap<>();

    public UserSessionEditDialog(Frame owner, String title, UserSession existing) {
        super(owner, title, true);
        setSize(500, 400);
        setLocationRelativeTo(owner);
        setResizable(true);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 名称
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        nameField = new JTextField(20);
        mainPanel.add(nameField, gbc);

        // 颜色
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        mainPanel.add(new JLabel("颜色:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel colorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        colorPreview = new JLabel("  ");
        colorPreview.setOpaque(true);
        colorPreview.setPreferredSize(new Dimension(30, 20));
        colorPreview.setBackground(Color.GRAY);
        JButton colorBtn = new JButton("选择颜色");
        colorBtn.addActionListener(e -> {
            Color c = JColorChooser.showDialog(this, "选择颜色", selectedColor);
            if (c != null) {
                selectedColor = c;
                colorPreview.setBackground(c);
            }
        });
        colorPanel.add(colorPreview);
        colorPanel.add(colorBtn);
        mainPanel.add(colorPanel, gbc);

        // 启用
        gbc.gridx = 0; gbc.gridy = 2;
        mainPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1;
        enabledCheckbox = new JCheckBox("启用此用户会话", true);
        mainPanel.add(enabledCheckbox, gbc);

        // 令牌值区域
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        mainPanel.add(new JLabel("令牌值:"), gbc);

        List<TokenLocation> locations = SessionManager.getInstance().getTokenLocations();
        if (!locations.isEmpty()) {
            JPanel tokenValuesPanel = new JPanel(new GridBagLayout());
            GridBagConstraints tgbc = new GridBagConstraints();
            tgbc.insets = new Insets(3, 3, 3, 3);
            tgbc.fill = GridBagConstraints.HORIZONTAL;

            for (int i = 0; i < locations.size(); i++) {
                TokenLocation loc = locations.get(i);
                tgbc.gridx = 0; tgbc.gridy = i; tgbc.weightx = 0;
                JLabel label = new JLabel(loc.getType().getDisplayName() + " [" + loc.getExpression() + "]:");
                tokenValuesPanel.add(label, tgbc);

                tgbc.gridx = 1; tgbc.weightx = 1.0;
                JTextField valueField = new JTextField(20);
                tokenValuesPanel.add(valueField, tgbc);

                tokenValueFields.put(loc.getId(), valueField);

                // 如果是编辑模式，填充现有值
                if (existing != null) {
                    String existingValue = existing.getTokenValue(loc.getId());
                    if (existingValue != null) {
                        valueField.setText(existingValue);
                    }
                }
            }

            JScrollPane scrollPane = new JScrollPane(tokenValuesPanel);
            scrollPane.setPreferredSize(new Dimension(440, 150));
            gbc.gridy = 4;
            mainPanel.add(scrollPane, gbc);
        } else {
            JLabel noLocationsLabel = new JLabel("请先添加令牌位置");
            gbc.gridy = 4;
            mainPanel.add(noLocationsLabel, gbc);
        }

        gbc.gridwidth = 1;

        // 按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");
        okBtn.addActionListener(e -> {
            if (nameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "名称不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 收集令牌值
            tokenValues = new LinkedHashMap<>();
            for (Map.Entry<Integer, JTextField> entry : tokenValueFields.entrySet()) {
                tokenValues.put(entry.getKey(), entry.getValue().getText());
            }
            confirmed = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);

        // 填充现有数据
        if (existing != null) {
            nameField.setText(existing.getName());
            enabledCheckbox.setSelected(existing.isEnabled());
            if (existing.getColor() != null) {
                selectedColor = existing.getColor();
                colorPreview.setBackground(selectedColor);
            }
        }

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(new JScrollPane(mainPanel), BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getName() {
        return nameField.getText().trim();
    }

    public String getColorHex() {
        if (selectedColor == null) return null;
        return String.format("#%02x%02x%02x", selectedColor.getRed(), selectedColor.getGreen(), selectedColor.getBlue());
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }

    public Map<Integer, String> getTokenValues() {
        return tokenValues;
    }
}
