package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;
import org.oxff.repeater.privilege.model.UserSession;
import org.oxff.repeater.utils.ScrollPaneWheelForwarder;
import org.oxff.repeater.utils.TextLineNumber;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户会话编辑对话框
 * 允许编辑用户名称、颜色、启用状态、方案选择，以及为每个字段定义设置值
 * 字段值区域仅在选中方案后显示
 */
public class UserSessionEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JCheckBox enabledCheckbox;
    private final JLabel colorPreview;
    private Color selectedColor;

    /** 方案选择下拉框 */
    private JComboBox<String> schemeComboBox;
    /** 方案名称到ID的映射 */
    private Map<String, Integer> schemeNameToId = new LinkedHashMap<>();

    /** 字段值输入框映射：fieldId -> JTextArea */
    private final Map<Integer, JTextArea> fieldInputAreas = new LinkedHashMap<>();

    /** 收集所有内层 JScrollPane，用于安装滚轮转发器 */
    private final List<JScrollPane> innerScrollPanes = new ArrayList<>();

    /** 最终的字段值 */
    private Map<Integer, String> fieldValues = new LinkedHashMap<>();

    /** 字段值容器面板 */
    private JPanel fieldValuesPanel;

    /** 字段值区域的标签 */
    private JLabel fieldValuesLabel;

    /** 外层滚动面板 */
    private JScrollPane outerScrollPane;

    /** 当前会话已有的字段值（编辑模式） */
    private Map<Integer, String> existingFieldValues = new LinkedHashMap<>();

    public UserSessionEditDialog(Frame owner, String title, UserSession existing) {
        super(owner, title, true);
        setSize(700, 600);
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

        // 方案选择
        gbc.gridx = 0; gbc.gridy = 3;
        mainPanel.add(new JLabel("方案:"), gbc);
        gbc.gridx = 1;
        SessionManager sm = SessionManager.getInstance();
        List<Scheme> schemes = sm.getSchemes();
        schemeComboBox = new JComboBox<>();
        schemeComboBox.addItem("-- 请选择方案 --");
        schemeNameToId.clear();
        for (Scheme scheme : schemes) {
            schemeComboBox.addItem(scheme.getName());
            schemeNameToId.put(scheme.getName(), scheme.getId());
        }
        // 选择变更时刷新字段值区域
        schemeComboBox.addActionListener(e -> refreshFieldValuesPanel());
        mainPanel.add(schemeComboBox, gbc);

        // 字段值区域标签
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        fieldValuesLabel = new JLabel("字段值:");
        fieldValuesLabel.setVisible(false);
        mainPanel.add(fieldValuesLabel, gbc);

        // 字段值容器面板
        fieldValuesPanel = new JPanel();
        fieldValuesPanel.setLayout(new BoxLayout(fieldValuesPanel, BoxLayout.Y_AXIS));

        gbc.gridy = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(8, 10, 8, 10);
        mainPanel.add(fieldValuesPanel, gbc);

        gbc.gridwidth = 1;
        gbc.weighty = 0;

        // 按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");
        okBtn.addActionListener(e -> {
            if (nameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "名称不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 收集字段值
            fieldValues = new LinkedHashMap<>();
            for (Map.Entry<Integer, JTextArea> entry : fieldInputAreas.entrySet()) {
                fieldValues.put(entry.getKey(), entry.getValue().getText());
            }
            confirmed = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);

        getContentPane().setLayout(new BorderLayout());
        outerScrollPane = new JScrollPane(mainPanel);
        getContentPane().add(outerScrollPane, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);

        // 填充现有数据
        if (existing != null) {
            nameField.setText(existing.getName());
            enabledCheckbox.setSelected(existing.isEnabled());
            if (existing.getColor() != null) {
                selectedColor = existing.getColor();
                colorPreview.setBackground(selectedColor);
            }
            // 保存现有字段值
            Map<Integer, String> existingVals = existing.getFieldValues();
            existingFieldValues = existingVals != null ? new LinkedHashMap<>(existingVals) : new LinkedHashMap<>();
            // 方案选择（最后执行，因为会触发 refreshFieldValuesPanel() 使用 outerScrollPane）
            if (existing.getSchemeId() != null) {
                for (Scheme scheme : schemes) {
                    if (scheme.getId() == existing.getSchemeId()) {
                        schemeComboBox.setSelectedItem(scheme.getName());
                        break;
                    }
                }
            }
        } else {
            // 初始化字段值区域（仅新建模式需要，编辑模式已在 setSelectedItem 触发）
            refreshFieldValuesPanel();
        }
    }

    /**
     * 根据当前选中的方案刷新字段值输入区域
     * 仅在选择方案后显示字段值输入框
     */
    private void refreshFieldValuesPanel() {
        fieldInputAreas.clear();
        innerScrollPanes.clear();
        fieldValuesPanel.removeAll();

        Integer schemeId = getSelectedSchemeId();

        if (schemeId == null) {
            // 未选择方案：隐藏字段值区域，显示提示
            fieldValuesLabel.setVisible(false);
            JLabel hintLabel = new JLabel("请先选择方案以配置字段值");
            hintLabel.setForeground(Color.GRAY);
            fieldValuesPanel.add(hintLabel);
        } else {
            // 选择了方案：显示方案关联的字段定义
            fieldValuesLabel.setVisible(true);
            List<FieldDefinition> locations = SessionManager.getInstance().getFieldDefinitionsByScheme(schemeId);

            if (locations.isEmpty()) {
                JLabel noLocationsLabel = new JLabel("该方案暂无关联的字段定义");
                noLocationsLabel.setForeground(Color.GRAY);
                fieldValuesPanel.add(noLocationsLabel);
            } else {
                for (int i = 0; i < locations.size(); i++) {
                    FieldDefinition loc = locations.get(i);

                    JPanel tokenPanel = new JPanel(new BorderLayout());
                    tokenPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

                    JLabel label = new JLabel(loc.getType().getDisplayName() + " [" + loc.getExpression() + "]:");
                    label.setBorder(BorderFactory.createEmptyBorder(0, 0, 3, 0));
                    tokenPanel.add(label, BorderLayout.NORTH);

                    JTextArea textArea = new JTextArea();
                    textArea.setRows(4);
                    textArea.setLineWrap(true);
                    textArea.setWrapStyleWord(true);
                    textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
                    textArea.setTabSize(4);

                    textArea.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS,
                            Collections.singleton(AWTKeyStroke.getAWTKeyStroke("TAB")));
                    textArea.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS,
                            Collections.singleton(AWTKeyStroke.getAWTKeyStroke("shift TAB")));

                    JScrollPane scrollPane = new JScrollPane(textArea);
                    TextLineNumber lineNumbers = new TextLineNumber(textArea);
                    lineNumbers.setCurrentLineForeground(new Color(44, 121, 217));
                    lineNumbers.setForeground(Color.GRAY);
                    lineNumbers.setBackground(new Color(245, 245, 245));
                    lineNumbers.setFont(new Font("Monospaced", Font.PLAIN, 12));
                    scrollPane.setRowHeaderView(lineNumbers);
                    tokenPanel.add(scrollPane, BorderLayout.CENTER);

                    innerScrollPanes.add(scrollPane);
                    textArea.setComponentPopupMenu(createTextContextMenu(textArea));

                    fieldValuesPanel.add(tokenPanel);

                    if (i < locations.size() - 1) {
                        fieldValuesPanel.add(Box.createVerticalStrut(8));
                    }

                    fieldInputAreas.put(loc.getId(), textArea);

                    // 填充现有值
                    String existingValue = existingFieldValues.get(loc.getId());
                    if (existingValue != null) {
                        textArea.setText(existingValue);
                        textArea.setCaretPosition(0);
                    }
                }
            }
        }

        fieldValuesPanel.revalidate();
        fieldValuesPanel.repaint();

        // 重新安装滚轮转发器
        for (JScrollPane innerPane : innerScrollPanes) {
            ScrollPaneWheelForwarder.install(innerPane, outerScrollPane);
        }
    }

    /**
     * 为JTextArea创建右键上下文菜单
     */
    private JPopupMenu createTextContextMenu(JTextArea textArea) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.addActionListener(e -> textArea.copy());
        JMenuItem pasteItem = new JMenuItem("粘贴");
        pasteItem.addActionListener(e -> textArea.paste());
        JMenuItem cutItem = new JMenuItem("剪切");
        cutItem.addActionListener(e -> textArea.cut());
        JMenuItem selectAllItem = new JMenuItem("全选");
        selectAllItem.addActionListener(e -> textArea.selectAll());
        JMenuItem clearItem = new JMenuItem("清空");
        clearItem.addActionListener(e -> textArea.setText(""));
        menu.add(copyItem);
        menu.add(pasteItem);
        menu.add(cutItem);
        menu.addSeparator();
        menu.add(selectAllItem);
        menu.add(clearItem);
        return menu;
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

    /**
     * 获取选中的方案ID，如果选择"请选择方案"则返回null
     */
    public Integer getSchemeId() {
        return getSelectedSchemeId();
    }

    private Integer getSelectedSchemeId() {
        int idx = schemeComboBox.getSelectedIndex();
        if (idx <= 0) return null; // 0 = "请选择方案"
        String selectedName = (String) schemeComboBox.getSelectedItem();
        return schemeNameToId.get(selectedName);
    }

    public Map<Integer, String> getFieldValues() {
        return fieldValues;
    }
}
