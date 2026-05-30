package oxff.top.ui.privilege;

import oxff.top.privilege.SessionManager;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;
import oxff.top.utils.ScrollPaneWheelForwarder;
import oxff.top.utils.TextLineNumber;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户会话编辑对话框
 * 允许编辑用户名称、颜色、启用状态，以及为每个令牌位置设置值
 * 令牌值使用带行号的多行文本区域，支持自动折行
 */
public class UserSessionEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JCheckBox enabledCheckbox;
    private final JLabel colorPreview;
    private Color selectedColor;

    /** 令牌值输入框映射：tokenLocationId -> JTextArea */
    private final Map<Integer, JTextArea> tokenValueFields = new LinkedHashMap<>();

    /** 收集所有内层 JScrollPane，用于安装滚轮转发器 */
    private final List<JScrollPane> innerScrollPanes = new ArrayList<>();

    /** 最终的令牌值 */
    private Map<Integer, String> tokenValues = new LinkedHashMap<>();

    public UserSessionEditDialog(Frame owner, String title, UserSession existing) {
        super(owner, title, true);
        setSize(650, 550);
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
            // 令牌值内容面板，使用垂直BoxLayout
            JPanel tokenValuesPanel = new JPanel();
            tokenValuesPanel.setLayout(new BoxLayout(tokenValuesPanel, BoxLayout.Y_AXIS));

            for (int i = 0; i < locations.size(); i++) {
                TokenLocation loc = locations.get(i);

                // 每个令牌位置的子面板
                JPanel tokenPanel = new JPanel(new BorderLayout());
                tokenPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

                // 标签
                JLabel label = new JLabel(loc.getType().getDisplayName() + " [" + loc.getExpression() + "]:");
                label.setBorder(BorderFactory.createEmptyBorder(0, 0, 3, 0));
                tokenPanel.add(label, BorderLayout.NORTH);

                // 多行文本区域
                JTextArea textArea = new JTextArea();
                textArea.setRows(4);
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);
                textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
                textArea.setTabSize(4);

                // Tab键焦点切换：恢复Tab在控件间的导航功能
                textArea.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS,
                        Collections.singleton(AWTKeyStroke.getAWTKeyStroke("TAB")));
                textArea.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS,
                        Collections.singleton(AWTKeyStroke.getAWTKeyStroke("shift TAB")));

                // 行号
                JScrollPane scrollPane = new JScrollPane(textArea);
                TextLineNumber lineNumbers = new TextLineNumber(textArea);
                lineNumbers.setCurrentLineForeground(new Color(44, 121, 217));
                lineNumbers.setForeground(Color.GRAY);
                lineNumbers.setBackground(new Color(245, 245, 245));
                lineNumbers.setFont(new Font("Monospaced", Font.PLAIN, 12));
                scrollPane.setRowHeaderView(lineNumbers);
                tokenPanel.add(scrollPane, BorderLayout.CENTER);

                // 收集内层 JScrollPane 引用，用于后续安装滚轮转发器
                innerScrollPanes.add(scrollPane);

                // 右键菜单
                textArea.setComponentPopupMenu(createTextContextMenu(textArea));

                tokenValuesPanel.add(tokenPanel);

                // 令牌位置之间添加分隔间距（最后一个不加）
                if (i < locations.size() - 1) {
                    tokenValuesPanel.add(Box.createVerticalStrut(8));
                }

                tokenValueFields.put(loc.getId(), textArea);

                // 如果是编辑模式，填充现有值
                if (existing != null) {
                    String existingValue = existing.getTokenValue(loc.getId());
                    if (existingValue != null) {
                        textArea.setText(existingValue);
                        textArea.setCaretPosition(0);
                    }
                }
            }

            // 令牌值面板直接加入 mainPanel（移除中间层 JScrollPane，实现统一滚动）
            gbc.gridy = 4;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weighty = 1.0;
            gbc.insets = new Insets(8, 10, 8, 10);
            mainPanel.add(tokenValuesPanel, gbc);
        } else {
            JLabel noLocationsLabel = new JLabel("请先添加令牌位置");
            gbc.gridy = 4;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weighty = 0;
            gbc.insets = new Insets(8, 10, 8, 10);
            mainPanel.add(noLocationsLabel, gbc);
        }

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
            // 收集令牌值
            tokenValues = new LinkedHashMap<>();
            for (Map.Entry<Integer, JTextArea> entry : tokenValueFields.entrySet()) {
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
        JScrollPane outerScrollPane = new JScrollPane(mainPanel);
        getContentPane().add(outerScrollPane, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);

        // 为所有内层 JScrollPane 安装滚轮转发器，实现嵌套滚动的无缝衔接
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

    public Map<Integer, String> getTokenValues() {
        return tokenValues;
    }
}
