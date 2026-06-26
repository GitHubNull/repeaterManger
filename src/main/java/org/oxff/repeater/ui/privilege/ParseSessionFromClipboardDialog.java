package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SchemeMatch;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.SessionParseResult;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.privilege.model.UserSession;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * 从HTTP报文解析用户会话的确认对话框
 * 展示解析结果摘要，允许用户确认并自定义会话信息
 */
public class ParseSessionFromClipboardDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JLabel colorPreview;
    private Color selectedColor;
    private final JCheckBox enabledCheckbox;
    private final JComboBox<String> schemeComboBox;
    private final JCheckBox updateExistingCheckbox;
    private final JLabel updateExistingLabel;

    private final Map<String, Integer> schemeNameToId = new LinkedHashMap<>();
    private final Map<String, Integer> existingSessionNameToId = new LinkedHashMap<>();

    private final SessionParseResult parseResult;
    private final List<SchemeMatch> schemeMatches;
    private final List<TokenLocation> allLocations;

    private Integer existingSessionId = null;

    public ParseSessionFromClipboardDialog(Frame owner, SessionParseResult parseResult,
                                            List<SchemeMatch> schemeMatches, List<TokenLocation> allLocations,
                                            String suggestedName) {
        super(owner, "从HTTP报文解析用户会话", true);
        this.parseResult = parseResult;
        this.schemeMatches = schemeMatches;
        this.allLocations = allLocations;

        setSize(650, 550);
        setLocationRelativeTo(owner);
        setResizable(true);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // ========== 顶部：解析结果摘要 ==========
        JPanel summaryPanel = new JPanel();
        summaryPanel.setLayout(new BoxLayout(summaryPanel, BoxLayout.Y_AXIS));
        summaryPanel.setBorder(BorderFactory.createTitledBorder("解析结果摘要"));

        // 匹配到的Scheme
        if (schemeMatches != null && !schemeMatches.isEmpty()) {
            SchemeMatch selectedMatch = schemeMatches.get(0);
            JLabel schemeLabel = new JLabel(String.format("已选方案: %s (%d/%d 令牌匹配, %.0f%%)",
                    selectedMatch.getScheme().getName(),
                    selectedMatch.getMatchedCount(),
                    selectedMatch.getTotalCount(),
                    selectedMatch.getMatchRate() * 100));
            schemeLabel.setFont(schemeLabel.getFont().deriveFont(Font.BOLD));
            summaryPanel.add(schemeLabel);
            summaryPanel.add(Box.createVerticalStrut(5));
        } else {
            JLabel noSchemeLabel = new JLabel("未匹配到任何令牌方案");
            noSchemeLabel.setForeground(Color.RED);
            summaryPanel.add(noSchemeLabel);
        }

        // 提取到的令牌值列表
        JLabel tokensLabel = new JLabel("提取到的令牌值:");
        tokensLabel.setFont(tokensLabel.getFont().deriveFont(Font.BOLD));
        summaryPanel.add(tokensLabel);

        JPanel tokensPanel = new JPanel(new GridLayout(0, 1, 2, 2));
        boolean anyExtracted = false;
        for (TokenLocation loc : allLocations) {
            String value = parseResult.getExtractedValue(loc.getId());
            JPanel tokenRow = new JPanel(new BorderLayout(5, 0));
            JLabel locLabel = new JLabel(loc.getType().getDisplayName() + " [" + loc.getExpression() + "]: ");
            locLabel.setPreferredSize(new Dimension(200, 20));
            JLabel valueLabel;
            if (value != null) {
                anyExtracted = true;
                String displayValue = value.length() > 40 ? value.substring(0, 37) + "..." : value;
                valueLabel = new JLabel(displayValue);
                valueLabel.setToolTipText(value);
                valueLabel.setForeground(new Color(0, 128, 0));
            } else {
                valueLabel = new JLabel("未匹配");
                valueLabel.setForeground(Color.GRAY);
            }
            tokenRow.add(locLabel, BorderLayout.WEST);
            tokenRow.add(valueLabel, BorderLayout.CENTER);
            tokensPanel.add(tokenRow);
        }
        if (!anyExtracted) {
            JLabel noneLabel = new JLabel("  未提取到任何令牌值");
            noneLabel.setForeground(Color.RED);
            tokensPanel.add(noneLabel);
        }

        JScrollPane tokensScroll = new JScrollPane(tokensPanel);
        tokensScroll.setPreferredSize(new Dimension(400, 120));
        tokensScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
        summaryPanel.add(tokensScroll);

        mainPanel.add(summaryPanel, BorderLayout.NORTH);

        // ========== 中部：会话配置 ==========
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("会话配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 会话名称
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("会话名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        nameField = new JTextField(suggestedName != null ? suggestedName : "", 20);
        configPanel.add(nameField, gbc);

        // 颜色选择
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        configPanel.add(new JLabel("颜色:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel colorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        colorPreview = new JLabel("  ");
        colorPreview.setOpaque(true);
        colorPreview.setPreferredSize(new Dimension(30, 20));
        selectedColor = generateRandomColor();
        colorPreview.setBackground(selectedColor);
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
        configPanel.add(colorPanel, gbc);

        // 启用复选框
        gbc.gridx = 0; gbc.gridy = 2;
        configPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1;
        enabledCheckbox = new JCheckBox("启用此用户会话", true);
        configPanel.add(enabledCheckbox, gbc);

        // 方案选择
        gbc.gridx = 0; gbc.gridy = 3;
        configPanel.add(new JLabel("令牌方案:"), gbc);
        gbc.gridx = 1;
        schemeComboBox = new JComboBox<>();
        schemeNameToId.clear();

        // 加载所有方案到下拉框
        List<TokenScheme> allSchemes = SessionManager.getInstance().getTokenSchemes();
        for (TokenScheme scheme : allSchemes) {
            schemeComboBox.addItem(scheme.getName());
            schemeNameToId.put(scheme.getName(), scheme.getId());
        }

        // 默认选中已确定的匹配方案
        if (schemeMatches != null && !schemeMatches.isEmpty()) {
            SchemeMatch selectedMatch = schemeMatches.get(0);
            schemeComboBox.setSelectedItem(selectedMatch.getScheme().getName());
        }
        configPanel.add(schemeComboBox, gbc);

        // 更新现有会话（如果存在同名会话）
        existingSessionNameToId.clear();
        List<UserSession> existingSessions = SessionManager.getInstance().getUserSessions();
        for (UserSession session : existingSessions) {
            existingSessionNameToId.put(session.getName(), session.getId());
        }

        gbc.gridx = 0; gbc.gridy = 4;
        updateExistingLabel = new JLabel("");
        configPanel.add(updateExistingLabel, gbc);
        gbc.gridx = 1;
        updateExistingCheckbox = new JCheckBox("更新现有会话");
        updateExistingCheckbox.setVisible(false);
        updateExistingCheckbox.setEnabled(false);
        configPanel.add(updateExistingCheckbox, gbc);

        // 监听名称变化，检查是否同名
        nameField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { checkExistingSession(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { checkExistingSession(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { checkExistingSession(); }
        });
        checkExistingSession();

        mainPanel.add(configPanel, BorderLayout.CENTER);

        // ========== 底部：按钮 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");

        okBtn.addActionListener(e -> {
            if (nameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "会话名称不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        getContentPane().add(mainPanel);
    }

    /**
     * 检查当前输入的名称是否对应现有会话，显示更新选项
     */
    private void checkExistingSession() {
        String name = nameField.getText().trim();
        Integer existingId = existingSessionNameToId.get(name);
        if (existingId != null) {
            existingSessionId = existingId;
            updateExistingLabel.setText("已存在同名会话:");
            updateExistingCheckbox.setVisible(true);
            updateExistingCheckbox.setEnabled(true);
            updateExistingCheckbox.setSelected(true);
        } else {
            existingSessionId = null;
            updateExistingLabel.setText("");
            updateExistingCheckbox.setVisible(false);
            updateExistingCheckbox.setEnabled(false);
            updateExistingCheckbox.setSelected(false);
        }
    }

    /**
     * 生成随机颜色（避免过暗）
     */
    private Color generateRandomColor() {
        Random rand = new Random();
        int r = 100 + rand.nextInt(156);
        int g = 100 + rand.nextInt(156);
        int b = 100 + rand.nextInt(156);
        return new Color(r, g, b);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getSessionName() {
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
     * 获取选中的方案ID
     */
    public Integer getSelectedSchemeId() {
        String selectedName = (String) schemeComboBox.getSelectedItem();
        if (selectedName == null || selectedName.isEmpty()) {
            // 默认返回已确定的匹配方案
            if (schemeMatches != null && !schemeMatches.isEmpty()) {
                return schemeMatches.get(0).getScheme().getId();
            }
            return null;
        }
        return schemeNameToId.get(selectedName);
    }

    public boolean isUpdateExisting() {
        return updateExistingCheckbox.isSelected() && updateExistingCheckbox.isEnabled();
    }

    public Integer getExistingSessionId() {
        return existingSessionId;
    }

    public SessionParseResult getParseResult() {
        return parseResult;
    }
}
