package oxff.top.ui.privilege;

import oxff.top.privilege.SessionManager;
import oxff.top.privilege.UserSessionYamlIO;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenLocationType;
import oxff.top.privilege.model.UserSession;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 会话配置子Tab
 * 上方：令牌位置表 + CRUD按钮
 * 中间：用户会话表 + CRUD按钮
 * 下方：重放配置（模式/去重/阈值）
 */
public class SessionConfigTab extends JPanel {

    private final JTable tokenLocationTable;
    private final TokenLocationTableModel tokenLocationModel;
    private TableRowSorter<TokenLocationTableModel> tokenLocationSorter;
    private JTextField tokenSearchField;
    private JCheckBox tokenCaseSensitiveCheckbox;
    private JCheckBox tokenRegexCheckbox;

    private final JTable userSessionTable;
    private final UserSessionTableModel userSessionModel;
    private TableRowSorter<UserSessionTableModel> userSessionSorter;
    private JTextField sessionSearchField;

    // 重放配置控件
    private JRadioButton realtimeRadio;
    private JRadioButton batchRadio;
    private JCheckBox dedupCheckbox;
    private JSpinner thresholdSpinner;

    public SessionConfigTab() {
        super(new BorderLayout(0, 5));

        // ========== 令牌位置区域 ==========
        JPanel tokenLocationPanel = new JPanel(new BorderLayout());
        tokenLocationPanel.setBorder(BorderFactory.createTitledBorder("令牌位置"));

        tokenLocationModel = new TokenLocationTableModel();
        tokenLocationTable = new JTable(tokenLocationModel);
        tokenLocationTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tokenLocationTable.getColumnModel().getColumn(0).setPreferredWidth(60);   // 类型
        tokenLocationTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // 表达式
        tokenLocationTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // 描述
        tokenLocationTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // 持久化到全局
        tokenLocationTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // 启用

        // 设置 TableRowSorter 启用列头排序
        tokenLocationSorter = new TableRowSorter<>(tokenLocationModel);
        tokenLocationTable.setRowSorter(tokenLocationSorter);

        // 令牌位置搜索面板
        JPanel tokenSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        tokenSearchPanel.add(new JLabel("搜索:"));
        tokenSearchField = new JTextField(15);
        tokenSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
        });
        tokenSearchPanel.add(tokenSearchField);

        tokenCaseSensitiveCheckbox = new JCheckBox("Aa");
        tokenCaseSensitiveCheckbox.setToolTipText("区分大小写");
        tokenCaseSensitiveCheckbox.addActionListener(e -> applyTokenLocationFilter());
        tokenSearchPanel.add(tokenCaseSensitiveCheckbox);

        tokenRegexCheckbox = new JCheckBox(".*");
        tokenRegexCheckbox.setToolTipText("启用正则表达式匹配");
        tokenRegexCheckbox.addActionListener(e -> applyTokenLocationFilter());
        tokenSearchPanel.add(tokenRegexCheckbox);

        JButton clearTokenSearchBtn = new JButton("清除");
        clearTokenSearchBtn.addActionListener(e -> {
            tokenSearchField.setText("");
            applyTokenLocationFilter();
        });
        tokenSearchPanel.add(clearTokenSearchBtn);

        tokenLocationPanel.add(tokenSearchPanel, BorderLayout.NORTH);

        // 令牌位置表格：双击编辑 + 右键行选择 + 右键菜单
        tokenLocationTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = tokenLocationTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editTokenLocation();
                    }
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                selectRowOnRightClick(e, tokenLocationTable);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                selectRowOnRightClick(e, tokenLocationTable);
            }
        });

        // 令牌位置右键菜单
        JPopupMenu tokenLocationPopupMenu = new JPopupMenu();
        JMenuItem editTokenLocItem = new JMenuItem("编辑");
        editTokenLocItem.addActionListener(e -> editTokenLocation());
        JMenuItem deleteTokenLocItem = new JMenuItem("删除");
        deleteTokenLocItem.addActionListener(e -> deleteTokenLocation());
        tokenLocationPopupMenu.add(editTokenLocItem);
        tokenLocationPopupMenu.add(deleteTokenLocItem);
        tokenLocationTable.setComponentPopupMenu(tokenLocationPopupMenu);

        JScrollPane tokenScroll = new JScrollPane(tokenLocationTable);
        tokenScroll.setPreferredSize(new Dimension(0, 120));
        tokenScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        JPanel tokenButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addTokenBtn = new JButton("添加位置");
        JButton editTokenBtn = new JButton("编辑位置");
        JButton deleteTokenBtn = new JButton("删除位置");
        JButton importTokenBtn = new JButton("导入");
        JButton exportTokenBtn = new JButton("导出");

        addTokenBtn.addActionListener(e -> addTokenLocation());
        editTokenBtn.addActionListener(e -> editTokenLocation());
        deleteTokenBtn.addActionListener(e -> deleteTokenLocation());
        importTokenBtn.addActionListener(e -> importTokenLocations());
        exportTokenBtn.addActionListener(e -> exportTokenLocations());

        tokenButtonPanel.add(addTokenBtn);
        tokenButtonPanel.add(editTokenBtn);
        tokenButtonPanel.add(deleteTokenBtn);
        tokenButtonPanel.add(importTokenBtn);
        tokenButtonPanel.add(exportTokenBtn);

        tokenLocationPanel.add(tokenScroll, BorderLayout.CENTER);
        tokenLocationPanel.add(tokenButtonPanel, BorderLayout.SOUTH);

        // ========== 用户会话区域 ==========
        JPanel userSessionPanel = new JPanel(new BorderLayout());
        userSessionPanel.setBorder(BorderFactory.createTitledBorder("用户会话"));

        userSessionModel = new UserSessionTableModel();
        userSessionTable = new JTable(userSessionModel);
        userSessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userSessionTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // 名称
        userSessionTable.getColumnModel().getColumn(1).setPreferredWidth(50);   // 颜色
        userSessionTable.getColumnModel().getColumn(2).setPreferredWidth(50);   // 启用
        userSessionTable.getColumnModel().getColumn(3).setPreferredWidth(300);  // 令牌值摘要

        // 设置 TableRowSorter 启用列头排序
        userSessionSorter = new TableRowSorter<>(userSessionModel);
        userSessionTable.setRowSorter(userSessionSorter);

        // 用户会话搜索面板
        JPanel sessionSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        sessionSearchPanel.add(new JLabel("搜索:"));
        sessionSearchField = new JTextField(15);
        sessionSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyUserSessionFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyUserSessionFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyUserSessionFilter(); }
        });
        sessionSearchPanel.add(sessionSearchField);

        JButton clearSessionSearchBtn = new JButton("清除");
        clearSessionSearchBtn.addActionListener(e -> {
            sessionSearchField.setText("");
            applyUserSessionFilter();
        });
        sessionSearchPanel.add(clearSessionSearchBtn);

        userSessionPanel.add(sessionSearchPanel, BorderLayout.NORTH);

        // 用户会话表格：双击编辑 + 右键行选择 + 右键菜单
        userSessionTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = userSessionTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editUserSession();
                    }
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                selectRowOnRightClick(e, userSessionTable);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                selectRowOnRightClick(e, userSessionTable);
            }
        });

        // 用户会话右键菜单
        JPopupMenu userSessionPopupMenu = new JPopupMenu();
        JMenuItem editSessionItem = new JMenuItem("编辑");
        editSessionItem.addActionListener(e -> editUserSession());
        JMenuItem deleteSessionItem = new JMenuItem("删除");
        deleteSessionItem.addActionListener(e -> deleteUserSession());
        userSessionPopupMenu.add(editSessionItem);
        userSessionPopupMenu.add(deleteSessionItem);
        userSessionTable.setComponentPopupMenu(userSessionPopupMenu);

        JScrollPane sessionScroll = new JScrollPane(userSessionTable);
        sessionScroll.setPreferredSize(new Dimension(0, 150));
        sessionScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        JPanel sessionButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addSessionBtn = new JButton("添加用户");
        JButton editSessionBtn = new JButton("编辑用户");
        JButton deleteSessionBtn = new JButton("删除用户");
        JButton toggleEnableBtn = new JButton("启用/禁用");
        JButton importSessionBtn = new JButton("导入");
        JButton exportSessionBtn = new JButton("导出");

        addSessionBtn.addActionListener(e -> addUserSession());
        editSessionBtn.addActionListener(e -> editUserSession());
        deleteSessionBtn.addActionListener(e -> deleteUserSession());
        toggleEnableBtn.addActionListener(e -> toggleUserSessionEnabled());
        importSessionBtn.addActionListener(e -> importUserSessions());
        exportSessionBtn.addActionListener(e -> exportUserSessions());

        sessionButtonPanel.add(addSessionBtn);
        sessionButtonPanel.add(editSessionBtn);
        sessionButtonPanel.add(deleteSessionBtn);
        sessionButtonPanel.add(toggleEnableBtn);
        sessionButtonPanel.add(importSessionBtn);
        sessionButtonPanel.add(exportSessionBtn);

        userSessionPanel.add(sessionScroll, BorderLayout.CENTER);
        userSessionPanel.add(sessionButtonPanel, BorderLayout.SOUTH);

        // ========== 重放配置区域 ==========
        JPanel replayConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        replayConfigPanel.setBorder(BorderFactory.createTitledBorder("重放配置"));

        realtimeRadio = new JRadioButton("实时重放", true);
        batchRadio = new JRadioButton("批量重放");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(realtimeRadio);
        modeGroup.add(batchRadio);

        dedupCheckbox = new JCheckBox("API去重", true);

        replayConfigPanel.add(new JLabel("模式:"));
        replayConfigPanel.add(realtimeRadio);
        replayConfigPanel.add(batchRadio);
        replayConfigPanel.add(Box.createHorizontalStrut(20));
        replayConfigPanel.add(dedupCheckbox);
        replayConfigPanel.add(Box.createHorizontalStrut(20));
        replayConfigPanel.add(new JLabel("相似度阈值:"));
        thresholdSpinner = new JSpinner(new SpinnerNumberModel(0.7, 0.0, 1.0, 0.05));
        thresholdSpinner.setPreferredSize(new Dimension(70, 25));
        replayConfigPanel.add(thresholdSpinner);

        // 保存配置按钮
        JButton saveConfigBtn = new JButton("保存配置");
        saveConfigBtn.addActionListener(e -> saveReplayConfig());
        replayConfigPanel.add(Box.createHorizontalStrut(20));
        replayConfigPanel.add(saveConfigBtn);

        // ========== 组装 ==========
        JSplitPane topSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tokenLocationPanel, userSessionPanel);
        topSplit.setResizeWeight(0.4);

        add(topSplit, BorderLayout.CENTER);
        add(replayConfigPanel, BorderLayout.SOUTH);

        // 初始加载数据
        refreshData();
    }

    /**
     * 右键点击时选中光标所在行
     */
    private void selectRowOnRightClick(MouseEvent e, JTable table) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = table.rowAtPoint(e.getPoint());
            if (row >= 0) {
                table.setRowSelectionInterval(row, row);
            }
        }
    }

    /**
     * 刷新所有数据
     */
    public void refreshData() {
        SessionManager sessionManager = SessionManager.getInstance();
        tokenLocationModel.setData(sessionManager.getTokenLocations());
        userSessionModel.setData(sessionManager.getUserSessions());

        // 同步重放配置
        realtimeRadio.setSelected(sessionManager.isRealtimeMode());
        batchRadio.setSelected(!sessionManager.isRealtimeMode());
        dedupCheckbox.setSelected(sessionManager.isDedupEnabled());
        thresholdSpinner.setValue(sessionManager.getSimilarityThreshold());
    }

    /**
     * 应用令牌位置表格过滤器
     */
    private void applyTokenLocationFilter() {
        String text = tokenSearchField.getText().trim();
        if (text.isEmpty()) {
            tokenLocationSorter.setRowFilter(null);
            return;
        }

        boolean caseSensitive = tokenCaseSensitiveCheckbox.isSelected();
        boolean regexMode = tokenRegexCheckbox.isSelected();

        String pattern;
        if (regexMode) {
            pattern = caseSensitive ? text : "(?i)" + text;
        } else {
            pattern = caseSensitive ? Pattern.quote(text) : "(?i)" + Pattern.quote(text);
        }

        try {
            tokenLocationSorter.setRowFilter(RowFilter.regexFilter(pattern));
        } catch (PatternSyntaxException e) {
            // 正则表达式无效时静默忽略，保持上一次过滤结果
        }
    }

    /**
     * 应用用户会话表格过滤器
     */
    private void applyUserSessionFilter() {
        String text = sessionSearchField.getText().trim();
        if (text.isEmpty()) {
            userSessionSorter.setRowFilter(null);
            return;
        }

        try {
            userSessionSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        } catch (PatternSyntaxException e) {
            // 忽略无效的正则匹配文本
        }
    }

    private void addTokenLocation() {
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加令牌位置", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addTokenLocation(
                    dialog.getLocationType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void editTokenLocation() {
        int viewRow = tokenLocationTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = tokenLocationTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TokenLocation selected = tokenLocationModel.getTokenLocation(modelRow);
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑令牌位置", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().updateTokenLocation(
                    selected.getId(), dialog.getLocationType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void deleteTokenLocation() {
        int viewRow = tokenLocationTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = tokenLocationTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TokenLocation selected = tokenLocationModel.getTokenLocation(modelRow);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除令牌位置: " + selected.getExpression() + "?\n关联的所有用户令牌值也会被删除。",
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteTokenLocation(selected.getId());
            refreshData();
        }
    }

    private void addUserSession() {
        UserSessionEditDialog dialog = new UserSessionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加用户会话", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            int id = sm.addUserSession(dialog.getName(), dialog.getColorHex(), dialog.isEnabled());
            if (id > 0) {
                sm.saveTokenValues(id, dialog.getTokenValues());
            }
            refreshData();
        }
    }

    private void editUserSession() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(modelRow);
        UserSessionEditDialog dialog = new UserSessionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑用户会话", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            sm.updateUserSession(selected.getId(), dialog.getName(), dialog.getColorHex(), dialog.isEnabled());
            sm.saveTokenValues(selected.getId(), dialog.getTokenValues());
            refreshData();
        }
    }

    private void deleteUserSession() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(modelRow);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除用户会话: " + selected.getName() + "?",
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteUserSession(selected.getId());
            refreshData();
        }
    }

    private void toggleUserSessionEnabled() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(modelRow);
        SessionManager sm = SessionManager.getInstance();
        sm.updateUserSession(selected.getId(), selected.getName(),
                selected.getColorHex(), !selected.isEnabled());
        refreshData();
    }

    private void saveReplayConfig() {
        SessionManager sm = SessionManager.getInstance();
        sm.setRealtimeMode(realtimeRadio.isSelected());
        sm.setDedupEnabled(dedupCheckbox.isSelected());
        sm.setSimilarityThreshold((Double) thresholdSpinner.getValue());
        JOptionPane.showMessageDialog(this, "重放配置已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    // ========== 令牌位置导入导出 ==========

    /**
     * 导出令牌位置到YAML文件
     */
    private void exportTokenLocations() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出令牌位置");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yaml)", "yaml"));
        fileChooser.setSelectedFile(new File("token_locations.yaml"));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
                file = new File(file.getAbsolutePath() + ".yaml");
            }

            try {
                List<TokenLocation> locations = SessionManager.getInstance().getTokenLocations();
                List<Map<String, Object>> exportList = new ArrayList<>();
                for (TokenLocation loc : locations) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("type", loc.getType().name());
                    entry.put("expression", loc.getExpression());
                    entry.put("description", loc.getDescription());
                    entry.put("persistToGlobal", loc.isPersistToGlobal());
                    entry.put("enabled", loc.isEnabled());
                    exportList.add(entry);
                }

                DumperOptions options = new DumperOptions();
                options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                options.setPrettyFlow(true);
                Yaml yaml = new Yaml(options);
                try (FileWriter writer = new FileWriter(file)) {
                    yaml.dump(exportList, writer);
                }

                JOptionPane.showMessageDialog(this,
                    "成功导出 " + exportList.size() + " 条令牌位置到:\n" + file.getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 从YAML文件导入令牌位置
     */
    private void importTokenLocations() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入令牌位置");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            try {
                Yaml yaml = new Yaml();
                List<Map<String, Object>> importList;

                try (FileInputStream fis = new FileInputStream(file)) {
                    Iterable<Object> objects = yaml.loadAll(fis);
                    List<Map<String, Object>> merged = new ArrayList<>();
                    for (Object obj : objects) {
                        if (obj instanceof List) {
                            for (Object item : (List<?>) obj) {
                                if (item instanceof Map) {
                                    merged.add(castToMap((Map<?, ?>) item));
                                }
                            }
                        } else if (obj instanceof Map) {
                            merged.add(castToMap((Map<?, ?>) obj));
                        }
                    }
                    importList = merged;
                }

                if (importList.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                        "文件中没有找到令牌位置数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                int imported = 0;
                SessionManager sm = SessionManager.getInstance();
                for (Map<String, Object> entry : importList) {
                    try {
                        String typeStr = String.valueOf(entry.get("type"));
                        TokenLocationType type = TokenLocationType.fromString(typeStr);
                        String expression = String.valueOf(entry.getOrDefault("expression", ""));
                        String description = String.valueOf(entry.getOrDefault("description", ""));
                        boolean persistToGlobal = toBoolean(entry.getOrDefault("persistToGlobal", true));
                        boolean enabled = toBoolean(entry.getOrDefault("enabled", true));
                        sm.addTokenLocation(type, expression, description, persistToGlobal, enabled);
                        imported++;
                    } catch (Exception e) {
                        // 跳过无效条目
                    }
                }

                refreshData();
                JOptionPane.showMessageDialog(this,
                    "成功导入 " + imported + " 条令牌位置",
                    "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ========== 用户会话导入导出 ==========

    /**
     * 导出用户会话到YAML文件
     */
    private void exportUserSessions() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出用户会话");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));
        fileChooser.setSelectedFile(new File("user_sessions.yaml"));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
                file = new File(file.getAbsolutePath() + ".yaml");
            }

            try {
                SessionManager sm = SessionManager.getInstance();
                List<UserSession> sessions = sm.getUserSessions();
                List<TokenLocation> locations = sm.getTokenLocations();

                boolean success = UserSessionYamlIO.writeToFile(sessions, locations, file.getAbsolutePath());
                if (success) {
                    JOptionPane.showMessageDialog(this,
                        "成功导出 " + sessions.size() + " 个用户会话到:\n" + file.getAbsolutePath(),
                        "导出成功", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this,
                        "导出失败", "导出错误", JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 从YAML文件导入用户会话
     */
    private void importUserSessions() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入用户会话");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            try {
                SessionManager sm = SessionManager.getInstance();
                List<TokenLocation> locations = sm.getTokenLocations();
                List<UserSession> importedSessions = UserSessionYamlIO.readFromFile(file.getAbsolutePath(), locations);

                if (importedSessions.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                        "文件中没有找到用户会话数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 选择导入模式：合并或替换
                String[] options = {"合并导入", "替换导入", "取消"};
                int choice = JOptionPane.showOptionDialog(this,
                    "发现 " + importedSessions.size() + " 个用户会话，请选择导入方式：\n" +
                    "合并导入：保留现有数据，仅添加不重名的会话\n" +
                    "替换导入：清空所有现有会话后导入",
                    "导入方式",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                    null, options, options[0]);

                if (choice == 0) {
                    // 合并导入
                    int count = sm.importUserSessionsMerge(importedSessions);
                    refreshData();
                    JOptionPane.showMessageDialog(this,
                        "合并导入完成，新增 " + count + " 个用户会话",
                        "导入成功", JOptionPane.INFORMATION_MESSAGE);
                } else if (choice == 1) {
                    // 替换导入
                    int confirm = JOptionPane.showConfirmDialog(this,
                        "替换导入将删除所有现有用户会话，是否继续？",
                        "替换确认", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    if (confirm == JOptionPane.YES_OPTION) {
                        int count = sm.importUserSessionsReplace(importedSessions);
                        refreshData();
                        JOptionPane.showMessageDialog(this,
                            "替换导入完成，共导入 " + count + " 个用户会话",
                            "导入成功", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ========== 辅助方法 ==========

    private static Map<String, Object> castToMap(Map<?, ?> map) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            result.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        return result;
    }

    private static boolean toBoolean(Object value) {
        if (value == null) return true;
        if (value instanceof Boolean) return (Boolean) value;
        String str = String.valueOf(value).trim().toLowerCase();
        return "true".equals(str) || "1".equals(str) || "yes".equals(str);
    }
}
