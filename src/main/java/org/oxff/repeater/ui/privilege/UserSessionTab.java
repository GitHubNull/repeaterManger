package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.UserSessionYamlIO;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.privilege.model.UserSession;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * 用户会话管理子标签页
 * 管理用户会话的CRUD操作，含方案关联和重放配置
 */
public class UserSessionTab extends JPanel {

    private static final Logger LOGGER = Logger.getLogger(UserSessionTab.class.getName());

    private final JTable userSessionTable;
    private final UserSessionTableModel userSessionModel;
    private TableRowSorter<UserSessionTableModel> userSessionSorter;
    private JTextField sessionSearchField;

    public UserSessionTab() {
        super(new BorderLayout(0, 5));

        // ========== 搜索面板 ==========
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

        add(sessionSearchPanel, BorderLayout.NORTH);

        // ========== 用户会话表格 ==========
        userSessionModel = new UserSessionTableModel();
        userSessionTable = new JTable(userSessionModel);
        userSessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userSessionTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // 名称
        userSessionTable.getColumnModel().getColumn(1).setPreferredWidth(50);   // 颜色
        userSessionTable.getColumnModel().getColumn(2).setPreferredWidth(100);  // 关联方案
        userSessionTable.getColumnModel().getColumn(3).setPreferredWidth(50);   // 启用
        userSessionTable.getColumnModel().getColumn(4).setPreferredWidth(250);  // 令牌值摘要
        userSessionTable.getColumnModel().getColumn(4).setMinWidth(100);
        userSessionTable.getColumnModel().getColumn(4).setCellRenderer(new TokenValueCellRenderer());

        userSessionSorter = new TableRowSorter<>(userSessionModel);
        userSessionTable.setRowSorter(userSessionSorter);

        // 双击编辑 + 右键
        userSessionTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = userSessionTable.rowAtPoint(e.getPoint());
                    if (row >= 0) editUserSession();
                }
            }
            @Override
            public void mousePressed(MouseEvent e) { selectRowOnRightClick(e); }
            @Override
            public void mouseReleased(MouseEvent e) { selectRowOnRightClick(e); }
        });

        JPopupMenu userSessionPopupMenu = new JPopupMenu();
        JMenuItem editSessionItem = new JMenuItem("编辑");
        editSessionItem.addActionListener(e -> editUserSession());
        JMenuItem deleteSessionItem = new JMenuItem("删除");
        deleteSessionItem.addActionListener(e -> deleteUserSession());
        userSessionPopupMenu.add(editSessionItem);
        userSessionPopupMenu.add(deleteSessionItem);
        userSessionTable.setComponentPopupMenu(userSessionPopupMenu);

        JScrollPane sessionScroll = new JScrollPane(userSessionTable);
        add(sessionScroll, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel sessionButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addSessionBtn = new JButton("添加用户");
        JButton editSessionBtn = new JButton("编辑用户");
        JButton deleteSessionBtn = new JButton("删除用户");
        JButton toggleEnableBtn = new JButton("启用/禁用");
        JButton importSessionBtn = new JButton("导入");
        JButton exportSessionBtn = new JButton("导出");
        JButton parseFromClipboardBtn = new JButton("从报文解析");
        JButton addAnonymousBtn = new JButton("添加匿名用户");

        addSessionBtn.addActionListener(e -> addUserSession());
        editSessionBtn.addActionListener(e -> editUserSession());
        deleteSessionBtn.addActionListener(e -> deleteUserSession());
        toggleEnableBtn.addActionListener(e -> toggleUserSessionEnabled());
        importSessionBtn.addActionListener(e -> importUserSessions());
        exportSessionBtn.addActionListener(e -> exportUserSessions());
        parseFromClipboardBtn.addActionListener(e -> parseSessionFromClipboard());
        addAnonymousBtn.addActionListener(e -> addAnonymousUser());

        sessionButtonPanel.add(addSessionBtn);
        sessionButtonPanel.add(addAnonymousBtn);
        sessionButtonPanel.add(parseFromClipboardBtn);
        sessionButtonPanel.add(editSessionBtn);
        sessionButtonPanel.add(deleteSessionBtn);
        sessionButtonPanel.add(toggleEnableBtn);
        sessionButtonPanel.add(importSessionBtn);
        sessionButtonPanel.add(exportSessionBtn);

        add(sessionButtonPanel, BorderLayout.SOUTH);
    }

    private void parseSessionFromClipboard() {
        // 检查是否配置了TokenScheme
        SessionManager sm = SessionManager.getInstance();
        List<TokenScheme> schemes = sm.getTokenSchemes();
        if (schemes.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "未配置任何令牌方案，请先配置令牌方案后再使用此功能。",
                    "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 启动后台解析Worker
        ParseSessionWorker worker = new ParseSessionWorker(this);
        worker.start();
    }

    private void selectRowOnRightClick(MouseEvent e) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = userSessionTable.rowAtPoint(e.getPoint());
            if (row >= 0) userSessionTable.setRowSelectionInterval(row, row);
        }
    }

    public void refreshData() {
        SessionManager sessionManager = SessionManager.getInstance();
        userSessionModel.setData(sessionManager.getUserSessions());
    }

    private void applyUserSessionFilter() {
        String text = sessionSearchField.getText().trim();
        if (text.isEmpty()) {
            userSessionSorter.setRowFilter(null);
            return;
        }
        try {
            userSessionSorter.setRowFilter(javax.swing.RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
        } catch (java.util.regex.PatternSyntaxException e) {
            // 忽略
        }
    }

    private void addUserSession() {
        UserSessionEditDialog dialog = new UserSessionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加用户会话", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            int id = sm.addUserSession(dialog.getName(), dialog.getColorHex(), dialog.isEnabled(),
                    dialog.getSchemeId());
            if (id > 0) {
                sm.saveTokenValues(id, dialog.getTokenValues());
            }
            refreshData();
        }
    }

    /**
     * 一键添加匿名用户（所有令牌值留空，用于未授权测试）
     * 令牌方案智能选择：优先复用已有用户方案，其次自动匹配唯一方案，多方案时弹窗选择
     */
    private void addAnonymousUser() {
        SessionManager sm = SessionManager.getInstance();

        // 生成唯一名称
        String baseName = "匿名用户";
        String candidateName = baseName;
        int suffix = 2;
        Set<String> existingNames = sm.getUserSessions().stream()
                .map(UserSession::getName).collect(Collectors.toSet());
        while (existingNames.contains(candidateName)) {
            candidateName = baseName + "_" + suffix++;
        }

        // 智能确定令牌方案
        Integer schemeId = determineAnonymousScheme(candidateName);
        if (schemeId == null) {
            return; // 用户取消
        }

        String colorHex = "#999999";
        int id = sm.addUserSession(candidateName, colorHex, true, schemeId);
        if (id > 0) {
            refreshData();
            JOptionPane.showMessageDialog(this,
                    "匿名用户 \"" + candidateName + "\" 已创建", "成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "创建匿名用户失败", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 为匿名用户智能确定令牌方案：
     * 1. 优先使用已有测试用户所使用的方案
     * 2. 若无用户，且只有一个启用的方案或只有一个方案，自动使用
     * 3. 否则弹出 UserSessionEditDialog 让用户手动选择方案
     *
     * @param candidateName 匿名用户的候选名称（用于预填充对话框）
     * @return 确定的 schemeId，若用户取消则返回 null
     */
    private Integer determineAnonymousScheme(String candidateName) {
        SessionManager sm = SessionManager.getInstance();
        List<UserSession> existingSessions = sm.getUserSessions();

        // Priority 1: 复用已有用户的方案
        if (!existingSessions.isEmpty()) {
            for (UserSession session : existingSessions) {
                if (session.getSchemeId() != null) {
                    return session.getSchemeId();
                }
            }
        }

        // Priority 2: 无已有用户时，检查可用方案数量
        List<TokenScheme> allSchemes = sm.getTokenSchemes();
        List<TokenScheme> enabledSchemes = sm.getEnabledTokenSchemes();

        if (enabledSchemes.size() == 1) {
            return enabledSchemes.get(0).getId();
        }
        if (enabledSchemes.isEmpty() && allSchemes.size() == 1) {
            return allSchemes.get(0).getId();
        }

        // Priority 3: 多方案时弹窗选择
        return showSchemeSelectionDialog(candidateName);
    }

    /**
     * 多方案时弹出 UserSessionEditDialog 让用户选择方案
     * 对话框预填充名称和灰色，令牌值区域默认为空
     *
     * @param candidateName 预填充的名称
     * @return 用户选择的 schemeId，若取消则返回 null
     */
    private Integer showSchemeSelectionDialog(String candidateName) {
        // 创建临时 UserSession 用于预填充名称和颜色
        UserSession tempSession = new UserSession();
        tempSession.setName(candidateName);
        tempSession.setColor(new Color(0x99, 0x99, 0x99));

        Frame owner = (Frame) SwingUtilities.getWindowAncestor(this);
        UserSessionEditDialog dialog = new UserSessionEditDialog(owner, "添加匿名用户", tempSession);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            return dialog.getSchemeId();
        }
        return null;
    }

    private void editUserSession() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
        UserSession selected = userSessionModel.getUserSession(modelRow);
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "无法获取选中的用户会话数据", "错误", JOptionPane.ERROR_MESSAGE);
            LOGGER.warning("editUserSession: getUserSession returned null for model row " + modelRow);
            return;
        }

        Window owner = SwingUtilities.getWindowAncestor(this);
        if (!(owner instanceof Frame)) {
            JOptionPane.showMessageDialog(this, "无法确定父窗口，请重试", "错误", JOptionPane.ERROR_MESSAGE);
            LOGGER.warning("editUserSession: owner is not a Frame, got " + (owner != null ? owner.getClass().getName() : "null"));
            return;
        }

        UserSessionEditDialog dialog = null;
        try {
            dialog = new UserSessionEditDialog((Frame) owner, "编辑用户会话", selected);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "创建编辑对话框失败", e);
            JOptionPane.showMessageDialog(this,
                    "创建编辑对话框失败: " + e.getMessage(),
                    "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            try {
                SessionManager sm = SessionManager.getInstance();
                boolean updated = sm.updateUserSession(selected.getId(), dialog.getName(), dialog.getColorHex(),
                        dialog.isEnabled(), dialog.getSchemeId());
                if (!updated) {
                    JOptionPane.showMessageDialog(this,
                            "更新用户会话失败，请检查日志", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                boolean saved = sm.saveTokenValues(selected.getId(), dialog.getTokenValues());
                if (!saved) {
                    JOptionPane.showMessageDialog(this,
                            "保存令牌值失败，请检查日志", "警告", JOptionPane.WARNING_MESSAGE);
                }
                refreshData();
                JOptionPane.showMessageDialog(this,
                        "用户会话 \"" + dialog.getName() + "\" 更新成功", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "保存用户会话失败", e);
                JOptionPane.showMessageDialog(this,
                        "保存用户会话失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deleteUserSession() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
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
        UserSession selected = userSessionModel.getUserSession(modelRow);
        SessionManager sm = SessionManager.getInstance();
        sm.updateUserSession(selected.getId(), selected.getName(),
                selected.getColorHex(), !selected.isEnabled(), selected.getSchemeId());
        refreshData();
    }

    private void exportUserSessions() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT, "导出用户会话", this,
                new File("user_sessions.yaml"),
                new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));
        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            SessionManager sm = SessionManager.getInstance();
            List<UserSession> sessions = sm.getUserSessions();
            List<TokenLocation> locations = sm.getTokenLocations();
            List<TokenScheme> schemes = sm.getTokenSchemes();

            boolean success = UserSessionYamlIO.writeToFile(sessions, locations, schemes, file.getAbsolutePath());
            if (success) {
                JOptionPane.showMessageDialog(this,
                    "成功导出 " + sessions.size() + " 个用户会话到:\n" + file.getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "导出失败", "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importUserSessions() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT, "导入用户会话", this,
                new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));
        if (selectedFile == null) return;

        try {
            SessionManager sm = SessionManager.getInstance();
            List<TokenLocation> locations = sm.getTokenLocations();
            List<TokenScheme> schemes = sm.getTokenSchemes();
            List<UserSession> importedSessions = UserSessionYamlIO.readFromFile(
                    selectedFile.getAbsolutePath(), locations, schemes);

            if (importedSessions.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    "文件中没有找到用户会话数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String[] options = {"合并导入", "替换导入", "取消"};
            int choice = JOptionPane.showOptionDialog(this,
                "发现 " + importedSessions.size() + " 个用户会话，请选择导入方式：\n" +
                "合并导入：保留现有数据，仅添加不重名的会话\n" +
                "替换导入：清空所有现有会话后导入",
                "导入方式",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]);

            if (choice == 0) {
                int count = sm.importUserSessionsMerge(importedSessions);
                refreshData();
                JOptionPane.showMessageDialog(this,
                    "合并导入完成，新增 " + count + " 个用户会话",
                    "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } else if (choice == 1) {
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
