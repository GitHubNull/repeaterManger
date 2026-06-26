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

/**
 * 用户会话管理子标签页
 * 管理用户会话的CRUD操作，含方案关联和重放配置
 */
public class UserSessionTab extends JPanel {

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

        addSessionBtn.addActionListener(e -> addUserSession());
        editSessionBtn.addActionListener(e -> editUserSession());
        deleteSessionBtn.addActionListener(e -> deleteUserSession());
        toggleEnableBtn.addActionListener(e -> toggleUserSessionEnabled());
        importSessionBtn.addActionListener(e -> importUserSessions());
        exportSessionBtn.addActionListener(e -> exportUserSessions());
        parseFromClipboardBtn.addActionListener(e -> parseSessionFromClipboard());

        sessionButtonPanel.add(addSessionBtn);
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

    private void editUserSession() {
        int viewRow = userSessionTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = userSessionTable.convertRowIndexToModel(viewRow);
        UserSession selected = userSessionModel.getUserSession(modelRow);
        UserSessionEditDialog dialog = new UserSessionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑用户会话", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            sm.updateUserSession(selected.getId(), dialog.getName(), dialog.getColorHex(), dialog.isEnabled(),
                    dialog.getSchemeId());
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
