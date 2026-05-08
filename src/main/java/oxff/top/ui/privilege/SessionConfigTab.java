package oxff.top.ui.privilege;

import oxff.top.privilege.SessionManager;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;

import javax.swing.*;
import java.awt.*;

/**
 * 会话配置子Tab
 * 上方：令牌位置表 + CRUD按钮
 * 中间：用户会话表 + CRUD按钮
 * 下方：重放配置（模式/去重/阈值）
 */
public class SessionConfigTab extends JPanel {

    private final JTable tokenLocationTable;
    private final TokenLocationTableModel tokenLocationModel;

    private final JTable userSessionTable;
    private final UserSessionTableModel userSessionModel;

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
        tokenLocationTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // 表达式
        tokenLocationTable.getColumnModel().getColumn(2).setPreferredWidth(200);  // 描述

        JScrollPane tokenScroll = new JScrollPane(tokenLocationTable);
        tokenScroll.setPreferredSize(new Dimension(0, 120));

        JPanel tokenButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addTokenBtn = new JButton("添加位置");
        JButton editTokenBtn = new JButton("编辑位置");
        JButton deleteTokenBtn = new JButton("删除位置");

        addTokenBtn.addActionListener(e -> addTokenLocation());
        editTokenBtn.addActionListener(e -> editTokenLocation());
        deleteTokenBtn.addActionListener(e -> deleteTokenLocation());

        tokenButtonPanel.add(addTokenBtn);
        tokenButtonPanel.add(editTokenBtn);
        tokenButtonPanel.add(deleteTokenBtn);

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

        JScrollPane sessionScroll = new JScrollPane(userSessionTable);
        sessionScroll.setPreferredSize(new Dimension(0, 150));

        JPanel sessionButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addSessionBtn = new JButton("添加用户");
        JButton editSessionBtn = new JButton("编辑用户");
        JButton deleteSessionBtn = new JButton("删除用户");
        JButton toggleEnableBtn = new JButton("启用/禁用");

        addSessionBtn.addActionListener(e -> addUserSession());
        editSessionBtn.addActionListener(e -> editUserSession());
        deleteSessionBtn.addActionListener(e -> deleteUserSession());
        toggleEnableBtn.addActionListener(e -> toggleUserSessionEnabled());

        sessionButtonPanel.add(addSessionBtn);
        sessionButtonPanel.add(editSessionBtn);
        sessionButtonPanel.add(deleteSessionBtn);
        sessionButtonPanel.add(toggleEnableBtn);

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

    private void addTokenLocation() {
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加令牌位置", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addTokenLocation(
                    dialog.getLocationType(), dialog.getExpression(), dialog.getDescription());
            refreshData();
        }
    }

    private void editTokenLocation() {
        int row = tokenLocationTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TokenLocation selected = tokenLocationModel.getTokenLocation(row);
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑令牌位置", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().updateTokenLocation(
                    selected.getId(), dialog.getLocationType(), dialog.getExpression(), dialog.getDescription());
            refreshData();
        }
    }

    private void deleteTokenLocation() {
        int row = tokenLocationTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TokenLocation selected = tokenLocationModel.getTokenLocation(row);
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
        int row = userSessionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(row);
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
        int row = userSessionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除用户会话: " + selected.getName() + "?",
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteUserSession(selected.getId());
            refreshData();
        }
    }

    private void toggleUserSessionEnabled() {
        int row = userSessionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个用户会话", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        UserSession selected = userSessionModel.getUserSession(row);
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
}
