package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.ScopeManager;
import org.oxff.repeater.privilege.model.ScopeEntry;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Scope配置子Tab
 * 包含：Scope条目管理 + Burp Scope开关 + 自动化测试开关
 */
public class ScopeConfigTab extends JPanel {

    private final JTable scopeTable;
    private final ScopeTableModel scopeModel;
    private JCheckBox useBurpScopeCheckbox;
    private JCheckBox autoTestCheckbox;
    private JLabel statusLabel;
    /** autoTestCheckbox 的 ActionListener 实例引用，供 syncAutoTestCheckbox 临时移除/恢复使用 */
    private final ActionListener autoTestActionListener = e -> toggleAutoTest();

    private JPanel controlPanel;
    private JButton clearDedupBtn;
    private JPanel tablePanel;
    private JPanel infoPanel;
    private JTextArea infoArea;
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton toggleBtn;

    public ScopeConfigTab() {
        super(new BorderLayout(0, 5));

        // ========== 自动化测试控制面板 ==========
        controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("scope.autoTest")));

        autoTestCheckbox = new JCheckBox(I18nManager.tr("scope.enableAutoTest"), false);
        autoTestCheckbox.setToolTipText(I18nManager.tr("scope.autoTest.tooltip"));
        autoTestCheckbox.addActionListener(autoTestActionListener);

        useBurpScopeCheckbox = new JCheckBox(I18nManager.tr("scope.useBurpScope"), false);
        useBurpScopeCheckbox.setToolTipText(I18nManager.tr("scope.useBurpScope.tooltip"));
        useBurpScopeCheckbox.addActionListener(e -> {
            ScopeManager.getInstance().setUseBurpScope(useBurpScopeCheckbox.isSelected());
        });

        clearDedupBtn = new JButton(I18nManager.tr("scope.clearDedup"));
        clearDedupBtn.addActionListener(e -> {
            org.oxff.repeater.privilege.AutoTestEngine.getInstance().clearProcessedApis();
            updateStatus();
            JOptionPane.showMessageDialog(this, I18nManager.tr("scope.clearDedup.done"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
        });

        statusLabel = new JLabel(I18nManager.tr("scope.status.stopped"));

        controlPanel.add(autoTestCheckbox);
        controlPanel.add(useBurpScopeCheckbox);
        controlPanel.add(clearDedupBtn);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(statusLabel);

        // ========== Scope表格 ==========
        tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("scope.table.title")));

        scopeModel = new ScopeTableModel();
        scopeTable = new JTable(scopeModel);
        scopeTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scopeTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // 名称
        scopeTable.getColumnModel().getColumn(1).setPreferredWidth(300);  // URL模式
        scopeTable.getColumnModel().getColumn(2).setPreferredWidth(40);   // 启用
        scopeTable.getColumnModel().getColumn(3).setPreferredWidth(200);  // 描述

        JScrollPane scrollPane = new JScrollPane(scopeTable);
        scrollPane.setPreferredSize(new Dimension(0, 200));
        tablePanel.add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton(I18nManager.tr("scope.add"));
        editBtn = new JButton(I18nManager.tr("scope.edit"));
        deleteBtn = new JButton(I18nManager.tr("scope.delete"));
        toggleBtn = new JButton(I18nManager.tr("scope.toggle"));

        addBtn.addActionListener(e -> addEntry());
        editBtn.addActionListener(e -> editEntry());
        deleteBtn.addActionListener(e -> deleteEntry());
        toggleBtn.addActionListener(e -> toggleEntry());

        buttonPanel.add(addBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(toggleBtn);

        tablePanel.add(buttonPanel, BorderLayout.SOUTH);

        // ========== 说明面板 ==========
        infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("scope.info.title")));
        infoArea = new JTextArea(2, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(I18nManager.tr("scope.info.text"));
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        // ========== 组装 ==========
        add(controlPanel, BorderLayout.NORTH);
        add(tablePanel, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.SOUTH);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);

        // 初始加载
        refreshData();
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        ((TitledBorder) controlPanel.getBorder()).setTitle(I18nManager.tr("scope.autoTest"));
        autoTestCheckbox.setText(I18nManager.tr("scope.enableAutoTest"));
        autoTestCheckbox.setToolTipText(I18nManager.tr("scope.autoTest.tooltip"));
        useBurpScopeCheckbox.setText(I18nManager.tr("scope.useBurpScope"));
        useBurpScopeCheckbox.setToolTipText(I18nManager.tr("scope.useBurpScope.tooltip"));
        clearDedupBtn.setText(I18nManager.tr("scope.clearDedup"));
        ((TitledBorder) tablePanel.getBorder()).setTitle(I18nManager.tr("scope.table.title"));
        addBtn.setText(I18nManager.tr("scope.add"));
        editBtn.setText(I18nManager.tr("scope.edit"));
        deleteBtn.setText(I18nManager.tr("scope.delete"));
        toggleBtn.setText(I18nManager.tr("scope.toggle"));
        ((TitledBorder) infoPanel.getBorder()).setTitle(I18nManager.tr("scope.info.title"));
        infoArea.setText(I18nManager.tr("scope.info.text"));
        scopeModel.refreshColumnNames();
        updateStatus();
        repaint();
    }

    /**
     * 刷新数据，同步ScopeManager状态到UI组件
     */
    public void refreshData() {
        ScopeManager manager = ScopeManager.getInstance();
        scopeModel.setData(manager.getAllEntries());
        useBurpScopeCheckbox.setSelected(manager.isUseBurpScope());
        syncAutoTestCheckbox(manager);
        updateStatus();
    }

    /**
     * 仅同步autoTestCheckbox状态（不触发ActionListener，避免递归调用toggleAutoTest）
     * 供外部联动变更（如越权模式按钮切换）后同步UI状态使用
     */
    public void syncAutoTestState() {
        syncAutoTestCheckbox(ScopeManager.getInstance());
        updateStatus();
    }

    /**
     * 同步autoTestCheckbox到ScopeManager当前状态
     * 临时移除ActionListener避免 setSelected 触发 toggleAutoTest → setAutoTestEnabled 递归
     */
    private void syncAutoTestCheckbox(ScopeManager manager) {
        autoTestCheckbox.removeActionListener(autoTestActionListener);
        try {
            autoTestCheckbox.setSelected(manager.isAutoTestEnabled());
        } finally {
            autoTestCheckbox.addActionListener(autoTestActionListener);
        }
    }

    private void updateStatus() {
        if (ScopeManager.getInstance().isAutoTestEnabled()) {
            int count = org.oxff.repeater.privilege.AutoTestEngine.getInstance().getProcessedApiCount();
            statusLabel.setText(I18nManager.tr("scope.status.running", count));
        } else {
            statusLabel.setText(I18nManager.tr("scope.status.stopped"));
        }
    }

    private void toggleAutoTest() {
        ScopeManager.getInstance().setAutoTestEnabled(autoTestCheckbox.isSelected());
        updateStatus();
    }

    private void addEntry() {
        ScopeEditDialog dialog = new ScopeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("scope.add.title"), null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            ScopeEntry entry = new ScopeEntry();
            entry.setName(dialog.getEntryName());
            entry.setUrlPattern(dialog.getUrlPattern());
            entry.setEnabled(dialog.isEntryEnabled());
            entry.setDescription(dialog.getDescription());
            ScopeManager.getInstance().addEntry(entry);
            refreshData();
        }
    }

    private void editEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scope.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ScopeEntry selected = scopeModel.getEntry(row);
        ScopeEditDialog dialog = new ScopeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("scope.edit.title"), selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            selected.setName(dialog.getEntryName());
            selected.setUrlPattern(dialog.getUrlPattern());
            selected.setEnabled(dialog.isEntryEnabled());
            selected.setDescription(dialog.getDescription());
            ScopeManager.getInstance().updateEntry(selected);
            refreshData();
        }
    }

    private void deleteEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scope.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ScopeEntry selected = scopeModel.getEntry(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("scope.delete.confirm", selected.getName()),
                I18nManager.tr("scope.delete.confirm.title"), JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            ScopeManager.getInstance().deleteEntry(selected.getId());
            refreshData();
        }
    }

    private void toggleEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scope.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ScopeEntry selected = scopeModel.getEntry(row);
        ScopeManager.getInstance().toggleEntryEnabled(selected.getId(), !selected.isEnabled());
        refreshData();
    }

    /**
     * Scope表格模型
     */
    private static class ScopeTableModel extends AbstractTableModel {
        private static final String[] COLUMN_KEYS = {
            "scope.col.name", "scope.col.urlPattern", "scope.col.enabled", "scope.col.description"
        };
        private List<ScopeEntry> entries = new ArrayList<>();

        public void setData(List<ScopeEntry> entries) {
            this.entries = entries != null ? entries : new ArrayList<>();
            fireTableDataChanged();
        }

        /**
         * 语言切换后刷新列名
         */
        public void refreshColumnNames() {
            fireTableStructureChanged();
        }

        public ScopeEntry getEntry(int row) {
            if (row >= 0 && row < entries.size()) return entries.get(row);
            return null;
        }

        @Override
        public int getRowCount() { return entries.size(); }
        @Override
        public int getColumnCount() { return COLUMN_KEYS.length; }
        @Override
        public String getColumnName(int column) { return I18nManager.tr(COLUMN_KEYS[column]); }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ScopeEntry entry = entries.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> entry.getName() != null ? entry.getName() : "";
                case 1 -> entry.getUrlPattern() != null ? entry.getUrlPattern() : "";
                case 2 -> entry.isEnabled() ? I18nManager.tr("common.yes") : I18nManager.tr("common.no");
                case 3 -> entry.getDescription() != null ? entry.getDescription() : "";
                default -> "";
            };
        }
    }

    /**
     * Scope条目编辑对话框
     */
    private static class ScopeEditDialog extends JDialog {
        private boolean confirmed = false;
        private JTextField nameField;
        private JTextField urlPatternField;
        private JCheckBox enabledCheckbox;
        private JTextField descriptionField;

        public ScopeEditDialog(Frame owner, String title, ScopeEntry entry) {
            super(owner, title, true);
            initComponents();
            if (entry != null) populateFields(entry);
            pack();
            setLocationRelativeTo(owner);
        }

        private void initComponents() {
            JPanel mainPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(4, 8, 4, 8);
            gbc.fill = GridBagConstraints.HORIZONTAL;

            int row = 0;
            gbc.gridx = 0; gbc.gridy = row;
            mainPanel.add(new JLabel(I18nManager.tr("scope.dialog.name")), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            nameField = new JTextField(30);
            mainPanel.add(nameField, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
            mainPanel.add(new JLabel(I18nManager.tr("scope.dialog.urlPattern")), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            urlPatternField = new JTextField(30);
            mainPanel.add(urlPatternField, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row;
            mainPanel.add(new JLabel(I18nManager.tr("scope.dialog.enabled")), gbc);
            gbc.gridx = 1; gbc.gridy = row;
            enabledCheckbox = new JCheckBox();
            enabledCheckbox.setSelected(true);
            mainPanel.add(enabledCheckbox, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row;
            mainPanel.add(new JLabel(I18nManager.tr("scope.dialog.description")), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            descriptionField = new JTextField(30);
            mainPanel.add(descriptionField, gbc);

            row++;
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton okBtn = new JButton(I18nManager.tr("common.ok"));
            JButton cancelBtn = new JButton(I18nManager.tr("common.cancel"));
            okBtn.addActionListener(e -> onOk());
            cancelBtn.addActionListener(e -> { confirmed = false; dispose(); });
            buttonPanel.add(okBtn);
            buttonPanel.add(cancelBtn);
            gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
            mainPanel.add(buttonPanel, gbc);

            setContentPane(mainPanel);
            setMinimumSize(new Dimension(400, 200));
        }

        private void populateFields(ScopeEntry entry) {
            if (entry.getName() != null) nameField.setText(entry.getName());
            if (entry.getUrlPattern() != null) urlPatternField.setText(entry.getUrlPattern());
            enabledCheckbox.setSelected(entry.isEnabled());
            if (entry.getDescription() != null) descriptionField.setText(entry.getDescription());
        }

        private void onOk() {
            if (urlPatternField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, I18nManager.tr("scope.dialog.urlPattern.empty"),
                        I18nManager.tr("scope.dialog.validation.failed"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        }

        public boolean isConfirmed() { return confirmed; }
        public String getEntryName() { return nameField.getText().trim(); }
        public String getUrlPattern() { return urlPatternField.getText().trim(); }
        public boolean isEntryEnabled() { return enabledCheckbox.isSelected(); }
        public String getDescription() { return descriptionField.getText().trim(); }
    }
}
