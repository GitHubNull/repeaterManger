package oxff.top.ui.privilege;

import oxff.top.privilege.ScopeManager;
import oxff.top.privilege.model.ScopeEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
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

    public ScopeConfigTab() {
        super(new BorderLayout(0, 5));

        // ========== 自动化测试控制面板 ==========
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.setBorder(BorderFactory.createTitledBorder("自动化测试控制"));

        autoTestCheckbox = new JCheckBox("启用自动化测试", false);
        autoTestCheckbox.setToolTipText("开启后将自动监听代理流量，对匹配Scope的请求执行权限测试");
        autoTestCheckbox.addActionListener(e -> toggleAutoTest());

        useBurpScopeCheckbox = new JCheckBox("使用Burp Suite Scope", false);
        useBurpScopeCheckbox.setToolTipText("同时使用Burp Suite自身的Target Scope作为匹配范围");
        useBurpScopeCheckbox.addActionListener(e -> {
            ScopeManager.getInstance().setUseBurpScope(useBurpScopeCheckbox.isSelected());
        });

        JButton clearDedupBtn = new JButton("清除去重记录");
        clearDedupBtn.addActionListener(e -> {
            oxff.top.privilege.AutoTestEngine.getInstance().clearProcessedApis();
            updateStatus();
            JOptionPane.showMessageDialog(this, "去重记录已清除", "提示", JOptionPane.INFORMATION_MESSAGE);
        });

        statusLabel = new JLabel("状态: 已停止");

        controlPanel.add(autoTestCheckbox);
        controlPanel.add(useBurpScopeCheckbox);
        controlPanel.add(clearDedupBtn);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(statusLabel);

        // ========== Scope表格 ==========
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("自定义Scope"));

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
        JButton addBtn = new JButton("添加条目");
        JButton editBtn = new JButton("编辑条目");
        JButton deleteBtn = new JButton("删除条目");
        JButton toggleBtn = new JButton("启用/禁用");

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
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("使用说明"));
        JTextArea infoArea = new JTextArea(2, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(
            "• 添加URL匹配模式（支持通配符 * ），如 *.example.com/api/*\n" +
            "• 启用自动化测试后，匹配Scope的代理请求将自动遍历用户会话重放"
        );
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        // ========== 组装 ==========
        add(controlPanel, BorderLayout.NORTH);
        add(tablePanel, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.SOUTH);

        // 初始加载
        refreshData();
    }

    public void refreshData() {
        ScopeManager manager = ScopeManager.getInstance();
        scopeModel.setData(manager.getAllEntries());
        useBurpScopeCheckbox.setSelected(manager.isUseBurpScope());
        autoTestCheckbox.setSelected(manager.isAutoTestEnabled());
        updateStatus();
    }

    private void updateStatus() {
        if (ScopeManager.getInstance().isAutoTestEnabled()) {
            int count = oxff.top.privilege.AutoTestEngine.getInstance().getProcessedApiCount();
            statusLabel.setText("状态: 运行中 | 已处理: " + count + " 个API");
        } else {
            statusLabel.setText("状态: 已停止");
        }
    }

    private void toggleAutoTest() {
        ScopeManager.getInstance().setAutoTestEnabled(autoTestCheckbox.isSelected());
        updateStatus();
    }

    private void addEntry() {
        ScopeEditDialog dialog = new ScopeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加Scope条目", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            ScopeEntry entry = new ScopeEntry();
            entry.setName(dialog.getEntryName());
            entry.setUrlPattern(dialog.getUrlPattern());
            entry.setEnabled(dialog.isEnabled());
            entry.setDescription(dialog.getDescription());
            ScopeManager.getInstance().addEntry(entry);
            refreshData();
        }
    }

    private void editEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个条目", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ScopeEntry selected = scopeModel.getEntry(row);
        ScopeEditDialog dialog = new ScopeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑Scope条目", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            selected.setName(dialog.getEntryName());
            selected.setUrlPattern(dialog.getUrlPattern());
            selected.setEnabled(dialog.isEnabled());
            selected.setDescription(dialog.getDescription());
            ScopeManager.getInstance().updateEntry(selected);
            refreshData();
        }
    }

    private void deleteEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个条目", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        ScopeEntry selected = scopeModel.getEntry(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除Scope条目: " + selected.getName() + "?",
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            ScopeManager.getInstance().deleteEntry(selected.getId());
            refreshData();
        }
    }

    private void toggleEntry() {
        int row = scopeTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个条目", "提示", JOptionPane.INFORMATION_MESSAGE);
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
        private static final String[] COLUMN_NAMES = {"名称", "URL模式", "启用", "描述"};
        private List<ScopeEntry> entries = new ArrayList<>();

        public void setData(List<ScopeEntry> entries) {
            this.entries = entries != null ? entries : new ArrayList<>();
            fireTableDataChanged();
        }

        public ScopeEntry getEntry(int row) {
            if (row >= 0 && row < entries.size()) return entries.get(row);
            return null;
        }

        @Override
        public int getRowCount() { return entries.size(); }
        @Override
        public int getColumnCount() { return COLUMN_NAMES.length; }
        @Override
        public String getColumnName(int column) { return COLUMN_NAMES[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ScopeEntry entry = entries.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> entry.getName() != null ? entry.getName() : "";
                case 1 -> entry.getUrlPattern() != null ? entry.getUrlPattern() : "";
                case 2 -> entry.isEnabled() ? "是" : "否";
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
            mainPanel.add(new JLabel("名称:"), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            nameField = new JTextField(30);
            mainPanel.add(nameField, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
            mainPanel.add(new JLabel("URL模式:"), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            urlPatternField = new JTextField(30);
            mainPanel.add(urlPatternField, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row;
            mainPanel.add(new JLabel("启用:"), gbc);
            gbc.gridx = 1; gbc.gridy = row;
            enabledCheckbox = new JCheckBox();
            enabledCheckbox.setSelected(true);
            mainPanel.add(enabledCheckbox, gbc);

            row++;
            gbc.gridx = 0; gbc.gridy = row;
            mainPanel.add(new JLabel("描述:"), gbc);
            gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
            descriptionField = new JTextField(30);
            mainPanel.add(descriptionField, gbc);

            row++;
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton okBtn = new JButton("确定");
            JButton cancelBtn = new JButton("取消");
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
                JOptionPane.showMessageDialog(this, "URL模式不能为空", "验证错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        }

        public boolean isConfirmed() { return confirmed; }
        public String getEntryName() { return nameField.getText().trim(); }
        public String getUrlPattern() { return urlPatternField.getText().trim(); }
        public boolean isEnabled() { return enabledCheckbox.isSelected(); }
        public String getDescription() { return descriptionField.getText().trim(); }
    }
}
