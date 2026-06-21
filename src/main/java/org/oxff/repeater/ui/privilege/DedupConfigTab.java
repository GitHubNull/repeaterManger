package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.DedupConfigManager;
import org.oxff.repeater.privilege.model.DedupConfig;
import org.oxff.repeater.privilege.DedupConfigYamlIO;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.PatternSyntaxException;

/**
 * 去重配置子标签页
 * 管理多配置优先级链式匹配，支持全局持久化和会话级存储
 */
public class DedupConfigTab extends JPanel {

    private final JTable configTable;
    private final DedupConfigTableModel tableModel;
    private TableRowSorter<DedupConfigTableModel> tableSorter;
    private JTextField searchField;

    public DedupConfigTab() {
        super(new BorderLayout(0, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // ========== 描述区域 ==========
        JPanel descPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel descLabel = new JLabel("去重配置按优先级顺序生效，数字越小优先级越高。所有策略失败时回退到PATH策略。");
        descLabel.setFont(new Font("SansSerif", Font.ITALIC, 12));
        descPanel.add(descLabel);
        add(descPanel, BorderLayout.NORTH);

        // ========== 表格 ==========
        tableModel = new DedupConfigTableModel();
        configTable = new JTable(tableModel);
        configTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configTable.getColumnModel().getColumn(0).setPreferredWidth(30);   // #
        configTable.getColumnModel().getColumn(1).setPreferredWidth(100);  // 策略
        configTable.getColumnModel().getColumn(2).setPreferredWidth(120);  // 表达式
        configTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // 保留策略
        configTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // 优先级
        configTable.getColumnModel().getColumn(5).setPreferredWidth(50);   // 启用
        configTable.getColumnModel().getColumn(6).setPreferredWidth(80);   // 存储类型

        tableSorter = new TableRowSorter<>(tableModel);
        configTable.setRowSorter(tableSorter);

        // 双击编辑
        configTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = configTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editConfig();
                    }
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                selectRowOnRightClick(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                selectRowOnRightClick(e);
            }
        });

        // 右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem editItem = new JMenuItem("编辑");
        editItem.addActionListener(e -> editConfig());
        JMenuItem deleteItem = new JMenuItem("删除");
        deleteItem.addActionListener(e -> deleteConfig());
        JMenuItem toggleItem = new JMenuItem("启用/禁用");
        toggleItem.addActionListener(e -> toggleConfigEnabled());
        popupMenu.add(editItem);
        popupMenu.add(toggleItem);
        popupMenu.addSeparator();
        popupMenu.add(deleteItem);
        configTable.setComponentPopupMenu(popupMenu);

        JScrollPane tableScroll = new JScrollPane(configTable);
        tableScroll.setPreferredSize(new Dimension(0, 200));
        add(tableScroll, BorderLayout.CENTER);

        // ========== 底部面板：搜索 + 按钮 ==========
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));

        // 搜索面板
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchPanel.add(new JLabel("搜索:"));
        searchField = new JTextField(15);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
        });
        searchPanel.add(searchField);

        JButton clearSearchBtn = new JButton("清除");
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);

        bottomPanel.add(searchPanel, BorderLayout.NORTH);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton addBtn = new JButton("添加配置");
        addBtn.addActionListener(e -> addConfig());

        JButton editBtn = new JButton("编辑配置");
        editBtn.addActionListener(e -> editConfig());

        JButton deleteBtn = new JButton("删除配置");
        deleteBtn.addActionListener(e -> deleteConfig());

        JButton toggleBtn = new JButton("启用/禁用");
        toggleBtn.addActionListener(e -> toggleConfigEnabled());

        JButton importBtn = new JButton("导入");
        importBtn.addActionListener(e -> importConfigs());

        JButton exportBtn = new JButton("导出");
        exportBtn.addActionListener(e -> exportConfigs());

        buttonPanel.add(addBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(toggleBtn);
        buttonPanel.add(Box.createHorizontalStrut(10));
        buttonPanel.add(importBtn);
        buttonPanel.add(exportBtn);

        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        add(bottomPanel, BorderLayout.SOUTH);

        // 初始加载
        refreshData();
    }

    private void selectRowOnRightClick(MouseEvent e) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = configTable.rowAtPoint(e.getPoint());
            if (row >= 0) {
                configTable.setRowSelectionInterval(row, row);
            }
        }
    }

    private void applyFilter() {
        String text = searchField.getText().trim();
        if (text.isEmpty()) {
            tableSorter.setRowFilter(null);
            return;
        }
        try {
            tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        } catch (PatternSyntaxException e) {
            // 忽略无效的正则
        }
    }

    public void refreshData() {
        DedupConfigManager mgr = DedupConfigManager.getInstance();
        tableModel.setData(mgr.getAllConfigs());
    }

    // ========== CRUD操作 ==========

    private void addConfig() {
        DedupConfigEditDialog dialog = new DedupConfigEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加去重配置", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            DedupConfig config = dialog.getConfig();
            DedupConfigManager mgr = DedupConfigManager.getInstance();
            if (config.getStorageType() == DedupConfig.StorageType.GLOBAL) {
                mgr.addGlobalConfig(config);
            } else {
                mgr.addSessionConfig(config);
            }
            refreshData();
        }
    }

    private void editConfig() {
        int viewRow = configTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条配置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = configTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) return;

        DedupConfig selected = tableModel.getConfig(modelRow);
        DedupConfigEditDialog dialog = new DedupConfigEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑去重配置", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            DedupConfig config = dialog.getConfig();
            DedupConfigManager mgr = DedupConfigManager.getInstance();
            mgr.updateConfig(selected.getId(), config);
            refreshData();
        }
    }

    private void deleteConfig() {
        int viewRow = configTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条配置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = configTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) return;

        DedupConfig selected = tableModel.getConfig(modelRow);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除此去重配置？\n策略: " + selected.getStrategy().getDisplayName()
                        + " | 优先级: " + selected.getPriority(),
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            DedupConfigManager.getInstance().deleteConfig(selected.getId());
            refreshData();
        }
    }

    private void toggleConfigEnabled() {
        int viewRow = configTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条配置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = configTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) return;

        DedupConfig config = tableModel.getConfig(modelRow);
        config.setEnabled(!config.isEnabled());
        DedupConfigManager.getInstance().updateConfig(config.getId(), config);
        refreshData();
    }

    // ========== 导入导出 ==========

    private void exportConfigs() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                "TOKEN_LOCATION", "导出去重配置", this,
                new File("dedup_configs.yaml"),
                new FileNameExtensionFilter("YAML文件 (*.yaml)", "yaml"));

        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            List<DedupConfig> allConfigs = DedupConfigManager.getInstance().getAllConfigs();
            boolean success = DedupConfigYamlIO.writeToFile(allConfigs, file.getAbsolutePath());
            if (success) {
                JOptionPane.showMessageDialog(this,
                        "成功导出 " + allConfigs.size() + " 条去重配置到:\n" + file.getAbsolutePath(),
                        "导出成功", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importConfigs() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                "TOKEN_LOCATION", "导入去重配置", this,
                new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

        if (selectedFile == null) return;

        try {
            List<DedupConfig> imported = DedupConfigYamlIO.readFromFile(selectedFile.getAbsolutePath());
            if (imported.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "文件中没有找到去重配置数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // 选择导入模式
            String[] options = {"合并导入", "替换导入", "取消"};
            int choice = JOptionPane.showOptionDialog(this,
                    "发现 " + imported.size() + " 条去重配置，请选择导入方式：\n" +
                            "合并导入：保留现有配置，追加新配置\n" +
                            "替换导入：清空所有现有配置后导入",
                    "导入方式",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                    null, options, options[0]);

            DedupConfigManager mgr = DedupConfigManager.getInstance();

            if (choice == 0) {
                // 合并导入：追加到全局配置
                int count = 0;
                for (DedupConfig config : imported) {
                    config.setStorageType(DedupConfig.StorageType.GLOBAL);
                    mgr.addGlobalConfig(config);
                    count++;
                }
                refreshData();
                JOptionPane.showMessageDialog(this,
                        "合并导入完成，新增 " + count + " 条去重配置",
                        "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } else if (choice == 1) {
                int confirm = JOptionPane.showConfirmDialog(this,
                        "替换导入将删除所有现有去重配置，是否继续？",
                        "替换确认", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (confirm == JOptionPane.YES_OPTION) {
                    // 清空现有全局配置
                    for (DedupConfig existing : mgr.getGlobalConfigs()) {
                        mgr.deleteGlobalConfig(existing.getId());
                    }
                    mgr.clearSessionConfigs();
                    // 导入
                    int count = 0;
                    for (DedupConfig config : imported) {
                        config.setStorageType(DedupConfig.StorageType.GLOBAL);
                        mgr.addGlobalConfig(config);
                        count++;
                    }
                    refreshData();
                    JOptionPane.showMessageDialog(this,
                            "替换导入完成，共导入 " + count + " 条去重配置",
                            "导入成功", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ==================== TableModel ====================

    private static class DedupConfigTableModel extends AbstractTableModel {

        private final String[] columnNames = {"#", "去重策略", "表达式", "保留策略", "优先级", "启用", "存储类型"};
        private List<DedupConfig> data = new ArrayList<>();

        public void setData(List<DedupConfig> configs) {
            this.data = configs != null ? configs : new ArrayList<>();
            fireTableDataChanged();
        }

        public DedupConfig getConfig(int row) {
            return data.get(row);
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0 || columnIndex == 4) return Integer.class;
            if (columnIndex == 5) return Boolean.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DedupConfig config = data.get(rowIndex);
            switch (columnIndex) {
                case 0: return config.getPriority(); // 用优先级作为行号显示
                case 1: return config.getStrategy().getDisplayName();
                case 2: return config.getExpression().isEmpty() ? "-" : config.getExpression();
                case 3: return config.getKeepPolicy().getDisplayName();
                case 4: return config.getPriority();
                case 5: return config.isEnabled();
                case 6: return config.getStorageType().getDisplayName();
                default: return "";
            }
        }
    }
}
