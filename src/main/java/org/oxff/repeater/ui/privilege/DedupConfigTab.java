package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
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

    private JLabel descLabel;
    private JLabel searchLabel;
    private JButton clearSearchBtn;
    private JMenuItem editItem;
    private JMenuItem deleteItem;
    private JMenuItem toggleItem;
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton toggleBtn;
    private JButton importBtn;
    private JButton exportBtn;

    public DedupConfigTab() {
        super(new BorderLayout(0, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // ========== 描述区域 ==========
        JPanel descPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        descLabel = new JLabel(I18nManager.tr("dedup.desc"));
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
        editItem = new JMenuItem(I18nManager.tr("dedup.edit"));
        editItem.addActionListener(e -> editConfig());
        deleteItem = new JMenuItem(I18nManager.tr("dedup.delete"));
        deleteItem.addActionListener(e -> deleteConfig());
        toggleItem = new JMenuItem(I18nManager.tr("dedup.toggle"));
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
        searchLabel = new JLabel(I18nManager.tr("dedup.search"));
        searchPanel.add(searchLabel);
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

        clearSearchBtn = new JButton(I18nManager.tr("dedup.clear"));
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);

        bottomPanel.add(searchPanel, BorderLayout.NORTH);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        addBtn = new JButton(I18nManager.tr("dedup.add"));
        addBtn.addActionListener(e -> addConfig());

        editBtn = new JButton(I18nManager.tr("dedup.edit.title"));
        editBtn.addActionListener(e -> editConfig());

        deleteBtn = new JButton(I18nManager.tr("dedup.delete.title"));
        deleteBtn.addActionListener(e -> deleteConfig());

        toggleBtn = new JButton(I18nManager.tr("dedup.toggle"));
        toggleBtn.addActionListener(e -> toggleConfigEnabled());

        importBtn = new JButton(I18nManager.tr("dedup.import"));
        importBtn.addActionListener(e -> importConfigs());

        exportBtn = new JButton(I18nManager.tr("dedup.export"));
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

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);

        // 初始加载
        refreshData();
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        descLabel.setText(I18nManager.tr("dedup.desc"));
        searchLabel.setText(I18nManager.tr("dedup.search"));
        clearSearchBtn.setText(I18nManager.tr("dedup.clear"));
        editItem.setText(I18nManager.tr("dedup.edit"));
        deleteItem.setText(I18nManager.tr("dedup.delete"));
        toggleItem.setText(I18nManager.tr("dedup.toggle"));
        addBtn.setText(I18nManager.tr("dedup.add"));
        editBtn.setText(I18nManager.tr("dedup.edit.title"));
        deleteBtn.setText(I18nManager.tr("dedup.delete.title"));
        toggleBtn.setText(I18nManager.tr("dedup.toggle"));
        importBtn.setText(I18nManager.tr("dedup.import"));
        exportBtn.setText(I18nManager.tr("dedup.export"));
        tableModel.refreshColumnNames();
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
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("dedup.add"), null);
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
            JOptionPane.showMessageDialog(this, I18nManager.tr("dedup.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = configTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) return;

        DedupConfig selected = tableModel.getConfig(modelRow);
        DedupConfigEditDialog dialog = new DedupConfigEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("dedup.edit.title"), selected);
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
            JOptionPane.showMessageDialog(this, I18nManager.tr("dedup.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = configTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0) return;

        DedupConfig selected = tableModel.getConfig(modelRow);
        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("dedup.delete.confirm",
                        selected.getStrategy().getDisplayName(), selected.getPriority()),
                I18nManager.tr("dedup.delete.title"), JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            DedupConfigManager.getInstance().deleteConfig(selected.getId());
            refreshData();
        }
    }

    private void toggleConfigEnabled() {
        int viewRow = configTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("dedup.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
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
                "TOKEN_LOCATION", I18nManager.tr("dedup.export.dialog"), this,
                new File("dedup_configs.yaml"),
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter"), "yaml"));

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
                        I18nManager.tr("dedup.export.success", allConfigs.size(), file.getAbsolutePath()),
                        I18nManager.tr("dedup.export.success.title"), JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("dedup.export.failed", e.getMessage()),
                    I18nManager.tr("dedup.export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importConfigs() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                "TOKEN_LOCATION", I18nManager.tr("dedup.import.dialog"), this,
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter.all"), "yaml", "yml"));

        if (selectedFile == null) return;

        try {
            List<DedupConfig> imported = DedupConfigYamlIO.readFromFile(selectedFile.getAbsolutePath());
            if (imported.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        I18nManager.tr("dedup.import.empty"),
                        I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // 选择导入模式
            String[] options = {I18nManager.tr("dedup.import.merge"),
                    I18nManager.tr("dedup.import.replace"), I18nManager.tr("dedup.import.cancel")};
            int choice = JOptionPane.showOptionDialog(this,
                    I18nManager.tr("dedup.import.choice.msg", imported.size()),
                    I18nManager.tr("dedup.import.choice.title"),
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
                        I18nManager.tr("dedup.import.merge.done", count),
                        I18nManager.tr("dedup.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
            } else if (choice == 1) {
                int confirm = JOptionPane.showConfirmDialog(this,
                        I18nManager.tr("dedup.import.replace.confirm"),
                        I18nManager.tr("dedup.import.replace.title"),
                        JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
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
                            I18nManager.tr("dedup.import.replace.done", count),
                            I18nManager.tr("dedup.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("dedup.import.failed", e.getMessage()),
                    I18nManager.tr("dedup.import.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    // ==================== TableModel ====================

    private static class DedupConfigTableModel extends AbstractTableModel {

        private static final String[] COLUMN_KEYS = {
            "dedup.col.index", "dedup.col.strategy", "dedup.col.expression",
            "dedup.col.keep", "dedup.col.priority", "dedup.col.enabled", "dedup.col.storage"
        };
        private List<DedupConfig> data = new ArrayList<>();

        public void setData(List<DedupConfig> configs) {
            this.data = configs != null ? configs : new ArrayList<>();
            fireTableDataChanged();
        }

        /**
         * 语言切换后刷新列名
         */
        public void refreshColumnNames() {
            fireTableStructureChanged();
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
            return COLUMN_KEYS.length;
        }

        @Override
        public String getColumnName(int column) {
            return I18nManager.tr(COLUMN_KEYS[column]);
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0 || columnIndex == 4) return Integer.class;
            if (columnIndex == 5) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 5;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex != 5 || rowIndex < 0 || rowIndex >= data.size()) return;
            DedupConfig config = data.get(rowIndex);
            config.setEnabled(Boolean.TRUE.equals(aValue));
            DedupConfigManager.getInstance().updateConfig(config.getId(), config);
            fireTableRowsUpdated(rowIndex, rowIndex);
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
