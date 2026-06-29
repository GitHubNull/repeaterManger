package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 令牌方案编辑对话框
 * 包含方案名称、描述、令牌位置穿梭框选择器、启用状态
 */
public class TokenSchemeEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JTextArea descriptionArea;
    private final JCheckBox enabledCheckbox;
    private final JCheckBox persistToGlobalCheckbox;

    /** 可用令牌位置表格模型 */
    private final AvailableLocationTableModel availableModel;
    /** 已选令牌位置表格模型 */
    private final SelectedLocationTableModel selectedModel;

    private final JTable availableTable;
    private final JTable selectedTable;

    /** 已选的令牌位置ID集合 */
    private final Set<Integer> selectedLocationIds = new HashSet<>();

    public TokenSchemeEditDialog(Frame owner, String title, TokenScheme existing) {
        super(owner, title, true);
        setSize(1052, 684);
        setLocationRelativeTo(owner);
        setResizable(true);

        JPanel mainPanel = new JPanel(new BorderLayout(0, 5));

        // 表单面板（顶部）
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 0, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 名称
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("名称:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        nameField = new JTextField(20);
        formPanel.add(nameField, gbc);

        // 描述
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        formPanel.add(new JLabel("描述:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        descriptionArea = new JTextArea(2, 20);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        JScrollPane descScroll = new JScrollPane(descriptionArea);
        formPanel.add(descScroll, gbc);

        // 启用
        gbc.gridx = 0; gbc.gridy = 2;
        formPanel.add(new JLabel("启用:"), gbc);
        gbc.gridx = 1;
        enabledCheckbox = new JCheckBox("启用此令牌方案", true);
        formPanel.add(enabledCheckbox, gbc);

        // 持久化到全局
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        formPanel.add(new JLabel("全局存储:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        persistToGlobalCheckbox = new JCheckBox("持久化到全局（方便后续项目复用）", true);
        formPanel.add(persistToGlobalCheckbox, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        // 获取所有令牌位置
        List<TokenLocation> allLocations = SessionManager.getInstance().getTokenLocations();

        // 如果是编辑模式，初始化已选位置
        if (existing != null && existing.getTokenLocationIds() != null) {
            selectedLocationIds.addAll(existing.getTokenLocationIds());
        }

        // 可用位置列表（排除已选的）
        List<TokenLocation> availableLocations = new ArrayList<>();
        List<TokenLocation> selectedLocations = new ArrayList<>();
        for (TokenLocation loc : allLocations) {
            if (selectedLocationIds.contains(loc.getId())) {
                selectedLocations.add(loc);
            } else {
                availableLocations.add(loc);
            }
        }

        availableModel = new AvailableLocationTableModel(availableLocations);
        selectedModel = new SelectedLocationTableModel(selectedLocations);

        availableTable = new JTable(availableModel);
        availableTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        availableTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        availableTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        availableTable.getColumnModel().getColumn(2).setPreferredWidth(150);

        selectedTable = new JTable(selectedModel);
        selectedTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        selectedTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        selectedTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        selectedTable.getColumnModel().getColumn(2).setPreferredWidth(150);

        JScrollPane availableScroll = new JScrollPane(availableTable);
        availableScroll.setMinimumSize(new Dimension(150, 150));
        JScrollPane selectedScroll = new JScrollPane(selectedTable);
        selectedScroll.setMinimumSize(new Dimension(150, 150));

        // 中间按钮面板
        JPanel shuttleButtonPanel = new JPanel();
        shuttleButtonPanel.setLayout(new BoxLayout(shuttleButtonPanel, BoxLayout.Y_AXIS));
        JButton addBtn = new JButton("添加 >>");
        JButton addAllBtn = new JButton("全部添加 >>");
        JButton removeBtn = new JButton("<< 移除");
        JButton removeAllBtn = new JButton("<< 全部移除");

        addBtn.addActionListener(e -> moveSelected(availableTable, availableModel, selectedModel));
        addAllBtn.addActionListener(e -> moveAll(availableModel, selectedModel));
        removeBtn.addActionListener(e -> moveSelected(selectedTable, selectedModel, availableModel));
        removeAllBtn.addActionListener(e -> moveAll(selectedModel, availableModel));

        shuttleButtonPanel.add(Box.createVerticalStrut(20));
        shuttleButtonPanel.add(addBtn);
        shuttleButtonPanel.add(Box.createVerticalStrut(5));
        shuttleButtonPanel.add(addAllBtn);
        shuttleButtonPanel.add(Box.createVerticalStrut(15));
        shuttleButtonPanel.add(removeBtn);
        shuttleButtonPanel.add(Box.createVerticalStrut(5));
        shuttleButtonPanel.add(removeAllBtn);

        // 穿梭框整体布局 - 使用 GridBagLayout 实现左右等比例伸缩 + 按钮居中
        JPanel shuttlePanel = new JPanel(new GridBagLayout());
        JPanel availablePanel = new JPanel(new BorderLayout());
        availablePanel.add(new JLabel("可用令牌位置"), BorderLayout.NORTH);
        availablePanel.add(availableScroll, BorderLayout.CENTER);
        JPanel selectedPanel = new JPanel(new BorderLayout());
        selectedPanel.add(new JLabel("已选令牌位置"), BorderLayout.NORTH);
        selectedPanel.add(selectedScroll, BorderLayout.CENTER);

        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.fill = GridBagConstraints.BOTH;
        sgbc.weighty = 1.0;

        // 左侧：可用令牌位置
        sgbc.gridx = 0; sgbc.weightx = 1.0;
        sgbc.insets = new Insets(0, 0, 0, 5);
        shuttlePanel.add(availablePanel, sgbc);

        // 中间：操作按钮（固定宽度，居中）
        sgbc.gridx = 1; sgbc.weightx = 0;
        sgbc.fill = GridBagConstraints.NONE;
        sgbc.anchor = GridBagConstraints.CENTER;
        sgbc.insets = new Insets(0, 8, 0, 8);
        shuttlePanel.add(shuttleButtonPanel, sgbc);

        // 右侧：已选令牌位置
        sgbc.gridx = 2; sgbc.weightx = 1.0;
        sgbc.fill = GridBagConstraints.BOTH;
        sgbc.insets = new Insets(0, 0, 0, 0);
        shuttlePanel.add(selectedPanel, sgbc);

        mainPanel.add(shuttlePanel, BorderLayout.CENTER);

        // 按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");
        okBtn.addActionListener(e -> {
            if (nameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "名称不能为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
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
            descriptionArea.setText(existing.getDescription());
            enabledCheckbox.setSelected(existing.isEnabled());
            persistToGlobalCheckbox.setSelected(existing.isPersistToGlobal());
        }

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(new JScrollPane(mainPanel), BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    /**
     * 将选中的行从一个模型移动到另一个模型
     */
    private void moveSelected(JTable sourceTable, LocationTableModel sourceModel, LocationTableModel targetModel) {
        int[] selectedRows = sourceTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        List<TokenLocation> toMove = new ArrayList<>();
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            toMove.add(sourceModel.getLocation(selectedRows[i]));
        }

        for (TokenLocation loc : toMove) {
            sourceModel.removeLocation(loc);
            targetModel.addLocation(loc);
        }

        // 更新已选ID集合
        syncSelectedIds();
    }

    /**
     * 将所有行从一个模型移动到另一个模型
     */
    private void moveAll(LocationTableModel sourceModel, LocationTableModel targetModel) {
        List<TokenLocation> all = new ArrayList<>(sourceModel.getAllLocations());
        for (TokenLocation loc : all) {
            sourceModel.removeLocation(loc);
            targetModel.addLocation(loc);
        }

        syncSelectedIds();
    }

    private void syncSelectedIds() {
        selectedLocationIds.clear();
        for (TokenLocation loc : selectedModel.getAllLocations()) {
            selectedLocationIds.add(loc.getId());
        }
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getSchemeName() {
        return nameField.getText().trim();
    }

    public String getDescription() {
        return descriptionArea.getText().trim();
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }

    public boolean isPersistToGlobal() {
        return persistToGlobalCheckbox.isSelected();
    }

    public List<Integer> getSelectedTokenLocationIds() {
        return new ArrayList<>(selectedLocationIds);
    }

    // ==================== 内部表格模型 ====================

    private abstract static class LocationTableModel extends AbstractTableModel {
        private static final String[] COLUMN_NAMES = {"类型", "表达式", "描述"};

        protected List<TokenLocation> locations;

        LocationTableModel(List<TokenLocation> locations) {
            this.locations = new ArrayList<>(locations);
        }

        @Override
        public int getRowCount() { return locations.size(); }

        @Override
        public int getColumnCount() { return COLUMN_NAMES.length; }

        @Override
        public String getColumnName(int column) { return COLUMN_NAMES[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TokenLocation loc = locations.get(rowIndex);
            switch (columnIndex) {
                case 0: return loc.getType().getDisplayName();
                case 1: return loc.getExpression();
                case 2: return loc.getDescription();
                default: return null;
            }
        }

        public TokenLocation getLocation(int rowIndex) {
            return locations.get(rowIndex);
        }

        public List<TokenLocation> getAllLocations() {
            return new ArrayList<>(locations);
        }

        public void addLocation(TokenLocation loc) {
            locations.add(loc);
            fireTableRowsInserted(locations.size() - 1, locations.size() - 1);
        }

        public void removeLocation(TokenLocation loc) {
            int idx = -1;
            for (int i = 0; i < locations.size(); i++) {
                if (locations.get(i).getId() == loc.getId()) {
                    idx = i;
                    break;
                }
            }
            if (idx >= 0) {
                locations.remove(idx);
                fireTableRowsDeleted(idx, idx);
            }
        }
    }

    private static class AvailableLocationTableModel extends LocationTableModel {
        AvailableLocationTableModel(List<TokenLocation> locations) { super(locations); }
    }

    private static class SelectedLocationTableModel extends LocationTableModel {
        SelectedLocationTableModel(List<TokenLocation> locations) { super(locations); }
    }
}
