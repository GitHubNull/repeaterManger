package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 方案编辑对话框
 * 包含方案名称、描述、字段定义穿梭框选择器、启用状态
 */
public class SchemeEditDialog extends JDialog {

    private boolean confirmed = false;

    private final JTextField nameField;
    private final JTextArea descriptionArea;
    private final JCheckBox enabledCheckbox;
    private final JCheckBox persistToGlobalCheckbox;

    /** 可用字段定义表格模型 */
    private final AvailableFieldTableModel availableModel;
    /** 已选字段定义表格模型 */
    private final SelectedFieldTableModel selectedModel;

    private final JTable availableTable;
    private final JTable selectedTable;

    /** 已选的字段定义ID集合 */
    private final Set<Integer> selectedFieldIds = new HashSet<>();

    public SchemeEditDialog(Frame owner, String title, Scheme existing) {
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
        enabledCheckbox = new JCheckBox("启用此方案", true);
        formPanel.add(enabledCheckbox, gbc);

        // 持久化到全局
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        formPanel.add(new JLabel("全局存储:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        persistToGlobalCheckbox = new JCheckBox("持久化到全局（方便后续项目复用）", true);
        formPanel.add(persistToGlobalCheckbox, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        // 获取所有字段定义
        List<FieldDefinition> allFields = SessionManager.getInstance().getFieldDefinitions();

        // 如果是编辑模式，初始化已选字段
        if (existing != null && existing.getFieldIds() != null) {
            selectedFieldIds.addAll(existing.getFieldIds());
        }

        // 可用字段列表（排除已选的）
        List<FieldDefinition> availableFields = new ArrayList<>();
        List<FieldDefinition> selectedFields = new ArrayList<>();
        for (FieldDefinition field : allFields) {
            if (selectedFieldIds.contains(field.getId())) {
                selectedFields.add(field);
            } else {
                availableFields.add(field);
            }
        }

        availableModel = new AvailableFieldTableModel(availableFields);
        selectedModel = new SelectedFieldTableModel(selectedFields);

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
        availablePanel.add(new JLabel("可用字段定义"), BorderLayout.NORTH);
        availablePanel.add(availableScroll, BorderLayout.CENTER);
        JPanel selectedPanel = new JPanel(new BorderLayout());
        selectedPanel.add(new JLabel("已选字段定义"), BorderLayout.NORTH);
        selectedPanel.add(selectedScroll, BorderLayout.CENTER);

        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.fill = GridBagConstraints.BOTH;
        sgbc.weighty = 1.0;

        // 左侧：可用字段定义
        sgbc.gridx = 0; sgbc.weightx = 1.0;
        sgbc.insets = new Insets(0, 0, 0, 5);
        shuttlePanel.add(availablePanel, sgbc);

        // 中间：操作按钮（固定宽度，居中）
        sgbc.gridx = 1; sgbc.weightx = 0;
        sgbc.fill = GridBagConstraints.NONE;
        sgbc.anchor = GridBagConstraints.CENTER;
        sgbc.insets = new Insets(0, 8, 0, 8);
        shuttlePanel.add(shuttleButtonPanel, sgbc);

        // 右侧：已选字段定义
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
    private void moveSelected(JTable sourceTable, FieldTableModel sourceModel, FieldTableModel targetModel) {
        int[] selectedRows = sourceTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        List<FieldDefinition> toMove = new ArrayList<>();
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            toMove.add(sourceModel.getField(selectedRows[i]));
        }

        for (FieldDefinition field : toMove) {
            sourceModel.removeField(field);
            targetModel.addField(field);
        }

        // 更新已选ID集合
        syncSelectedIds();
    }

    /**
     * 将所有行从一个模型移动到另一个模型
     */
    private void moveAll(FieldTableModel sourceModel, FieldTableModel targetModel) {
        List<FieldDefinition> all = new ArrayList<>(sourceModel.getAllFields());
        for (FieldDefinition field : all) {
            sourceModel.removeField(field);
            targetModel.addField(field);
        }

        syncSelectedIds();
    }

    private void syncSelectedIds() {
        selectedFieldIds.clear();
        for (FieldDefinition field : selectedModel.getAllFields()) {
            selectedFieldIds.add(field.getId());
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

    public List<Integer> getSelectedFieldIds() {
        return new ArrayList<>(selectedFieldIds);
    }

    // ==================== 内部表格模型 ====================

    private abstract static class FieldTableModel extends AbstractTableModel {
        private static final String[] COLUMN_NAMES = {"类型", "表达式", "描述"};

        protected List<FieldDefinition> fields;

        FieldTableModel(List<FieldDefinition> fields) {
            this.fields = new ArrayList<>(fields);
        }

        @Override
        public int getRowCount() { return fields.size(); }

        @Override
        public int getColumnCount() { return COLUMN_NAMES.length; }

        @Override
        public String getColumnName(int column) { return COLUMN_NAMES[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            FieldDefinition field = fields.get(rowIndex);
            switch (columnIndex) {
                case 0: return field.getType().getDisplayName();
                case 1: return field.getExpression();
                case 2: return field.getDescription();
                default: return null;
            }
        }

        public FieldDefinition getField(int rowIndex) {
            return fields.get(rowIndex);
        }

        public List<FieldDefinition> getAllFields() {
            return new ArrayList<>(fields);
        }

        public void addField(FieldDefinition field) {
            fields.add(field);
            fireTableRowsInserted(fields.size() - 1, fields.size() - 1);
        }

        public void removeField(FieldDefinition field) {
            int idx = -1;
            for (int i = 0; i < fields.size(); i++) {
                if (fields.get(i).getId() == field.getId()) {
                    idx = i;
                    break;
                }
            }
            if (idx >= 0) {
                fields.remove(idx);
                fireTableRowsDeleted(idx, idx);
            }
        }
    }

    private static class AvailableFieldTableModel extends FieldTableModel {
        AvailableFieldTableModel(List<FieldDefinition> fields) { super(fields); }
    }

    private static class SelectedFieldTableModel extends FieldTableModel {
        SelectedFieldTableModel(List<FieldDefinition> fields) { super(fields); }
    }
}
