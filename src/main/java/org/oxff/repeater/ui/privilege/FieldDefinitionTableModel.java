package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 字段定义表格模型
 */
public class FieldDefinitionTableModel extends DefaultTableModel {

    private static final String[] COLUMN_NAMES = {"类型", "表达式", "描述", "持久化到全局", "启用"};

    private final List<FieldDefinition> fields = new ArrayList<>();

    public FieldDefinitionTableModel() {
        super(COLUMN_NAMES, 0);
    }

    public void setData(List<FieldDefinition> fields) {
        this.fields.clear();
        setRowCount(0);
        if (fields != null) {
            for (FieldDefinition field : fields) {
                this.fields.add(field);
                addRow(new Object[]{
                        field.getType().getDisplayName(),
                        field.getExpression(),
                        field.getDescription(),
                        field.isPersistToGlobal(),
                        field.isEnabled()
                });
            }
        }
        fireTableDataChanged();
    }

    public FieldDefinition getFieldDefinition(int row) {
        if (row >= 0 && row < fields.size()) {
            return fields.get(row);
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 3 || columnIndex == 4) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 3 || column == 4;
    }

    @Override
    public void setValueAt(Object aValue, int row, int column) {
        if (row < 0 || row >= fields.size()) return;
        FieldDefinition field = fields.get(row);
        boolean newValue = Boolean.TRUE.equals(aValue);
        if (column == 3) {
            // 持久化到全局列
            SessionManager.getInstance().updateFieldDefinition(
                    field.getId(), field.getType(), field.getExpression(),
                    field.getDescription(), newValue, field.isEnabled());
        } else if (column == 4) {
            // 启用列
            SessionManager.getInstance().updateFieldDefinition(
                    field.getId(), field.getType(), field.getExpression(),
                    field.getDescription(), field.isPersistToGlobal(), newValue);
        } else {
            return;
        }
        // 重新拉取数据，保证模型内对象与数据库/缓存一致，
        // 避免编辑对话框读取到旧的字段状态
        setData(SessionManager.getInstance().getFieldDefinitions());
    }
}
