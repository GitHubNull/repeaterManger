package org.oxff.repeater.ui.privilege;

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
                        field.isPersistToGlobal() ? "是" : "否",
                        field.isEnabled() ? "是" : "否"
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
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}
