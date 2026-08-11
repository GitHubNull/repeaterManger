package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.Scheme;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 方案表格模型
 * 列：名称、描述、关联字段数、全局、启用
 */
public class SchemeTableModel extends AbstractTableModel {

    private static final String[] COLUMN_KEYS = {
        "scheme.col.name", "scheme.col.description", "scheme.col.fieldCount",
        "scheme.col.global", "scheme.col.enabled"
    };

    private List<Scheme> schemes = new ArrayList<>();

    public void setData(List<Scheme> schemes) {
        this.schemes = schemes != null ? schemes : new ArrayList<>();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return schemes.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_KEYS.length;
    }

    @Override
    public String getColumnName(int column) {
        return I18nManager.tr(COLUMN_KEYS[column]);
    }

    /**
     * 语言切换后刷新列名
     */
    public void refreshColumnNames() {
        fireTableStructureChanged();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 2: return Integer.class;
            case 3: return Boolean.class;  // 全局
            case 4: return Boolean.class;  // 启用
            default: return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Scheme scheme = schemes.get(rowIndex);
        switch (columnIndex) {
            case 0: return scheme.getName();
            case 1: return scheme.getDescription();
            case 2: return scheme.getFieldCount();
            case 3: return scheme.isPersistToGlobal();
            case 4: return scheme.isEnabled();
            default: return null;
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 3 || columnIndex == 4;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= schemes.size()) return;
        Scheme scheme = schemes.get(rowIndex);
        boolean newValue = Boolean.TRUE.equals(aValue);
        if (columnIndex == 3) {
            // 全局列
            SessionManager.getInstance().updateScheme(
                    scheme.getId(), scheme.getName(), scheme.getDescription(),
                    scheme.isEnabled(), newValue);
        } else if (columnIndex == 4) {
            // 启用列
            SessionManager.getInstance().updateScheme(
                    scheme.getId(), scheme.getName(), scheme.getDescription(),
                    newValue, scheme.isPersistToGlobal());
        } else {
            return;
        }
        // 重新拉取数据，保证模型内对象与数据库/缓存一致
        setData(SessionManager.getInstance().getSchemes());
    }

    public Scheme getScheme(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < schemes.size()) {
            return schemes.get(rowIndex);
        }
        return null;
    }
}
